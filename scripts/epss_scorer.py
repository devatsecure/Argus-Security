#!/usr/bin/env python3
"""
EPSS Scorer Module

Fetches Exploit Prediction Scoring System (EPSS) probability scores from
the FIRST.org API for CVE findings. EPSS provides a daily estimate of the
probability that a vulnerability will be exploited in the wild within the
next 30 days.

Features:
- Batch CVE lookups against the FIRST.org EPSS API
- File-based caching with configurable TTL (default 24h)
- Thread-safe cache operations
- Risk categorization (critical/high/medium/low)
- Graceful degradation on API failures
- Finding enrichment for pipeline integration

References:
- https://www.first.org/epss/
- https://api.first.org/data/v1/epss
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = ["EPSSScore", "EPSSCache", "EPSSScorer"]

logger = logging.getLogger(__name__)


@dataclass
class EPSSScore:
    """Represents an EPSS score for a single CVE.

    Attributes:
        cve_id: The CVE identifier (e.g., "CVE-2021-44228").
        epss_score: Probability of exploitation in the next 30 days (0.0-1.0).
        percentile: Percentile ranking among all scored CVEs (0.0-1.0).
        risk_category: Categorical risk level derived from epss_score.
        fetched_at: ISO 8601 timestamp of when the score was retrieved.
    """

    cve_id: str
    epss_score: float
    percentile: float
    risk_category: str
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        """Validate score ranges after initialization."""
        if not 0.0 <= self.epss_score <= 1.0:
            raise ValueError(
                f"epss_score must be between 0.0 and 1.0, got {self.epss_score}"
            )
        if not 0.0 <= self.percentile <= 1.0:
            raise ValueError(
                f"percentile must be between 0.0 and 1.0, got {self.percentile}"
            )
        valid_categories = {"critical", "high", "medium", "low"}
        if self.risk_category not in valid_categories:
            raise ValueError(
                f"risk_category must be one of {valid_categories}, got '{self.risk_category}'"
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EPSSScore:
        """Create an EPSSScore from a dictionary."""
        return cls(
            cve_id=data["cve_id"],
            epss_score=float(data["epss_score"]),
            percentile=float(data["percentile"]),
            risk_category=data["risk_category"],
            fetched_at=data.get(
                "fetched_at", datetime.now(timezone.utc).isoformat()
            ),
        )


class EPSSCache:
    """Thread-safe, file-based cache for EPSS scores.

    Stores scores as JSON on disk with configurable TTL. All public methods
    are protected by a threading lock to ensure safe concurrent access.

    Attributes:
        cache_path: Path to the JSON cache file.
        ttl_hours: Time-to-live for cache entries in hours.
    """

    def __init__(
        self, cache_dir: str = ".argus-cache", ttl_hours: int = 24
    ) -> None:
        """Initialize the EPSS cache.

        Args:
            cache_dir: Directory to store the cache file.
            ttl_hours: Hours before a cache entry expires.
        """
        self.cache_dir = cache_dir
        self.cache_path = os.path.join(cache_dir, "epss_cache.json")
        self.ttl_hours = ttl_hours
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        """Load cache from disk. Creates empty cache if file doesn't exist."""
        with self._lock:
            self._load_unlocked()

    def _load_unlocked(self) -> None:
        """Internal load without acquiring the lock."""
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
                logger.debug(
                    "Loaded %d entries from EPSS cache at %s",
                    len(self._cache),
                    self.cache_path,
                )
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load EPSS cache: %s", e)
                self._cache = {}
        else:
            self._cache = {}

    def save(self) -> None:
        """Persist cache to disk. Creates cache directory if needed."""
        with self._lock:
            self._save_unlocked()

    def _save_unlocked(self) -> None:
        """Internal save without acquiring the lock."""
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
            logger.debug(
                "Saved %d entries to EPSS cache at %s",
                len(self._cache),
                self.cache_path,
            )
        except OSError as e:
            logger.warning("Failed to save EPSS cache: %s", e)

    def is_expired(self, entry: dict[str, Any]) -> bool:
        """Check if a cache entry has exceeded its TTL.

        Args:
            entry: A cache entry dict containing a 'fetched_at' timestamp.

        Returns:
            True if the entry is expired or has an invalid timestamp.
        """
        try:
            fetched_at_str = entry.get("fetched_at", "")
            if not fetched_at_str:
                return True
            # Parse ISO format timestamp
            fetched_at = datetime.fromisoformat(fetched_at_str)
            # Ensure timezone-aware comparison
            if fetched_at.tzinfo is None:
                fetched_at = fetched_at.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_hours = (now - fetched_at).total_seconds() / 3600
            return age_hours >= self.ttl_hours
        except (ValueError, TypeError) as e:
            logger.debug("Invalid timestamp in cache entry: %s", e)
            return True

    def get(self, cve_id: str) -> EPSSScore | None:
        """Retrieve a cached EPSS score if it exists and is not expired.

        Args:
            cve_id: The CVE identifier to look up.

        Returns:
            The cached EPSSScore, or None if not found or expired.
        """
        with self._lock:
            entry = self._cache.get(cve_id)
            if entry is None:
                return None
            if self.is_expired(entry):
                logger.debug("Cache entry expired for %s", cve_id)
                del self._cache[cve_id]
                return None
            try:
                return EPSSScore.from_dict(entry)
            except (KeyError, ValueError) as e:
                logger.warning("Invalid cache entry for %s: %s", cve_id, e)
                del self._cache[cve_id]
                return None

    def put(self, cve_id: str, score: EPSSScore) -> None:
        """Store a single EPSS score in the cache.

        Args:
            cve_id: The CVE identifier.
            score: The EPSSScore to cache.
        """
        with self._lock:
            self._cache[cve_id] = score.to_dict()
            self._save_unlocked()

    def put_batch(self, scores: dict[str, EPSSScore]) -> None:
        """Store multiple EPSS scores in the cache at once.

        More efficient than individual puts as it only writes to disk once.

        Args:
            scores: Mapping of CVE IDs to EPSSScore objects.
        """
        if not scores:
            return
        with self._lock:
            for cve_id, score in scores.items():
                self._cache[cve_id] = score.to_dict()
            self._save_unlocked()
        logger.debug("Batch cached %d EPSS scores", len(scores))


class EPSSScorer:
    """Fetches and manages EPSS scores for CVE findings.

    Queries the FIRST.org EPSS API in batches, caches results locally,
    and provides enrichment of security findings with EPSS data.

    Attributes:
        API_URL: Base URL for the FIRST.org EPSS API.
        BATCH_SIZE: Maximum number of CVEs per API request.
    """

    API_URL = "https://api.first.org/data/v1/epss"
    BATCH_SIZE = 100

    def __init__(
        self,
        cache_dir: str = ".argus-cache",
        ttl_hours: int = 24,
        timeout: int = 30,
    ) -> None:
        """Initialize the EPSS scorer.

        Args:
            cache_dir: Directory for the cache file.
            ttl_hours: Cache TTL in hours.
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout
        self.cache = EPSSCache(cache_dir=cache_dir, ttl_hours=ttl_hours)
        logger.info(
            "EPSSScorer initialized (cache_dir=%s, ttl=%dh, timeout=%ds)",
            cache_dir,
            ttl_hours,
            timeout,
        )

    @staticmethod
    def _categorize_score(score: float) -> str:
        """Categorize an EPSS score into a risk level.

        Thresholds:
        - critical: > 0.5 (more than 50% chance of exploitation)
        - high:     > 0.2 (more than 20% chance)
        - medium:   > 0.05 (more than 5% chance)
        - low:      <= 0.05

        Args:
            score: EPSS probability score (0.0-1.0).

        Returns:
            Risk category string.
        """
        if score > 0.5:
            return "critical"
        elif score > 0.2:
            return "high"
        elif score > 0.05:
            return "medium"
        else:
            return "low"

    def _fetch_batch(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Fetch EPSS scores for a single batch of CVEs.

        Args:
            cve_ids: List of CVE identifiers (max BATCH_SIZE).

        Returns:
            Mapping of CVE IDs to EPSSScore objects for successful lookups.
        """
        if not cve_ids:
            return {}

        results: dict[str, EPSSScore] = {}

        try:
            # Build query parameters
            params = urllib.parse.urlencode({"cve": ",".join(cve_ids)})
            url = f"{self.API_URL}?{params}"

            logger.debug("Fetching EPSS scores for %d CVEs", len(cve_ids))

            request = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Argus-Security/1.0",
                },
            )

            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    logger.warning(
                        "EPSS API returned status %d", response.status
                    )
                    return results

                body = response.read().decode("utf-8")
                data = json.loads(body)

            # Parse API response
            api_data = data.get("data", [])
            now_iso = datetime.now(timezone.utc).isoformat()

            for entry in api_data:
                cve_id = entry.get("cve", "")
                epss_val = float(entry.get("epss", 0.0))
                percentile_val = float(entry.get("percentile", 0.0))

                if not cve_id:
                    continue

                score = EPSSScore(
                    cve_id=cve_id,
                    epss_score=epss_val,
                    percentile=percentile_val,
                    risk_category=self._categorize_score(epss_val),
                    fetched_at=now_iso,
                )
                results[cve_id] = score

            logger.debug(
                "Retrieved %d/%d EPSS scores from API",
                len(results),
                len(cve_ids),
            )

        except urllib.error.URLError as e:
            logger.warning("EPSS API network error: %s", e)
        except urllib.error.HTTPError as e:
            logger.warning("EPSS API HTTP error %d: %s", e.code, e.reason)
        except json.JSONDecodeError as e:
            logger.warning("EPSS API returned invalid JSON: %s", e)
        except (OSError, ValueError, TypeError) as e:
            logger.warning("EPSS API request failed: %s", e)

        return results

    def fetch_scores(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Fetch EPSS scores for a list of CVEs, using cache where possible.

        CVEs are first checked against the local cache. Cache misses are
        batched into groups of BATCH_SIZE for API retrieval. Results are
        cached for future lookups.

        Args:
            cve_ids: List of CVE identifiers to score.

        Returns:
            Mapping of CVE IDs to EPSSScore objects. CVEs that could not be
            scored (API errors, not in EPSS database) are omitted.
        """
        if not cve_ids:
            return {}

        # Deduplicate input
        unique_cves = list(set(cve_ids))
        results: dict[str, EPSSScore] = {}
        uncached: list[str] = []

        # Check cache first
        for cve_id in unique_cves:
            cached = self.cache.get(cve_id)
            if cached is not None:
                results[cve_id] = cached
            else:
                uncached.append(cve_id)

        if not uncached:
            logger.info(
                "All %d CVEs found in EPSS cache", len(results)
            )
            return results

        logger.info(
            "EPSS cache: %d hits, %d misses. Fetching from API...",
            len(results),
            len(uncached),
        )

        # Batch API calls
        fetched: dict[str, EPSSScore] = {}
        for i in range(0, len(uncached), self.BATCH_SIZE):
            batch = uncached[i : i + self.BATCH_SIZE]
            batch_results = self._fetch_batch(batch)
            fetched.update(batch_results)

        # Cache new results
        if fetched:
            self.cache.put_batch(fetched)
            results.update(fetched)

        logger.info(
            "EPSS scoring complete: %d/%d CVEs scored",
            len(results),
            len(unique_cves),
        )

        return results

    def enrich_findings(self, findings: list[dict]) -> list[dict]:
        """Enrich a list of security findings with EPSS data.

        For each finding that contains a 'cve_id' field, adds:
        - epss_score: The EPSS probability (0.0-1.0)
        - epss_percentile: The EPSS percentile (0.0-1.0)
        - epss_risk_category: The risk category string

        Findings without a 'cve_id' field are passed through unchanged.

        Args:
            findings: List of finding dictionaries from the pipeline.

        Returns:
            The same list of findings, enriched with EPSS data where available.
        """
        if not findings:
            return findings

        # Collect CVE IDs from findings
        cve_ids = [
            f["cve_id"]
            for f in findings
            if f.get("cve_id")
        ]

        if not cve_ids:
            logger.debug("No CVE IDs found in findings, skipping EPSS enrichment")
            return findings

        # Fetch scores
        scores = self.fetch_scores(cve_ids)

        # Enrich findings
        enriched_count = 0
        for finding in findings:
            cve_id = finding.get("cve_id")
            if cve_id and cve_id in scores:
                score = scores[cve_id]
                finding["epss_score"] = score.epss_score
                finding["epss_percentile"] = score.percentile
                finding["epss_risk_category"] = score.risk_category
                enriched_count += 1

        logger.info(
            "Enriched %d/%d findings with EPSS data",
            enriched_count,
            len(findings),
        )

        return findings

    def get_summary(self, scores: dict[str, EPSSScore]) -> dict[str, Any]:
        """Generate a summary of EPSS scores.

        Args:
            scores: Mapping of CVE IDs to EPSSScore objects.

        Returns:
            Summary dictionary with:
            - total_scored: Number of CVEs scored
            - by_category: Count per risk category
            - average_score: Mean EPSS score
            - highest_risk: Top 5 CVEs by EPSS score
        """
        if not scores:
            return {
                "total_scored": 0,
                "by_category": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                },
                "average_score": 0.0,
                "highest_risk": [],
            }

        # Category counts
        by_category: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for score in scores.values():
            by_category[score.risk_category] = (
                by_category.get(score.risk_category, 0) + 1
            )

        # Average score
        all_scores = [s.epss_score for s in scores.values()]
        average_score = sum(all_scores) / len(all_scores)

        # Top 5 highest risk
        sorted_scores = sorted(
            scores.values(), key=lambda s: s.epss_score, reverse=True
        )
        highest_risk = [
            {
                "cve_id": s.cve_id,
                "epss_score": s.epss_score,
                "percentile": s.percentile,
                "risk_category": s.risk_category,
            }
            for s in sorted_scores[:5]
        ]

        return {
            "total_scored": len(scores),
            "by_category": by_category,
            "average_score": round(average_score, 6),
            "highest_risk": highest_risk,
        }
