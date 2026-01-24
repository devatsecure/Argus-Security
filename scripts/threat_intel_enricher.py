#!/usr/bin/env python3
"""
Threat Intelligence Integration for Argus
Enriches findings with real-time threat intelligence from multiple sources.

Features:
- CISA KEV catalog integration (actively exploited vulnerabilities)
- EPSS scoring (exploitation probability)
- NVD data (CVSS scores and details)
- GitHub Advisory Database
- OSV (Open Source Vulnerabilities)
- Exploit-DB references
- Intelligent caching (24h TTL)
- Rate limiting and retry logic
- Priority adjustment based on threat context
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import urllib.request
import urllib.error
import urllib.parse
from collections import defaultdict
from tenacity import (
    retry,
    wait_exponential,
    stop_after_attempt,
    retry_if_exception_type,
)

logger = logging.getLogger(__name__)


@dataclass
class ThreatContext:
    """Threat intelligence context for a CVE"""

    cve_id: str
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None  # 0.0-1.0
    epss_percentile: Optional[float] = None
    in_kev_catalog: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    kev_action_required: Optional[str] = None
    public_exploit_available: bool = False
    exploit_sources: List[str] = field(default_factory=list)
    exploit_count: int = 0
    trending: bool = False
    vendor_patch_available: bool = False
    patch_url: Optional[str] = None
    github_advisories: List[Dict] = field(default_factory=list)
    osv_entries: List[Dict] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    last_updated: Optional[str] = None
    confidence: float = 1.0  # Confidence in enrichment data (0.0-1.0)


@dataclass
class EnrichedFinding:
    """Finding enriched with threat intelligence"""

    original_finding: Dict
    threat_context: Optional[ThreatContext]
    original_priority: str
    adjusted_priority: str
    priority_boost_reasons: List[str]
    priority_downgrade_reasons: List[str]
    recommended_action: str
    remediation_deadline: Optional[str]
    risk_score: float  # 0.0-10.0 composite risk score


class ThreatIntelEnricher:
    """Enrich findings with threat intelligence from multiple sources"""

    # API endpoints
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    GITHUB_ADVISORY_URL = "https://api.github.com/advisories"
    OSV_API_URL = "https://api.osv.dev/v1/vulns"

    # Rate limiting
    RATE_LIMIT_DELAY = 0.6  # 600ms between API calls (max ~100/min)
    NVD_RATE_LIMIT_DELAY = 6.0  # NVD requires 6 second delay without API key

    # Cache TTL
    CACHE_TTL = 86400  # 24 hours

    # CVE pattern
    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")

    def __init__(self, cache_dir: Optional[Path] = None, use_progress: bool = False):
        """
        Initialize threat intel enricher.

        Args:
            cache_dir: Directory for caching API responses
            use_progress: Whether to show progress bars (requires rich)
        """
        # Try default cache location, fallback to /cache for Docker read-only workspaces
        default_cache = cache_dir or Path(".argus-cache/threat-intel")
        try:
            default_cache.mkdir(parents=True, exist_ok=True)
            # Test if writable
            test_file = default_cache / ".write_test"
            test_file.touch()
            test_file.unlink()
            self.cache_dir = default_cache
        except (PermissionError, OSError):
            # Fallback to /cache for Docker read-only mounts
            self.cache_dir = Path("/cache/threat-intel")
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.warning(f"Using fallback cache directory: {self.cache_dir}")

        self.use_progress = use_progress

        # Rate limiting state
        self._last_api_call: Dict[str, float] = defaultdict(float)

        # Statistics (initialize before loading KEV catalog)
        self.stats = {
            "total_enriched": 0,
            "in_kev": 0,
            "high_epss": 0,
            "has_exploit": 0,
            "priority_boosted": 0,
            "priority_downgraded": 0,
            "github_advisories": 0,
            "osv_entries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "api_errors": 0,
        }

        # Load cached data sources
        self.kev_catalog = self._load_kev_catalog()

    def enrich_findings(self, findings: List[Dict]) -> List[EnrichedFinding]:
        """
        Enrich findings with threat intelligence.

        Args:
            findings: List of findings from scanners

        Returns:
            List of enriched findings with threat context
        """
        logger.info(f"Enriching {len(findings)} findings with threat intelligence")

        enriched = []

        # Filter for CVE findings
        cve_findings = [f for f in findings if self._has_cve(f)]
        logger.info(f"Found {len(cve_findings)} findings with CVEs")

        if not cve_findings:
            logger.warning("No CVE findings to enrich")
            return enriched

        # Process each finding
        try:
            if self.use_progress:
                enriched = self._enrich_with_progress(cve_findings)
            else:
                enriched = self._enrich_without_progress(cve_findings)
        except KeyboardInterrupt:
            logger.warning("Enrichment interrupted by user")
            return enriched

        # Log statistics
        self._print_enrichment_stats(enriched)

        return enriched

    def _enrich_with_progress(self, findings: List[Dict]) -> List[EnrichedFinding]:
        """Enrich findings with progress bar"""
        try:
            from rich.progress import (
                Progress,
                SpinnerColumn,
                TextColumn,
                BarColumn,
                TaskProgressColumn,
                TimeRemainingColumn,
            )

            enriched = []

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task(
                    "[cyan]Enriching findings...", total=len(findings)
                )

                for finding in findings:
                    enriched_finding = self._enrich_single_finding(finding)
                    if enriched_finding:
                        enriched.append(enriched_finding)
                    progress.advance(task)

            return enriched

        except ImportError:
            logger.warning("Rich not available, falling back to simple progress")
            return self._enrich_without_progress(findings)

    def _enrich_without_progress(self, findings: List[Dict]) -> List[EnrichedFinding]:
        """Enrich findings without progress bar"""
        enriched = []

        for i, finding in enumerate(findings, 1):
            if i % 10 == 0:
                logger.info(f"Processed {i}/{len(findings)} findings...")

            enriched_finding = self._enrich_single_finding(finding)
            if enriched_finding:
                enriched.append(enriched_finding)

        return enriched

    def _enrich_single_finding(self, finding: Dict) -> Optional[EnrichedFinding]:
        """Enrich a single finding"""
        cve_id = self._extract_cve(finding)
        if not cve_id:
            return None

        # Get threat context
        context = self.enrich_cve(cve_id)

        if not context:
            return None

        # Adjust priority based on threat intel
        original_priority = self._normalize_priority(
            finding.get("severity", "MEDIUM")
        )
        adjusted_priority, boost_reasons, downgrade_reasons = self._adjust_priority(
            original_priority, context
        )

        # Calculate risk score
        risk_score = self._calculate_risk_score(context, adjusted_priority)

        # Determine recommended action and deadline
        action, deadline = self._recommend_action(context, adjusted_priority)

        enriched_finding = EnrichedFinding(
            original_finding=finding,
            threat_context=context,
            original_priority=original_priority,
            adjusted_priority=adjusted_priority,
            priority_boost_reasons=boost_reasons,
            priority_downgrade_reasons=downgrade_reasons,
            recommended_action=action,
            remediation_deadline=deadline,
            risk_score=risk_score,
        )

        # Update stats
        self.stats["total_enriched"] += 1
        if boost_reasons:
            self.stats["priority_boosted"] += 1
        if downgrade_reasons:
            self.stats["priority_downgraded"] += 1

        return enriched_finding

    def enrich_cve(self, cve_id: str) -> Optional[ThreatContext]:
        """
        Enrich a single CVE with threat intelligence from all sources.

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)

        Returns:
            ThreatContext with enrichment data, or None if no data available
        """
        logger.debug(f"Enriching {cve_id}")

        context = ThreatContext(cve_id=cve_id)
        data_sources_successful = 0

        # 1. Check CISA KEV catalog (highest priority)
        if self.kev_catalog:
            kev_entry = self._check_kev(cve_id)
            if kev_entry:
                context.in_kev_catalog = True
                context.kev_date_added = kev_entry.get("dateAdded")
                context.kev_due_date = kev_entry.get("dueDate")
                context.kev_action_required = kev_entry.get("requiredAction")
                data_sources_successful += 1
                self.stats["in_kev"] += 1

        # 2. Get EPSS score (exploitation probability)
        epss_data = self._get_epss_score(cve_id)
        if epss_data:
            context.epss_score = epss_data.get("epss")
            context.epss_percentile = epss_data.get("percentile")
            data_sources_successful += 1
            if context.epss_score and context.epss_score > 0.5:
                self.stats["high_epss"] += 1

        # 3. Get NVD data (CVSS, CWE, references)
        nvd_data = self._get_nvd_data(cve_id)
        if nvd_data:
            context.cvss_score = nvd_data.get("cvss_score")
            context.cvss_severity = nvd_data.get("severity")
            context.cvss_vector = nvd_data.get("cvss_vector")
            context.cwe_ids = nvd_data.get("cwe_ids", [])
            context.references = nvd_data.get("references", [])
            context.public_exploit_available = nvd_data.get("has_exploit", False)
            if nvd_data.get("exploit_sources"):
                context.exploit_sources.extend(nvd_data["exploit_sources"])
            data_sources_successful += 1

        # 4. Get GitHub Advisory data
        gh_advisories = self._get_github_advisories(cve_id)
        if gh_advisories:
            context.github_advisories = gh_advisories
            data_sources_successful += 1
            self.stats["github_advisories"] += len(gh_advisories)

            # Check for patch info
            for advisory in gh_advisories:
                if advisory.get("patched_versions"):
                    context.vendor_patch_available = True
                    context.patch_url = advisory.get("html_url")
                    break

        # 5. Get OSV data (Open Source Vulnerabilities)
        osv_data = self._get_osv_data(cve_id)
        if osv_data:
            context.osv_entries = osv_data
            data_sources_successful += 1
            self.stats["osv_entries"] += len(osv_data)

            # Extract additional references
            for entry in osv_data:
                if entry.get("references"):
                    context.references.extend(
                        [ref.get("url") for ref in entry["references"] if ref.get("url")]
                    )

        # 6. Check for public exploits in references
        exploit_indicators = ["exploit-db", "exploitdb", "exploit", "poc", "proof-of-concept"]
        for ref in context.references:
            if any(indicator in ref.lower() for indicator in exploit_indicators):
                context.public_exploit_available = True
                if ref not in context.exploit_sources:
                    context.exploit_sources.append(ref)

        context.exploit_count = len(context.exploit_sources)
        if context.exploit_count > 0:
            self.stats["has_exploit"] += 1

        # 7. Detect trending (heuristic based on recency and KEV status)
        context.trending = self._detect_trending(context)

        # Calculate confidence based on data sources
        context.confidence = min(1.0, data_sources_successful / 5.0)

        context.last_updated = datetime.utcnow().isoformat()

        # Return None if we couldn't get any meaningful data
        if data_sources_successful == 0:
            logger.warning(f"No threat intelligence data found for {cve_id}")
            return None

        return context

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((urllib.error.URLError, urllib.error.HTTPError, ConnectionError, TimeoutError)),
    )
    def _fetch_kev_data(self) -> Dict:
        """Fetch KEV data from CISA API with retry logic"""
        logger.info("Fetching CISA KEV catalog...")
        self._rate_limit("kev")

        req = urllib.request.Request(self.CISA_KEV_URL)
        req.add_header("User-Agent", "Argus-Security-Scanner/1.0")

        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read())

        return data

    def _load_kev_catalog(self) -> Optional[Dict]:
        """Load CISA KEV catalog with 24h caching"""
        cache_file = self.cache_dir / "kev_catalog.json"

        # Check cache
        if cache_file.exists():
            cache_age = time.time() - cache_file.stat().st_mtime
            if cache_age < self.CACHE_TTL:
                try:
                    with open(cache_file) as f:
                        data = json.load(f)
                    logger.info(
                        f"Loaded KEV catalog from cache ({len(data.get('vulnerabilities', []))} entries)"
                    )
                    self.stats["cache_hits"] += 1
                    return data
                except Exception as e:
                    logger.warning(f"Failed to load KEV cache: {e}")

        # Fetch fresh data with retry logic
        try:
            data = self._fetch_kev_data()

            # Cache it
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)

            vuln_count = len(data.get("vulnerabilities", []))
            logger.info(f"Loaded {vuln_count} KEV entries from CISA")
            self.stats["cache_misses"] += 1
            return data

        except Exception as e:
            logger.error(f"Failed to fetch KEV catalog after retries: {e}")
            self.stats["api_errors"] += 1
            return None

    def _check_kev(self, cve_id: str) -> Optional[Dict]:
        """Check if CVE is in CISA KEV catalog"""
        if not self.kev_catalog:
            return None

        for vuln in self.kev_catalog.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return vuln

        return None

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((urllib.error.URLError, urllib.error.HTTPError, ConnectionError, TimeoutError)),
    )
    def _fetch_epss_data(self, cve_id: str) -> Dict:
        """Fetch EPSS data from FIRST API with retry logic"""
        self._rate_limit("epss")
        url = f"{self.EPSS_API_URL}?cve={cve_id}"

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Argus-Security-Scanner/1.0")

        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read())

        if data.get("data") and len(data["data"]) > 0:
            epss_data = data["data"][0]
            return {
                "epss": float(epss_data.get("epss", 0)),
                "percentile": float(epss_data.get("percentile", 0)),
            }
        return {}

    def _get_epss_score(self, cve_id: str) -> Optional[Dict]:
        """Get EPSS score from FIRST API with caching"""
        cache_file = self.cache_dir / f"epss_{cve_id}.json"

        # Check cache
        if cache_file.exists():
            cache_age = time.time() - cache_file.stat().st_mtime
            if cache_age < self.CACHE_TTL:
                try:
                    with open(cache_file) as f:
                        self.stats["cache_hits"] += 1
                        return json.load(f)
                except Exception:
                    pass

        # Fetch from API with retry logic
        try:
            result = self._fetch_epss_data(cve_id)

            if result:
                # Cache it
                with open(cache_file, "w") as f:
                    json.dump(result, f, indent=2)

                self.stats["cache_misses"] += 1
                return result

        except Exception as e:
            logger.debug(f"Failed to get EPSS for {cve_id} after retries: {e}")
            self.stats["api_errors"] += 1

        return None

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((urllib.error.URLError, ConnectionError, TimeoutError)),
    )
    def _fetch_nvd_data(self, cve_id: str) -> Dict:
        """Fetch NVD data from API with retry logic"""
        self._rate_limit("nvd")
        url = f"{self.NVD_API_URL}?cveId={cve_id}"

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Argus-Security-Scanner/1.0")

        with urllib.request.urlopen(req, timeout=20) as response:
            data = json.loads(response.read())

        if data.get("vulnerabilities") and len(data["vulnerabilities"]) > 0:
            vuln = data["vulnerabilities"][0]["cve"]
            return self._parse_nvd_vulnerability(vuln)

        return {}

    def _get_nvd_data(self, cve_id: str) -> Optional[Dict]:
        """Get NVD data for CVE with caching"""
        cache_file = self.cache_dir / f"nvd_{cve_id}.json"

        # Check cache
        if cache_file.exists():
            cache_age = time.time() - cache_file.stat().st_mtime
            if cache_age < self.CACHE_TTL:
                try:
                    with open(cache_file) as f:
                        self.stats["cache_hits"] += 1
                        return json.load(f)
                except Exception:
                    pass

        # Fetch from NVD API with retry logic
        try:
            result = self._fetch_nvd_data(cve_id)

            if result:
                # Cache it
                with open(cache_file, "w") as f:
                    json.dump(result, f, indent=2)

                self.stats["cache_misses"] += 1
                return result

        except urllib.error.HTTPError as e:
            if e.code == 404:
                logger.debug(f"CVE {cve_id} not found in NVD")
            else:
                logger.debug(f"Failed to get NVD data for {cve_id} after retries: HTTP {e.code}")
            self.stats["api_errors"] += 1
        except Exception as e:
            logger.debug(f"Failed to get NVD data for {cve_id} after retries: {e}")
            self.stats["api_errors"] += 1

        return None

    def _parse_nvd_vulnerability(self, vuln: Dict) -> Dict:
        """Parse NVD vulnerability data"""
        metrics = vuln.get("metrics", {})

        # Extract CVSS score (prefer v3.1 > v3.0 > v2.0)
        cvss_score = None
        severity = None
        cvss_vector = None

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")

                if "cvssMetricV3" in version:
                    severity = cvss_data.get("baseSeverity")
                else:
                    # Map CVSS v2 to severity
                    if cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                break

        # Extract CWE IDs
        cwe_ids = []
        for weakness in vuln.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id.startswith("CWE-"):
                    cwe_ids.append(cwe_id)

        # Extract references and check for exploits
        references = []
        exploit_sources = []
        has_exploit = False

        for ref in vuln.get("references", []):
            url = ref.get("url", "")
            references.append(url)

            # Check if reference indicates exploit
            tags = ref.get("tags", [])
            if "Exploit" in tags:
                has_exploit = True
                exploit_sources.append(url)

        return {
            "cvss_score": cvss_score,
            "severity": severity,
            "cvss_vector": cvss_vector,
            "cwe_ids": cwe_ids,
            "references": references,
            "has_exploit": has_exploit,
            "exploit_sources": exploit_sources,
        }

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((urllib.error.URLError, urllib.error.HTTPError, ConnectionError, TimeoutError)),
    )
    def _fetch_github_advisories(self, cve_id: str) -> List[Dict]:
        """Fetch GitHub advisories from API with retry logic"""
        self._rate_limit("github")

        # GitHub API v3 requires proper URL encoding
        params = urllib.parse.urlencode({"cve_id": cve_id})
        url = f"{self.GITHUB_ADVISORY_URL}?{params}"

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Argus-Security-Scanner/1.0")
        req.add_header("Accept", "application/vnd.github+json")

        with urllib.request.urlopen(req, timeout=15) as response:
            advisories = json.loads(response.read())

        # Extract relevant fields
        result = []
        for advisory in advisories:
            result.append(
                {
                    "id": advisory.get("ghsa_id"),
                    "summary": advisory.get("summary"),
                    "severity": advisory.get("severity"),
                    "html_url": advisory.get("html_url"),
                    "published_at": advisory.get("published_at"),
                    "updated_at": advisory.get("updated_at"),
                    "patched_versions": advisory.get("vulnerabilities", [{}])[0].get(
                        "patched_versions"
                    ),
                }
            )

        return result

    def _get_github_advisories(self, cve_id: str) -> List[Dict]:
        """Get GitHub Security Advisories for CVE"""
        cache_file = self.cache_dir / f"github_{cve_id}.json"

        # Check cache
        if cache_file.exists():
            cache_age = time.time() - cache_file.stat().st_mtime
            if cache_age < self.CACHE_TTL:
                try:
                    with open(cache_file) as f:
                        self.stats["cache_hits"] += 1
                        return json.load(f)
                except Exception:
                    pass

        # Fetch from GitHub API with retry logic
        try:
            result = self._fetch_github_advisories(cve_id)

            # Cache it
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)

            self.stats["cache_misses"] += 1
            return result

        except Exception as e:
            logger.debug(f"Failed to get GitHub advisories for {cve_id} after retries: {e}")
            self.stats["api_errors"] += 1

        return []

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((urllib.error.URLError, ConnectionError, TimeoutError)),
    )
    def _fetch_osv_data(self, cve_id: str) -> List[Dict]:
        """Fetch OSV data from API with retry logic"""
        self._rate_limit("osv")
        url = f"{self.OSV_API_URL}/{cve_id}"

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Argus-Security-Scanner/1.0")

        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read())

        result = [
            {
                "id": data.get("id"),
                "summary": data.get("summary"),
                "details": data.get("details"),
                "severity": data.get("severity"),
                "references": data.get("references", []),
                "affected": data.get("affected", []),
            }
        ]

        return result

    def _get_osv_data(self, cve_id: str) -> List[Dict]:
        """Get OSV (Open Source Vulnerabilities) data"""
        cache_file = self.cache_dir / f"osv_{cve_id}.json"

        # Check cache
        if cache_file.exists():
            cache_age = time.time() - cache_file.stat().st_mtime
            if cache_age < self.CACHE_TTL:
                try:
                    with open(cache_file) as f:
                        self.stats["cache_hits"] += 1
                        return json.load(f)
                except Exception:
                    pass

        # Fetch from OSV API with retry logic
        try:
            result = self._fetch_osv_data(cve_id)

            # Cache it
            with open(cache_file, "w") as f:
                json.dump(result, f, indent=2)

            self.stats["cache_misses"] += 1
            return result

        except urllib.error.HTTPError as e:
            if e.code == 404:
                logger.debug(f"CVE {cve_id} not found in OSV")
            else:
                logger.debug(f"Failed to get OSV data for {cve_id} after retries: HTTP {e.code}")
            self.stats["api_errors"] += 1
        except Exception as e:
            logger.debug(f"Failed to get OSV data for {cve_id} after retries: {e}")
            self.stats["api_errors"] += 1

        return []

    def _rate_limit(self, source: str):
        """Rate limit API calls"""
        # Special handling for NVD (6 second delay required without API key)
        delay = self.NVD_RATE_LIMIT_DELAY if source == "nvd" else self.RATE_LIMIT_DELAY

        last_call = self._last_api_call[source]
        time_since_last = time.time() - last_call

        if time_since_last < delay:
            sleep_time = delay - time_since_last
            logger.debug(f"Rate limiting {source}: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)

        self._last_api_call[source] = time.time()

    def _detect_trending(self, context: ThreatContext) -> bool:
        """
        Detect if CVE is trending based on heuristics.

        A CVE is considered trending if:
        - Recently added to KEV catalog (within 30 days)
        - High EPSS score with recent update
        - Multiple exploit sources
        """
        if context.in_kev_catalog and context.kev_date_added:
            try:
                kev_date = datetime.fromisoformat(context.kev_date_added)
                days_since_kev = (datetime.utcnow() - kev_date).days
                if days_since_kev <= 30:
                    return True
            except Exception:
                pass

        # High EPSS with multiple exploits suggests active exploitation
        if (
            context.epss_score
            and context.epss_score > 0.7
            and context.exploit_count >= 2
        ):
            return True

        return False

    def _adjust_priority(
        self, original: str, context: ThreatContext
    ) -> Tuple[str, List[str], List[str]]:
        """
        Adjust priority based on threat intelligence.

        Returns:
            Tuple of (adjusted_priority, boost_reasons, downgrade_reasons)
        """
        priority = original
        boost_reasons = []
        downgrade_reasons = []

        # Priority levels: CRITICAL > HIGH > MEDIUM > LOW > INFO
        priority_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

        def upgrade_to(target: str, reason: str):
            nonlocal priority
            if priority_levels.index(target) > priority_levels.index(priority):
                priority = target
                boost_reasons.append(reason)

        def downgrade_to(target: str, reason: str):
            nonlocal priority
            if priority_levels.index(target) < priority_levels.index(priority):
                priority = target
                downgrade_reasons.append(reason)

        # Critical boost: In KEV catalog (actively exploited in wild)
        if context.in_kev_catalog:
            upgrade_to(
                "CRITICAL",
                f"In CISA KEV catalog - exploited in wild since {context.kev_date_added}",
            )

        # Critical boost: Very high EPSS + public exploit
        if (
            context.epss_score
            and context.epss_score > 0.8
            and context.public_exploit_available
        ):
            upgrade_to(
                "CRITICAL",
                f"EPSS score {context.epss_score:.3f} with public exploits available",
            )

        # High boost: High EPSS score (>50% exploitation probability)
        if context.epss_score and context.epss_score > 0.5:
            percentile = (
                f" (top {100-context.epss_percentile:.1f}%)"
                if context.epss_percentile
                else ""
            )
            upgrade_to(
                "HIGH", f"EPSS score {context.epss_score:.3f}{percentile} - high exploitation risk"
            )

        # High boost: Multiple public exploits
        if context.exploit_count >= 2:
            upgrade_to(
                "HIGH", f"{context.exploit_count} public exploits available"
            )

        # Medium boost: Single public exploit
        if context.public_exploit_available and context.exploit_count == 1:
            upgrade_to("MEDIUM", "Public exploit available")

        # Boost based on CVSS
        if context.cvss_score:
            if context.cvss_score >= 9.0:
                upgrade_to(
                    "HIGH",
                    f"CVSS score {context.cvss_score} (CRITICAL severity)",
                )
            elif context.cvss_score >= 7.0:
                upgrade_to("MEDIUM", f"CVSS score {context.cvss_score} (HIGH severity)")

        # Boost if trending
        if context.trending:
            upgrade_to("HIGH", "Trending vulnerability - recent active exploitation")

        # Downgrade if low EPSS and no exploit
        if (
            context.epss_score
            and context.epss_score < 0.1
            and not context.public_exploit_available
            and not context.in_kev_catalog
        ):
            downgrade_to(
                "LOW", f"Low exploitation probability (EPSS {context.epss_score:.3f}, no public exploits)"
            )

        # Downgrade if patch available (but still keep some priority)
        if context.vendor_patch_available and priority not in ["CRITICAL"]:
            downgrade_reasons.append(
                f"Vendor patch available at {context.patch_url or 'upstream'}"
            )

        return priority, boost_reasons, downgrade_reasons

    def _calculate_risk_score(self, context: ThreatContext, priority: str) -> float:
        """
        Calculate composite risk score (0.0-10.0).

        Factors:
        - CVSS base score (0-10)
        - EPSS score (0-1) weighted heavily
        - KEV catalog membership (boolean)
        - Public exploit availability (boolean)
        - Exploit count
        """
        score = 0.0

        # Base: CVSS score (0-10)
        if context.cvss_score:
            score = context.cvss_score
        else:
            # Fallback to priority-based score
            priority_scores = {
                "CRITICAL": 9.5,
                "HIGH": 8.0,
                "MEDIUM": 5.0,
                "LOW": 3.0,
                "INFO": 1.0,
            }
            score = priority_scores.get(priority, 5.0)

        # EPSS multiplier (1.0-2.0x)
        if context.epss_score:
            epss_multiplier = 1.0 + context.epss_score
            score *= epss_multiplier

        # KEV catalog: +3.0 points
        if context.in_kev_catalog:
            score += 3.0

        # Public exploits: +1.0 per exploit (max +3.0)
        if context.public_exploit_available:
            score += min(3.0, context.exploit_count)

        # Trending: +1.0
        if context.trending:
            score += 1.0

        # Patch available: -0.5
        if context.vendor_patch_available:
            score -= 0.5

        # Clamp to 0.0-10.0
        return max(0.0, min(10.0, score))

    def _recommend_action(
        self, context: ThreatContext, priority: str
    ) -> Tuple[str, Optional[str]]:
        """
        Recommend remediation action and deadline.

        Returns:
            Tuple of (action_description, deadline_iso_string)
        """
        now = datetime.utcnow()

        if context.in_kev_catalog:
            # KEV catalog has specific due dates
            deadline = context.kev_due_date or (now + timedelta(hours=24)).isoformat()
            action = f"🚨 URGENT: {context.kev_action_required or 'Patch immediately'}"
            return action, deadline

        if priority == "CRITICAL":
            deadline = (now + timedelta(hours=24)).isoformat()
            return "Patch within 24 hours - Critical vulnerability with active exploitation", deadline

        if priority == "HIGH":
            deadline = (now + timedelta(days=7)).isoformat()
            return "Patch within 7 days - High risk of exploitation", deadline

        if priority == "MEDIUM":
            deadline = (now + timedelta(days=30)).isoformat()
            return "Patch within 30 days - Moderate risk", deadline

        if priority == "LOW":
            deadline = (now + timedelta(days=90)).isoformat()
            return "Patch within 90 days - Low risk but should be addressed", deadline

        deadline = None
        return "Monitor and patch in next maintenance window", deadline

    def _has_cve(self, finding: Dict) -> bool:
        """Check if finding has a CVE identifier"""
        text = " ".join(
            str(finding.get(field, ""))
            for field in ["cve", "description", "title", "id", "message"]
        )
        return bool(self.CVE_PATTERN.search(text))

    def _extract_cve(self, finding: Dict) -> Optional[str]:
        """Extract CVE ID from finding"""
        for field in ["cve", "id", "description", "title", "message"]:
            value = str(finding.get(field, ""))
            match = self.CVE_PATTERN.search(value)
            if match:
                return match.group(0)
        return None

    def _normalize_priority(self, priority: str) -> str:
        """Normalize priority to standard levels"""
        priority_upper = priority.upper()

        # Map common variations
        mappings = {
            "BLOCKER": "CRITICAL",
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "NOTE": "LOW",
        }

        return mappings.get(priority_upper, priority_upper)

    def _print_enrichment_stats(self, enriched: List[EnrichedFinding]):
        """Print enrichment statistics"""
        total = len(enriched)
        in_kev = self.stats["in_kev"]
        high_epss = self.stats["high_epss"]
        has_exploit = self.stats["has_exploit"]
        boosted = self.stats["priority_boosted"]
        downgraded = self.stats["priority_downgraded"]

        # Calculate average risk score
        avg_risk = (
            sum(e.risk_score for e in enriched) / total if total > 0 else 0.0
        )

        logger.info("\n" + "=" * 70)
        logger.info("📊 Threat Intelligence Enrichment Summary")
        logger.info("=" * 70)
        logger.info(f"Total CVEs enriched:         {total}")
        logger.info(f"In CISA KEV catalog:         {in_kev} (actively exploited)")
        logger.info(f"High EPSS (>0.5):            {high_epss} (likely to be exploited)")
        logger.info(f"Public exploits available:   {has_exploit}")
        logger.info(f"GitHub advisories found:     {self.stats['github_advisories']}")
        logger.info(f"OSV entries found:           {self.stats['osv_entries']}")
        logger.info(f"Priority boosted:            {boosted}")
        logger.info(f"Priority downgraded:         {downgraded}")
        logger.info(f"Average risk score:          {avg_risk:.2f}/10.0")
        logger.info(f"\nCache performance:")
        logger.info(f"  Cache hits:                {self.stats['cache_hits']}")
        logger.info(f"  Cache misses:              {self.stats['cache_misses']}")
        logger.info(f"  API errors:                {self.stats['api_errors']}")
        logger.info("=" * 70 + "\n")

    def export_enriched_findings(
        self, enriched: List[EnrichedFinding], output_file: Path
    ):
        """Export enriched findings to JSON file"""
        output_data = []

        for e in enriched:
            entry = {
                "finding": e.original_finding,
                "threat_context": asdict(e.threat_context) if e.threat_context else None,
                "priority": {
                    "original": e.original_priority,
                    "adjusted": e.adjusted_priority,
                    "boost_reasons": e.priority_boost_reasons,
                    "downgrade_reasons": e.priority_downgrade_reasons,
                },
                "risk_score": e.risk_score,
                "remediation": {
                    "action": e.recommended_action,
                    "deadline": e.remediation_deadline,
                },
            }
            output_data.append(entry)

        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2)

        logger.info(f"✅ Exported {len(output_data)} enriched findings to {output_file}")


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Threat Intelligence Enrichment for Argus",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Enrich findings from Trivy scan
  %(prog)s --findings trivy-results.json --output enriched.json

  # Enrich with progress bar
  %(prog)s --findings findings.json --output enriched.json --progress

  # Debug mode
  %(prog)s --findings findings.json --debug
        """,
    )
    parser.add_argument(
        "--findings", required=True, help="Input findings JSON file"
    )
    parser.add_argument(
        "--output",
        help="Output file (default: findings_enriched.json)",
        default="findings_enriched.json",
    )
    parser.add_argument(
        "--cache-dir",
        help="Cache directory (default: .argus-cache/threat-intel)",
        type=Path,
    )
    parser.add_argument(
        "--progress", action="store_true", help="Show progress bar (requires rich)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Load findings
    try:
        with open(args.findings) as f:
            findings = json.load(f)
        logger.info(f"Loaded {len(findings)} findings from {args.findings}")
    except Exception as e:
        logger.error(f"Failed to load findings: {e}")
        return 1

    # Enrich
    try:
        enricher = ThreatIntelEnricher(
            cache_dir=args.cache_dir, use_progress=args.progress
        )
        enriched = enricher.enrich_findings(findings)

        # Export
        output_path = Path(args.output)
        enricher.export_enriched_findings(enriched, output_path)

        return 0

    except KeyboardInterrupt:
        logger.warning("\n⚠️  Enrichment interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Enrichment failed: {e}", exc_info=args.debug)
        return 1


if __name__ == "__main__":
    exit(main())
