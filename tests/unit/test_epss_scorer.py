#!/usr/bin/env python3
"""
Unit tests for EPSS Scorer Module

Tests cover:
- EPSSScore dataclass creation and validation
- EPSSCache get/put/put_batch, TTL expiration, file persistence
- EPSSScorer score categorization, batch fetching, enrichment, summary
- Graceful degradation on API failures
- Edge cases and empty inputs

All network calls are mocked - no real API requests are made.
"""

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch, mock_open

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from epss_scorer import EPSSScore, EPSSCache, EPSSScorer


# ---------------------------------------------------------------------------
# EPSSScore dataclass tests
# ---------------------------------------------------------------------------


class TestEPSSScore:
    """Test EPSSScore dataclass creation and validation."""

    def test_create_valid_score(self):
        """Test creating a valid EPSSScore with all fields."""
        score = EPSSScore(
            cve_id="CVE-2021-44228",
            epss_score=0.97,
            percentile=0.99,
            risk_category="critical",
            fetched_at="2025-01-15T10:00:00+00:00",
        )
        assert score.cve_id == "CVE-2021-44228"
        assert score.epss_score == 0.97
        assert score.percentile == 0.99
        assert score.risk_category == "critical"
        assert score.fetched_at == "2025-01-15T10:00:00+00:00"

    def test_create_score_default_fetched_at(self):
        """Test that fetched_at defaults to current UTC time."""
        score = EPSSScore(
            cve_id="CVE-2023-1234",
            epss_score=0.1,
            percentile=0.5,
            risk_category="medium",
        )
        assert score.fetched_at is not None
        # Should be a parseable ISO timestamp
        dt = datetime.fromisoformat(score.fetched_at)
        assert dt is not None

    def test_score_boundary_values(self):
        """Test boundary values for score and percentile (0.0 and 1.0)."""
        score_low = EPSSScore(
            cve_id="CVE-2023-0001",
            epss_score=0.0,
            percentile=0.0,
            risk_category="low",
        )
        assert score_low.epss_score == 0.0
        assert score_low.percentile == 0.0

        score_high = EPSSScore(
            cve_id="CVE-2023-0002",
            epss_score=1.0,
            percentile=1.0,
            risk_category="critical",
        )
        assert score_high.epss_score == 1.0
        assert score_high.percentile == 1.0

    def test_invalid_epss_score_too_high(self):
        """Test that epss_score > 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="epss_score must be between"):
            EPSSScore(
                cve_id="CVE-2023-0001",
                epss_score=1.5,
                percentile=0.5,
                risk_category="critical",
            )

    def test_invalid_epss_score_negative(self):
        """Test that negative epss_score raises ValueError."""
        with pytest.raises(ValueError, match="epss_score must be between"):
            EPSSScore(
                cve_id="CVE-2023-0001",
                epss_score=-0.1,
                percentile=0.5,
                risk_category="low",
            )

    def test_invalid_percentile(self):
        """Test that percentile > 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="percentile must be between"):
            EPSSScore(
                cve_id="CVE-2023-0001",
                epss_score=0.5,
                percentile=1.1,
                risk_category="critical",
            )

    def test_invalid_risk_category(self):
        """Test that invalid risk_category raises ValueError."""
        with pytest.raises(ValueError, match="risk_category must be one of"):
            EPSSScore(
                cve_id="CVE-2023-0001",
                epss_score=0.5,
                percentile=0.5,
                risk_category="extreme",
            )

    def test_to_dict(self):
        """Test serialization to dictionary."""
        score = EPSSScore(
            cve_id="CVE-2023-1234",
            epss_score=0.3,
            percentile=0.8,
            risk_category="high",
            fetched_at="2025-01-15T10:00:00+00:00",
        )
        d = score.to_dict()
        assert d["cve_id"] == "CVE-2023-1234"
        assert d["epss_score"] == 0.3
        assert d["percentile"] == 0.8
        assert d["risk_category"] == "high"
        assert d["fetched_at"] == "2025-01-15T10:00:00+00:00"

    def test_from_dict(self):
        """Test deserialization from dictionary."""
        data = {
            "cve_id": "CVE-2023-5678",
            "epss_score": 0.15,
            "percentile": 0.65,
            "risk_category": "medium",
            "fetched_at": "2025-06-01T12:00:00+00:00",
        }
        score = EPSSScore.from_dict(data)
        assert score.cve_id == "CVE-2023-5678"
        assert score.epss_score == 0.15
        assert score.percentile == 0.65
        assert score.risk_category == "medium"

    def test_to_dict_from_dict_roundtrip(self):
        """Test that to_dict -> from_dict produces an equivalent object."""
        original = EPSSScore(
            cve_id="CVE-2024-9999",
            epss_score=0.42,
            percentile=0.88,
            risk_category="high",
            fetched_at="2025-03-20T08:30:00+00:00",
        )
        reconstructed = EPSSScore.from_dict(original.to_dict())
        assert original.cve_id == reconstructed.cve_id
        assert original.epss_score == reconstructed.epss_score
        assert original.percentile == reconstructed.percentile
        assert original.risk_category == reconstructed.risk_category
        assert original.fetched_at == reconstructed.fetched_at


# ---------------------------------------------------------------------------
# EPSSCache tests
# ---------------------------------------------------------------------------


class TestEPSSCache:
    """Test EPSSCache get/put/put_batch, TTL, and persistence."""

    def test_put_and_get(self, tmp_path):
        """Test storing and retrieving a single score."""
        cache = EPSSCache(cache_dir=str(tmp_path), ttl_hours=24)
        score = EPSSScore(
            cve_id="CVE-2023-1111",
            epss_score=0.25,
            percentile=0.7,
            risk_category="high",
        )
        cache.put("CVE-2023-1111", score)

        result = cache.get("CVE-2023-1111")
        assert result is not None
        assert result.cve_id == "CVE-2023-1111"
        assert result.epss_score == 0.25

    def test_get_missing_key(self, tmp_path):
        """Test that getting a non-existent key returns None."""
        cache = EPSSCache(cache_dir=str(tmp_path), ttl_hours=24)
        assert cache.get("CVE-DOES-NOT-EXIST") is None

    def test_put_batch(self, tmp_path):
        """Test batch insertion of multiple scores."""
        cache = EPSSCache(cache_dir=str(tmp_path), ttl_hours=24)
        scores = {
            "CVE-2023-0001": EPSSScore(
                cve_id="CVE-2023-0001",
                epss_score=0.1,
                percentile=0.4,
                risk_category="medium",
            ),
            "CVE-2023-0002": EPSSScore(
                cve_id="CVE-2023-0002",
                epss_score=0.6,
                percentile=0.95,
                risk_category="critical",
            ),
            "CVE-2023-0003": EPSSScore(
                cve_id="CVE-2023-0003",
                epss_score=0.01,
                percentile=0.1,
                risk_category="low",
            ),
        }
        cache.put_batch(scores)

        for cve_id in scores:
            result = cache.get(cve_id)
            assert result is not None
            assert result.cve_id == cve_id

    def test_put_batch_empty(self, tmp_path):
        """Test that batch insertion of empty dict is a no-op."""
        cache = EPSSCache(cache_dir=str(tmp_path), ttl_hours=24)
        cache.put_batch({})
        # Should not raise

    def test_cache_ttl_expiration(self, tmp_path):
        """Test that expired entries are evicted on get."""
        cache = EPSSCache(cache_dir=str(tmp_path), ttl_hours=1)

        # Create a score with a timestamp 2 hours in the past
        old_time = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        ).isoformat()
        score = EPSSScore(
            cve_id="CVE-2023-OLD",
            epss_score=0.3,
            percentile=0.7,
            risk_category="high",
            fetched_at=old_time,
        )
        cache.put("CVE-2023-OLD", score)

        # Should return None because the entry is expired
        result = cache.get("CVE-2023-OLD")
        assert result is None

    def test_cache_not_expired(self, tmp_path):
        """Test that fresh entries are returned correctly."""
        cache = EPSSCache(cache_dir=str(tmp_path), ttl_hours=24)
        recent_time = datetime.now(timezone.utc).isoformat()
        score = EPSSScore(
            cve_id="CVE-2023-FRESH",
            epss_score=0.2,
            percentile=0.6,
            risk_category="medium",
            fetched_at=recent_time,
        )
        cache.put("CVE-2023-FRESH", score)

        result = cache.get("CVE-2023-FRESH")
        assert result is not None
        assert result.cve_id == "CVE-2023-FRESH"

    def test_is_expired_missing_timestamp(self, tmp_path):
        """Test that entries without fetched_at are considered expired."""
        cache = EPSSCache(cache_dir=str(tmp_path), ttl_hours=24)
        assert cache.is_expired({}) is True
        assert cache.is_expired({"fetched_at": ""}) is True

    def test_is_expired_invalid_timestamp(self, tmp_path):
        """Test that entries with invalid timestamps are considered expired."""
        cache = EPSSCache(cache_dir=str(tmp_path), ttl_hours=24)
        assert cache.is_expired({"fetched_at": "not-a-date"}) is True

    def test_file_persistence_save_load(self, tmp_path):
        """Test that cache data survives save/load cycle."""
        cache_dir = str(tmp_path)

        # Create and populate cache
        cache1 = EPSSCache(cache_dir=cache_dir, ttl_hours=24)
        score = EPSSScore(
            cve_id="CVE-2023-PERSIST",
            epss_score=0.45,
            percentile=0.9,
            risk_category="high",
        )
        cache1.put("CVE-2023-PERSIST", score)

        # Create a new cache instance pointing to the same directory
        cache2 = EPSSCache(cache_dir=cache_dir, ttl_hours=24)
        result = cache2.get("CVE-2023-PERSIST")
        assert result is not None
        assert result.epss_score == 0.45
        assert result.risk_category == "high"

    def test_load_corrupted_cache(self, tmp_path):
        """Test that a corrupted cache file is handled gracefully."""
        cache_path = tmp_path / "epss_cache.json"
        cache_path.write_text("NOT VALID JSON {{{", encoding="utf-8")

        cache = EPSSCache(cache_dir=str(tmp_path), ttl_hours=24)
        # Should initialize with empty cache, not raise
        assert cache.get("CVE-2023-0001") is None


# ---------------------------------------------------------------------------
# EPSSScorer tests
# ---------------------------------------------------------------------------


class TestEPSSScorer:
    """Test EPSSScorer categorization, fetching, enrichment, and summary."""

    def test_categorize_score_critical(self):
        """Test that scores > 0.5 are categorized as critical."""
        assert EPSSScorer._categorize_score(0.6) == "critical"
        assert EPSSScorer._categorize_score(0.51) == "critical"
        assert EPSSScorer._categorize_score(1.0) == "critical"

    def test_categorize_score_high(self):
        """Test that scores > 0.2 and <= 0.5 are categorized as high."""
        assert EPSSScorer._categorize_score(0.3) == "high"
        assert EPSSScorer._categorize_score(0.21) == "high"
        assert EPSSScorer._categorize_score(0.5) == "high"

    def test_categorize_score_medium(self):
        """Test that scores > 0.05 and <= 0.2 are categorized as medium."""
        assert EPSSScorer._categorize_score(0.1) == "medium"
        assert EPSSScorer._categorize_score(0.06) == "medium"
        assert EPSSScorer._categorize_score(0.2) == "medium"

    def test_categorize_score_low(self):
        """Test that scores <= 0.05 are categorized as low."""
        assert EPSSScorer._categorize_score(0.02) == "low"
        assert EPSSScorer._categorize_score(0.05) == "low"
        assert EPSSScorer._categorize_score(0.0) == "low"

    @patch("epss_scorer.urllib.request.urlopen")
    def test_fetch_scores_mocked_api(self, mock_urlopen, tmp_path):
        """Test fetch_scores with mocked API response."""
        api_response = {
            "status": "OK",
            "status-code": 200,
            "version": "1.0",
            "total": 2,
            "data": [
                {"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99961"},
                {"cve": "CVE-2023-1234", "epss": "0.08200", "percentile": "0.55000"},
            ],
        }
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(api_response).encode("utf-8")
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        results = scorer.fetch_scores(["CVE-2021-44228", "CVE-2023-1234"])

        assert len(results) == 2
        assert "CVE-2021-44228" in results
        assert results["CVE-2021-44228"].epss_score == pytest.approx(0.97565)
        assert results["CVE-2021-44228"].risk_category == "critical"
        assert "CVE-2023-1234" in results
        assert results["CVE-2023-1234"].epss_score == pytest.approx(0.082)
        assert results["CVE-2023-1234"].risk_category == "medium"

    @patch("epss_scorer.urllib.request.urlopen")
    def test_fetch_scores_uses_cache(self, mock_urlopen, tmp_path):
        """Test that cached scores are returned without API calls."""
        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)

        # Pre-populate cache
        cached_score = EPSSScore(
            cve_id="CVE-2023-CACHED",
            epss_score=0.55,
            percentile=0.92,
            risk_category="critical",
        )
        scorer.cache.put("CVE-2023-CACHED", cached_score)

        results = scorer.fetch_scores(["CVE-2023-CACHED"])

        assert len(results) == 1
        assert results["CVE-2023-CACHED"].epss_score == 0.55
        # API should NOT have been called
        mock_urlopen.assert_not_called()

    @patch("epss_scorer.urllib.request.urlopen")
    def test_fetch_scores_batch_splitting(self, mock_urlopen, tmp_path):
        """Test that >100 CVEs are split into multiple batches."""
        # Generate 150 CVEs
        cve_ids = [f"CVE-2023-{i:04d}" for i in range(150)]

        # Mock returns empty data each time
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(
            {"status": "OK", "data": []}
        ).encode("utf-8")
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        scorer.fetch_scores(cve_ids)

        # Should have made 2 API calls (100 + 50)
        assert mock_urlopen.call_count == 2

    @patch("epss_scorer.urllib.request.urlopen")
    def test_fetch_scores_api_failure_graceful(self, mock_urlopen, tmp_path):
        """Test graceful degradation when API fails."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        results = scorer.fetch_scores(["CVE-2023-0001", "CVE-2023-0002"])

        # Should return empty dict, not raise exception
        assert results == {}

    @patch("epss_scorer.urllib.request.urlopen")
    def test_fetch_scores_json_parse_error(self, mock_urlopen, tmp_path):
        """Test graceful handling of invalid JSON from API."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"<html>Not JSON</html>"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        results = scorer.fetch_scores(["CVE-2023-0001"])

        assert results == {}

    def test_fetch_scores_empty_input(self, tmp_path):
        """Test that empty input returns empty result without API calls."""
        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        results = scorer.fetch_scores([])
        assert results == {}

    @patch("epss_scorer.urllib.request.urlopen")
    def test_fetch_scores_deduplicates(self, mock_urlopen, tmp_path):
        """Test that duplicate CVE IDs are deduplicated before API call."""
        api_response = {
            "status": "OK",
            "data": [
                {"cve": "CVE-2023-0001", "epss": "0.10", "percentile": "0.50"},
            ],
        }
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(api_response).encode("utf-8")
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        results = scorer.fetch_scores(
            ["CVE-2023-0001", "CVE-2023-0001", "CVE-2023-0001"]
        )

        # Should only make 1 API call, not 3
        assert mock_urlopen.call_count == 1
        assert len(results) == 1

    @patch("epss_scorer.urllib.request.urlopen")
    def test_enrich_findings_adds_epss_data(self, mock_urlopen, tmp_path):
        """Test that enrich_findings adds EPSS fields to findings."""
        api_response = {
            "status": "OK",
            "data": [
                {"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99961"},
            ],
        }
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(api_response).encode("utf-8")
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        findings = [
            {"id": "f1", "cve_id": "CVE-2021-44228", "severity": "critical"},
            {"id": "f2", "title": "No CVE here"},
        ]

        enriched = scorer.enrich_findings(findings)

        assert len(enriched) == 2
        # First finding should have EPSS data
        assert enriched[0]["epss_score"] == pytest.approx(0.97565)
        assert enriched[0]["epss_percentile"] == pytest.approx(0.99961)
        assert enriched[0]["epss_risk_category"] == "critical"
        # Second finding should NOT have EPSS data
        assert "epss_score" not in enriched[1]

    def test_enrich_findings_skips_no_cve(self, tmp_path):
        """Test that findings without cve_id are passed through unchanged."""
        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        findings = [
            {"id": "f1", "title": "SAST finding, no CVE"},
            {"id": "f2", "title": "Another non-CVE finding"},
        ]

        enriched = scorer.enrich_findings(findings)

        assert len(enriched) == 2
        assert "epss_score" not in enriched[0]
        assert "epss_score" not in enriched[1]

    def test_enrich_findings_empty_list(self, tmp_path):
        """Test that empty findings list is returned as-is."""
        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        result = scorer.enrich_findings([])
        assert result == []

    def test_get_summary_with_scores(self, tmp_path):
        """Test summary generation with multiple scores."""
        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        scores = {
            "CVE-2023-0001": EPSSScore(
                cve_id="CVE-2023-0001",
                epss_score=0.8,
                percentile=0.98,
                risk_category="critical",
            ),
            "CVE-2023-0002": EPSSScore(
                cve_id="CVE-2023-0002",
                epss_score=0.3,
                percentile=0.85,
                risk_category="high",
            ),
            "CVE-2023-0003": EPSSScore(
                cve_id="CVE-2023-0003",
                epss_score=0.1,
                percentile=0.55,
                risk_category="medium",
            ),
            "CVE-2023-0004": EPSSScore(
                cve_id="CVE-2023-0004",
                epss_score=0.02,
                percentile=0.2,
                risk_category="low",
            ),
        }

        summary = scorer.get_summary(scores)

        assert summary["total_scored"] == 4
        assert summary["by_category"]["critical"] == 1
        assert summary["by_category"]["high"] == 1
        assert summary["by_category"]["medium"] == 1
        assert summary["by_category"]["low"] == 1
        assert summary["average_score"] == pytest.approx(0.305, rel=1e-3)
        # Highest risk should be sorted by score descending
        assert len(summary["highest_risk"]) == 4
        assert summary["highest_risk"][0]["cve_id"] == "CVE-2023-0001"
        assert summary["highest_risk"][0]["epss_score"] == 0.8

    def test_get_summary_top_5_limit(self, tmp_path):
        """Test that highest_risk is limited to top 5."""
        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        scores = {}
        for i in range(10):
            cve_id = f"CVE-2023-{i:04d}"
            val = (i + 1) * 0.05
            scores[cve_id] = EPSSScore(
                cve_id=cve_id,
                epss_score=min(val, 1.0),
                percentile=0.5,
                risk_category=EPSSScorer._categorize_score(min(val, 1.0)),
            )

        summary = scorer.get_summary(scores)

        assert summary["total_scored"] == 10
        assert len(summary["highest_risk"]) == 5
        # First entry should be the highest score
        assert summary["highest_risk"][0]["epss_score"] >= summary["highest_risk"][1]["epss_score"]

    def test_get_summary_empty_scores(self, tmp_path):
        """Test summary with empty scores dict."""
        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        summary = scorer.get_summary({})

        assert summary["total_scored"] == 0
        assert summary["by_category"]["critical"] == 0
        assert summary["by_category"]["high"] == 0
        assert summary["by_category"]["medium"] == 0
        assert summary["by_category"]["low"] == 0
        assert summary["average_score"] == 0.0
        assert summary["highest_risk"] == []

    @patch("epss_scorer.urllib.request.urlopen")
    def test_fetch_batch_non_200_status(self, mock_urlopen, tmp_path):
        """Test that non-200 HTTP status returns empty dict."""
        mock_response = MagicMock()
        mock_response.status = 503
        mock_response.read.return_value = b'{"error": "Service Unavailable"}'
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        results = scorer._fetch_batch(["CVE-2023-0001"])

        assert results == {}

    def test_fetch_batch_empty_input(self, tmp_path):
        """Test that _fetch_batch with empty list returns empty dict."""
        scorer = EPSSScorer(cache_dir=str(tmp_path), ttl_hours=24)
        results = scorer._fetch_batch([])
        assert results == {}
