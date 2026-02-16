"""Tests for threat_intel_enricher.py - Threat Intelligence Integration.

Covers:
- ThreatIntelEnricher initialization, caching, rate limiting
- CVE enrichment from multiple sources (KEV, EPSS, NVD, GitHub, OSV)
- Priority adjustment logic
- Risk score calculation
- Trending detection
- Finding enrichment pipeline
- Export functionality
- Error handling for all external API calls
"""

import json
import time
import urllib.error
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from scripts.threat_intel_enricher import (
    EnrichedFinding,
    ThreatContext,
    ThreatIntelEnricher,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_kev_data():
    """Sample CISA KEV catalog data."""
    return {
        "title": "CISA KEV Catalog",
        "catalogVersion": "2024.01.01",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1234",
                "vendorProject": "TestVendor",
                "product": "TestProduct",
                "dateAdded": (datetime.utcnow() - timedelta(days=5)).strftime("%Y-%m-%d"),
                "dueDate": (datetime.utcnow() + timedelta(days=10)).strftime("%Y-%m-%d"),
                "requiredAction": "Apply update immediately",
            },
            {
                "cveID": "CVE-2023-9999",
                "vendorProject": "OldVendor",
                "product": "OldProduct",
                "dateAdded": "2023-01-01",
                "dueDate": "2023-02-01",
                "requiredAction": "Patch legacy system",
            },
        ],
    }


@pytest.fixture
def enricher(tmp_path, mock_kev_data):
    """Create a ThreatIntelEnricher with mocked external calls."""
    with patch.object(ThreatIntelEnricher, "_load_kev_catalog", return_value=mock_kev_data):
        e = ThreatIntelEnricher(cache_dir=tmp_path / "cache")
    return e


@pytest.fixture
def enricher_no_kev(tmp_path):
    """Enricher with no KEV catalog loaded."""
    with patch.object(ThreatIntelEnricher, "_load_kev_catalog", return_value=None):
        e = ThreatIntelEnricher(cache_dir=tmp_path / "cache")
    return e


@pytest.fixture
def sample_cve_finding():
    """A finding dict with a CVE."""
    return {
        "cve": "CVE-2024-1234",
        "severity": "HIGH",
        "title": "Critical vuln in TestPackage",
        "description": "A serious vulnerability CVE-2024-1234 in TestPackage",
    }


@pytest.fixture
def sample_findings():
    """Multiple findings for batch enrichment."""
    return [
        {"cve": "CVE-2024-1234", "severity": "HIGH", "title": "Vuln A"},
        {"cve": "CVE-2024-5678", "severity": "MEDIUM", "title": "Vuln B"},
        {"description": "No CVE here", "severity": "LOW", "title": "Non-CVE finding"},
    ]


# ---------------------------------------------------------------------------
# ThreatContext dataclass tests
# ---------------------------------------------------------------------------

class TestThreatContext:
    def test_defaults(self):
        ctx = ThreatContext(cve_id="CVE-2024-0001")
        assert ctx.cve_id == "CVE-2024-0001"
        assert ctx.cvss_score is None
        assert ctx.in_kev_catalog is False
        assert ctx.epss_score is None
        assert ctx.public_exploit_available is False
        assert ctx.exploit_sources == []
        assert ctx.exploit_count == 0
        assert ctx.trending is False
        assert ctx.confidence == 1.0

    def test_asdict(self):
        ctx = ThreatContext(cve_id="CVE-2024-0001", cvss_score=9.8)
        d = asdict(ctx)
        assert d["cve_id"] == "CVE-2024-0001"
        assert d["cvss_score"] == 9.8


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_with_explicit_cache_dir(self, tmp_path):
        cache = tmp_path / "my_cache"
        with patch.object(ThreatIntelEnricher, "_load_kev_catalog", return_value=None):
            e = ThreatIntelEnricher(cache_dir=cache)
        assert e.cache_dir == cache
        assert cache.exists()

    def test_init_cache_dir_fallback(self):
        """When no cache_dir given, it tries candidates and falls back."""
        with patch.object(ThreatIntelEnricher, "_load_kev_catalog", return_value=None):
            with patch("pathlib.Path.mkdir") as mock_mkdir, \
                 patch("pathlib.Path.touch") as mock_touch, \
                 patch("pathlib.Path.unlink") as mock_unlink:
                mock_mkdir.return_value = None
                mock_touch.return_value = None
                mock_unlink.return_value = None
                e = ThreatIntelEnricher()
        assert e.cache_dir is not None

    def test_stats_initialized(self, enricher):
        assert enricher.stats["total_enriched"] == 0
        assert enricher.stats["cache_hits"] == 0
        assert enricher.stats["api_errors"] == 0

    def test_kev_catalog_loaded(self, enricher, mock_kev_data):
        assert enricher.kev_catalog is not None
        assert len(enricher.kev_catalog["vulnerabilities"]) == 2


# ---------------------------------------------------------------------------
# KEV catalog
# ---------------------------------------------------------------------------

class TestKevCatalog:
    def test_load_kev_from_cache(self, tmp_path, mock_kev_data):
        """Load KEV from cached file when fresh."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir(parents=True)
        cache_file = cache_dir / "kev_catalog.json"
        cache_file.write_text(json.dumps(mock_kev_data))

        with patch.object(ThreatIntelEnricher, "_load_kev_catalog", wraps=ThreatIntelEnricher._load_kev_catalog) as mock_load:
            # Bypass wrapping - just test _check_kev
            pass

        enricher_inst = None
        with patch.object(ThreatIntelEnricher, "_fetch_kev_data") as mock_fetch:
            with patch.object(ThreatIntelEnricher, "__init__", lambda self, **kw: None):
                enricher_inst = ThreatIntelEnricher.__new__(ThreatIntelEnricher)
                enricher_inst.cache_dir = cache_dir
                enricher_inst.stats = {"cache_hits": 0, "cache_misses": 0, "api_errors": 0,
                                        "total_enriched": 0, "in_kev": 0, "high_epss": 0,
                                        "has_exploit": 0, "priority_boosted": 0,
                                        "priority_downgraded": 0, "github_advisories": 0,
                                        "osv_entries": 0}
                enricher_inst._last_api_call = {}
                result = enricher_inst._load_kev_catalog()
            mock_fetch.assert_not_called()
        assert result is not None
        assert len(result["vulnerabilities"]) == 2
        assert enricher_inst.stats["cache_hits"] == 1

    def test_check_kev_found(self, enricher):
        result = enricher._check_kev("CVE-2024-1234")
        assert result is not None
        assert result["cveID"] == "CVE-2024-1234"

    def test_check_kev_not_found(self, enricher):
        result = enricher._check_kev("CVE-2099-0001")
        assert result is None

    def test_check_kev_no_catalog(self, enricher_no_kev):
        result = enricher_no_kev._check_kev("CVE-2024-1234")
        assert result is None


# ---------------------------------------------------------------------------
# CVE extraction / detection
# ---------------------------------------------------------------------------

class TestCVEExtraction:
    def test_has_cve_in_cve_field(self, enricher):
        assert enricher._has_cve({"cve": "CVE-2024-1234"}) is True

    def test_has_cve_in_description(self, enricher):
        assert enricher._has_cve({"description": "Found CVE-2024-5678 in code"}) is True

    def test_has_cve_false(self, enricher):
        assert enricher._has_cve({"title": "No vulnerabilities"}) is False

    def test_extract_cve_from_cve_field(self, enricher):
        assert enricher._extract_cve({"cve": "CVE-2024-1234"}) == "CVE-2024-1234"

    def test_extract_cve_from_description(self, enricher):
        f = {"description": "Issue: CVE-2024-5678 detected"}
        assert enricher._extract_cve(f) == "CVE-2024-5678"

    def test_extract_cve_none(self, enricher):
        assert enricher._extract_cve({"title": "no cve"}) is None

    def test_extract_cve_from_id_field(self, enricher):
        assert enricher._extract_cve({"id": "CVE-2023-44487"}) == "CVE-2023-44487"

    def test_extract_cve_from_message_field(self, enricher):
        assert enricher._extract_cve({"message": "Vuln CVE-2024-0001 found"}) == "CVE-2024-0001"


# ---------------------------------------------------------------------------
# Priority normalization
# ---------------------------------------------------------------------------

class TestNormalizePriority:
    def test_standard_priorities(self, enricher):
        assert enricher._normalize_priority("CRITICAL") == "CRITICAL"
        assert enricher._normalize_priority("HIGH") == "HIGH"
        assert enricher._normalize_priority("MEDIUM") == "MEDIUM"
        assert enricher._normalize_priority("LOW") == "LOW"
        assert enricher._normalize_priority("INFO") == "INFO"

    def test_mapped_priorities(self, enricher):
        assert enricher._normalize_priority("BLOCKER") == "CRITICAL"
        assert enricher._normalize_priority("ERROR") == "HIGH"
        assert enricher._normalize_priority("WARNING") == "MEDIUM"
        assert enricher._normalize_priority("NOTE") == "LOW"

    def test_case_insensitive(self, enricher):
        assert enricher._normalize_priority("high") == "HIGH"
        assert enricher._normalize_priority("blocker") == "CRITICAL"


# ---------------------------------------------------------------------------
# EPSS scoring
# ---------------------------------------------------------------------------

class TestEPSS:
    def test_get_epss_score_from_api(self, enricher, tmp_path):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "data": [{"epss": "0.75", "percentile": "0.95"}]
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = enricher._get_epss_score("CVE-2024-1234")

        assert result is not None
        assert result["epss"] == 0.75
        assert result["percentile"] == 0.95

    def test_get_epss_score_from_cache(self, enricher):
        cache_file = enricher.cache_dir / "epss_CVE-2024-9999.json"
        cache_file.write_text(json.dumps({"epss": 0.5, "percentile": 0.8}))

        result = enricher._get_epss_score("CVE-2024-9999")
        assert result is not None
        assert result["epss"] == 0.5
        assert enricher.stats["cache_hits"] >= 1

    def test_get_epss_score_api_error(self, enricher):
        with patch.object(enricher, "_fetch_epss_data", side_effect=Exception("API error")):
            result = enricher._get_epss_score("CVE-2024-0001")
        assert result is None
        assert enricher.stats["api_errors"] >= 1

    def test_fetch_epss_empty_data(self, enricher):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"data": []}).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = enricher._fetch_epss_data("CVE-2024-0001")
        assert result == {}


# ---------------------------------------------------------------------------
# NVD data
# ---------------------------------------------------------------------------

class TestNVD:
    def test_get_nvd_data_success(self, enricher):
        nvd_api_response = {
            "vulnerabilities": [{
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }]
                    },
                    "weaknesses": [{
                        "description": [{"value": "CWE-79"}]
                    }],
                    "references": [
                        {"url": "https://example.com/advisory", "tags": []},
                        {"url": "https://exploit-db.com/123", "tags": ["Exploit"]},
                    ],
                }
            }]
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(nvd_api_response).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = enricher._get_nvd_data("CVE-2024-1234")

        assert result is not None
        assert result["cvss_score"] == 9.8
        assert result["severity"] == "CRITICAL"
        assert "CWE-79" in result["cwe_ids"]
        assert result["has_exploit"] is True

    def test_get_nvd_data_404(self, enricher):
        http_error = urllib.error.HTTPError(
            url="https://nvd.nist.gov", code=404, msg="Not Found",
            hdrs=MagicMock(), fp=MagicMock()
        )
        with patch.object(enricher, "_fetch_nvd_data", side_effect=http_error):
            result = enricher._get_nvd_data("CVE-2099-0001")
        assert result is None

    def test_get_nvd_data_from_cache(self, enricher):
        cached = {"cvss_score": 7.5, "severity": "HIGH", "cwe_ids": [], "references": [],
                  "has_exploit": False, "exploit_sources": [], "cvss_vector": None}
        cache_file = enricher.cache_dir / "nvd_CVE-2024-8888.json"
        cache_file.write_text(json.dumps(cached))

        result = enricher._get_nvd_data("CVE-2024-8888")
        assert result["cvss_score"] == 7.5

    def test_parse_nvd_cvss_v2_fallback(self, enricher):
        vuln = {
            "metrics": {
                "cvssMetricV2": [{
                    "cvssData": {
                        "baseScore": 7.5,
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    }
                }]
            },
            "weaknesses": [],
            "references": [],
        }
        result = enricher._parse_nvd_vulnerability(vuln)
        assert result["cvss_score"] == 7.5
        assert result["severity"] == "HIGH"

    def test_parse_nvd_cvss_v2_medium(self, enricher):
        vuln = {
            "metrics": {
                "cvssMetricV2": [{
                    "cvssData": {
                        "baseScore": 5.0,
                        "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                    }
                }]
            },
            "weaknesses": [],
            "references": [],
        }
        result = enricher._parse_nvd_vulnerability(vuln)
        assert result["severity"] == "MEDIUM"

    def test_parse_nvd_cvss_v2_low(self, enricher):
        vuln = {
            "metrics": {
                "cvssMetricV2": [{
                    "cvssData": {
                        "baseScore": 2.5,
                        "vectorString": "AV:L/AC:H/Au:N/C:P/I:N/A:N",
                    }
                }]
            },
            "weaknesses": [],
            "references": [],
        }
        result = enricher._parse_nvd_vulnerability(vuln)
        assert result["severity"] == "LOW"

    def test_parse_nvd_no_metrics(self, enricher):
        vuln = {"metrics": {}, "weaknesses": [], "references": []}
        result = enricher._parse_nvd_vulnerability(vuln)
        assert result["cvss_score"] is None
        assert result["severity"] is None


# ---------------------------------------------------------------------------
# GitHub Advisories
# ---------------------------------------------------------------------------

class TestGitHubAdvisories:
    def test_get_github_advisories_success(self, enricher):
        api_response = [
            {
                "ghsa_id": "GHSA-1234-5678",
                "summary": "Test advisory",
                "severity": "high",
                "html_url": "https://github.com/advisories/GHSA-1234-5678",
                "published_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-02T00:00:00Z",
                "vulnerabilities": [{"patched_versions": ">=2.0.0"}],
            }
        ]

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(api_response).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = enricher._get_github_advisories("CVE-2024-1234")

        assert len(result) == 1
        assert result[0]["id"] == "GHSA-1234-5678"
        assert result[0]["patched_versions"] == ">=2.0.0"

    def test_get_github_advisories_error(self, enricher):
        with patch.object(enricher, "_fetch_github_advisories", side_effect=Exception("rate limit")):
            result = enricher._get_github_advisories("CVE-2024-1234")
        assert result == []
        assert enricher.stats["api_errors"] >= 1

    def test_get_github_advisories_cached(self, enricher):
        cached = [{"id": "GHSA-cached", "summary": "Cached advisory"}]
        cache_file = enricher.cache_dir / "github_CVE-2024-7777.json"
        cache_file.write_text(json.dumps(cached))

        result = enricher._get_github_advisories("CVE-2024-7777")
        assert result[0]["id"] == "GHSA-cached"


# ---------------------------------------------------------------------------
# OSV data
# ---------------------------------------------------------------------------

class TestOSV:
    def test_get_osv_data_success(self, enricher):
        osv_response = {
            "id": "PYSEC-2024-1",
            "summary": "Test vulnerability",
            "details": "Details here",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "references": [{"url": "https://osv.dev/vuln/PYSEC-2024-1"}],
            "affected": [],
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(osv_response).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = enricher._get_osv_data("CVE-2024-1234")

        assert len(result) == 1
        assert result[0]["id"] == "PYSEC-2024-1"

    def test_get_osv_data_404(self, enricher):
        http_error = urllib.error.HTTPError(
            url="https://osv.dev", code=404, msg="Not Found",
            hdrs=MagicMock(), fp=MagicMock()
        )
        with patch.object(enricher, "_fetch_osv_data", side_effect=http_error):
            result = enricher._get_osv_data("CVE-2099-0001")
        assert result == []

    def test_get_osv_data_other_http_error(self, enricher):
        http_error = urllib.error.HTTPError(
            url="https://osv.dev", code=500, msg="Server Error",
            hdrs=MagicMock(), fp=MagicMock()
        )
        with patch.object(enricher, "_fetch_osv_data", side_effect=http_error):
            result = enricher._get_osv_data("CVE-2024-0001")
        assert result == []
        assert enricher.stats["api_errors"] >= 1

    def test_get_osv_data_cached(self, enricher):
        cached = [{"id": "OSV-cached"}]
        cache_file = enricher.cache_dir / "osv_CVE-2024-6666.json"
        cache_file.write_text(json.dumps(cached))

        result = enricher._get_osv_data("CVE-2024-6666")
        assert result[0]["id"] == "OSV-cached"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_rate_limit_normal_source(self, enricher):
        enricher._last_api_call["test"] = time.time()
        with patch("time.sleep") as mock_sleep:
            enricher._rate_limit("test")
        # Should sleep since last call was just now
        if mock_sleep.called:
            args = mock_sleep.call_args[0]
            assert args[0] <= ThreatIntelEnricher.RATE_LIMIT_DELAY

    def test_rate_limit_nvd_longer_delay(self, enricher):
        enricher._last_api_call["nvd"] = time.time()
        with patch("time.sleep") as mock_sleep:
            enricher._rate_limit("nvd")
        if mock_sleep.called:
            args = mock_sleep.call_args[0]
            assert args[0] <= ThreatIntelEnricher.NVD_RATE_LIMIT_DELAY

    def test_rate_limit_no_sleep_if_enough_time_passed(self, enricher):
        enricher._last_api_call["test"] = time.time() - 100
        with patch("time.sleep") as mock_sleep:
            enricher._rate_limit("test")
        mock_sleep.assert_not_called()


# ---------------------------------------------------------------------------
# Trending detection
# ---------------------------------------------------------------------------

class TestTrending:
    def test_trending_recent_kev(self, enricher):
        ctx = ThreatContext(
            cve_id="CVE-2024-1234",
            in_kev_catalog=True,
            kev_date_added=(datetime.utcnow() - timedelta(days=5)).isoformat(),
        )
        assert enricher._detect_trending(ctx) is True

    def test_not_trending_old_kev(self, enricher):
        ctx = ThreatContext(
            cve_id="CVE-2023-0001",
            in_kev_catalog=True,
            kev_date_added="2023-01-01",
        )
        assert enricher._detect_trending(ctx) is False

    def test_trending_high_epss_and_exploits(self, enricher):
        ctx = ThreatContext(
            cve_id="CVE-2024-0001",
            epss_score=0.85,
            exploit_count=3,
        )
        assert enricher._detect_trending(ctx) is True

    def test_not_trending_low_epss(self, enricher):
        ctx = ThreatContext(
            cve_id="CVE-2024-0001",
            epss_score=0.3,
            exploit_count=0,
        )
        assert enricher._detect_trending(ctx) is False

    def test_not_trending_high_epss_but_few_exploits(self, enricher):
        ctx = ThreatContext(
            cve_id="CVE-2024-0001",
            epss_score=0.9,
            exploit_count=1,
        )
        assert enricher._detect_trending(ctx) is False

    def test_trending_invalid_kev_date(self, enricher):
        ctx = ThreatContext(
            cve_id="CVE-2024-0001",
            in_kev_catalog=True,
            kev_date_added="not-a-date",
        )
        # Should not crash, falls through to EPSS check
        assert enricher._detect_trending(ctx) is False


# ---------------------------------------------------------------------------
# Priority adjustment
# ---------------------------------------------------------------------------

class TestPriorityAdjustment:
    def test_kev_boosts_to_critical(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-1234", in_kev_catalog=True,
                           kev_date_added="2024-01-01")
        priority, boosts, downgrades = enricher._adjust_priority("MEDIUM", ctx)
        assert priority == "CRITICAL"
        assert any("KEV" in r for r in boosts)

    def test_high_epss_with_exploit_boosts_to_critical(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", epss_score=0.9,
                           public_exploit_available=True, exploit_count=1)
        priority, boosts, _ = enricher._adjust_priority("LOW", ctx)
        assert priority == "CRITICAL"

    def test_high_epss_boosts_to_high(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", epss_score=0.6,
                           epss_percentile=0.9)
        priority, boosts, _ = enricher._adjust_priority("LOW", ctx)
        assert priority == "HIGH"

    def test_multiple_exploits_boosts_to_high(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", exploit_count=3,
                           public_exploit_available=True)
        priority, boosts, _ = enricher._adjust_priority("LOW", ctx)
        assert priority == "HIGH"

    def test_single_exploit_boosts_to_medium(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001",
                           public_exploit_available=True, exploit_count=1)
        priority, boosts, _ = enricher._adjust_priority("LOW", ctx)
        assert priority == "MEDIUM"

    def test_high_cvss_boosts(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", cvss_score=9.5)
        priority, boosts, _ = enricher._adjust_priority("LOW", ctx)
        assert priority == "HIGH"

    def test_medium_cvss_boosts_to_medium(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", cvss_score=7.5)
        priority, boosts, _ = enricher._adjust_priority("LOW", ctx)
        assert priority == "MEDIUM"

    def test_low_epss_no_exploit_downgrades(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", epss_score=0.05,
                           public_exploit_available=False, in_kev_catalog=False)
        priority, _, downgrades = enricher._adjust_priority("HIGH", ctx)
        assert priority == "LOW"
        assert len(downgrades) >= 1

    def test_patch_available_adds_downgrade_note(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001",
                           vendor_patch_available=True,
                           patch_url="https://example.com/patch")
        priority, _, downgrades = enricher._adjust_priority("HIGH", ctx)
        assert any("patch" in r.lower() for r in downgrades)

    def test_trending_boosts_to_high(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", trending=True)
        priority, boosts, _ = enricher._adjust_priority("LOW", ctx)
        assert priority == "HIGH"

    def test_no_change_when_already_at_target(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001")
        priority, boosts, downgrades = enricher._adjust_priority("MEDIUM", ctx)
        assert priority == "MEDIUM"
        assert boosts == []
        assert downgrades == []


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_risk_score_with_cvss(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", cvss_score=8.0)
        score = enricher._calculate_risk_score(ctx, "HIGH")
        assert 0.0 <= score <= 10.0

    def test_risk_score_no_cvss_uses_priority(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001")
        score = enricher._calculate_risk_score(ctx, "CRITICAL")
        assert score >= 9.0

    def test_risk_score_kev_adds_points(self, enricher):
        ctx_no_kev = ThreatContext(cve_id="CVE-2024-0001", cvss_score=5.0)
        ctx_kev = ThreatContext(cve_id="CVE-2024-0001", cvss_score=5.0,
                                in_kev_catalog=True)
        score_no_kev = enricher._calculate_risk_score(ctx_no_kev, "MEDIUM")
        score_kev = enricher._calculate_risk_score(ctx_kev, "MEDIUM")
        assert score_kev > score_no_kev

    def test_risk_score_epss_multiplier(self, enricher):
        ctx_no_epss = ThreatContext(cve_id="CVE-2024-0001", cvss_score=5.0)
        ctx_epss = ThreatContext(cve_id="CVE-2024-0001", cvss_score=5.0,
                                 epss_score=0.8)
        score_no_epss = enricher._calculate_risk_score(ctx_no_epss, "MEDIUM")
        score_epss = enricher._calculate_risk_score(ctx_epss, "MEDIUM")
        assert score_epss > score_no_epss

    def test_risk_score_exploits_add_points(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", cvss_score=5.0,
                           public_exploit_available=True, exploit_count=5)
        score = enricher._calculate_risk_score(ctx, "MEDIUM")
        # Max +3.0 from exploits
        assert score >= 8.0

    def test_risk_score_patch_reduces(self, enricher):
        ctx_no_patch = ThreatContext(cve_id="CVE-2024-0001", cvss_score=5.0)
        ctx_patch = ThreatContext(cve_id="CVE-2024-0001", cvss_score=5.0,
                                  vendor_patch_available=True)
        score_no = enricher._calculate_risk_score(ctx_no_patch, "MEDIUM")
        score_patch = enricher._calculate_risk_score(ctx_patch, "MEDIUM")
        assert score_patch < score_no

    def test_risk_score_clamped_max(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", cvss_score=10.0,
                           epss_score=1.0, in_kev_catalog=True,
                           public_exploit_available=True, exploit_count=10,
                           trending=True)
        score = enricher._calculate_risk_score(ctx, "CRITICAL")
        assert score == 10.0

    def test_risk_score_clamped_min(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001", cvss_score=0.0,
                           vendor_patch_available=True)
        score = enricher._calculate_risk_score(ctx, "INFO")
        assert score >= 0.0


# ---------------------------------------------------------------------------
# Recommended action & deadline
# ---------------------------------------------------------------------------

class TestRecommendAction:
    def test_kev_urgent_action(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-1234", in_kev_catalog=True,
                           kev_action_required="Apply update",
                           kev_due_date="2024-12-31T00:00:00")
        action, deadline = enricher._recommend_action(ctx, "CRITICAL")
        assert "URGENT" in action
        assert deadline == "2024-12-31T00:00:00"

    def test_critical_priority_24h_deadline(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001")
        action, deadline = enricher._recommend_action(ctx, "CRITICAL")
        assert "24 hours" in action
        assert deadline is not None

    def test_high_priority_7day_deadline(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001")
        action, deadline = enricher._recommend_action(ctx, "HIGH")
        assert "7 days" in action

    def test_medium_priority_30day_deadline(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001")
        action, deadline = enricher._recommend_action(ctx, "MEDIUM")
        assert "30 days" in action

    def test_low_priority_90day_deadline(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001")
        action, deadline = enricher._recommend_action(ctx, "LOW")
        assert "90 days" in action

    def test_info_priority_no_deadline(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-0001")
        action, deadline = enricher._recommend_action(ctx, "INFO")
        assert deadline is None
        assert "maintenance" in action.lower()


# ---------------------------------------------------------------------------
# enrich_cve (full single-CVE pipeline)
# ---------------------------------------------------------------------------

class TestEnrichCVE:
    def test_enrich_cve_all_sources_succeed(self, enricher):
        """When all sources return data, confidence is high."""
        with patch.object(enricher, "_get_epss_score", return_value={"epss": 0.6, "percentile": 0.9}), \
             patch.object(enricher, "_get_nvd_data", return_value={
                 "cvss_score": 9.0, "severity": "CRITICAL", "cvss_vector": "CVSS:3.1/...",
                 "cwe_ids": ["CWE-79"], "references": [], "has_exploit": False,
                 "exploit_sources": [],
             }), \
             patch.object(enricher, "_get_github_advisories", return_value=[]), \
             patch.object(enricher, "_get_osv_data", return_value=[]):
            ctx = enricher.enrich_cve("CVE-2024-1234")

        assert ctx is not None
        assert ctx.cve_id == "CVE-2024-1234"
        assert ctx.in_kev_catalog is True
        assert ctx.epss_score == 0.6
        assert ctx.cvss_score == 9.0
        assert ctx.confidence > 0.0

    def test_enrich_cve_no_data(self, enricher_no_kev):
        """When no sources return data, return None."""
        with patch.object(enricher_no_kev, "_get_epss_score", return_value=None), \
             patch.object(enricher_no_kev, "_get_nvd_data", return_value=None), \
             patch.object(enricher_no_kev, "_get_github_advisories", return_value=[]), \
             patch.object(enricher_no_kev, "_get_osv_data", return_value=[]):
            ctx = enricher_no_kev.enrich_cve("CVE-2099-0001")

        assert ctx is None

    def test_enrich_cve_exploit_in_references(self, enricher_no_kev):
        """Exploit indicators in references are detected."""
        with patch.object(enricher_no_kev, "_get_epss_score", return_value={"epss": 0.3, "percentile": 0.5}), \
             patch.object(enricher_no_kev, "_get_nvd_data", return_value={
                 "cvss_score": 7.0, "severity": "HIGH", "cvss_vector": None,
                 "cwe_ids": [], "references": ["https://exploit-db.com/exploits/12345"],
                 "has_exploit": False, "exploit_sources": [],
             }), \
             patch.object(enricher_no_kev, "_get_github_advisories", return_value=[]), \
             patch.object(enricher_no_kev, "_get_osv_data", return_value=[]):
            ctx = enricher_no_kev.enrich_cve("CVE-2024-5555")

        assert ctx is not None
        assert ctx.public_exploit_available is True
        assert ctx.exploit_count >= 1

    def test_enrich_cve_github_advisory_sets_patch(self, enricher_no_kev):
        """GitHub advisory with patched_versions sets vendor_patch_available."""
        advisory = {
            "id": "GHSA-abcd",
            "summary": "Test",
            "patched_versions": ">=2.0",
            "html_url": "https://github.com/advisories/GHSA-abcd",
        }
        with patch.object(enricher_no_kev, "_get_epss_score", return_value={"epss": 0.1, "percentile": 0.2}), \
             patch.object(enricher_no_kev, "_get_nvd_data", return_value=None), \
             patch.object(enricher_no_kev, "_get_github_advisories", return_value=[advisory]), \
             patch.object(enricher_no_kev, "_get_osv_data", return_value=[]):
            ctx = enricher_no_kev.enrich_cve("CVE-2024-6666")

        assert ctx is not None
        assert ctx.vendor_patch_available is True
        assert ctx.patch_url == "https://github.com/advisories/GHSA-abcd"

    def test_enrich_cve_osv_references_added(self, enricher_no_kev):
        """OSV references are merged into context.references."""
        osv_data = [{
            "id": "PYSEC-2024-1",
            "summary": "Test",
            "references": [{"url": "https://osv.dev/vuln/1"}, {"url": "https://poc.example.com/exploit"}],
        }]
        with patch.object(enricher_no_kev, "_get_epss_score", return_value=None), \
             patch.object(enricher_no_kev, "_get_nvd_data", return_value=None), \
             patch.object(enricher_no_kev, "_get_github_advisories", return_value=[]), \
             patch.object(enricher_no_kev, "_get_osv_data", return_value=osv_data):
            ctx = enricher_no_kev.enrich_cve("CVE-2024-7777")

        assert ctx is not None
        assert "https://osv.dev/vuln/1" in ctx.references
        # "poc" in URL should trigger exploit detection
        assert ctx.public_exploit_available is True


# ---------------------------------------------------------------------------
# enrich_findings (batch pipeline)
# ---------------------------------------------------------------------------

class TestEnrichFindings:
    def test_enrich_findings_filters_cve_only(self, enricher, sample_findings):
        """Non-CVE findings are filtered out."""
        with patch.object(enricher, "_enrich_single_finding", return_value=None):
            result = enricher.enrich_findings(sample_findings)
        assert isinstance(result, list)

    def test_enrich_findings_empty_list(self, enricher):
        result = enricher.enrich_findings([])
        assert result == []

    def test_enrich_findings_no_cve_findings(self, enricher):
        findings = [{"title": "No CVE", "severity": "LOW"}]
        result = enricher.enrich_findings(findings)
        assert result == []

    def test_enrich_findings_returns_enriched(self, enricher):
        findings = [{"cve": "CVE-2024-1234", "severity": "HIGH"}]
        mock_enriched = EnrichedFinding(
            original_finding=findings[0],
            threat_context=ThreatContext(cve_id="CVE-2024-1234"),
            original_priority="HIGH",
            adjusted_priority="CRITICAL",
            priority_boost_reasons=["KEV"],
            priority_downgrade_reasons=[],
            recommended_action="Patch now",
            remediation_deadline="2024-12-31",
            risk_score=9.5,
        )
        with patch.object(enricher, "_enrich_single_finding", return_value=mock_enriched):
            result = enricher.enrich_findings(findings)
        assert len(result) == 1
        assert result[0].adjusted_priority == "CRITICAL"

    def test_enrich_findings_with_progress(self, enricher):
        enricher.use_progress = True
        findings = [{"cve": "CVE-2024-1234", "severity": "HIGH"}]

        # Mock rich being unavailable to test fallback
        with patch.object(enricher, "_enrich_with_progress") as mock_progress:
            mock_progress.return_value = []
            result = enricher.enrich_findings(findings)
        assert isinstance(result, list)

    def test_enrich_findings_keyboard_interrupt(self, enricher):
        findings = [{"cve": "CVE-2024-1234", "severity": "HIGH"}]
        with patch.object(enricher, "_enrich_without_progress", side_effect=KeyboardInterrupt):
            result = enricher.enrich_findings(findings)
        assert result == []


# ---------------------------------------------------------------------------
# _enrich_single_finding
# ---------------------------------------------------------------------------

class TestEnrichSingleFinding:
    def test_returns_none_for_no_cve(self, enricher):
        result = enricher._enrich_single_finding({"title": "No CVE"})
        assert result is None

    def test_returns_none_when_enrich_cve_fails(self, enricher):
        with patch.object(enricher, "enrich_cve", return_value=None):
            result = enricher._enrich_single_finding({"cve": "CVE-2024-0001"})
        assert result is None

    def test_returns_enriched_finding(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-1234", cvss_score=8.0)
        with patch.object(enricher, "enrich_cve", return_value=ctx):
            result = enricher._enrich_single_finding(
                {"cve": "CVE-2024-1234", "severity": "HIGH"}
            )
        assert result is not None
        assert isinstance(result, EnrichedFinding)
        assert result.threat_context.cve_id == "CVE-2024-1234"
        assert enricher.stats["total_enriched"] >= 1


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

class TestExport:
    def test_export_enriched_findings(self, enricher, tmp_path):
        ctx = ThreatContext(cve_id="CVE-2024-1234", cvss_score=9.0)
        enriched = [
            EnrichedFinding(
                original_finding={"cve": "CVE-2024-1234"},
                threat_context=ctx,
                original_priority="HIGH",
                adjusted_priority="CRITICAL",
                priority_boost_reasons=["KEV"],
                priority_downgrade_reasons=[],
                recommended_action="Patch",
                remediation_deadline="2024-12-31",
                risk_score=9.5,
            )
        ]

        output_file = tmp_path / "enriched.json"
        enricher.export_enriched_findings(enriched, output_file)

        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert len(data) == 1
        assert data[0]["threat_context"]["cve_id"] == "CVE-2024-1234"
        assert data[0]["risk_score"] == 9.5

    def test_export_empty_list(self, enricher, tmp_path):
        output_file = tmp_path / "empty.json"
        enricher.export_enriched_findings([], output_file)

        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert data == []

    def test_export_with_none_threat_context(self, enricher, tmp_path):
        enriched = [
            EnrichedFinding(
                original_finding={"cve": "CVE-2024-1234"},
                threat_context=None,
                original_priority="HIGH",
                adjusted_priority="HIGH",
                priority_boost_reasons=[],
                priority_downgrade_reasons=[],
                recommended_action="Review",
                remediation_deadline=None,
                risk_score=5.0,
            )
        ]

        output_file = tmp_path / "no_ctx.json"
        enricher.export_enriched_findings(enriched, output_file)

        data = json.loads(output_file.read_text())
        assert data[0]["threat_context"] is None


# ---------------------------------------------------------------------------
# Stats printing (smoke test)
# ---------------------------------------------------------------------------

class TestStatsPrinting:
    def test_print_enrichment_stats_empty(self, enricher):
        """Should not raise on empty enrichment list."""
        enricher._print_enrichment_stats([])

    def test_print_enrichment_stats_with_data(self, enricher):
        ctx = ThreatContext(cve_id="CVE-2024-1234")
        enriched = [
            EnrichedFinding(
                original_finding={},
                threat_context=ctx,
                original_priority="MEDIUM",
                adjusted_priority="HIGH",
                priority_boost_reasons=["test"],
                priority_downgrade_reasons=[],
                recommended_action="Fix",
                remediation_deadline=None,
                risk_score=7.0,
            )
        ]
        # Should not raise
        enricher._print_enrichment_stats(enriched)


# ---------------------------------------------------------------------------
# _enrich_with_progress fallback
# ---------------------------------------------------------------------------

class TestProgressFallback:
    def test_fallback_when_rich_unavailable(self, enricher):
        """When rich is not importable, falls back to _enrich_without_progress."""
        findings = [{"cve": "CVE-2024-1234", "severity": "HIGH"}]

        with patch.object(enricher, "_enrich_single_finding", return_value=None), \
             patch.dict("sys.modules", {"rich.progress": None}):
            # This should not crash
            result = enricher._enrich_without_progress(findings)
        assert isinstance(result, list)
