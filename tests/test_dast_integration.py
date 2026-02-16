#!/usr/bin/env python3
"""
Integration tests for DAST Orchestrator wiring into hybrid pipeline.

Tests the ``run_dast()`` function in ``scanner_runners.py`` which converts
DASTOrchestrator results into HybridFinding objects, and verifies graceful
degradation when the orchestrator fails or returns empty results.
"""

import logging
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from hybrid.models import HybridFinding
from hybrid.scanner_runners import run_dast, _discover_openapi_spec


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_dast_scan_result(
    aggregated_findings=None,
    agents_run=None,
    agents_succeeded=None,
    agents_failed=None,
    target_url="http://example.com",
):
    """Build a mock DASTScanResult-like object matching the orchestrator output."""
    result = MagicMock()
    result.timestamp = "2026-02-16T12:00:00"
    result.target_url = target_url
    result.duration_seconds = 10.5
    result.agents_run = agents_run or ["nuclei", "zap"]
    result.agents_succeeded = agents_succeeded or ["nuclei", "zap"]
    result.agents_failed = agents_failed or []
    result.total_findings = len(aggregated_findings) if aggregated_findings else 0
    result.aggregated_findings = aggregated_findings or []
    result.severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    return result


def _sample_nuclei_finding():
    """Return a sample aggregated finding dict from the orchestrator (Nuclei source)."""
    return {
        "source": "nuclei",
        "severity": "high",
        "name": "SQL Injection in /api/users",
        "url": "http://example.com/api/users?id=1",
        "description": "SQL injection detected via error-based technique",
        "evidence": ["MySQL error in response"],
        "raw": {
            "info": {
                "classification": {
                    "cwe-id": "CWE-89",
                    "cve-id": "CVE-2024-1234",
                },
            },
            "template-id": "sqli-error-based",
        },
    }


def _sample_zap_finding():
    """Return a sample aggregated finding dict from the orchestrator (ZAP source)."""
    return {
        "source": "zap",
        "severity": "medium",
        "name": "X-Frame-Options Header Missing",
        "url": "http://example.com/",
        "description": "X-Frame-Options header is not included in the response",
        "evidence": "",
        "raw": {},
    }


# ---------------------------------------------------------------------------
# Tests for run_dast()
# ---------------------------------------------------------------------------


class TestRunDast:
    """Tests for the run_dast() scanner runner function."""

    def setup_method(self):
        self.logger = logging.getLogger("test_dast")
        self.config = {
            "dast_severity": "critical,high,medium",
            "dast_timeout": 300,
        }

    def test_returns_findings_from_nuclei(self):
        """run_dast converts Nuclei orchestrator findings to HybridFinding."""
        orchestrator = MagicMock()
        scan_result = _make_dast_scan_result(
            aggregated_findings=[_sample_nuclei_finding()],
        )
        orchestrator.scan.return_value = scan_result

        findings = run_dast(
            orchestrator, "/tmp/project", self.logger, self.config,
            dast_target_url="http://example.com",
        )

        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, HybridFinding)
        assert f.source_tool == "dast-nuclei"
        assert f.severity == "high"
        assert f.title == "SQL Injection in /api/users"
        assert f.cwe_id == "CWE-89"
        assert f.cve_id == "CVE-2024-1234"
        assert f.category == "dast"
        assert f.confidence == 0.95

    def test_returns_findings_from_zap(self):
        """run_dast converts ZAP orchestrator findings to HybridFinding."""
        orchestrator = MagicMock()
        scan_result = _make_dast_scan_result(
            aggregated_findings=[_sample_zap_finding()],
        )
        orchestrator.scan.return_value = scan_result

        findings = run_dast(
            orchestrator, "/tmp/project", self.logger, self.config,
            dast_target_url="http://example.com",
        )

        assert len(findings) == 1
        f = findings[0]
        assert f.source_tool == "dast-zap"
        assert f.severity == "medium"
        assert f.cwe_id is None  # ZAP finding has no classification in raw

    def test_mixed_nuclei_and_zap_findings(self):
        """run_dast handles mixed findings from both agents."""
        orchestrator = MagicMock()
        scan_result = _make_dast_scan_result(
            aggregated_findings=[_sample_nuclei_finding(), _sample_zap_finding()],
            agents_run=["nuclei", "zap"],
            agents_succeeded=["nuclei", "zap"],
        )
        orchestrator.scan.return_value = scan_result

        findings = run_dast(
            orchestrator, "/tmp/project", self.logger, self.config,
            dast_target_url="http://example.com",
        )

        assert len(findings) == 2
        sources = {f.source_tool for f in findings}
        assert sources == {"dast-nuclei", "dast-zap"}

    def test_empty_findings(self):
        """run_dast returns empty list when orchestrator finds nothing."""
        orchestrator = MagicMock()
        scan_result = _make_dast_scan_result(aggregated_findings=[])
        orchestrator.scan.return_value = scan_result

        findings = run_dast(
            orchestrator, "/tmp/project", self.logger, self.config,
            dast_target_url="http://example.com",
        )

        assert findings == []

    def test_orchestrator_exception_returns_empty(self):
        """run_dast catches orchestrator exceptions and returns empty list."""
        orchestrator = MagicMock()
        orchestrator.scan.side_effect = RuntimeError("Nuclei binary not found")

        findings = run_dast(
            orchestrator, "/tmp/project", self.logger, self.config,
            dast_target_url="http://example.com",
        )

        assert findings == []

    def test_no_target_url_no_spec_skips(self):
        """run_dast skips when no target URL and no OpenAPI spec found."""
        orchestrator = MagicMock()

        with tempfile.TemporaryDirectory() as tmpdir:
            findings = run_dast(
                orchestrator, tmpdir, self.logger, self.config,
                dast_target_url=None,
            )

        assert findings == []
        orchestrator.scan.assert_not_called()

    def test_auto_discover_openapi_spec(self):
        """run_dast auto-discovers OpenAPI spec and uses fallback URL."""
        orchestrator = MagicMock()
        scan_result = _make_dast_scan_result(aggregated_findings=[_sample_nuclei_finding()])
        orchestrator.scan.return_value = scan_result

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create an OpenAPI spec file
            spec_file = Path(tmpdir) / "openapi.yaml"
            spec_file.write_text("openapi: '3.0.0'\npaths: {}\n")

            findings = run_dast(
                orchestrator, tmpdir, self.logger, self.config,
                dast_target_url=None,
            )

        assert len(findings) == 1
        # Verify orchestrator was called with the fallback URL
        orchestrator.scan.assert_called_once()
        call_kwargs = orchestrator.scan.call_args
        assert call_kwargs.kwargs.get("target_url") == "http://localhost:8080"

    def test_failed_agents_logged_not_crashed(self):
        """run_dast logs failed agents but doesn't crash."""
        orchestrator = MagicMock()
        scan_result = _make_dast_scan_result(
            aggregated_findings=[_sample_nuclei_finding()],
            agents_run=["nuclei", "zap"],
            agents_succeeded=["nuclei"],
            agents_failed=["zap"],
        )
        orchestrator.scan.return_value = scan_result

        findings = run_dast(
            orchestrator, "/tmp/project", self.logger, self.config,
            dast_target_url="http://example.com",
        )

        # Should still return findings from the successful agent
        assert len(findings) == 1

    def test_finding_id_includes_source_and_index(self):
        """run_dast generates unique finding IDs with source and index."""
        orchestrator = MagicMock()
        nuclei1 = _sample_nuclei_finding()
        nuclei2 = dict(nuclei1)
        nuclei2["name"] = "XSS in /search"
        scan_result = _make_dast_scan_result(
            aggregated_findings=[nuclei1, nuclei2],
        )
        orchestrator.scan.return_value = scan_result

        findings = run_dast(
            orchestrator, "/tmp/project", self.logger, self.config,
            dast_target_url="http://example.com",
        )

        ids = [f.finding_id for f in findings]
        assert ids[0] == "dast-nuclei-0"
        assert ids[1] == "dast-nuclei-1"

    def test_severity_normalization(self):
        """run_dast normalizes severity values from orchestrator."""
        orchestrator = MagicMock()
        finding_data = _sample_nuclei_finding()
        finding_data["severity"] = "warning"  # Non-standard severity
        scan_result = _make_dast_scan_result(aggregated_findings=[finding_data])
        orchestrator.scan.return_value = scan_result

        findings = run_dast(
            orchestrator, "/tmp/project", self.logger, self.config,
            dast_target_url="http://example.com",
        )

        assert findings[0].severity == "medium"  # "warning" normalizes to "medium"

    def test_missing_raw_classification_handled(self):
        """run_dast handles findings with no classification in raw data."""
        orchestrator = MagicMock()
        finding_data = {
            "source": "nuclei",
            "severity": "low",
            "name": "Information Disclosure",
            "url": "http://example.com/robots.txt",
            "description": "robots.txt found",
            "evidence": [],
            "raw": {},  # No classification
        }
        scan_result = _make_dast_scan_result(aggregated_findings=[finding_data])
        orchestrator.scan.return_value = scan_result

        findings = run_dast(
            orchestrator, "/tmp/project", self.logger, self.config,
            dast_target_url="http://example.com",
        )

        assert len(findings) == 1
        assert findings[0].cwe_id is None
        assert findings[0].cve_id is None


# ---------------------------------------------------------------------------
# Tests for _discover_openapi_spec()
# ---------------------------------------------------------------------------


class TestDiscoverOpenAPISpec:
    """Tests for the OpenAPI spec auto-discovery helper."""

    def setup_method(self):
        self.logger = logging.getLogger("test_discover")

    def test_finds_openapi_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "openapi.yaml").write_text("openapi: '3.0.0'")
            result = _discover_openapi_spec(tmpdir, self.logger)
            assert result is not None
            assert "openapi.yaml" in result

    def test_finds_swagger_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "swagger.json").write_text("{}")
            result = _discover_openapi_spec(tmpdir, self.logger)
            assert result is not None
            assert "swagger.json" in result

    def test_returns_none_when_no_spec(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _discover_openapi_spec(tmpdir, self.logger)
            assert result is None


# ---------------------------------------------------------------------------
# Tests for config_loader DAST settings
# ---------------------------------------------------------------------------


class TestDastConfig:
    """Tests that DAST config keys are properly handled."""

    def test_default_config_has_dast_disabled(self):
        from config_loader import get_default_config

        config = get_default_config()
        assert config["enable_dast"] is False
        assert config["dast_target_url"] == ""
        assert config["dast_auth_config_path"] == ""

    def test_env_var_dast_target_url(self):
        from config_loader import load_env_overrides

        with patch.dict("os.environ", {"DAST_TARGET_URL": "http://target.local"}):
            overrides = load_env_overrides()
            assert overrides.get("dast_target_url") == "http://target.local"

    def test_env_var_enable_dast(self):
        from config_loader import load_env_overrides

        with patch.dict("os.environ", {"ENABLE_DAST": "true"}):
            overrides = load_env_overrides()
            assert overrides.get("enable_dast") is True

    def test_validate_config_warns_dast_without_url(self):
        from config_loader import get_default_config, validate_config

        config = get_default_config()
        config["enable_dast"] = True
        config["dast_target_url"] = ""
        # Suppress API key warnings by providing a key
        config["anthropic_api_key"] = "test-key"

        issues = validate_config(config)
        dast_warnings = [i for i in issues if "DAST" in i.upper()]
        assert len(dast_warnings) > 0


# ---------------------------------------------------------------------------
# Tests for phase1_scanning DAST integration
# ---------------------------------------------------------------------------


class TestPhase1DastIntegration:
    """Tests that phase1_scanning properly handles DAST scanner."""

    def test_dast_disabled_marks_disabled_in_health(self):
        """When enable_dast=False, scanner_health should show 'disabled'."""
        from hybrid.phases.phase1_scanning import run_phase1_scanning

        analyzer = MagicMock()
        analyzer.enable_semgrep = False
        analyzer.semgrep_scanner = None
        analyzer.enable_trivy = False
        analyzer.trivy_scanner = None
        analyzer.enable_checkov = False
        analyzer.checkov_scanner = None
        analyzer.enable_api_security = False
        analyzer.api_security_scanner = None
        analyzer.enable_dast = False
        analyzer.dast_scanner = None
        analyzer.enable_supply_chain = False
        analyzer.supply_chain_scanner = None
        analyzer.enable_fuzzing = False
        analyzer.fuzzing_scanner = None
        analyzer.enable_threat_intel = False
        analyzer.threat_intel_enricher = None
        analyzer.enable_runtime_security = False
        analyzer.runtime_security_monitor = None
        analyzer.enable_regression_testing = False
        analyzer.regression_tester = None
        analyzer.enable_trufflehog = False
        analyzer.trufflehog_scanner = None
        analyzer.enable_gitleaks = False
        analyzer.gitleaks_scanner = None
        analyzer.enable_nuclei_templates = False
        analyzer.nuclei_template_scanner = None
        analyzer.enable_zap_baseline = False
        analyzer.zap_baseline_scanner = None

        findings, duration, health = run_phase1_scanning(
            target_path="/tmp/test", analyzer=analyzer
        )

        assert health["DAST"] == "disabled"

    def test_dast_exception_marks_failed_in_health(self):
        """When DAST scanner raises, scanner_health should show 'failed'."""
        from hybrid.phases.phase1_scanning import run_phase1_scanning

        analyzer = MagicMock()
        # Disable all scanners except DAST
        for attr in [
            "enable_semgrep", "enable_trivy", "enable_checkov",
            "enable_api_security", "enable_supply_chain", "enable_fuzzing",
            "enable_threat_intel", "enable_runtime_security",
            "enable_regression_testing", "enable_trufflehog",
            "enable_gitleaks", "enable_nuclei_templates", "enable_zap_baseline",
        ]:
            setattr(analyzer, attr, False)
        for attr in [
            "semgrep_scanner", "trivy_scanner", "checkov_scanner",
            "api_security_scanner", "supply_chain_scanner", "fuzzing_scanner",
            "threat_intel_enricher", "runtime_security_monitor",
            "regression_tester", "trufflehog_scanner", "gitleaks_scanner",
            "nuclei_template_scanner", "zap_baseline_scanner",
        ]:
            setattr(analyzer, attr, None)

        # Enable DAST but make it fail
        analyzer.enable_dast = True
        analyzer.dast_scanner = MagicMock()
        analyzer._run_dast.side_effect = RuntimeError("DAST exploded")

        findings, duration, health = run_phase1_scanning(
            target_path="/tmp/test", analyzer=analyzer
        )

        assert health["DAST"] == "failed"
        # Pipeline should not crash
        assert isinstance(findings, list)
