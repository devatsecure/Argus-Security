"""
Tests for hybrid.scanner_runners module.

Verifies that runner functions correctly convert scanner-specific output
to HybridFinding objects and handle errors gracefully.
"""

import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from hybrid.models import HybridFinding
from hybrid.scanner_runners import (
    normalize_severity,
    count_by_severity,
    count_by_source,
    run_checkov,
    run_semgrep,
    run_trivy,
)

_logger = logging.getLogger("test_scanner_runners")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_checkov_finding(**overrides):
    """Create a mock Checkov finding with standard attributes."""
    defaults = {
        "check_id": "CKV_AWS_1",
        "check_name": "Ensure S3 bucket versioning is enabled",
        "severity": "HIGH",
        "file_path": "/main.tf",
        "file_line_range": [10, 20],
        "guideline": "https://docs.checkov.io/...",
        "description": "S3 bucket versioning not enabled",
        "framework": "terraform",
    }
    defaults.update(overrides)

    finding = MagicMock()
    for key, value in defaults.items():
        setattr(finding, key, value)
    return finding


def _make_checkov_scan_result(findings=None):
    """Create a mock CheckovScanResult wrapping the given findings list."""
    result = MagicMock()
    result.findings = findings if findings is not None else []
    return result


def _make_trivy_finding(**overrides):
    """Create a mock Trivy finding with standard attributes."""
    defaults = {
        "cve_id": "CVE-2024-1234",
        "severity": "HIGH",
        "package_name": "lodash",
        "description": "Prototype pollution in lodash",
        "file_path": "package-lock.json",
        "cwe_id": "CWE-1321",
        "cvss_score": 7.5,
        "exploitability": "moderate",
        "fixed_version": "4.17.21",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
    }
    defaults.update(overrides)

    finding = MagicMock()
    for key, value in defaults.items():
        setattr(finding, key, value)
    return finding


def _make_trivy_scan_result(findings=None):
    """Create a mock Trivy scan result with .findings attribute."""
    result = MagicMock()
    result.findings = findings if findings is not None else []
    return result


# ---------------------------------------------------------------------------
# Tests: normalize_severity
# ---------------------------------------------------------------------------


class TestNormalizeSeverity:
    """Tests for the normalize_severity helper."""

    def test_standard_levels_pass_through(self):
        assert normalize_severity("critical") == "critical"
        assert normalize_severity("high") == "high"
        assert normalize_severity("medium") == "medium"
        assert normalize_severity("low") == "low"

    def test_case_insensitive(self):
        assert normalize_severity("CRITICAL") == "critical"
        assert normalize_severity("High") == "high"
        assert normalize_severity("MEDIUM") == "medium"

    def test_alias_mapping(self):
        assert normalize_severity("error") == "critical"
        assert normalize_severity("warning") == "medium"
        assert normalize_severity("info") == "low"
        assert normalize_severity("note") == "low"

    def test_unknown_defaults_to_medium(self):
        assert normalize_severity("unknown") == "medium"
        assert normalize_severity("something_else") == "medium"


# ---------------------------------------------------------------------------
# Tests: count_by_severity
# ---------------------------------------------------------------------------


class TestCountBySeverity:
    """Tests for count_by_severity."""

    def test_empty_list(self):
        result = count_by_severity([])
        assert result == {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def test_counts_correctly(self):
        findings = [
            HybridFinding(
                finding_id="f1", source_tool="semgrep", severity="critical",
                category="security", title="t1", description="d1", file_path="f.py",
            ),
            HybridFinding(
                finding_id="f2", source_tool="semgrep", severity="high",
                category="security", title="t2", description="d2", file_path="f.py",
            ),
            HybridFinding(
                finding_id="f3", source_tool="trivy", severity="high",
                category="security", title="t3", description="d3", file_path="f.py",
            ),
        ]
        result = count_by_severity(findings)
        assert result["critical"] == 1
        assert result["high"] == 2
        assert result["medium"] == 0
        assert result["low"] == 0


# ---------------------------------------------------------------------------
# Tests: count_by_source
# ---------------------------------------------------------------------------


class TestCountBySource:
    """Tests for count_by_source."""

    def test_empty_list(self):
        assert count_by_source([]) == {}

    def test_counts_by_tool(self):
        findings = [
            HybridFinding(
                finding_id="f1", source_tool="semgrep", severity="high",
                category="security", title="t1", description="d1", file_path="f.py",
            ),
            HybridFinding(
                finding_id="f2", source_tool="trivy", severity="high",
                category="security", title="t2", description="d2", file_path="f.py",
            ),
            HybridFinding(
                finding_id="f3", source_tool="semgrep", severity="medium",
                category="security", title="t3", description="d3", file_path="f.py",
            ),
        ]
        result = count_by_source(findings)
        assert result == {"semgrep": 2, "trivy": 1}


# ---------------------------------------------------------------------------
# Tests: run_checkov
# ---------------------------------------------------------------------------


class TestRunCheckov:
    """Tests for the run_checkov runner function."""

    def test_converts_findings_to_hybrid_finding(self):
        """Mock scanner with findings, verify output is list of HybridFinding
        with source_tool == 'checkov'."""
        finding1 = _make_checkov_finding(check_id="CKV_AWS_1", severity="HIGH")
        finding2 = _make_checkov_finding(check_id="CKV_AWS_2", severity="MEDIUM")
        scan_result = _make_checkov_scan_result([finding1, finding2])

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = scan_result

        results = run_checkov(mock_scanner, "/tmp/repo", _logger)

        assert isinstance(results, list)
        assert len(results) == 2
        for r in results:
            assert isinstance(r, HybridFinding)
            assert r.source_tool == "checkov"
        assert results[0].finding_id == "checkov-CKV_AWS_1"
        assert results[1].finding_id == "checkov-CKV_AWS_2"

    def test_empty_results(self):
        """Mock scanner with empty findings, verify [] returned."""
        scan_result = _make_checkov_scan_result([])
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = scan_result

        results = run_checkov(mock_scanner, "/tmp/repo", _logger)

        assert results == []

    def test_exception_returns_empty(self):
        """Mock scanner.scan to raise, verify [] returned."""
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = RuntimeError("checkov crash")

        results = run_checkov(mock_scanner, "/tmp/repo", _logger)

        assert results == []

    def test_finding_fields_mapped_correctly(self):
        """Verify that Checkov finding attributes are correctly mapped
        to HybridFinding fields."""
        finding = _make_checkov_finding(
            check_id="CKV_K8S_3",
            check_name="Ensure containers run as non-root",
            severity="HIGH",
            file_path="/deployment.yaml",
            file_line_range=[15, 25],
            guideline="https://docs.checkov.io/k8s-3",
            description="Container runs as root",
            framework="kubernetes",
        )
        scan_result = _make_checkov_scan_result([finding])
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = scan_result

        results = run_checkov(mock_scanner, "/tmp/repo", _logger)

        assert len(results) == 1
        hf = results[0]
        assert hf.finding_id == "checkov-CKV_K8S_3"
        assert hf.severity == "high"
        assert hf.file_path == "/deployment.yaml"
        assert hf.line_number == 15
        assert hf.confidence == 0.9

    def test_finding_without_line_range(self):
        """Verify graceful handling when file_line_range is empty or None."""
        finding = _make_checkov_finding(file_line_range=[])
        scan_result = _make_checkov_scan_result([finding])
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = scan_result

        results = run_checkov(mock_scanner, "/tmp/repo", _logger)

        assert len(results) == 1
        assert results[0].line_number is None


# ---------------------------------------------------------------------------
# Tests: run_semgrep
# ---------------------------------------------------------------------------


class TestRunSemgrep:
    """Tests for the run_semgrep runner function."""

    def test_converts_findings_dict_format(self):
        """Mock scanner returning dict with 'findings' key, verify conversion
        to HybridFinding."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "findings": [
                {
                    "rule_id": "python.sql-injection",
                    "severity": "high",
                    "message": "SQL injection detected",
                    "file_path": "app.py",
                    "start_line": 42,
                    "fix": "Use parameterized queries",
                    "references": ["https://owasp.org/sql-injection"],
                    "cwe": "CWE-89",
                },
            ]
        }

        results = run_semgrep(mock_scanner, "/tmp/repo", _logger)

        assert len(results) == 1
        hf = results[0]
        assert isinstance(hf, HybridFinding)
        assert hf.source_tool == "semgrep"
        assert hf.finding_id == "semgrep-python.sql-injection"
        assert hf.severity == "high"
        assert hf.description == "SQL injection detected"
        assert hf.file_path == "app.py"
        assert hf.line_number == 42
        assert hf.cwe_id == "CWE-89"
        assert hf.confidence == 0.9

    def test_converts_findings_list_format(self):
        """Mock scanner returning a list directly (legacy format), verify
        conversion to HybridFinding."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = [
            {
                "rule_id": "python.hardcoded-secret",
                "severity": "critical",
                "message": "Hardcoded secret found",
                "file_path": "config.py",
                "start_line": 10,
            },
        ]

        results = run_semgrep(mock_scanner, "/tmp/repo", _logger)

        assert len(results) == 1
        assert results[0].source_tool == "semgrep"
        assert results[0].finding_id == "semgrep-python.hardcoded-secret"
        assert results[0].severity == "critical"

    def test_exception_returns_empty(self):
        """Mock scanner.scan to raise, verify [] returned."""
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = RuntimeError("semgrep crash")

        results = run_semgrep(mock_scanner, "/tmp/repo", _logger)

        assert results == []

    def test_empty_findings_returns_empty(self):
        """Scanner returning dict with empty findings list returns []."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"findings": []}

        results = run_semgrep(mock_scanner, "/tmp/repo", _logger)

        assert results == []

    def test_scanner_without_scan_method(self):
        """If the scanner object has no 'scan' attribute, return []."""
        mock_scanner = MagicMock(spec=[])  # no methods

        results = run_semgrep(mock_scanner, "/tmp/repo", _logger)

        assert results == []

    def test_missing_fields_use_defaults(self):
        """Findings with missing optional fields should use defaults."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "findings": [
                {
                    "rule_id": "generic-rule",
                    # no severity, message, file_path, etc.
                },
            ]
        }

        results = run_semgrep(mock_scanner, "/tmp/repo", _logger)

        assert len(results) == 1
        hf = results[0]
        assert hf.severity == "medium"  # default from normalize_severity
        assert hf.description == ""
        assert hf.file_path == ""
        assert hf.line_number is None


# ---------------------------------------------------------------------------
# Tests: run_trivy
# ---------------------------------------------------------------------------


class TestRunTrivy:
    """Tests for the run_trivy runner function."""

    def test_converts_findings_to_hybrid_finding(self):
        """Mock scanner with findings, verify conversion to HybridFinding."""
        finding1 = _make_trivy_finding(cve_id="CVE-2024-1234", severity="HIGH")
        finding2 = _make_trivy_finding(cve_id="CVE-2024-5678", severity="CRITICAL")
        scan_result = _make_trivy_scan_result([finding1, finding2])

        mock_scanner = MagicMock()
        mock_scanner.scan_filesystem.return_value = scan_result

        results = run_trivy(mock_scanner, "/tmp/repo", _logger)

        assert isinstance(results, list)
        assert len(results) == 2
        for r in results:
            assert isinstance(r, HybridFinding)
            assert r.source_tool == "trivy"
            assert r.confidence == 1.0
            assert r.llm_enriched is False
        assert results[0].finding_id == "trivy-CVE-2024-1234"
        assert results[1].finding_id == "trivy-CVE-2024-5678"

    def test_empty_results(self):
        """Mock scanner with empty findings, verify [] returned."""
        scan_result = _make_trivy_scan_result([])
        mock_scanner = MagicMock()
        mock_scanner.scan_filesystem.return_value = scan_result

        results = run_trivy(mock_scanner, "/tmp/repo", _logger)

        assert results == []

    def test_exception_returns_empty(self):
        """Mock scanner.scan_filesystem to raise, verify [] returned."""
        mock_scanner = MagicMock()
        mock_scanner.scan_filesystem.side_effect = RuntimeError("trivy crash")

        results = run_trivy(mock_scanner, "/tmp/repo", _logger)

        assert results == []

    def test_finding_with_fix_version(self):
        """Verify recommendation includes upgrade path when fix version exists."""
        finding = _make_trivy_finding(
            cve_id="CVE-2024-9999",
            package_name="requests",
            fixed_version="2.31.0",
        )
        scan_result = _make_trivy_scan_result([finding])
        mock_scanner = MagicMock()
        mock_scanner.scan_filesystem.return_value = scan_result

        results = run_trivy(mock_scanner, "/tmp/repo", _logger)

        assert len(results) == 1
        assert "Upgrade requests to 2.31.0" in results[0].recommendation

    def test_finding_without_fix_version(self):
        """Verify recommendation says 'No fix available' when no fix exists."""
        finding = _make_trivy_finding(
            cve_id="CVE-2024-0000",
            package_name="vulnerable-lib",
            fixed_version=None,
        )
        scan_result = _make_trivy_scan_result([finding])
        mock_scanner = MagicMock()
        mock_scanner.scan_filesystem.return_value = scan_result

        results = run_trivy(mock_scanner, "/tmp/repo", _logger)

        assert len(results) == 1
        assert "No fix available" in results[0].recommendation

    def test_finding_fields_mapped_correctly(self):
        """Verify that all Trivy finding fields are mapped to HybridFinding."""
        finding = _make_trivy_finding(
            cve_id="CVE-2024-7777",
            severity="CRITICAL",
            package_name="express",
            description="Remote code execution",
            file_path="node_modules/express/package.json",
            cwe_id="CWE-94",
            cvss_score=9.8,
            exploitability="trivial",
            fixed_version="4.18.3",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-7777"],
        )
        scan_result = _make_trivy_scan_result([finding])
        mock_scanner = MagicMock()
        mock_scanner.scan_filesystem.return_value = scan_result

        results = run_trivy(mock_scanner, "/tmp/repo", _logger)

        hf = results[0]
        assert hf.cve_id == "CVE-2024-7777"
        assert hf.severity == "critical"
        assert hf.cwe_id == "CWE-94"
        assert hf.cvss_score == 9.8
        assert hf.exploitability == "trivial"
        assert hf.title == "CVE-2024-7777 in express"
