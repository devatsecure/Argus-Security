"""
Tests for the Gitleaks scanner module and its pipeline integration.

Covers:
- GitleaksScanner class (binary check, output parsing, error handling)
- run_gitleaks scanner runner (HybridFinding conversion)
- Phase 1 scanner_health flag registration
"""

import json
import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from gitleaks_scanner import GitleaksFinding, GitleaksScanner
from hybrid.models import HybridFinding
from hybrid.scanner_runners import run_gitleaks

_logger = logging.getLogger("test_gitleaks_scanner")


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_GITLEAKS_JSON = json.dumps([
    {
        "Description": "AWS Access Key",
        "StartLine": 10,
        "EndLine": 10,
        "StartColumn": 1,
        "EndColumn": 40,
        "Match": "AKIAIOSFODNN7EXAMPLE",
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "File": "config/settings.py",
        "Commit": "abc1234def5678",
        "Entropy": 3.5,
        "Author": "developer",
        "Email": "dev@example.com",
        "Date": "2024-01-15",
        "Message": "Add config",
        "Tags": ["aws", "key"],
        "RuleID": "aws-access-key",
    },
    {
        "Description": "Generic API Key",
        "StartLine": 25,
        "EndLine": 25,
        "StartColumn": 5,
        "EndColumn": 50,
        "Match": "api_key=sk-1234567890abcdef",
        "Secret": "sk-1234567890abcdef",
        "File": "src/app.py",
        "Commit": "def5678abc1234",
        "Entropy": 4.1,
        "Author": "developer",
        "Email": "dev@example.com",
        "Date": "2024-02-20",
        "Message": "Add API integration",
        "Tags": ["api-key"],
        "RuleID": "generic-api-key",
    },
])

SAMPLE_GITLEAKS_EMPTY = json.dumps([])


# ---------------------------------------------------------------------------
# Tests: GitleaksScanner class
# ---------------------------------------------------------------------------


class TestGitleaksScannerInit:
    """Tests for GitleaksScanner initialization."""

    @patch("gitleaks_scanner.subprocess.run")
    def test_init_gitleaks_installed(self, mock_run):
        """Scanner initializes successfully when gitleaks is installed."""
        mock_run.return_value = MagicMock(returncode=0, stdout="v8.18.0")
        scanner = GitleaksScanner()
        assert scanner._installed is True

    @patch("gitleaks_scanner.subprocess.run")
    def test_init_gitleaks_not_installed(self, mock_run):
        """Scanner logs warning when gitleaks is not installed."""
        mock_run.side_effect = FileNotFoundError("gitleaks not found")
        scanner = GitleaksScanner()
        assert scanner._installed is False

    @patch("gitleaks_scanner.subprocess.run")
    def test_init_gitleaks_subprocess_error(self, mock_run):
        """Scanner handles subprocess errors gracefully."""
        mock_run.side_effect = OSError("permission denied")
        scanner = GitleaksScanner()
        assert scanner._installed is False


class TestGitleaksScannerParseOutput:
    """Tests for GitleaksScanner._parse_output."""

    def _make_scanner(self):
        """Create a GitleaksScanner with installation check mocked out."""
        with patch("gitleaks_scanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="v8.18.0")
            return GitleaksScanner()

    def test_parse_valid_json(self):
        """Parses valid Gitleaks JSON output into GitleaksFinding objects."""
        scanner = self._make_scanner()
        findings = scanner._parse_output(SAMPLE_GITLEAKS_JSON)

        assert len(findings) == 2
        assert isinstance(findings[0], GitleaksFinding)
        assert findings[0].rule_id == "aws-access-key"
        assert findings[0].file_path == "config/settings.py"
        assert findings[0].start_line == 10
        assert findings[0].commit == "abc1234def5678"

        assert findings[1].rule_id == "generic-api-key"
        assert findings[1].file_path == "src/app.py"
        assert findings[1].start_line == 25

    def test_parse_empty_json(self):
        """Returns empty list for empty JSON array."""
        scanner = self._make_scanner()
        findings = scanner._parse_output(SAMPLE_GITLEAKS_EMPTY)
        assert findings == []

    def test_parse_empty_string(self):
        """Returns empty list for empty string."""
        scanner = self._make_scanner()
        findings = scanner._parse_output("")
        assert findings == []

    def test_parse_none(self):
        """Returns empty list for None."""
        scanner = self._make_scanner()
        findings = scanner._parse_output(None)
        assert findings == []

    def test_parse_invalid_json(self):
        """Returns empty list for malformed JSON."""
        scanner = self._make_scanner()
        findings = scanner._parse_output("not json at all")
        assert findings == []

    def test_parse_skips_empty_file_path(self):
        """Skips findings with empty File field."""
        scanner = self._make_scanner()
        data = json.dumps([
            {
                "Description": "Test",
                "File": "",
                "RuleID": "test",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 1,
                "EndColumn": 10,
                "Match": "secret",
                "Secret": "secret",
            },
            {
                "Description": "Test2",
                "File": "valid.py",
                "RuleID": "test2",
                "StartLine": 5,
                "EndLine": 5,
                "StartColumn": 1,
                "EndColumn": 10,
                "Match": "secret2",
                "Secret": "secret2",
            },
        ])
        findings = scanner._parse_output(data)
        assert len(findings) == 1
        assert findings[0].file_path == "valid.py"

    def test_parse_skips_dot_file_path(self):
        """Skips findings with '.' as File field."""
        scanner = self._make_scanner()
        data = json.dumps([{"File": ".", "RuleID": "test", "Description": "d",
                            "StartLine": 1, "EndLine": 1, "StartColumn": 1,
                            "EndColumn": 1, "Match": "m", "Secret": "s"}])
        findings = scanner._parse_output(data)
        assert findings == []

    def test_parse_non_dict_item_skipped(self):
        """Skips non-dict items in array."""
        scanner = self._make_scanner()
        data = json.dumps(["not a dict", 42])
        findings = scanner._parse_output(data)
        assert findings == []

    def test_parse_non_array_output(self):
        """Returns empty list when output is not an array."""
        scanner = self._make_scanner()
        findings = scanner._parse_output('{"not": "an array"}')
        assert findings == []


class TestGitleaksScannerScan:
    """Tests for GitleaksScanner.scan method."""

    @patch("gitleaks_scanner.subprocess.run")
    def test_scan_not_installed(self, mock_run):
        """Returns error result when gitleaks is not installed."""
        mock_run.side_effect = FileNotFoundError("not found")
        scanner = GitleaksScanner()
        result = scanner.scan("/tmp/test")

        assert result["tool"] == "gitleaks"
        assert result["error"] == "gitleaks_not_installed"
        assert result["findings_count"] == 0
        assert result["findings"] == []

    @patch("gitleaks_scanner.subprocess.run")
    def test_scan_path_not_found(self, mock_run):
        """Returns error when target path does not exist."""
        # First call: version check (success)
        # Second call: scan itself (should not happen because path is checked first)
        mock_run.return_value = MagicMock(returncode=0, stdout="v8.18.0")
        scanner = GitleaksScanner()
        result = scanner.scan("/nonexistent/path/that/does/not/exist")

        assert result["error"] == "path_not_found"
        assert result["findings"] == []

    @patch("gitleaks_scanner.subprocess.run")
    def test_scan_success_with_findings(self, mock_run):
        """Returns parsed findings on successful scan."""
        # version check
        version_result = MagicMock(returncode=0, stdout="v8.18.0")
        # scan call (exit code 1 = findings found)
        scan_result = MagicMock(
            returncode=1,
            stdout=SAMPLE_GITLEAKS_JSON,
            stderr="",
        )

        mock_run.side_effect = [version_result, scan_result, version_result]
        scanner = GitleaksScanner()

        with patch.object(Path, "exists", return_value=True):
            result = scanner.scan("/tmp/test")

        assert result["tool"] == "gitleaks"
        assert result["findings_count"] == 2
        assert len(result["findings"]) == 2
        assert result["findings"][0]["rule_id"] == "aws-access-key"

    @patch("gitleaks_scanner.subprocess.run")
    def test_scan_success_no_findings(self, mock_run):
        """Returns zero findings on clean scan."""
        version_result = MagicMock(returncode=0, stdout="v8.18.0")
        scan_result = MagicMock(
            returncode=0,
            stdout=SAMPLE_GITLEAKS_EMPTY,
            stderr="",
        )

        mock_run.side_effect = [version_result, scan_result, version_result]
        scanner = GitleaksScanner()

        with patch.object(Path, "exists", return_value=True):
            result = scanner.scan("/tmp/test")

        assert result["findings_count"] == 0
        assert result["findings"] == []

    @patch("gitleaks_scanner.subprocess.run")
    def test_scan_timeout(self, mock_run):
        """Returns error on timeout."""
        import subprocess

        version_result = MagicMock(returncode=0, stdout="v8.18.0")
        mock_run.side_effect = [
            version_result,
            subprocess.TimeoutExpired(cmd="gitleaks", timeout=600),
        ]
        scanner = GitleaksScanner()

        with patch.object(Path, "exists", return_value=True):
            result = scanner.scan("/tmp/test")

        assert result["error"] == "timeout"
        assert result["findings"] == []

    @patch("gitleaks_scanner.subprocess.run")
    def test_scan_failure_exit_code(self, mock_run):
        """Returns error on non-standard exit code."""
        version_result = MagicMock(returncode=0, stdout="v8.18.0")
        scan_result = MagicMock(
            returncode=2,
            stdout="",
            stderr="gitleaks: fatal error",
        )

        mock_run.side_effect = [version_result, scan_result]
        scanner = GitleaksScanner()

        with patch.object(Path, "exists", return_value=True):
            result = scanner.scan("/tmp/test")

        assert result["error"] == "gitleaks_failed"
        assert result["exit_code"] == 2


class TestGitleaksScannerRedact:
    """Tests for secret redaction."""

    def _make_scanner(self):
        with patch("gitleaks_scanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="v8.18.0")
            return GitleaksScanner()

    def test_redact_normal_secret(self):
        scanner = self._make_scanner()
        # 20 chars: first 4 + (20-8)=12 asterisks + last 4
        assert scanner._redact_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"

    def test_redact_short_secret(self):
        scanner = self._make_scanner()
        assert scanner._redact_secret("abcd1234") == "***REDACTED***"

    def test_redact_empty_secret(self):
        scanner = self._make_scanner()
        assert scanner._redact_secret("") == "***REDACTED***"

    def test_redact_none(self):
        scanner = self._make_scanner()
        assert scanner._redact_secret(None) == "***REDACTED***"


# ---------------------------------------------------------------------------
# Tests: run_gitleaks scanner runner
# ---------------------------------------------------------------------------


class TestRunGitleaks:
    """Tests for the run_gitleaks scanner runner function."""

    def test_run_gitleaks_with_findings(self):
        """Converts Gitleaks results to HybridFinding objects."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "tool": "gitleaks",
            "findings_count": 2,
            "findings": [
                {
                    "rule_id": "aws-access-key",
                    "description": "AWS Access Key",
                    "file_path": "config/settings.py",
                    "start_line": 10,
                    "commit": "abc1234def5678",
                },
                {
                    "rule_id": "generic-api-key",
                    "description": "Generic API Key",
                    "file_path": "src/app.py",
                    "start_line": 25,
                    "commit": None,
                },
            ],
        }

        findings = run_gitleaks(mock_scanner, "/tmp/test", _logger)

        assert len(findings) == 2
        assert isinstance(findings[0], HybridFinding)
        assert findings[0].source_tool == "gitleaks"
        assert findings[0].category == "secrets"
        assert findings[0].severity == "high"
        assert findings[0].file_path == "config/settings.py"
        assert findings[0].line_number == 10
        assert "AWS Access Key" in findings[0].title
        assert "abc1234d" in findings[0].description  # commit prefix

        assert findings[1].file_path == "src/app.py"
        assert findings[1].line_number == 25

    def test_run_gitleaks_no_findings(self):
        """Returns empty list when scan has no findings."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "tool": "gitleaks",
            "findings_count": 0,
            "findings": [],
        }

        findings = run_gitleaks(mock_scanner, "/tmp/test", _logger)
        assert findings == []

    def test_run_gitleaks_not_installed(self):
        """Returns empty list when gitleaks is not installed."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "tool": "gitleaks",
            "error": "gitleaks_not_installed",
            "findings_count": 0,
            "findings": [],
        }

        findings = run_gitleaks(mock_scanner, "/tmp/test", _logger)
        assert findings == []

    def test_run_gitleaks_scan_error(self):
        """Returns empty list when scan returns an error."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "tool": "gitleaks",
            "error": "gitleaks_failed",
            "findings_count": 0,
            "findings": [],
        }

        findings = run_gitleaks(mock_scanner, "/tmp/test", _logger)
        assert findings == []

    def test_run_gitleaks_exception(self):
        """Returns empty list when scanner raises an exception."""
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = RuntimeError("Scanner crashed")

        findings = run_gitleaks(mock_scanner, "/tmp/test", _logger)
        assert findings == []

    def test_run_gitleaks_skips_empty_file_path(self):
        """Skips findings with empty file paths."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "tool": "gitleaks",
            "findings_count": 2,
            "findings": [
                {
                    "rule_id": "test",
                    "description": "Bad path",
                    "file_path": "",
                    "start_line": 1,
                },
                {
                    "rule_id": "test2",
                    "description": "Good path",
                    "file_path": "valid.py",
                    "start_line": 5,
                },
            ],
        }

        findings = run_gitleaks(mock_scanner, "/tmp/test", _logger)
        assert len(findings) == 1
        assert findings[0].file_path == "valid.py"

    def test_run_gitleaks_finding_ids_unique(self):
        """Each finding gets a unique finding_id."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {
            "tool": "gitleaks",
            "findings_count": 3,
            "findings": [
                {"rule_id": "aws-key", "description": "AWS Key", "file_path": "a.py", "start_line": 1},
                {"rule_id": "aws-key", "description": "AWS Key", "file_path": "b.py", "start_line": 2},
                {"rule_id": "generic-key", "description": "Generic", "file_path": "c.py", "start_line": 3},
            ],
        }

        findings = run_gitleaks(mock_scanner, "/tmp/test", _logger)
        ids = [f.finding_id for f in findings]
        assert len(ids) == len(set(ids)), "Finding IDs should be unique"


# ---------------------------------------------------------------------------
# Tests: GitleaksFinding dataclass
# ---------------------------------------------------------------------------


class TestGitleaksFinding:
    """Tests for the GitleaksFinding dataclass."""

    def test_to_dict(self):
        """Converts to dictionary correctly."""
        finding = GitleaksFinding(
            rule_id="aws-access-key",
            description="AWS Access Key",
            file_path="config.py",
            start_line=10,
            end_line=10,
            start_column=1,
            end_column=20,
            match="AKIA...",
            secret="AKIAEXAMPLE",
        )
        d = finding.to_dict()
        assert d["rule_id"] == "aws-access-key"
        assert d["file_path"] == "config.py"
        assert d["start_line"] == 10

    def test_default_tags(self):
        """Tags default to empty list."""
        finding = GitleaksFinding(
            rule_id="test",
            description="test",
            file_path="test.py",
            start_line=1,
            end_line=1,
            start_column=1,
            end_column=10,
            match="m",
            secret="s",
        )
        assert finding.tags == []

    def test_optional_fields_default_none(self):
        """Optional fields default to None."""
        finding = GitleaksFinding(
            rule_id="test",
            description="test",
            file_path="test.py",
            start_line=1,
            end_line=1,
            start_column=1,
            end_column=10,
            match="m",
            secret="s",
        )
        assert finding.commit is None
        assert finding.author is None
        assert finding.email is None
        assert finding.date is None
        assert finding.message is None
        assert finding.entropy is None
