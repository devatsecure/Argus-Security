"""
Extended unit tests for scripts/semgrep_scanner.py.

Covers path resolution, command construction, and scan output parsing
that are NOT covered by the existing test_semgrep_scanner.py.
"""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Ensure scripts directory is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from semgrep_scanner import SemgrepFinding, SemgrepScanner

# ---------------------------------------------------------------------------
# _resolve_semgrep_path tests
# ---------------------------------------------------------------------------


class TestResolveSemgrepPath:
    """Tests for SemgrepScanner._resolve_semgrep_path()."""

    @patch("shutil.which")
    def test_shutil_which_found(self, mock_which):
        """When shutil.which finds semgrep, returns that path."""
        mock_which.return_value = "/usr/local/bin/semgrep"
        scanner = SemgrepScanner()
        assert scanner._semgrep_bin == "/usr/local/bin/semgrep"
        assert isinstance(scanner._semgrep_bin, str)

    @patch("shutil.which", return_value=None)
    @patch("pathlib.Path.is_file")
    def test_fallback_candidate_paths(self, mock_is_file, mock_which):
        """When shutil.which returns None, tries common install locations."""

        def custom_is_file(path_self):
            # Return True for /usr/local/bin/semgrep (first candidate)
            return str(path_self) == "/usr/local/bin/semgrep"

        with patch.object(Path, "is_file", custom_is_file):
            scanner = SemgrepScanner()
            assert scanner._semgrep_bin == "/usr/local/bin/semgrep"
            assert isinstance(scanner._semgrep_bin, str)

    @patch("shutil.which", return_value=None)
    @patch("pathlib.Path.is_file", return_value=False)
    @patch("subprocess.run")
    def test_python_m_fallback_success(self, mock_run, mock_is_file, mock_which):
        """When binary not found, falls back to python -m semgrep."""
        mock_run.return_value = Mock(returncode=0, stdout="1.60.0", stderr="")
        scanner = SemgrepScanner()
        assert isinstance(scanner._semgrep_bin, list)
        assert scanner._semgrep_bin[0] == sys.executable
        assert scanner._semgrep_bin[1] == "-m"
        assert scanner._semgrep_bin[2] == "semgrep"

    @patch("shutil.which", return_value=None)
    @patch("pathlib.Path.is_file", return_value=False)
    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_nothing_available_returns_none(self, mock_run, mock_is_file, mock_which):
        """When no semgrep installation found, _semgrep_bin is None."""
        scanner = SemgrepScanner()
        assert scanner._semgrep_bin is None

    @patch("shutil.which", return_value=None)
    @patch("pathlib.Path.is_file", return_value=False)
    @patch("subprocess.run")
    def test_python_m_fallback_nonzero_rc(self, mock_run, mock_is_file, mock_which):
        """If python -m semgrep --version fails with non-zero RC, returns None."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="error")
        scanner = SemgrepScanner()
        assert scanner._semgrep_bin is None

    @patch("shutil.which", return_value=None)
    @patch("pathlib.Path.is_file", return_value=False)
    @patch("subprocess.run", side_effect=subprocess.SubprocessError("broken"))
    def test_python_m_fallback_subprocess_error(self, mock_run, mock_is_file, mock_which):
        """SubprocessError during python -m fallback should return None."""
        scanner = SemgrepScanner()
        assert scanner._semgrep_bin is None

    @patch("shutil.which", return_value=None)
    @patch("pathlib.Path.is_file", return_value=False)
    @patch("subprocess.run", side_effect=OSError("os error"))
    def test_python_m_fallback_os_error(self, mock_run, mock_is_file, mock_which):
        """OSError during python -m fallback should return None."""
        scanner = SemgrepScanner()
        assert scanner._semgrep_bin is None


# ---------------------------------------------------------------------------
# _semgrep_cmd_prefix tests
# ---------------------------------------------------------------------------


class TestSemgrepCmdPrefix:
    """Tests for _semgrep_cmd_prefix() command construction."""

    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_binary_path_prefix(self, mock_which):
        scanner = SemgrepScanner()
        prefix = scanner._semgrep_cmd_prefix()
        assert prefix == ["/usr/bin/semgrep"]

    @patch("shutil.which", return_value=None)
    @patch("pathlib.Path.is_file", return_value=False)
    @patch("subprocess.run")
    def test_python_module_prefix(self, mock_run, mock_is_file, mock_which):
        mock_run.return_value = Mock(returncode=0, stdout="1.60.0", stderr="")
        scanner = SemgrepScanner()
        prefix = scanner._semgrep_cmd_prefix()
        assert prefix == [sys.executable, "-m", "semgrep"]

    @patch("shutil.which", return_value=None)
    @patch("pathlib.Path.is_file", return_value=False)
    @patch("subprocess.run")
    def test_prefix_returns_copy(self, mock_run, mock_is_file, mock_which):
        """_semgrep_cmd_prefix should return a new list each time."""
        mock_run.return_value = Mock(returncode=0, stdout="1.60.0", stderr="")
        scanner = SemgrepScanner()
        p1 = scanner._semgrep_cmd_prefix()
        p2 = scanner._semgrep_cmd_prefix()
        assert p1 == p2
        assert p1 is not p2  # different list objects


# ---------------------------------------------------------------------------
# scan method with mocked subprocess
# ---------------------------------------------------------------------------


class TestScanWithMockedSubprocess:
    """Tests for the scan() method with fully mocked subprocess calls."""

    def _make_scanner_with_bin(self, bin_path="/usr/local/bin/semgrep"):
        """Create a SemgrepScanner with a specific _semgrep_bin value."""
        with patch("shutil.which", return_value=bin_path):
            scanner = SemgrepScanner()
        return scanner

    @patch("subprocess.run")
    def test_scan_parses_findings_correctly(self, mock_run):
        """Test that scan() correctly parses semgrep JSON output."""
        semgrep_output = {
            "results": [
                {
                    "check_id": "python.lang.security.insecure-hash",
                    "path": "crypto.py",
                    "start": {"line": 5},
                    "end": {"line": 5},
                    "extra": {
                        "severity": "WARNING",
                        "message": "Use of insecure hash function MD5",
                        "lines": "hashlib.md5(data)",
                        "metadata": {
                            "cwe": ["CWE-328"],
                            "owasp": ["A2:2017-Broken-Authentication"],
                        },
                    },
                },
                {
                    "check_id": "python.lang.security.eval-injection",
                    "path": "handler.py",
                    "start": {"line": 20},
                    "end": {"line": 22},
                    "extra": {
                        "severity": "ERROR",
                        "message": "eval() with user input",
                        "lines": "eval(user_input)",
                        "metadata": {"cwe": ["CWE-95"]},
                    },
                },
            ]
        }

        scanner = self._make_scanner_with_bin()

        # _check_semgrep_installed calls --version (needs rc=0),
        # then scan itself calls subprocess.run (returns rc=1 = findings found)
        mock_run.side_effect = [
            Mock(returncode=0, stdout="1.60.0", stderr=""),  # --version check
            Mock(
                returncode=1,
                stdout=json.dumps(semgrep_output),
                stderr="",
            ),  # scan
            Mock(returncode=0, stdout="1.60.0", stderr=""),  # _get_semgrep_version
        ]

        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "resolve", return_value=Path("/tmp/repo")),
        ):
            results = scanner.scan("/tmp/repo")

        assert results["tool"] == "semgrep"
        assert results["findings_count"] == 2

        finding1 = results["findings"][0]
        assert finding1["rule_id"] == "python.lang.security.insecure-hash"
        assert finding1["severity"] == "high"  # WARNING -> high
        assert finding1["cwe"] == "CWE-328"
        assert finding1["owasp"] == "A2:2017-Broken-Authentication"

        finding2 = results["findings"][1]
        assert finding2["rule_id"] == "python.lang.security.eval-injection"
        assert finding2["severity"] == "critical"  # ERROR -> critical
        assert finding2["cwe"] == "CWE-95"
        assert finding2["owasp"] is None  # no owasp in metadata

    @patch("subprocess.run")
    def test_scan_semgrep_failure_returncode(self, mock_run):
        """Semgrep returning RC > 1 should report error."""
        scanner = self._make_scanner_with_bin()

        # First call: _check_semgrep_installed returns True
        # Second call: scan returns RC=2 (error)
        mock_run.side_effect = [
            Mock(returncode=0, stdout="", stderr=""),  # version check
            Mock(returncode=2, stdout="", stderr="Internal error"),  # scan
        ]

        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "resolve", return_value=Path("/tmp/repo")),
        ):
            results = scanner.scan("/tmp/repo")

        assert results["error"] == "semgrep_failed"

    @patch("subprocess.run")
    def test_scan_nonexistent_path(self, mock_run):
        """Scanning a non-existent path should return path_not_found error."""
        scanner = self._make_scanner_with_bin()

        mock_run.return_value = Mock(returncode=0)  # version check

        with (
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "resolve", return_value=Path("/nonexistent")),
        ):
            results = scanner.scan("/nonexistent")

        assert results["error"] == "path_not_found"

    @patch("subprocess.run")
    def test_scan_timeout(self, mock_run):
        """Timeout during scan should return timeout error."""
        scanner = self._make_scanner_with_bin()

        mock_run.side_effect = [
            Mock(returncode=0),  # version check
            subprocess.TimeoutExpired("semgrep", 300),  # scan timeout
        ]

        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "resolve", return_value=Path("/tmp/repo")),
        ):
            results = scanner.scan("/tmp/repo")

        assert results["error"] == "timeout"

    @patch("subprocess.run")
    def test_scan_json_parse_error(self, mock_run):
        """Invalid JSON output should return parse_failed error."""
        scanner = self._make_scanner_with_bin()

        mock_run.side_effect = [
            Mock(returncode=0),  # version check
            Mock(returncode=0, stdout="not valid json{{{", stderr=""),  # scan
        ]

        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "resolve", return_value=Path("/tmp/repo")),
        ):
            results = scanner.scan("/tmp/repo")

        assert results["error"] == "parse_failed"


# ---------------------------------------------------------------------------
# _parse_semgrep_output edge cases
# ---------------------------------------------------------------------------


class TestParseSemgrepOutputEdgeCases:
    """Edge case tests for _parse_semgrep_output()."""

    def _make_scanner(self):
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            return SemgrepScanner()

    def test_empty_results(self):
        scanner = self._make_scanner()
        findings = scanner._parse_semgrep_output({"results": []})
        assert findings == []

    def test_missing_results_key(self):
        scanner = self._make_scanner()
        findings = scanner._parse_semgrep_output({})
        assert findings == []

    def test_missing_metadata_fields(self):
        """Findings with no CWE/OWASP in metadata should have None."""
        scanner = self._make_scanner()
        output = {
            "results": [
                {
                    "check_id": "generic-rule",
                    "path": "file.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "severity": "INFO",
                        "message": "Generic issue",
                        "lines": "code",
                        "metadata": {},
                    },
                }
            ]
        }
        findings = scanner._parse_semgrep_output(output)
        assert len(findings) == 1
        assert findings[0].cwe is None
        assert findings[0].owasp is None

    def test_severity_mapping(self):
        """Verify all severity mappings: ERROR->critical, WARNING->high, INFO->medium."""
        scanner = self._make_scanner()
        for raw_sev, expected in [("ERROR", "critical"), ("WARNING", "high"), ("INFO", "medium")]:
            output = {
                "results": [
                    {
                        "check_id": "rule",
                        "path": "f.py",
                        "start": {"line": 1},
                        "end": {"line": 1},
                        "extra": {
                            "severity": raw_sev,
                            "message": "msg",
                            "lines": "code",
                            "metadata": {},
                        },
                    }
                ]
            }
            findings = scanner._parse_semgrep_output(output)
            assert findings[0].severity == expected, (
                f"Severity {raw_sev} should map to {expected}, got {findings[0].severity}"
            )

    def test_unknown_severity_maps_to_medium(self):
        scanner = self._make_scanner()
        output = {
            "results": [
                {
                    "check_id": "rule",
                    "path": "f.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "severity": "UNKNOWN_LEVEL",
                        "message": "msg",
                        "lines": "code",
                        "metadata": {},
                    },
                }
            ]
        }
        findings = scanner._parse_semgrep_output(output)
        assert findings[0].severity == "medium"

    def test_cwe_list_extracts_first(self):
        """When CWE is a list, should extract the first element."""
        scanner = self._make_scanner()
        output = {
            "results": [
                {
                    "check_id": "rule",
                    "path": "f.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "severity": "ERROR",
                        "message": "msg",
                        "lines": "code",
                        "metadata": {"cwe": ["CWE-89", "CWE-564"]},
                    },
                }
            ]
        }
        findings = scanner._parse_semgrep_output(output)
        assert findings[0].cwe == "CWE-89"

    def test_cwe_empty_list_gives_none(self):
        scanner = self._make_scanner()
        output = {
            "results": [
                {
                    "check_id": "rule",
                    "path": "f.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {
                        "severity": "ERROR",
                        "message": "msg",
                        "lines": "code",
                        "metadata": {"cwe": []},
                    },
                }
            ]
        }
        findings = scanner._parse_semgrep_output(output)
        assert findings[0].cwe is None

    def test_multiple_findings_parsed(self):
        scanner = self._make_scanner()
        results = [
            {
                "check_id": f"rule-{i}",
                "path": f"file{i}.py",
                "start": {"line": i},
                "end": {"line": i},
                "extra": {
                    "severity": "WARNING",
                    "message": f"Issue {i}",
                    "lines": f"code {i}",
                    "metadata": {},
                },
            }
            for i in range(5)
        ]
        findings = scanner._parse_semgrep_output({"results": results})
        assert len(findings) == 5
        assert findings[3].rule_id == "rule-3"


# ---------------------------------------------------------------------------
# _check_semgrep_installed tests
# ---------------------------------------------------------------------------


class TestCheckSemgrepInstalled:
    """Tests for _check_semgrep_installed()."""

    def test_returns_false_when_no_bin(self):
        with (
            patch("shutil.which", return_value=None),
            patch("pathlib.Path.is_file", return_value=False),
            patch("subprocess.run", side_effect=FileNotFoundError),
        ):
            scanner = SemgrepScanner()
        assert scanner._check_semgrep_installed() is False

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_returns_true_when_version_succeeds(self, mock_which, mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="1.60.0")
        scanner = SemgrepScanner()
        assert scanner._check_semgrep_installed() is True

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_returns_false_on_subprocess_error(self, mock_which, mock_run):
        # First call for init succeeds
        # Second call for _check_semgrep_installed raises
        mock_run.side_effect = [
            None,  # init doesn't call run for binary path case
            subprocess.SubprocessError("broken"),
        ]
        scanner = SemgrepScanner()
        mock_run.side_effect = subprocess.SubprocessError("broken")
        assert scanner._check_semgrep_installed() is False


# ---------------------------------------------------------------------------
# SemgrepFinding additional tests
# ---------------------------------------------------------------------------


class TestSemgrepFindingExtended:
    """Extended tests for SemgrepFinding not in the original test file."""

    def test_default_confidence(self):
        f = SemgrepFinding(
            rule_id="r",
            severity="high",
            message="m",
            file_path="f.py",
            start_line=1,
            end_line=1,
            code_snippet="code",
        )
        assert f.confidence == "HIGH"

    def test_to_dict_includes_all_fields(self):
        f = SemgrepFinding(
            rule_id="r",
            severity="high",
            message="m",
            file_path="f.py",
            start_line=1,
            end_line=2,
            code_snippet="code",
            cwe="CWE-89",
            owasp="A1",
            confidence="MEDIUM",
        )
        d = f.to_dict()
        assert d["rule_id"] == "r"
        assert d["cwe"] == "CWE-89"
        assert d["owasp"] == "A1"
        assert d["confidence"] == "MEDIUM"
        assert d["start_line"] == 1
        assert d["end_line"] == 2


# ---------------------------------------------------------------------------
# Scanner configuration tests
# ---------------------------------------------------------------------------


class TestScannerConfig:
    """Tests for scanner configuration handling."""

    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_default_rules(self, mock_which):
        scanner = SemgrepScanner()
        assert scanner.semgrep_rules == "auto"

    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_custom_rules(self, mock_which):
        scanner = SemgrepScanner(config={"semgrep_rules": "p/owasp-top-ten"})
        assert scanner.semgrep_rules == "p/owasp-top-ten"

    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_default_exclude_patterns(self, mock_which):
        scanner = SemgrepScanner()
        assert "*/test/*" in scanner.exclude_patterns
        assert "*/node_modules/*" in scanner.exclude_patterns
        assert "*/.git/*" in scanner.exclude_patterns

    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_custom_exclude_patterns(self, mock_which):
        scanner = SemgrepScanner(config={"exclude_patterns": ["*/vendor/*"]})
        assert scanner.exclude_patterns == ["*/vendor/*"]

    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_empty_config(self, mock_which):
        scanner = SemgrepScanner(config={})
        assert scanner.semgrep_rules == "auto"
        assert scanner.languages == []
