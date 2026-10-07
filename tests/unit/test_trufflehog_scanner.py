#!/usr/bin/env python3
"""
Unit tests for TruffleHog Scanner

Tests cover:
- Scanner initialization
- TruffleHog installation check
- Subprocess execution (ensuring no shell=True)
- JSON output parsing
- Finding dataclass creation
- Secret redaction
- Error handling
- File and directory scanning
"""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from trufflehog_scanner import TruffleHogFinding, TruffleHogScanner


class TestTruffleHogFinding:
    """Test TruffleHogFinding dataclass"""

    def test_finding_creation_git(self):
        """Test creating a TruffleHog finding with git metadata"""
        finding = TruffleHogFinding(
            detector_type="AWS",
            detector_name="AWS Access Key",
            verified=True,
            raw="AKIAIOSFODNN7EXAMPLE",
            redacted="AKIA***************MPLE",
            file_path="config/aws.yaml",
            commit="abc123def456",
            line=15,
            timestamp="2024-01-08T12:00:00Z",
            author="John Doe",
            email="john@example.com",
            repository_url="https://github.com/example/repo",
        )

        assert finding.detector_type == "AWS"
        assert finding.detector_name == "AWS Access Key"
        assert finding.verified is True
        assert finding.raw == "AKIAIOSFODNN7EXAMPLE"
        assert finding.redacted == "AKIA***************MPLE"
        assert finding.file_path == "config/aws.yaml"
        assert finding.commit == "abc123def456"
        assert finding.line == 15
        assert finding.author == "John Doe"
        assert finding.repository_url == "https://github.com/example/repo"

    def test_finding_creation_filesystem(self):
        """Test creating a TruffleHog finding with filesystem metadata"""
        finding = TruffleHogFinding(
            detector_type="GitHub",
            detector_name="GitHub Token",
            verified=False,
            raw="ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            redacted="ghp_***********************************xyz",
            file_path="/app/secrets.txt",
            commit="",
            line=5,
            timestamp="2024-01-08T12:00:00Z",
            author="",
            email="",
        )

        assert finding.detector_type == "GitHub"
        assert finding.verified is False
        assert finding.commit == ""
        assert finding.author == ""
        assert finding.repository_url is None

    def test_finding_to_dict(self):
        """Test converting finding to dictionary"""
        finding = TruffleHogFinding(
            detector_type="Slack",
            detector_name="Slack Webhook",
            verified=True,
            raw="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
            redacted="https://hooks.slack.com/services/T00000000/B00000000/XXX***************XXX",
            file_path="webhook.py",
            commit="def456",
            line=20,
            timestamp="2024-01-08T12:00:00Z",
            author="Jane Doe",
            email="jane@example.com",
        )

        result = finding.to_dict()
        assert isinstance(result, dict)
        assert result["detector_type"] == "Slack"
        assert result["detector_name"] == "Slack Webhook"
        assert result["verified"] is True
        assert result["file_path"] == "webhook.py"
        assert result["line"] == 20


class TestTruffleHogScanner:
    """Test TruffleHogScanner class"""

    def test_scanner_initialization_default(self):
        """Test scanner initialization with default config"""
        with patch.object(TruffleHogScanner, "_check_trufflehog_installed", return_value=True):
            scanner = TruffleHogScanner()

            assert scanner.verified_only is True
            assert scanner.scan_depth is None
            assert scanner.include_unverified is False
            assert isinstance(scanner.exclude_patterns, list)
            assert "*/test/*" in scanner.exclude_patterns
            assert "*/node_modules/*" in scanner.exclude_patterns

    def test_scanner_initialization_custom_config(self):
        """Test scanner with custom configuration"""
        config = {
            "verified_only": False,
            "scan_depth": 50,
            "exclude_patterns": ["*/custom/*"],
            "include_unverified": True,
        }

        with patch.object(TruffleHogScanner, "_check_trufflehog_installed", return_value=True):
            scanner = TruffleHogScanner(config)

            assert scanner.verified_only is False
            assert scanner.scan_depth == 50
            assert scanner.include_unverified is True
            assert scanner.exclude_patterns == ["*/custom/*"]

    def test_scanner_initialization_warning_when_not_installed(self):
        """Test that scanner logs warning when TruffleHog not installed"""
        with (
            patch.object(TruffleHogScanner, "_check_trufflehog_installed", return_value=False),
            patch("trufflehog_scanner.logger.warning") as mock_warning,
        ):
            TruffleHogScanner()
            mock_warning.assert_called_once()
            assert "TruffleHog not installed" in mock_warning.call_args[0][0]

    @patch("subprocess.run")
    def test_check_trufflehog_installed_success(self, mock_run):
        """Test checking if TruffleHog is installed (success)"""
        mock_run.return_value = Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr="")

        scanner = TruffleHogScanner()
        result = scanner._check_trufflehog_installed()

        assert result is True
        # Verify no shell=True is used
        mock_run.assert_called()
        call_args = mock_run.call_args
        assert "shell" not in call_args[1] or call_args[1]["shell"] is False

    @patch("subprocess.run")
    def test_check_trufflehog_installed_not_found(self, mock_run):
        """Test checking if TruffleHog is installed (not found)"""
        mock_run.side_effect = FileNotFoundError()

        scanner = TruffleHogScanner()
        result = scanner._check_trufflehog_installed()

        assert result is False

    @patch("subprocess.run")
    def test_check_trufflehog_installed_subprocess_error(self, mock_run):
        """Test checking if TruffleHog is installed (subprocess error)"""
        mock_run.side_effect = subprocess.SubprocessError("Command failed")

        scanner = TruffleHogScanner()
        result = scanner._check_trufflehog_installed()

        assert result is False

    @patch("subprocess.run")
    def test_check_trufflehog_installed_nonzero_exit(self, mock_run):
        """Test checking if TruffleHog is installed (non-zero exit code)"""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="error")

        scanner = TruffleHogScanner()
        result = scanner._check_trufflehog_installed()

        assert result is False

    @patch("subprocess.run")
    def test_install_trufflehog_already_installed(self, mock_run):
        """Test install_trufflehog when already installed"""
        mock_run.return_value = Mock(returncode=0, stdout="trufflehog v3.63.0\n")

        scanner = TruffleHogScanner()
        result = scanner.install_trufflehog()

        assert result is True

    @patch("subprocess.run")
    def test_install_trufflehog_not_installed(self, mock_run):
        """Test install_trufflehog when not installed"""
        mock_run.side_effect = FileNotFoundError()

        scanner = TruffleHogScanner()

        with patch("trufflehog_scanner.logger.info") as mock_info:
            result = scanner.install_trufflehog()

            assert result is False
            # Should log installation instructions
            assert mock_info.call_count >= 5

    @patch("subprocess.run")
    def test_get_trufflehog_version_success(self, mock_run):
        """Test getting TruffleHog version"""
        mock_run.return_value = Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr="")

        scanner = TruffleHogScanner()
        version = scanner._get_trufflehog_version()

        assert version == "trufflehog v3.63.0"

    @patch("subprocess.run")
    def test_get_trufflehog_version_error(self, mock_run):
        """Test getting TruffleHog version with error"""
        # First call from __init__, second from _get_trufflehog_version
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Exception("Command failed"),  # _get_trufflehog_version call
        ]

        scanner = TruffleHogScanner()
        version = scanner._get_trufflehog_version()

        assert version == "unknown"

    def test_redact_secret_standard(self):
        """Test secret redaction for standard length secrets"""
        scanner = TruffleHogScanner()

        secret = "AKIAIOSFODNN7EXAMPLE"
        redacted = scanner._redact_secret(secret)

        assert redacted == "AKIA************MPLE"
        assert len(redacted) == len(secret)

    def test_redact_secret_short(self):
        """Test secret redaction for short secrets"""
        scanner = TruffleHogScanner()

        secret = "abc123"
        redacted = scanner._redact_secret(secret)

        assert redacted == "***REDACTED***"

    def test_redact_secret_empty(self):
        """Test secret redaction for empty string"""
        scanner = TruffleHogScanner()

        secret = ""
        redacted = scanner._redact_secret(secret)

        assert redacted == "***REDACTED***"

    def test_redact_secret_exactly_8_chars(self):
        """Test secret redaction for exactly 8 character secrets"""
        scanner = TruffleHogScanner()

        secret = "12345678"
        redacted = scanner._redact_secret(secret)

        assert redacted == "***REDACTED***"

    def test_redact_secret_long(self):
        """Test secret redaction for long secrets"""
        scanner = TruffleHogScanner()

        secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        redacted = scanner._redact_secret(secret)

        assert redacted.startswith("ghp_")
        assert redacted.endswith("wxyz")
        assert "*" in redacted

    def test_parse_output_empty(self):
        """Test parsing empty output"""
        scanner = TruffleHogScanner()

        findings = scanner._parse_output("")
        assert findings == []

        findings = scanner._parse_output("   \n  \n  ")
        assert findings == []

    def test_parse_output_git_metadata(self):
        """Test parsing TruffleHog output with Git metadata"""
        scanner = TruffleHogScanner()

        trufflehog_output = json.dumps(
            {
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": "config/aws.yaml",
                            "commit": "abc123def456",
                            "timestamp": "2024-01-08T12:00:00Z",
                            "author": "John Doe",
                            "email": "john@example.com",
                            "line": 15,
                            "repository": "https://github.com/example/repo",
                        }
                    }
                },
                "DetectorType": "AWS",
                "DetectorName": "AWS Access Key",
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "Redacted": "AKIA***************MPLE",
                "Verified": True,
            }
        )

        findings = scanner._parse_output(trufflehog_output)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detector_type == "AWS"
        assert finding.detector_name == "AWS Access Key"
        assert finding.verified is True
        assert finding.file_path == "config/aws.yaml"
        assert finding.commit == "abc123def456"
        assert finding.author == "John Doe"
        assert finding.email == "john@example.com"
        assert finding.line == 15
        assert finding.repository_url == "https://github.com/example/repo"

    def test_parse_output_filesystem_metadata(self):
        """Test parsing TruffleHog output with filesystem metadata"""
        scanner = TruffleHogScanner()

        trufflehog_output = json.dumps(
            {
                "SourceMetadata": {"Data": {"Filesystem": {"file": "/app/secrets.txt", "line": 5}}},
                "DetectorType": "GitHub",
                "DetectorName": "GitHub Token",
                "Raw": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
                "Verified": False,
            }
        )

        findings = scanner._parse_output(trufflehog_output)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detector_type == "GitHub"
        assert finding.detector_name == "GitHub Token"
        assert finding.verified is False
        assert finding.file_path == "/app/secrets.txt"
        assert finding.line == 5
        assert finding.commit == ""
        assert finding.author == ""
        assert finding.email == ""
        assert finding.repository_url is None

    def test_parse_output_multiple_findings(self):
        """Test parsing multiple findings (newline-delimited JSON)"""
        scanner = TruffleHogScanner()

        finding1 = json.dumps(
            {
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": "file1.py",
                            "commit": "abc123",
                            "timestamp": "2024-01-08T12:00:00Z",
                            "author": "Alice",
                            "email": "alice@example.com",
                            "line": 10,
                        }
                    }
                },
                "DetectorType": "AWS",
                "DetectorName": "AWS Key",
                "Raw": "secret1",
                "Verified": True,
            }
        )

        finding2 = json.dumps(
            {
                "SourceMetadata": {"Data": {"Filesystem": {"file": "file2.py", "line": 20}}},
                "DetectorType": "Slack",
                "DetectorName": "Slack Webhook",
                "Raw": "secret2",
                "Verified": False,
            }
        )

        output = f"{finding1}\n{finding2}"
        findings = scanner._parse_output(output)

        assert len(findings) == 2
        assert findings[0].detector_type == "AWS"
        assert findings[0].verified is True
        assert findings[1].detector_type == "Slack"
        assert findings[1].verified is False

    def test_parse_output_invalid_json_line_rejected(self):
        """Test that invalid JSON lines fail the scan"""
        scanner = TruffleHogScanner()

        valid_finding = json.dumps(
            {
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": "test.py",
                            "commit": "abc",
                            "timestamp": "2024-01-08T12:00:00Z",
                            "author": "Test",
                            "email": "test@test.com",
                            "line": 1,
                        }
                    }
                },
                "DetectorType": "Test",
                "DetectorName": "Test Detector",
                "Raw": "secret",
                "Verified": True,
            }
        )

        output = f"invalid json\n{valid_finding}\n{{broken json"

        with pytest.raises(ValueError):
            scanner._parse_output(output)

    def test_parse_output_missing_fields_handled(self):
        """Test parsing output with missing optional fields"""
        scanner = TruffleHogScanner()

        minimal_finding = json.dumps({"SourceMetadata": {"Data": {}}, "DetectorType": "Unknown"})

        findings = scanner._parse_output(minimal_finding)

        # Should not crash, should create finding with defaults
        assert len(findings) == 1
        assert findings[0].detector_type == "Unknown"

    def test_parse_output_public_wrapper(self):
        """Test public parse_output wrapper method"""
        scanner = TruffleHogScanner()

        output = json.dumps(
            {
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": "test.py",
                            "commit": "abc",
                            "timestamp": "2024-01-08T12:00:00Z",
                            "author": "Test",
                            "email": "test@test.com",
                            "line": 1,
                        }
                    }
                },
                "DetectorType": "Test",
                "DetectorName": "Test",
                "Raw": "secret",
                "Verified": True,
            }
        )

        # Both methods should return same result
        findings1 = scanner.parse_output(output)
        findings2 = scanner._parse_output(output)

        assert len(findings1) == len(findings2)
        assert findings1[0].detector_type == findings2[0].detector_type

    @patch("subprocess.run")
    def test_scan_filesystem_verified_only(self, mock_run, tmp_path):
        """Test filesystem scan with verified_only flag"""
        # Three calls: __init__ check, scan() check, and actual scan
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            Mock(
                returncode=183,  # TruffleHog returns 183 when secrets found
                stdout=json.dumps(
                    {
                        "SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / "test.py"), "line": 5}}},
                        "DetectorType": "AWS",
                        "DetectorName": "AWS Key",
                        "Raw": "AKIAIOSFODNN7EXAMPLE",
                        "Verified": True,
                    }
                ),
                stderr="",
            ),
        ]

        scanner = TruffleHogScanner()
        results = scanner.scan(str(tmp_path), scan_type="filesystem")

        assert results["tool"] == "trufflehog"
        assert results["scan_type"] == "filesystem"
        assert results["findings_count"] == 1
        assert results["verified_count"] == 1
        assert results["unverified_count"] == 0
        assert len(results["findings"]) == 1

        # Verify command construction - no shell=True
        call_args = mock_run.call_args_list[2]  # Get third call (actual scan)
        cmd = call_args[0][0]
        assert cmd[0] == "trufflehog"
        assert cmd[1] == "filesystem"
        assert cmd[2] == str(tmp_path)
        assert "--json" in cmd
        assert "--only-verified" in cmd
        assert "shell" not in call_args[1] or call_args[1]["shell"] is False

    @patch("subprocess.run")
    def test_scan_git_with_depth(self, mock_run, tmp_path):
        """Test git scan with depth limit"""
        # Three calls: __init__ check, scan() check, and actual scan
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            Mock(
                returncode=0,  # No secrets found
                stdout="",
                stderr="",
            ),
        ]

        config = {"scan_depth": 100}
        scanner = TruffleHogScanner(config)
        scanner.scan(str(tmp_path), scan_type="git")

        # Verify command includes depth
        call_args = mock_run.call_args_list[2]  # Get third call (actual scan)
        cmd = call_args[0][0]
        assert "trufflehog" in cmd
        assert "git" in cmd
        assert "--max-depth" in cmd
        assert "100" in cmd

    @patch("subprocess.run")
    def test_scan_include_unverified(self, mock_run, tmp_path):
        """Test scan including unverified secrets"""
        verified_finding = json.dumps(
            {
                "SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / "file1.py"), "line": 5}}},
                "DetectorType": "AWS",
                "DetectorName": "AWS",
                "Raw": "secret1",
                "Verified": True,
            }
        )
        unverified_finding = json.dumps(
            {
                "SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / "file2.py"), "line": 10}}},
                "DetectorType": "GitHub",
                "DetectorName": "GitHub",
                "Raw": "secret2",
                "Verified": False,
            }
        )

        # Three calls: __init__ check, scan() check, and actual scan
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            Mock(returncode=183, stdout=f"{verified_finding}\n{unverified_finding}", stderr=""),
        ]

        config = {"verified_only": False, "include_unverified": True}
        scanner = TruffleHogScanner(config)
        results = scanner.scan(str(tmp_path))

        assert results["findings_count"] == 2
        assert results["verified_count"] == 1
        assert results["unverified_count"] == 1

        # Verify --only-verified NOT in command
        call_args = mock_run.call_args_list[2]  # Get third call (actual scan)
        cmd = call_args[0][0]
        assert "--only-verified" not in cmd

    @patch("subprocess.run")
    def test_scan_path_not_found(self, mock_run):
        """Test scan with non-existent path"""
        # Two calls: __init__ check, scan() check (no actual scan since path doesn't exist)
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
        ]

        scanner = TruffleHogScanner()
        results = scanner.scan("/nonexistent/path")

        assert "error" in results
        assert results["error"] == "path_not_found"
        assert results["findings"] == []

    @patch("subprocess.run")
    def test_scan_trufflehog_not_installed(self, mock_run):
        """Test scan when TruffleHog is not installed"""
        mock_run.side_effect = FileNotFoundError()

        scanner = TruffleHogScanner()
        results = scanner.scan("/app")

        assert "error" in results
        assert results["error"] == "trufflehog_not_installed"

    @patch("subprocess.run")
    def test_scan_trufflehog_failure(self, mock_run, tmp_path):
        """Test scan when TruffleHog fails with unexpected exit code"""
        # Three calls: __init__ check, scan() check, and actual scan
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            Mock(
                returncode=2,  # Unexpected error code
                stdout="",
                stderr="Error: Something went wrong",
            ),
        ]

        scanner = TruffleHogScanner()
        results = scanner.scan(str(tmp_path))

        assert "error" in results
        assert results["error"] == "trufflehog_failed"
        assert results["exit_code"] == 2
        assert "stderr" in results

    @patch("subprocess.run")
    def test_scan_timeout(self, mock_run, tmp_path):
        """Test scan timeout handling"""
        # Three calls: __init__ check, scan() check, and actual scan (timeout)
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            subprocess.TimeoutExpired("trufflehog", 600),  # actual scan call
        ]

        scanner = TruffleHogScanner()
        results = scanner.scan(str(tmp_path))

        assert "error" in results
        assert results["error"] == "timeout"

    @patch("subprocess.run")
    def test_scan_exception_handling(self, mock_run, tmp_path):
        """Test generic exception handling during scan"""
        # Three calls: __init__ check, scan() check, and actual scan (exception)
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            Exception("Unexpected error"),  # actual scan call
        ]

        scanner = TruffleHogScanner()
        results = scanner.scan(str(tmp_path))

        assert "error" in results
        assert "Unexpected error" in results["error"]

    @patch("subprocess.run")
    def test_scan_verified_only_filtering(self, mock_run, tmp_path):
        """Test that verified_only config filters results correctly"""
        verified_finding = json.dumps(
            {
                "SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / "file1.py"), "line": 5}}},
                "DetectorType": "AWS",
                "DetectorName": "AWS",
                "Raw": "secret1",
                "Verified": True,
            }
        )
        unverified_finding = json.dumps(
            {
                "SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / "file2.py"), "line": 10}}},
                "DetectorType": "GitHub",
                "DetectorName": "GitHub",
                "Raw": "secret2",
                "Verified": False,
            }
        )

        # Three calls: __init__ check, scan() check, and actual scan
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            Mock(returncode=183, stdout=f"{verified_finding}\n{unverified_finding}", stderr=""),
        ]

        scanner = TruffleHogScanner({"verified_only": True})
        results = scanner.scan(str(tmp_path))

        # Should only include verified finding
        assert results["findings_count"] == 1
        assert results["verified_count"] == 1
        assert results["findings"][0]["verified"] is True

    @patch("subprocess.run")
    def test_scan_no_secrets_found(self, mock_run, tmp_path):
        """Test scan when no secrets are found"""
        # Three calls: __init__ check, scan() check, and actual scan
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            Mock(
                returncode=0,  # Exit code 0 means no secrets
                stdout="",
                stderr="",
            ),
        ]

        scanner = TruffleHogScanner()
        results = scanner.scan(str(tmp_path))

        assert results["tool"] == "trufflehog"
        assert results["findings_count"] == 0
        assert results["verified_count"] == 0
        assert results["findings"] == []

    @patch("subprocess.run")
    def test_scan_subprocess_security(self, mock_run, tmp_path):
        """Test that scan never uses shell=True for security"""
        # Three calls: __init__ check, scan() check, and actual scan
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            Mock(returncode=0, stdout="", stderr=""),  # actual scan call
        ]

        scanner = TruffleHogScanner()
        scanner.scan(str(tmp_path))

        # Verify subprocess.run was called without shell=True (check third call)
        call_args = mock_run.call_args_list[2]
        assert "shell" not in call_args[1] or call_args[1]["shell"] is False

        # Verify command is a list (array), not a string
        assert isinstance(call_args[0][0], list)

    @patch("subprocess.run")
    @patch.object(TruffleHogScanner, "scan")
    def test_scan_file_success(self, mock_scan, mock_run):
        """Test scanning individual file"""
        mock_run.return_value = Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr="")

        # Create a temporary test file
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            test_file = f.name
            f.write("test content")

        try:
            # Normalize path to handle macOS /private/var
            normalized_path = os.path.realpath(test_file)
            parent_dir = os.path.dirname(normalized_path)

            mock_scan.return_value = {
                "tool": "trufflehog",
                "findings": [
                    {"file_path": normalized_path, "verified": True},
                    {"file_path": os.path.join(parent_dir, "other.txt"), "verified": False},
                ],
                "findings_count": 2,
                "verified_count": 1,
            }

            scanner = TruffleHogScanner()
            results = scanner.scan_file(test_file)

            # Should have called scan on parent directory
            mock_scan.assert_called_once()

            # Results should be filtered to just this file
            assert results["target"] == normalized_path
            assert results["findings_count"] == 1
        finally:
            Path(test_file).unlink()

    def test_scan_file_not_found(self):
        """Test scan_file with non-existent file"""
        scanner = TruffleHogScanner()
        results = scanner.scan_file("/nonexistent/file.txt")

        assert "error" in results
        assert results["error"] == "file_not_found"

    def test_scan_file_not_a_file(self, tmp_path):
        """Test scan_file with directory instead of file"""
        scanner = TruffleHogScanner()
        results = scanner.scan_file(str(tmp_path))

        assert "error" in results
        assert results["error"] == "not_a_file"

    def test_save_results_redacts_secrets(self, tmp_path):
        """Test that save_results redacts raw secrets"""
        scanner = TruffleHogScanner()

        results = {
            "tool": "trufflehog",
            "findings": [
                {
                    "detector_type": "AWS",
                    "raw": "AKIAIOSFODNN7EXAMPLE",
                    "redacted": "AKIA************MPLE",
                    "verified": True,
                }
            ],
            "findings_count": 1,
        }

        output_path = tmp_path / "results.json"
        scanner.save_results(results, str(output_path))

        assert output_path.exists()

        with open(output_path) as f:
            saved = json.load(f)

        # Raw secret should be replaced with redacted version
        assert saved["findings"][0]["raw"] == "AKIA************MPLE"

    def test_save_results_creates_parent_directories(self, tmp_path):
        """Test that save_results creates parent directories"""
        scanner = TruffleHogScanner()

        results = {"tool": "trufflehog", "findings": []}
        output_path = tmp_path / "nested" / "dir" / "results.json"

        scanner.save_results(results, str(output_path))

        assert output_path.exists()
        assert output_path.parent.exists()

    def test_save_results_handles_no_findings(self, tmp_path):
        """Test save_results with no findings"""
        scanner = TruffleHogScanner()

        results = {"tool": "trufflehog", "findings_count": 0}
        output_path = tmp_path / "results.json"

        scanner.save_results(results, str(output_path))

        assert output_path.exists()

        with open(output_path) as f:
            saved = json.load(f)

        assert saved["findings_count"] == 0


class TestTruffleHogCLI:
    """Test command-line interface functionality"""

    @patch("subprocess.run")
    def test_cli_check_install(self, mock_run):
        """Test --check-install flag"""
        mock_run.return_value = Mock(returncode=0, stdout="trufflehog v3.63.0\n")

        from trufflehog_scanner import main

        with patch("sys.argv", ["trufflehog_scanner.py", "/app", "--check-install"]):
            result = main()
            assert result == 0

    @patch.object(TruffleHogScanner, "scan")
    def test_cli_verified_secrets_exit_code(self, mock_scan):
        """Test that CLI returns exit code 1 when verified secrets found"""
        mock_scan.return_value = {"tool": "trufflehog", "findings": [], "findings_count": 2, "verified_count": 1}

        from trufflehog_scanner import main

        with patch("sys.argv", ["trufflehog_scanner.py", "/app"]):
            result = main()
            assert result == 1

    @patch.object(TruffleHogScanner, "scan")
    def test_cli_no_secrets_exit_code(self, mock_scan):
        """Test that CLI returns exit code 0 when no secrets found"""
        mock_scan.return_value = {"tool": "trufflehog", "findings": [], "findings_count": 0, "verified_count": 0}

        from trufflehog_scanner import main

        with patch("sys.argv", ["trufflehog_scanner.py", "/app"]):
            result = main()
            assert result == 0


class TestTruffleHogIntegration:
    """Integration-style tests (mocked but realistic scenarios)"""

    @patch("subprocess.run")
    def test_end_to_end_git_scan(self, mock_run, tmp_path):
        """Test complete git scan workflow"""
        # Mock TruffleHog output with multiple findings
        finding1 = json.dumps(
            {
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": "config/database.yml",
                            "commit": "abc123",
                            "timestamp": "2024-01-08T12:00:00Z",
                            "author": "Developer",
                            "email": "dev@example.com",
                            "line": 5,
                            "repository": "https://github.com/example/repo",
                        }
                    }
                },
                "DetectorType": "PostgreSQL",
                "DetectorName": "PostgreSQL Connection String",
                "Raw": "postgresql://user:password@localhost/db",
                "Redacted": "postgresql://user:***@localhost/db",
                "Verified": True,
            }
        )

        finding2 = json.dumps(
            {
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": ".env",
                            "commit": "def456",
                            "timestamp": "2024-01-08T11:00:00Z",
                            "author": "Admin",
                            "email": "admin@example.com",
                            "line": 10,
                        }
                    }
                },
                "DetectorType": "Generic",
                "DetectorName": "Generic Secret",
                "Raw": "secret_key_12345",
                "Verified": False,
            }
        )

        # Three calls: __init__ check, scan() check, and actual scan
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            Mock(returncode=183, stdout=f"{finding1}\n{finding2}", stderr=""),
        ]

        scanner = TruffleHogScanner({"verified_only": False})
        results = scanner.scan(str(tmp_path), scan_type="git")

        assert results["tool"] == "trufflehog"
        assert results["scan_type"] == "git"
        assert results["findings_count"] == 2
        assert results["verified_count"] == 1
        assert results["unverified_count"] == 1

        # Verify findings structure
        findings = results["findings"]
        assert findings[0]["detector_type"] == "PostgreSQL"
        assert findings[0]["verified"] is True
        assert findings[1]["detector_type"] == "Generic"
        assert findings[1]["verified"] is False

    @patch("subprocess.run")
    def test_end_to_end_filesystem_scan(self, mock_run, tmp_path):
        """Test complete filesystem scan workflow"""
        finding = json.dumps(
            {
                "SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / "credentials.json"), "line": 3}}},
                "DetectorType": "AWS",
                "DetectorName": "AWS Access Key",
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "Redacted": "AKIA************MPLE",
                "Verified": True,
            }
        )

        # Three calls: __init__ check, scan() check, and actual scan
        mock_run.side_effect = [
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # __init__ check
            Mock(returncode=0, stdout="trufflehog v3.63.0\n", stderr=""),  # scan() check
            Mock(returncode=183, stdout=finding, stderr=""),
        ]

        scanner = TruffleHogScanner()
        results = scanner.scan(str(tmp_path), scan_type="filesystem")

        assert results["scan_type"] == "filesystem"
        assert results["verified_count"] == 1
        assert results["findings"][0]["file_path"] == str(tmp_path / "credentials.json")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
