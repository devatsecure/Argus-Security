#!/usr/bin/env python3
"""
Unit tests for Checkov Scanner
Tests IaC security scanning functionality including Terraform, Kubernetes, and Dockerfile support
"""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open
import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from checkov_scanner import CheckovFinding, CheckovScanResult, CheckovScanner


class TestCheckovFinding:
    """Test CheckovFinding dataclass"""

    def test_finding_creation(self):
        """Test creating a Checkov finding"""
        finding = CheckovFinding(
            check_id="CKV_AWS_1",
            check_name="Ensure S3 bucket has encryption enabled",
            check_class="checkov.terraform.checks.resource.aws.S3Encryption",
            severity="HIGH",
            file_path="main.tf",
            resource="aws_s3_bucket.example",
            resource_type="aws_s3_bucket",
            file_line_range=[10, 20],
            guideline="https://docs.bridgecrew.io/docs/s3_1-encryption",
            description="S3 bucket should have encryption enabled",
            code_block=["resource \"aws_s3_bucket\" \"example\" {", "  bucket = \"my-bucket\"", "}"],
            check_result={"result": "FAILED"},
            framework="terraform",
        )

        assert finding.check_id == "CKV_AWS_1"
        assert finding.severity == "HIGH"
        assert finding.framework == "terraform"
        assert finding.resource_type == "aws_s3_bucket"

    def test_finding_to_dict(self):
        """Test converting finding to dictionary"""
        finding = CheckovFinding(
            check_id="CKV_K8S_1",
            check_name="Test check",
            check_class="checkov.kubernetes.checks.Test",
            severity="MEDIUM",
            file_path="deployment.yaml",
            resource="nginx-deployment",
            resource_type="Deployment",
            file_line_range=[1, 10],
            guideline="",
            description="Test description",
            code_block=["apiVersion: apps/v1", "kind: Deployment"],
            check_result={},
            framework="kubernetes",
        )

        result = finding.to_dict()
        assert isinstance(result, dict)
        assert result["check_id"] == "CKV_K8S_1"
        assert result["severity"] == "MEDIUM"
        assert result["framework"] == "kubernetes"
        assert result["file_line_range"] == [1, 10]


class TestCheckovScanResult:
    """Test CheckovScanResult dataclass"""

    def test_scan_result_creation(self):
        """Test creating a scan result"""
        findings = [
            CheckovFinding(
                check_id="CKV_1",
                check_name="Test",
                check_class="checkov.test",
                severity="HIGH",
                file_path="test.tf",
                resource="test_resource",
                resource_type="test",
                file_line_range=[1, 2],
                guideline="",
                description="Test",
                code_block=[],
                check_result={},
                framework="terraform",
            )
        ]

        result = CheckovScanResult(
            scan_type="filesystem",
            target="/tmp/test",
            timestamp="2024-01-01T00:00:00",
            total_checks=100,
            passed_checks=90,
            failed_checks=10,
            skipped_checks=0,
            parsing_errors=0,
            findings=findings,
            frameworks=["terraform"],
            scan_duration_seconds=5.5,
            checkov_version="2.3.0",
        )

        assert result.scan_type == "filesystem"
        assert result.total_checks == 100
        assert result.failed_checks == 10
        assert len(result.findings) == 1

    def test_scan_result_to_dict(self):
        """Test converting scan result to dictionary"""
        result = CheckovScanResult(
            scan_type="file",
            target="test.tf",
            timestamp="2024-01-01T00:00:00",
            total_checks=10,
            passed_checks=9,
            failed_checks=1,
            skipped_checks=0,
            parsing_errors=0,
            findings=[],
            frameworks=["terraform"],
            scan_duration_seconds=2.0,
            checkov_version="2.3.0",
        )

        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict["scan_type"] == "file"
        assert result_dict["total_checks"] == 10
        assert result_dict["frameworks"] == ["terraform"]
        assert isinstance(result_dict["findings"], list)


class TestCheckovScanner:
    """Test CheckovScanner class"""

    def test_scanner_initialization_default(self):
        """Test scanner initialization with default config"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            assert scanner.config == {}
            assert scanner.frameworks == []
            assert scanner.checks == []
            assert scanner.skip_checks == []
            assert scanner.compact is True
            assert scanner.quiet is True
            assert scanner.download_external_modules is False

    def test_scanner_initialization_custom_config(self):
        """Test scanner initialization with custom configuration"""
        config = {
            "frameworks": ["terraform", "kubernetes"],
            "checks": ["CKV_AWS_1", "CKV_AWS_2"],
            "skip_checks": ["CKV_AWS_20"],
            "compact": False,
            "quiet": False,
            "download_external_modules": True,
        }

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner(config)

            assert scanner.frameworks == ["terraform", "kubernetes"]
            assert scanner.checks == ["CKV_AWS_1", "CKV_AWS_2"]
            assert scanner.skip_checks == ["CKV_AWS_20"]
            assert scanner.compact is False
            assert scanner.quiet is False
            assert scanner.download_external_modules is True

    @patch("subprocess.run")
    def test_check_checkov_installed_true(self, mock_run):
        """Test checking if Checkov is installed (success)"""
        mock_run.return_value = Mock(returncode=0)

        scanner = CheckovScanner()
        result = scanner._check_checkov_installed()

        assert result is True
        mock_run.assert_called_with(["which", "checkov"], capture_output=True, text=True, timeout=5)

    @patch("subprocess.run")
    def test_check_checkov_installed_false(self, mock_run):
        """Test checking if Checkov is installed (failure)"""
        mock_run.side_effect = FileNotFoundError()

        scanner = CheckovScanner()
        result = scanner._check_checkov_installed()

        assert result is False

    @patch("subprocess.run")
    def test_check_checkov_installed_subprocess_error(self, mock_run):
        """Test checking if Checkov is installed (subprocess error)"""
        mock_run.side_effect = subprocess.SubprocessError()

        scanner = CheckovScanner()
        result = scanner._check_checkov_installed()

        assert result is False

    @patch.object(CheckovScanner, "_check_checkov_installed")
    @patch("subprocess.run")
    def test_install_checkov_success(self, mock_run, mock_check):
        """Test successful Checkov installation"""
        # Three calls: __init__ check, install_checkov check (before pip), check after pip install
        mock_check.side_effect = [False, False, True]
        mock_run.return_value = Mock(returncode=0, stderr="")

        scanner = CheckovScanner()
        result = scanner.install_checkov()

        assert result is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args == [sys.executable, "-m", "pip", "install", "checkov"]

    @patch.object(CheckovScanner, "_check_checkov_installed")
    def test_install_checkov_already_installed(self, mock_check):
        """Test installation when Checkov is already installed"""
        mock_check.return_value = True

        scanner = CheckovScanner()
        result = scanner.install_checkov()

        assert result is True

    @patch.object(CheckovScanner, "_check_checkov_installed")
    @patch("subprocess.run")
    def test_install_checkov_failure(self, mock_run, mock_check):
        """Test failed Checkov installation"""
        mock_check.side_effect = [False, False]  # Never becomes installed
        mock_run.return_value = Mock(returncode=1, stderr="Installation failed")

        scanner = CheckovScanner()
        result = scanner.install_checkov()

        assert result is False

    @patch.object(CheckovScanner, "_check_checkov_installed")
    @patch("subprocess.run")
    def test_install_checkov_timeout(self, mock_run, mock_check):
        """Test Checkov installation timeout"""
        mock_check.return_value = False
        mock_run.side_effect = subprocess.TimeoutExpired("pip", 120)

        scanner = CheckovScanner()
        result = scanner.install_checkov()

        assert result is False

    def test_build_scan_command_file(self):
        """Test building scan command for a file"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            cmd = scanner._build_scan_command("/tmp/test.tf", framework="terraform")

            assert "checkov" in cmd
            assert "--file" in cmd
            assert "/tmp/test.tf" in cmd
            assert "--output" in cmd
            assert "json" in cmd
            assert "--framework" in cmd
            assert "terraform" in cmd
            assert "--compact" in cmd
            assert "--quiet" in cmd

    def test_build_scan_command_directory(self):
        """Test building scan command for a directory"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            with patch("pathlib.Path.is_file", return_value=False):
                cmd = scanner._build_scan_command("/tmp/test-dir")

                assert "checkov" in cmd
                assert "--directory" in cmd
                assert "/tmp/test-dir" in cmd
                assert "--output" in cmd
                assert "json" in cmd

    def test_build_scan_command_with_checks(self):
        """Test building scan command with specific checks"""
        config = {
            "checks": ["CKV_AWS_1", "CKV_AWS_2"],
            "skip_checks": ["CKV_AWS_20"],
        }

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner(config)
            cmd = scanner._build_scan_command("/tmp/test.tf")

            assert "--check" in cmd
            assert "CKV_AWS_1,CKV_AWS_2" in cmd
            assert "--skip-check" in cmd
            assert "CKV_AWS_20" in cmd

    def test_build_scan_command_with_frameworks(self):
        """Test building scan command with multiple frameworks"""
        config = {"frameworks": ["terraform", "kubernetes"]}

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner(config)
            cmd = scanner._build_scan_command("/tmp/test")

            framework_count = cmd.count("--framework")
            assert framework_count == 2
            assert "terraform" in cmd
            assert "kubernetes" in cmd

    def test_build_scan_command_download_modules(self):
        """Test building scan command with external modules download"""
        config = {"download_external_modules": True}

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner(config)
            cmd = scanner._build_scan_command("/tmp/test.tf")

            assert "--download-external-modules" in cmd
            assert "true" in cmd

    def test_detect_framework_terraform(self):
        """Test framework detection for Terraform files"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            assert scanner._detect_framework(Path("main.tf")) == "terraform"
            assert scanner._detect_framework(Path("variables.hcl")) == "terraform"

    def test_detect_framework_dockerfile(self):
        """Test framework detection for Dockerfiles"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            assert scanner._detect_framework(Path("Dockerfile")) == "dockerfile"
            assert scanner._detect_framework(Path("Dockerfile.prod")) == "dockerfile"

    def test_detect_framework_kubernetes(self):
        """Test framework detection for Kubernetes files"""
        k8s_content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
"""

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            with patch("builtins.open", mock_open(read_data=k8s_content)):
                assert scanner._detect_framework(Path("deployment.yaml")) == "kubernetes"

    def test_detect_framework_cloudformation(self):
        """Test framework detection for CloudFormation files"""
        cfn_content = """
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {}
}
"""

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            with patch("builtins.open", mock_open(read_data=cfn_content)):
                assert scanner._detect_framework(Path("template.json")) == "cloudformation"

    def test_detect_framework_arm(self):
        """Test framework detection for Azure ARM templates"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            assert scanner._detect_framework(Path("azure-template.json")) == "arm"

    def test_detect_framework_yaml_fallback(self):
        """Test framework detection falls back to kubernetes for YAML"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            with patch("builtins.open", side_effect=Exception("File read error")):
                assert scanner._detect_framework(Path("unknown.yaml")) == "kubernetes"

    def test_normalize_severity_critical(self):
        """Test severity normalization for CRITICAL"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            assert scanner._normalize_severity("CRITICAL") == "CRITICAL"
            assert scanner._normalize_severity("critical") == "CRITICAL"

    def test_normalize_severity_high(self):
        """Test severity normalization for HIGH"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            assert scanner._normalize_severity("HIGH") == "HIGH"
            assert scanner._normalize_severity("high") == "HIGH"

    def test_normalize_severity_medium(self):
        """Test severity normalization for MEDIUM"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            assert scanner._normalize_severity("MEDIUM") == "MEDIUM"
            assert scanner._normalize_severity("MODERATE") == "MEDIUM"
            assert scanner._normalize_severity("moderate") == "MEDIUM"

    def test_normalize_severity_low(self):
        """Test severity normalization for LOW"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            assert scanner._normalize_severity("LOW") == "LOW"
            assert scanner._normalize_severity("INFO") == "LOW"
            assert scanner._normalize_severity("INFORMATIONAL") == "LOW"
            assert scanner._normalize_severity("info") == "LOW"

    def test_normalize_severity_unknown(self):
        """Test severity normalization for unknown values"""
        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()

            assert scanner._normalize_severity("UNKNOWN") == "MEDIUM"
            assert scanner._normalize_severity("") == "MEDIUM"

    def test_parse_output_with_findings(self):
        """Test parsing Checkov output with findings"""
        checkov_output = {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_1",
                        "check_name": "S3 encryption check",
                        "check_class": "checkov.terraform.checks.aws.S3Encryption",
                        "file_path": "main.tf",
                        "resource": "aws_s3_bucket.example",
                        "resource_type": "aws_s3_bucket",
                        "file_line_range": [10, 20],
                        "guideline": "https://example.com",
                        "description": "Ensure S3 encryption",
                        "code_block": ["resource \"aws_s3_bucket\" \"example\" {}"],
                        "check_result": {"severity": "HIGH"},
                    },
                    {
                        "check_id": "CKV_K8S_1",
                        "check_name": "K8s security check",
                        "check_class": "checkov.kubernetes.checks.SecurityContext",
                        "file_path": "deployment.yaml",
                        "resource": "nginx",
                        "resource_type": "Deployment",
                        "file_line_range": [1, 10],
                        "guideline": "",
                        "description": "Security context required",
                        "code_block": ["apiVersion: apps/v1"],
                        "check_result": {"severity": "MEDIUM"},
                    },
                ]
            }
        }

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            findings = scanner.parse_output(checkov_output)

            assert len(findings) == 2
            assert findings[0].check_id == "CKV_AWS_1"
            assert findings[0].severity == "HIGH"
            assert findings[0].framework == "terraform"
            assert findings[1].check_id == "CKV_K8S_1"
            assert findings[1].severity == "MEDIUM"
            assert findings[1].framework == "kubernetes"

    def test_parse_output_no_findings(self):
        """Test parsing Checkov output with no findings"""
        checkov_output = {"results": {"failed_checks": []}}

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            findings = scanner.parse_output(checkov_output)

            assert len(findings) == 0

    def test_parse_output_missing_fields(self):
        """Test parsing Checkov output with missing fields"""
        checkov_output = {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_TEST",
                        # Missing many fields
                    }
                ]
            }
        }

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            findings = scanner.parse_output(checkov_output)

            assert len(findings) == 1
            assert findings[0].check_id == "CKV_TEST"
            assert findings[0].check_name == "IaC Security Check"  # Default
            assert findings[0].severity == "MEDIUM"  # Default

    def test_parse_output_invalid_finding(self):
        """Test parsing Checkov output with invalid finding (exception handling)"""
        checkov_output = {
            "results": {
                "failed_checks": [
                    None,  # Invalid finding that will cause exception
                    {
                        "check_id": "CKV_VALID",
                        "check_name": "Valid check",
                        "check_class": "checkov.terraform.checks.Test",
                        "file_path": "test.tf",
                        "resource": "test",
                        "resource_type": "test",
                        "file_line_range": [1, 2],
                        "guideline": "",
                        "description": "Test",
                        "code_block": [],
                        "check_result": {},
                    },
                ]
            }
        }

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            findings = scanner.parse_output(checkov_output)

            # Should skip invalid finding and parse valid one
            assert len(findings) == 1
            assert findings[0].check_id == "CKV_VALID"

    def test_extract_frameworks(self):
        """Test extracting frameworks from Checkov output"""
        checkov_output = {
            "results": {
                "failed_checks": [
                    {"check_class": "checkov.terraform.checks.aws.Test"},
                    {"check_class": "checkov.kubernetes.checks.security.Test"},
                    {"check_class": "checkov.terraform.checks.gcp.Test"},
                ],
                "passed_checks": [
                    {"check_class": "checkov.dockerfile.checks.Test"},
                ],
            }
        }

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            frameworks = scanner._extract_frameworks(checkov_output)

            assert frameworks == ["dockerfile", "kubernetes", "terraform"]
            assert isinstance(frameworks, list)

    def test_extract_frameworks_empty(self):
        """Test extracting frameworks with no checks"""
        checkov_output = {"results": {"failed_checks": [], "passed_checks": []}}

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            frameworks = scanner._extract_frameworks(checkov_output)

            assert frameworks == []

    @patch("subprocess.run")
    def test_get_checkov_version_success(self, mock_run):
        """Test getting Checkov version"""
        mock_run.return_value = Mock(
            stdout="2.3.0\nother output\n",
            returncode=0,
        )

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            version = scanner._get_checkov_version()

            assert version == "2.3.0"

    @patch("subprocess.run")
    def test_get_checkov_version_failure(self, mock_run):
        """Test getting Checkov version on failure"""
        mock_run.side_effect = Exception("Command failed")

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            version = scanner._get_checkov_version()

            assert version == "unknown"

    def test_save_results(self, tmp_path):
        """Test saving scan results to file"""
        scan_result = CheckovScanResult(
            scan_type="filesystem",
            target="/tmp/test",
            timestamp="2024-01-01T00:00:00",
            total_checks=100,
            passed_checks=90,
            failed_checks=10,
            skipped_checks=0,
            parsing_errors=0,
            findings=[],
            frameworks=["terraform"],
            scan_duration_seconds=5.0,
            checkov_version="2.3.0",
        )

        output_file = tmp_path / "results.json"

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            scanner._save_results(scan_result, str(output_file))

            assert output_file.exists()
            with open(output_file) as f:
                loaded = json.load(f)
            assert loaded["scan_type"] == "filesystem"
            assert loaded["total_checks"] == 100

    def test_save_results_creates_parent_dirs(self, tmp_path):
        """Test saving results creates parent directories"""
        scan_result = CheckovScanResult(
            scan_type="file",
            target="test.tf",
            timestamp="2024-01-01T00:00:00",
            total_checks=10,
            passed_checks=9,
            failed_checks=1,
            skipped_checks=0,
            parsing_errors=0,
            findings=[],
            frameworks=["terraform"],
            scan_duration_seconds=1.0,
            checkov_version="2.3.0",
        )

        output_file = tmp_path / "nested" / "dir" / "results.json"

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            scanner._save_results(scan_result, str(output_file))

            assert output_file.exists()
            assert output_file.parent.exists()

    @patch.object(CheckovScanner, "_check_checkov_installed")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_file")
    @patch("subprocess.run")
    @patch.object(CheckovScanner, "_get_checkov_version")
    def test_scan_success(self, mock_version, mock_run, mock_is_file, mock_exists, mock_check):
        """Test successful Checkov scan"""
        mock_check.return_value = True
        mock_exists.return_value = True
        mock_is_file.return_value = False  # Directory scan
        mock_version.return_value = "2.3.0"

        checkov_output = {
            "summary": {
                "passed": 80,
                "failed": 20,
                "skipped": 5,
                "parsing_errors": 0,
            },
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_1",
                        "check_name": "Test check",
                        "check_class": "checkov.terraform.checks.Test",
                        "file_path": "main.tf",
                        "resource": "test",
                        "resource_type": "test",
                        "file_line_range": [1, 2],
                        "guideline": "",
                        "description": "Test",
                        "code_block": [],
                        "check_result": {"severity": "HIGH"},
                    }
                ],
                "passed_checks": [],
            },
        }

        mock_run.return_value = Mock(
            returncode=1,  # Checkov returns 1 when findings are found
            stdout=json.dumps(checkov_output),
            stderr="",
        )

        scanner = CheckovScanner()
        result = scanner.scan("/tmp/test")

        assert result.scan_type == "filesystem"
        assert result.total_checks == 105  # 80+20+5+0
        assert result.passed_checks == 80
        assert result.failed_checks == 20
        assert len(result.findings) == 1
        assert result.findings[0].check_id == "CKV_AWS_1"

    @patch.object(CheckovScanner, "_check_checkov_installed")
    def test_scan_checkov_not_installed(self, mock_check):
        """Test scan fails when Checkov is not installed and path doesn't exist"""
        mock_check.return_value = False

        scanner = CheckovScanner()

        # When checkov is not installed, scan() warns but continues.
        # It then checks path existence and raises RuntimeError for missing path.
        with pytest.raises(RuntimeError, match="Target path not found"):
            scanner.scan("/tmp/test")

    @patch.object(CheckovScanner, "_check_checkov_installed")
    @patch("pathlib.Path.exists")
    def test_scan_target_not_found(self, mock_exists, mock_check):
        """Test scan fails when target path doesn't exist"""
        mock_check.return_value = True
        mock_exists.return_value = False

        scanner = CheckovScanner()

        with pytest.raises(RuntimeError, match="Target path not found"):
            scanner.scan("/nonexistent/path")

    @patch.object(CheckovScanner, "_check_checkov_installed")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_file")
    @patch("subprocess.run")
    def test_scan_command_failure(self, mock_run, mock_is_file, mock_exists, mock_check):
        """Test scan handles command failure"""
        mock_check.return_value = True
        mock_exists.return_value = True
        mock_is_file.return_value = False
        mock_run.return_value = Mock(
            returncode=2,  # Error code
            stdout="",
            stderr="Command failed",
        )

        scanner = CheckovScanner()

        with pytest.raises(RuntimeError, match="Checkov scan failed"):
            scanner.scan("/tmp/test")

    @patch.object(CheckovScanner, "_check_checkov_installed")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_file")
    @patch("subprocess.run")
    def test_scan_invalid_json_output(self, mock_run, mock_is_file, mock_exists, mock_check):
        """Test scan handles invalid JSON output"""
        mock_check.return_value = True
        mock_exists.return_value = True
        mock_is_file.return_value = False
        mock_run.return_value = Mock(
            returncode=0,
            stdout="invalid json output",
            stderr="",
        )

        scanner = CheckovScanner()

        with pytest.raises(RuntimeError, match="Failed to parse Checkov output"):
            scanner.scan("/tmp/test")

    @patch.object(CheckovScanner, "_check_checkov_installed")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_file")
    @patch("subprocess.run")
    def test_scan_timeout(self, mock_run, mock_is_file, mock_exists, mock_check):
        """Test scan timeout handling"""
        mock_check.return_value = True
        mock_exists.return_value = True
        mock_is_file.return_value = False
        mock_run.side_effect = subprocess.TimeoutExpired("checkov", 600)

        scanner = CheckovScanner()

        with pytest.raises(RuntimeError, match="Checkov scan timed out"):
            scanner.scan("/tmp/test")

    @patch.object(CheckovScanner, "_check_checkov_installed")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_file")
    @patch("pathlib.Path.resolve")
    @patch.object(CheckovScanner, "_detect_framework")
    def test_scan_file(self, mock_detect, mock_resolve, mock_is_file, mock_exists, mock_check):
        """Test scanning a single file"""
        mock_check.return_value = True
        mock_exists.return_value = True
        mock_is_file.return_value = True
        mock_resolve.return_value = Path("/tmp/test.tf")
        mock_detect.return_value = "terraform"

        scanner = CheckovScanner()

        # Mock the scan method to avoid full execution
        with patch.object(scanner, "scan") as mock_scan:
            mock_scan.return_value = CheckovScanResult(
                scan_type="file",
                target="/tmp/test.tf",
                timestamp="2024-01-01T00:00:00",
                total_checks=10,
                passed_checks=9,
                failed_checks=1,
                skipped_checks=0,
                parsing_errors=0,
                findings=[],
                frameworks=["terraform"],
                scan_duration_seconds=1.0,
                checkov_version="2.3.0",
            )

            result = scanner.scan_file("/tmp/test.tf")

            mock_detect.assert_called_once()
            mock_scan.assert_called_once_with("/tmp/test.tf", framework="terraform")
            assert result.scan_type == "file"

    @patch.object(CheckovScanner, "_check_checkov_installed")
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_file")
    def test_scan_file_not_a_file(self, mock_is_file, mock_exists, mock_check):
        """Test scan_file fails when target is not a file"""
        mock_check.return_value = True
        mock_exists.return_value = True
        mock_is_file.return_value = False

        scanner = CheckovScanner()

        with pytest.raises(RuntimeError, match="Not a file"):
            scanner.scan_file("/tmp/directory")

    def test_print_summary(self, capsys):
        """Test printing scan summary"""
        findings = [
            CheckovFinding(
                check_id="CKV_1",
                check_name="Critical check",
                check_class="checkov.test",
                severity="CRITICAL",
                file_path="test.tf",
                resource="test",
                resource_type="test",
                file_line_range=[1, 2],
                guideline="https://example.com",
                description="Test",
                code_block=[],
                check_result={},
                framework="terraform",
            ),
            CheckovFinding(
                check_id="CKV_2",
                check_name="High check",
                check_class="checkov.test",
                severity="HIGH",
                file_path="test.tf",
                resource="test2",
                resource_type="test",
                file_line_range=[3, 4],
                guideline="",
                description="Test",
                code_block=[],
                check_result={},
                framework="terraform",
            ),
        ]

        scan_result = CheckovScanResult(
            scan_type="filesystem",
            target="/tmp/test",
            timestamp="2024-01-01T00:00:00",
            total_checks=100,
            passed_checks=90,
            failed_checks=10,
            skipped_checks=0,
            parsing_errors=0,
            findings=findings,
            frameworks=["terraform"],
            scan_duration_seconds=5.5,
            checkov_version="2.3.0",
        )

        with patch.object(CheckovScanner, "_check_checkov_installed", return_value=True):
            scanner = CheckovScanner()
            scanner._print_summary(scan_result)

            captured = capsys.readouterr()
            assert "CHECKOV IAC SCAN RESULTS" in captured.out
            assert "Total Checks: 100" in captured.out
            assert "Passed:       90" in captured.out
            assert "Failed:       10" in captured.out
            assert "Critical: 1" in captured.out
            assert "High:     1" in captured.out
            assert "CKV_1" in captured.out
            assert "CKV_2" in captured.out


class TestCheckovScannerIntegration:
    """Integration tests (would require Checkov installed)"""

    @pytest.mark.integration
    @pytest.mark.skipif(True, reason="Requires Checkov installation")
    def test_real_checkov_scan_terraform(self, tmp_path):
        """Test real Checkov scan on Terraform file (integration test)"""
        # Create a test Terraform file with a security issue
        tf_file = tmp_path / "main.tf"
        tf_file.write_text("""
resource "aws_s3_bucket" "example" {
  bucket = "my-test-bucket"
  # Missing encryption configuration
}
""")

        scanner = CheckovScanner()
        result = scanner.scan(str(tmp_path))

        # Should find security issues
        assert isinstance(result, CheckovScanResult)
        assert result.scan_type == "filesystem"
        assert len(result.findings) > 0

    @pytest.mark.integration
    @pytest.mark.skipif(True, reason="Requires Checkov installation")
    def test_real_checkov_scan_kubernetes(self, tmp_path):
        """Test real Checkov scan on Kubernetes file (integration test)"""
        # Create a test Kubernetes deployment with security issues
        k8s_file = tmp_path / "deployment.yaml"
        k8s_file.write_text("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        # Missing security context, resource limits, etc.
""")

        scanner = CheckovScanner()
        result = scanner.scan_file(str(k8s_file), framework="kubernetes")

        # Should find security issues
        assert isinstance(result, CheckovScanResult)
        assert result.scan_type == "file"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
