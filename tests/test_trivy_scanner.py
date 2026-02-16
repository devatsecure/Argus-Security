"""Tests for trivy_scanner.py - Trivy CVE Scanner with Foundation-Sec-8B CWE Mapping.

Covers:
- TrivyScanner initialization and Trivy installation verification
- Filesystem scanning (happy path, errors, timeouts)
- Container image scanning
- Trivy result parsing
- CVSS score extraction
- Foundation-Sec-8B enrichment (CWE mapping, exploitability)
- Severity counting
- Result saving
- SBOM generation delegation
- Summary printing
- CLI entry point
"""

import json
import subprocess
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from scripts.trivy_scanner import (
    CVEFinding,
    TrivyScanResult,
    TrivyScanner,
)


# ---------------------------------------------------------------------------
# Sample Trivy output data
# ---------------------------------------------------------------------------

SAMPLE_TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1234",
                    "Severity": "CRITICAL",
                    "PkgName": "requests",
                    "InstalledVersion": "2.25.0",
                    "FixedVersion": "2.28.0",
                    "Title": "HTTP Request Smuggling",
                    "Description": "A critical vulnerability in requests library",
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
                    "CVSS": {
                        "nvd": {"V3Score": 9.8},
                    },
                },
                {
                    "VulnerabilityID": "CVE-2024-5678",
                    "Severity": "HIGH",
                    "PkgName": "flask",
                    "InstalledVersion": "2.0.0",
                    "FixedVersion": "2.3.0",
                    "Title": "XSS in Jinja2 template",
                    "Description": "Cross-site scripting vulnerability",
                    "References": [],
                    "CVSS": {
                        "redhat": {"V3Score": 7.5},
                    },
                },
                {
                    "VulnerabilityID": "CVE-2024-9999",
                    "Severity": "MEDIUM",
                    "PkgName": "urllib3",
                    "InstalledVersion": "1.26.0",
                    "FixedVersion": None,
                    "Title": "Information disclosure",
                    "Description": "Medium severity info leak",
                    "References": [],
                    "CVSS": {},
                },
            ],
        },
        {
            "Target": "Pipfile.lock",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1111",
                    "Severity": "LOW",
                    "PkgName": "setuptools",
                    "InstalledVersion": "50.0.0",
                    "FixedVersion": "65.5.1",
                    "Title": "Regex DoS",
                    "Description": "Low severity regex denial of service",
                    "References": [],
                    "CVSS": {
                        "nvd": {"V2Score": 3.5},
                    },
                },
            ],
        },
    ]
}

EMPTY_TRIVY_OUTPUT = {"Results": []}
NO_VULN_TRIVY_OUTPUT = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": []}]}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner():
    """Create a TrivyScanner with mocked Trivy installation."""
    with patch.object(TrivyScanner, "_verify_trivy_installation"):
        return TrivyScanner()


@pytest.fixture
def scanner_with_foundation_sec():
    """Create a TrivyScanner with Foundation-Sec enabled."""
    mock_model = MagicMock()
    with patch.object(TrivyScanner, "_verify_trivy_installation"):
        return TrivyScanner(foundation_sec_enabled=True, foundation_sec_model=mock_model)


# ---------------------------------------------------------------------------
# CVEFinding dataclass
# ---------------------------------------------------------------------------

class TestCVEFinding:
    def test_defaults(self):
        f = CVEFinding(
            cve_id="CVE-2024-0001",
            severity="HIGH",
            package_name="pkg",
            installed_version="1.0",
            fixed_version="2.0",
            title="Test vuln",
            description="Test desc",
            references=["https://example.com"],
        )
        assert f.cvss_score is None
        assert f.cwe_id is None
        assert f.exploitability is None
        assert f.attack_vector is None
        assert f.file_path is None

    def test_all_fields(self):
        f = CVEFinding(
            cve_id="CVE-2024-0001",
            severity="CRITICAL",
            package_name="pkg",
            installed_version="1.0",
            fixed_version="2.0",
            title="Test",
            description="Desc",
            references=[],
            cvss_score=9.8,
            cwe_id="CWE-79",
            exploitability="trivial",
            attack_vector="network",
            file_path="requirements.txt",
        )
        assert f.cvss_score == 9.8
        assert f.cwe_id == "CWE-79"


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_trivy_installed(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Version: 0.50.0"

        with patch("subprocess.run", return_value=mock_result):
            scanner = TrivyScanner()
        assert scanner.foundation_sec_enabled is False

    def test_init_trivy_not_installed(self):
        with patch("subprocess.run", side_effect=FileNotFoundError("trivy not found")):
            with pytest.raises(RuntimeError, match="Trivy installation check failed"):
                TrivyScanner()

    def test_init_trivy_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=10)):
            with pytest.raises(RuntimeError, match="Trivy installation check failed"):
                TrivyScanner()

    def test_init_trivy_nonzero_return(self):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="Trivy not found"):
                TrivyScanner()

    def test_init_with_foundation_sec(self):
        mock_model = MagicMock()
        with patch.object(TrivyScanner, "_verify_trivy_installation"):
            scanner = TrivyScanner(foundation_sec_enabled=True, foundation_sec_model=mock_model)
        assert scanner.foundation_sec_enabled is True
        assert scanner.foundation_sec_model is mock_model


# ---------------------------------------------------------------------------
# Filesystem scanning
# ---------------------------------------------------------------------------

class TestScanFilesystem:
    def test_scan_filesystem_success(self, scanner, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(SAMPLE_TRIVY_OUTPUT)
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result), \
             patch.object(scanner, "_get_trivy_version", return_value="Trivy v0.50.0"):
            result = scanner.scan_filesystem(str(tmp_path))

        assert isinstance(result, TrivyScanResult)
        assert result.scan_type == "filesystem"
        assert result.total_vulnerabilities == 4
        assert result.critical == 1
        assert result.high == 1
        assert result.medium == 1
        assert result.low == 1

    def test_scan_filesystem_empty_output(self, scanner, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result), \
             patch.object(scanner, "_get_trivy_version", return_value="Trivy v0.50.0"):
            result = scanner.scan_filesystem(str(tmp_path))

        assert result.total_vulnerabilities == 0

    def test_scan_filesystem_nonzero_exit(self, scanner, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "scan error occurred"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="Trivy scan failed"):
                scanner.scan_filesystem(str(tmp_path))

    def test_scan_filesystem_timeout(self, scanner, tmp_path):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=300)):
            with pytest.raises(subprocess.TimeoutExpired):
                scanner.scan_filesystem(str(tmp_path))

    def test_scan_filesystem_json_decode_error(self, scanner, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "not valid json{{"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(json.JSONDecodeError):
                scanner.scan_filesystem(str(tmp_path))

    def test_scan_filesystem_saves_output(self, scanner, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(EMPTY_TRIVY_OUTPUT)
        mock_result.stderr = ""
        output_file = str(tmp_path / "results.json")

        with patch("subprocess.run", return_value=mock_result), \
             patch.object(scanner, "_get_trivy_version", return_value="v0.50.0"):
            scanner.scan_filesystem(str(tmp_path), output_file=output_file)

        assert Path(output_file).exists()

    def test_scan_filesystem_with_severity_filter(self, scanner, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(EMPTY_TRIVY_OUTPUT)
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result) as mock_run, \
             patch.object(scanner, "_get_trivy_version", return_value="v0.50.0"):
            scanner.scan_filesystem(str(tmp_path), severity="CRITICAL,HIGH")

        # Check the command included the severity filter
        cmd = mock_run.call_args[0][0]
        assert "--severity" in cmd
        idx = cmd.index("--severity")
        assert cmd[idx + 1] == "CRITICAL,HIGH"

    def test_scan_filesystem_with_foundation_sec(self, scanner_with_foundation_sec, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(SAMPLE_TRIVY_OUTPUT)
        mock_result.stderr = ""

        scanner_with_foundation_sec.foundation_sec_model.generate.return_value = "79"

        with patch("subprocess.run", return_value=mock_result), \
             patch.object(scanner_with_foundation_sec, "_get_trivy_version", return_value="v0.50.0"):
            result = scanner_with_foundation_sec.scan_filesystem(str(tmp_path))

        assert result.total_vulnerabilities == 4


# ---------------------------------------------------------------------------
# Container image scanning
# ---------------------------------------------------------------------------

class TestScanContainerImage:
    def test_scan_image_success(self, scanner):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps(SAMPLE_TRIVY_OUTPUT)
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result), \
             patch.object(scanner, "_get_trivy_version", return_value="v0.50.0"):
            result = scanner.scan_container_image("nginx:latest")

        assert result.scan_type == "image"
        assert result.target == "nginx:latest"
        assert result.total_vulnerabilities == 4

    def test_scan_image_failure(self, scanner):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "image not found"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="Trivy image scan failed"):
                scanner.scan_container_image("nonexistent:image")

    def test_scan_image_timeout(self, scanner):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=600)):
            with pytest.raises(subprocess.TimeoutExpired):
                scanner.scan_container_image("nginx:latest")

    def test_scan_image_empty_result(self, scanner):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result), \
             patch.object(scanner, "_get_trivy_version", return_value="v0.50.0"):
            result = scanner.scan_container_image("alpine:latest")

        assert result.total_vulnerabilities == 0


# ---------------------------------------------------------------------------
# Trivy result parsing
# ---------------------------------------------------------------------------

class TestParseResults:
    def test_parse_trivy_results_full(self, scanner):
        findings = scanner._parse_trivy_results(SAMPLE_TRIVY_OUTPUT)
        assert len(findings) == 4
        assert findings[0].cve_id == "CVE-2024-1234"
        assert findings[0].severity == "CRITICAL"
        assert findings[0].package_name == "requests"
        assert findings[0].installed_version == "2.25.0"
        assert findings[0].fixed_version == "2.28.0"
        assert findings[0].file_path == "requirements.txt"

    def test_parse_trivy_results_empty(self, scanner):
        findings = scanner._parse_trivy_results(EMPTY_TRIVY_OUTPUT)
        assert findings == []

    def test_parse_trivy_results_no_vulns(self, scanner):
        findings = scanner._parse_trivy_results(NO_VULN_TRIVY_OUTPUT)
        assert findings == []

    def test_parse_trivy_results_missing_fields(self, scanner):
        data = {
            "Results": [{
                "Target": "unknown",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-0001",
                    # Most fields missing
                }],
            }]
        }
        findings = scanner._parse_trivy_results(data)
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2024-0001"
        assert findings[0].severity == "UNKNOWN"
        assert findings[0].package_name == ""
        assert findings[0].fixed_version is None

    def test_parse_trivy_no_results_key(self, scanner):
        findings = scanner._parse_trivy_results({})
        assert findings == []


# ---------------------------------------------------------------------------
# CVSS score extraction
# ---------------------------------------------------------------------------

class TestExtractCVSS:
    def test_extract_cvss_nvd_v3(self, scanner):
        vuln = {"CVSS": {"nvd": {"V3Score": 9.8}}}
        assert scanner._extract_cvss_score(vuln) == 9.8

    def test_extract_cvss_other_source_v3(self, scanner):
        vuln = {"CVSS": {"redhat": {"V3Score": 7.5}}}
        assert scanner._extract_cvss_score(vuln) == 7.5

    def test_extract_cvss_v2_fallback(self, scanner):
        vuln = {"CVSS": {"nvd": {"V2Score": 5.0}}}
        assert scanner._extract_cvss_score(vuln) == 5.0

    def test_extract_cvss_no_data(self, scanner):
        vuln = {"CVSS": {}}
        assert scanner._extract_cvss_score(vuln) is None

    def test_extract_cvss_no_key(self, scanner):
        vuln = {}
        assert scanner._extract_cvss_score(vuln) is None

    def test_extract_cvss_prefers_nvd_v3(self, scanner):
        vuln = {
            "CVSS": {
                "nvd": {"V3Score": 9.8, "V2Score": 7.0},
                "redhat": {"V3Score": 8.0},
            }
        }
        assert scanner._extract_cvss_score(vuln) == 9.8


# ---------------------------------------------------------------------------
# Foundation-Sec-8B enrichment
# ---------------------------------------------------------------------------

class TestFoundationSecEnrichment:
    def test_enrich_with_foundation_sec(self, scanner_with_foundation_sec):
        scanner_with_foundation_sec.foundation_sec_model.generate.return_value = "79"

        finding = CVEFinding(
            cve_id="CVE-2024-0001",
            severity="HIGH",
            package_name="flask",
            installed_version="1.0",
            fixed_version="2.0",
            title="XSS",
            description="Cross-site scripting vulnerability",
            references=[],
            cvss_score=7.5,
        )

        enriched = scanner_with_foundation_sec._enrich_with_foundation_sec([finding])
        assert len(enriched) == 1
        assert enriched[0].cwe_id == "CWE-79"
        assert enriched[0].exploitability == "moderate"

    def test_map_cve_to_cwe_success(self, scanner_with_foundation_sec):
        scanner_with_foundation_sec.foundation_sec_model.generate.return_value = "89"

        finding = CVEFinding(
            cve_id="CVE-2024-0001", severity="HIGH",
            package_name="django", installed_version="3.0",
            fixed_version="3.1", title="SQL Injection",
            description="SQL injection vuln", references=[],
        )
        cwe = scanner_with_foundation_sec._map_cve_to_cwe(finding)
        assert cwe == "CWE-89"

    def test_map_cve_to_cwe_no_model(self, scanner):
        finding = CVEFinding(
            cve_id="CVE-2024-0001", severity="HIGH",
            package_name="pkg", installed_version="1.0",
            fixed_version="2.0", title="Test",
            description="Test", references=[],
        )
        assert scanner._map_cve_to_cwe(finding) is None

    def test_map_cve_to_cwe_exception(self, scanner_with_foundation_sec):
        scanner_with_foundation_sec.foundation_sec_model.generate.side_effect = RuntimeError("model error")

        finding = CVEFinding(
            cve_id="CVE-2024-0001", severity="HIGH",
            package_name="pkg", installed_version="1.0",
            fixed_version="2.0", title="Test",
            description="Test", references=[],
        )
        cwe = scanner_with_foundation_sec._map_cve_to_cwe(finding)
        assert cwe is None

    def test_map_cve_model_no_generate(self):
        mock_model = MagicMock(spec=[])  # No 'generate' attribute
        with patch.object(TrivyScanner, "_verify_trivy_installation"):
            scanner = TrivyScanner(foundation_sec_enabled=True, foundation_sec_model=mock_model)

        finding = CVEFinding(
            cve_id="CVE-2024-0001", severity="HIGH",
            package_name="pkg", installed_version="1.0",
            fixed_version="2.0", title="Test",
            description="Test", references=[],
        )
        cwe = scanner._map_cve_to_cwe(finding)
        assert cwe is None


# ---------------------------------------------------------------------------
# Exploitability assessment
# ---------------------------------------------------------------------------

class TestExploitability:
    def test_trivial_high_cvss(self, scanner):
        finding = CVEFinding(
            cve_id="CVE-2024-0001", severity="CRITICAL",
            package_name="pkg", installed_version="1.0",
            fixed_version="2.0", title="T", description="D",
            references=[], cvss_score=9.5,
        )
        assert scanner._assess_exploitability(finding) == "trivial"

    def test_moderate_cvss(self, scanner):
        finding = CVEFinding(
            cve_id="CVE-2024-0001", severity="HIGH",
            package_name="pkg", installed_version="1.0",
            fixed_version="2.0", title="T", description="D",
            references=[], cvss_score=7.5,
        )
        assert scanner._assess_exploitability(finding) == "moderate"

    def test_complex_cvss(self, scanner):
        finding = CVEFinding(
            cve_id="CVE-2024-0001", severity="MEDIUM",
            package_name="pkg", installed_version="1.0",
            fixed_version="2.0", title="T", description="D",
            references=[], cvss_score=5.0,
        )
        assert scanner._assess_exploitability(finding) == "complex"

    def test_theoretical_low_cvss(self, scanner):
        finding = CVEFinding(
            cve_id="CVE-2024-0001", severity="LOW",
            package_name="pkg", installed_version="1.0",
            fixed_version="2.0", title="T", description="D",
            references=[], cvss_score=2.0,
        )
        assert scanner._assess_exploitability(finding) == "theoretical"

    def test_fallback_to_severity_critical(self, scanner):
        finding = CVEFinding(
            cve_id="CVE-2024-0001", severity="CRITICAL",
            package_name="pkg", installed_version="1.0",
            fixed_version="2.0", title="T", description="D",
            references=[],
        )
        assert scanner._assess_exploitability(finding) == "trivial"

    def test_fallback_to_severity_unknown(self, scanner):
        finding = CVEFinding(
            cve_id="CVE-2024-0001", severity="UNKNOWN",
            package_name="pkg", installed_version="1.0",
            fixed_version="2.0", title="T", description="D",
            references=[],
        )
        assert scanner._assess_exploitability(finding) == "theoretical"


# ---------------------------------------------------------------------------
# Severity counting
# ---------------------------------------------------------------------------

class TestSeverityCounts:
    def test_all_severities(self, scanner):
        findings = [
            CVEFinding(cve_id="1", severity="CRITICAL", package_name="", installed_version="", fixed_version=None, title="", description="", references=[]),
            CVEFinding(cve_id="2", severity="HIGH", package_name="", installed_version="", fixed_version=None, title="", description="", references=[]),
            CVEFinding(cve_id="3", severity="MEDIUM", package_name="", installed_version="", fixed_version=None, title="", description="", references=[]),
            CVEFinding(cve_id="4", severity="LOW", package_name="", installed_version="", fixed_version=None, title="", description="", references=[]),
        ]
        counts = scanner._calculate_severity_counts(findings)
        assert counts == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 0}

    def test_empty_findings(self, scanner):
        counts = scanner._calculate_severity_counts([])
        assert counts == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

    def test_unknown_severity(self, scanner):
        findings = [
            CVEFinding(cve_id="1", severity="WEIRD", package_name="", installed_version="", fixed_version=None, title="", description="", references=[]),
        ]
        counts = scanner._calculate_severity_counts(findings)
        assert counts["UNKNOWN"] == 1


# ---------------------------------------------------------------------------
# Get Trivy version
# ---------------------------------------------------------------------------

class TestGetTrivyVersion:
    def test_get_version_success(self, scanner):
        mock_result = MagicMock()
        mock_result.stdout = "Version: 0.50.0\nother info"

        with patch("subprocess.run", return_value=mock_result):
            version = scanner._get_trivy_version()
        assert version == "Version: 0.50.0"

    def test_get_version_failure(self, scanner):
        with patch("subprocess.run", side_effect=Exception("fail")):
            version = scanner._get_trivy_version()
        assert version == "unknown"


# ---------------------------------------------------------------------------
# Save results
# ---------------------------------------------------------------------------

class TestSaveResults:
    def test_save_results_creates_file(self, scanner, tmp_path):
        result = TrivyScanResult(
            scan_type="filesystem",
            target="/test",
            timestamp="2024-01-01T00:00:00",
            total_vulnerabilities=1,
            critical=1,
            high=0,
            medium=0,
            low=0,
            findings=[
                CVEFinding(
                    cve_id="CVE-2024-0001", severity="CRITICAL",
                    package_name="pkg", installed_version="1.0",
                    fixed_version="2.0", title="Test",
                    description="Desc", references=[],
                )
            ],
            scan_duration_seconds=5.0,
            trivy_version="v0.50.0",
        )

        output_path = tmp_path / "output" / "results.json"
        scanner._save_results(result, str(output_path))

        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data["scan_type"] == "filesystem"
        assert data["total_vulnerabilities"] == 1
        assert len(data["findings"]) == 1

    def test_save_results_creates_parent_dirs(self, scanner, tmp_path):
        output_path = tmp_path / "a" / "b" / "c" / "results.json"
        result = TrivyScanResult(
            scan_type="image", target="test", timestamp="now",
            total_vulnerabilities=0, critical=0, high=0, medium=0, low=0,
            findings=[], scan_duration_seconds=0.0, trivy_version="v0.50.0",
        )
        scanner._save_results(result, str(output_path))
        assert output_path.exists()


# ---------------------------------------------------------------------------
# SBOM generation
# ---------------------------------------------------------------------------

class TestGenerateSBOM:
    def test_generate_sbom_default_formats(self, scanner):
        with patch("scripts.sbom_generator.SBOMGenerator") as MockGen:
            mock_gen = MockGen.return_value
            mock_gen.generate_cyclonedx.return_value = {"success": True, "format": "cyclonedx"}
            mock_gen.generate_spdx.return_value = {"success": True, "format": "spdx"}

            results = scanner.generate_sbom("/target")

        assert "cyclonedx" in results
        assert "spdx" in results
        assert results["cyclonedx"]["success"] is True

    def test_generate_sbom_unknown_format(self, scanner):
        result = scanner.generate_sbom("/target", formats=["invalid_format"])
        assert result["success"] is False
        assert "Unknown SBOM format" in result["error"]

    def test_generate_sbom_init_failure(self, scanner):
        with patch("scripts.sbom_generator.SBOMGenerator", side_effect=RuntimeError("no trivy")):
            result = scanner.generate_sbom("/target")
        assert result["success"] is False

    def test_generate_sbom_specific_format(self, scanner):
        with patch("scripts.sbom_generator.SBOMGenerator") as MockGen:
            mock_gen = MockGen.return_value
            mock_gen.generate_cyclonedx.return_value = {"success": True}

            results = scanner.generate_sbom("/target", formats=["cyclonedx"])

        assert "cyclonedx" in results
        assert "spdx" not in results


# ---------------------------------------------------------------------------
# Print summary (smoke tests)
# ---------------------------------------------------------------------------

class TestPrintSummary:
    def test_print_summary_basic(self, scanner, capsys):
        result = TrivyScanResult(
            scan_type="filesystem", target="/test",
            timestamp="2024-01-01", total_vulnerabilities=10,
            critical=2, high=3, medium=3, low=2,
            findings=[], scan_duration_seconds=5.0,
            trivy_version="v0.50.0",
        )
        scanner._print_summary(result)
        captured = capsys.readouterr()
        assert "TRIVY CVE SCAN RESULTS" in captured.out
        assert "Critical: 2" in captured.out
        assert "High:     3" in captured.out

    def test_print_summary_with_foundation_sec(self, scanner_with_foundation_sec, capsys):
        findings = [
            CVEFinding(
                cve_id="CVE-2024-0001", severity="CRITICAL",
                package_name="pkg", installed_version="1.0",
                fixed_version="2.0", title="Test",
                description="Desc", references=[],
                cwe_id="CWE-79",
            )
        ]
        result = TrivyScanResult(
            scan_type="filesystem", target="/test",
            timestamp="2024-01-01", total_vulnerabilities=1,
            critical=1, high=0, medium=0, low=0,
            findings=findings, scan_duration_seconds=1.0,
            trivy_version="v0.50.0",
        )
        scanner_with_foundation_sec._print_summary(result)
        captured = capsys.readouterr()
        assert "Foundation-Sec-8B" in captured.out
        assert "CWE Mapped: 1/1" in captured.out

    def test_print_summary_with_critical_findings(self, scanner, capsys):
        findings = [
            CVEFinding(
                cve_id="CVE-2024-0001", severity="CRITICAL",
                package_name="requests", installed_version="1.0",
                fixed_version="2.0", title="Critical Bug" * 5,
                description="D", references=[],
                cwe_id="CWE-79", exploitability="trivial",
            )
        ]
        result = TrivyScanResult(
            scan_type="filesystem", target="/test",
            timestamp="2024-01-01", total_vulnerabilities=1,
            critical=1, high=0, medium=0, low=0,
            findings=findings, scan_duration_seconds=1.0,
            trivy_version="v0.50.0",
        )
        scanner._print_summary(result)
        captured = capsys.readouterr()
        assert "CVE-2024-0001" in captured.out
        assert "requests" in captured.out


# ---------------------------------------------------------------------------
# TrivyScanResult dataclass
# ---------------------------------------------------------------------------

class TestTrivyScanResult:
    def test_asdict(self):
        result = TrivyScanResult(
            scan_type="filesystem", target="/test",
            timestamp="2024-01-01", total_vulnerabilities=0,
            critical=0, high=0, medium=0, low=0,
            findings=[], scan_duration_seconds=0.0,
            trivy_version="v0.50.0",
        )
        d = asdict(result)
        assert d["scan_type"] == "filesystem"
        assert d["findings"] == []
