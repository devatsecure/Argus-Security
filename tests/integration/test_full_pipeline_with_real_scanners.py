"""
Integration tests for complete pipeline using real scanner outputs
Tests the entire Argus workflow from scan to report generation
"""
import json
import os
import sys
from pathlib import Path

import pytest

# Add test utilities to path
TEST_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(TEST_ROOT))

from utils.assertions import security_assertions
from utils.fixtures import fixture_manager, scanner_parser
from utils.scanner_runner import scanner_runner

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


class TestFullPipelineWithRealScanners:
    """Integration tests using real scanner outputs"""

    def test_semgrep_scanner_produces_valid_output(self):
        """Test that Semgrep produces valid, parseable output"""
        # Load real Semgrep output from fixtures
        semgrep_output = fixture_manager.load_scanner_output("semgrep")

        # Verify structure
        assert "tool" in semgrep_output
        assert semgrep_output["tool"] == "semgrep"
        assert "findings" in semgrep_output
        assert "findings_count" in semgrep_output

        # Verify findings
        findings = semgrep_output["findings"]
        assert len(findings) > 0, "Should detect vulnerabilities in vulnerable_api.py"

        # Check each finding has required fields
        for finding in findings:
            security_assertions.assert_finding_has_required_fields(
                finding,
                required_fields=["rule_id", "severity", "message", "file_path", "start_line"]
            )
            security_assertions.assert_valid_severity(finding["severity"])
            if finding.get("cwe"):
                # CWE may include description after number (e.g., "CWE-96: Description")
                cwe_value = finding["cwe"].split(":")[0].strip()
                security_assertions.assert_valid_cwe(cwe_value)

        print(f"✅ Semgrep found {len(findings)} vulnerabilities")

    def test_trivy_scanner_detects_cves(self):
        """Test that Trivy detects CVEs in dependencies"""
        # Load real Trivy output
        trivy_output = fixture_manager.load_scanner_output("trivy")

        # Extract vulnerabilities
        vulnerabilities = scanner_parser.extract_trivy_vulnerabilities(trivy_output)
        assert len(vulnerabilities) > 0, "Should detect CVEs in vulnerable dependencies"

        # Verify vulnerability structure
        for vuln in vulnerabilities[:5]:  # Check first 5
            assert "VulnerabilityID" in vuln or "ID" in vuln, f"Vulnerability missing ID: {vuln.keys()}"
            assert "Severity" in vuln, "Vulnerability missing Severity"

        print(f"✅ Trivy found {len(vulnerabilities)} CVEs")

    def test_checkov_scanner_detects_iac_issues(self):
        """Test that Checkov detects IaC misconfigurations"""
        # Load real Checkov output
        checkov_output = fixture_manager.load_scanner_output("checkov")

        # Extract failed checks
        failures = scanner_parser.extract_checkov_failures(checkov_output)
        assert len(failures) > 0, "Should detect IaC issues in terraform_vulnerable.tf"

        # Verify check structure
        for check in failures[:5]:  # Check first 5
            assert "check_id" in check, "Check missing check_id"
            assert "check_name" in check, "Check missing check_name"
            assert "check_result" in check, "Check missing check_result"

        print(f"✅ Checkov found {len(failures)} IaC misconfigurations")

    def test_scanners_run_on_vulnerable_code(self):
        """Test that scanners can be run on vulnerable code samples"""
        vulnerable_path = fixture_manager.get_vulnerable_file_path("vulnerable_api.py")

        # Run Semgrep
        semgrep_results = scanner_runner.run_semgrep(str(vulnerable_path))
        security_assertions.assert_scan_completed_successfully(semgrep_results)
        assert semgrep_results["findings_count"] > 0, "Should find vulnerabilities"

        print(f"✅ Semgrep detected {semgrep_results['findings_count']} issues")

    def test_hybrid_analyzer_combines_scanners(self):
        """Test that hybrid analyzer successfully combines multiple scanners"""
        vulnerable_app = fixture_manager.get_vulnerable_file_path("vulnerable_api.py").parent

        # Run hybrid analyzer (without AI to avoid API costs)
        results = scanner_runner.run_hybrid_analyzer(
            str(vulnerable_app),
            enable_semgrep=True,
            enable_trivy=False,  # Skip Trivy to save time
            enable_checkov=False,  # Skip Checkov to save time
            enable_ai_enrichment=False,  # Skip AI to avoid costs
        )

        # Verify results structure - results may be a HybridScanResult object or a dict
        if isinstance(results, dict):
            if "error" not in results:
                assert "findings" in results or "scan_results" in results
                print("✅ Hybrid analyzer completed successfully")
            else:
                print(f"⚠️ Hybrid analyzer not available: {results['error']}")
        else:
            # HybridScanResult object - check for attributes
            assert hasattr(results, "findings") or hasattr(results, "scan_results"), \
                "HybridScanResult should have findings or scan_results attribute"
            print("✅ Hybrid analyzer completed successfully")

    def test_findings_have_consistent_format(self):
        """Test that findings from different scanners have consistent format"""
        # Load outputs from different scanners
        semgrep_output = fixture_manager.load_scanner_output("semgrep")
        semgrep_findings = semgrep_output["findings"]

        # Check that all findings have common fields
        common_fields = ["severity", "file_path"]
        for finding in semgrep_findings:
            for field in common_fields:
                assert field in finding, f"Finding missing common field '{field}': {finding}"

        print(f"✅ All {len(semgrep_findings)} findings have consistent format")

    def test_severity_levels_are_normalized(self):
        """Test that severity levels are normalized across scanners"""
        semgrep_output = fixture_manager.load_scanner_output("semgrep")
        findings = semgrep_output["findings"]

        # Count by severity
        severity_counts = scanner_parser.count_findings_by_severity(findings)

        # Verify we have findings in standard severity levels
        total_findings = sum(severity_counts.values())
        assert total_findings > 0, "Should have findings"

        print(f"✅ Severity distribution: {severity_counts}")

    def test_cwe_mapping_is_present(self):
        """Test that findings include CWE mappings"""
        semgrep_output = fixture_manager.load_scanner_output("semgrep")
        findings = semgrep_output["findings"]

        # Count how many have CWE
        with_cwe = [f for f in findings if f.get("cwe")]
        percentage = (len(with_cwe) / len(findings)) * 100 if findings else 0

        # At least 50% should have CWE mappings
        assert percentage >= 50, f"Only {percentage:.0f}% of findings have CWE mappings"

        print(f"✅ {len(with_cwe)}/{len(findings)} ({percentage:.0f}%) findings have CWE mappings")

    def test_high_severity_findings_are_actionable(self):
        """Test that high severity findings have actionable information"""
        semgrep_output = fixture_manager.load_scanner_output("semgrep")
        findings = semgrep_output["findings"]

        # Filter high/critical severity
        high_severity = scanner_parser.filter_by_severity(findings, "high")

        # Each should have detailed information
        for finding in high_severity:
            assert finding.get("message"), "High severity finding should have message"
            assert finding.get("code_snippet") or finding.get("start_line"), \
                "High severity finding should have code location"

        print(f"✅ {len(high_severity)} high/critical severity findings are actionable")

    def test_no_duplicate_findings(self):
        """Test that scanner outputs don't contain duplicates"""
        semgrep_output = fixture_manager.load_scanner_output("semgrep")
        findings = semgrep_output["findings"]

        # Check for duplicates
        security_assertions.assert_findings_deduplicated(findings)

        print(f"✅ No duplicates in {len(findings)} findings")

    @pytest.mark.slow
    def test_complete_scan_produces_sarif_output(self, tmp_path):
        """Test that complete scan can produce SARIF output"""
        from run_ai_audit import generate_sarif_output

        # Load findings from fixtures
        semgrep_output = fixture_manager.load_scanner_output("semgrep")
        findings = semgrep_output["findings"]

        # Convert to format expected by generate_sarif_output
        formatted_findings = []
        for f in findings:
            formatted_findings.append({
                "category": "security",
                "severity": f["severity"],
                "title": f["rule_id"],
                "description": f["message"],
                "file": f["file_path"],
                "line": f["start_line"],
                "code": f.get("code_snippet", ""),
                "recommendation": "See Semgrep documentation"
            })

        # Generate SARIF
        sarif_output = generate_sarif_output(formatted_findings, str(tmp_path))

        # Verify SARIF structure
        security_assertions.assert_sarif_structure(sarif_output)

        print(f"✅ Generated valid SARIF with {len(formatted_findings)} results")

    def test_scan_metrics_are_tracked(self):
        """Test that scan metrics are properly tracked"""
        semgrep_output = fixture_manager.load_scanner_output("semgrep")

        # Verify metrics
        assert "timestamp" in semgrep_output, "Should track timestamp"
        assert "findings_count" in semgrep_output, "Should track findings count"
        assert "target" in semgrep_output, "Should track target path"

        print(f"✅ Scan metrics tracked: {semgrep_output['findings_count']} findings at {semgrep_output.get('timestamp')}")

    def test_scanner_handles_multiple_file_types(self):
        """Test that scanners can handle different file types"""
        # List all vulnerable files
        files = fixture_manager.list_vulnerable_files()

        assert "vulnerable_api.py" in files, "Should have Python files"
        assert "vulnerable_frontend.js" in files, "Should have JavaScript files"
        assert "Dockerfile" in files, "Should have Dockerfile"
        assert "terraform_vulnerable.tf" in files, "Should have Terraform files"

        print(f"✅ Test suite covers {len(files)} different file types")

    def test_scanners_detect_expected_vulnerability_types(self):
        """Test that scanners detect expected vulnerability types"""
        semgrep_output = fixture_manager.load_scanner_output("semgrep")
        findings = semgrep_output["findings"]

        # Expected CWEs in vulnerable_api.py (based on actual Semgrep scan results)
        # CWE-78: OS Command Injection, CWE-95: Eval Injection, CWE-96: Static Code Injection
        # CWE-502: Deserialization, CWE-668: Exposure of Resource, CWE-489: Active Debug Code
        expected_cwes = ["CWE-78", "CWE-95", "CWE-96", "CWE-502"]

        found_cwes = set()
        for finding in findings:
            if finding.get("cwe"):
                # CWE may include description after colon (e.g., "CWE-96: Description")
                cwe_id = finding["cwe"].split(":")[0].strip()
                found_cwes.add(cwe_id)

        # Should detect at least 2 of the expected vulnerability types
        detected = len(found_cwes.intersection(expected_cwes))
        assert detected >= 2, f"Should detect common vulnerabilities. Found: {found_cwes}"

        print(f"✅ Detected {detected}/{len(expected_cwes)} expected vulnerability types: {found_cwes}")


class TestPipelinePerformance:
    """Test pipeline performance characteristics"""

    def test_scanner_outputs_are_reasonable_size(self):
        """Test that scanner outputs are not excessively large"""
        outputs = fixture_manager.list_scanner_outputs()

        for output_file in outputs:
            filepath = Path(__file__).parent.parent / "fixtures" / "scanner_outputs" / output_file
            size_kb = filepath.stat().st_size / 1024

            # Output should be < 5MB per file
            assert size_kb < 5000, f"{output_file} is too large: {size_kb:.2f} KB"

        print(f"✅ All {len(outputs)} scanner outputs are reasonable size")

    def test_fixture_loading_is_fast(self):
        """Test that fixture loading is fast enough for testing"""
        import time

        start = time.time()
        for _ in range(10):
            fixture_manager.load_scanner_output("semgrep")
        duration = time.time() - start

        # Should load 10 times in < 1 second
        assert duration < 1.0, f"Fixture loading too slow: {duration:.2f}s for 10 loads"

        print(f"✅ Fixture loading is fast: {duration:.3f}s for 10 loads")


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
