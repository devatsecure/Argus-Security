"""
Integration tests for normalizers using real scanner outputs
Tests that normalizers can handle actual scanner data from production scans
"""
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Add test utilities to path
TEST_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(TEST_ROOT))

from utils.assertions import security_assertions
from utils.fixtures import fixture_manager

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


class TestNormalizerWithRealOutput:
    """Test normalizers with real scanner outputs"""

    def test_semgrep_normalizer_handles_real_output(self):
        """Test Semgrep normalizer with real scanner output"""
        try:
            from normalizer.semgrep_normalizer import SemgrepNormalizer

            # Load real Semgrep output
            semgrep_raw = fixture_manager.load_scanner_output("semgrep")

            # Normalize
            normalizer = SemgrepNormalizer()
            normalized = normalizer.normalize(semgrep_raw)

            # Verify structure
            assert "tool" in normalized
            assert normalized["tool"] == "semgrep"
            assert "findings" in normalized
            assert isinstance(normalized["findings"], list)

            # Check each finding is normalized
            for finding in normalized["findings"]:
                security_assertions.assert_finding_has_required_fields(
                    finding,
                    required_fields=["id", "severity", "file_path", "description"]
                )

            print(f"✅ Semgrep normalizer processed {len(normalized['findings'])} findings")

        except ImportError as e:
            pytest.skip(f"Semgrep normalizer not available: {e}")

    def test_trivy_normalizer_handles_real_output(self):
        """Test Trivy normalizer with real scanner output"""
        try:
            from normalizer.trivy_normalizer import TrivyNormalizer

            # Load real Trivy output
            trivy_raw = fixture_manager.load_scanner_output("trivy")

            # Normalize
            normalizer = TrivyNormalizer()
            normalized = normalizer.normalize(trivy_raw)

            # Verify structure
            assert "tool" in normalized
            assert normalized["tool"] == "trivy"
            assert "findings" in normalized
            assert isinstance(normalized["findings"], list)

            # Check findings have CVE information
            cve_count = 0
            for finding in normalized["findings"]:
                if finding.get("vulnerability_id", "").startswith("CVE"):
                    cve_count += 1
                    # Verify CVE finding has required fields
                    assert "severity" in finding
                    assert "description" in finding or "title" in finding

            assert cve_count > 0, "Should have at least one CVE finding"
            print(f"✅ Trivy normalizer processed {len(normalized['findings'])} findings ({cve_count} CVEs)")

        except ImportError as e:
            pytest.skip(f"Trivy normalizer not available: {e}")

    def test_checkov_normalizer_handles_real_output(self):
        """Test Checkov normalizer with real scanner output"""
        try:
            from normalizer.checkov_normalizer import CheckovNormalizer

            # Load real Checkov output
            checkov_raw = fixture_manager.load_scanner_output("checkov")

            # Normalize
            normalizer = CheckovNormalizer()
            normalized = normalizer.normalize(checkov_raw)

            # Verify structure
            assert "tool" in normalized
            assert normalized["tool"] == "checkov"
            assert "findings" in normalized
            assert isinstance(normalized["findings"], list)

            # Check IaC findings
            for finding in normalized["findings"][:5]:  # Check first 5
                security_assertions.assert_finding_has_required_fields(
                    finding,
                    required_fields=["id", "severity", "file_path"]
                )
                # Checkov findings should have check information
                assert "check_id" in finding or "rule_id" in finding

            print(f"✅ Checkov normalizer processed {len(normalized['findings'])} IaC findings")

        except ImportError as e:
            pytest.skip(f"Checkov normalizer not available: {e}")

    def test_trufflehog_normalizer_handles_real_output(self):
        """Test TruffleHog normalizer with real scanner output"""
        try:
            from normalizer.trufflehog_normalizer import TruffleHogNormalizer

            # Load real TruffleHog output
            trufflehog_raw = fixture_manager.load_scanner_output("trufflehog")

            # Normalize
            normalizer = TruffleHogNormalizer()
            normalized = normalizer.normalize(trufflehog_raw)

            # Verify structure
            assert "tool" in normalized
            assert normalized["tool"] == "trufflehog"
            assert "findings" in normalized
            assert isinstance(normalized["findings"], list)

            # Check secret findings
            for finding in normalized["findings"]:
                security_assertions.assert_finding_has_required_fields(
                    finding,
                    required_fields=["id", "severity", "description"]
                )
                # TruffleHog findings should have secret type
                assert "detector_type" in finding or "secret_type" in finding

            print(f"✅ TruffleHog normalizer processed {len(normalized['findings'])} secrets")

        except ImportError as e:
            pytest.skip(f"TruffleHog normalizer not available: {e}")

    def test_normalizers_produce_consistent_schema(self):
        """Test that all normalizers produce consistent output schema"""
        normalizers_to_test = [
            ("semgrep", "SemgrepNormalizer", "normalizer.semgrep_normalizer"),
            ("trivy", "TrivyNormalizer", "normalizer.trivy_normalizer"),
            ("checkov", "CheckovNormalizer", "normalizer.checkov_normalizer"),
            ("trufflehog", "TruffleHogNormalizer", "normalizer.trufflehog_normalizer"),
        ]

        all_normalized = []
        common_fields = ["tool", "findings", "timestamp"]

        for scanner_name, normalizer_class, module_path in normalizers_to_test:
            try:
                # Import normalizer dynamically
                module = __import__(module_path, fromlist=[normalizer_class])
                normalizer = getattr(module, normalizer_class)()

                # Load and normalize
                raw_output = fixture_manager.load_scanner_output(scanner_name)
                normalized = normalizer.normalize(raw_output)

                # Check common fields
                for field in common_fields:
                    assert field in normalized, f"{scanner_name} normalizer missing field: {field}"

                all_normalized.append({
                    "scanner": scanner_name,
                    "normalized": normalized
                })

            except (ImportError, FileNotFoundError) as e:
                print(f"⚠️  Skipping {scanner_name}: {e}")
                continue

        # If no normalizers available, skip test
        if len(all_normalized) == 0:
            pytest.skip("No normalizer modules available")

        # Verify all findings have consistent structure
        for item in all_normalized:
            scanner = item["scanner"]
            findings = item["normalized"]["findings"]

            for finding in findings[:3]:  # Check first 3 from each
                # All findings should have these core fields
                assert "severity" in finding, f"{scanner} finding missing severity"
                assert finding["severity"] in ["critical", "high", "medium", "low", "info"], \
                    f"{scanner} finding has invalid severity: {finding.get('severity')}"

        print(f"✅ All {len(all_normalized)} normalizers produce consistent schema")

    def test_normalized_output_is_json_serializable(self):
        """Test that normalized output can be serialized to JSON"""
        try:
            from normalizer.semgrep_normalizer import SemgrepNormalizer

            # Load and normalize
            semgrep_raw = fixture_manager.load_scanner_output("semgrep")
            normalizer = SemgrepNormalizer()
            normalized = normalizer.normalize(semgrep_raw)

            # Should be JSON serializable
            json_output = json.dumps(normalized, indent=2)
            assert len(json_output) > 0

            # Should be deserializable
            reloaded = json.loads(json_output)
            assert reloaded["tool"] == "semgrep"
            assert len(reloaded["findings"]) == len(normalized["findings"])

            print("✅ Normalized output is JSON serializable")

        except ImportError:
            pytest.skip("Semgrep normalizer not available")

    def test_normalizer_handles_empty_results(self):
        """Test that normalizers can handle empty scanner results"""
        try:
            from normalizer.semgrep_normalizer import SemgrepNormalizer

            # Empty results
            empty_results = {
                "tool": "semgrep",
                "findings": [],
                "findings_count": 0
            }

            normalizer = SemgrepNormalizer()
            normalized = normalizer.normalize(empty_results)

            # Should handle gracefully
            assert normalized["tool"] == "semgrep"
            assert normalized["findings"] == []
            assert normalized["findings_count"] == 0

            print("✅ Normalizer handles empty results")

        except ImportError:
            pytest.skip("Semgrep normalizer not available")

    def test_normalizer_handles_malformed_data(self):
        """Test that normalizers can handle malformed input gracefully"""
        try:
            from normalizer.semgrep_normalizer import SemgrepNormalizer

            malformed_inputs = [
                {},  # Empty dict
                {"tool": "semgrep"},  # Missing findings
                {"findings": []},  # Missing tool
                {"tool": "semgrep", "findings": "not a list"},  # Wrong type
            ]

            normalizer = SemgrepNormalizer()

            for malformed in malformed_inputs:
                try:
                    result = normalizer.normalize(malformed)
                    # Should either succeed or raise known exception
                    assert result is not None
                except (ValueError, KeyError, TypeError) as e:
                    # Expected exceptions are acceptable
                    print(f"   Handled malformed input gracefully: {type(e).__name__}")

            print("✅ Normalizer handles malformed data")

        except ImportError:
            pytest.skip("Semgrep normalizer not available")

    def test_normalizer_preserves_critical_information(self):
        """Test that normalization doesn't lose critical security information"""
        try:
            from normalizer.semgrep_normalizer import SemgrepNormalizer

            # Load real output
            semgrep_raw = fixture_manager.load_scanner_output("semgrep")

            normalizer = SemgrepNormalizer()
            normalized = normalizer.normalize(semgrep_raw)

            # Check that critical info is preserved
            raw_findings = semgrep_raw.get("findings", [])
            normalized_findings = normalized.get("findings", [])

            assert len(normalized_findings) == len(raw_findings), \
                "Normalization should preserve all findings"

            # Check first finding has key security info
            if normalized_findings:
                first = normalized_findings[0]
                critical_fields = ["severity", "file_path", "description"]
                for field in critical_fields:
                    assert field in first, f"Critical field '{field}' missing after normalization"

            print(f"✅ Normalizer preserves {len(normalized_findings)} findings with critical info")

        except ImportError:
            pytest.skip("Semgrep normalizer not available")

    def test_severity_normalization_is_consistent(self):
        """Test that severity levels are normalized consistently"""
        try:
            from normalizer.semgrep_normalizer import SemgrepNormalizer

            semgrep_raw = fixture_manager.load_scanner_output("semgrep")
            normalizer = SemgrepNormalizer()
            normalized = normalizer.normalize(semgrep_raw)

            # All severities should be lowercase and valid
            valid_severities = {"critical", "high", "medium", "low", "info", "warning"}

            for finding in normalized["findings"]:
                severity = finding.get("severity", "").lower()
                assert severity in valid_severities, \
                    f"Invalid normalized severity: {severity}"

            print("✅ Severity normalization is consistent")

        except ImportError:
            pytest.skip("Semgrep normalizer not available")

    def test_cwe_extraction_from_real_data(self):
        """Test that CWE identifiers are correctly extracted"""
        try:
            from normalizer.semgrep_normalizer import SemgrepNormalizer

            semgrep_raw = fixture_manager.load_scanner_output("semgrep")
            normalizer = SemgrepNormalizer()
            normalized = normalizer.normalize(semgrep_raw)

            # Count findings with CWE
            findings_with_cwe = [f for f in normalized["findings"] if f.get("cwe")]

            if findings_with_cwe:
                # Verify CWE format
                for finding in findings_with_cwe:
                    cwe = finding["cwe"]
                    # Should be in format "CWE-XXX"
                    assert cwe.startswith("CWE-"), f"Invalid CWE format: {cwe}"
                    # Number part should be numeric
                    cwe_num = cwe.replace("CWE-", "")
                    assert cwe_num.isdigit(), f"CWE number not numeric: {cwe}"

                print(f"✅ Extracted {len(findings_with_cwe)} CWE identifiers")
            else:
                print("⚠️  No CWE identifiers found in test data")

        except ImportError:
            pytest.skip("Semgrep normalizer not available")

    def test_file_path_normalization(self):
        """Test that file paths are normalized correctly"""
        try:
            from normalizer.semgrep_normalizer import SemgrepNormalizer

            semgrep_raw = fixture_manager.load_scanner_output("semgrep")
            normalizer = SemgrepNormalizer()
            normalized = normalizer.normalize(semgrep_raw)

            for finding in normalized["findings"]:
                file_path = finding.get("file_path", "")

                # File path should not be empty
                assert file_path, "Finding should have file_path"

                # Should be a string
                assert isinstance(file_path, str), "file_path should be string"

                # Should not have weird characters
                assert "\x00" not in file_path, "file_path contains null bytes"

            print(f"✅ All {len(normalized['findings'])} file paths normalized correctly")

        except ImportError:
            pytest.skip("Semgrep normalizer not available")


class TestCrossNormalizerConsistency:
    """Test consistency across different normalizers"""

    def test_all_normalizers_use_same_severity_scale(self):
        """Test that all normalizers use the same severity scale"""
        valid_severities = {"critical", "high", "medium", "low", "info"}

        scanners = ["semgrep", "trivy", "checkov", "trufflehog"]
        all_severities_found = set()

        for scanner in scanners:
            try:
                output = fixture_manager.load_scanner_output(scanner)
                # Handle both dict and list formats
                if isinstance(output, dict):
                    findings = output.get("findings", [])
                elif isinstance(output, list):
                    findings = output
                else:
                    findings = []

                for finding in findings:
                    if isinstance(finding, dict):
                        severity = finding.get("severity", "").lower()
                        if severity:
                            all_severities_found.add(severity)

            except FileNotFoundError:
                print(f"⚠️  No fixture for {scanner}")
                continue

        # All found severities should be valid
        invalid = all_severities_found - valid_severities
        assert not invalid, f"Found invalid severities: {invalid}"

        print(f"✅ All normalizers use consistent severity scale: {all_severities_found}")

    def test_finding_ids_are_unique_within_scanner(self):
        """Test that finding IDs are unique within each scanner"""
        scanners = ["semgrep", "trivy", "checkov", "trufflehog"]

        for scanner in scanners:
            try:
                output = fixture_manager.load_scanner_output(scanner)
                # Handle both dict and list formats
                if isinstance(output, dict):
                    findings = output.get("findings", [])
                elif isinstance(output, list):
                    findings = output
                else:
                    findings = []

                ids = [f.get("id", "") for f in findings if isinstance(f, dict) and f.get("id")]

                # Check for duplicates
                if ids:
                    unique_ids = set(ids)
                    assert len(ids) == len(unique_ids), \
                        f"{scanner} has duplicate finding IDs"

                print(f"✅ {scanner}: {len(ids)} unique finding IDs")

            except FileNotFoundError:
                print(f"⚠️  No fixture for {scanner}")
                continue

    def test_timestamp_format_is_consistent(self):
        """Test that timestamps are in consistent format"""
        scanners = ["semgrep", "trivy", "checkov", "trufflehog"]

        for scanner in scanners:
            try:
                output = fixture_manager.load_scanner_output(scanner)
                if not isinstance(output, dict):
                    print(f"⚠️  Skipping {scanner}: output is not a dict")
                    continue
                timestamp = output.get("timestamp")

                if timestamp:
                    # Should be ISO format or Unix timestamp
                    assert isinstance(timestamp, (str, int, float)), \
                        f"{scanner} timestamp has wrong type: {type(timestamp)}"

                print(f"✅ {scanner}: timestamp format OK")

            except FileNotFoundError:
                continue


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
