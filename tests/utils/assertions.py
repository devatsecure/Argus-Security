"""
Custom assertions for security testing
Provides domain-specific assertions for security findings and vulnerabilities
"""
from typing import Any, Dict, List, Optional


class SecurityAssertions:
    """Custom assertions for security testing"""

    @staticmethod
    def assert_finding_has_required_fields(finding: Dict[str, Any], required_fields: Optional[List[str]] = None):
        """
        Assert that a finding has all required fields

        Args:
            finding: Finding dictionary
            required_fields: List of required field names (default: standard set)
        """
        if required_fields is None:
            required_fields = ["severity", "file_path", "description"]

        missing_fields = [field for field in required_fields if field not in finding]
        assert not missing_fields, f"Finding missing required fields: {missing_fields}. Finding: {finding}"

    @staticmethod
    def assert_valid_severity(severity: str):
        """Assert that severity is a valid value"""
        valid_severities = ["critical", "high", "medium", "low", "info", "warning", "error"]
        assert severity.lower() in valid_severities, f"Invalid severity: {severity}. Must be one of {valid_severities}"

    @staticmethod
    def assert_valid_cwe(cwe: str):
        """Assert that CWE ID is properly formatted"""
        if not cwe:
            return  # CWE can be optional
        assert cwe.upper().startswith("CWE-"), f"Invalid CWE format: {cwe}. Must start with 'CWE-'"
        cwe_number = cwe.upper().replace("CWE-", "")
        assert cwe_number.isdigit(), f"Invalid CWE number: {cwe_number}. Must be numeric"

    @staticmethod
    def assert_valid_cve(cve: str):
        """Assert that CVE ID is properly formatted"""
        if not cve:
            return  # CVE can be optional
        assert cve.upper().startswith("CVE-"), f"Invalid CVE format: {cve}. Must start with 'CVE-'"

    @staticmethod
    def assert_sarif_structure(sarif_output: Dict[str, Any]):
        """
        Assert that output is valid SARIF 2.1.0 format

        Args:
            sarif_output: SARIF output dictionary
        """
        # Check SARIF version
        assert "version" in sarif_output, "SARIF output missing 'version' field"
        assert sarif_output["version"] == "2.1.0", f"Expected SARIF version 2.1.0, got {sarif_output['version']}"

        # Check schema
        assert "$schema" in sarif_output, "SARIF output missing '$schema' field"

        # Check runs
        assert "runs" in sarif_output, "SARIF output missing 'runs' field"
        assert isinstance(sarif_output["runs"], list), "SARIF 'runs' must be a list"
        assert len(sarif_output["runs"]) > 0, "SARIF 'runs' cannot be empty"

        # Check each run
        for run in sarif_output["runs"]:
            assert "tool" in run, "SARIF run missing 'tool' field"
            assert "driver" in run["tool"], "SARIF tool missing 'driver' field"
            assert "name" in run["tool"]["driver"], "SARIF driver missing 'name' field"
            assert "results" in run, "SARIF run missing 'results' field"
            assert isinstance(run["results"], list), "SARIF 'results' must be a list"

            # Check each result
            for result in run["results"]:
                assert "ruleId" in result, "SARIF result missing 'ruleId' field"
                assert "message" in result, "SARIF result missing 'message' field"
                assert "locations" in result or "stacks" in result, "SARIF result must have 'locations' or 'stacks'"

    @staticmethod
    def assert_findings_deduplicated(findings: List[Dict[str, Any]]):
        """
        Assert that findings list has no duplicates

        Args:
            findings: List of findings to check
        """
        # Create unique identifiers for each finding
        seen = set()
        duplicates = []

        for finding in findings:
            # Create identifier from key fields (handle multiple naming conventions)
            identifier = (
                finding.get("file_path", finding.get("file", "")),
                finding.get("line_number", finding.get("start_line", 0)),
                finding.get("title", finding.get("rule_id", "")),
                finding.get("cwe_id", finding.get("cwe", "")),
            )

            if identifier in seen:
                duplicates.append(finding)
            seen.add(identifier)

        assert not duplicates, f"Found {len(duplicates)} duplicate findings"

    @staticmethod
    def assert_exploitability_is_valid(exploitability: str):
        """Assert that exploitability level is valid"""
        valid_levels = ["trivial", "moderate", "complex", "theoretical", "unknown"]
        assert exploitability.lower() in valid_levels, f"Invalid exploitability: {exploitability}"

    @staticmethod
    def assert_confidence_score_valid(confidence: float):
        """Assert that confidence score is between 0.0 and 1.0"""
        assert 0.0 <= confidence <= 1.0, f"Confidence score must be 0.0-1.0, got {confidence}"

    @staticmethod
    def assert_correlation_accuracy_acceptable(
        true_positives: int,
        false_positives: int,
        false_negatives: int,
        min_precision: float = 0.8,
        min_recall: float = 0.7,
    ):
        """
        Assert that correlation accuracy meets minimum thresholds

        Args:
            true_positives: Number of true positives
            false_positives: Number of false positives
            false_negatives: Number of false negatives
            min_precision: Minimum acceptable precision (default 0.8)
            min_recall: Minimum acceptable recall (default 0.7)
        """
        # Calculate precision
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0

        # Calculate recall
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0

        assert precision >= min_precision, f"Precision too low: {precision:.2%} (min: {min_precision:.2%})"
        assert recall >= min_recall, f"Recall too low: {recall:.2%} (min: {min_recall:.2%})"

    @staticmethod
    def assert_remediation_is_valid(remediation: Dict[str, Any]):
        """Assert that remediation has required structure"""
        required_fields = ["description", "fix_type"]
        missing = [f for f in required_fields if f not in remediation]
        assert not missing, f"Remediation missing required fields: {missing}"

        valid_fix_types = ["code_change", "configuration", "dependency_update", "manual"]
        fix_type = remediation["fix_type"]
        assert fix_type in valid_fix_types, f"Invalid fix_type: {fix_type}"

    @staticmethod
    def assert_threat_model_is_complete(threat_model: Dict[str, Any]):
        """Assert that threat model has all required components"""
        required_sections = ["threats", "assets", "trust_boundaries", "data_flows"]
        missing = [s for s in required_sections if s not in threat_model]
        assert not missing, f"Threat model missing sections: {missing}"

        # Check threats are non-empty
        threats = threat_model.get("threats", [])
        assert len(threats) > 0, "Threat model must identify at least one threat"

        # Validate threat structure
        for threat in threats:
            assert "id" in threat, "Threat missing 'id' field"
            assert "category" in threat, "Threat missing 'category' field"
            assert "description" in threat, "Threat missing 'description' field"

    @staticmethod
    def assert_scan_completed_successfully(result: Dict[str, Any]):
        """Assert that scan completed without errors"""
        assert "error" not in result or result["error"] is None, f"Scan failed with error: {result.get('error')}"
        assert "findings" in result, "Scan result missing 'findings' field"
        assert isinstance(result["findings"], list), "'findings' must be a list"

    @staticmethod
    def assert_enrichment_added_value(original_finding: Dict[str, Any], enriched_finding: Dict[str, Any]):
        """
        Assert that enrichment added valuable information

        Args:
            original_finding: Finding before enrichment
            enriched_finding: Finding after enrichment
        """
        # Check that enrichment added new fields or improved existing ones
        added_fields = set(enriched_finding.keys()) - set(original_finding.keys())
        assert len(added_fields) > 0, "Enrichment did not add any new fields"

        # Common enrichment fields
        enrichment_fields = ["cwe_id", "exploitability", "recommendation", "references", "cvss_score"]
        enriched_count = sum(1 for field in enrichment_fields if field in enriched_finding and field not in original_finding)

        assert enriched_count > 0, f"Enrichment should add at least one of: {enrichment_fields}"


# Convenience instance
security_assertions = SecurityAssertions()
