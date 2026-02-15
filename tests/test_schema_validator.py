"""Tests for scripts/schema_validator.py — lightweight schema validation."""

import pytest
from schema_validator import ValidationError, validate_finding, validate_llm_response, validate_scanner_output

# ---------------------------------------------------------------------------
# validate_finding
# ---------------------------------------------------------------------------


class TestValidateFinding:
    """Tests for validate_finding()."""

    def test_validate_finding_valid(self):
        """A finding dict with required fields passes validation."""
        data = {"severity": "HIGH", "message": "SQL injection detected"}
        result = validate_finding(data)
        assert result["severity"] == "high"  # normalized to lowercase
        assert result["message"] == "SQL injection detected"

    def test_validate_finding_missing_required_field(self):
        """Missing a required field raises ValidationError."""
        # Has severity but no message
        with pytest.raises(ValidationError, match="missing required field.*message"):
            validate_finding({"severity": "high"})
        # Has message but no severity
        with pytest.raises(ValidationError, match="missing required field.*severity"):
            validate_finding({"message": "something"})

    def test_validate_finding_empty_dict(self):
        """An empty dict raises ValidationError for the first missing field."""
        with pytest.raises(ValidationError, match="missing required field"):
            validate_finding({})

    def test_validate_finding_not_a_dict(self):
        """Passing a non-dict raises ValidationError."""
        with pytest.raises(ValidationError, match="must be a dict"):
            validate_finding("not-a-dict")

    def test_validate_finding_unknown_severity_defaults_to_medium(self):
        """Unknown severity values are silently defaulted to 'medium'."""
        result = validate_finding({"severity": "banana", "message": "test"})
        assert result["severity"] == "medium"

    def test_validate_finding_preserves_extra_keys(self):
        """Extra keys in the finding dict are preserved in the output."""
        data = {"severity": "low", "message": "test", "cwe": "CWE-79", "line": 42}
        result = validate_finding(data)
        assert result["cwe"] == "CWE-79"
        assert result["line"] == 42


# ---------------------------------------------------------------------------
# validate_scanner_output
# ---------------------------------------------------------------------------


class TestValidateScannerOutput:
    """Tests for validate_scanner_output()."""

    def test_validate_scanner_output_valid(self):
        """A dict (with or without 'findings' key) passes validation."""
        data = {"findings": [{"severity": "high", "message": "test"}], "scanner": "semgrep"}
        result = validate_scanner_output(data, scanner_name="semgrep")
        assert result is data  # returns same dict

    def test_validate_scanner_output_no_findings_key(self):
        """A dict without 'findings' key also passes (optional field)."""
        data = {"status": "ok"}
        result = validate_scanner_output(data, scanner_name="trivy")
        assert result == {"status": "ok"}

    def test_validate_scanner_output_missing_fields(self):
        """A non-dict input raises ValidationError with scanner name in message."""
        with pytest.raises(ValidationError, match="semgrep.*must be a dict"):
            validate_scanner_output("raw-string", scanner_name="semgrep")

    def test_validate_scanner_output_findings_not_a_list(self):
        """When 'findings' is present but not a list, raises ValidationError."""
        with pytest.raises(ValidationError, match="findings.*must be a list"):
            validate_scanner_output({"findings": "not-a-list"}, scanner_name="trivy")


# ---------------------------------------------------------------------------
# validate_llm_response
# ---------------------------------------------------------------------------


class TestValidateLlmResponse:
    """Tests for validate_llm_response()."""

    def test_validate_llm_response_valid(self):
        """A dict with all expected keys passes validation."""
        data = {"risk_score": 8.5, "analysis": "Critical vulnerability"}
        result = validate_llm_response(data, expected_keys={"risk_score", "analysis"})
        assert result is data

    def test_validate_llm_response_not_dict(self):
        """A non-dict (e.g. a string) raises ValidationError."""
        with pytest.raises(ValidationError, match="must be a dict.*str"):
            validate_llm_response("just a plain string")

    def test_validate_llm_response_missing_keys(self):
        """Missing expected keys produces a warning but does NOT raise."""
        data = {"risk_score": 5}
        # Should not raise -- only logs a warning
        result = validate_llm_response(data, expected_keys={"risk_score", "analysis", "cwe"})
        assert result is data

    def test_validate_llm_response_no_expected_keys(self):
        """When expected_keys is None, any dict passes."""
        result = validate_llm_response({"arbitrary": True})
        assert result == {"arbitrary": True}

    def test_validate_llm_response_empty_dict(self):
        """An empty dict is valid (it *is* a dict)."""
        result = validate_llm_response({})
        assert result == {}
