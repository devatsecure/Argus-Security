"""
Tests for Phase Gate validation logic.

Covers schema validation, strict vs lenient mode, finding structure
checks, agent report validation, and edge cases.
"""

import pytest

from scripts.phase_gate import GateDecision, PhaseGate, PhaseOutput

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def lenient_gate():
    """Return a PhaseGate in lenient (non-strict) mode."""
    return PhaseGate(strict=False)


@pytest.fixture
def strict_gate():
    """Return a PhaseGate in strict mode."""
    return PhaseGate(strict=True)


# ---------------------------------------------------------------------------
# Basic validation tests
# ---------------------------------------------------------------------------

class TestPhaseGateValidation:
    """Test core validation behavior."""

    def test_valid_scanner_output_passes(self, lenient_gate):
        """Valid scanner output with findings passes the gate."""
        output = {
            "findings": [
                {"severity": "high", "message": "SQL injection found"},
                {"severity": "medium", "message": "Missing CSRF token"},
            ]
        }
        decision = lenient_gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []
        assert "passed validation" in decision.reason

    def test_empty_findings_list_passes_scanner(self, lenient_gate):
        """Scanner phase allows an empty findings list (nothing found)."""
        output = {"findings": []}
        decision = lenient_gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []

    def test_missing_required_key_detected(self, lenient_gate):
        """Missing a required key produces a validation error."""
        output = {}  # Missing 'findings'
        decision = lenient_gate.validate("scanner_orchestration", output)
        assert len(decision.validation_errors) > 0
        assert any("Missing required key" in e for e in decision.validation_errors)

    def test_none_value_for_required_key(self, lenient_gate):
        """A None value for a required key is flagged."""
        output = {"findings": None}
        decision = lenient_gate.validate("scanner_orchestration", output)
        assert len(decision.validation_errors) > 0
        assert any("is None" in e for e in decision.validation_errors)

    def test_non_dict_output_fails(self, lenient_gate):
        """Non-dict output produces a validation error."""
        decision = lenient_gate.validate("scanner_orchestration", "not a dict")
        assert len(decision.validation_errors) > 0
        assert any("must be a dict" in e for e in decision.validation_errors)

    def test_non_dict_output_list(self, lenient_gate):
        """A list (not a dict) is caught as invalid output type."""
        decision = lenient_gate.validate("scanner_orchestration", [1, 2, 3])
        assert len(decision.validation_errors) > 0
        assert "must be a dict" in decision.validation_errors[0]

    def test_unknown_phase_passes_by_default(self, lenient_gate):
        """An unknown phase name produces no errors and allows progression."""
        decision = lenient_gate.validate("unknown_phase", {"whatever": True})
        assert decision.should_proceed is True
        assert decision.validation_errors == []
        assert "No schema" in decision.reason

    def test_unknown_phase_returns_phase_output(self, lenient_gate):
        """Unknown phase still returns a PhaseOutput in the decision."""
        decision = lenient_gate.validate("unknown_phase", {})
        assert decision.phase_output is not None
        assert decision.phase_output.phase_name == "unknown_phase"


# ---------------------------------------------------------------------------
# Strict vs lenient mode
# ---------------------------------------------------------------------------

class TestStrictVsLenientMode:
    """Test strict and lenient mode behavior."""

    def test_lenient_proceeds_on_error(self, lenient_gate):
        """In lenient mode, validation errors still allow progression."""
        output = {}  # Missing required key 'findings'
        decision = lenient_gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is True
        assert len(decision.validation_errors) > 0

    def test_strict_blocks_on_error(self, strict_gate):
        """In strict mode, validation errors block progression."""
        output = {}  # Missing required key 'findings'
        decision = strict_gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is False
        assert len(decision.validation_errors) > 0

    def test_strict_passes_valid_output(self, strict_gate):
        """Strict mode still allows valid output to proceed."""
        output = {
            "findings": [
                {"severity": "low", "message": "Minor code smell"},
            ]
        }
        decision = strict_gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []

    def test_strict_property(self, strict_gate, lenient_gate):
        """The strict property reflects the mode."""
        assert strict_gate.strict is True
        assert lenient_gate.strict is False

    def test_strict_blocks_non_dict_output(self, strict_gate):
        """Strict mode blocks non-dict output."""
        decision = strict_gate.validate("scanner_orchestration", 42)
        assert decision.should_proceed is False

    def test_lenient_allows_non_dict_output(self, lenient_gate):
        """Lenient mode warns but allows non-dict output."""
        decision = lenient_gate.validate("scanner_orchestration", 42)
        assert decision.should_proceed is True
        assert len(decision.validation_errors) > 0


# ---------------------------------------------------------------------------
# Findings structure validation
# ---------------------------------------------------------------------------

class TestFindingsStructureValidation:
    """Test validation of individual finding dictionaries."""

    def test_valid_findings_no_errors(self, lenient_gate):
        """Well-formed findings produce no structural errors."""
        findings = [
            {"severity": "high", "message": "Issue A"},
            {"severity": "low", "message": "Issue B"},
        ]
        errors = lenient_gate.validate_findings_structure(findings)
        assert errors == []

    def test_missing_severity_field(self, lenient_gate):
        """A finding missing the severity field is flagged."""
        findings = [{"message": "No severity here"}]
        errors = lenient_gate.validate_findings_structure(findings)
        assert len(errors) == 1
        assert "severity" in errors[0]

    def test_missing_message_field(self, lenient_gate):
        """A finding missing the message field is flagged."""
        findings = [{"severity": "high"}]
        errors = lenient_gate.validate_findings_structure(findings)
        assert len(errors) == 1
        assert "message" in errors[0]

    def test_missing_both_fields(self, lenient_gate):
        """A finding missing both fields is flagged once with both names."""
        findings = [{"file": "test.py"}]
        errors = lenient_gate.validate_findings_structure(findings)
        assert len(errors) == 1
        assert "severity" in errors[0]
        assert "message" in errors[0]

    def test_non_dict_finding(self, lenient_gate):
        """A finding that is not a dict is flagged."""
        findings = ["not a dict", 42]
        errors = lenient_gate.validate_findings_structure(findings)
        assert len(errors) == 2
        assert all("not a dict" in e for e in errors)

    def test_mixed_valid_and_invalid(self, lenient_gate):
        """Mix of valid and invalid findings only flags the bad ones."""
        findings = [
            {"severity": "high", "message": "Good finding"},
            {"oops": True},  # Missing both required fields
            {"severity": "low", "message": "Another good one"},
        ]
        errors = lenient_gate.validate_findings_structure(findings)
        assert len(errors) == 1
        assert "[1]" in errors[0]

    def test_empty_findings_no_errors(self, lenient_gate):
        """An empty findings list produces no errors."""
        errors = lenient_gate.validate_findings_structure([])
        assert errors == []

    def test_finding_validation_integrated_in_gate(self, strict_gate):
        """Finding structure errors flow through the full gate validation."""
        output = {
            "findings": [
                {"severity": "high"},  # Missing 'message'
            ]
        }
        decision = strict_gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is False
        assert any("message" in e for e in decision.validation_errors)


# ---------------------------------------------------------------------------
# Agent reports validation
# ---------------------------------------------------------------------------

class TestAgentReportsValidation:
    """Test validation of multi-agent review reports."""

    def test_valid_agent_reports(self, lenient_gate):
        """Reports with sufficient content produce no errors."""
        reports = {
            "SecretHunter": "Found 3 hardcoded API keys in config.py, lines 42-50.",
            "ExploitAssessor": "SQL injection is exploitable via user input on line 88.",
        }
        errors = lenient_gate.validate_agent_reports(reports)
        assert errors == []

    def test_empty_report_flagged(self, lenient_gate):
        """An empty string report is flagged."""
        reports = {
            "SecretHunter": "",
            "ExploitAssessor": "Valid report content here.",
        }
        errors = lenient_gate.validate_agent_reports(reports)
        assert len(errors) == 1
        assert "SecretHunter" in errors[0]

    def test_none_report_flagged(self, lenient_gate):
        """A None report is flagged."""
        reports = {
            "SecretHunter": None,
        }
        errors = lenient_gate.validate_agent_reports(reports)
        assert len(errors) == 1
        assert "SecretHunter" in errors[0]

    def test_too_short_report_flagged(self, lenient_gate):
        """A report shorter than 10 chars is flagged as too short."""
        reports = {
            "SecretHunter": "OK",  # Only 2 chars
        }
        errors = lenient_gate.validate_agent_reports(reports)
        assert len(errors) == 1
        assert "too short" in errors[0]

    def test_whitespace_only_report_flagged(self, lenient_gate):
        """A whitespace-only report is flagged as too short."""
        reports = {
            "SecretHunter": "         ",  # 9 spaces, stripped < 10
        }
        errors = lenient_gate.validate_agent_reports(reports)
        assert len(errors) == 1

    def test_exactly_10_chars_passes(self, lenient_gate):
        """A report with exactly 10 characters passes."""
        reports = {
            "SecretHunter": "1234567890",
        }
        errors = lenient_gate.validate_agent_reports(reports)
        assert errors == []

    def test_agent_reports_integrated_in_gate(self, strict_gate):
        """Agent report errors flow through the full gate for multi-agent phase."""
        output = {
            "agent_reports": {
                "SecretHunter": "",  # Empty report
            }
        }
        decision = strict_gate.validate("multi_agent_review", output)
        assert decision.should_proceed is False
        assert any("SecretHunter" in e for e in decision.validation_errors)


# ---------------------------------------------------------------------------
# Multi-agent review min_agents check
# ---------------------------------------------------------------------------

class TestMultiAgentMinAgents:
    """Test minimum agent count validation."""

    def test_enough_agents_passes(self, lenient_gate):
        """Meeting the minimum agent count passes."""
        output = {
            "agent_reports": {
                "SecretHunter": "Found issues in authentication module.",
            }
        }
        decision = lenient_gate.validate("multi_agent_review", output)
        # min_agents is 1, we have 1 agent -- no min_agents error expected
        assert not any("Expected at least" in e for e in decision.validation_errors)

    def test_zero_agents_fails(self, strict_gate):
        """Zero agents when min_agents=1 is flagged."""
        output = {
            "agent_reports": {}
        }
        decision = strict_gate.validate("multi_agent_review", output)
        assert decision.should_proceed is False
        assert any("Expected at least" in e for e in decision.validation_errors)


# ---------------------------------------------------------------------------
# All phase schemas
# ---------------------------------------------------------------------------

class TestAllPhaseSchemas:
    """Test validation across all defined phase schemas."""

    def test_ai_enrichment_valid(self, lenient_gate):
        """Valid AI enrichment output passes."""
        output = {"enriched_findings": [{"severity": "high", "enriched": True}]}
        decision = lenient_gate.validate("ai_enrichment", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []

    def test_ai_enrichment_missing_key(self, strict_gate):
        """Missing enriched_findings key is caught."""
        output = {"findings": []}  # Wrong key name
        decision = strict_gate.validate("ai_enrichment", output)
        assert decision.should_proceed is False
        assert any("enriched_findings" in e for e in decision.validation_errors)

    def test_sandbox_validation_valid(self, lenient_gate):
        """Valid sandbox validation output passes."""
        output = {"validation_results": [{"status": "EXPLOITABLE"}]}
        decision = lenient_gate.validate("sandbox_validation", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []

    def test_sandbox_validation_missing(self, strict_gate):
        """Missing validation_results is caught."""
        output = {}
        decision = strict_gate.validate("sandbox_validation", output)
        assert decision.should_proceed is False

    def test_policy_gates_valid(self, lenient_gate):
        """Valid policy gate output with both required keys passes."""
        output = {"gate_result": {"allowed": True}, "pass_fail": "pass"}
        decision = lenient_gate.validate("policy_gates", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []

    def test_policy_gates_missing_pass_fail(self, strict_gate):
        """Missing pass_fail key is caught in policy gates."""
        output = {"gate_result": {"allowed": True}}
        decision = strict_gate.validate("policy_gates", output)
        assert decision.should_proceed is False
        assert any("pass_fail" in e for e in decision.validation_errors)

    def test_policy_gates_none_gate_result(self, strict_gate):
        """None gate_result value is caught."""
        output = {"gate_result": None, "pass_fail": "fail"}
        decision = strict_gate.validate("policy_gates", output)
        assert decision.should_proceed is False
        assert any("gate_result" in e and "None" in e for e in decision.validation_errors)

    def test_reporting_valid(self, lenient_gate):
        """Valid reporting output passes."""
        output = {"report_paths": {"sarif": "/tmp/results.sarif"}}
        decision = lenient_gate.validate("reporting", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []

    def test_reporting_missing_paths(self, strict_gate):
        """Missing report_paths is caught."""
        output = {}
        decision = strict_gate.validate("reporting", output)
        assert decision.should_proceed is False
        assert any("report_paths" in e for e in decision.validation_errors)


# ---------------------------------------------------------------------------
# GateDecision and PhaseOutput dataclass tests
# ---------------------------------------------------------------------------

class TestGateDecisionDataclass:
    """Test GateDecision dataclass defaults and construction."""

    def test_defaults(self):
        """GateDecision has sensible defaults."""
        decision = GateDecision(should_proceed=True, reason="test")
        assert decision.should_proceed is True
        assert decision.reason == "test"
        assert decision.validation_errors == []
        assert decision.phase_output is None

    def test_with_all_fields(self):
        """GateDecision can be constructed with all fields."""
        po = PhaseOutput(phase_name="test_phase")
        decision = GateDecision(
            should_proceed=False,
            reason="blocked",
            validation_errors=["error1", "error2"],
            phase_output=po,
        )
        assert decision.should_proceed is False
        assert len(decision.validation_errors) == 2
        assert decision.phase_output.phase_name == "test_phase"


class TestPhaseOutputDataclass:
    """Test PhaseOutput dataclass defaults and construction."""

    def test_defaults(self):
        """PhaseOutput has sensible defaults."""
        po = PhaseOutput(phase_name="scanner")
        assert po.phase_name == "scanner"
        assert po.findings == []
        assert po.reports == {}
        assert po.metrics == {}
        assert po.timestamp == ""

    def test_with_data(self):
        """PhaseOutput can hold actual data."""
        po = PhaseOutput(
            phase_name="scanner",
            findings=[{"id": 1}],
            reports={"sarif": "path"},
            metrics={"count": 5},
            timestamp="2025-01-01T00:00:00Z",
        )
        assert len(po.findings) == 1
        assert po.reports["sarif"] == "path"
        assert po.metrics["count"] == 5
        assert po.timestamp == "2025-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_extra_keys_ignored(self, lenient_gate):
        """Extra keys in the output dict are silently ignored."""
        output = {
            "findings": [],
            "extra_data": "should be fine",
            "another_key": 42,
        }
        decision = lenient_gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []

    def test_multiple_errors_aggregated(self, strict_gate):
        """Multiple validation errors are all collected."""
        output = {"gate_result": None, "pass_fail": None}
        decision = strict_gate.validate("policy_gates", output)
        assert len(decision.validation_errors) == 2

    def test_error_count_in_reason(self, lenient_gate):
        """The reason string includes the error count."""
        output = {"gate_result": None, "pass_fail": None}
        decision = lenient_gate.validate("policy_gates", output)
        assert "2 validation error(s)" in decision.reason

    def test_phase_output_always_set_on_success(self, lenient_gate):
        """Successful validation always sets phase_output."""
        output = {"findings": []}
        decision = lenient_gate.validate("scanner_orchestration", output)
        assert decision.phase_output is not None
        assert decision.phase_output.phase_name == "scanner_orchestration"

    def test_phase_output_set_on_known_phase_with_errors(self, lenient_gate):
        """Even with errors, phase_output is set for known phases."""
        output = {}
        decision = lenient_gate.validate("scanner_orchestration", output)
        assert decision.phase_output is not None

    def test_required_schemas_immutable_usage(self, lenient_gate):
        """Calling validate does not mutate REQUIRED_SCHEMAS."""
        original_schemas = dict(PhaseGate.REQUIRED_SCHEMAS)
        lenient_gate.validate("scanner_orchestration", {"findings": []})
        assert original_schemas == PhaseGate.REQUIRED_SCHEMAS
