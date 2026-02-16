"""
Tests for scripts/phase_gate.py — Phase validation gating.

Covers:
- PhaseGate.validate() with known and unknown phases
- Strict vs lenient mode behavior
- Finding structure validation
- Agent report validation
- Edge cases: None output, non-dict output, empty data
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from phase_gate import GateDecision, PhaseGate, PhaseOutput


# ============================================================================
# PhaseGate.validate — happy path
# ============================================================================


class TestPhaseGateValidateHappyPath:
    """Test validate() with valid outputs for each phase schema."""

    def test_scanner_orchestration_valid_output(self):
        """Valid scanner output with findings should pass."""
        gate = PhaseGate(strict=False)
        output = {
            "findings": [
                {"severity": "high", "message": "SQL injection found"},
                {"severity": "medium", "message": "XSS in template"},
            ]
        }
        decision = gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []
        assert "passed" in decision.reason.lower()
        assert isinstance(decision.phase_output, PhaseOutput)
        assert decision.phase_output.phase_name == "scanner_orchestration"

    def test_scanner_orchestration_empty_findings(self):
        """Scanner may legitimately find nothing — should still pass."""
        gate = PhaseGate(strict=True)
        output = {"findings": []}
        decision = gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []

    def test_ai_enrichment_valid(self):
        """Valid ai_enrichment output should pass."""
        gate = PhaseGate(strict=True)
        output = {"enriched_findings": [{"severity": "high", "cwe": "CWE-89"}]}
        decision = gate.validate("ai_enrichment", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []

    def test_policy_gates_valid(self):
        """Valid policy gate output with both required keys should pass."""
        gate = PhaseGate(strict=True)
        output = {"gate_result": "pass", "pass_fail": "pass"}
        decision = gate.validate("policy_gates", output)
        assert decision.should_proceed is True

    def test_reporting_valid(self):
        """Valid reporting output should pass."""
        gate = PhaseGate(strict=False)
        output = {"report_paths": ["/tmp/report.json", "/tmp/report.md"]}
        decision = gate.validate("reporting", output)
        assert decision.should_proceed is True

    def test_multi_agent_review_valid(self):
        """Valid multi-agent review output should pass."""
        gate = PhaseGate(strict=True)
        output = {
            "agent_reports": {
                "security_agent": "Found 3 critical issues that need attention in the authentication module.",
            }
        }
        decision = gate.validate("multi_agent_review", output)
        assert decision.should_proceed is True
        assert decision.validation_errors == []


# ============================================================================
# PhaseGate.validate — missing keys / errors
# ============================================================================


class TestPhaseGateValidateErrors:
    """Test validate() catches missing keys and structural errors."""

    def test_missing_required_key_strict_blocks(self):
        """Strict mode should block when required key is missing."""
        gate = PhaseGate(strict=True)
        output = {}  # Missing 'findings'
        decision = gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is False
        assert len(decision.validation_errors) > 0
        assert any("Missing required key" in e for e in decision.validation_errors)

    def test_missing_required_key_lenient_continues(self):
        """Lenient mode should continue with warnings when required key is missing."""
        gate = PhaseGate(strict=False)
        output = {}  # Missing 'findings'
        decision = gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is True
        assert len(decision.validation_errors) > 0

    def test_required_key_is_none(self):
        """A required key set to None should produce a validation error."""
        gate = PhaseGate(strict=True)
        output = {"enriched_findings": None}
        decision = gate.validate("ai_enrichment", output)
        assert decision.should_proceed is False
        assert any("None" in e for e in decision.validation_errors)

    def test_policy_gates_missing_one_key(self):
        """Policy gates requires both gate_result and pass_fail."""
        gate = PhaseGate(strict=True)
        output = {"gate_result": "pass"}  # Missing pass_fail
        decision = gate.validate("policy_gates", output)
        assert decision.should_proceed is False
        assert any("pass_fail" in e for e in decision.validation_errors)

    def test_non_dict_output_strict(self):
        """Non-dict output should fail with type error in strict mode."""
        gate = PhaseGate(strict=True)
        decision = gate.validate("scanner_orchestration", "not a dict")
        assert decision.should_proceed is False
        assert any("dict" in e for e in decision.validation_errors)

    def test_non_dict_output_lenient(self):
        """Non-dict output should proceed with warning in lenient mode."""
        gate = PhaseGate(strict=False)
        decision = gate.validate("scanner_orchestration", [1, 2, 3])
        assert decision.should_proceed is True
        assert len(decision.validation_errors) > 0


# ============================================================================
# PhaseGate.validate — unknown phases
# ============================================================================


class TestPhaseGateUnknownPhase:
    """Test behavior with unrecognized phase names."""

    def test_unknown_phase_allows_by_default(self):
        """Unknown phase names should be allowed with a warning."""
        gate = PhaseGate(strict=True)
        decision = gate.validate("some_future_phase", {"data": 123})
        assert decision.should_proceed is True
        assert "No schema" in decision.reason

    def test_unknown_phase_returns_phase_output(self):
        """Unknown phase should still populate phase_output."""
        gate = PhaseGate(strict=False)
        decision = gate.validate("custom_phase", {})
        assert decision.phase_output is not None
        assert decision.phase_output.phase_name == "custom_phase"


# ============================================================================
# PhaseGate.validate_findings_structure
# ============================================================================


class TestValidateFindingsStructure:
    """Test structural validation of individual findings."""

    def test_valid_findings(self):
        """Findings with required fields should produce no errors."""
        gate = PhaseGate()
        findings = [
            {"severity": "high", "message": "SQL injection"},
            {"severity": "low", "message": "Info disclosure"},
        ]
        errors = gate.validate_findings_structure(findings)
        assert errors == []

    def test_finding_missing_fields(self):
        """Findings missing severity or message should be flagged."""
        gate = PhaseGate()
        findings = [
            {"severity": "high"},  # Missing 'message'
            {"message": "test"},   # Missing 'severity'
        ]
        errors = gate.validate_findings_structure(findings)
        assert len(errors) == 2
        assert "Finding [0]" in errors[0]
        assert "Finding [1]" in errors[1]

    def test_finding_not_dict(self):
        """Non-dict findings should be caught."""
        gate = PhaseGate()
        findings = ["not a dict", 42]
        errors = gate.validate_findings_structure(findings)
        assert len(errors) == 2
        assert "not a dict" in errors[0]

    def test_empty_findings_list(self):
        """Empty findings list should produce no errors."""
        gate = PhaseGate()
        errors = gate.validate_findings_structure([])
        assert errors == []

    def test_malformed_findings_trigger_validate_errors(self):
        """Findings with missing fields should appear as validation_errors in GateDecision."""
        gate = PhaseGate(strict=True)
        output = {"findings": [{"severity": "high"}]}  # Missing 'message'
        decision = gate.validate("scanner_orchestration", output)
        assert decision.should_proceed is False
        assert any("missing fields" in e.lower() for e in decision.validation_errors)


# ============================================================================
# PhaseGate.validate_agent_reports
# ============================================================================


class TestValidateAgentReports:
    """Test agent report content validation."""

    def test_valid_reports(self):
        """Non-empty, meaningful reports should pass."""
        gate = PhaseGate()
        reports = {
            "security_agent": "Found 3 critical vulnerabilities in the auth module.",
            "quality_agent": "Code follows best practices with minor exceptions.",
        }
        errors = gate.validate_agent_reports(reports)
        assert errors == []

    def test_empty_report(self):
        """Empty string reports should be flagged."""
        gate = PhaseGate()
        reports = {"agent1": "", "agent2": "Valid report with enough content."}
        errors = gate.validate_agent_reports(reports)
        assert len(errors) == 1
        assert "agent1" in errors[0]

    def test_too_short_report(self):
        """Reports shorter than 10 chars should be flagged."""
        gate = PhaseGate()
        reports = {"agent_x": "Short"}  # 5 chars
        errors = gate.validate_agent_reports(reports)
        assert len(errors) == 1
        assert "too short" in errors[0].lower()

    def test_none_report_value(self):
        """None report value should be flagged."""
        gate = PhaseGate()
        reports = {"agent_null": None}
        errors = gate.validate_agent_reports(reports)
        assert len(errors) == 1

    def test_too_few_agents_in_validate(self):
        """Multi-agent review with 0 reports should fail when min_agents=1."""
        gate = PhaseGate(strict=True)
        output = {"agent_reports": {}}
        decision = gate.validate("multi_agent_review", output)
        assert decision.should_proceed is False
        assert any("at least 1" in e for e in decision.validation_errors)


# ============================================================================
# PhaseGate strict property
# ============================================================================


class TestPhaseGateStrictProperty:
    """Test the strict property accessor."""

    def test_strict_true(self):
        gate = PhaseGate(strict=True)
        assert gate.strict is True

    def test_strict_false_default(self):
        gate = PhaseGate()
        assert gate.strict is False


# ============================================================================
# GateDecision and PhaseOutput dataclasses
# ============================================================================


class TestDataclasses:
    """Test dataclass construction and defaults."""

    def test_gate_decision_defaults(self):
        """GateDecision should have sensible defaults."""
        decision = GateDecision(should_proceed=True, reason="OK")
        assert decision.validation_errors == []
        assert decision.phase_output is None

    def test_phase_output_defaults(self):
        """PhaseOutput should have sensible defaults."""
        po = PhaseOutput(phase_name="test_phase")
        assert po.findings == []
        assert po.reports == {}
        assert po.metrics == {}
        assert po.timestamp == ""
