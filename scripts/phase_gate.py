"""Phase gating for the Argus Security pipeline.

Validates phase outputs before allowing pipeline progression.
Supports strict mode (stop on failure) and lenient mode (warn and continue).

Usage::

    from phase_gate import PhaseGate, GateDecision

    gate = PhaseGate(strict=False)
    decision = gate.validate("scanner_orchestration", {"findings": [...]})
    if not decision.should_proceed:
        raise RuntimeError(decision.reason)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PhaseOutput:
    """Structured output from a pipeline phase."""

    phase_name: str
    findings: list[dict] = field(default_factory=list)
    reports: dict[str, str] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""


@dataclass
class GateDecision:
    """Result of a phase gate validation.

    Attributes
    ----------
    should_proceed : bool
        Whether the pipeline should continue to the next phase.
    reason : str
        Human-readable explanation of the decision.
    validation_errors : list[str]
        Individual validation error messages.
    phase_output : PhaseOutput | None
        Structured representation of the validated output.
    """

    should_proceed: bool
    reason: str
    validation_errors: list[str] = field(default_factory=list)
    phase_output: PhaseOutput | None = None


class PhaseGate:
    """Validates phase outputs before allowing pipeline progression.

    Each pipeline phase has a schema that defines required keys, minimum
    counts, and structural expectations.  The gate checks outputs against
    the appropriate schema and returns a ``GateDecision``.

    Parameters
    ----------
    strict : bool
        When ``True``, validation errors block progression (``should_proceed=False``).
        When ``False`` (default), errors produce warnings but allow continuation.
    """

    # Schema definitions for each phase
    REQUIRED_SCHEMAS: dict[str, dict[str, Any]] = {
        "scanner_orchestration": {
            "required_keys": ["findings"],
            "min_findings": 0,  # Scanner may legitimately find nothing
        },
        "ai_enrichment": {
            "required_keys": ["enriched_findings"],
        },
        "multi_agent_review": {
            "required_keys": ["agent_reports"],
            "min_agents": 1,
        },
        "sandbox_validation": {
            "required_keys": ["validation_results"],
        },
        "policy_gates": {
            "required_keys": ["gate_result", "pass_fail"],
        },
        "reporting": {
            "required_keys": ["report_paths"],
        },
    }

    def __init__(self, strict: bool = False):
        self._strict = strict

    @property
    def strict(self) -> bool:
        """Whether the gate blocks on validation errors."""
        return self._strict

    def validate(self, phase_name: str, output: dict[str, Any]) -> GateDecision:
        """Validate phase output against its schema.

        Parameters
        ----------
        phase_name : str
            The name of the phase whose output is being validated.
            Must match a key in ``REQUIRED_SCHEMAS`` for schema-based
            checking; unknown phases are allowed by default.
        output : dict
            The phase output dictionary to validate.

        Returns
        -------
        GateDecision
            The validation result including whether to proceed, any errors,
            and the reason for the decision.
        """
        errors: list[str] = []
        schema = self.REQUIRED_SCHEMAS.get(phase_name)

        if schema is None:
            # Unknown phase -- warn but allow
            logger.warning(
                "No schema defined for phase '%s', allowing by default",
                phase_name,
            )
            return GateDecision(
                should_proceed=True,
                reason=f"No schema for phase '{phase_name}'",
                phase_output=PhaseOutput(phase_name=phase_name),
            )

        if not isinstance(output, dict):
            errors.append(
                f"Phase output must be a dict, got {type(output).__name__}"
            )
            return GateDecision(
                should_proceed=not self._strict,
                reason="Invalid output type",
                validation_errors=errors,
            )

        # Check required keys
        for key in schema.get("required_keys", []):
            if key not in output:
                errors.append(f"Missing required key: '{key}'")
            elif output[key] is None:
                errors.append(f"Required key '{key}' is None")

        # Check minimum findings if applicable
        if "min_findings" in schema and "findings" in output:
            findings = output.get("findings", [])
            if isinstance(findings, list):
                # Validate individual finding structure
                finding_errors = self.validate_findings_structure(findings)
                errors.extend(finding_errors)

        # Check minimum agents for multi-agent review
        if "min_agents" in schema and "agent_reports" in output:
            reports = output.get("agent_reports", {})
            min_count = schema["min_agents"]
            if isinstance(reports, dict) and len(reports) < min_count:
                errors.append(
                    f"Expected at least {min_count} agent report(s), "
                    f"got {len(reports)}"
                )
            # Validate report content
            if isinstance(reports, dict):
                report_errors = self.validate_agent_reports(reports)
                errors.extend(report_errors)

        if errors:
            should_proceed = not self._strict
            reason = (
                f"{len(errors)} validation error(s) in phase '{phase_name}'"
            )
            if should_proceed:
                logger.warning(
                    "Phase gate: %s (continuing in lenient mode)", reason
                )
            else:
                logger.error("Phase gate BLOCKED: %s", reason)
            for err in errors:
                logger.warning("  - %s", err)
        else:
            should_proceed = True
            reason = f"Phase '{phase_name}' passed validation"
            logger.info("Phase gate: %s", reason)

        return GateDecision(
            should_proceed=should_proceed,
            reason=reason,
            validation_errors=errors,
            phase_output=PhaseOutput(phase_name=phase_name),
        )

    def validate_findings_structure(self, findings: list[dict]) -> list[str]:
        """Check that each finding has the minimum required fields.

        Parameters
        ----------
        findings : list[dict]
            List of finding dictionaries to validate.

        Returns
        -------
        list[str]
            Validation error messages for malformed findings.
        """
        errors: list[str] = []
        required_fields = {"severity", "message"}
        for i, finding in enumerate(findings):
            if not isinstance(finding, dict):
                errors.append(f"Finding [{i}] is not a dict")
                continue
            missing = required_fields - set(finding.keys())
            if missing:
                errors.append(f"Finding [{i}] missing fields: {missing}")
        return errors

    def validate_agent_reports(self, reports: dict[str, str]) -> list[str]:
        """Check that agent reports are non-empty and meaningful.

        Parameters
        ----------
        reports : dict[str, str]
            Agent reports keyed by agent name.

        Returns
        -------
        list[str]
            Validation error messages for empty or too-short reports.
        """
        errors: list[str] = []
        for agent_name, report in reports.items():
            if not report or (
                isinstance(report, str) and len(report.strip()) < 10
            ):
                errors.append(
                    f"Agent report '{agent_name}' is empty or too short"
                )
        return errors
