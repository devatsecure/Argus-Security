"""
Phase 4: Sandbox Validation.

Validates exploitable findings in a Docker-based sandbox environment.
Only high-severity findings with high CVSS scores or known exploitability
are candidates for sandbox validation.

Note: Automatic PoC exploit generation is not yet implemented. The
infrastructure is in place but findings are currently marked as
*not validated* (accurate status).
"""

import logging
import time
from typing import Any

from hybrid.models import HybridFinding

logger = logging.getLogger(__name__)


def run_phase4_sandbox(
    *,
    all_findings: list[HybridFinding],
    target_path: str,
    analyzer: Any,
) -> tuple[list[HybridFinding], float | None]:
    """Execute Phase 4 -- Docker sandbox validation.

    Args:
        all_findings: Findings from Phases 1-3.
        target_path: Filesystem path being scanned.
        analyzer: ``HybridSecurityAnalyzer`` instance.

    Returns:
        A tuple of ``(validated_findings, duration_seconds | None)``.
        *duration_seconds* is ``None`` if the phase was skipped.
    """
    if not (analyzer.enable_sandbox and analyzer.sandbox_validator and all_findings):
        if analyzer.enable_sandbox and not all_findings:
            logger.info("   Skipping Phase 4: No findings to validate")
        elif analyzer.enable_sandbox and not analyzer.sandbox_validator:
            logger.info("   Skipping Phase 4: Sandbox validator not initialized")
        return all_findings, None

    logger.info("")
    logger.info("-" * 80)
    logger.info("Phase 4: Sandbox Validation (Docker)")
    logger.info("-" * 80)

    phase4_start = time.time()

    try:
        validated_findings = _run_sandbox_validation(
            findings=all_findings,
            target_path=target_path,
            sandbox_validator=analyzer.sandbox_validator,
        )
        all_findings = validated_findings
        logger.info("   Phase 4 checked %d findings (validation not yet implemented)", len(all_findings))
    except Exception as e:
        logger.error("   Sandbox validation failed: %s", e)
        logger.info("   Continuing with unvalidated findings...")

    duration = time.time() - phase4_start
    logger.info("   Phase 4 duration: %.1fs", duration)
    return all_findings, duration


# ------------------------------------------------------------------
# Core sandbox logic (extracted from HybridSecurityAnalyzer._run_sandbox_validation)
# ------------------------------------------------------------------

def _run_sandbox_validation(
    *,
    findings: list[HybridFinding],
    target_path: str,
    sandbox_validator: Any,
) -> list[HybridFinding]:
    """Validate exploitable findings in Docker sandbox.

    Only validates findings that are critical/high severity AND have
    trivial/moderate exploitability or CVSS >= 7.0.

    Args:
        findings: Findings to validate.
        target_path: Repository path being analyzed.
        sandbox_validator: ``SandboxValidator`` instance.

    Returns:
        Findings with ``sandbox_validated`` flag updated.
    """
    if not sandbox_validator:
        logger.warning("Sandbox validator not available")
        return findings

    validated_findings: list[HybridFinding] = []
    validation_count = 0

    for finding in findings:
        should_validate = finding.severity in ["critical", "high"] and (
            finding.exploitability in ["trivial", "moderate"]
            or (finding.cvss_score and finding.cvss_score >= 7.0)
        )

        if not should_validate:
            validated_findings.append(finding)
            continue

        try:
            logger.info("   Checking: %s...", finding.finding_id)
            validation_count += 1

            # TODO: Implement automatic PoC exploit generation
            # Current limitation: Sandbox validation requires:
            # 1. PoC exploit code generation (not yet implemented)
            # 2. Target environment setup
            # 3. Safe execution in Docker
            #
            # The sandbox_validator infrastructure exists and works,
            # but automatic exploit generation is not yet implemented.
            # For now, mark findings as NOT validated (accurate status)

            finding.sandbox_validated = False
            validated_findings.append(finding)

        except Exception as e:
            logger.warning("   Validation failed for %s: %s", finding.finding_id, e)
            finding.sandbox_validated = False
            validated_findings.append(finding)

    if validation_count > 0:
        logger.info("   Checked %d high-risk findings (validation not yet implemented)", validation_count)
    else:
        logger.info("   No findings required sandbox validation")

    return validated_findings
