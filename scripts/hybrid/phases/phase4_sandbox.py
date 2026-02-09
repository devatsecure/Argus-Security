"""
Phase 4: Sandbox Validation.

Validates exploitable findings in a Docker-based sandbox environment.
Only high-severity findings with high CVSS scores or known exploitability
are candidates for sandbox validation.

When ``enable_proof_by_exploitation`` is True and an LLM client is available,
findings are sent through the ExploitGenerator -> SandboxValidator pipeline
(``ProofByExploitation``).  Otherwise the phase falls back to marking
candidates as *not validated*.
"""

import logging
import time
from typing import Any

from hybrid.models import HybridFinding

logger = logging.getLogger(__name__)

# Try to import proof-by-exploitation classes.  These live in
# sandbox_validator.py which may not be importable if Docker or other
# dependencies are missing.
try:
    from sandbox_validator import ExploitGenerator, ProofByExploitation

    _PROOF_BY_EXPLOITATION_AVAILABLE = True
except ImportError:
    _PROOF_BY_EXPLOITATION_AVAILABLE = False


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
            analyzer=analyzer,
        )
        all_findings = validated_findings

        sandbox_tested = sum(1 for f in all_findings if f.sandbox_validated)
        logger.info(
            "   Phase 4 completed: %d/%d findings sandbox-validated",
            sandbox_tested,
            len(all_findings),
        )
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
    analyzer: Any = None,
) -> list[HybridFinding]:
    """Validate exploitable findings in Docker sandbox.

    Only validates findings that are critical/high severity AND have
    trivial/moderate exploitability or CVSS >= 7.0.

    When proof-by-exploitation is enabled (``enable_proof_by_exploitation``
    in ``analyzer.config``) and an LLM client is available, the function
    uses ``ExploitGenerator`` to create targeted PoC code and then
    validates it inside a Docker sandbox via ``ProofByExploitation``.

    Args:
        findings: Findings to validate.
        target_path: Repository path being analyzed.
        sandbox_validator: ``SandboxValidator`` instance.
        analyzer: ``HybridSecurityAnalyzer`` instance (optional).
            Provides ``ai_client`` (LLM) and ``config`` dict.

    Returns:
        Findings with ``sandbox_validated`` flag updated.
    """
    if not sandbox_validator:
        logger.warning("Sandbox validator not available")
        return findings

    # Determine whether proof-by-exploitation is enabled and possible.
    config = getattr(analyzer, "config", {}) or {}
    proof_enabled = config.get("enable_proof_by_exploitation", False)
    ai_client = getattr(analyzer, "ai_client", None)
    max_exploits = config.get("max_exploit_attempts", 10)

    use_proof = proof_enabled and _PROOF_BY_EXPLOITATION_AVAILABLE and ai_client is not None

    if proof_enabled and not _PROOF_BY_EXPLOITATION_AVAILABLE:
        logger.warning(
            "   Proof-by-exploitation requested but sandbox_validator imports unavailable; "
            "falling back to marking findings as unvalidated"
        )
    elif proof_enabled and ai_client is None:
        logger.warning(
            "   Proof-by-exploitation requested but no LLM client available; "
            "falling back to marking findings as unvalidated"
        )

    # ----------------------------------------------------------------
    # Partition findings: candidates vs. skipped
    # ----------------------------------------------------------------
    candidates: list[HybridFinding] = []
    validated_findings: list[HybridFinding] = []

    for finding in findings:
        should_validate = finding.severity in ["critical", "high"] and (
            finding.exploitability in ["trivial", "moderate"] or (finding.cvss_score and finding.cvss_score >= 7.0)
        )

        if should_validate:
            candidates.append(finding)
        else:
            validated_findings.append(finding)

    if not candidates:
        logger.info("   No findings met the severity/exploitability threshold for sandbox validation")
        return findings  # nothing to do, return original list unchanged

    logger.info(
        "   %d finding(s) meet sandbox validation criteria (critical/high, CVSS >= 7.0)",
        len(candidates),
    )

    # ----------------------------------------------------------------
    # Path A: Full proof-by-exploitation (LLM exploit gen + sandbox)
    # ----------------------------------------------------------------
    if use_proof:
        validated_findings = _prove_candidates(
            candidates=candidates,
            already_validated=validated_findings,
            sandbox_validator=sandbox_validator,
            ai_client=ai_client,
            target_path=target_path,
            max_exploits=max_exploits,
        )
    else:
        # ----------------------------------------------------------------
        # Path B: No LLM / proof disabled -- mark as not validated
        # ----------------------------------------------------------------
        for finding in candidates:
            finding.sandbox_validated = False
            validated_findings.append(finding)

        if not proof_enabled:
            logger.info(
                "   Proof-by-exploitation is disabled (enable_proof_by_exploitation=False); "
                "%d candidate(s) marked as unvalidated",
                len(candidates),
            )
        else:
            logger.info(
                "   %d candidate(s) marked as unvalidated (prerequisites not met)",
                len(candidates),
            )

    return validated_findings


def _prove_candidates(
    *,
    candidates: list[HybridFinding],
    already_validated: list[HybridFinding],
    sandbox_validator: Any,
    ai_client: Any,
    target_path: str,
    max_exploits: int,
) -> list[HybridFinding]:
    """Run ExploitGenerator + SandboxValidator for candidate findings.

    Converts ``HybridFinding`` objects to dicts consumable by
    ``ProofByExploitation.prove_findings``, then maps the enriched
    results back onto the original finding objects.

    Args:
        candidates: Findings that meet severity/exploitability threshold.
        already_validated: Findings that did not meet the threshold.
        sandbox_validator: Initialized ``SandboxValidator``.
        ai_client: LLM client with a ``generate(prompt)`` method.
        target_path: Path to the project being scanned.
        max_exploits: Cap on how many PoCs to generate.

    Returns:
        Combined list of all findings with sandbox_validated updated.
    """
    validated_findings = list(already_validated)

    # Build the LLM call function expected by ExploitGenerator:
    #   callable(prompt: str) -> str
    def llm_call_fn(prompt: str) -> str:
        return ai_client.generate(prompt)

    try:
        generator = ExploitGenerator(llm_call_fn=llm_call_fn)
        prover = ProofByExploitation(
            validator=sandbox_validator,
            generator=generator,
        )
    except Exception as e:
        logger.error("   Failed to initialize ProofByExploitation: %s", e)
        for finding in candidates:
            finding.sandbox_validated = False
            validated_findings.append(finding)
        return validated_findings

    # Convert HybridFinding -> dict for ProofByExploitation
    finding_dicts: list[dict] = []
    finding_map: dict[str, HybridFinding] = {}

    for finding in candidates:
        fdict = {
            "finding_id": finding.finding_id,
            "severity": finding.severity,
            "message": finding.title,
            "description": finding.description,
            "file": finding.file_path,
            "line": finding.line_number or 0,
            "cwe": finding.cwe_id or "",
        }
        finding_dicts.append(fdict)
        finding_map[finding.finding_id] = finding

    logger.info(
        "   Running proof-by-exploitation on %d candidate(s) (max %d PoCs)...",
        len(finding_dicts),
        max_exploits,
    )

    try:
        enriched_dicts = prover.prove_findings(
            findings=finding_dicts,
            source_files=None,  # source files not pre-loaded at this stage
            max_exploits=max_exploits,
        )
    except Exception as e:
        logger.error("   ProofByExploitation.prove_findings failed: %s", e)
        for finding in candidates:
            finding.sandbox_validated = False
            validated_findings.append(finding)
        return validated_findings

    # Map enriched results back to HybridFinding objects
    exploitable_count = 0
    tested_count = 0

    for edict in enriched_dicts:
        fid = edict.get("finding_id", "")
        original = finding_map.get(fid)

        if original is None:
            # Should not happen but guard defensively
            logger.warning("   Could not map enriched finding back: %s", fid)
            continue

        exploitability = edict.get("exploitability", "not_tested")

        if exploitability == "exploitable":
            original.sandbox_validated = True
            exploitable_count += 1
            tested_count += 1
            logger.info("   EXPLOITABLE: %s (sandbox confirmed)", original.finding_id)
        elif exploitability in ("partial",):
            original.sandbox_validated = True
            tested_count += 1
            logger.info("   PARTIAL: %s (partially exploitable)", original.finding_id)
        elif exploitability in ("not_exploitable",):
            original.sandbox_validated = False
            tested_count += 1
            logger.info("   NOT EXPLOITABLE: %s", original.finding_id)
        elif exploitability in ("generation_failed", "not_tested"):
            original.sandbox_validated = False
            logger.info("   SKIPPED: %s (%s)", original.finding_id, exploitability)
        else:
            # sandbox_error, timeout, error, etc.
            original.sandbox_validated = False
            tested_count += 1
            logger.info("   %s: %s", exploitability.upper(), original.finding_id)

        validated_findings.append(original)

    logger.info(
        "   Proof-by-exploitation complete: %d tested, %d confirmed exploitable",
        tested_count,
        exploitable_count,
    )

    return validated_findings
