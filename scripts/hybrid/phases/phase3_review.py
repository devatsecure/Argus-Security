"""
Phase 3: Multi-Agent Persona Review.

Runs specialized AI personas (SecretHunter, ArchitectureReviewer,
ExploitAssessor, FalsePositiveFilter, ThreatModeler) over the
enriched findings to filter false positives and enhance confirmed ones.

Optionally uses collaborative reasoning (multi-round discussion) for
higher confidence verdicts at additional API cost.
"""

import logging
import time
from typing import Any

from hybrid.models import HybridFinding

logger = logging.getLogger(__name__)


def run_phase3_review(
    *,
    all_findings: list[HybridFinding],
    target_path: str,
    analyzer: Any,
) -> tuple[list[HybridFinding], float | None]:
    """Execute Phase 3 -- multi-agent persona review.

    Args:
        all_findings: Findings from Phases 1-2.
        target_path: Filesystem path being scanned.
        analyzer: ``HybridSecurityAnalyzer`` instance.

    Returns:
        A tuple of ``(reviewed_findings, duration_seconds | None)``.
        *duration_seconds* is ``None`` if the phase was skipped.
    """
    if not (analyzer.enable_multi_agent and analyzer.agent_personas and all_findings):
        # Log skip reason
        if analyzer.enable_multi_agent and not all_findings:
            logger.info("   Skipping Phase 3: No findings to review")
        elif analyzer.enable_multi_agent and not analyzer.agent_personas:
            logger.info("   Skipping Phase 3: Multi-agent personas not initialized")
        return all_findings, None

    logger.info("")
    logger.info("-" * 80)
    logger.info("Phase 3: Multi-Agent Persona Review")
    logger.info("-" * 80)

    phase3_start = time.time()

    try:
        enriched_findings = _run_argus_review(
            findings=all_findings,
            target_path=target_path,
            agent_personas=analyzer.agent_personas,
            ai_client=analyzer.ai_client,
            collaborative_reasoning=analyzer.collaborative_reasoning,
            enable_collaborative_reasoning=analyzer.enable_collaborative_reasoning,
            skills_knowledge=getattr(analyzer, "skills_knowledge", None),
        )
        all_findings = enriched_findings
        logger.info("   Multi-agent persona review complete: %d findings reviewed", len(all_findings))
    except Exception as e:
        logger.error("   Multi-agent persona review failed: %s", e)
        logger.info("   Continuing with findings from Phase 1 & 2")

    duration = time.time() - phase3_start
    logger.info("   Phase 3 duration: %.1fs", duration)
    return all_findings, duration


# ------------------------------------------------------------------
# Core review logic (extracted from HybridSecurityAnalyzer._run_argus_review)
# ------------------------------------------------------------------


def _run_argus_review(
    *,
    findings: list[HybridFinding],
    target_path: str,
    agent_personas: Any,
    ai_client: Any,
    collaborative_reasoning: Any | None,
    enable_collaborative_reasoning: bool,
    skills_knowledge: Any | None = None,
) -> list[HybridFinding]:
    """Run multi-agent persona review on findings.

    This integrates multi-agent personas to:
    1. SecretHunter -- validates secret/credential findings
    2. ArchitectureReviewer -- assesses architectural security flaws
    3. ExploitAssessor -- evaluates real-world exploitability
    4. FalsePositiveFilter -- eliminates test code and false positives
    5. ThreatModeler -- maps attack chains and escalation paths

    Args:
        findings: List of findings to review.
        target_path: Repository path being analyzed.
        agent_personas: The ``agent_personas`` module reference.
        ai_client: AI client for LLM calls.
        collaborative_reasoning: Optional collaborative reasoning engine.
        enable_collaborative_reasoning: Whether collaborative mode is on.

    Returns:
        Enhanced findings with agent analysis metadata (false positives removed).
    """
    if not agent_personas:
        logger.warning("Agent personas not initialized, skipping multi-agent review")
        return findings

    enhanced_findings: list[HybridFinding] = []
    logger.info("   Running multi-agent analysis on %d findings...", len(findings))

    for finding in findings:
        finding_dict = {
            "id": finding.finding_id,
            "source_tool": finding.source_tool,
            "severity": finding.severity,
            "category": finding.category,
            "title": finding.title,
            "description": finding.description,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "cwe_id": finding.cwe_id,
            "cve_id": finding.cve_id,
            "cvss_score": finding.cvss_score,
        }

        if enable_collaborative_reasoning and collaborative_reasoning:
            logger.debug("   Running collaborative reasoning on finding %s", finding.finding_id)
            verdict = collaborative_reasoning.analyze_collaboratively(
                finding=finding_dict,
                mode="discussion",
            )

            if verdict.final_decision == "false_positive":
                logger.debug("      FP: %s - %s...", finding.finding_id, verdict.reasoning[:80])
                continue
            elif verdict.final_decision == "confirmed":
                finding.confidence = verdict.confidence
                finding.description = (
                    f"[Multi-Agent Consensus: {verdict.confidence:.0%} confidence] "
                    f"{finding.description}\n\nReasoning: {verdict.reasoning}"
                )
                enhanced_findings.append(finding)
            else:  # needs_review
                finding.confidence = verdict.confidence
                finding.description = (
                    f"[Needs Review: {verdict.confidence:.0%} confidence] "
                    f"{finding.description}\n\nReasoning: {verdict.reasoning}"
                )
                enhanced_findings.append(finding)

        else:
            agent = agent_personas.select_agent_for_finding(finding_dict, ai_client)
            if skills_knowledge:
                agent.skills_knowledge = skills_knowledge
            analysis = agent.analyze(finding_dict)

            if analysis.verdict == "false_positive":
                logger.debug("      FP: %s - %s...", finding.finding_id, analysis.reasoning[:80])
                continue
            elif analysis.verdict == "confirmed":
                finding.confidence = analysis.confidence
                finding.description = (
                    f"[Agent: {analysis.agent_name}, {analysis.confidence:.0%} confidence] "
                    f"{finding.description}\n\n"
                    f"Reasoning: {analysis.reasoning}\n"
                    f"Recommendations: {', '.join(analysis.recommendations)}"
                )
                enhanced_findings.append(finding)
            else:  # needs_review
                finding.confidence = analysis.confidence
                finding.description = (
                    f"[Needs Review by {analysis.agent_name}: {analysis.confidence:.0%} confidence] "
                    f"{finding.description}\n\n"
                    f"Reasoning: {analysis.reasoning}"
                )
                enhanced_findings.append(finding)

    reduction_pct = ((len(findings) - len(enhanced_findings)) / len(findings) * 100) if findings else 0
    logger.info(
        "   Multi-agent review complete: %d/%d findings validated (%.1f%% reduction)",
        len(enhanced_findings),
        len(findings),
        reduction_pct,
    )

    return enhanced_findings
