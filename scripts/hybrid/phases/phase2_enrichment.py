"""
Phase 2: AI Enrichment.

Covers the AI enrichment sub-phases:
    Phase 2   -- Claude/OpenAI enrichment (CWE mapping, exploitability, etc.)
    Phase 2.3 -- IRIS semantic analysis (arXiv 2405.17238)
    Phase 2.5 -- Automated remediation (AI-generated fix suggestions)
    Phase 2.6 -- Spontaneous discovery (beyond scanner rules)

Each sub-phase is gated on the corresponding ``enable_*`` flag and the
availability of its supporting component.
"""

import glob as glob_module
import logging
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from hybrid.models import HybridFinding

logger = logging.getLogger(__name__)


def run_phase2_enrichment(
    *,
    all_findings: list[HybridFinding],
    target_path: str,
    analyzer: Any,
) -> tuple[list[HybridFinding], dict[str, float]]:
    """Execute Phase 2 -- AI enrichment (all sub-phases).

    Args:
        all_findings: Findings from Phase 1.
        target_path: Filesystem path being scanned.
        analyzer: ``HybridSecurityAnalyzer`` instance.

    Returns:
        A tuple of ``(enriched_findings, phase_timings_dict)``.
    """
    phase_timings: dict[str, float] = {}

    # --- Phase 2: Core AI Enrichment ---
    if analyzer.enable_ai_enrichment and all_findings:
        logger.info("")
        logger.info("-" * 80)
        logger.info("Phase 2: AI Enrichment (Claude/OpenAI)")
        logger.info("-" * 80)

        phase2_start = time.time()
        try:
            enriched_findings = analyzer._enrich_with_ai(all_findings)
            all_findings = enriched_findings
            logger.info("   AI enrichment complete")
        except Exception as e:
            logger.error("   AI enrichment failed: %s", e)
            logger.info("   Continuing with unenriched findings...")

        phase_timings["phase2_ai_enrichment"] = time.time() - phase2_start
        logger.info("   Phase 2 duration: %.1fs", phase_timings["phase2_ai_enrichment"])
    elif analyzer.enable_ai_enrichment and not all_findings:
        logger.info("   Skipping Phase 2: No findings to enrich")

    # --- Phase 2.3: IRIS Semantic Analysis ---
    if analyzer.enable_iris and all_findings and analyzer.iris_analyzer:
        logger.info("")
        logger.info("-" * 80)
        logger.info("Phase 2.3: IRIS Semantic Analysis (Research-Proven Deep Analysis)")
        logger.info("-" * 80)

        phase2_3_start = time.time()
        try:
            iris_enriched = analyzer._enrich_with_iris(all_findings, target_path=target_path)
            all_findings = iris_enriched

            iris_stats = analyzer.iris_analyzer.get_statistics()
            logger.info("   IRIS analysis complete")
            logger.info("      Findings analyzed: %d", iris_stats["total_findings_analyzed"])
            logger.info("      True positives: %d", iris_stats["true_positives"])
            logger.info("      False positives: %d", iris_stats["false_positives"])
            logger.info("      Cost: $%s", iris_stats["total_cost_usd"])
        except Exception as e:
            logger.error("   IRIS semantic analysis failed: %s", e)
            logger.info("   Continuing with basic AI enrichment...")

        phase_timings["phase2_3_iris"] = time.time() - phase2_3_start
        logger.info("   Phase 2.3 duration: %.1fs", phase_timings["phase2_3_iris"])
    elif analyzer.enable_iris and not all_findings:
        logger.info("   Skipping Phase 2.3: No findings to analyze with IRIS")

    # --- Phase 2.5: Automated Remediation ---
    if analyzer.enable_remediation and all_findings and analyzer.remediation_engine:
        logger.info("")
        logger.info("-" * 80)
        logger.info("Phase 2.5: Automated Remediation (AI-Generated Fixes)")
        logger.info("-" * 80)

        phase2_5_start = time.time()
        try:
            remediated_findings = analyzer._run_remediation(all_findings)
            all_findings = remediated_findings
            logger.info("   Remediation suggestions generated")
        except Exception as e:
            logger.error("   Remediation generation failed: %s", e)
            logger.info("   Continuing without remediation suggestions...")

        phase_timings["phase2_5_remediation"] = time.time() - phase2_5_start
        logger.info("   Phase 2.5 duration: %.1fs", phase_timings["phase2_5_remediation"])
    elif analyzer.enable_remediation and not all_findings:
        logger.info("   Skipping Phase 2.5: No findings to remediate")

    # --- Phase 2.6: Spontaneous Discovery ---
    if analyzer.enable_spontaneous_discovery and analyzer.spontaneous_discovery:
        logger.info("")
        logger.info("-" * 80)
        logger.info("Phase 2.6: Spontaneous Discovery (Beyond Scanner Rules)")
        logger.info("-" * 80)

        phase2_6_start = time.time()
        try:
            all_findings = _run_spontaneous_discovery(
                all_findings=all_findings,
                target_path=target_path,
                spontaneous_discovery=analyzer.spontaneous_discovery,
                config=analyzer.config,
            )
        except Exception as e:
            logger.error("   Spontaneous discovery failed: %s", e)
            logger.info("   Continuing with findings from Phase 1 & 2")

        phase_timings["phase2_6_spontaneous_discovery"] = time.time() - phase2_6_start
        logger.info("   Phase 2.6 duration: %.1fs", phase_timings["phase2_6_spontaneous_discovery"])
    elif analyzer.enable_spontaneous_discovery and not analyzer.spontaneous_discovery:
        logger.info("   Skipping Phase 2.6: Spontaneous discovery not initialized")

    return all_findings, phase_timings


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _run_spontaneous_discovery(
    *,
    all_findings: list[HybridFinding],
    target_path: str,
    spontaneous_discovery: Any,
    config: dict,
) -> list[HybridFinding]:
    """Run spontaneous discovery sub-phase and append new findings."""
    # Gather code files
    code_files: list[str] = []
    for ext in ["**/*.py", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.java", "**/*.go"]:
        code_files.extend(glob_module.glob(str(Path(target_path) / ext), recursive=True))

    architecture = config.get("architecture", "backend-api")

    logger.info("   Analyzing %d code files for hidden issues...", len(code_files))
    discoveries = spontaneous_discovery.discover(
        files=code_files[:100],
        existing_findings=[asdict(f) for f in all_findings],
        architecture=architecture,
    )

    for discovery in discoveries:
        hybrid_finding = HybridFinding(
            finding_id=f"spontaneous-{len(all_findings) + 1}",
            source_tool="spontaneous_discovery",
            severity=discovery.severity,
            category=discovery.category,
            title=discovery.title,
            description=discovery.description,
            file_path=discovery.evidence[0] if discovery.evidence else str(target_path),
            line_number=None,
            cwe_id=discovery.cwe_id,
            cve_id=None,
            cvss_score=None,
            exploitability=None,
            recommendation=discovery.remediation,
            references=[],
            confidence=discovery.confidence,
            llm_enriched=True,
            sandbox_validated=False,
        )
        all_findings.append(hybrid_finding)

    logger.info("   Spontaneous discovery complete: %d new issues found", len(discoveries))
    logger.info("   Total findings after discovery: %d", len(all_findings))

    return all_findings
