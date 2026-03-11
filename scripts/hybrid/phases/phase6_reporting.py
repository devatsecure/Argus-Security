"""
Phase 6: Report Generation.

Covers:
    Phase 6.5 -- Responsible disclosure report generation (optional)
    v2.0 vulnerability enrichment pipeline (EPSS, fix versions, VEX, dedup)
    Result assembly, severity filtering, and output saving.

The main entry point ``run_phase6_reporting`` orchestrates all sub-steps
and returns the final ``HybridScanResult``.
"""

import logging
import os
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from hybrid.models import HybridFinding, HybridScanResult

logger = logging.getLogger(__name__)


def run_phase6_reporting(
    *,
    all_findings: list[HybridFinding],
    target_path: str,
    analyzer: Any,
    output_dir: Optional[str],
    severity_filter: Optional[list[str]],
    overall_start: float,
    phase_timings: dict[str, float],
    total_cost: float,
    policy_gate_result: Optional[dict],
    vulnerability_chains: Optional[dict],
) -> HybridScanResult:
    """Execute Phase 6 -- report generation and result assembly.

    Args:
        all_findings: Findings from all previous phases.
        target_path: Filesystem path being scanned.
        analyzer: ``HybridSecurityAnalyzer`` instance.
        output_dir: Optional output directory.
        severity_filter: Optional list of severity levels to include.
        overall_start: Epoch time when analysis began (for duration calc).
        phase_timings: Accumulated phase timings dict (mutated in-place).
        total_cost: Running total of API costs.
        policy_gate_result: Result from Phase 5 policy gate (or None).
        vulnerability_chains: Result from Phase 5.5 chaining (or None).

    Returns:
        Fully assembled ``HybridScanResult``.
    """
    # --- Phase 6.5: Responsible Disclosure Report Generation ---
    enable_disclosure = os.environ.get("ENABLE_DISCLOSURE_REPORT", "false").lower() == "true"

    if enable_disclosure and all_findings:
        logger.info("")
        logger.info("-" * 80)
        logger.info("Phase 6.5: Responsible Disclosure Report Generation")
        logger.info("-" * 80)

        phase65_start = time.time()

        try:
            _generate_disclosure_report(
                all_findings=all_findings,
                config=analyzer.config,
                output_dir=output_dir,
            )
        except ImportError:
            logger.warning("   Disclosure generator not available")
        except Exception as e:
            logger.error("   Disclosure report generation failed: %s", e)
            logger.info("   Continuing without disclosure reports...")

        phase_timings["phase6.5_disclosure"] = time.time() - phase65_start
        logger.info("   Phase 6.5 duration: %.1fs", phase_timings["phase6.5_disclosure"])

    # --- v2.0: Vulnerability Enrichment Pipeline ---
    all_findings = analyzer._enrich_findings(all_findings, target_path)

    # --- Calculate statistics ---
    overall_duration = time.time() - overall_start

    findings_by_severity = analyzer._count_by_severity(all_findings)
    findings_by_source = analyzer._count_by_source(all_findings)

    # --- Apply severity filter ---
    if severity_filter:
        all_findings = [f for f in all_findings if f.severity.lower() in [s.lower() for s in severity_filter]]

    # --- Assemble result ---
    result = HybridScanResult(
        target_path=target_path,
        scan_timestamp=datetime.now().isoformat(),
        total_findings=len(all_findings),
        findings_by_severity=findings_by_severity,
        findings_by_source=findings_by_source,
        findings=all_findings,
        scan_duration_seconds=overall_duration,
        cost_usd=total_cost,
        phase_timings=phase_timings,
        tools_used=analyzer._get_enabled_tools(),
        llm_enrichment_enabled=analyzer.enable_ai_enrichment,
    )

    if vulnerability_chains:
        result.__dict__["vulnerability_chains"] = vulnerability_chains

    # --- Save results ---
    if output_dir:
        analyzer._save_results(result, output_dir)

    # --- Print summary ---
    analyzer._print_summary(result)

    return result


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _generate_disclosure_report(
    *,
    all_findings: list[HybridFinding],
    config: dict,
    output_dir: Optional[str],
) -> None:
    """Generate responsible disclosure reports.

    Raises:
        ImportError: If ``disclosure_generator`` is not available.
    """
    from disclosure_generator import DisclosureGenerator

    repo_url = os.environ.get("DISCLOSURE_REPO_URL", config.get("repo_url", ""))
    reporter_name = os.environ.get("DISCLOSURE_REPORTER", "Security Researcher")

    generator = DisclosureGenerator(repo_url=repo_url)

    findings_dict = [asdict(f) for f in all_findings]

    disclosure_output_dir = None
    if output_dir:
        disclosure_output_dir = str(Path(output_dir) / "disclosure")

    disclosure_report = generator.generate(
        findings=findings_dict,
        output_dir=disclosure_output_dir,
        reporter_name=reporter_name,
    )

    logger.info("   Disclosure reports generated")
    logger.info("      High/Critical findings: %d", len(disclosure_report.high_findings))
    logger.info("      Dependency CVEs: %d", len(disclosure_report.dependency_findings))
    logger.info("      Private report: DISCLOSURE_PRIVATE.md")
    logger.info("      Public-safe report: ISSUE_PUBLIC_SAFE.md")

    if disclosure_report.has_security_policy:
        logger.info("   Repository has SECURITY.md - use private reporting")
    elif disclosure_report.has_discussions:
        logger.info("   Repository has Discussions - request security contact there")

    create_discussion = os.environ.get("DISCLOSURE_CREATE_DISCUSSION", "false").lower() == "true"
    if create_discussion and disclosure_report.has_discussions:
        discussion_url = generator.create_github_discussion()
        if discussion_url:
            logger.info("   Created security contact discussion: %s", discussion_url)
