"""
Phase 5: Policy Gate Evaluation.

Evaluates findings against Rego/OPA policies and optionally runs
vulnerability chaining analysis (Phase 5.5).

Sub-phases:
    Phase 5   -- Rego policy gate evaluation (PR/release gates)
    Phase 5.5 -- Vulnerability chaining analysis (attack chain discovery)
"""

import logging
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from hybrid.models import HybridFinding

logger = logging.getLogger(__name__)


def run_phase5_policy(
    *,
    all_findings: list[HybridFinding],
    analyzer: Any,
    output_dir: Optional[str] = None,
) -> tuple[Optional[dict], Optional[dict], dict[str, float]]:
    """Execute Phase 5 -- policy gate evaluation and vulnerability chaining.

    Args:
        all_findings: Findings from Phases 1-4.
        analyzer: ``HybridSecurityAnalyzer`` instance.
        output_dir: Optional output directory for chain reports.

    Returns:
        A tuple of ``(policy_gate_result, vulnerability_chains, phase_timings)``.
    """
    phase_timings: dict[str, float] = {}
    policy_gate_result = None
    vulnerability_chains = None

    # --- Phase 5: Policy Gate Evaluation ---
    if all_findings:
        logger.info("")
        logger.info("-" * 80)
        logger.info("Phase 5: Policy Gate Evaluation")
        logger.info("-" * 80)

        phase5_start = time.time()

        try:
            policy_gate_result = _evaluate_policy_gate(
                all_findings=all_findings,
                config=analyzer.config,
            )
        except ImportError:
            logger.warning("   PolicyGate not available - skipping policy evaluation")
        except Exception as e:
            logger.error("   Policy gate evaluation failed: %s", e)
            logger.info("   Continuing without policy enforcement...")

        phase_timings["phase5_policy_gate"] = time.time() - phase5_start
        logger.info("   Phase 5 duration: %.1fs", phase_timings["phase5_policy_gate"])
    else:
        logger.info("   Skipping Phase 5: No findings to evaluate")

    # --- Phase 5.5: Vulnerability Chaining Analysis ---
    enable_chaining = os.environ.get("ENABLE_VULNERABILITY_CHAINING", "false").lower() == "true"

    if enable_chaining and all_findings:
        logger.info("-" * 80)
        logger.info("Phase 5.5: Vulnerability Chaining Analysis")
        logger.info("-" * 80)

        phase55_start = time.time()

        try:
            vulnerability_chains = _run_vulnerability_chaining(
                all_findings=all_findings,
                output_dir=output_dir,
            )
        except ImportError:
            logger.warning("   Vulnerability chaining engine not available")
            logger.info("   Install networkx: pip install networkx")
        except Exception as e:
            logger.error("   Vulnerability chaining failed: %s", e)
            logger.info("   Continuing without chain analysis...")

        phase_timings["phase5.5_vulnerability_chaining"] = time.time() - phase55_start
        logger.info("   Phase 5.5 duration: %.1fs", phase_timings["phase5.5_vulnerability_chaining"])

    return policy_gate_result, vulnerability_chains, phase_timings


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _evaluate_policy_gate(
    *,
    all_findings: list[HybridFinding],
    config: dict,
) -> Optional[dict]:
    """Evaluate findings against Rego/OPA policy gate.

    Raises:
        ImportError: If ``gate`` module is not available.
    """
    from gate import PolicyGate

    stage = config.get("policy_stage", "pr")
    policy_dir = config.get("policy_dir", "policy/rego")

    policy_gate = PolicyGate(policy_dir=policy_dir)

    findings_dict = []
    for finding in all_findings:
        finding_dict = {
            "id": finding.finding_id,
            "source_tool": finding.source_tool,
            "severity": finding.severity,
            "category": finding.category,
            "title": finding.title,
            "description": finding.description,
            "path": finding.file_path,
            "line": finding.line_number,
            "cwe_id": finding.cwe_id,
            "cve_id": finding.cve_id,
            "cvss_score": finding.cvss_score,
            "exploitability": finding.exploitability,
            "confidence": finding.confidence,
        }
        findings_dict.append(finding_dict)

    logger.info("   Evaluating %d findings against %s policy...", len(findings_dict), stage)
    policy_gate_result = policy_gate.evaluate(
        stage=stage,
        findings=findings_dict,
        metadata=config.get("policy_metadata", {}),
    )

    decision = policy_gate_result.get("decision", "pass")
    blocks = policy_gate_result.get("blocks", [])
    warnings = policy_gate_result.get("warnings", [])
    reasons = policy_gate_result.get("reasons", [])

    if decision == "pass":
        logger.info("   Policy gate PASSED: %d findings evaluated", len(findings_dict))
        if warnings:
            logger.info("   %d warnings (non-blocking)", len(warnings))
    else:
        logger.warning("   Policy gate FAILED: %d blocking issues", len(blocks))
        for reason in reasons[:5]:
            logger.warning("      - %s", reason)

    return policy_gate_result


def _run_vulnerability_chaining(
    *,
    all_findings: list[HybridFinding],
    output_dir: Optional[str],
) -> dict:
    """Run vulnerability chaining analysis.

    Raises:
        ImportError: If ``vulnerability_chaining_engine`` is not available.
    """
    from vulnerability_chaining_engine import VulnerabilityChainer

    findings_dict = [asdict(f) for f in all_findings]

    logger.info("   Analyzing attack chains...")
    chainer = VulnerabilityChainer(
        max_chain_length=int(os.environ.get("CHAIN_MAX_LENGTH", "4")),
        min_risk_threshold=float(os.environ.get("CHAIN_MIN_RISK", "5.0")),
    )

    vulnerability_chains = chainer.analyze(findings_dict)

    logger.info("   Found %d attack chains", vulnerability_chains["total_chains"])

    if vulnerability_chains["total_chains"] > 0:
        stats = vulnerability_chains["statistics"]
        logger.info("      Critical chains: %d", stats.get("critical_chains", 0))
        logger.info("      High-risk chains: %d", stats.get("high_chains", 0))
        logger.info("      Average chain length: %.1f", stats.get("avg_chain_length", 0))
        logger.info("      Maximum risk score: %.1f/10.0", stats.get("max_risk_score", 0))

        if output_dir:
            from chain_visualizer import ChainVisualizer

            visualizer = ChainVisualizer()
            chain_report_path = Path(output_dir) / "vulnerability-chains.md"
            chain_json_path = Path(output_dir) / "vulnerability-chains.json"

            visualizer.generate_markdown_report(vulnerability_chains, str(chain_report_path))
            visualizer.generate_json_summary(vulnerability_chains, str(chain_json_path))

            logger.info("   Chain report: %s", chain_report_path)
    else:
        logger.info("   No significant attack chains found")

    return vulnerability_chains
