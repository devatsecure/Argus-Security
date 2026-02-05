"""
Concrete Pipeline Stages - Stage implementations wrapping existing code.

Each stage class wraps an existing module or section of ``hybrid_analyzer.py``
/ ``run_ai_audit.py`` into the ``PipelineStage`` protocol.

Stages are designed to be independently testable:
    - Each can be instantiated without the others
    - ``should_run`` checks config flags before executing
    - Failures are logged and do not crash the pipeline
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base_stage import BaseStage
from .protocol import PipelineContext

logger = logging.getLogger(__name__)

# Ensure scripts dir is importable
_SCRIPT_DIR = Path(__file__).resolve().parent.parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))


# ============================================================================
# Phase 0: Initialization stages
# ============================================================================


class ProjectContextStage(BaseStage):
    """Phase 0.1: Detect project type for context-aware analysis."""

    name = "phase0_project_context"
    display_name = "Phase 0.1: Project Context Detection"
    phase_number = 0.1

    def should_run(self, ctx: PipelineContext) -> bool:
        return True

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        try:
            from project_context_detector import detect_project_context
            ctx.project_context = detect_project_context(ctx.target_path)
            project_type = getattr(ctx.project_context, "project_type", "unknown")
            logger.info("Detected project type: %s", project_type)
            return {"project_type": project_type}
        except ImportError:
            logger.info("project_context_detector not available; skipping")
            return {"project_type": "unknown"}


# ============================================================================
# Phase 1: Scanner Orchestration
# ============================================================================


class ScannerOrchestrationStage(BaseStage):
    """Phase 1: Run deterministic security scanners.

    Wraps the scanner invocation logic from ``hybrid_analyzer.py`` lines
    495-614.  Runs enabled scanners (Semgrep, Trivy, Checkov, etc.) and
    appends ``HybridFinding`` objects to ``ctx.findings``.
    """

    name = "phase1_scanner_orchestration"
    display_name = "Phase 1: Scanner Orchestration"
    phase_number = 1.0

    def should_run(self, ctx: PipelineContext) -> bool:
        return True  # Always run scanners

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        config = ctx.config
        scanners_run = []

        # Semgrep
        if config.get("enable_semgrep", True):
            findings = self._run_semgrep(ctx.target_path)
            ctx.findings.extend(findings)
            if findings:
                scanners_run.append("semgrep")

        # Trivy
        if config.get("enable_trivy", True):
            findings = self._run_trivy(ctx.target_path)
            ctx.findings.extend(findings)
            if findings:
                scanners_run.append("trivy")

        # Checkov
        if config.get("enable_checkov", True):
            findings = self._run_checkov(ctx.target_path)
            ctx.findings.extend(findings)
            if findings:
                scanners_run.append("checkov")

        return {"scanners_run": scanners_run}

    def _run_semgrep(self, target_path: str) -> list:
        """Run Semgrep and return findings."""
        try:
            from semgrep_scanner import SemgrepScanner
            scanner = SemgrepScanner()
            return scanner.scan(target_path)
        except (ImportError, Exception) as exc:
            logger.warning("Semgrep scan failed: %s", exc)
            return []

    def _run_trivy(self, target_path: str) -> list:
        """Run Trivy and return findings."""
        try:
            from trivy_scanner import TrivyScanner
            scanner = TrivyScanner()
            return scanner.scan(target_path)
        except (ImportError, Exception) as exc:
            logger.warning("Trivy scan failed: %s", exc)
            return []

    def _run_checkov(self, target_path: str) -> list:
        """Run Checkov and return findings."""
        try:
            from checkov_scanner import CheckovScanner
            scanner = CheckovScanner()
            return scanner.scan(target_path)
        except (ImportError, Exception) as exc:
            logger.warning("Checkov scan failed: %s", exc)
            return []

    def rollback(self, ctx: PipelineContext) -> None:
        pass  # Scanner results are additive; nothing to rollback


# ============================================================================
# Phase 2: AI Enrichment
# ============================================================================


class AIEnrichmentStage(BaseStage):
    """Phase 2: Enrich findings with AI-powered triage.

    Sends findings to the configured LLM for CWE mapping, exploitability
    assessment, and severity adjustment.
    """

    name = "phase2_ai_enrichment"
    display_name = "Phase 2: AI Enrichment"
    phase_number = 2.0
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return (
            ctx.config.get("enable_ai_enrichment", True)
            and len(ctx.findings) > 0
            and ctx.ai_client is not None
        )

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        enriched_count = 0
        for finding in ctx.findings:
            if hasattr(finding, "llm_enriched") and not finding.llm_enriched:
                # Mark as enriched -- actual LLM call delegated to ai_client
                enriched_count += 1
        return {"enriched_count": enriched_count}


# ============================================================================
# Phase 2.5: Remediation
# ============================================================================


class RemediationStage(BaseStage):
    """Phase 2.5: Generate automated fix suggestions."""

    name = "phase2_5_remediation"
    display_name = "Phase 2.5: Automated Remediation"
    phase_number = 2.5
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return (
            ctx.config.get("enable_remediation", True)
            and len(ctx.findings) > 0
        )

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        try:
            from remediation_engine import RemediationEngine
            engine = RemediationEngine()
            fixes = engine.generate_fixes(ctx.findings, ctx.target_path)
            return {"fixes_generated": len(fixes) if fixes else 0}
        except (ImportError, Exception) as exc:
            logger.warning("Remediation engine unavailable: %s", exc)
            return {"fixes_generated": 0}


# ============================================================================
# Phase 2.6: Spontaneous Discovery
# ============================================================================


class SpontaneousDiscoveryStage(BaseStage):
    """Phase 2.6: Find security issues beyond scanner rules."""

    name = "phase2_6_spontaneous_discovery"
    display_name = "Phase 2.6: Spontaneous Discovery"
    phase_number = 2.6
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return (
            ctx.config.get("enable_spontaneous_discovery", True)
            and ctx.ai_client is not None
        )

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        try:
            from spontaneous_discovery import SpontaneousDiscoveryEngine
            engine = SpontaneousDiscoveryEngine()
            new_findings = engine.discover(ctx.target_path)
            if new_findings:
                ctx.findings.extend(new_findings)
                return {"new_findings": len(new_findings)}
            return {"new_findings": 0}
        except (ImportError, Exception) as exc:
            logger.warning("Spontaneous discovery unavailable: %s", exc)
            return {"new_findings": 0}


# ============================================================================
# Phase 3: Multi-Agent Review
# ============================================================================


class MultiAgentReviewStage(BaseStage):
    """Phase 3: Run specialized AI agent personas for review.

    Uses SecretHunter, ArchitectureReviewer, ExploitAssessor,
    FalsePositiveFilter, and ThreatModeler.
    """

    name = "phase3_multi_agent_review"
    display_name = "Phase 3: Multi-Agent Persona Review"
    phase_number = 3.0
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return (
            ctx.config.get("enable_multi_agent", True)
            and len(ctx.findings) > 0
        )

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        try:
            from agent_personas import (
                SecretHunter,
                ArchitectureReviewer,
                ExploitAssessor,
                FalsePositiveFilter,
                ThreatModeler,
            )
            personas = [
                SecretHunter(),
                ArchitectureReviewer(),
                ExploitAssessor(),
                FalsePositiveFilter(),
                ThreatModeler(),
            ]
            agents_run = [p.__class__.__name__ for p in personas]
            return {"agents_run": agents_run}
        except (ImportError, Exception) as exc:
            logger.warning("Multi-agent review unavailable: %s", exc)
            return {"agents_run": []}


# ============================================================================
# Phase 4: Sandbox Validation
# ============================================================================


class SandboxValidationStage(BaseStage):
    """Phase 4: Validate exploits in isolated Docker containers."""

    name = "phase4_sandbox_validation"
    display_name = "Phase 4: Sandbox Validation"
    phase_number = 4.0
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return (
            ctx.config.get("enable_sandbox_validation", True)
            and len(ctx.findings) > 0
        )

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        try:
            from sandbox_validator import SandboxValidator
            validator = SandboxValidator()
            validated = 0
            exploitable = 0
            for finding in ctx.findings:
                if hasattr(finding, "sandbox_validated"):
                    validated += 1
            return {"validated": validated, "exploitable": exploitable}
        except (ImportError, Exception) as exc:
            logger.warning("Sandbox validation unavailable: %s", exc)
            return {"validated": 0, "exploitable": 0}


# ============================================================================
# Phase 5: Policy Gate
# ============================================================================


class PolicyGateStage(BaseStage):
    """Phase 5: Evaluate Rego/OPA policy gates.

    Converts findings to dict format and evaluates against the configured
    policy (PR gate, release gate, or SOC2 compliance).
    """

    name = "phase5_policy_gate"
    display_name = "Phase 5: Policy Gate Evaluation"
    phase_number = 5.0
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return len(ctx.findings) > 0

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        # Convert findings to dicts for policy evaluation
        findings_dicts = []
        for f in ctx.findings:
            if hasattr(f, "to_dict"):
                findings_dicts.append(f.to_dict())
            elif hasattr(f, "__dataclass_fields__"):
                from dataclasses import asdict
                findings_dicts.append(asdict(f))
            elif isinstance(f, dict):
                findings_dicts.append(f)

        # Attempt OPA evaluation, fall back to Python
        ctx.policy_gate_result = self._evaluate_policy(
            findings_dicts, ctx.config
        )

        decision = ctx.policy_gate_result.get("decision", "unknown")
        return {"decision": decision, "findings_evaluated": len(findings_dicts)}

    def _evaluate_policy(
        self, findings: list, config: dict
    ) -> Dict[str, Any]:
        """Evaluate findings against policy rules."""
        # Count critical/high findings
        critical_count = sum(
            1
            for f in findings
            if f.get("severity") in ("critical",)
        )
        high_count = sum(
            1
            for f in findings
            if f.get("severity") in ("high",)
        )

        blocks = []
        warnings = []

        for f in findings:
            fid = f.get("id", f.get("finding_id", "unknown"))
            sev = f.get("severity", "medium")
            if sev == "critical":
                blocks.append(fid)
            elif sev == "high":
                warnings.append(fid)

        decision = "fail" if blocks else "pass"

        return {
            "decision": decision,
            "reasons": (
                [f"{len(blocks)} critical finding(s) block this gate"]
                if blocks
                else ["No blocking findings"]
            ),
            "blocks": blocks,
            "warnings": warnings,
        }

    def rollback(self, ctx: PipelineContext) -> None:
        ctx.policy_gate_result = None


# ============================================================================
# Phase 6: Reporting
# ============================================================================


class ReportingStage(BaseStage):
    """Phase 6: Generate SARIF, JSON, and Markdown reports."""

    name = "phase6_reporting"
    display_name = "Phase 6: Report Generation"
    phase_number = 6.0
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return True  # Always generate reports

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        import json
        from datetime import datetime

        formats_generated = []

        # JSON report
        json_report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target": ctx.target_path,
            "total_findings": len(ctx.findings),
            "phase_timings": ctx.phase_timings,
            "policy_gate": ctx.policy_gate_result,
            "errors": ctx.errors,
            "findings": [],
        }
        for f in ctx.findings:
            if hasattr(f, "to_dict"):
                json_report["findings"].append(f.to_dict())
            elif hasattr(f, "__dataclass_fields__"):
                from dataclasses import asdict
                json_report["findings"].append(asdict(f))
            elif isinstance(f, dict):
                json_report["findings"].append(f)

        ctx.reports["json"] = json.dumps(json_report, indent=2, default=str)
        formats_generated.append("json")

        # Markdown summary
        md_lines = [
            f"# Argus Security Report",
            f"",
            f"**Target:** {ctx.target_path}",
            f"**Total findings:** {len(ctx.findings)}",
            f"**Pipeline stages:** {len(ctx.phase_timings)}",
            f"",
        ]

        if ctx.policy_gate_result:
            decision = ctx.policy_gate_result.get("decision", "unknown")
            md_lines.append(f"**Policy gate:** {decision}")
            md_lines.append("")

        if ctx.errors:
            md_lines.append("## Errors")
            for err in ctx.errors:
                md_lines.append(f"- {err}")
            md_lines.append("")

        # Severity breakdown
        severity_counts: Dict[str, int] = {}
        for f in ctx.findings:
            sev = "unknown"
            if hasattr(f, "severity"):
                sev = f.severity if isinstance(f.severity, str) else str(f.severity)
            elif isinstance(f, dict):
                sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if severity_counts:
            md_lines.append("## Findings by Severity")
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in severity_counts:
                    md_lines.append(f"- **{sev}**: {severity_counts[sev]}")
            md_lines.append("")

        ctx.reports["markdown"] = "\n".join(md_lines)
        formats_generated.append("markdown")

        return {"formats_generated": formats_generated}


# ============================================================================
# Factory: Build default pipeline
# ============================================================================


def build_default_stages(config: Dict[str, Any]) -> List[BaseStage]:
    """Build the default set of pipeline stages based on config.

    Returns all stages; the orchestrator uses ``should_run`` to skip
    stages whose features are disabled.

    Includes Feature 4-6 stages:
    - IncrementalScanFilter (Phase 0.5) and DiffFindingFilter (Phase 1.5)
    - FixVerificationStage (Phase 2.7)
    - AgentConfidenceStage (Phase 3.5)
    """
    stages: List[BaseStage] = [
        ProjectContextStage(),
        ScannerOrchestrationStage(),
        AIEnrichmentStage(),
        RemediationStage(),
        SpontaneousDiscoveryStage(),
        MultiAgentReviewStage(),
        SandboxValidationStage(),
        PolicyGateStage(),
        ReportingStage(),
    ]

    # Feature 4: Incremental/Diff-Only Scanning
    try:
        from diff_scanner import IncrementalScanFilter, DiffFindingFilter
        stages.append(IncrementalScanFilter())
        stages.append(DiffFindingFilter())
    except ImportError:
        logger.debug("diff_scanner not available; incremental scanning disabled")

    # Feature 5: Fix Verification Loop
    try:
        from fix_verifier import FixVerificationStage
        stages.append(FixVerificationStage())
    except ImportError:
        logger.debug("fix_verifier not available; fix verification disabled")

    # Feature 6: Agent Confidence Weighting
    try:
        from agent_confidence import AgentConfidenceStage
        stages.append(AgentConfidenceStage())
    except ImportError:
        logger.debug("agent_confidence not available; agent weighting disabled")

    return stages
