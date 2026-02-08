"""
Pipeline Orchestrator - Composes and runs pipeline stages.

Replaces the monolithic ``analyze()`` in ``hybrid_analyzer.py`` and
``run_audit()`` in ``run_ai_audit.py`` with a composable, testable
pipeline runner.

Features:
- Dependency resolution (validates ``required_stages`` graph)
- Conditional execution (``should_run`` checks)
- Cost-aware early termination
- Graceful degradation on stage failure
- Comprehensive metrics and timing
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from .protocol import PipelineContext, PipelineStage, StageResult

logger = logging.getLogger(__name__)

# Lazy import to avoid circular dependencies.  The phase_gate module is
# stdlib-only so the import is cheap.
_PhaseGate = None


def _get_phase_gate_class():
    """Lazily import PhaseGate to avoid import-time side-effects."""
    global _PhaseGate
    if _PhaseGate is None:
        from phase_gate import PhaseGate
        _PhaseGate = PhaseGate
    return _PhaseGate


# Maps stage names (as registered in PipelineStage.name) to the schema
# keys defined in PhaseGate.REQUIRED_SCHEMAS.
_STAGE_TO_GATE_PHASE: Dict[str, str] = {
    "phase1_scanner_orchestration": "scanner_orchestration",
    "scanner_orchestration": "scanner_orchestration",
    "phase2_ai_enrichment": "ai_enrichment",
    "ai_enrichment": "ai_enrichment",
    "phase3_multi_agent_review": "multi_agent_review",
    "multi_agent_review": "multi_agent_review",
    "phase4_sandbox_validation": "sandbox_validation",
    "sandbox_validation": "sandbox_validation",
    "phase5_policy_gates": "policy_gates",
    "policy_gates": "policy_gates",
    "phase6_reporting": "reporting",
    "reporting": "reporting",
}


class PipelineOrchestrator:
    """Compose and execute pipeline stages in dependency order.

    Parameters
    ----------
    stages : list[PipelineStage]
        Stages to run.  Automatically sorted by ``phase_number``.
    config : dict
        Flat configuration dict (from ``config_loader.build_unified_config``).

    Example
    -------
    ::

        pipeline = PipelineOrchestrator(
            stages=[ScannerStage(), AIEnrichmentStage(), ReportingStage()],
            config=config,
        )
        ctx, results = pipeline.run("/path/to/repo")
    """

    def __init__(
        self,
        stages: List[PipelineStage],
        config: Dict[str, Any],
    ):
        self.stages = sorted(stages, key=lambda s: s.phase_number)
        self.config = config
        self._validate_dependencies()
        self._init_phase_gate()

    def _validate_dependencies(self) -> None:
        """Verify that all ``required_stages`` references are satisfiable.

        Raises
        ------
        ValueError
            If a stage declares a dependency on a stage not in the pipeline.
        """
        stage_names = {s.name for s in self.stages}
        for stage in self.stages:
            for dep in stage.required_stages:
                if dep not in stage_names:
                    raise ValueError(
                        f"Stage '{stage.name}' requires '{dep}' which is "
                        f"not registered in the pipeline.  Available: "
                        f"{sorted(stage_names)}"
                    )

    def _init_phase_gate(self) -> None:
        """Initialize the phase gate if enabled in config."""
        self._phase_gate = None
        if self.config.get("enable_phase_gating", True):
            try:
                phase_gate_cls = _get_phase_gate_class()
                strict = bool(self.config.get("phase_gate_strict", False))
                self._phase_gate = phase_gate_cls(strict=strict)
                logger.info(
                    "Phase gating enabled (strict=%s)", strict
                )
            except Exception as exc:
                logger.warning(
                    "Failed to initialize phase gate: %s (continuing without gating)",
                    exc,
                )

    @staticmethod
    def _build_gate_output(
        stage_name: str, ctx: PipelineContext
    ) -> Dict[str, Any]:
        """Build a gate-compatible output dict from the pipeline context.

        Maps the mutable ``PipelineContext`` fields to the dict structure
        that ``PhaseGate.validate()`` expects.
        """
        gate_phase = _STAGE_TO_GATE_PHASE.get(stage_name, stage_name)

        if gate_phase == "scanner_orchestration":
            return {"findings": ctx.findings}
        if gate_phase == "ai_enrichment":
            return {"enriched_findings": ctx.findings}
        if gate_phase == "multi_agent_review":
            return {"agent_reports": ctx.agent_reports}
        if gate_phase == "sandbox_validation":
            return {"validation_results": ctx.findings}
        if gate_phase == "policy_gates":
            return {
                "gate_result": ctx.policy_gate_result,
                "pass_fail": (
                    ctx.policy_gate_result.get("pass_fail")
                    if isinstance(ctx.policy_gate_result, dict)
                    else None
                ),
            }
        if gate_phase == "reporting":
            return {"report_paths": ctx.report_paths}
        # Fallback for unknown stages
        return {}

    def _build_context(self, target_path: str) -> PipelineContext:
        """Build the initial ``PipelineContext`` from config.

        Subclass or replace this method to inject custom metrics,
        cost trackers, or AI clients.
        """
        return PipelineContext(
            config=self.config,
            target_path=target_path,
        )

    def run(
        self,
        target_path: str,
        ctx: Optional[PipelineContext] = None,
    ) -> Tuple[PipelineContext, List[StageResult]]:
        """Execute the full pipeline.

        Parameters
        ----------
        target_path : str
            Filesystem path to the codebase being analyzed.
        ctx : PipelineContext | None
            Optional pre-built context.  If ``None``, one is created via
            ``_build_context``.

        Returns
        -------
        tuple[PipelineContext, list[StageResult]]
            The final context (with findings, reports, etc.) and the list
            of stage results for each stage that was attempted.
        """
        if ctx is None:
            ctx = self._build_context(target_path)

        results: List[StageResult] = []
        completed_stages: set[str] = set()
        pipeline_start = time.time()

        logger.info(
            "Pipeline starting with %d stages targeting %s",
            len(self.stages),
            target_path,
        )

        for stage in self.stages:
            # -- Check dependencies --
            unmet = [
                dep for dep in stage.required_stages
                if dep not in completed_stages
            ]
            if unmet:
                result = StageResult(
                    success=False,
                    stage_name=stage.name,
                    error=f"Unmet dependencies: {unmet}",
                    skipped=True,
                    skip_reason=f"Unmet dependencies: {unmet}",
                )
                results.append(result)
                logger.warning(
                    "Skipping %s: unmet deps %s", stage.display_name, unmet
                )
                continue

            # -- Check preconditions --
            try:
                if not stage.should_run(ctx):
                    result = StageResult(
                        success=True,
                        stage_name=stage.name,
                        skipped=True,
                        skip_reason="Preconditions not met (should_run=False)",
                        findings_before=len(ctx.findings),
                        findings_after=len(ctx.findings),
                    )
                    results.append(result)
                    completed_stages.add(stage.name)
                    logger.info(
                        "Skipping %s: should_run returned False",
                        stage.display_name,
                    )
                    continue
            except Exception as exc:
                result = StageResult(
                    success=False,
                    stage_name=stage.name,
                    error=f"should_run check failed: {exc}",
                    skipped=True,
                    skip_reason=f"should_run raised: {exc}",
                )
                results.append(result)
                completed_stages.add(stage.name)
                logger.warning(
                    "Skipping %s: should_run raised %s",
                    stage.display_name,
                    exc,
                )
                continue

            # -- Execute --
            findings_before = len(ctx.findings)
            stage_start = time.time()
            logger.info("Starting %s ...", stage.display_name)

            try:
                result = stage.execute(ctx)
                result.duration_seconds = time.time() - stage_start
                result.findings_before = findings_before
                result.findings_after = len(ctx.findings)
                ctx.phase_timings[stage.name] = result.duration_seconds

                results.append(result)
                completed_stages.add(stage.name)

                if result.success:
                    logger.info(
                        "Completed %s in %.1fs (findings: %d -> %d)",
                        stage.display_name,
                        result.duration_seconds,
                        result.findings_before,
                        result.findings_after,
                    )

                    # -- Phase gate validation --
                    if self._phase_gate is not None:
                        gate_phase = _STAGE_TO_GATE_PHASE.get(
                            stage.name, stage.name
                        )
                        gate_output = self._build_gate_output(
                            stage.name, ctx
                        )
                        decision = self._phase_gate.validate(
                            gate_phase, gate_output
                        )
                        if not decision.should_proceed:
                            ctx.errors.append(
                                f"Phase gate blocked after "
                                f"{stage.display_name}: {decision.reason}"
                            )
                            logger.error(
                                "Phase gate BLOCKED pipeline after %s: %s",
                                stage.display_name,
                                decision.reason,
                            )
                            break
                else:
                    logger.warning(
                        "Stage %s reported failure: %s",
                        stage.display_name,
                        result.error,
                    )
                    ctx.errors.append(
                        f"{stage.display_name}: {result.error}"
                    )
                    try:
                        stage.rollback(ctx)
                    except Exception as rb_exc:
                        logger.warning(
                            "Rollback for %s failed: %s",
                            stage.display_name,
                            rb_exc,
                        )

            except Exception as exc:
                duration = time.time() - stage_start
                error_msg = f"{type(exc).__name__}: {exc}"

                # Check for cost-limit errors
                cost_error = _is_cost_limit_error(exc)
                if cost_error:
                    result = StageResult(
                        success=False,
                        stage_name=stage.name,
                        duration_seconds=duration,
                        findings_before=findings_before,
                        findings_after=len(ctx.findings),
                        error=f"Cost limit exceeded: {exc}",
                    )
                    results.append(result)
                    ctx.errors.append(f"Cost limit hit at {stage.display_name}")
                    logger.error(
                        "Pipeline stopping: cost limit exceeded at %s",
                        stage.display_name,
                    )
                    break  # Hard stop on cost overrun

                # Non-fatal: log and continue
                result = StageResult(
                    success=False,
                    stage_name=stage.name,
                    duration_seconds=duration,
                    findings_before=findings_before,
                    findings_after=len(ctx.findings),
                    error=error_msg,
                )
                results.append(result)
                completed_stages.add(stage.name)
                ctx.errors.append(f"{stage.display_name}: {error_msg}")

                logger.error(
                    "Stage %s failed with %s (continuing)",
                    stage.display_name,
                    error_msg,
                    exc_info=True,
                )
                try:
                    stage.rollback(ctx)
                except Exception as rb_exc:
                    logger.warning(
                        "Rollback for %s failed: %s",
                        stage.display_name,
                        rb_exc,
                    )

        # -- Finalize --
        pipeline_duration = time.time() - pipeline_start
        ctx.phase_timings["_total"] = pipeline_duration

        logger.info(
            "Pipeline completed in %.1fs: %d stages run, %d findings, %d errors",
            pipeline_duration,
            len([r for r in results if not r.skipped]),
            len(ctx.findings),
            len(ctx.errors),
        )

        return ctx, results


def _is_cost_limit_error(exc: Exception) -> bool:
    """Check if an exception represents a cost-limit breach.

    Matches the various CostLimitExceededError classes defined across
    the codebase (exceptions.py, cost_tracker.py, llm_manager.py).
    """
    return "CostLimit" in type(exc).__name__
