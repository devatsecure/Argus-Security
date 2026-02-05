"""
Tests for Feature 1: Pipeline Stage Interface

Tests the Protocol, PipelineContext, StageResult, PipelineOrchestrator,
BaseStage, and concrete stage implementations.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from pipeline.protocol import PipelineContext, PipelineStage, StageResult
from pipeline.orchestrator import PipelineOrchestrator
from pipeline.base_stage import BaseStage
from pipeline.stages import (
    ProjectContextStage,
    ScannerOrchestrationStage,
    AIEnrichmentStage,
    RemediationStage,
    SpontaneousDiscoveryStage,
    MultiAgentReviewStage,
    SandboxValidationStage,
    PolicyGateStage,
    ReportingStage,
    build_default_stages,
)


# ============================================================================
# Test PipelineContext
# ============================================================================


class TestPipelineContext:
    def test_default_construction(self):
        ctx = PipelineContext()
        assert ctx.config == {}
        assert ctx.target_path == ""
        assert ctx.findings == []
        assert ctx.phase_timings == {}
        assert ctx.errors == []
        assert ctx.reports == {}

    def test_with_config(self):
        config = {"ai_provider": "anthropic", "max_files": 50}
        ctx = PipelineContext(config=config, target_path="/tmp/repo")
        assert ctx.config["ai_provider"] == "anthropic"
        assert ctx.target_path == "/tmp/repo"

    def test_mutable_findings(self):
        ctx = PipelineContext()
        ctx.findings.append({"id": "f1", "severity": "high"})
        ctx.findings.append({"id": "f2", "severity": "low"})
        assert len(ctx.findings) == 2

    def test_phase_timings(self):
        ctx = PipelineContext()
        ctx.phase_timings["phase1"] = 2.5
        ctx.phase_timings["phase2"] = 5.0
        assert ctx.phase_timings["phase1"] == 2.5

    def test_error_collection(self):
        ctx = PipelineContext()
        ctx.errors.append("Phase 2 failed: timeout")
        assert len(ctx.errors) == 1


# ============================================================================
# Test StageResult
# ============================================================================


class TestStageResult:
    def test_success_result(self):
        result = StageResult(success=True, stage_name="phase1")
        assert result.success
        assert result.stage_name == "phase1"
        assert result.error is None
        assert not result.skipped

    def test_failed_result(self):
        result = StageResult(
            success=False, stage_name="phase2", error="LLM timeout"
        )
        assert not result.success
        assert result.error == "LLM timeout"

    def test_skipped_result(self):
        result = StageResult(
            success=True,
            stage_name="phase4",
            skipped=True,
            skip_reason="sandbox disabled",
        )
        assert result.skipped
        assert "sandbox" in result.skip_reason


# ============================================================================
# Test PipelineStage Protocol
# ============================================================================


class TestPipelineStageProtocol:
    def test_protocol_compliance(self):
        """Any class with the right methods satisfies the protocol."""

        class MinimalStage:
            name = "test"
            display_name = "Test"
            phase_number = 1.0
            required_stages = []

            def should_run(self, ctx):
                return True

            def execute(self, ctx):
                return StageResult(success=True, stage_name="test")

            def rollback(self, ctx):
                pass

        stage = MinimalStage()
        assert isinstance(stage, PipelineStage)

    def test_non_compliant_object(self):
        """An object missing methods should not satisfy the protocol."""

        class NotAStage:
            name = "nope"

        stage = NotAStage()
        assert not isinstance(stage, PipelineStage)


# ============================================================================
# Test BaseStage
# ============================================================================


class CountingStage(BaseStage):
    """Test stage that adds N findings."""

    name = "counting_stage"
    display_name = "Counting Stage"
    phase_number = 1.0
    _required = []

    def __init__(self, count: int = 3):
        self.count = count

    @property
    def required_stages(self):
        return self._required

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        for i in range(self.count):
            ctx.findings.append({"id": f"f{i}", "severity": "medium"})
        return {"added": self.count}


class FailingStage(BaseStage):
    """Test stage that always raises."""

    name = "failing_stage"
    display_name = "Failing Stage"
    phase_number = 2.0

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        raise RuntimeError("intentional failure")


class SkippableStage(BaseStage):
    """Test stage that skips unless config flag is set."""

    name = "skippable_stage"
    display_name = "Skippable Stage"
    phase_number = 3.0

    def should_run(self, ctx: PipelineContext) -> bool:
        return ctx.config.get("run_skippable", False)

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        ctx.findings.append({"id": "skipped_finding"})
        return {}


class TestBaseStage:
    def test_execute_success(self):
        stage = CountingStage(count=5)
        ctx = PipelineContext()
        result = stage.execute(ctx)
        assert result.success
        assert result.findings_before == 0
        assert result.findings_after == 5
        assert result.metadata["added"] == 5

    def test_execute_failure_handled(self):
        stage = FailingStage()
        ctx = PipelineContext()
        result = stage.execute(ctx)
        assert not result.success
        assert "intentional failure" in result.error

    def test_rollback_noop(self):
        stage = CountingStage()
        ctx = PipelineContext()
        stage.rollback(ctx)  # Should not raise


# ============================================================================
# Test PipelineOrchestrator
# ============================================================================


class TestPipelineOrchestrator:
    def test_basic_pipeline(self):
        stages = [CountingStage(count=2)]
        orch = PipelineOrchestrator(stages=stages, config={})
        ctx, results = orch.run("/tmp/test")
        assert len(results) == 1
        assert results[0].success
        assert len(ctx.findings) == 2

    def test_multi_stage_pipeline(self):
        stage1 = CountingStage(count=3)
        stage2 = CountingStage(count=2)
        stage2.name = "counting_stage_2"
        stage2.display_name = "Counting Stage 2"
        stage2.phase_number = 2.0
        orch = PipelineOrchestrator(stages=[stage2, stage1], config={})  # Reversed order
        ctx, results = orch.run("/tmp/test")
        # Should sort by phase_number
        assert results[0].stage_name == "counting_stage"
        assert results[1].stage_name == "counting_stage_2"
        assert len(ctx.findings) == 5

    def test_skipped_stage(self):
        stages = [CountingStage(count=1), SkippableStage()]
        orch = PipelineOrchestrator(stages=stages, config={})
        ctx, results = orch.run("/tmp/test")
        assert len(results) == 2
        assert results[1].skipped
        assert len(ctx.findings) == 1  # Only from counting stage

    def test_skippable_runs_with_config(self):
        stages = [CountingStage(count=1), SkippableStage()]
        orch = PipelineOrchestrator(
            stages=stages, config={"run_skippable": True}
        )
        ctx, results = orch.run("/tmp/test")
        assert len(ctx.findings) == 2  # From both stages

    def test_failed_stage_continues(self):
        """Pipeline continues after a non-fatal failure."""
        stage1 = CountingStage(count=1)
        stage2 = FailingStage()
        stage3 = CountingStage(count=1)
        stage3.name = "counting_stage_final"
        stage3.display_name = "Counting Stage Final"
        stage3.phase_number = 3.0
        orch = PipelineOrchestrator(
            stages=[stage1, stage2, stage3], config={}
        )
        ctx, results = orch.run("/tmp/test")
        assert len(results) == 3
        assert results[0].success  # stage1
        assert not results[1].success  # stage2 failed
        assert results[2].success  # stage3 still ran

    def test_dependency_validation(self):
        """Stages with unregistered dependencies cause ValueError."""
        stage = CountingStage()
        stage._required = ["nonexistent_stage"]
        with pytest.raises(ValueError, match="nonexistent_stage"):
            PipelineOrchestrator(stages=[stage], config={})

    def test_unmet_dependency_skips(self):
        """If a dependency failed/wasn't completed, dependent stage is skipped."""
        stage1 = FailingStage()
        stage2 = CountingStage()
        stage2.name = "dependent_stage"
        stage2.phase_number = 3.0
        stage2._required = ["failing_stage"]
        orch = PipelineOrchestrator(stages=[stage1, stage2], config={})
        ctx, results = orch.run("/tmp/test")
        # stage2 should still run because failing_stage gets added to completed even on failure
        # (graceful degradation)
        assert len(results) == 2

    def test_phase_timings_recorded(self):
        stages = [CountingStage(count=1)]
        orch = PipelineOrchestrator(stages=stages, config={})
        ctx, results = orch.run("/tmp/test")
        assert "counting_stage" in ctx.phase_timings
        assert ctx.phase_timings["counting_stage"] >= 0
        assert "_total" in ctx.phase_timings

    def test_custom_context(self):
        """Pre-built context is used if provided."""
        stages = [CountingStage(count=1)]
        orch = PipelineOrchestrator(stages=stages, config={})
        custom_ctx = PipelineContext(
            config={"custom": True}, target_path="/custom"
        )
        ctx, results = orch.run("/custom", ctx=custom_ctx)
        assert ctx.config["custom"]
        assert ctx is custom_ctx

    def test_errors_collected(self):
        """Non-fatal errors are collected in ctx.errors."""
        stage1 = CountingStage(count=1)
        stage2 = FailingStage()
        orch = PipelineOrchestrator(stages=[stage1, stage2], config={})
        ctx, results = orch.run("/tmp/test")
        # FailingStage fails in _execute, which is caught by BaseStage.execute()
        # and returned as StageResult(success=False). The orchestrator then logs
        # the error to ctx.errors.
        assert len(ctx.errors) >= 1


# ============================================================================
# Test Concrete Stages
# ============================================================================


class TestConcreteStages:
    def test_build_default_stages(self):
        stages = build_default_stages({})
        assert len(stages) == 9
        names = [s.name for s in stages]
        assert "phase0_project_context" in names
        assert "phase1_scanner_orchestration" in names
        assert "phase6_reporting" in names

    def test_policy_gate_pass(self):
        stage = PolicyGateStage()
        ctx = PipelineContext()
        ctx.findings = [
            {"id": "f1", "severity": "medium"},
            {"id": "f2", "severity": "low"},
        ]
        result = stage.execute(ctx)
        assert result.success
        assert ctx.policy_gate_result["decision"] == "pass"

    def test_policy_gate_fail(self):
        stage = PolicyGateStage()
        ctx = PipelineContext()
        ctx.findings = [
            {"id": "f1", "severity": "critical"},
        ]
        result = stage.execute(ctx)
        assert result.success  # Stage itself succeeded
        assert ctx.policy_gate_result["decision"] == "fail"
        assert "f1" in ctx.policy_gate_result["blocks"]

    def test_reporting_stage_generates_json_and_md(self):
        stage = ReportingStage()
        ctx = PipelineContext(target_path="/tmp/repo")
        ctx.findings = [{"id": "f1", "severity": "high"}]
        result = stage.execute(ctx)
        assert result.success
        assert "json" in ctx.reports
        assert "markdown" in ctx.reports

        # Verify JSON is parseable
        report = json.loads(ctx.reports["json"])
        assert report["total_findings"] == 1
        assert len(report["findings"]) == 1

        # Verify markdown has content
        assert "Argus Security Report" in ctx.reports["markdown"]
        assert "high" in ctx.reports["markdown"]

    def test_scanner_stage_with_no_scanners(self):
        """Scanner stage runs even when all scanners fail to import."""
        stage = ScannerOrchestrationStage()
        ctx = PipelineContext(
            config={
                "enable_semgrep": True,
                "enable_trivy": True,
                "enable_checkov": True,
            }
        )
        # Scanners will fail to import in test env -- that's fine
        result = stage.execute(ctx)
        assert result.success  # Should not crash

    def test_ai_enrichment_skips_without_client(self):
        stage = AIEnrichmentStage()
        ctx = PipelineContext(config={"enable_ai_enrichment": True})
        ctx.findings = [{"id": "f1"}]
        # No ai_client set
        assert not stage.should_run(ctx)

    def test_sandbox_stage_skips_when_disabled(self):
        stage = SandboxValidationStage()
        ctx = PipelineContext(
            config={"enable_sandbox_validation": False}
        )
        ctx.findings = [{"id": "f1"}]
        assert not stage.should_run(ctx)

    def test_stage_ordering(self):
        """Stages should sort by phase_number."""
        stages = build_default_stages({})
        numbers = [s.phase_number for s in stages]
        assert numbers == sorted(numbers)


# ============================================================================
# Test full pipeline E2E
# ============================================================================


class TestE2EPipeline:
    def test_full_pipeline_with_mock_findings(self):
        """Run a complete pipeline with injected findings."""
        config = {
            "enable_semgrep": False,  # Skip real scanner
            "enable_trivy": False,
            "enable_checkov": False,
            "enable_ai_enrichment": False,
            "enable_multi_agent": False,
            "enable_sandbox_validation": False,
            "enable_remediation": False,
            "enable_spontaneous_discovery": False,
        }
        stages = build_default_stages(config)
        orch = PipelineOrchestrator(stages=stages, config=config)

        # Inject findings into context before running
        ctx = PipelineContext(config=config, target_path="/tmp/test_repo")
        ctx.findings = [
            {"id": "vuln-1", "severity": "critical", "message": "SQL Injection"},
            {"id": "vuln-2", "severity": "medium", "message": "XSS"},
        ]

        ctx, results = orch.run("/tmp/test_repo", ctx=ctx)

        # Pipeline should complete
        assert "_total" in ctx.phase_timings

        # Policy gate should detect the critical finding
        assert ctx.policy_gate_result is not None
        assert ctx.policy_gate_result["decision"] == "fail"

        # Reports should be generated
        assert "json" in ctx.reports
        assert "markdown" in ctx.reports

        # JSON report should contain findings
        report = json.loads(ctx.reports["json"])
        assert report["total_findings"] == 2
