"""
End-to-End Integration Test: Features 1 + 2 + 3

Tests that all three features work together:
1. Configuration Profiles load and configure the pipeline
2. Pipeline Stage Interface orchestrates the stages
3. Typed Finding Schemas validate data at boundaries

This is the "top of the pyramid" test that proves the features integrate.
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from config_loader import build_unified_config, load_profile
from pipeline.protocol import PipelineContext, StageResult
from pipeline.orchestrator import PipelineOrchestrator
from pipeline.base_stage import BaseStage
from pipeline.stages import (
    PolicyGateStage,
    ReportingStage,
    build_default_stages,
)
from schemas.pipeline import (
    ConsensusResult,
    AgentVerdictSummary,
    PipelineFinding,
    PipelineMetadata,
    PipelineResult,
    SandboxResult,
)


# ============================================================================
# Mock scanner stage that produces typed PipelineFindings
# ============================================================================


class MockScannerStage(BaseStage):
    """Injects typed PipelineFinding objects into the pipeline context."""

    name = "phase1_scanner_orchestration"
    display_name = "Phase 1: Mock Scanner"
    phase_number = 1.0

    def __init__(self, findings: List[PipelineFinding]):
        self._findings = findings

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        ctx.findings.extend(self._findings)
        return {"scanners_run": ["mock"], "findings_injected": len(self._findings)}


class MockConsensusStage(BaseStage):
    """Attaches consensus data to findings."""

    name = "phase3_consensus"
    display_name = "Phase 3: Mock Consensus"
    phase_number = 3.0
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return len(ctx.findings) > 0

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        for finding in ctx.findings:
            if isinstance(finding, PipelineFinding):
                finding.consensus = ConsensusResult(
                    votes=4,
                    total_agents=5,
                    consensus_level="strong",
                    confidence=0.85,
                    agents_agree=["SecretHunter", "ExploitAssessor",
                                  "ArchitectureReviewer", "ThreatModeler"],
                )
        return {"findings_with_consensus": len(ctx.findings)}


class MockSandboxStage(BaseStage):
    """Attaches sandbox results to findings."""

    name = "phase4_sandbox_validation"
    display_name = "Phase 4: Mock Sandbox"
    phase_number = 4.0
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return ctx.config.get("enable_sandbox_validation", False)

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        validated = 0
        for finding in ctx.findings:
            if isinstance(finding, PipelineFinding):
                sev = finding.severity
                if isinstance(sev, str):
                    sev_str = sev
                else:
                    sev_str = sev.value if hasattr(sev, 'value') else str(sev)

                if sev_str == "critical":
                    finding.sandbox = SandboxResult(
                        validated=True,
                        result="exploitable",
                        execution_time_ms=1200,
                        indicators_found=["command execution confirmed"],
                    )
                    validated += 1
        return {"validated": validated}


# ============================================================================
# Integration Test: Config -> Pipeline -> Typed Schemas
# ============================================================================


class TestFullIntegration:
    """End-to-end tests proving all 3 features work together."""

    def _make_findings(self) -> List[PipelineFinding]:
        """Create a realistic set of typed findings."""
        return [
            PipelineFinding(
                id="sql-inject-001",
                origin="semgrep",
                repo="test-org/webapp",
                commit_sha="abc123",
                branch="main",
                path="src/api/users.py",
                severity="critical",
                category="SAST",
                title="SQL Injection in user query",
                description="User-controlled input concatenated into SQL",
                line=42,
                cwe="CWE-89",
                exploitability="trivial",
                confidence=0.95,
            ),
            PipelineFinding(
                id="xss-002",
                origin="semgrep",
                repo="test-org/webapp",
                commit_sha="abc123",
                branch="main",
                path="src/templates/profile.html",
                severity="high",
                category="SAST",
                title="Reflected XSS",
                description="User input rendered without escaping",
                line=15,
                cwe="CWE-79",
                exploitability="moderate",
            ),
            PipelineFinding(
                id="dep-vuln-003",
                origin="trivy",
                repo="test-org/webapp",
                commit_sha="abc123",
                branch="main",
                path="requirements.txt",
                severity="medium",
                category="DEPS",
                title="Vulnerable dependency",
                description="requests 2.25.0 has known CVE",
                cve="CVE-2023-32681",
                cvss=6.1,
            ),
        ]

    def test_quick_profile_pipeline(self):
        """Quick profile -> minimal pipeline -> typed output."""
        config = build_unified_config(profile="quick")
        findings = self._make_findings()

        stages = [
            MockScannerStage(findings),
            PolicyGateStage(),
            ReportingStage(),
        ]
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/webapp")

        # Verify pipeline ran
        assert len(results) == 3
        assert all(r.success for r in results)

        # Verify policy gate detected critical
        assert ctx.policy_gate_result["decision"] == "fail"

        # Verify typed findings in context
        assert len(ctx.findings) == 3
        for f in ctx.findings:
            assert isinstance(f, PipelineFinding)

        # Verify reports generated
        assert "json" in ctx.reports
        report = json.loads(ctx.reports["json"])
        assert report["total_findings"] == 3

    def test_standard_profile_with_consensus(self):
        """Standard profile -> scanners + consensus -> policy gate."""
        config = build_unified_config(profile="standard")
        findings = self._make_findings()

        stages = [
            MockScannerStage(findings),
            MockConsensusStage(),
            PolicyGateStage(),
            ReportingStage(),
        ]
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/webapp")

        assert len(results) == 4
        # Verify consensus was attached
        for f in ctx.findings:
            if isinstance(f, PipelineFinding) and f.consensus:
                assert f.consensus.consensus_level == "strong"
                assert f.consensus.votes == 4

    def test_deep_profile_with_sandbox(self):
        """Deep profile -> all stages including sandbox."""
        config = build_unified_config(profile="deep")
        findings = self._make_findings()

        stages = [
            MockScannerStage(findings),
            MockConsensusStage(),
            MockSandboxStage(),
            PolicyGateStage(),
            ReportingStage(),
        ]
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/webapp")

        # Sandbox should have run (deep profile enables it)
        sandbox_result = next(
            r for r in results if r.stage_name == "phase4_sandbox_validation"
        )
        assert not sandbox_result.skipped

        # Critical finding should have sandbox result
        critical = [
            f for f in ctx.findings
            if isinstance(f, PipelineFinding)
            and f.severity == "critical"
        ]
        assert len(critical) == 1
        assert critical[0].sandbox is not None
        assert critical[0].sandbox.result == "exploitable"

    def test_secrets_only_skips_most_stages(self):
        """Secrets-only profile -> minimal stage execution."""
        config = build_unified_config(profile="secrets-only")
        findings = self._make_findings()

        stages = [
            MockScannerStage(findings),
            MockConsensusStage(),  # should_run checks multi_agent
            MockSandboxStage(),  # should_run checks sandbox flag
            PolicyGateStage(),
            ReportingStage(),
        ]
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/webapp")

        # Sandbox should be skipped
        sandbox_r = next(
            r for r in results if r.stage_name == "phase4_sandbox_validation"
        )
        assert sandbox_r.skipped

    def test_pipeline_result_construction(self):
        """Build a full PipelineResult from pipeline output."""
        config = build_unified_config(profile="standard")
        findings = self._make_findings()

        stages = [
            MockScannerStage(findings),
            MockConsensusStage(),
            PolicyGateStage(),
            ReportingStage(),
        ]
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/webapp")

        # Build typed PipelineResult from context
        pipeline_findings = [
            f for f in ctx.findings if isinstance(f, PipelineFinding)
        ]

        pr = PipelineResult(
            findings=pipeline_findings,
            metadata=PipelineMetadata(
                repository="test-org/webapp",
                commit="abc123",
                branch="main",
                duration_seconds=ctx.phase_timings.get("_total", 0),
                provider=config.get("ai_provider", "auto"),
                model=config.get("model", "auto"),
                phase_timings=ctx.phase_timings,
                tools_used=["semgrep", "trivy"],
                policy_decision=ctx.policy_gate_result.get("decision"),
            ),
            policy_gate_result=ctx.policy_gate_result,
        )

        # Verify typed result
        assert len(pr.findings) == 3
        assert pr.findings_by_severity()["critical"] == 1
        assert pr.findings_by_source()["semgrep"] == 2
        assert len(pr.critical_findings()) == 1
        assert pr.metadata.policy_decision == "fail"

        # Verify JSON serialization
        json_str = pr.model_dump_json()
        data = json.loads(json_str)
        assert data["metadata"]["repository"] == "test-org/webapp"
        assert len(data["findings"]) == 3

    def test_config_override_changes_pipeline_behavior(self):
        """CLI override disabling sandbox -> sandbox stage skips."""
        # Start with deep profile (sandbox enabled)
        config = build_unified_config(profile="deep")
        assert config["enable_sandbox_validation"] is True

        # Override via 'CLI'
        config["enable_sandbox_validation"] = False

        stages = [
            MockScannerStage(self._make_findings()),
            MockSandboxStage(),
            ReportingStage(),
        ]
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/webapp")

        sandbox_r = next(
            r for r in results if r.stage_name == "phase4_sandbox_validation"
        )
        assert sandbox_r.skipped

    def test_hybrid_finding_to_pipeline_finding_in_pipeline(self):
        """HybridFinding -> PipelineFinding conversion works in pipeline."""

        @dataclass
        class HybridFinding:
            finding_id: str = "hf-001"
            source_tool: str = "semgrep"
            severity: str = "high"
            category: str = "security"
            title: str = "Command Injection"
            description: str = "os.system with user input"
            file_path: str = "src/utils.py"
            line_number: int = 99
            cwe_id: str = "CWE-78"
            cve_id: Optional[str] = None
            cvss_score: Optional[float] = None
            exploitability: str = "trivial"
            recommendation: str = "Use subprocess with shell=False"
            references: list = None
            confidence: float = 0.9
            llm_enriched: bool = True
            sandbox_validated: bool = False
            iris_verified: bool = False
            iris_confidence: Optional[float] = None
            iris_verdict: Optional[str] = None

            def __post_init__(self):
                if self.references is None:
                    self.references = []

        # Convert HybridFinding to PipelineFinding
        hf = HybridFinding()
        pf = PipelineFinding.from_hybrid_finding(hf)

        # Run through pipeline
        config = build_unified_config(profile="quick")
        stages = [
            MockScannerStage([pf]),
            PolicyGateStage(),
            ReportingStage(),
        ]
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/webapp")

        assert len(ctx.findings) == 1
        finding = ctx.findings[0]
        assert isinstance(finding, PipelineFinding)
        assert finding.title == "Command Injection"
        assert finding.cwe == "CWE-78"
        assert finding.origin == "semgrep"
