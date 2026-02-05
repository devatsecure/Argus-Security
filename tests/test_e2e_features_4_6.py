"""
End-to-End Integration Test: Features 4 + 5 + 6

Tests that all three new features work together in the pipeline:
4. Incremental/Diff-Only Scanning filters findings to changed files
5. Fix Verification Loop validates remediation suggestions
6. Agent Confidence Weighting re-scores consensus by domain expertise

This tests the full pipeline path from scanner -> diff filter ->
AI enrichment -> remediation -> fix verification -> multi-agent ->
agent confidence -> policy gate -> reporting.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from agent_confidence import (
    AGENT_NAMES,
    AgentAccuracyTracker,
    AgentConfidenceStage,
    WeightedConsensusBuilder,
)
from diff_scanner import ChangedFile, DiffDetector, DiffFindingFilter, IncrementalScanFilter
from fix_verifier import FixVerificationStage, FixVerifier
from pipeline.base_stage import BaseStage
from pipeline.orchestrator import PipelineOrchestrator
from pipeline.protocol import PipelineContext, StageResult
from pipeline.stages import PolicyGateStage, ReportingStage, build_default_stages


# ============================================================================
# Mock stages for controlled testing
# ============================================================================


class MockScannerStage(BaseStage):
    """Injects findings into the pipeline."""

    name = "phase1_scanner_orchestration"
    display_name = "Phase 1: Mock Scanner"
    phase_number = 1.0

    def __init__(self, findings: list):
        self._findings = findings

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        ctx.findings.extend(self._findings)
        return {"scanners_run": ["mock"], "count": len(self._findings)}


class MockRemediationStage(BaseStage):
    """Attaches fix suggestions to findings."""

    name = "phase2_5_remediation"
    display_name = "Phase 2.5: Mock Remediation"
    phase_number = 2.5
    required_stages = ["phase1_scanner_orchestration"]

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        fixes = 0
        for f in ctx.findings:
            if isinstance(f, dict) and f.get("cwe") == "CWE-89":
                f["fix_suggestion"] = {
                    "finding_id": f.get("id", "unknown"),
                    "original_code": 'cursor.execute(f"SELECT * FROM t WHERE x={v}")',
                    "fixed_code": 'cursor.execute("SELECT * FROM t WHERE x=?", (v,))',
                    "cwe_references": ["CWE-89"],
                    "vulnerability_type": "sql_injection",
                }
                fixes += 1
        return {"fixes_generated": fixes}


class MockMultiAgentStage(BaseStage):
    """Attaches consensus data to findings."""

    name = "phase3_multi_agent_review"
    display_name = "Phase 3: Mock Multi-Agent Review"
    phase_number = 3.0
    required_stages = ["phase1_scanner_orchestration"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return ctx.config.get("enable_multi_agent", True) and len(ctx.findings) > 0

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        for f in ctx.findings:
            if isinstance(f, dict):
                category = f.get("category", "SAST")
                # Simulate 3 agents agreeing
                f["consensus"] = {
                    "votes": 3,
                    "total_agents": 5,
                    "agents_agree": ["SecretHunter", "ExploitAssessor", "FalsePositiveFilter"],
                    "consensus_level": "strong",
                    "confidence": 0.85,
                    "weighted_score": 0.60,
                }
        return {"agents_run": 5}


# ============================================================================
# Test fixtures
# ============================================================================


def _make_findings() -> list:
    """Create a realistic set of findings for integration testing."""
    return [
        {
            "id": "sqli-001",
            "path": "src/api/users.py",
            "line": 42,
            "severity": "critical",
            "category": "SAST",
            "cwe": "CWE-89",
            "message": "SQL Injection in user query",
        },
        {
            "id": "xss-002",
            "path": "src/templates/profile.html",
            "line": 15,
            "severity": "high",
            "category": "SAST",
            "message": "Reflected XSS",
        },
        {
            "id": "secret-003",
            "path": "config/settings.py",
            "line": 8,
            "severity": "critical",
            "category": "SECRETS",
            "message": "Hardcoded API key",
        },
        {
            "id": "dep-004",
            "path": "requirements.txt",
            "line": None,
            "severity": "medium",
            "category": "DEPS",
            "message": "Vulnerable dependency",
        },
    ]


# ============================================================================
# Integration: Feature 4 (Diff Filter) in pipeline
# ============================================================================


class TestDiffFilterIntegration:
    @patch.object(DiffDetector, "get_changed_files")
    @patch.object(DiffDetector, "get_changed_lines")
    def test_incremental_filter_limits_scope(self, mock_lines, mock_files):
        """IncrementalScanFilter sets changed_files on context."""
        mock_files.return_value = [
            ChangedFile(path="src/api/users.py", status="M"),
            ChangedFile(path="src/templates/profile.html", status="M"),
        ]
        mock_lines.return_value = [(1, 100)]

        stages = [
            IncrementalScanFilter(),
            MockScannerStage(_make_findings()),
            ReportingStage(),
        ]
        config = {"only_changed": True}
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/repo")

        assert ctx.changed_files is not None
        assert len(ctx.changed_files) == 2

    @patch.object(DiffDetector, "filter_findings_to_diff")
    @patch.object(DiffDetector, "get_changed_files")
    @patch.object(DiffDetector, "get_changed_lines")
    def test_diff_finding_filter_reduces_findings(
        self, mock_lines, mock_files, mock_filter
    ):
        """DiffFindingFilter removes findings outside the diff."""
        all_findings = _make_findings()
        # Only keep sqli-001 and xss-002 (the changed files)
        mock_files.return_value = [
            ChangedFile(path="src/api/users.py", status="M"),
            ChangedFile(path="src/templates/profile.html", status="M"),
        ]
        mock_lines.return_value = [(1, 100)]
        mock_filter.return_value = [all_findings[0], all_findings[1]]

        stages = [
            IncrementalScanFilter(),
            MockScannerStage(all_findings),
            DiffFindingFilter(),
            ReportingStage(),
        ]
        config = {"only_changed": True}
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/repo")

        # Should be filtered from 4 to 2
        assert len(ctx.findings) == 2

    def test_diff_filter_skipped_when_not_incremental(self):
        """DiffFindingFilter is a no-op when only_changed=False."""
        stages = [
            MockScannerStage(_make_findings()),
            DiffFindingFilter(),
            ReportingStage(),
        ]
        config = {"only_changed": False}
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/repo")

        # All 4 findings remain
        assert len(ctx.findings) == 4
        # DiffFindingFilter was skipped
        diff_result = next(r for r in results if r.stage_name == "phase1_5_diff_finding_filter")
        assert diff_result.skipped


# ============================================================================
# Integration: Feature 5 (Fix Verification) in pipeline
# ============================================================================


class TestFixVerificationIntegration:
    def test_fix_verification_in_pipeline(self):
        """FixVerificationStage verifies fixes after remediation."""
        stages = [
            MockScannerStage(_make_findings()),
            MockRemediationStage(),
            FixVerificationStage(),
            ReportingStage(),
        ]
        config = {"enable_fix_verification": True}
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/repo")

        # Verify the stage ran
        fv_result = next(r for r in results if r.stage_name == "phase2_7_fix_verification")
        assert fv_result.success
        assert not fv_result.skipped
        assert fv_result.metadata["verified"] >= 1

        # The SQL injection finding should have fix_confidence
        sqli = next(f for f in ctx.findings if f.get("id") == "sqli-001")
        assert "fix_confidence" in sqli

    def test_fix_verification_disabled(self):
        stages = [
            MockScannerStage(_make_findings()),
            MockRemediationStage(),
            FixVerificationStage(),
            ReportingStage(),
        ]
        config = {"enable_fix_verification": False}
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/repo")

        fv_result = next(r for r in results if r.stage_name == "phase2_7_fix_verification")
        assert fv_result.skipped


# ============================================================================
# Integration: Feature 6 (Agent Confidence) in pipeline
# ============================================================================


class TestAgentConfidenceIntegration:
    def test_confidence_weighting_in_pipeline(self):
        """AgentConfidenceStage re-scores consensus after multi-agent review."""
        stages = [
            MockScannerStage(_make_findings()),
            MockMultiAgentStage(),
            AgentConfidenceStage(),
            ReportingStage(),
        ]
        config = {"enable_agent_weighting": True, "enable_multi_agent": True}
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/repo")

        ac_result = next(r for r in results if r.stage_name == "phase3_5_agent_confidence")
        assert ac_result.success
        assert not ac_result.skipped
        assert ac_result.metadata["rescored"] > 0

    def test_secrets_finding_weighted_higher_by_secret_hunter(self):
        """SecretHunter carries more weight on SECRETS findings."""
        stages = [
            MockScannerStage(_make_findings()),
            MockMultiAgentStage(),
            AgentConfidenceStage(),
            ReportingStage(),
        ]
        config = {"enable_agent_weighting": True, "enable_multi_agent": True}
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/repo")

        # Find the SECRETS finding
        secret_finding = next(
            f for f in ctx.findings
            if isinstance(f, dict) and f.get("category") == "SECRETS"
        )
        c = secret_finding["consensus"]
        # SecretHunter is one of the agreeing agents and has 1.8 weight on SECRETS
        # Weighted score should be different from raw 3/5 = 0.60
        assert c["weighted_score"] != 0.60

    def test_confidence_disabled(self):
        stages = [
            MockScannerStage(_make_findings()),
            MockMultiAgentStage(),
            AgentConfidenceStage(),
            ReportingStage(),
        ]
        config = {"enable_agent_weighting": False, "enable_multi_agent": True}
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/repo")

        ac_result = next(r for r in results if r.stage_name == "phase3_5_agent_confidence")
        assert ac_result.skipped


# ============================================================================
# Full E2E: All 3 features together
# ============================================================================


class TestFullPipelineFeatures4_6:
    @patch.object(DiffDetector, "filter_findings_to_diff")
    @patch.object(DiffDetector, "get_changed_files")
    @patch.object(DiffDetector, "get_changed_lines")
    def test_all_features_together(self, mock_lines, mock_files, mock_filter):
        """Full pipeline: diff filter -> scanner -> diff finding filter ->
        remediation -> fix verification -> multi-agent -> agent confidence ->
        policy gate -> reporting."""
        all_findings = _make_findings()

        # Mock diff to only include 2 files
        mock_files.return_value = [
            ChangedFile(path="src/api/users.py", status="M"),
            ChangedFile(path="config/settings.py", status="M"),
        ]
        mock_lines.return_value = [(1, 100)]
        # Filter keeps sqli-001 and secret-003
        mock_filter.return_value = [all_findings[0], all_findings[2]]

        stages = [
            IncrementalScanFilter(),
            MockScannerStage(all_findings),
            DiffFindingFilter(),
            MockRemediationStage(),
            FixVerificationStage(),
            MockMultiAgentStage(),
            AgentConfidenceStage(),
            PolicyGateStage(),
            ReportingStage(),
        ]
        config = {
            "only_changed": True,
            "enable_fix_verification": True,
            "enable_agent_weighting": True,
            "enable_multi_agent": True,
        }
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/repo")

        # All stages should succeed
        assert all(r.success for r in results)

        # Diff filter reduced from 4 to 2
        assert len(ctx.findings) == 2

        # Fix verification ran on the SQL injection finding
        sqli = next(f for f in ctx.findings if f["id"] == "sqli-001")
        assert "fix_confidence" in sqli

        # Agent confidence re-scored consensus
        secret = next(f for f in ctx.findings if f["id"] == "secret-003")
        assert "consensus" in secret
        assert "weighted_score" in secret["consensus"]

        # Policy gate detected critical findings
        assert ctx.policy_gate_result is not None
        assert ctx.policy_gate_result["decision"] == "fail"

        # Reports generated
        assert "json" in ctx.reports
        report = json.loads(ctx.reports["json"])
        assert report["total_findings"] == 2

    def test_build_default_stages_includes_features_4_6(self):
        """build_default_stages() includes Feature 4-6 stages."""
        stages = build_default_stages({})
        stage_names = [s.name for s in stages]

        assert "phase0_5_incremental_filter" in stage_names
        assert "phase1_5_diff_finding_filter" in stage_names
        assert "phase2_7_fix_verification" in stage_names
        assert "phase3_5_agent_confidence" in stage_names

    def test_build_default_stages_ordering(self):
        """Feature 4-6 stages are ordered correctly after sorting (as orchestrator does)."""
        stages = build_default_stages({})
        # The orchestrator sorts by phase_number; verify constraints after sort
        stages_sorted = sorted(stages, key=lambda s: s.phase_number)
        phases = [(s.name, s.phase_number) for s in stages_sorted]
        phase_numbers = [p[1] for p in phases]

        # Verify sorted ordering
        assert phase_numbers == sorted(phase_numbers)

        # Verify specific ordering constraints
        name_to_phase = {name: phase for name, phase in phases}
        assert name_to_phase["phase0_5_incremental_filter"] < name_to_phase["phase1_scanner_orchestration"]
        assert name_to_phase["phase1_5_diff_finding_filter"] > name_to_phase["phase1_scanner_orchestration"]
        assert name_to_phase["phase2_7_fix_verification"] > name_to_phase["phase2_5_remediation"]
        assert name_to_phase["phase3_5_agent_confidence"] > name_to_phase["phase3_multi_agent_review"]

    def test_pipeline_degradation_when_features_disabled(self):
        """All feature 4-6 stages gracefully skip when disabled."""
        stages = [
            IncrementalScanFilter(),
            MockScannerStage(_make_findings()),
            DiffFindingFilter(),
            MockRemediationStage(),
            FixVerificationStage(),
            MockMultiAgentStage(),
            AgentConfidenceStage(),
            PolicyGateStage(),
            ReportingStage(),
        ]
        config = {
            "only_changed": False,
            "enable_fix_verification": False,
            "enable_agent_weighting": False,
            "enable_multi_agent": True,
        }
        orch = PipelineOrchestrator(stages=stages, config=config)
        ctx, results = orch.run("/tmp/repo")

        # All stages should still succeed
        assert all(r.success for r in results)

        # Feature 4-6 stages should be skipped
        incremental_r = next(r for r in results if r.stage_name == "phase0_5_incremental_filter")
        diff_r = next(r for r in results if r.stage_name == "phase1_5_diff_finding_filter")
        fv_r = next(r for r in results if r.stage_name == "phase2_7_fix_verification")
        ac_r = next(r for r in results if r.stage_name == "phase3_5_agent_confidence")

        assert incremental_r.skipped
        assert diff_r.skipped
        assert fv_r.skipped
        assert ac_r.skipped

        # But findings still pass through
        assert len(ctx.findings) == 4
