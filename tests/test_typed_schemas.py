"""
Tests for Feature 2: Typed Finding Schemas (Pydantic pipeline models)

Tests EvidenceData, BusinessContext, ConsensusResult, AgentVerdictSummary,
SandboxResult, PipelineFinding, PipelineMetadata, PipelineResult.
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from schemas.pipeline import (
    EvidenceData,
    BusinessContext,
    ConsensusResult,
    AgentVerdictSummary,
    SandboxResult,
    PipelineFinding,
    PipelineMetadata,
    PipelineResult,
)


# ============================================================================
# Test EvidenceData
# ============================================================================


class TestEvidenceData:
    def test_default_construction(self):
        ev = EvidenceData()
        assert ev.message == ""
        assert ev.snippet == ""

    def test_with_fields(self):
        ev = EvidenceData(
            message="SQL injection found",
            snippet="SELECT * FROM users WHERE id = ' + input",
            url="https://example.com/api",
            method="POST",
        )
        assert ev.message == "SQL injection found"
        assert ev.method == "POST"

    def test_extra_fields_preserved(self):
        ev = EvidenceData(message="test", custom_field="custom_value")
        assert ev.custom_field == "custom_value"

    def test_serialization_roundtrip(self):
        ev = EvidenceData(message="test", snippet="code")
        data = ev.model_dump()
        ev2 = EvidenceData(**data)
        assert ev2.message == "test"


# ============================================================================
# Test BusinessContext
# ============================================================================


class TestBusinessContext:
    def test_defaults(self):
        bc = BusinessContext()
        assert bc.service_tier == "internal"
        assert bc.exposure == "internal"
        assert bc.data_classification == "public"

    def test_custom(self):
        bc = BusinessContext(
            service_tier="public",
            exposure="external",
            data_classification="pii",
        )
        assert bc.service_tier == "public"


# ============================================================================
# Test ConsensusResult
# ============================================================================


class TestConsensusResult:
    def test_valid_construction(self):
        cr = ConsensusResult(
            votes=5,
            total_agents=5,
            consensus_level="unanimous",
            confidence=0.95,
            agents_agree=["SecretHunter", "ExploitAssessor", "ThreatModeler",
                          "FalsePositiveFilter", "ArchitectureReviewer"],
        )
        assert cr.votes == 5
        assert cr.consensus_level == "unanimous"

    def test_invalid_consensus_level(self):
        with pytest.raises(ValueError, match="consensus_level"):
            ConsensusResult(
                votes=1,
                total_agents=5,
                consensus_level="invalid",
                confidence=0.5,
                agents_agree=["agent1"],
            )

    def test_confidence_bounds(self):
        with pytest.raises(ValueError):
            ConsensusResult(
                votes=1,
                total_agents=5,
                consensus_level="weak",
                confidence=1.5,  # > 1.0
                agents_agree=["agent1"],
            )

    def test_all_levels(self):
        for level in ("unanimous", "strong", "majority", "weak"):
            cr = ConsensusResult(
                votes=1,
                total_agents=5,
                consensus_level=level,
                confidence=0.5,
                agents_agree=["a1"],
            )
            assert cr.consensus_level == level


# ============================================================================
# Test AgentVerdictSummary
# ============================================================================


class TestAgentVerdictSummary:
    def test_valid_construction(self):
        avs = AgentVerdictSummary(
            verdict="confirmed",
            confidence=0.9,
            reasoning="Multiple agents agree this is a real vulnerability",
            agreement_level="strong",
            agent_verdicts={"SecretHunter": "confirmed", "ExploitAssessor": "confirmed"},
            agents_analyzed=["SecretHunter", "ExploitAssessor"],
            evidence=["Hardcoded API key in config.py"],
            recommendations=["Rotate the key immediately"],
        )
        assert avs.verdict == "confirmed"
        assert len(avs.agents_analyzed) == 2

    def test_invalid_verdict(self):
        with pytest.raises(ValueError, match="verdict"):
            AgentVerdictSummary(
                verdict="maybe",
                confidence=0.5,
                reasoning="test",
                agreement_level="weak",
            )

    def test_all_verdicts(self):
        for v in ("confirmed", "likely_true", "uncertain", "likely_false", "false_positive"):
            avs = AgentVerdictSummary(
                verdict=v,
                confidence=0.5,
                reasoning="test",
                agreement_level="test",
            )
            assert avs.verdict == v


# ============================================================================
# Test SandboxResult
# ============================================================================


class TestSandboxResult:
    def test_default(self):
        sr = SandboxResult()
        assert not sr.validated
        assert sr.result is None

    def test_exploitable(self):
        sr = SandboxResult(
            validated=True,
            result="exploitable",
            execution_time_ms=1500,
            indicators_found=["command execution confirmed"],
        )
        assert sr.validated
        assert sr.result == "exploitable"

    def test_invalid_result(self):
        with pytest.raises(ValueError, match="result"):
            SandboxResult(result="unknown_status")

    def test_all_results(self):
        for r in ("exploitable", "not_exploitable", "partial", "error"):
            sr = SandboxResult(result=r)
            assert sr.result == r


# ============================================================================
# Test PipelineFinding
# ============================================================================


class TestPipelineFinding:
    def _make_finding(self, **overrides):
        base = {
            "id": "abc123",
            "origin": "semgrep",
            "repo": "test-repo",
            "commit_sha": "abc123def",
            "branch": "main",
            "path": "src/app.py",
        }
        base.update(overrides)
        return PipelineFinding(**base)

    def test_basic_construction(self):
        f = self._make_finding()
        assert f.id == "abc123"
        assert f.origin == "semgrep"
        assert f.title == ""
        assert f.consensus is None
        assert f.sandbox is None

    def test_with_consensus(self):
        cr = ConsensusResult(
            votes=3,
            total_agents=5,
            consensus_level="strong",
            confidence=0.85,
            agents_agree=["a1", "a2", "a3"],
        )
        f = self._make_finding(consensus=cr)
        assert f.consensus.votes == 3
        assert f.consensus.consensus_level == "strong"

    def test_with_sandbox(self):
        sr = SandboxResult(validated=True, result="exploitable")
        f = self._make_finding(sandbox=sr)
        assert f.sandbox.validated
        assert f.sandbox.result == "exploitable"

    def test_extra_fields_preserved(self):
        f = self._make_finding(custom_scanner_data="extra")
        assert f.custom_scanner_data == "extra"

    def test_inherits_unified_finding_validation(self):
        """Path validation from UnifiedFinding should still work."""
        with pytest.raises(ValueError):
            PipelineFinding(
                id="test",
                origin="test",
                repo="test",
                commit_sha="test",
                branch="test",
                path=".",  # Invalid path
            )

    def test_from_hybrid_finding(self):
        """Test conversion from HybridFinding dataclass."""

        @dataclass
        class MockHybridFinding:
            finding_id: str = "hf-001"
            source_tool: str = "semgrep"
            severity: str = "high"
            category: str = "security"
            title: str = "SQL Injection"
            description: str = "User input in query"
            file_path: str = "src/db.py"
            line_number: int = 42
            cwe_id: str = "CWE-89"
            cve_id: Optional[str] = None
            cvss_score: Optional[float] = 8.5
            exploitability: str = "trivial"
            recommendation: str = "Use parameterized queries"
            references: list = None
            confidence: float = 0.95
            llm_enriched: bool = True
            sandbox_validated: bool = False
            iris_verified: bool = False
            iris_confidence: Optional[float] = None
            iris_verdict: Optional[str] = None

            def __post_init__(self):
                if self.references is None:
                    self.references = []

        hf = MockHybridFinding()
        pf = PipelineFinding.from_hybrid_finding(hf)

        assert pf.id == "hf-001"
        assert pf.origin == "semgrep"
        assert str(pf.path) == "src/db.py"
        assert pf.line == 42
        assert pf.cwe == "CWE-89"
        assert pf.cvss == 8.5
        assert pf.title == "SQL Injection"
        assert pf.description == "User input in query"
        assert pf.llm_enriched

    def test_from_normalizer_finding(self):
        """Test conversion from normalizer Finding dataclass."""

        @dataclass
        class MockFinding:
            id: str = "nf-001"
            origin: str = "trivy"
            repo: str = "test-repo"
            commit_sha: str = "abc"
            branch: str = "main"
            path: str = "requirements.txt"
            asset_type: str = "code"
            severity: str = "critical"
            category: str = "DEPS"
            rule_id: str = "CVE-2023-1234"
            rule_name: str = "Critical dependency vulnerability"
            line: int = 10
            cve: str = "CVE-2023-1234"
            cwe: Optional[str] = None
            cvss: float = 9.8
            evidence: dict = None
            references: list = None
            reachability: str = "unknown"
            exploitability: str = "trivial"
            secret_verified: str = "na"
            owner_team: Optional[str] = None
            service_tier: str = "public"
            risk_score: float = 0.0
            noise_score: float = 0.0
            false_positive_probability: float = 0.0
            historical_fix_rate: float = 0.0
            correlation_group_id: Optional[str] = None
            business_context: dict = None
            suppression_id: Optional[str] = None
            suppression_expires_at: Optional[str] = None
            suppression_reason: Optional[str] = None
            auto_fixable: bool = False
            fix_suggestion: Optional[str] = None
            fix_confidence: float = 0.0
            first_seen_at: str = "2024-01-01T00:00:00Z"
            last_seen_at: str = "2024-01-01T00:00:00Z"
            status: str = "open"
            llm_enriched: bool = False
            confidence: float = 1.0
            pr_number: Optional[int] = None
            resource_id: Optional[str] = None
            stride: Optional[str] = None

            def __post_init__(self):
                if self.evidence is None:
                    self.evidence = {}
                if self.references is None:
                    self.references = []
                if self.business_context is None:
                    self.business_context = {
                        "service_tier": "internal",
                        "exposure": "internal",
                        "data_classification": "public",
                    }

        nf = MockFinding()
        pf = PipelineFinding.from_normalizer_finding(nf)
        assert pf.id == "nf-001"
        assert pf.origin == "trivy"
        assert pf.severity == "critical"
        assert pf.cve == "CVE-2023-1234"

    def test_serialization_roundtrip(self):
        f = self._make_finding(
            severity="high",
            title="Test Finding",
            consensus=ConsensusResult(
                votes=3,
                total_agents=5,
                consensus_level="strong",
                confidence=0.85,
                agents_agree=["a1", "a2", "a3"],
            ),
        )
        # Serialize to JSON
        json_str = f.model_dump_json()
        data = json.loads(json_str)
        assert data["title"] == "Test Finding"
        assert data["consensus"]["votes"] == 3


# ============================================================================
# Test PipelineResult
# ============================================================================


class TestPipelineResult:
    def _make_result(self, findings=None):
        if findings is None:
            findings = [
                PipelineFinding(
                    id="f1", origin="semgrep", repo="r", commit_sha="c",
                    branch="main", path="a.py", severity="critical",
                ),
                PipelineFinding(
                    id="f2", origin="trivy", repo="r", commit_sha="c",
                    branch="main", path="b.py", severity="high",
                ),
                PipelineFinding(
                    id="f3", origin="semgrep", repo="r", commit_sha="c",
                    branch="main", path="c.py", severity="medium",
                ),
            ]
        return PipelineResult(
            findings=findings,
            metadata=PipelineMetadata(
                repository="test-repo",
                provider="anthropic",
                model="claude-sonnet-4-5-20250929",
            ),
        )

    def test_findings_by_severity(self):
        pr = self._make_result()
        counts = pr.findings_by_severity()
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1

    def test_findings_by_source(self):
        pr = self._make_result()
        counts = pr.findings_by_source()
        assert counts["semgrep"] == 2
        assert counts["trivy"] == 1

    def test_critical_findings(self):
        pr = self._make_result()
        crits = pr.critical_findings()
        assert len(crits) == 1
        assert crits[0].id == "f1"

    def test_empty_result(self):
        pr = self._make_result(findings=[])
        assert pr.findings_by_severity() == {}
        assert pr.critical_findings() == []

    def test_metadata_defaults(self):
        meta = PipelineMetadata()
        assert meta.version == "1.0.0"
        assert meta.timestamp != ""
        assert meta.findings_summary == {}
