"""
Tests for Feature 6: Agent Confidence Weighting (agent_confidence.py).

Tests AgentAccuracyTracker, WeightedConsensusBuilder, AgentConfidenceStage.
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from agent_confidence import (
    AGENT_NAMES,
    CATEGORIES,
    SMOOTHING_N,
    SMOOTHING_PRIOR,
    WEIGHT_MAX,
    WEIGHT_MIN,
    AgentAccuracyTracker,
    AgentConfidenceStage,
    WeightedConsensusBuilder,
    _compute_weighted_score,
    _get_category,
    _get_consensus,
    _update_consensus,
)
from pipeline.protocol import PipelineContext


# ============================================================================
# AgentAccuracyTracker - Expert Priors
# ============================================================================


class TestAgentAccuracyTrackerDefaults:
    def test_default_weights_loaded(self):
        tracker = AgentAccuracyTracker()
        matrix = tracker.get_weight_matrix()
        assert "SecretHunter" in matrix
        assert "ExploitAssessor" in matrix
        assert len(matrix) == 5

    def test_secret_hunter_strongest_on_secrets(self):
        tracker = AgentAccuracyTracker()
        w = tracker.get_agent_weight("SecretHunter", "SECRETS")
        assert w == 1.8
        # And weaker on IAC
        w_iac = tracker.get_agent_weight("SecretHunter", "IAC")
        assert w_iac < w

    def test_exploit_assessor_strongest_on_sast(self):
        tracker = AgentAccuracyTracker()
        w = tracker.get_agent_weight("ExploitAssessor", "SAST")
        assert w == 1.6

    def test_threat_modeler_strongest_on_iac(self):
        tracker = AgentAccuracyTracker()
        w = tracker.get_agent_weight("ThreatModeler", "IAC")
        assert w == 1.5

    def test_unknown_agent_returns_1(self):
        tracker = AgentAccuracyTracker()
        assert tracker.get_agent_weight("UnknownAgent", "SAST") == 1.0

    def test_unknown_category_returns_1(self):
        tracker = AgentAccuracyTracker()
        assert tracker.get_agent_weight("SecretHunter", "UNKNOWN_CAT") == 1.0

    def test_weight_clamping(self):
        """Weights are clamped to [WEIGHT_MIN, WEIGHT_MAX]."""
        tracker = AgentAccuracyTracker()
        # All default weights should be within bounds
        for agent, cats in tracker.get_weight_matrix().items():
            for cat, w in cats.items():
                assert WEIGHT_MIN <= w <= WEIGHT_MAX

    def test_case_insensitive_category(self):
        tracker = AgentAccuracyTracker()
        w_upper = tracker.get_agent_weight("SecretHunter", "SECRETS")
        w_lower = tracker.get_agent_weight("SecretHunter", "secrets")
        assert w_upper == w_lower


# ============================================================================
# AgentAccuracyTracker - Feedback DB
# ============================================================================


class TestAgentAccuracyTrackerFeedback:
    def _create_db_with_outcomes(self, db_path: str, outcomes: list):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE agent_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL,
                category TEXT NOT NULL,
                agent_verdict TEXT NOT NULL,
                actual_verdict TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE INDEX idx_agent_outcomes_agent_cat
            ON agent_outcomes(agent_name, category)
        """)
        for agent, cat, a_v, act_v in outcomes:
            cursor.execute(
                "INSERT INTO agent_outcomes (agent_name, category, agent_verdict, actual_verdict) "
                "VALUES (?, ?, ?, ?)",
                (agent, cat, a_v, act_v),
            )
        conn.commit()
        conn.close()

    def test_feedback_db_loaded(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        # SecretHunter is 100% accurate on SECRETS (10 correct, 0 incorrect)
        outcomes = [
            ("SecretHunter", "SECRETS", "confirmed", "true_positive")
            for _ in range(10)
        ]
        self._create_db_with_outcomes(db_path, outcomes)

        tracker = AgentAccuracyTracker(feedback_db_path=db_path)
        w = tracker.get_agent_weight("SecretHunter", "SECRETS")
        # With 10 correct + 10*0.5 prior = 15 / (10+10) = 0.75, weight = 1.25
        assert w > 1.0

    def test_feedback_db_bad_accuracy(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        # ThreatModeler is 0% accurate on SECRETS (10 incorrect)
        outcomes = [
            ("ThreatModeler", "SECRETS", "confirmed", "false_positive")
            for _ in range(10)
        ]
        self._create_db_with_outcomes(db_path, outcomes)

        tracker = AgentAccuracyTracker(feedback_db_path=db_path)
        w = tracker.get_agent_weight("ThreatModeler", "SECRETS")
        # With 0 correct + 10*0.5 prior = 5 / (10+10) = 0.25, weight = 0.75
        assert w < 1.0

    def test_record_outcome(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        tracker = AgentAccuracyTracker(feedback_db_path=db_path)
        tracker.record_outcome("SecretHunter", "SECRETS", "confirmed", "true_positive")

        # Verify it was written
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM agent_outcomes")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 1

    def test_record_outcome_no_db(self):
        """No crash when no feedback DB is configured."""
        tracker = AgentAccuracyTracker()
        tracker.record_outcome("SecretHunter", "SECRETS", "confirmed", "true_positive")

    def test_nonexistent_db_path(self):
        """Non-existent DB path falls back to defaults."""
        tracker = AgentAccuracyTracker(feedback_db_path="/tmp/nonexistent.db")
        matrix = tracker.get_weight_matrix()
        assert "SecretHunter" in matrix


# ============================================================================
# WeightedConsensusBuilder
# ============================================================================


class TestWeightedConsensusBuilder:
    def _make_builder(self) -> WeightedConsensusBuilder:
        tracker = AgentAccuracyTracker()
        return WeightedConsensusBuilder(agents=list(AGENT_NAMES), tracker=tracker)

    def test_aggregate_single_agent(self):
        builder = self._make_builder()
        agent_findings = {
            "SecretHunter": [
                {"path": "config.py", "rule_id": "hardcoded-secret", "line": 10,
                 "severity": "high", "category": "SECRETS", "message": "Found secret"},
            ],
        }
        results = builder.aggregate_findings(agent_findings)
        assert len(results) == 1
        c = results[0]["consensus"]
        assert c["votes"] == 1
        assert c["total_agents"] == 5
        assert c["weighted_score"] > 0

    def test_aggregate_unanimous(self):
        """All 5 agents agree -> unanimous consensus."""
        builder = self._make_builder()
        finding = {
            "path": "app.py", "rule_id": "sqli", "line": 42,
            "severity": "critical", "category": "SAST", "message": "SQL Injection",
        }
        agent_findings = {name: [dict(finding)] for name in AGENT_NAMES}
        results = builder.aggregate_findings(agent_findings)
        assert len(results) == 1
        c = results[0]["consensus"]
        assert c["votes"] == 5
        assert c["consensus_level"] == "unanimous"
        assert c["confidence"] == 0.95

    def test_aggregate_strong_consensus(self):
        """3-4 agents agree -> strong consensus."""
        builder = self._make_builder()
        finding = {
            "path": "a.py", "rule_id": "xss", "line": 5,
            "severity": "high", "category": "SAST", "message": "XSS",
        }
        agent_findings = {
            "SecretHunter": [dict(finding)],
            "ExploitAssessor": [dict(finding)],
            "ArchitectureReviewer": [dict(finding)],
        }
        results = builder.aggregate_findings(agent_findings)
        c = results[0]["consensus"]
        assert c["votes"] == 3
        assert c["consensus_level"] in ("strong", "majority")

    def test_severity_takes_most_severe(self):
        """Multiple agents with different severities -> most severe wins."""
        builder = self._make_builder()
        agent_findings = {
            "SecretHunter": [
                {"path": "a.py", "rule_id": "x", "line": 10,
                 "severity": "high", "category": "SAST", "message": "A"},
            ],
            "ExploitAssessor": [
                {"path": "a.py", "rule_id": "x", "line": 10,
                 "severity": "critical", "category": "SAST", "message": "B"},
            ],
        }
        results = builder.aggregate_findings(agent_findings)
        assert results[0]["severity"] == "critical"

    def test_filter_by_threshold(self):
        builder = self._make_builder()
        findings = [
            {"consensus": {"confidence": 0.95}},
            {"consensus": {"confidence": 0.50}},
            {"consensus": {"confidence": 0.30}},
        ]
        filtered = builder.filter_by_threshold(findings, min_confidence=0.5)
        assert len(filtered) == 2

    def test_dedup_key(self):
        key = WeightedConsensusBuilder._create_dedup_key(
            {"path": "a.py", "rule_id": "sqli", "line": 42}
        )
        assert "a.py" in key
        assert "sqli" in key

    def test_dedup_key_attr(self):
        @dataclass
        class F:
            file_path: str = "b.py"
            rule_id: str = "xss"
            line: int = 15

        key = WeightedConsensusBuilder._create_dedup_key(F())
        assert "b.py" in key

    def test_extract_category_dict(self):
        assert WeightedConsensusBuilder._extract_category({"category": "SECRETS"}) == "SECRETS"
        assert WeightedConsensusBuilder._extract_category({}) == "SAST"

    def test_copy_finding_dict(self):
        original = {"id": "f1", "severity": "high"}
        copy = WeightedConsensusBuilder._copy_finding(original)
        assert copy == original
        assert copy is not original

    def test_weighted_score_reflects_expertise(self):
        """SecretHunter's weight on SECRETS finding should exceed ThreatModeler's."""
        builder = self._make_builder()
        secret_finding = {
            "path": "creds.py", "rule_id": "hardcoded-key", "line": 1,
            "severity": "critical", "category": "SECRETS", "message": "Hardcoded key",
        }

        # Only SecretHunter agrees
        r1 = builder.aggregate_findings({"SecretHunter": [dict(secret_finding)]})
        sh_score = r1[0]["consensus"]["weighted_score"]

        # Only ThreatModeler agrees
        r2 = builder.aggregate_findings({"ThreatModeler": [dict(secret_finding)]})
        tm_score = r2[0]["consensus"]["weighted_score"]

        # SecretHunter should carry more weight on SECRETS
        assert sh_score > tm_score


# ============================================================================
# Helper functions
# ============================================================================


class TestHelpers:
    def test_get_consensus_dict(self):
        f = {"consensus": {"votes": 3}}
        assert _get_consensus(f) == {"votes": 3}

    def test_get_consensus_attr(self):
        @dataclass
        class F:
            consensus: dict = None

            def __post_init__(self):
                self.consensus = {"votes": 2}

        assert _get_consensus(F())["votes"] == 2

    def test_get_consensus_none(self):
        assert _get_consensus({"severity": "high"}) is None

    def test_get_category_dict(self):
        assert _get_category({"category": "DEPS"}) == "DEPS"
        assert _get_category({}) == "SAST"

    def test_get_category_lowercase(self):
        assert _get_category({"category": "secrets"}) == "SECRETS"

    def test_compute_weighted_score(self):
        tracker = AgentAccuracyTracker()
        consensus = {
            "agents_agree": ["SecretHunter", "FalsePositiveFilter"],
            "total_agents": 5,
            "votes": 2,
        }
        score = _compute_weighted_score(consensus, "SECRETS", tracker)
        assert 0 < score < 1

    def test_compute_weighted_score_no_agents(self):
        tracker = AgentAccuracyTracker()
        consensus = {"agents_agree": [], "total_agents": 5, "votes": 0}
        score = _compute_weighted_score(consensus, "SAST", tracker)
        assert score == 0.0

    def test_update_consensus_unanimous(self):
        finding = {"consensus": {"agents_agree": ["a"], "votes": 1}}
        _update_consensus(finding, 0.90)
        assert finding["consensus"]["consensus_level"] == "unanimous"
        assert finding["consensus"]["confidence"] == 0.95

    def test_update_consensus_weak(self):
        finding = {"consensus": {"agents_agree": ["a"], "votes": 1}}
        _update_consensus(finding, 0.20)
        assert finding["consensus"]["consensus_level"] == "weak"
        assert finding["consensus"]["confidence"] == 0.50


# ============================================================================
# AgentConfidenceStage (Pipeline Stage)
# ============================================================================


class TestAgentConfidenceStage:
    def _make_ctx(
        self,
        enable_weighting: bool = True,
        enable_multi_agent: bool = True,
    ) -> PipelineContext:
        return PipelineContext(
            config={
                "enable_agent_weighting": enable_weighting,
                "enable_multi_agent": enable_multi_agent,
            },
            target_path="/tmp/repo",
        )

    def test_should_run_enabled(self):
        stage = AgentConfidenceStage()
        ctx = self._make_ctx()
        ctx.findings = [{"severity": "high"}]
        assert stage.should_run(ctx) is True

    def test_should_run_disabled(self):
        stage = AgentConfidenceStage()
        ctx = self._make_ctx(enable_weighting=False)
        ctx.findings = [{"severity": "high"}]
        assert stage.should_run(ctx) is False

    def test_should_run_no_multi_agent(self):
        stage = AgentConfidenceStage()
        ctx = self._make_ctx(enable_multi_agent=False)
        ctx.findings = [{"severity": "high"}]
        assert stage.should_run(ctx) is False

    def test_should_run_no_findings(self):
        stage = AgentConfidenceStage()
        ctx = self._make_ctx()
        assert stage.should_run(ctx) is False

    def test_name_and_phase(self):
        stage = AgentConfidenceStage()
        assert stage.name == "phase3_5_agent_confidence"
        assert stage.phase_number == 3.5
        assert "phase3_multi_agent_review" in stage.required_stages

    def test_execute_rescores_findings(self):
        stage = AgentConfidenceStage()
        ctx = self._make_ctx()
        ctx.findings = [
            {
                "severity": "high",
                "category": "SECRETS",
                "consensus": {
                    "votes": 2,
                    "total_agents": 5,
                    "agents_agree": ["SecretHunter", "FalsePositiveFilter"],
                    "consensus_level": "majority",
                    "confidence": 0.70,
                    "weighted_score": 0.40,
                },
            },
        ]
        result = stage.execute(ctx)
        assert result.success
        assert result.metadata["rescored"] == 1
        # Weighted score should have been updated
        c = ctx.findings[0]["consensus"]
        assert c["weighted_score"] != 0.40

    def test_execute_no_consensus(self):
        """Findings without consensus data are not rescored."""
        stage = AgentConfidenceStage()
        ctx = self._make_ctx()
        ctx.findings = [{"severity": "low", "category": "SAST"}]
        result = stage.execute(ctx)
        assert result.success
        assert result.metadata["rescored"] == 0

    def test_execute_returns_weight_matrix(self):
        stage = AgentConfidenceStage()
        ctx = self._make_ctx()
        ctx.findings = [{"severity": "high"}]
        result = stage.execute(ctx)
        assert "weight_matrix" in result.metadata
        assert "SecretHunter" in result.metadata["weight_matrix"]
