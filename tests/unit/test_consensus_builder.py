#!/usr/bin/env python3
"""
Unit Tests for Consensus Builder

Tests cover:
- ConsensusBuilder initialization
- Finding aggregation with AST deduplication
- Consensus level calculation (unanimous, strong, majority, weak)
- Severity merging (most severe wins)
- Message enhancement with vote counts
- Sorting by votes and confidence
- filter_by_threshold
- Edge cases (empty findings, single agent, duplicate keys)
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from consensus_builder import ConsensusBuilder

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestConsensusBuilderInit:
    """Test ConsensusBuilder initialization"""

    @patch("consensus_builder.ASTDeduplicator")
    def test_initialization(self, mock_dedup_class):
        agents = ["security", "performance", "quality"]
        builder = ConsensusBuilder(agents)
        assert builder.agents == agents
        assert builder.total_agents == 3
        assert builder.deduplicator is not None

    @patch("consensus_builder.ASTDeduplicator")
    def test_initialization_single_agent(self, mock_dedup_class):
        builder = ConsensusBuilder(["agent1"])
        assert builder.total_agents == 1

    @patch("consensus_builder.ASTDeduplicator")
    def test_initialization_five_agents(self, mock_dedup_class):
        agents = ["sec", "perf", "quality", "testing", "arch"]
        builder = ConsensusBuilder(agents)
        assert builder.total_agents == 5


# ---------------------------------------------------------------------------
# Aggregate Findings
# ---------------------------------------------------------------------------


class TestAggregateFindings:
    """Test aggregate_findings"""

    @patch("consensus_builder.ASTDeduplicator")
    def setup_method(self, method, mock_dedup_class=None):
        mock_dedup = MagicMock()
        if mock_dedup_class:
            mock_dedup_class.return_value = mock_dedup
        else:
            with patch("consensus_builder.ASTDeduplicator") as mdc:
                mdc.return_value = mock_dedup
                self.builder = ConsensusBuilder(["agent_a", "agent_b", "agent_c"])
                self.mock_dedup = mock_dedup
                return

        self.builder = ConsensusBuilder(["agent_a", "agent_b", "agent_c"])
        self.mock_dedup = mock_dedup

    def test_unanimous_agreement(self):
        """All 3 agents agree on the same finding"""
        self.mock_dedup.create_dedup_key.return_value = "key_sql_injection"

        finding = {"id": "f1", "severity": "high", "message": "SQL injection in api.py"}
        agent_findings = {
            "agent_a": [finding.copy()],
            "agent_b": [finding.copy()],
            "agent_c": [finding.copy()],
        }

        result = self.builder.aggregate_findings(agent_findings)
        assert len(result) == 1
        assert result[0]["consensus"]["votes"] == 3
        assert result[0]["consensus"]["consensus_level"] == "unanimous"
        assert result[0]["consensus"]["confidence"] == 0.95

    def test_majority_agreement(self):
        """2 of 3 agents agree (66.7%) — below 0.67 threshold so it's majority, not strong"""
        self.mock_dedup.create_dedup_key.return_value = "key_xss"

        finding = {"id": "f1", "severity": "medium", "message": "XSS in template"}
        agent_findings = {
            "agent_a": [finding.copy()],
            "agent_b": [finding.copy()],
            "agent_c": [],
        }

        result = self.builder.aggregate_findings(agent_findings)
        assert len(result) == 1
        assert result[0]["consensus"]["votes"] == 2
        assert result[0]["consensus"]["consensus_level"] == "majority"
        assert result[0]["consensus"]["confidence"] == 0.70

    def test_weak_agreement(self):
        """1 of 3 agents (33%)"""
        self.mock_dedup.create_dedup_key.return_value = "key_info_leak"

        finding = {"id": "f1", "severity": "low", "message": "Info leak"}
        agent_findings = {
            "agent_a": [finding.copy()],
            "agent_b": [],
            "agent_c": [],
        }

        result = self.builder.aggregate_findings(agent_findings)
        assert len(result) == 1
        assert result[0]["consensus"]["votes"] == 1
        assert result[0]["consensus"]["consensus_level"] == "weak"
        assert result[0]["consensus"]["confidence"] == 0.50

    def test_empty_findings(self):
        """No findings from any agent"""
        agent_findings = {
            "agent_a": [],
            "agent_b": [],
            "agent_c": [],
        }
        result = self.builder.aggregate_findings(agent_findings)
        assert result == []

    def test_multiple_distinct_findings(self):
        """Different findings get separate groups"""

        def side_effect(finding):
            # Use message to differentiate
            if "SQL" in finding.get("message", ""):
                return "key_sql"
            return "key_xss"

        self.mock_dedup.create_dedup_key.side_effect = side_effect

        agent_findings = {
            "agent_a": [
                {"id": "f1", "severity": "high", "message": "SQL injection"},
                {"id": "f2", "severity": "medium", "message": "XSS vulnerability"},
            ],
            "agent_b": [
                {"id": "f3", "severity": "high", "message": "SQL injection in query"},
            ],
            "agent_c": [],
        }

        result = self.builder.aggregate_findings(agent_findings)
        assert len(result) == 2

    def test_severity_merging_most_severe_wins(self):
        """When agents disagree on severity, most severe wins"""
        self.mock_dedup.create_dedup_key.return_value = "key_same"

        agent_findings = {
            "agent_a": [{"id": "f1", "severity": "medium", "message": "Issue"}],
            "agent_b": [{"id": "f2", "severity": "critical", "message": "Same issue"}],
            "agent_c": [{"id": "f3", "severity": "high", "message": "Same issue"}],
        }

        result = self.builder.aggregate_findings(agent_findings)
        assert len(result) == 1
        assert result[0]["severity"] == "critical"

    def test_message_enhancement_with_votes(self):
        """Multi-vote findings get enhanced message"""
        self.mock_dedup.create_dedup_key.return_value = "key_same"

        finding = {"id": "f1", "severity": "high", "message": "SQL injection"}
        agent_findings = {
            "agent_a": [finding.copy()],
            "agent_b": [finding.copy()],
            "agent_c": [],
        }

        result = self.builder.aggregate_findings(agent_findings)
        assert "[2/3 agents agree]" in result[0]["message"]

    def test_single_vote_no_message_prefix(self):
        """Single-vote findings keep original message"""
        self.mock_dedup.create_dedup_key.return_value = "key_solo"

        finding = {"id": "f1", "severity": "low", "message": "Minor issue"}
        agent_findings = {
            "agent_a": [finding.copy()],
            "agent_b": [],
            "agent_c": [],
        }

        result = self.builder.aggregate_findings(agent_findings)
        assert "agents agree" not in result[0]["message"]

    def test_sorting_by_votes_then_confidence(self):
        """Results sorted by votes descending, then confidence descending"""

        def side_effect(finding):
            msg = finding.get("message", "")
            if "A" in msg:
                return "key_a"
            elif "B" in msg:
                return "key_b"
            return "key_c"

        self.mock_dedup.create_dedup_key.side_effect = side_effect

        agent_findings = {
            "agent_a": [
                {"id": "f1", "severity": "high", "message": "Finding A"},
                {"id": "f2", "severity": "medium", "message": "Finding B"},
            ],
            "agent_b": [
                {"id": "f3", "severity": "high", "message": "Finding A"},
                {"id": "f4", "severity": "medium", "message": "Finding B"},
            ],
            "agent_c": [
                {"id": "f5", "severity": "high", "message": "Finding A"},
            ],
        }

        result = self.builder.aggregate_findings(agent_findings)
        # Finding A has 3 votes, Finding B has 2 votes
        assert result[0]["consensus"]["votes"] >= result[1]["consensus"]["votes"]

    def test_agents_agree_list(self):
        """consensus should track which agents agreed"""
        self.mock_dedup.create_dedup_key.return_value = "key_same"

        agent_findings = {
            "agent_a": [{"id": "f1", "severity": "high", "message": "Issue"}],
            "agent_b": [{"id": "f2", "severity": "high", "message": "Issue"}],
            "agent_c": [],
        }

        result = self.builder.aggregate_findings(agent_findings)
        assert "agent_a" in result[0]["consensus"]["agents_agree"]
        assert "agent_b" in result[0]["consensus"]["agents_agree"]
        assert "agent_c" not in result[0]["consensus"]["agents_agree"]

    def test_all_descriptions_collected(self):
        """All agent descriptions should be collected"""
        self.mock_dedup.create_dedup_key.return_value = "key_same"

        agent_findings = {
            "agent_a": [{"id": "f1", "severity": "high", "message": "SQL injection in query"}],
            "agent_b": [{"id": "f2", "severity": "high", "message": "SQL injection vulnerability"}],
            "agent_c": [],
        }

        result = self.builder.aggregate_findings(agent_findings)
        all_desc = result[0]["consensus"]["all_descriptions"]
        assert len(all_desc) == 2


# ---------------------------------------------------------------------------
# Majority consensus (exactly 50% with even agents)
# ---------------------------------------------------------------------------


class TestMajorityConsensus:
    """Test majority consensus level"""

    @patch("consensus_builder.ASTDeduplicator")
    def test_majority_with_four_agents(self, mock_dedup_class):
        mock_dedup = MagicMock()
        mock_dedup_class.return_value = mock_dedup
        mock_dedup.create_dedup_key.return_value = "key_same"

        builder = ConsensusBuilder(["a1", "a2", "a3", "a4"])
        agent_findings = {
            "a1": [{"id": "f1", "severity": "medium", "message": "Issue"}],
            "a2": [{"id": "f2", "severity": "medium", "message": "Issue"}],
            "a3": [],
            "a4": [],
        }
        result = builder.aggregate_findings(agent_findings)
        # 2/4 = 50% -> majority
        assert result[0]["consensus"]["consensus_level"] == "majority"
        assert result[0]["consensus"]["confidence"] == 0.70


# ---------------------------------------------------------------------------
# filter_by_threshold
# ---------------------------------------------------------------------------


class TestFilterByThreshold:
    """Test filter_by_threshold"""

    @patch("consensus_builder.ASTDeduplicator")
    def setup_method(self, method, mock_dedup_class=None):
        with patch("consensus_builder.ASTDeduplicator"):
            self.builder = ConsensusBuilder(["a", "b", "c"])

    def test_filter_keeps_high_confidence(self):
        findings = [
            {"consensus": {"confidence": 0.95}},
            {"consensus": {"confidence": 0.50}},
            {"consensus": {"confidence": 0.85}},
        ]
        result = self.builder.filter_by_threshold(findings, min_confidence=0.8)
        assert len(result) == 2

    def test_filter_removes_all_below(self):
        findings = [
            {"consensus": {"confidence": 0.30}},
            {"consensus": {"confidence": 0.40}},
        ]
        result = self.builder.filter_by_threshold(findings, min_confidence=0.5)
        assert len(result) == 0

    def test_filter_keeps_all_above(self):
        findings = [
            {"consensus": {"confidence": 0.90}},
            {"consensus": {"confidence": 0.80}},
        ]
        result = self.builder.filter_by_threshold(findings, min_confidence=0.5)
        assert len(result) == 2

    def test_filter_default_threshold(self):
        findings = [
            {"consensus": {"confidence": 0.60}},
            {"consensus": {"confidence": 0.40}},
        ]
        result = self.builder.filter_by_threshold(findings)
        assert len(result) == 1  # Default is 0.5, so 0.60 passes

    def test_filter_empty_findings(self):
        result = self.builder.filter_by_threshold([], min_confidence=0.5)
        assert result == []

    def test_filter_missing_consensus_key(self):
        """Findings without consensus key should be filtered out"""
        findings = [{"id": "f1"}, {"consensus": {"confidence": 0.95}}]
        result = self.builder.filter_by_threshold(findings, min_confidence=0.5)
        assert len(result) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
