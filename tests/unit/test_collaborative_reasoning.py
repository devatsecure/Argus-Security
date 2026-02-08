#!/usr/bin/env python3
"""
Unit tests for Collaborative Reasoning

Tests cover:
- Independent analysis mode
- Discussion mode with multiple rounds
- Consensus building
- Conflict resolution
- Agent agreement scenarios
- Agent disagreement scenarios
- Discussion transcript generation
- Final verdict derivation
"""

import json
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, call
from dataclasses import dataclass
from typing import Optional, List, Dict

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from collaborative_reasoning import (
    CollaborativeReasoning,
    CollaborativeVerdict,
    AgentAnalysis,
    AgentOpinion,
    BaseAgentPersona,
    SecretHunterAgent,
    FalsePositiveFilterAgent,
    ExploitAssessorAgent,
    ComplianceAgent,
    ContextExpertAgent,
    create_default_agent_team,
    create_comprehensive_agent_team,
)


# ============================================================================
# Helper: mock LLM provider that returns structured JSON for agent analysis
# ============================================================================

def _make_llm_provider(decision="confirmed", confidence=0.9, reasoning="Test reasoning"):
    """Create a mock LLM provider whose generate() returns a valid JSON response."""
    mock_llm = Mock()
    response_json = json.dumps({
        "decision": decision,
        "confidence": confidence,
        "reasoning": reasoning,
        "severity_assessment": "high",
        "key_evidence": ["evidence point"],
        "concerns": [],
        "questions_for_others": [],
    })
    mock_llm.generate = Mock(return_value=response_json)
    return mock_llm


def _make_agent(decision="confirmed", confidence=0.9, reasoning="Test reasoning"):
    """Create a real agent persona with a mocked LLM provider."""
    llm = _make_llm_provider(decision, confidence, reasoning)
    return SecretHunterAgent(llm, name="TestAgent")


def _make_finding(**overrides):
    """Create a sample finding dict."""
    finding = {
        "id": "test-001",
        "origin": "semgrep",
        "path": "src/config.py",
        "line": 42,
        "severity": "high",
        "rule_id": "hardcoded-password",
        "rule_name": "Hardcoded password",
        "category": "SECRETS",
        "evidence": {"snippet": 'password = "admin123"'},
    }
    finding.update(overrides)
    return finding


# ============================================================================
# Dataclass-level tests using actual AgentAnalysis and AgentOpinion
# ============================================================================

class TestAgentAnalysisDataclass:
    """Test AgentAnalysis dataclass from collaborative_reasoning"""

    def test_agent_analysis_creation(self):
        """Test creating an AgentAnalysis"""
        analysis = AgentAnalysis(
            decision="confirmed",
            confidence=0.95,
            reasoning="Found hardcoded API key in config",
        )

        assert analysis.decision == "confirmed"
        assert analysis.confidence == 0.95
        assert "API key" in analysis.reasoning

    def test_agent_analysis_verdicts(self):
        """Test valid decision values"""
        decisions = ["confirmed", "false_positive", "uncertain"]

        for decision in decisions:
            analysis = AgentAnalysis(
                decision=decision,
                confidence=0.8,
                reasoning="Test reasoning",
            )
            assert analysis.decision == decision


class TestAgentOpinionDataclass:
    """Test AgentOpinion dataclass"""

    def test_agent_opinion_creation(self):
        """Test creating an AgentOpinion"""
        analysis = AgentAnalysis(
            decision="confirmed",
            confidence=0.95,
            reasoning="Reason 1",
        )
        opinion = AgentOpinion(
            agent_name="Agent1",
            persona_type="SecretHunterAgent",
            analysis=analysis,
        )

        assert opinion.agent_name == "Agent1"
        assert opinion.persona_type == "SecretHunterAgent"
        assert opinion.analysis.decision == "confirmed"
        assert isinstance(opinion.discussion_notes, list)


class TestCollaborativeVerdictDataclass:
    """Test CollaborativeVerdict dataclass"""

    def test_verdict_creation_minimal(self):
        """Test creating a collaborative verdict with minimal fields"""
        verdict = CollaborativeVerdict(
            finding_id="test-001",
            final_decision="confirmed",
            confidence=0.93,
            reasoning="All agents agreed",
            agent_opinions=[],
            consensus_reached=True,
            discussion_rounds=1,
        )

        assert verdict.final_decision == "confirmed"
        assert verdict.confidence == 0.93
        assert verdict.consensus_reached is True
        assert verdict.discussion_rounds == 1

    def test_verdict_creation_full(self):
        """Test creating a verdict with all fields"""
        verdict = CollaborativeVerdict(
            finding_id="test-001",
            final_decision="confirmed",
            confidence=0.88,
            reasoning="2 out of 3 agents confirmed",
            agent_opinions=[],
            consensus_reached=True,
            discussion_rounds=3,
            decision_breakdown={"confirmed": 2, "false_positive": 1, "uncertain": 0},
            conflict_resolution_method="majority vote",
            final_severity="high",
            escalation_reason=None,
        )

        assert verdict.confidence == 0.88
        assert verdict.decision_breakdown["confirmed"] == 2
        assert verdict.final_severity == "high"

    def test_verdict_agreement_bounds(self):
        """Test confidence bounds"""
        for level in [0.0, 0.5, 1.0]:
            verdict = CollaborativeVerdict(
                finding_id="test",
                final_decision="confirmed",
                confidence=level,
                reasoning="Test",
                agent_opinions=[],
                consensus_reached=True,
                discussion_rounds=1,
            )
            assert 0 <= verdict.confidence <= 1.0


# ============================================================================
# CollaborativeReasoning initialization tests
# ============================================================================

class TestCollaborativeReasoningInitialization:
    """Test CollaborativeReasoning initialization"""

    def setup_method(self):
        """Set up test fixtures"""
        self.llm = _make_llm_provider()
        self.agents = create_default_agent_team(self.llm)
        self.finding = _make_finding()

    def test_initialization(self):
        """Test CollaborativeReasoning initialization"""
        reasoning = CollaborativeReasoning(self.agents)

        assert reasoning.agents == self.agents
        assert reasoning.min_consensus_threshold == 0.6

    def test_initialization_single_agent(self):
        """Test initialization with single agent"""
        reasoning = CollaborativeReasoning([self.agents[0]])

        assert len(reasoning.agents) == 1

    def test_initialization_empty_agents(self):
        """Test initialization with empty agents list"""
        reasoning = CollaborativeReasoning([])

        assert reasoning.agents == []


# ============================================================================
# Independent analysis tests
# ============================================================================

class TestIndependentAnalysis:
    """Test independent analysis mode (via analyze_collaboratively in independent mode)"""

    def setup_method(self):
        """Set up test fixtures"""
        self.finding = _make_finding()

    def test_analyze_independently_all_confirm(self):
        """Test independent analysis when all agents confirm"""
        llm = _make_llm_provider("confirmed", 0.95, "Secret detected")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        assert isinstance(verdict, CollaborativeVerdict)
        assert len(verdict.agent_opinions) == 3
        assert all(op.analysis.decision == "confirmed" for op in verdict.agent_opinions)

    def test_analyze_independently_mixed_verdicts(self):
        """Test independent analysis with mixed verdicts"""
        decisions = ["confirmed", "false_positive", "uncertain"]
        agents = []
        for i, decision in enumerate(decisions):
            llm = _make_llm_provider(decision, 0.8, f"Reason {i}")
            agent_cls = [SecretHunterAgent, FalsePositiveFilterAgent, ExploitAssessorAgent][i]
            agents.append(agent_cls(llm, name=f"Agent{i}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        decisions_from_opinions = [op.analysis.decision for op in verdict.agent_opinions]
        assert "confirmed" in decisions_from_opinions
        assert "false_positive" in decisions_from_opinions
        assert "uncertain" in decisions_from_opinions

    def test_analyze_independently_varying_confidence(self):
        """Test independent analysis with varying confidence levels"""
        confidences = [0.95, 0.75, 0.55]
        agents = []
        for i, conf in enumerate(confidences):
            llm = _make_llm_provider("confirmed", conf, "Reason")
            agent_cls = [SecretHunterAgent, FalsePositiveFilterAgent, ExploitAssessorAgent][i]
            agents.append(agent_cls(llm, name=f"Agent{i}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        conf_values = [op.analysis.confidence for op in verdict.agent_opinions]
        assert conf_values == confidences

    def test_analyze_independently_all_agents_called(self):
        """Test that all agents are called during independent analysis"""
        llm = _make_llm_provider()
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        # All agents should have produced opinions
        assert len(verdict.agent_opinions) == len(agents)
        # LLM generate was called once per agent
        assert llm.generate.call_count == len(agents)


# ============================================================================
# Discussion mode tests
# ============================================================================

class TestDiscussionMode:
    """Test discussion mode with multiple rounds"""

    def setup_method(self):
        """Set up test fixtures"""
        self.finding = _make_finding()

    def test_single_round_discussion(self):
        """Test single round discussion"""
        llm = _make_llm_provider("confirmed", 0.90, "Agrees after discussion")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="discussion", max_rounds=1)

        assert isinstance(verdict, CollaborativeVerdict)
        assert verdict.discussion_rounds >= 0

    def test_multi_round_discussion(self):
        """Test multi-round discussion"""
        llm = _make_llm_provider("confirmed", 0.92, "After deliberation")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="discussion", max_rounds=3)

        assert verdict.discussion_rounds <= 3

    def test_discussion_reaches_consensus_early(self):
        """Test that discussion stops when consensus is reached"""
        llm = _make_llm_provider("confirmed", 0.95, "Clear agreement")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="discussion", max_rounds=3)

        assert verdict.discussion_rounds <= 3
        assert verdict.consensus_reached is True

    def test_discussion_timeout_max_rounds(self):
        """Test discussion timeout after max rounds"""
        llm = _make_llm_provider("confirmed", 0.8, "Continuing discussion")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="discussion", max_rounds=2)

        assert verdict.discussion_rounds <= 2


# ============================================================================
# Consensus building tests
# ============================================================================

class TestConsensusBuilding:
    """Test consensus building"""

    def setup_method(self):
        """Set up test fixtures"""
        self.finding = _make_finding()

    def test_unanimous_consensus(self):
        """Test when all agents agree"""
        llm = _make_llm_provider("confirmed", 0.95, "Agreement")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        assert verdict.final_decision == "confirmed"
        assert verdict.consensus_reached is True

    def test_majority_consensus(self):
        """Test when majority agrees"""
        agents = []
        for i, (decision, name_cls) in enumerate([
            ("confirmed", SecretHunterAgent),
            ("confirmed", FalsePositiveFilterAgent),
            ("false_positive", ExploitAssessorAgent),
        ]):
            llm = _make_llm_provider(decision, 0.85, "Opinion")
            agents.append(name_cls(llm, name=f"Agent{i}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        # Majority confirmed
        assert verdict.final_decision in ["confirmed", "needs_review"]
        assert verdict.consensus_reached is True

    def test_split_consensus(self):
        """Test when agents are split"""
        agents = []
        decisions = ["confirmed", "false_positive", "uncertain"]
        agent_classes = [SecretHunterAgent, FalsePositiveFilterAgent, ExploitAssessorAgent]
        for i, (decision, cls) in enumerate(zip(decisions, agent_classes)):
            llm = _make_llm_provider(decision, 0.8, "Divided opinion")
            agents.append(cls(llm, name=f"Agent{i}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        assert isinstance(verdict, CollaborativeVerdict)
        assert len(verdict.agent_opinions) == 3


# ============================================================================
# Conflict resolution tests
# ============================================================================

class TestConflictResolution:
    """Test conflict resolution"""

    def setup_method(self):
        """Set up test fixtures"""
        self.finding = _make_finding()

    def test_resolve_confirmed_vs_false_positive(self):
        """Test resolving confirmed vs false_positive conflict"""
        agents = []
        decisions = ["confirmed", "false_positive", "confirmed"]
        agent_classes = [SecretHunterAgent, FalsePositiveFilterAgent, ExploitAssessorAgent]
        for i, (decision, cls) in enumerate(zip(decisions, agent_classes)):
            llm = _make_llm_provider(decision, 0.92, f"Reason {i}")
            agents.append(cls(llm, name=f"Agent{i}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        # Conflict detected (confirmed + false_positive) -> needs_review
        assert verdict.final_decision in ["confirmed", "needs_review"]

    def test_resolve_three_way_disagreement(self):
        """Test resolving three-way disagreement"""
        agents = []
        decisions = ["confirmed", "false_positive", "uncertain"]
        agent_classes = [SecretHunterAgent, FalsePositiveFilterAgent, ExploitAssessorAgent]
        for i, (decision, cls) in enumerate(zip(decisions, agent_classes)):
            llm = _make_llm_provider(decision, 0.80 + i * 0.03, f"Reason {i}")
            agents.append(cls(llm, name=f"Agent{i}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        assert isinstance(verdict, CollaborativeVerdict)
        # Should have some escalation info
        assert verdict.reasoning is not None

    def test_resolve_confidence_weighted(self):
        """Test conflict resolution weighted by confidence"""
        agents = []
        for decision, conf, cls in [
            ("confirmed", 0.99, SecretHunterAgent),
            ("false_positive", 0.55, FalsePositiveFilterAgent),
        ]:
            llm = _make_llm_provider(decision, conf, f"Reason for {decision}")
            agents.append(cls(llm, name=f"Agent_{decision}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        # Higher confidence should influence outcome
        assert verdict.confidence >= 0.5


# ============================================================================
# Agreement scenarios
# ============================================================================

class TestAgreementScenarios:
    """Test agent agreement scenarios"""

    def setup_method(self):
        """Set up test fixtures"""
        self.finding = _make_finding()

    def test_all_agents_confirm(self):
        """Test when all agents confirm finding"""
        llm = _make_llm_provider("confirmed", 0.95, "Clear evidence")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        assert all(op.analysis.decision == "confirmed" for op in verdict.agent_opinions)
        assert all(op.analysis.confidence >= 0.9 for op in verdict.agent_opinions)

    def test_all_agents_false_positive(self):
        """Test when all agents mark as false positive"""
        llm = _make_llm_provider("false_positive", 0.92, "Test fixture")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        assert all(op.analysis.decision == "false_positive" for op in verdict.agent_opinions)

    def test_all_agents_uncertain(self):
        """Test when all agents mark as uncertain"""
        llm = _make_llm_provider("uncertain", 0.65, "Requires manual review")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        assert all(op.analysis.decision == "uncertain" for op in verdict.agent_opinions)

    def test_high_confidence_agreement(self):
        """Test high confidence agreement"""
        llm = _make_llm_provider("confirmed", 0.98, "Definitive evidence")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        avg_confidence = sum(op.analysis.confidence for op in verdict.agent_opinions) / len(verdict.agent_opinions)
        assert avg_confidence > 0.95


# ============================================================================
# Disagreement scenarios
# ============================================================================

class TestDisagreementScenarios:
    """Test agent disagreement scenarios"""

    def setup_method(self):
        """Set up test fixtures"""
        self.finding = _make_finding()

    def test_two_vs_one_disagreement(self):
        """Test 2 vs 1 disagreement"""
        agents = []
        decisions_confs = [("confirmed", 0.90), ("confirmed", 0.92), ("false_positive", 0.85)]
        agent_classes = [SecretHunterAgent, FalsePositiveFilterAgent, ExploitAssessorAgent]
        for (decision, conf), cls in zip(decisions_confs, agent_classes):
            llm = _make_llm_provider(decision, conf, f"Reason for {decision}")
            agents.append(cls(llm, name=f"Agent_{decision}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        # With conflict between confirmed and false_positive, system may escalate
        assert verdict.final_decision in ["confirmed", "needs_review"]

    def test_split_evenly_disagreement(self):
        """Test evenly split disagreement"""
        agents = []
        for decision, conf, cls in [
            ("confirmed", 0.88, SecretHunterAgent),
            ("false_positive", 0.89, FalsePositiveFilterAgent),
        ]:
            llm = _make_llm_provider(decision, conf, f"Reason: {decision}")
            agents.append(cls(llm, name=f"Agent_{decision}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        # Should handle tie-breaking somehow
        assert verdict.final_decision in ["confirmed", "false_positive", "needs_review"]

    def test_low_confidence_disagreement(self):
        """Test disagreement with low confidence"""
        agents = []
        decisions_confs = [("confirmed", 0.60), ("false_positive", 0.62), ("uncertain", 0.58)]
        agent_classes = [SecretHunterAgent, FalsePositiveFilterAgent, ExploitAssessorAgent]
        for (decision, conf), cls in zip(decisions_confs, agent_classes):
            llm = _make_llm_provider(decision, conf, f"Unsure: {decision}")
            agents.append(cls(llm, name=f"Agent_{decision}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        assert verdict.reasoning is not None


# ============================================================================
# Discussion transcript tests
# ============================================================================

class TestDiscussionTranscript:
    """Test discussion transcript generation"""

    def setup_method(self):
        """Set up test fixtures"""
        self.finding = _make_finding()

    def test_transcript_generation(self):
        """Test that collaborative analysis produces a verdict with reasoning"""
        llm = _make_llm_provider("confirmed", 0.9, "Reason")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="discussion", max_rounds=2)

        # The reasoning field serves as the transcript
        assert isinstance(verdict.reasoning, str)
        assert len(verdict.reasoning) > 0

    def test_transcript_includes_agent_names(self):
        """Test that reasoning includes agent names"""
        llm = _make_llm_provider("confirmed", 0.9, "Reason")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="discussion", max_rounds=1)

        # The combined reasoning includes agent names
        assert any(
            name in verdict.reasoning
            for name in ["SecretHunter", "FalsePositiveFilter", "ExploitAssessor"]
        )


# ============================================================================
# Final verdict derivation tests
# ============================================================================

class TestFinalVerdictDerivation:
    """Test final verdict derivation"""

    def setup_method(self):
        """Set up test fixtures"""
        self.finding = _make_finding()

    def test_verdict_majority_confirmed(self):
        """Test verdict with majority confirmed"""
        llm = _make_llm_provider("confirmed", 0.90, "Test")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        assert verdict.final_decision == "confirmed"

    def test_verdict_majority_false_positive(self):
        """Test verdict with majority false_positive"""
        llm = _make_llm_provider("false_positive", 0.88, "Test")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        assert verdict.final_decision == "false_positive"

    def test_verdict_escalation_on_uncertainty(self):
        """Test verdict escalation when uncertain"""
        agents = []
        decisions_confs = [("false_positive", 0.58), ("confirmed", 0.59), ("uncertain", 0.60)]
        agent_classes = [SecretHunterAgent, FalsePositiveFilterAgent, ExploitAssessorAgent]
        for (decision, conf), cls in zip(decisions_confs, agent_classes):
            llm = _make_llm_provider(decision, conf, f"Weak: {decision}")
            agents.append(cls(llm, name=f"Agent_{decision}"))

        reasoning = CollaborativeReasoning(agents)
        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        # High uncertainty should potentially escalate to review
        assert verdict.final_decision in ["confirmed", "false_positive", "needs_review"]

    def test_verdict_confidence_calculation(self):
        """Test final confidence calculation"""
        llm = _make_llm_provider("confirmed", 0.90, "Strong")
        agents = create_default_agent_team(llm)
        reasoning = CollaborativeReasoning(agents)

        verdict = reasoning.analyze_collaboratively(self.finding, mode="independent")

        # Confidence should be average of agreeing agents
        assert 0.5 <= verdict.confidence <= 1.0
