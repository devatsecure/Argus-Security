#!/usr/bin/env python3
"""
Collaborative Reasoning System for Argus
Multi-agent collaboration with discussion and consensus building

This module enables multiple specialized AI agents to:
1. Independently analyze security findings
2. Discuss and debate their conclusions
3. Reach consensus or escalate disagreements
4. Provide transparent reasoning chains

Architecture:
- Agent Personas: Specialized agents (SecretHunter, FalsePositiveFilter, etc.)
- Collaboration Modes: Independent analysis or multi-round discussion
- Consensus Building: Weighted voting with conflict resolution
- Transparency: Full reasoning chain captured for audit
"""

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============================================================================
# Data Structures
# ============================================================================


@dataclass
class AgentAnalysis:
    """Single agent's analysis of a finding"""

    decision: str  # "confirmed", "false_positive", "uncertain"
    confidence: float  # 0.0 - 1.0
    reasoning: str
    severity_assessment: Optional[str] = None  # Agent's severity opinion
    key_evidence: List[str] = field(default_factory=list)  # Key points
    concerns: List[str] = field(default_factory=list)  # Concerns/doubts
    questions_for_others: List[str] = field(default_factory=list)  # Discussion questions


@dataclass
class AgentOpinion:
    """Agent's opinion with discussion history"""

    agent_name: str
    persona_type: str  # SecretHunter, FalsePositiveFilter, etc.
    analysis: AgentAnalysis
    discussion_notes: List[str] = field(default_factory=list)  # Multi-round comments
    opinion_changes: List[Dict[str, Any]] = field(default_factory=list)  # Track changes
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "agent_name": self.agent_name,
            "persona_type": self.persona_type,
            "analysis": {
                "decision": self.analysis.decision,
                "confidence": self.analysis.confidence,
                "reasoning": self.analysis.reasoning,
                "severity_assessment": self.analysis.severity_assessment,
                "key_evidence": self.analysis.key_evidence,
                "concerns": self.analysis.concerns,
                "questions_for_others": self.analysis.questions_for_others,
            },
            "discussion_notes": self.discussion_notes,
            "opinion_changes": self.opinion_changes,
            "timestamp": self.timestamp,
        }


@dataclass
class CollaborativeVerdict:
    """Final verdict from collaborative analysis"""

    finding_id: str
    final_decision: str  # "confirmed", "false_positive", "needs_review"
    confidence: float  # 0.0 - 1.0
    reasoning: str  # Combined reasoning from all agents
    agent_opinions: List[AgentOpinion]
    consensus_reached: bool
    discussion_rounds: int
    decision_breakdown: Dict[str, int] = field(default_factory=dict)  # Count of each decision
    conflict_resolution_method: Optional[str] = None  # How conflicts were resolved
    final_severity: Optional[str] = None
    escalation_reason: Optional[str] = None  # Why escalated if needs_review
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "finding_id": self.finding_id,
            "final_decision": self.final_decision,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "agent_opinions": [op.to_dict() for op in self.agent_opinions],
            "consensus_reached": self.consensus_reached,
            "discussion_rounds": self.discussion_rounds,
            "decision_breakdown": self.decision_breakdown,
            "conflict_resolution_method": self.conflict_resolution_method,
            "final_severity": self.final_severity,
            "escalation_reason": self.escalation_reason,
            "timestamp": self.timestamp,
        }


# ============================================================================
# Agent Personas
# ============================================================================


class BaseAgentPersona(ABC):
    """Base class for specialized agent personas"""

    def __init__(self, llm_provider, name: str = None):
        """
        Initialize agent persona

        Args:
            llm_provider: LLM provider instance (AnthropicProvider, OpenAIProvider, etc.)
            name: Optional custom name for this agent
        """
        self.llm = llm_provider
        self.name = name or self.__class__.__name__
        self.persona_type = self.__class__.__name__

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return system prompt defining agent's expertise and approach"""
        pass

    def analyze(self, finding: Dict[str, Any], context: Optional[Dict] = None) -> AgentAnalysis:
        """
        Analyze a finding from this agent's perspective

        Args:
            finding: Finding dictionary (from normalizer/base.py Finding.to_dict())
            context: Optional additional context (file content, git history, etc.)

        Returns:
            AgentAnalysis with decision, confidence, and reasoning
        """
        # Build prompt
        system_prompt = self.get_system_prompt()
        user_prompt = self._build_analysis_prompt(finding, context)

        # Get LLM response
        try:
            response_text = self.llm.generate(user_prompt, system_prompt)
            analysis = self._parse_analysis_response(response_text)
            return analysis
        except Exception as e:
            logger.error(f"{self.name} analysis failed: {e}")
            # Return uncertain analysis on error
            return AgentAnalysis(
                decision="uncertain",
                confidence=0.0,
                reasoning=f"Analysis failed: {str(e)}",
                key_evidence=[],
                concerns=[f"Error during analysis: {str(e)}"],
            )

    def discuss(
        self, finding: Dict[str, Any], other_opinions: List[AgentOpinion], context: Optional[Dict] = None
    ) -> str:
        """
        Respond to other agents' opinions in discussion round

        Args:
            finding: Finding dictionary
            other_opinions: Opinions from other agents
            context: Optional additional context

        Returns:
            Discussion comment addressing others' points
        """
        system_prompt = self.get_system_prompt()
        user_prompt = self._build_discussion_prompt(finding, other_opinions, context)

        try:
            return self.llm.generate(user_prompt, system_prompt)
        except Exception as e:
            logger.error(f"{self.name} discussion failed: {e}")
            return f"Unable to participate in discussion: {str(e)}"

    def _build_analysis_prompt(self, finding: Dict[str, Any], context: Optional[Dict]) -> str:
        """Build prompt for initial analysis"""
        prompt = f"""Analyze this security finding from your specialized perspective.

**Finding Details:**
- ID: {finding.get('id', 'unknown')}
- Origin: {finding.get('origin', 'unknown')}
- File: {finding.get('path', 'unknown')}
- Line: {finding.get('line', 'N/A')}
- Severity: {finding.get('severity', 'unknown')}
- Rule: {finding.get('rule_id', 'unknown')} - {finding.get('rule_name', '')}
- Category: {finding.get('category', 'unknown')}
- CWE: {finding.get('cwe', 'N/A')}
- CVE: {finding.get('cve', 'N/A')}

**Evidence:**
{json.dumps(finding.get('evidence', {}), indent=2)}
"""

        if context:
            prompt += f"\n**Additional Context:**\n{json.dumps(context, indent=2)}\n"

        prompt += """
**Your Task:**
Provide your analysis in this JSON format:
{
  "decision": "confirmed" | "false_positive" | "uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "Detailed explanation of your assessment",
  "severity_assessment": "critical|high|medium|low|info" (optional),
  "key_evidence": ["Point 1", "Point 2"],
  "concerns": ["Concern 1", "Concern 2"],
  "questions_for_others": ["Question for other agents"]
}
"""
        return prompt

    def _build_discussion_prompt(
        self, finding: Dict[str, Any], other_opinions: List[AgentOpinion], context: Optional[Dict]
    ) -> str:
        """Build prompt for discussion round"""
        prompt = f"""You are participating in a multi-agent discussion about this finding.

**Finding:** {finding.get('id', 'unknown')} - {finding.get('rule_name', '')}

**Other Agents' Opinions:**
"""
        for opinion in other_opinions:
            if opinion.agent_name == self.name:
                continue  # Skip self
            prompt += f"""
- **{opinion.agent_name}** ({opinion.persona_type}):
  - Decision: {opinion.analysis.decision} (confidence: {opinion.analysis.confidence:.2f})
  - Reasoning: {opinion.analysis.reasoning}
  - Key Evidence: {', '.join(opinion.analysis.key_evidence)}
  - Concerns: {', '.join(opinion.analysis.concerns)}
"""

        prompt += """
**Your Task:**
Respond to the other agents' points. You may:
1. Agree with their analysis and provide supporting evidence
2. Disagree and explain why (with evidence)
3. Ask clarifying questions
4. Change your opinion if their arguments are convincing

Keep your response concise (2-3 sentences focused on key points).
"""
        return prompt

    def _parse_analysis_response(self, response_text: str) -> AgentAnalysis:
        """Parse LLM response into AgentAnalysis"""
        try:
            # Try to extract JSON from response
            import re

            json_match = re.search(r"\{.*\}", response_text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group(0))
                return AgentAnalysis(
                    decision=data.get("decision", "uncertain"),
                    confidence=float(data.get("confidence", 0.5)),
                    reasoning=data.get("reasoning", ""),
                    severity_assessment=data.get("severity_assessment"),
                    key_evidence=data.get("key_evidence", []),
                    concerns=data.get("concerns", []),
                    questions_for_others=data.get("questions_for_others", []),
                )
            else:
                # Fallback: treat as unstructured reasoning
                return AgentAnalysis(
                    decision="uncertain", confidence=0.5, reasoning=response_text, key_evidence=[], concerns=[]
                )
        except Exception as e:
            logger.error(f"Failed to parse analysis response: {e}")
            return AgentAnalysis(
                decision="uncertain",
                confidence=0.0,
                reasoning=f"Parse error: {response_text[:200]}",
                key_evidence=[],
                concerns=[],
            )


# ============================================================================
# Specialized Agent Personas
# ============================================================================


class SecretHunterAgent(BaseAgentPersona):
    """Specialized in detecting hardcoded secrets and credentials"""

    def get_system_prompt(self) -> str:
        return """You are a SecretHunter agent specializing in detecting hardcoded secrets, credentials, and API keys.

**Your Expertise:**
- Pattern recognition for secrets (API keys, passwords, tokens)
- Distinguishing real secrets from test/mock data
- Assessing secret entropy and validity
- Identifying secret rotation requirements
- OAuth2 public vs confidential clients

**Your Approach:**
- Check if the detected pattern actually looks like a valid secret (entropy, format)
- Verify if it's in test files, examples, or documentation
- Consider if the secret appears to be redacted or fake
- For OAuth2: Distinguish public clients (no secret needed) from confidential clients
- Check for PKCE flow in OAuth2 public clients (secure alternative to secrets)
- Assess severity based on secret type and exposure

Be conservative but accurate. Many "secrets" are actually test fixtures, examples, or public client IDs that don't need protection."""

class FalsePositiveFilterAgent(BaseAgentPersona):
    """Specialized in identifying false positives"""

    def get_system_prompt(self) -> str:
        return """You are a FalsePositiveFilter agent specializing in identifying false positives.

**Your Expertise:**
- Recognizing test code, fixtures, and examples
- Understanding common security scanner limitations
- Identifying intentional security patterns (e.g., security tests)
- Context-aware analysis (file paths, naming conventions)
- OAuth2 public client patterns
- File permission validation
- Dev-only configuration detection
- Locking mechanism analysis

**Your Approach:**
- Check file paths: tests/, examples/, docs/, fixtures/
- Look for test framework indicators (pytest, jest, mock, stub)
- Assess if code is production vs test/example
- Identify intentional "vulnerable" code in security tests
- OAuth2: Recognize public clients (SPAs/mobile) that use PKCE instead of secrets
- File permissions: Check if files have restrictive permissions (600/640, not world-readable)
- Dev configs: Identify DEBUG flags wrapped in environment checks
- Locking: Distinguish proper mutex/file locks from actual race conditions

Be thorough. A false positive that blocks CI/CD wastes developer time."""


class ExploitAssessorAgent(BaseAgentPersona):
    """Specialized in assessing exploitability and severity"""

    def get_system_prompt(self) -> str:
        return """You are an ExploitAssessor agent specializing in exploit analysis and severity assessment.

**Your Expertise:**
- CVE analysis and CVSS scoring
- Attack vector assessment (network, local, physical)
- Exploit complexity evaluation
- Real-world exploitability analysis

**Your Approach:**
- Assess attack surface and reachability
- Evaluate exploit difficulty (trivial, moderate, complex, theoretical)
- Consider mitigating factors (authentication, network isolation)
- Provide realistic severity based on actual risk

Be pragmatic. Not all "critical" findings are equally exploitable."""


class ComplianceAgent(BaseAgentPersona):
    """Specialized in compliance and regulatory requirements"""

    def get_system_prompt(self) -> str:
        return """You are a ComplianceAgent specializing in regulatory and compliance requirements.

**Your Expertise:**
- PCI-DSS, SOC2, HIPAA, GDPR compliance
- Industry-specific security requirements
- Data classification and handling
- Audit trail requirements

**Your Approach:**
- Identify if finding impacts compliance requirements
- Assess data exposure risks (PII, financial, PHI)
- Consider regulatory deadlines and SLAs
- Flag findings that could fail audits

Be precise. Compliance violations can have legal consequences."""


class ContextExpertAgent(BaseAgentPersona):
    """Specialized in understanding code context and business logic"""

    def get_system_prompt(self) -> str:
        return """You are a ContextExpert agent specializing in code context and business logic.

**Your Expertise:**
- Understanding code intent and business logic
- Recognizing framework-specific patterns (Django, Flask, Express)
- Identifying compensating controls
- Assessing code quality and maintainability

**Your Approach:**
- Consider the broader context of the code
- Look for security controls elsewhere in the codebase
- Understand framework security features
- Assess if finding is mitigated by architecture

Be holistic. Security is not just about isolated code snippets."""


# ============================================================================
# Main Collaborative Reasoning System
# ============================================================================


class CollaborativeReasoning:
    """
    Multi-agent collaborative reasoning system

    Orchestrates multiple specialized agents to analyze findings collaboratively,
    with support for independent analysis and multi-round discussion.
    """

    def __init__(self, agent_personas: List[BaseAgentPersona], min_consensus_threshold: float = 0.6):
        """
        Initialize collaborative reasoning system

        Args:
            agent_personas: List of agent persona instances
            min_consensus_threshold: Minimum agreement threshold for consensus (0.0-1.0)
        """
        self.agents = agent_personas
        self.min_consensus_threshold = min_consensus_threshold
        logger.info(f"Initialized collaborative reasoning with {len(self.agents)} agents")

    def analyze_collaboratively(
        self, finding: Dict[str, Any], mode: str = "discussion", max_rounds: int = 2, context: Optional[Dict] = None
    ) -> CollaborativeVerdict:
        """
        Analyze finding collaboratively with multiple agents

        Args:
            finding: Finding dictionary (from Finding.to_dict())
            mode: "independent" (no discussion) or "discussion" (multi-round)
            max_rounds: Maximum discussion rounds (default: 2)
            context: Optional additional context

        Returns:
            CollaborativeVerdict with final decision and reasoning
        """
        finding_id = finding.get("id", self._generate_finding_id(finding))
        logger.info(f"Starting collaborative analysis for {finding_id} in {mode} mode")

        # Phase 1: Independent analysis
        opinions = self._gather_opinions(finding, context)

        # Phase 2: Discussion (if enabled)
        discussion_rounds = 0
        if mode == "discussion" and len(self.agents) > 1:
            opinions, discussion_rounds = self._run_discussion(finding, opinions, max_rounds, context)

        # Phase 3: Build consensus
        verdict = self._build_consensus(finding_id, opinions, discussion_rounds)

        logger.info(
            f"Collaborative analysis complete: {verdict.final_decision} "
            f"(confidence: {verdict.confidence:.2f}, consensus: {verdict.consensus_reached})"
        )

        return verdict

    def _gather_opinions(self, finding: Dict[str, Any], context: Optional[Dict]) -> List[AgentOpinion]:
        """
        Gather independent opinions from all agents

        Args:
            finding: Finding dictionary
            context: Optional context

        Returns:
            List of AgentOpinion objects
        """
        logger.info(f"Gathering opinions from {len(self.agents)} agents")
        opinions = []

        for agent in self.agents:
            try:
                logger.debug(f"Requesting analysis from {agent.name}")
                analysis = agent.analyze(finding, context)
                opinion = AgentOpinion(
                    agent_name=agent.name, persona_type=agent.persona_type, analysis=analysis, discussion_notes=[]
                )
                opinions.append(opinion)
                logger.debug(
                    f"{agent.name}: {analysis.decision} (confidence: {analysis.confidence:.2f}) - {analysis.reasoning[:100]}"
                )
            except Exception as e:
                logger.error(f"Agent {agent.name} failed: {e}")
                # Create fallback uncertain opinion
                fallback = AgentOpinion(
                    agent_name=agent.name,
                    persona_type=agent.persona_type,
                    analysis=AgentAnalysis(
                        decision="uncertain", confidence=0.0, reasoning=f"Agent error: {str(e)}", key_evidence=[]
                    ),
                )
                opinions.append(fallback)

        return opinions

    def _run_discussion(
        self, finding: Dict[str, Any], opinions: List[AgentOpinion], max_rounds: int, context: Optional[Dict]
    ) -> tuple[List[AgentOpinion], int]:
        """
        Run multi-round discussion between agents

        Args:
            finding: Finding dictionary
            opinions: Initial opinions
            max_rounds: Maximum discussion rounds
            context: Optional context

        Returns:
            Tuple of (updated opinions, number of rounds executed)
        """
        logger.info(f"Starting discussion (max {max_rounds} rounds)")

        for round_num in range(1, max_rounds + 1):
            logger.info(f"Discussion round {round_num}/{max_rounds}")

            # Check if consensus already reached
            if self._check_early_consensus(opinions):
                logger.info(f"Early consensus reached after round {round_num - 1}")
                return opinions, round_num - 1

            # Each agent discusses others' opinions
            for i, agent in enumerate(self.agents):
                try:
                    # Get this agent's opinion
                    agent_opinion = opinions[i]

                    # Agent discusses with others
                    discussion_comment = agent.discuss(finding, opinions, context)
                    agent_opinion.discussion_notes.append(f"Round {round_num}: {discussion_comment}")

                    # Check if agent wants to change opinion based on discussion
                    if self._should_reconsider(discussion_comment):
                        logger.info(f"{agent.name} reconsidering opinion after discussion")
                        # Re-analyze with discussion context
                        new_analysis = agent.analyze(finding, context)

                        # Track opinion change
                        if new_analysis.decision != agent_opinion.analysis.decision:
                            agent_opinion.opinion_changes.append(
                                {
                                    "round": round_num,
                                    "old_decision": agent_opinion.analysis.decision,
                                    "new_decision": new_analysis.decision,
                                    "reason": discussion_comment,
                                }
                            )
                            logger.info(
                                f"{agent.name} changed opinion: {agent_opinion.analysis.decision} -> {new_analysis.decision}"
                            )
                            agent_opinion.analysis = new_analysis

                except Exception as e:
                    logger.error(f"Discussion failed for {agent.name}: {e}")
                    opinions[i].discussion_notes.append(f"Round {round_num}: Error - {str(e)}")

        return opinions, max_rounds

    def _build_consensus(self, finding_id: str, opinions: List[AgentOpinion], discussion_rounds: int) -> CollaborativeVerdict:
        """
        Build consensus from agent opinions

        Args:
            finding_id: Finding identifier
            opinions: Agent opinions
            discussion_rounds: Number of discussion rounds executed

        Returns:
            CollaborativeVerdict with final decision
        """
        # Count decisions
        decision_counts = {"confirmed": 0, "false_positive": 0, "uncertain": 0}
        confidence_weights = {"confirmed": 0.0, "false_positive": 0.0, "uncertain": 0.0}

        for opinion in opinions:
            decision = opinion.analysis.decision
            confidence = opinion.analysis.confidence
            decision_counts[decision] = decision_counts.get(decision, 0) + 1
            confidence_weights[decision] = confidence_weights.get(decision, 0.0) + confidence

        total_agents = len(opinions)
        max_decision = max(decision_counts, key=decision_counts.get)
        max_count = decision_counts[max_decision]

        # Calculate consensus strength
        consensus_pct = max_count / total_agents
        consensus_reached = consensus_pct >= self.min_consensus_threshold

        # Weighted confidence (average confidence of agents agreeing with majority)
        if max_count > 0:
            avg_confidence = confidence_weights[max_decision] / max_count
        else:
            avg_confidence = 0.0

        # Determine final decision and resolution method
        if consensus_reached and max_decision in ["confirmed", "false_positive"]:
            final_decision = max_decision
            resolution_method = f"consensus ({max_count}/{total_agents} agents agree)"
        elif self._detect_conflict(opinions):
            final_decision = "needs_review"
            resolution_method = f"conflicting opinions (escalated for manual review)"
        else:
            # No clear consensus but not total conflict - use weighted approach
            if avg_confidence >= 0.7 and max_count >= (total_agents / 2):
                final_decision = max_decision
                resolution_method = f"majority with high confidence ({max_count}/{total_agents})"
            else:
                final_decision = "needs_review"
                resolution_method = "low confidence, escalated for manual review"

        # Build combined reasoning
        reasoning = self._build_combined_reasoning(opinions, final_decision, resolution_method)

        # Determine final severity (most conservative from agreeing agents)
        final_severity = self._determine_severity(opinions, max_decision)

        # Build escalation reason if needed
        escalation_reason = None
        if final_decision == "needs_review":
            escalation_reason = self._build_escalation_reason(opinions, decision_counts)

        return CollaborativeVerdict(
            finding_id=finding_id,
            final_decision=final_decision,
            confidence=avg_confidence,
            reasoning=reasoning,
            agent_opinions=opinions,
            consensus_reached=consensus_reached,
            discussion_rounds=discussion_rounds,
            decision_breakdown=decision_counts,
            conflict_resolution_method=resolution_method,
            final_severity=final_severity,
            escalation_reason=escalation_reason,
        )

    def _check_early_consensus(self, opinions: List[AgentOpinion]) -> bool:
        """Check if consensus already reached (for early termination)"""
        decisions = [op.analysis.decision for op in opinions]
        if not decisions:
            return False
        most_common = max(set(decisions), key=decisions.count)
        consensus_pct = decisions.count(most_common) / len(decisions)
        return consensus_pct >= self.min_consensus_threshold

    def _detect_conflict(self, opinions: List[AgentOpinion]) -> bool:
        """
        Detect significant conflict between agents

        Returns True if agents significantly disagree (e.g., some say confirmed, others say false_positive)
        """
        decisions = [op.analysis.decision for op in opinions]
        has_confirmed = "confirmed" in decisions
        has_false_positive = "false_positive" in decisions

        # Significant conflict if both confirmed and false_positive present
        return has_confirmed and has_false_positive

    def _should_reconsider(self, discussion_comment: str) -> bool:
        """Determine if agent should reconsider opinion based on discussion"""
        reconsider_indicators = [
            "you're right",
            "good point",
            "i agree",
            "convinced",
            "changing my opinion",
            "reconsidering",
            "didn't consider",
            "missed that",
        ]
        comment_lower = discussion_comment.lower()
        return any(indicator in comment_lower for indicator in reconsider_indicators)

    def _build_combined_reasoning(self, opinions: List[AgentOpinion], final_decision: str, resolution_method: str) -> str:
        """Build combined reasoning from all agents"""
        reasoning_parts = [f"**Decision:** {final_decision}", f"**Resolution:** {resolution_method}", ""]

        # Group agents by decision
        by_decision = {"confirmed": [], "false_positive": [], "uncertain": []}
        for opinion in opinions:
            by_decision[opinion.analysis.decision].append(opinion)

        # Summarize each group
        for decision in ["confirmed", "false_positive", "uncertain"]:
            agents_with_decision = by_decision[decision]
            if not agents_with_decision:
                continue

            reasoning_parts.append(f"**{decision.upper()} ({len(agents_with_decision)} agents):**")
            for opinion in agents_with_decision:
                confidence_str = f"confidence: {opinion.analysis.confidence:.2f}"
                reasoning_parts.append(f"- {opinion.agent_name}: {opinion.analysis.reasoning[:150]}... ({confidence_str})")

        return "\n".join(reasoning_parts)

    def _determine_severity(self, opinions: List[AgentOpinion], majority_decision: str) -> Optional[str]:
        """Determine final severity from agents agreeing with majority"""
        severity_order = ["critical", "high", "medium", "low", "info"]

        # Get severity assessments from agents agreeing with majority
        severities = []
        for opinion in opinions:
            if opinion.analysis.decision == majority_decision and opinion.analysis.severity_assessment:
                severities.append(opinion.analysis.severity_assessment)

        if not severities:
            return None

        # Return most conservative (highest) severity
        for severity in severity_order:
            if severity in severities:
                return severity
        return severities[0]

    def _build_escalation_reason(self, opinions: List[AgentOpinion], decision_counts: Dict[str, int]) -> str:
        """Build explanation for why finding was escalated"""
        reasons = []

        if decision_counts.get("confirmed", 0) > 0 and decision_counts.get("false_positive", 0) > 0:
            reasons.append(
                f"Conflicting opinions: {decision_counts['confirmed']} confirmed, {decision_counts['false_positive']} false positive"
            )

        # Check for low confidence
        avg_confidence = sum(op.analysis.confidence for op in opinions) / len(opinions)
        if avg_confidence < 0.6:
            reasons.append(f"Low average confidence: {avg_confidence:.2f}")

        # Check for significant concerns
        total_concerns = sum(len(op.analysis.concerns) for op in opinions)
        if total_concerns > len(opinions):
            reasons.append(f"Multiple concerns raised: {total_concerns} concerns from {len(opinions)} agents")

        return "; ".join(reasons) if reasons else "Unable to reach consensus"

    def _generate_finding_id(self, finding: Dict[str, Any]) -> str:
        """Generate finding ID from finding data"""
        key = f"{finding.get('path', 'unknown')}:{finding.get('rule_id', 'unknown')}:{finding.get('line', 0)}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


# ============================================================================
# Convenience Functions
# ============================================================================


def create_default_agent_team(llm_provider) -> List[BaseAgentPersona]:
    """
    Create default team of agent personas

    Args:
        llm_provider: LLM provider instance

    Returns:
        List of agent personas ready for collaborative reasoning
    """
    return [
        SecretHunterAgent(llm_provider, name="SecretHunter"),
        FalsePositiveFilterAgent(llm_provider, name="FalsePositiveFilter"),
        ExploitAssessorAgent(llm_provider, name="ExploitAssessor"),
    ]


def create_comprehensive_agent_team(llm_provider) -> List[BaseAgentPersona]:
    """
    Create comprehensive team of all agent personas

    Args:
        llm_provider: LLM provider instance

    Returns:
        List of all available agent personas
    """
    return [
        SecretHunterAgent(llm_provider, name="SecretHunter"),
        FalsePositiveFilterAgent(llm_provider, name="FalsePositiveFilter"),
        ExploitAssessorAgent(llm_provider, name="ExploitAssessor"),
        ComplianceAgent(llm_provider, name="ComplianceExpert"),
        ContextExpertAgent(llm_provider, name="ContextExpert"),
    ]


# ============================================================================
# Example Usage
# ============================================================================


def example_usage():
    """Example usage of collaborative reasoning system"""
    # This is for documentation purposes only
    print(
        """
Example Usage:

```python
from collaborative_reasoning import CollaborativeReasoning, create_default_agent_team
from providers.anthropic_provider import AnthropicProvider

# Initialize LLM provider
llm = AnthropicProvider(api_key="your-api-key")

# Create agent team
agents = create_default_agent_team(llm)

# Initialize collaborative reasoning
collab = CollaborativeReasoning(agents, min_consensus_threshold=0.6)

# Analyze finding
finding = {
    "id": "abc123",
    "origin": "semgrep",
    "path": "app/config.py",
    "line": 42,
    "severity": "high",
    "rule_id": "hardcoded-password",
    "evidence": {"matched_string": "password = 'admin123'"}
}

# Run collaborative analysis with discussion
verdict = collab.analyze_collaboratively(finding, mode="discussion", max_rounds=2)

print(f"Decision: {verdict.final_decision}")
print(f"Confidence: {verdict.confidence:.2f}")
print(f"Consensus: {verdict.consensus_reached}")
print(f"Reasoning: {verdict.reasoning}")
```

Example Collaboration Flow:

Round 1 - Independent Analysis:
- SecretHunter: "Confirmed - plaintext password (confidence: 0.9)"
- FalsePositiveFilter: "Wait, this is in tests/fixtures/config.py - test data (confidence: 0.8)"
- ExploitAssessor: "If real, critical severity"

Round 2 - Discussion:
- SecretHunter: "Good catch on test context, reviewing filepath..."
- SecretHunter: "Agreed - test fixture, changing to FALSE POSITIVE"
- FalsePositiveFilter: "Confirmed, all test fixtures are safe"

Final Verdict: FALSE POSITIVE (confidence: 0.85, consensus: True)
"""
    )


if __name__ == "__main__":
    example_usage()
