#!/usr/bin/env python3
"""
Unit tests for Agent Personas

Tests cover:
- Persona initialization (all 5 types)
- Agent selection logic
- Analysis output structure
- LLM response handling
- Error handling
- Expertise verification
- Finding analysis with confidence scoring
"""

import json
import sys
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, call
from dataclasses import dataclass, asdict
from typing import Optional

import pytest

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from agent_personas import (
    AgentAnalysis,
    BaseAgentPersona,
    SecretHunter,
    ArchitectureReviewer,
    ExploitAssessor,
    FalsePositiveFilter,
    ThreatModeler,
    select_agent_for_finding,
    select_agents_for_discovery,
    run_multi_agent_analysis,
    build_consensus,
)


def _make_llm_mock(response_text="Verdict: confirmed\nConfidence: 0.95\nReasoning: Found a real security issue"):
    """Create a mock LLM manager that returns the given response text from call_llm_api."""
    mock_llm = Mock()
    mock_llm.client = Mock()  # Non-None so _call_llm proceeds
    mock_llm.call_llm_api = Mock(return_value=(response_text, 100, 0.01))
    return mock_llm


def _make_finding(**overrides):
    """Create a sample finding dict with sensible defaults."""
    finding = {
        "id": "test-001",
        "path": "src/config.py",
        "line": 42,
        "severity": "high",
        "category": "SECRETS",
        "rule_id": "hardcoded-password",
        "origin": "semgrep",
        "evidence": {
            "snippet": 'password = "admin123"',
            "code": 'password = "admin123"',
        },
    }
    finding.update(overrides)
    return finding


class TestAgentAnalysisDataclass:
    """Test AgentAnalysis dataclass structure"""

    def test_analysis_creation_minimal(self):
        """Test creating an AgentAnalysis with minimal fields"""
        analysis = AgentAnalysis(
            agent_name="SecretHunter",
            verdict="confirmed",
            confidence=0.95,
            reasoning="Found hardcoded AWS key in config file",
        )

        assert analysis.agent_name == "SecretHunter"
        assert analysis.verdict == "confirmed"
        assert analysis.confidence == 0.95
        assert analysis.reasoning == "Found hardcoded AWS key in config file"
        assert analysis.severity_adjustment is None
        assert analysis.exploitability_score is None

    def test_analysis_creation_full(self):
        """Test creating an AgentAnalysis with all core fields"""
        analysis = AgentAnalysis(
            agent_name="ExploitAssessor",
            verdict="confirmed",
            confidence=0.88,
            reasoning="SQL injection vulnerability detected in user input handler",
            severity_adjustment="upgrade",
            exploitability_score=0.9,
        )

        assert analysis.agent_name == "ExploitAssessor"
        assert analysis.verdict == "confirmed"
        assert analysis.confidence == 0.88
        assert analysis.severity_adjustment == "upgrade"
        assert analysis.exploitability_score == 0.9

    def test_analysis_verdict_values(self):
        """Test all valid verdict values"""
        verdicts = ["confirmed", "false_positive", "needs_review", "likely_true", "likely_fp", "uncertain"]

        for verdict in verdicts:
            analysis = AgentAnalysis(
                agent_name="Test",
                verdict=verdict,
                confidence=0.8,
                reasoning="Test",
            )
            assert analysis.verdict == verdict

    def test_analysis_confidence_bounds(self):
        """Test confidence value bounds"""
        for confidence in [0.0, 0.5, 1.0]:
            analysis = AgentAnalysis(
                agent_name="Test",
                verdict="confirmed",
                confidence=confidence,
                reasoning="Test",
            )
            assert analysis.confidence == confidence


class TestSecretHunter:
    """Test SecretHunter persona"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = _make_llm_mock(
            "Verdict: confirmed\nConfidence: 0.95\n"
            "Reasoning: Hardcoded secret found in source file with high entropy pattern"
        )
        self.hunter = SecretHunter(self.mock_llm)

    def test_initialization(self):
        """Test SecretHunter initialization"""
        assert self.hunter.name == "SecretHunter"
        assert "oauth_tokens" in self.hunter.expertise
        assert "api_keys" in self.hunter.expertise
        assert "passwords" in self.hunter.expertise
        assert "private_keys" in self.hunter.expertise
        assert self.hunter.llm == self.mock_llm

    def test_analyze_hardcoded_secret(self):
        """Test analyzing a hardcoded secret finding"""
        finding = _make_finding(
            path="src/config.py",
            category="SECRETS",
            evidence={"snippet": "sk-api-1234567890", "code": "sk-api-1234567890"},
        )

        result = self.hunter.analyze(finding)

        assert isinstance(result, AgentAnalysis)
        assert result.agent_name == "SecretHunter"
        assert result.verdict in ["confirmed", "likely_true", "needs_review", "uncertain", "likely_fp", "false_positive"]
        assert result.confidence >= 0.0
        self.mock_llm.call_llm_api.assert_called_once()

    def test_analyze_aws_credentials(self):
        """Test analyzing AWS credentials"""
        finding = _make_finding(
            path=".env",
            rule_id="aws-access-key",
            evidence={"snippet": "AKIA1234567890EXAMPLE", "code": "AKIA1234567890EXAMPLE"},
        )

        result = self.hunter.analyze(finding)

        assert result.verdict in ["confirmed", "likely_true", "needs_review", "uncertain", "likely_fp", "false_positive"]
        assert isinstance(result.confidence, float)

    def test_analyze_false_positive_secret(self):
        """Test analyzing a false positive secret in test file"""
        self.mock_llm = _make_llm_mock(
            "Verdict: false_positive\nConfidence: 0.92\n"
            "Reasoning: Test token in test file, not a real secret"
        )
        self.hunter = SecretHunter(self.mock_llm)

        finding = _make_finding(
            path="tests/test_api.py",
            evidence={"snippet": "test-token-12345", "code": "test-token-12345"},
        )

        result = self.hunter.analyze(finding)

        # Test file path causes confidence reduction
        assert isinstance(result, AgentAnalysis)

    def test_analyze_needs_review(self):
        """Test analyzing a finding that needs review"""
        self.mock_llm = _make_llm_mock(
            "Verdict: needs_review\nConfidence: 0.65\n"
            "Reasoning: Ambiguous pattern, manual review recommended"
        )
        self.hunter = SecretHunter(self.mock_llm)

        finding = _make_finding(path="src/auth.py")

        result = self.hunter.analyze(finding)

        assert isinstance(result, AgentAnalysis)

    def test_llm_provider_called_correctly(self):
        """Test that LLM provider is called with proper parameters"""
        finding = _make_finding()

        self.hunter.analyze(finding)

        # Verify LLM was called via call_llm_api
        self.mock_llm.call_llm_api.assert_called_once()


class TestArchitectureReviewer:
    """Test ArchitectureReviewer persona"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = _make_llm_mock(
            "Verdict: confirmed\nConfidence: 0.85\n"
            "Reasoning: Singleton pattern implemented incorrectly leading to security issues\n"
            "Recommendations:\n- Use dependency injection instead"
        )
        self.reviewer = ArchitectureReviewer(self.mock_llm)

    def test_initialization(self):
        """Test ArchitectureReviewer initialization"""
        assert self.reviewer.name == "ArchitectureReviewer"
        assert "authentication_design" in self.reviewer.expertise
        assert "authorization_patterns" in self.reviewer.expertise
        assert "data_flow_security" in self.reviewer.expertise
        assert "api_security" in self.reviewer.expertise

    def test_analyze_design_pattern_issue(self):
        """Test analyzing a design pattern issue"""
        finding = _make_finding(
            path="src/service.py",
            category="SAST",
            rule_id="authentication-bypass",
        )

        result = self.reviewer.analyze(finding)

        assert isinstance(result, AgentAnalysis)
        assert result.agent_name == "ArchitectureReviewer"
        assert result.verdict in ["confirmed", "likely_true", "needs_review", "uncertain", "likely_fp", "false_positive"]

    def test_analyze_circular_dependency(self):
        """Test analyzing a circular dependency"""
        finding = _make_finding(
            path="src/models.py",
            category="SAST",
            rule_id="insecure-design",
        )

        result = self.reviewer.analyze(finding)

        assert isinstance(result, AgentAnalysis)
        assert isinstance(result.confidence, float)


class TestExploitAssessor:
    """Test ExploitAssessor persona (replaces PerformanceAnalyst)"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = _make_llm_mock(
            "Verdict: confirmed\nConfidence: 0.88\n"
            "Exploitability: trivial\n"
            "Reasoning: This vulnerability is easily exploitable with minimal privileges required\n"
            "Recommendations:\n- Use batch loading or eager loading"
        )
        self.assessor = ExploitAssessor(self.mock_llm)

    def test_initialization(self):
        """Test ExploitAssessor initialization"""
        assert self.assessor.name == "ExploitAssessor"
        assert "exploit_development" in self.assessor.expertise
        assert "attack_vectors" in self.assessor.expertise
        assert "cvss_scoring" in self.assessor.expertise
        assert "vulnerability_chaining" in self.assessor.expertise

    def test_analyze_exploitable_finding(self):
        """Test analyzing an exploitable finding"""
        finding = _make_finding(
            path="src/db.py",
            severity="critical",
            rule_id="sql-injection",
        )

        result = self.assessor.analyze(finding)

        assert isinstance(result, AgentAnalysis)
        assert result.verdict in ["confirmed", "likely_true", "needs_review", "uncertain", "likely_fp", "false_positive"]
        # Exploitability score should be set for "trivial"
        assert result.exploitability_score == 0.9

    def test_analyze_high_severity(self):
        """Test analyzing a high severity finding"""
        self.mock_llm = _make_llm_mock(
            "Verdict: confirmed\nConfidence: 0.82\n"
            "Exploitability: moderate\n"
            "Reasoning: Cache has no eviction policy leading to DoS potential"
        )
        self.assessor = ExploitAssessor(self.mock_llm)

        finding = _make_finding(severity="high")

        result = self.assessor.analyze(finding)

        assert isinstance(result, AgentAnalysis)
        assert result.exploitability_score == 0.6


class TestFalsePositiveFilter:
    """Test FalsePositiveFilter persona (replaces ComplianceExpert)"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = _make_llm_mock(
            "Verdict: confirmed\nConfidence: 0.95\n"
            "Reasoning: This is a real vulnerability, not in test code"
        )
        self.expert = FalsePositiveFilter(self.mock_llm)

    def test_initialization(self):
        """Test FalsePositiveFilter initialization"""
        assert self.expert.name == "FalsePositiveFilter"
        assert "test_patterns" in self.expert.expertise
        assert "mock_data" in self.expert.expertise
        assert "safe_contexts" in self.expert.expertise
        assert "development_code" in self.expert.expertise

    def test_analyze_real_vulnerability(self):
        """Test analyzing a real vulnerability (not FP)"""
        finding = _make_finding(
            path="src/user.py",
            category="SAST",
            severity="critical",
        )

        result = self.expert.analyze(finding)

        assert isinstance(result, AgentAnalysis)
        assert result.agent_name == "FalsePositiveFilter"

    def test_analyze_test_file(self):
        """Test analyzing a finding in a test file"""
        self.mock_llm = _make_llm_mock(
            "Verdict: false_positive\nConfidence: 0.99\n"
            "Reasoning: This is test code, not production"
        )
        self.expert = FalsePositiveFilter(self.mock_llm)

        finding = _make_finding(
            path="tests/test_payment.py",
            category="SECRETS",
        )

        result = self.expert.analyze(finding)

        assert isinstance(result, AgentAnalysis)
        # FP filter adds evidence about test paths
        assert isinstance(result.confidence, float)


class TestThreatModeler:
    """Test ThreatModeler persona (replaces VulnerabilityAssessor)"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = _make_llm_mock(
            "Verdict: confirmed\nConfidence: 0.99\n"
            "STRIDE Categories: Information Disclosure\n"
            "Reasoning: User input concatenated into SQL query allowing data exfiltration\n"
            "Attack Scenarios:\n- Attacker sends malicious input to extract database contents\n"
            "Risk Factors:\n- Public-facing API endpoint"
        )
        self.modeler = ThreatModeler(self.mock_llm)

    def test_initialization(self):
        """Test ThreatModeler initialization"""
        assert self.modeler.name == "ThreatModeler"
        assert "stride_methodology" in self.modeler.expertise
        assert "attack_trees" in self.modeler.expertise
        assert "threat_scenarios" in self.modeler.expertise
        assert "vulnerability_chaining" in self.modeler.expertise
        assert "risk_assessment" in self.modeler.expertise

    def test_analyze_sql_injection(self):
        """Test analyzing SQL injection vulnerability"""
        finding = _make_finding(
            path="src/query.py",
            rule_id="sql-injection",
            severity="critical",
        )

        result = self.modeler.analyze(finding)

        assert isinstance(result, AgentAnalysis)
        assert result.agent_name == "ThreatModeler"
        assert result.verdict in ["confirmed", "likely_true", "needs_review", "uncertain", "likely_fp", "false_positive"]

    def test_analyze_xss_vulnerability(self):
        """Test analyzing XSS vulnerability"""
        self.mock_llm = _make_llm_mock(
            "Verdict: confirmed\nConfidence: 0.92\n"
            "Reasoning: User input rendered without escaping in HTML template\n"
            "Attack Scenarios:\n- Reflected XSS via URL parameter"
        )
        self.modeler = ThreatModeler(self.mock_llm)

        finding = _make_finding(
            path="src/template.html",
            severity="high",
            rule_id="xss-reflected",
        )

        result = self.modeler.analyze(finding)

        assert isinstance(result, AgentAnalysis)

    def test_analyze_cve_finding(self):
        """Test analyzing known CVE"""
        finding = _make_finding(
            path="requirements.txt",
            severity="critical",
            rule_id="known-cve",
        )

        result = self.modeler.analyze(finding)

        assert isinstance(result, AgentAnalysis)
        assert isinstance(result.confidence, float)


class TestPersonaSelection:
    """Test agent selection logic"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = _make_llm_mock()

    def test_select_persona_for_secret_finding(self):
        """Test selecting SecretHunter for secret finding"""
        finding = _make_finding(category="SECRETS", rule_id="hardcoded-password")
        agent = select_agent_for_finding(finding, self.mock_llm)
        assert isinstance(agent, SecretHunter)
        assert agent.name == "SecretHunter"

    def test_select_persona_for_architecture_finding(self):
        """Test selecting ArchitectureReviewer for architecture finding"""
        finding = _make_finding(
            severity="medium",
            category="SAST",
            rule_id="authentication-bypass",
        )
        agent = select_agent_for_finding(finding, self.mock_llm)
        assert isinstance(agent, ArchitectureReviewer)
        assert agent.name == "ArchitectureReviewer"

    def test_select_persona_for_vulnerability_finding(self):
        """Test selecting ExploitAssessor for high severity finding"""
        finding = _make_finding(
            severity="critical",
            category="SAST",
            rule_id="sql-injection",
        )
        agent = select_agent_for_finding(finding, self.mock_llm)
        assert isinstance(agent, ExploitAssessor)

    def test_all_personas_have_expertise(self):
        """Test that all personas have defined expertise"""
        personas = [
            SecretHunter(self.mock_llm),
            ArchitectureReviewer(self.mock_llm),
            ExploitAssessor(self.mock_llm),
            FalsePositiveFilter(self.mock_llm),
            ThreatModeler(self.mock_llm),
        ]
        for persona in personas:
            assert isinstance(persona.expertise, list)
            assert len(persona.expertise) > 0

    def test_all_personas_have_llm_provider(self):
        """Test that all personas have LLM provider"""
        personas = [
            SecretHunter(self.mock_llm),
            ArchitectureReviewer(self.mock_llm),
            ExploitAssessor(self.mock_llm),
            FalsePositiveFilter(self.mock_llm),
            ThreatModeler(self.mock_llm),
        ]
        for persona in personas:
            assert persona.llm == self.mock_llm


class TestErrorHandling:
    """Test error handling in agent personas"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = _make_llm_mock()
        self.hunter = SecretHunter(self.mock_llm)

    def test_handle_llm_error(self):
        """Test handling LLM provider error - should not raise, returns fallback"""
        finding = _make_finding()

        # LLM call raises but _call_llm catches and returns error string
        self.mock_llm.call_llm_api = Mock(side_effect=Exception("LLM API error"))

        # The agent catches the exception internally and returns an analysis with error text
        result = self.hunter.analyze(finding)
        assert isinstance(result, AgentAnalysis)

    def test_handle_invalid_finding_structure(self):
        """Test handling invalid finding structure"""
        finding = {}  # Empty finding

        result = self.hunter.analyze(finding)
        assert isinstance(result, AgentAnalysis)

    def test_handle_missing_required_fields(self):
        """Test handling finding with minimal fields"""
        finding = {"path": "src/api.py"}

        result = self.hunter.analyze(finding)
        assert isinstance(result, AgentAnalysis)
        assert result.verdict in ["confirmed", "likely_true", "needs_review", "uncertain", "likely_fp", "false_positive"]

    def test_confidence_boundary_conditions(self):
        """Test confidence boundary conditions"""
        finding = _make_finding()

        # Test with confidence = 1.0 in LLM response
        self.mock_llm.call_llm_api = Mock(
            return_value=("Verdict: confirmed\nConfidence: 1.0\nReasoning: Certain", 100, 0.01)
        )

        result = self.hunter.analyze(finding)
        assert isinstance(result.confidence, float)

        # Test with confidence = 0.0
        self.mock_llm.call_llm_api = Mock(
            return_value=("Verdict: confirmed\nConfidence: 0.0\nReasoning: Unknown", 100, 0.01)
        )

        result = self.hunter.analyze(finding)
        assert isinstance(result.confidence, float)


class TestAnalysisOutputStructure:
    """Test analysis output structure and validation"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = _make_llm_mock(
            "Verdict: confirmed\nConfidence: 0.95\n"
            "Reasoning: Found API key with high entropy in production config"
        )
        self.hunter = SecretHunter(self.mock_llm)

    def test_analysis_contains_required_fields(self):
        """Test that analysis output contains all required fields"""
        finding = _make_finding()

        result = self.hunter.analyze(finding)

        # Required fields
        assert hasattr(result, "agent_name")
        assert hasattr(result, "verdict")
        assert hasattr(result, "confidence")
        assert hasattr(result, "reasoning")

    def test_analysis_verdict_is_valid(self):
        """Test that verdict is one of valid values"""
        finding = _make_finding()

        valid_verdicts = ["confirmed", "false_positive", "needs_review", "likely_true", "likely_fp", "uncertain"]

        result = self.hunter.analyze(finding)
        assert result.verdict in valid_verdicts

    def test_analysis_confidence_is_float(self):
        """Test that confidence is a float value"""
        finding = _make_finding()

        result = self.hunter.analyze(finding)
        assert isinstance(result.confidence, (int, float))
        assert 0 <= result.confidence <= 1

    def test_analysis_reasoning_is_string(self):
        """Test that reasoning is a string"""
        finding = _make_finding()

        result = self.hunter.analyze(finding)
        assert isinstance(result.reasoning, str)
        assert len(result.reasoning) > 0


class TestPersonaSpecialization:
    """Test that each persona has appropriate specialization"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_llm = _make_llm_mock()

    def test_secret_hunter_specialization(self):
        """Test SecretHunter specialization"""
        hunter = SecretHunter(self.mock_llm)

        expected_expertise = ["oauth_tokens", "api_keys", "passwords", "private_keys"]
        for skill in expected_expertise:
            assert skill in hunter.expertise

    def test_architecture_reviewer_specialization(self):
        """Test ArchitectureReviewer specialization"""
        reviewer = ArchitectureReviewer(self.mock_llm)

        expected_expertise = ["authentication_design", "authorization_patterns", "data_flow_security", "api_security"]
        for skill in expected_expertise:
            assert skill in reviewer.expertise

    def test_exploit_assessor_specialization(self):
        """Test ExploitAssessor specialization"""
        assessor = ExploitAssessor(self.mock_llm)

        expected_expertise = ["exploit_development", "attack_vectors", "cvss_scoring", "vulnerability_chaining"]
        for skill in expected_expertise:
            assert skill in assessor.expertise

    def test_false_positive_filter_specialization(self):
        """Test FalsePositiveFilter specialization"""
        fp_filter = FalsePositiveFilter(self.mock_llm)

        expected_expertise = ["test_patterns", "mock_data", "safe_contexts", "development_code"]
        for skill in expected_expertise:
            assert skill in fp_filter.expertise

    def test_threat_modeler_specialization(self):
        """Test ThreatModeler specialization"""
        modeler = ThreatModeler(self.mock_llm)

        expected_expertise = ["stride_methodology", "attack_trees", "threat_scenarios", "vulnerability_chaining"]
        for skill in expected_expertise:
            assert skill in modeler.expertise
