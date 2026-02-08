#!/usr/bin/env python3
"""
Multi-Agent Persona System for Argus Security Analysis
Inspired by Slack's security investigation agents.

This module provides specialized security analysis agents with different personas/roles:
- SecretHunter: Expert at finding hidden credentials and API keys
- ArchitectureReviewer: Finds design flaws and security gaps
- ExploitAssessor: Determines if findings are exploitable
- FalsePositiveFilter: Identifies noise and test code
- ThreatModeler: Identifies threat scenarios and attack chains

Each agent uses specialized prompts and domain expertise to provide
focused analysis of security findings.
"""

import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

# Import verdict taxonomy
from verdict_taxonomy import VerdictType, VerdictClassifier, VerdictMetadata

# Import enhanced FP detector and suppression policy
from enhanced_fp_detector import EnhancedFalsePositiveDetector
from suppression_policy import SuppressionPolicy

logger = logging.getLogger(__name__)


@dataclass
class AgentAnalysis:
    """Structured result from agent persona analysis"""

    agent_name: str
    confidence: float  # 0.0-1.0
    verdict: str  # Now supports 6 verdicts (kept as string for backward compat)
    reasoning: str
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    severity_adjustment: Optional[str] = None  # "upgrade", "downgrade", "maintain"
    exploitability_score: Optional[float] = None  # 0.0-1.0 (for ExploitAssessor)
    risk_factors: list[str] = field(default_factory=list)
    attack_scenarios: list[str] = field(default_factory=list)  # For ThreatModeler

    # NEW FIELDS
    verdict_type: Optional[VerdictType] = None  # Enum for type-safe comparison
    verdict_metadata: Optional[VerdictMetadata] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary with verdict metadata"""
        result = asdict(self)
        if self.verdict_type:
            result['verdict_type'] = self.verdict_type.value
            result['verdict_display_name'] = self.verdict_type.get_display_name()
            result['verdict_priority'] = self.verdict_type.get_priority()
        if self.verdict_metadata:
            result['verdict_metadata'] = {
                'confidence': self.verdict_metadata.confidence,
                'reasoning': self.verdict_metadata.reasoning,
                'review_reason': self.verdict_metadata.review_reason,
                'recommended_action': self.verdict_metadata.recommended_action
            }
        return result


class BaseAgentPersona(ABC):
    """Base class for specialized security analysis agents"""

    def __init__(self, llm_manager):
        """
        Initialize agent persona

        Args:
            llm_manager: LLMManager instance for AI analysis
        """
        self.llm = llm_manager
        self.name = ""
        self.role = ""
        self.expertise = []
        self.focus_areas = []
        self.prompt_template = ""

    @abstractmethod
    def analyze(self, finding: dict[str, Any]) -> AgentAnalysis:
        """
        Analyze a security finding with specialized expertise

        Args:
            finding: Finding dictionary (normalized format)

        Returns:
            AgentAnalysis with structured results
        """
        pass

    def _build_base_prompt(self, finding: dict[str, Any]) -> str:
        """
        Build base prompt with finding context

        Args:
            finding: Finding dictionary

        Returns:
            Formatted prompt string
        """
        file_path = finding.get("path", finding.get("file_path", "unknown"))
        line = finding.get("line", finding.get("line_number"))
        severity = finding.get("severity", "unknown")
        rule_id = finding.get("rule_id", "unknown")
        category = finding.get("category", "unknown")
        evidence = finding.get("evidence", {})

        # Extract code snippet if available
        code_snippet = evidence.get("snippet", evidence.get("code", ""))

        context = f"""
Finding Details:
- File: {file_path}
- Line: {line or "N/A"}
- Severity: {severity}
- Rule: {rule_id}
- Category: {category}
- Scanner: {finding.get("origin", "unknown")}

Code Context:
```
{code_snippet[:500] if code_snippet else "No code snippet available"}
```

Your Role: {self.role}
Your Expertise: {", ".join(self.expertise)}
"""
        return context

    def _parse_llm_response(self, response: str, agent_name: str, finding: dict[str, Any] = None) -> AgentAnalysis:
        """
        Parse LLM response into structured AgentAnalysis with new verdict taxonomy

        Args:
            response: Raw LLM response text
            agent_name: Name of the agent
            finding: Finding dictionary to extract severity (optional, defaults to "medium")

        Returns:
            Structured AgentAnalysis
        """
        # Extract confidence score first (needed for classification)
        confidence = 0.7  # default
        confidence_match = re.search(r"confidence:\s*(\d+(?:\.\d+)?)", response.lower())
        if confidence_match:
            confidence = float(confidence_match.group(1))
            # Normalize to 0-1 range if given as percentage
            if confidence > 1.0:
                confidence = confidence / 100.0

        # Extract old-style verdict for backward compatibility
        verdict_str = "needs_review"
        if "verdict: confirmed" in response.lower() or "confirmed vulnerable" in response.lower():
            verdict_str = "confirmed"
        elif "verdict: false positive" in response.lower() or "verdict: false_positive" in response.lower():
            verdict_str = "false_positive"
        elif "verdict: uncertain" in response.lower():  # NEW
            verdict_str = "uncertain"
        elif "verdict: likely true" in response.lower() or "verdict: likely_true" in response.lower():  # NEW
            verdict_str = "likely_true"
        elif "verdict: likely false positive" in response.lower() or "verdict: likely_fp" in response.lower():  # NEW
            verdict_str = "likely_fp"
        elif "verdict: needs review" in response.lower() or "needs_review" in response.lower():
            verdict_str = "needs_review"

        # Classify using new taxonomy with ACTUAL severity from finding
        analysis_complete = "analysis incomplete" not in response.lower()
        severity = finding.get("severity", "medium") if finding else "medium"

        verdict_type = VerdictClassifier.classify_verdict(
            confidence, analysis_complete, severity
        )

        # Extract reasoning (look for reasoning section)
        reasoning = ""
        reasoning_patterns = [
            r"reasoning:\s*(.+?)(?=\n\n|\nevidence:|\nrecommendations:|\nverdict:|$)",
            r"analysis:\s*(.+?)(?=\n\n|\nevidence:|\nrecommendations:|\nverdict:|$)",
        ]
        for pattern in reasoning_patterns:
            match = re.search(pattern, response, re.IGNORECASE | re.DOTALL)
            if match:
                reasoning = match.group(1).strip()
                break

        if not reasoning:
            # Use first substantial paragraph as reasoning
            lines = response.split("\n")
            reasoning_lines = [line.strip() for line in lines if len(line.strip()) > 50]
            reasoning = reasoning_lines[0] if reasoning_lines else response[:200]

        # Create verdict metadata
        review_reason = None
        if verdict_type in [VerdictType.UNCERTAIN, VerdictType.NEEDS_REVIEW]:
            # Try to extract why uncertain
            uncertain_match = re.search(
                r"uncertain because:?\s*(.+?)(?=\n\n|\nevidence:|\nrecommendations:|$)",
                response,
                re.IGNORECASE
            )
            if uncertain_match:
                review_reason = uncertain_match.group(1).strip()
            elif verdict_type == VerdictType.NEEDS_REVIEW:
                review_reason = "Analysis incomplete or insufficient information"

        verdict_metadata = VerdictMetadata(
            confidence=confidence,
            reasoning=reasoning,
            review_reason=review_reason,
            recommended_action=VerdictClassifier.get_recommended_action(verdict_type, severity)
        )

        # Extract evidence (bullet points or numbered lists)
        evidence = []
        evidence_section = re.search(
            r"evidence:\s*(.+?)(?=\n\n|\nrecommendations:|\nverdict:|$)",
            response,
            re.IGNORECASE | re.DOTALL,
        )
        if evidence_section:
            evidence_text = evidence_section.group(1)
            # Extract bullet points or numbered items
            evidence = re.findall(r"[-*•]\s*(.+?)(?=\n|$)", evidence_text)
            if not evidence:
                evidence = re.findall(r"\d+\.\s*(.+?)(?=\n|$)", evidence_text)

        # Extract recommendations
        recommendations = []
        rec_section = re.search(
            r"recommendations?:\s*(.+?)(?=\n\n|\nverdict:|$)",
            response,
            re.IGNORECASE | re.DOTALL,
        )
        if rec_section:
            rec_text = rec_section.group(1)
            recommendations = re.findall(r"[-*•]\s*(.+?)(?=\n|$)", rec_text)
            if not recommendations:
                recommendations = re.findall(r"\d+\.\s*(.+?)(?=\n|$)", rec_text)

        # Extract risk factors
        risk_factors = []
        risk_section = re.search(
            r"risk factors?:\s*(.+?)(?=\n\n|\nrecommendations:|\nverdict:|$)",
            response,
            re.IGNORECASE | re.DOTALL,
        )
        if risk_section:
            risk_text = risk_section.group(1)
            risk_factors = re.findall(r"[-*•]\s*(.+?)(?=\n|$)", risk_text)

        return AgentAnalysis(
            agent_name=agent_name,
            confidence=confidence,
            verdict=verdict_str,  # Backward compatible string
            reasoning=reasoning,
            evidence=evidence,
            recommendations=recommendations,
            risk_factors=risk_factors,
            verdict_type=verdict_type,  # NEW
            verdict_metadata=verdict_metadata  # NEW
        )

    def _call_llm(self, prompt: str, max_tokens: int = 1000) -> str:
        """
        Call LLM with prompt

        Args:
            prompt: Formatted prompt
            max_tokens: Maximum response tokens

        Returns:
            LLM response text
        """
        try:
            if not self.llm or not self.llm.client:
                logger.warning(f"{self.name}: LLM not initialized, skipping AI analysis")
                return "LLM not available"

            response_text, _, _ = self.llm.call_llm_api(prompt, max_tokens)
            return response_text
        except Exception as e:
            logger.error(f"{self.name}: LLM call failed: {e}")
            return f"Error: {str(e)}"


class SecretHunter(BaseAgentPersona):
    """Expert at finding hidden credentials and API keys"""

    def __init__(self, llm_manager):
        super().__init__(llm_manager)
        self.name = "SecretHunter"
        self.role = "Expert at finding hidden credentials, API keys, and sensitive data"
        self.expertise = [
            "oauth_tokens",
            "api_keys",
            "private_keys",
            "passwords",
            "database_credentials",
            "jwt_secrets",
            "encryption_keys",
        ]
        self.focus_areas = [
            "obfuscated secrets",
            "base64 encoded credentials",
            "split strings",
            "environment variables",
            "hardcoded credentials",
            "temporary tokens",
        ]

    def analyze(self, finding: dict[str, Any]) -> AgentAnalysis:
        """
        Analyze finding for secret patterns and credential exposure

        Args:
            finding: Finding dictionary

        Returns:
            AgentAnalysis with secret-specific assessment
        """
        logger.debug(f"{self.name}: Analyzing finding {finding.get('id', 'unknown')}")

        base_context = self._build_base_prompt(finding)

        # Build specialized prompt for secret detection
        prompt = f"""{base_context}

TASK: Analyze this potential secret/credential exposure with your expertise in secret detection.

Focus Areas:
1. Is this a real credential or test/example data?
2. Is the secret hardcoded, obfuscated, or in plain text?
3. What is the potential impact if this secret is compromised?
4. Are there indicators this is a false positive (test files, mocks, examples)?
5. What type of credential is this? (API key, OAuth token, private key, password, etc.)

Analysis Guidelines:
- Look for patterns like base64 encoding, split strings, or XOR obfuscation
- Check if the file path suggests test code (test/, mock/, example/, fixture/)
- Evaluate the entropy and format of the potential secret
- Consider if placeholder patterns are present (e.g., "YOUR_API_KEY_HERE", "example.com")
- Assess if the secret appears to be production vs development/test

Provide your analysis in this format:

Verdict: [confirmed/likely_true/uncertain/likely_fp/false_positive/needs_review]
Confidence: [0.0-1.0]

Verdict Guidelines:
- confirmed (0.9-1.0): Definite vulnerability
- likely_true (0.7-0.9): Probably vulnerable
- uncertain (0.4-0.7): Need more information
- likely_fp (0.2-0.4): Probably false positive
- false_positive (0.0-0.2): Definitely not vulnerable
- needs_review: Analysis inconclusive

Reasoning:
[Explain your assessment focusing on secret-specific indicators]

Evidence:
- [Key evidence point 1]
- [Key evidence point 2]
- [Key evidence point 3]

Risk Factors:
- [Risk factor 1 if confirmed]
- [Risk factor 2 if confirmed]

Recommendations:
- [Action item 1]
- [Action item 2]
"""

        response = self._call_llm(prompt, max_tokens=800)
        analysis = self._parse_llm_response(response, self.name, finding)

        # Additional secret-specific heuristics
        evidence = finding.get("evidence", {})
        code = evidence.get("snippet", evidence.get("code", ""))
        file_path = finding.get("path", "")

        # Downgrade confidence if clear test indicators
        test_indicators = ["test", "mock", "example", "fixture", "dummy", "sample"]
        if any(indicator in file_path.lower() for indicator in test_indicators):
            analysis.confidence *= 0.7
            analysis.evidence.append(f"File path contains test indicator: {file_path}")

        # Check for placeholder patterns
        placeholder_patterns = [
            r"your[_-]?api[_-]?key",
            r"example\.com",
            r"replace[_-]?me",
            r"xxx+",
            r"\*\*\*+",
            r"dummy",
        ]
        if any(re.search(pattern, code, re.IGNORECASE) for pattern in placeholder_patterns):
            analysis.verdict = "false_positive"
            analysis.confidence = max(0.9, analysis.confidence)
            analysis.evidence.append("Contains placeholder pattern")

        return analysis


class ArchitectureReviewer(BaseAgentPersona):
    """Finds design flaws and security gaps in architecture"""

    def __init__(self, llm_manager):
        super().__init__(llm_manager)
        self.name = "ArchitectureReviewer"
        self.role = "Expert at identifying architectural security flaws and design weaknesses"
        self.expertise = [
            "authentication_design",
            "authorization_patterns",
            "data_flow_security",
            "api_security",
            "session_management",
            "cryptographic_design",
        ]
        self.focus_areas = [
            "missing authentication",
            "broken access control",
            "insecure data exposure",
            "security boundaries",
            "privilege escalation paths",
        ]

    def analyze(self, finding: dict[str, Any]) -> AgentAnalysis:
        """
        Analyze finding for architectural security issues

        Args:
            finding: Finding dictionary

        Returns:
            AgentAnalysis with architecture-specific assessment
        """
        logger.debug(f"{self.name}: Analyzing finding {finding.get('id', 'unknown')}")

        base_context = self._build_base_prompt(finding)

        prompt = f"""{base_context}

TASK: Analyze this finding from an architectural security perspective.

Focus Areas:
1. Does this represent a systemic design flaw vs. a localized bug?
2. Are security boundaries properly defined and enforced?
3. Is there a missing security control (authentication, authorization, encryption)?
4. Could this enable privilege escalation or unauthorized access?
5. Does the data flow expose sensitive information inappropriately?

Analysis Guidelines:
- Identify if this is an architectural pattern problem vs. implementation issue
- Consider the broader security implications across the system
- Evaluate if proper security controls are in place
- Look for missing defense-in-depth layers
- Assess if this violates security principles (least privilege, secure by default, etc.)

Provide your analysis in this format:

Verdict: [confirmed/likely_true/uncertain/likely_fp/false_positive/needs_review]
Confidence: [0.0-1.0]

Verdict Guidelines:
- confirmed (0.9-1.0): Definite vulnerability
- likely_true (0.7-0.9): Probably vulnerable
- uncertain (0.4-0.7): Need more information
- likely_fp (0.2-0.4): Probably false positive
- false_positive (0.0-0.2): Definitely not vulnerable
- needs_review: Analysis inconclusive

Reasoning:
[Explain the architectural security implications]

Evidence:
- [Key architectural issue 1]
- [Key architectural issue 2]

Risk Factors:
- [Systemic risk 1]
- [Systemic risk 2]

Recommendations:
- [Architectural fix 1]
- [Architectural fix 2]
"""

        response = self._call_llm(prompt, max_tokens=800)
        analysis = self._parse_llm_response(response, self.name, finding)

        return analysis


class ExploitAssessor(BaseAgentPersona):
    """Determines if findings are actually exploitable"""

    def __init__(self, llm_manager):
        super().__init__(llm_manager)
        self.name = "ExploitAssessor"
        self.role = "Expert at assessing real-world exploitability and attack complexity"
        self.expertise = [
            "exploit_development",
            "attack_vectors",
            "cvss_scoring",
            "vulnerability_chaining",
            "security_controls",
        ]
        self.focus_areas = [
            "attack complexity",
            "required privileges",
            "user interaction",
            "exploit availability",
            "security mitigations",
        ]

    def analyze(self, finding: dict[str, Any]) -> AgentAnalysis:
        """
        Assess exploitability and attack feasibility

        Args:
            finding: Finding dictionary

        Returns:
            AgentAnalysis with exploitability assessment
        """
        logger.debug(f"{self.name}: Analyzing finding {finding.get('id', 'unknown')}")

        base_context = self._build_base_prompt(finding)

        prompt = f"""{base_context}

TASK: Assess the real-world exploitability of this security finding.

Focus Areas:
1. What is the attack complexity? (trivial, moderate, complex, theoretical)
2. What privileges/access does an attacker need?
3. Is user interaction required?
4. Are security controls in place that would prevent exploitation?
5. What is the potential business impact if exploited?

Analysis Guidelines:
- Consider CVSS metrics: Attack Vector, Attack Complexity, Privileges Required
- Evaluate if this is exploitable in production vs. only in dev/test
- Assess if existing security controls (WAF, authentication, input validation) mitigate this
- Consider if the vulnerability is publicly known with available exploits
- Determine if this requires chaining with other vulnerabilities

Provide your analysis in this format:

Verdict: [confirmed/likely_true/uncertain/likely_fp/false_positive/needs_review]
Confidence: [0.0-1.0]
Exploitability: [trivial/moderate/complex/theoretical]

Verdict Guidelines:
- confirmed (0.9-1.0): Definite vulnerability
- likely_true (0.7-0.9): Probably vulnerable
- uncertain (0.4-0.7): Need more information
- likely_fp (0.2-0.4): Probably false positive
- false_positive (0.0-0.2): Definitely not vulnerable
- needs_review: Analysis inconclusive

Reasoning:
[Explain the exploitability assessment with specific attack scenarios]

Evidence:
- [Attack vector detail 1]
- [Attack vector detail 2]

Risk Factors:
- [Exploitation risk 1]
- [Exploitation risk 2]

Recommendations:
- [Mitigation 1]
- [Mitigation 2]
"""

        response = self._call_llm(prompt, max_tokens=800)
        analysis = self._parse_llm_response(response, self.name, finding)

        # Extract exploitability score
        exploit_match = re.search(
            r"exploitability:\s*(trivial|moderate|complex|theoretical)",
            response.lower(),
        )
        if exploit_match:
            exploit_level = exploit_match.group(1)
            exploit_map = {
                "trivial": 0.9,
                "moderate": 0.6,
                "complex": 0.3,
                "theoretical": 0.1,
            }
            analysis.exploitability_score = exploit_map.get(exploit_level, 0.5)

        return analysis


class FalsePositiveFilter(BaseAgentPersona):
    """Identifies noise and test code that generates false positives"""

    def __init__(self, llm_manager):
        super().__init__(llm_manager)
        self.name = "FalsePositiveFilter"
        self.role = "Expert at identifying false positives, test code, and safe contexts"
        self.expertise = [
            "test_patterns",
            "mock_data",
            "safe_contexts",
            "development_code",
            "intentional_patterns",
            "oauth2_public_clients",  # Added
            "file_permissions",  # Added
            "locking_mechanisms",  # Added
        ]
        self.focus_areas = [
            "test files",
            "example code",
            "documentation",
            "commented code",
            "safe wrappers",
            "dev_only_configs",  # Added
        ]
        # Initialize enhanced detector and suppression policy
        self.enhanced_detector = EnhancedFalsePositiveDetector()
        self.suppression_policy = SuppressionPolicy()

    def analyze(self, finding: dict[str, Any]) -> AgentAnalysis:
        """
        Determine if finding is a false positive

        Args:
            finding: Finding dictionary

        Returns:
            AgentAnalysis with false positive assessment
        """
        logger.debug(f"{self.name}: Analyzing finding {finding.get('id', 'unknown')}")

        # First try enhanced detector
        enhanced_result = self.enhanced_detector.analyze(finding)
        if enhanced_result:
            logger.debug(f"Enhanced FP detector result: {enhanced_result.category}, FP={enhanced_result.is_false_positive}, confidence={enhanced_result.confidence}")

            # Evaluate suppression policy
            if enhanced_result.is_false_positive:
                suppression_decision = self.suppression_policy.evaluate_suppression(
                    enhanced_result, finding
                )

                if suppression_decision.can_suppress:
                    logger.info(f"✅ Suppression approved: {suppression_decision.reasoning}")
                    return AgentAnalysis(
                        agent_name=self.name,
                        confidence=enhanced_result.confidence,
                        verdict="false_positive",
                        reasoning=enhanced_result.reasoning,
                        evidence=enhanced_result.evidence + [
                            f"Policy: {suppression_decision.reasoning}"
                        ],
                        recommendations=["No action needed - false positive"],
                    )
                else:
                    logger.warning(f"⚠️ Suppression denied: {suppression_decision.reasoning}")
                    # Fall through to LLM analysis

            # Fallback: Use confidence-only check if suppression not evaluated
            elif enhanced_result.confidence > 0.7:
                return AgentAnalysis(
                    agent_name=self.name,
                    confidence=enhanced_result.confidence,
                    verdict="false_positive" if enhanced_result.is_false_positive else "confirmed",
                    reasoning=enhanced_result.reasoning,
                    evidence=enhanced_result.evidence,
                    recommendations=["No action needed - false positive" if enhanced_result.is_false_positive else "Address security issue"],
                )

        base_context = self._build_base_prompt(finding)

        file_path = finding.get("path", finding.get("file_path", ""))

        prompt = f"""{base_context}

TASK: Determine if this is a false positive or legitimate security issue.

Focus Areas:
1. Is this in test/mock/example code?
2. Is the code intentionally vulnerable for testing purposes?
3. Are there safe wrappers or security controls that mitigate this?
4. Is this commented-out code or documentation?
5. Is the context safe (e.g., admin-only endpoint, localhost-only)?
6. OAuth2: Is this a public client (SPA/mobile) that doesn't need a secret?
7. File Storage: Does the file have proper restrictive permissions?
8. Dev Config: Is this a dev-only flag that won't run in production?
9. Locking: Is this a proper mutex/file lock preventing race conditions?

Analysis Guidelines:
- Check file path for test/mock/example/fixture indicators
- Look for test frameworks (pytest, jest, junit, etc.)
- Identify if security controls are properly used
- Evaluate if the finding is in dead/unreachable code
- Consider if this is intentionally designed for security testing
- For OAuth2: Check for PKCE, public client patterns, absence of client_secret
- For file storage: Validate file permissions (should not be world-readable)
- For config flags: Check if wrapped in environment conditionals
- For locking: Distinguish mutex (thread sync) vs file locks (process sync)

Common False Positive Patterns:
- Test files with mock credentials
- Example code in documentation
- Security test fixtures
- Commented-out experimental code
- Development-only endpoints (when properly restricted)
- OAuth2 public clients using PKCE instead of secrets
- Config files with proper Unix permissions (600/644)
- Debug flags wrapped in NODE_ENV checks
- Proper mutex/lock usage preventing race conditions
- SQL code using parameterized queries (? placeholders, $1 params, :named params,
  execute(query, [params])) — NOT sql injection even if scanner flags concatenation
- Command execution using shell:false / shell=False with hardcoded arguments and
  no user-controllable input — NOT command injection
- Regex operations preceded by input validation/length limits (MAX_COUNT checks,
  .length < N, .slice()) — ReDoS risk already mitigated
- Localhost-only dev tools with missing auth — by design, not a vulnerability
- Resource exhaustion findings in local-only tools with no network exposure

Provide your analysis in this format:

Verdict: [confirmed/likely_true/uncertain/likely_fp/false_positive/needs_review]
Confidence: [0.0-1.0]

Verdict Guidelines:
- confirmed (0.9-1.0): Definite vulnerability
- likely_true (0.7-0.9): Probably vulnerable
- uncertain (0.4-0.7): Need more information
- likely_fp (0.2-0.4): Probably false positive
- false_positive (0.0-0.2): Definitely not vulnerable
- needs_review: Analysis inconclusive

Reasoning:
[Explain why this is or isn't a false positive]

Evidence:
- [FP indicator 1 OR legitimate issue indicator 1]
- [FP indicator 2 OR legitimate issue indicator 2]

Recommendations:
- [Action item 1]
- [Action item 2]
"""

        response = self._call_llm(prompt, max_tokens=800)
        analysis = self._parse_llm_response(response, self.name, finding)

        # Apply heuristic rules for common FP patterns
        fp_indicators = {
            "test/": 0.8,
            "tests/": 0.8,
            "spec/": 0.8,
            "__tests__/": 0.8,
            "mock": 0.7,
            "fixture": 0.7,
            "example": 0.6,
            "sample": 0.6,
            "demo": 0.6,
            "docs/": 0.5,
        }

        max_fp_score = 0.0
        for pattern, score in fp_indicators.items():
            if pattern in file_path.lower():
                max_fp_score = max(max_fp_score, score)

        if max_fp_score > 0.5:
            # High likelihood of false positive
            if analysis.verdict == "confirmed":
                analysis.verdict = "needs_review"
            elif analysis.verdict == "needs_review":
                analysis.verdict = "false_positive"

            analysis.confidence = max(analysis.confidence, max_fp_score)
            analysis.evidence.append(f"File path suggests test/example code: {file_path}")

        return analysis


class ThreatModeler(BaseAgentPersona):
    """Identifies threat scenarios and attack chains"""

    def __init__(self, llm_manager):
        super().__init__(llm_manager)
        self.name = "ThreatModeler"
        self.role = "Expert at threat modeling and identifying attack chains"
        self.expertise = [
            "stride_methodology",
            "attack_trees",
            "threat_scenarios",
            "vulnerability_chaining",
            "risk_assessment",
        ]
        self.focus_areas = [
            "spoofing",
            "tampering",
            "repudiation",
            "information_disclosure",
            "denial_of_service",
            "elevation_of_privilege",
        ]

    def analyze(self, finding: dict[str, Any]) -> AgentAnalysis:
        """
        Model threats and identify attack scenarios

        Args:
            finding: Finding dictionary

        Returns:
            AgentAnalysis with threat modeling insights
        """
        logger.debug(f"{self.name}: Analyzing finding {finding.get('id', 'unknown')}")

        base_context = self._build_base_prompt(finding)

        prompt = f"""{base_context}

TASK: Perform threat modeling on this security finding using STRIDE methodology.

STRIDE Categories:
- Spoofing: Can attacker impersonate a user/system?
- Tampering: Can attacker modify data/code?
- Repudiation: Can attacker deny actions?
- Information Disclosure: Can attacker access sensitive data?
- Denial of Service: Can attacker disrupt service?
- Elevation of Privilege: Can attacker gain unauthorized access?

Focus Areas:
1. Which STRIDE category does this vulnerability fall into?
2. What attack scenarios could exploit this finding?
3. Can this be chained with other vulnerabilities?
4. What is the attack path from initial access to impact?
5. What are the business/technical consequences?

Analysis Guidelines:
- Map the vulnerability to STRIDE categories
- Describe concrete attack scenarios step-by-step
- Identify potential attack chains
- Assess the likelihood and impact
- Consider attacker profiles (insider vs. external, skill level)

Provide your analysis in this format:

Verdict: [confirmed/likely_true/uncertain/likely_fp/false_positive/needs_review]
Confidence: [0.0-1.0]
STRIDE Categories: [e.g., "Information Disclosure, Elevation of Privilege"]

Verdict Guidelines:
- confirmed (0.9-1.0): Definite vulnerability
- likely_true (0.7-0.9): Probably vulnerable
- uncertain (0.4-0.7): Need more information
- likely_fp (0.2-0.4): Probably false positive
- false_positive (0.0-0.2): Definitely not vulnerable
- needs_review: Analysis inconclusive

Reasoning:
[Explain the threat modeling analysis]

Attack Scenarios:
- [Scenario 1: Step-by-step attack path]
- [Scenario 2: Alternative attack approach]

Risk Factors:
- [Risk factor 1]
- [Risk factor 2]

Recommendations:
- [Defense 1]
- [Defense 2]
"""

        response = self._call_llm(prompt, max_tokens=1000)
        analysis = self._parse_llm_response(response, self.name, finding)

        # Extract attack scenarios
        scenario_section = re.search(
            r"attack scenarios?:\s*(.+?)(?=\n\n|\nrisk factors?:|\nrecommendations?:|$)",
            response,
            re.IGNORECASE | re.DOTALL,
        )
        if scenario_section:
            scenario_text = scenario_section.group(1)
            scenarios = re.findall(r"[-*•]\s*(.+?)(?=\n|$)", scenario_text)
            if not scenarios:
                scenarios = re.findall(r"\d+\.\s*(.+?)(?=\n|$)", scenario_text)
            analysis.attack_scenarios = scenarios

        return analysis


# Agent Selection Logic


def select_agent_for_finding(finding: dict[str, Any], llm_manager) -> BaseAgentPersona:
    """
    Select the best agent persona for analyzing a specific finding

    Args:
        finding: Finding dictionary
        llm_manager: LLMManager instance

    Returns:
        Best-matched agent persona instance
    """
    category = finding.get("category", "").upper()
    rule_id = finding.get("rule_id", "").lower()
    file_path = finding.get("path", finding.get("file_path", "")).lower()
    severity = finding.get("severity", "").lower()

    # Secret-related findings → SecretHunter
    if category == "SECRETS" or "secret" in rule_id or "credential" in rule_id or "password" in rule_id:
        logger.debug("Selected SecretHunter for secrets finding")
        return SecretHunter(llm_manager)

    # Test files → FalsePositiveFilter
    if any(indicator in file_path for indicator in ["test", "spec", "mock", "fixture", "example"]):
        logger.debug("Selected FalsePositiveFilter for test file")
        return FalsePositiveFilter(llm_manager)

    # Critical/High severity vulnerabilities → ExploitAssessor
    if severity in ["critical", "high"]:
        logger.debug("Selected ExploitAssessor for high severity finding")
        return ExploitAssessor(llm_manager)

    # Architecture/design issues → ArchitectureReviewer
    arch_keywords = ["authentication", "authorization", "access-control", "session", "crypto"]
    if any(keyword in rule_id for keyword in arch_keywords):
        logger.debug("Selected ArchitectureReviewer for architectural finding")
        return ArchitectureReviewer(llm_manager)

    # Default to ThreatModeler for comprehensive analysis
    logger.debug("Selected ThreatModeler as default")
    return ThreatModeler(llm_manager)


def select_agents_for_discovery(finding: dict[str, Any], llm_manager, max_agents: int = 3) -> list[BaseAgentPersona]:
    """
    Select multiple agents for comprehensive analysis of a finding

    Args:
        finding: Finding dictionary
        llm_manager: LLMManager instance
        max_agents: Maximum number of agents to select (default: 3)

    Returns:
        List of agent persona instances
    """
    agents = []
    category = finding.get("category", "").upper()
    severity = finding.get("severity", "").lower()

    # Always run FalsePositiveFilter first for any finding
    agents.append(FalsePositiveFilter(llm_manager))

    # Add category-specific agent
    if category == "SECRETS":
        agents.append(SecretHunter(llm_manager))
    elif category in ["SAST", "SECURITY"]:
        agents.append(ArchitectureReviewer(llm_manager))

    # Add severity-based agent
    if severity in ["critical", "high"] and len(agents) < max_agents:
        if not any(isinstance(a, ExploitAssessor) for a in agents):
            agents.append(ExploitAssessor(llm_manager))

    # Add ThreatModeler for critical findings or if slots available
    if len(agents) < max_agents:
        if not any(isinstance(a, ThreatModeler) for a in agents):
            agents.append(ThreatModeler(llm_manager))

    logger.debug(f"Selected {len(agents)} agents for discovery: {[a.name for a in agents]}")
    return agents[:max_agents]


def run_multi_agent_analysis(
    finding: dict[str, Any],
    llm_manager,
    agents: Optional[list[BaseAgentPersona]] = None,
) -> list[AgentAnalysis]:
    """
    Run multiple agents on a finding and collect their analyses

    Args:
        finding: Finding dictionary
        llm_manager: LLMManager instance
        agents: Optional list of agents (if None, will auto-select)

    Returns:
        List of AgentAnalysis results
    """
    if agents is None:
        agents = select_agents_for_discovery(finding, llm_manager)

    results = []
    for agent in agents:
        try:
            logger.info(f"Running {agent.name} on finding {finding.get('id', 'unknown')}")
            analysis = agent.analyze(finding)
            results.append(analysis)
        except Exception as e:
            logger.error(f"Agent {agent.name} failed: {e}")
            # Continue with other agents

    return results


def build_consensus(analyses: list[AgentAnalysis]) -> dict[str, Any]:
    """
    Build consensus from multiple agent analyses with support for new verdict taxonomy

    Args:
        analyses: List of AgentAnalysis results

    Returns:
        Consensus result dictionary
    """
    if not analyses:
        return {
            "verdict": "needs_review",
            "confidence": 0.0,
            "reasoning": "No agent analyses available",
            "agreement_level": "none",
        }

    # Count verdicts (support both old and new formats)
    verdict_counts = {
        "confirmed": 0,
        "likely_true": 0,
        "uncertain": 0,
        "needs_review": 0,
        "likely_fp": 0,
        "false_positive": 0
    }
    total_confidence = 0.0
    all_evidence = []
    all_recommendations = []
    verdict_types = []

    for analysis in analyses:
        # Count by verdict string
        verdict_key = analysis.verdict
        if verdict_key in verdict_counts:
            verdict_counts[verdict_key] += 1
        else:
            # Fallback for unknown verdicts
            verdict_counts["needs_review"] += 1

        total_confidence += analysis.confidence
        all_evidence.extend(analysis.evidence)
        all_recommendations.extend(analysis.recommendations)

        # Track verdict types for priority-based consensus
        if analysis.verdict_type:
            verdict_types.append(analysis.verdict_type)

    # Determine consensus verdict using priority-based approach
    if verdict_types:
        # Use the highest priority verdict (lowest priority number = highest priority)
        consensus_verdict_type = min(verdict_types, key=lambda v: v.get_priority())
        consensus_verdict = consensus_verdict_type.value
    else:
        # Fallback to simple majority
        max_count = max(verdict_counts.values())
        consensus_verdict = [v for v, c in verdict_counts.items() if c == max_count][0]

    # Calculate agreement level
    verdict_with_max = verdict_counts[consensus_verdict]
    agreement_pct = verdict_with_max / len(analyses)
    if agreement_pct == 1.0:
        agreement_level = "unanimous"
    elif agreement_pct >= 0.67:
        agreement_level = "strong"
    elif agreement_pct >= 0.5:
        agreement_level = "majority"
    else:
        agreement_level = "weak"

    # Average confidence
    avg_confidence = total_confidence / len(analyses)

    # Aggregate reasoning
    reasoning_parts = [f"{a.agent_name}: {a.reasoning[:150]}" for a in analyses]
    combined_reasoning = " | ".join(reasoning_parts)

    return {
        "verdict": consensus_verdict,
        "confidence": avg_confidence,
        "reasoning": combined_reasoning,
        "agreement_level": agreement_level,
        "agent_verdicts": verdict_counts,
        "agents_analyzed": [a.agent_name for a in analyses],
        "evidence": list(set(all_evidence)),  # Deduplicate
        "recommendations": list(set(all_recommendations)),  # Deduplicate
    }


# Main CLI interface for testing
if __name__ == "__main__":
    import sys
    from pathlib import Path

    # Add parent directory to path for imports
    sys.path.insert(0, str(Path(__file__).parent))
    from orchestrator.llm_manager import LLMManager

    # Sample finding for testing
    sample_finding = {
        "id": "test-finding-001",
        "path": "src/api/auth.py",
        "line": 42,
        "severity": "high",
        "category": "SECRETS",
        "rule_id": "hardcoded-password",
        "origin": "semgrep",
        "evidence": {
            "snippet": 'password = "admin123"  # TODO: move to config',
            "code": 'password = "admin123"  # TODO: move to config',
        },
    }

    print("=" * 80)
    print("Agent Persona System Test")
    print("=" * 80)

    # Initialize LLM Manager (will use environment variables)
    config = {
        "ai_provider": "auto",
        "anthropic_api_key": os.environ.get("ANTHROPIC_API_KEY"),
        "openai_api_key": os.environ.get("OPENAI_API_KEY"),
    }
    llm_manager = LLMManager(config)

    if not llm_manager.initialize():
        print("WARNING: LLM not initialized. Agent analysis will be limited.")
    else:
        print(f"LLM initialized: {llm_manager.provider} / {llm_manager.model}\n")

    # Test single agent selection
    print("\n1. Single Agent Selection Test")
    print("-" * 80)
    agent = select_agent_for_finding(sample_finding, llm_manager)
    print(f"Selected Agent: {agent.name}")
    print(f"Role: {agent.role}")
    print(f"Expertise: {', '.join(agent.expertise)}")

    # Test multi-agent discovery
    print("\n2. Multi-Agent Discovery Test")
    print("-" * 80)
    agents = select_agents_for_discovery(sample_finding, llm_manager)
    for i, agent in enumerate(agents, 1):
        print(f"{i}. {agent.name} - {agent.role}")

    # Test analysis (if LLM is available)
    if llm_manager.client:
        print("\n3. Agent Analysis Test")
        print("-" * 80)
        results = run_multi_agent_analysis(sample_finding, llm_manager, agents[:2])

        for result in results:
            print(f"\n{result.agent_name}:")
            print(f"  Verdict: {result.verdict}")
            print(f"  Confidence: {result.confidence:.2f}")
            print(f"  Reasoning: {result.reasoning[:200]}...")

        # Build consensus
        print("\n4. Consensus Building Test")
        print("-" * 80)
        consensus = build_consensus(results)
        print(f"Consensus Verdict: {consensus['verdict']}")
        print(f"Agreement Level: {consensus['agreement_level']}")
        print(f"Confidence: {consensus['confidence']:.2f}")
        print(f"Agent Verdicts: {consensus['agent_verdicts']}")

    print("\n" + "=" * 80)
    print("Test completed!")
    print("=" * 80)
