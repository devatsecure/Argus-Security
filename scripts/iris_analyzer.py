#!/usr/bin/env python3
"""
IRIS-Style LLM Semantic Analyzer

Based on research: "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities"
arXiv 2405.17238, 2025

IRIS achieves:
- 2x more vulnerability detection than traditional SAST (55 vs 27 vulnerabilities)
- 5% improvement in false discovery rate over CodeQL
- Deep semantic reasoning for complex vulnerabilities

This module implements IRIS-style multi-step LLM reasoning for vulnerability analysis.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class VulnerabilityVerdict(Enum):
    """IRIS analysis verdict"""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


@dataclass
class IRISAnalysis:
    """
    Result of IRIS semantic analysis
    """
    verdict: VulnerabilityVerdict
    confidence: float  # 0.0-1.0

    # Multi-step reasoning components
    data_flow_analysis: str
    vulnerability_assessment: str
    impact_analysis: str

    # Detailed findings
    attack_vector: Optional[str] = None
    preconditions: List[str] = field(default_factory=list)
    exploitation_complexity: str = "UNKNOWN"  # LOW, MEDIUM, HIGH
    impact_severity: str = "UNKNOWN"  # CRITICAL, HIGH, MEDIUM, LOW

    # IRIS-specific metadata
    reasoning_steps: List[str] = field(default_factory=list)
    code_semantics: Dict[str, Any] = field(default_factory=dict)

    # Token usage tracking
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "data_flow_analysis": self.data_flow_analysis,
            "vulnerability_assessment": self.vulnerability_assessment,
            "impact_analysis": self.impact_analysis,
            "attack_vector": self.attack_vector,
            "preconditions": self.preconditions,
            "exploitation_complexity": self.exploitation_complexity,
            "impact_severity": self.impact_severity,
            "reasoning_steps": self.reasoning_steps,
            "code_semantics": self.code_semantics,
            "token_usage": {
                "input": self.input_tokens,
                "output": self.output_tokens,
                "cost_usd": self.cost_usd
            }
        }


@dataclass
class IRISFinding:
    """
    Enhanced finding with IRIS semantic analysis
    """
    original_finding_id: str
    iris_verified: bool
    iris_analysis: Optional[IRISAnalysis] = None

    # Enhanced metadata
    semantic_confidence: float = 0.0
    exploitability_score: float = 0.0  # 0.0-1.0
    business_impact: str = "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = {
            "finding_id": self.original_finding_id,
            "iris_verified": self.iris_verified,
            "semantic_confidence": self.semantic_confidence,
            "exploitability_score": self.exploitability_score,
            "business_impact": self.business_impact,
        }

        if self.iris_analysis:
            result["iris_analysis"] = self.iris_analysis.to_dict()

        return result


class IRISAnalyzer:
    """
    IRIS-style LLM semantic analyzer for vulnerability detection

    Implements multi-step reasoning approach:
    1. Data flow analysis - Track untrusted inputs through code
    2. Vulnerability assessment - Deep semantic understanding
    3. Impact analysis - Business and security impact
    4. Confidence scoring - High-confidence filtering (>0.85)
    """

    def __init__(self, ai_provider, confidence_threshold: float = 0.85):
        """
        Initialize IRIS analyzer

        Args:
            ai_provider: AI provider instance (AnthropicProvider, OpenAIProvider, etc.)
            confidence_threshold: Minimum confidence for True Positive verdict (default: 0.85)
        """
        self.ai_provider = ai_provider
        self.confidence_threshold = confidence_threshold
        self.total_cost = 0.0
        self.total_findings_analyzed = 0
        self.true_positives = 0
        self.false_positives = 0

        logger.info(f"IRIS Analyzer initialized (confidence threshold: {confidence_threshold})")

    def analyze_finding(
        self,
        finding: Dict[str, Any],
        code_context: str,
        repo_context: Optional[Dict[str, Any]] = None
    ) -> IRISFinding:
        """
        Perform IRIS-style semantic analysis on a finding

        Args:
            finding: Finding dictionary with metadata
            code_context: Source code surrounding the vulnerability
            repo_context: Optional repository-level context (frameworks, patterns, etc.)

        Returns:
            IRISFinding with semantic analysis results
        """
        self.total_findings_analyzed += 1

        try:
            # Build IRIS prompt with multi-step reasoning
            prompt = self._build_iris_prompt(finding, code_context, repo_context)

            # Get LLM analysis
            logger.debug(f"Analyzing finding {finding.get('id', 'unknown')} with IRIS")
            response = self.ai_provider.analyze(prompt)

            # Parse LLM response
            analysis = self._parse_llm_response(response)

            # Track token usage
            if hasattr(response, 'usage'):
                analysis.input_tokens = getattr(response.usage, 'input_tokens', 0)
                analysis.output_tokens = getattr(response.usage, 'output_tokens', 0)
                analysis.cost_usd = self._calculate_cost(response)
                self.total_cost += analysis.cost_usd

            # Determine verdict based on confidence
            if analysis.confidence >= self.confidence_threshold:
                analysis.verdict = VulnerabilityVerdict.TRUE_POSITIVE
                self.true_positives += 1
                iris_verified = True
            elif analysis.confidence <= 0.3:
                analysis.verdict = VulnerabilityVerdict.FALSE_POSITIVE
                self.false_positives += 1
                iris_verified = False
            else:
                analysis.verdict = VulnerabilityVerdict.UNCERTAIN
                iris_verified = False

            # Create IRIS finding
            iris_finding = IRISFinding(
                original_finding_id=finding.get('id', 'unknown'),
                iris_verified=iris_verified,
                iris_analysis=analysis,
                semantic_confidence=analysis.confidence,
                exploitability_score=self._calculate_exploitability(analysis),
                business_impact=analysis.impact_severity
            )

            logger.info(
                f"IRIS analysis complete: {analysis.verdict.value} "
                f"(confidence: {analysis.confidence:.2f})"
            )

            return iris_finding

        except Exception as e:
            logger.error(f"IRIS analysis failed for finding {finding.get('id')}: {e}")

            # Return unverified finding on error
            return IRISFinding(
                original_finding_id=finding.get('id', 'unknown'),
                iris_verified=False,
                iris_analysis=None
            )

    def _build_iris_prompt(
        self,
        finding: Dict[str, Any],
        code_context: str,
        repo_context: Optional[Dict[str, Any]]
    ) -> str:
        """
        Build IRIS-style multi-step reasoning prompt

        Based on IRIS paper's structured reasoning approach
        """

        # Extract finding metadata
        finding_type = finding.get('type', 'UNKNOWN')
        severity = finding.get('severity', 'UNKNOWN')
        cwe_id = finding.get('cwe_id', 'N/A')
        description = finding.get('description', 'No description')
        file_path = finding.get('file_path', 'unknown')
        line_number = finding.get('line_number', 0)

        # Repository context (if available)
        frameworks = []
        if repo_context:
            frameworks = repo_context.get('frameworks', [])

        frameworks_str = ", ".join(frameworks) if frameworks else "None detected"

        prompt = f"""You are a security expert performing deep semantic analysis of a potential vulnerability.

VULNERABILITY REPORT:
Type: {finding_type}
Severity: {severity}
CWE: {cwe_id}
Description: {description}
Location: {file_path}:{line_number}

REPOSITORY CONTEXT:
Frameworks: {frameworks_str}

VULNERABLE CODE:
```
{code_context}
```

Perform IRIS-style multi-step reasoning analysis:

## STEP 1: DATA FLOW ANALYSIS
Trace data flow to identify security-critical paths:
- Where does untrusted input originate? (user input, network, files, etc.)
- How is data transformed as it flows through the code?
- Are there sanitization/validation points?
- Does untrusted data reach a security-sensitive sink?

## STEP 2: VULNERABILITY ASSESSMENT
Analyze if this is a TRUE vulnerability or FALSE POSITIVE:
- Is there an actual exploitable security flaw?
- What are the PRECONDITIONS for exploitation?
- What SECURITY CONTROLS (if any) prevent exploitation?
- Is this test code, example code, or dead code?

## STEP 3: IMPACT ANALYSIS
If exploitable, assess the security impact:
- What is the ATTACK VECTOR? (network, local, physical)
- What is the WORST-CASE SCENARIO if exploited?
- What data/systems are at RISK?
- How COMPLEX is the exploitation? (low/medium/high)

## STEP 4: CONFIDENCE RATING
Rate your confidence this is a TRUE POSITIVE vulnerability:
- 0.9-1.0 = Definite vulnerability, clear exploit path
- 0.7-0.9 = Likely vulnerable, minor uncertainties
- 0.5-0.7 = Possible vulnerability, needs more context
- 0.3-0.5 = Probably false positive, weak evidence
- 0.0-0.3 = Definite false positive

## OUTPUT FORMAT (JSON):
{{
  "data_flow_analysis": "Detailed explanation of data flow...",
  "vulnerability_assessment": "Assessment of whether this is exploitable...",
  "impact_analysis": "Security and business impact...",
  "attack_vector": "Specific attack vector or null if false positive",
  "preconditions": ["condition1", "condition2"],
  "exploitation_complexity": "LOW|MEDIUM|HIGH",
  "impact_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0.0-1.0,
  "reasoning_steps": [
    "Step 1: Identified untrusted input from...",
    "Step 2: Traced data to sensitive sink...",
    "Step 3: No sanitization found..."
  ],
  "code_semantics": {{
    "input_sources": ["source1", "source2"],
    "sanitization_present": true/false,
    "sensitive_sinks": ["sink1", "sink2"]
  }}
}}

Respond with ONLY the JSON object, no additional text."""

        return prompt

    def _parse_llm_response(self, response: Any) -> IRISAnalysis:
        """
        Parse LLM response into IRISAnalysis structure

        Args:
            response: LLM response object

        Returns:
            IRISAnalysis with parsed data
        """
        try:
            # Extract content from response
            if hasattr(response, 'content'):
                # Anthropic format
                content = response.content[0].text if isinstance(response.content, list) else response.content
            elif hasattr(response, 'choices'):
                # OpenAI format
                content = response.choices[0].message.content
            else:
                content = str(response)

            # Parse JSON from content
            # Handle markdown code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            data = json.loads(content)

            # Create IRISAnalysis from parsed data
            analysis = IRISAnalysis(
                verdict=VulnerabilityVerdict.UNCERTAIN,  # Will be determined by confidence
                confidence=float(data.get('confidence', 0.5)),
                data_flow_analysis=data.get('data_flow_analysis', ''),
                vulnerability_assessment=data.get('vulnerability_assessment', ''),
                impact_analysis=data.get('impact_analysis', ''),
                attack_vector=data.get('attack_vector'),
                preconditions=data.get('preconditions', []),
                exploitation_complexity=data.get('exploitation_complexity', 'UNKNOWN'),
                impact_severity=data.get('impact_severity', 'UNKNOWN'),
                reasoning_steps=data.get('reasoning_steps', []),
                code_semantics=data.get('code_semantics', {})
            )

            return analysis

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            logger.debug(f"Response content: {content}")

            # Return low-confidence analysis on parse error
            return IRISAnalysis(
                verdict=VulnerabilityVerdict.UNCERTAIN,
                confidence=0.0,
                data_flow_analysis="Parse error - could not analyze",
                vulnerability_assessment="Parse error",
                impact_analysis="Parse error"
            )

        except Exception as e:
            logger.error(f"Unexpected error parsing LLM response: {e}")
            return IRISAnalysis(
                verdict=VulnerabilityVerdict.UNCERTAIN,
                confidence=0.0,
                data_flow_analysis="Error during analysis",
                vulnerability_assessment="Error",
                impact_analysis="Error"
            )

    def _calculate_cost(self, response: Any) -> float:
        """
        Calculate cost of LLM API call

        Args:
            response: LLM response with usage data

        Returns:
            Cost in USD
        """
        if not hasattr(response, 'usage'):
            return 0.0

        usage = response.usage
        input_tokens = getattr(usage, 'input_tokens', 0)
        output_tokens = getattr(usage, 'output_tokens', 0)

        # Pricing (approximate, update as needed)
        # Claude Sonnet 4.5: $3/MTok input, $15/MTok output
        # GPT-4: $30/MTok input, $60/MTok output
        # Ollama: Free

        # Default to Claude pricing
        input_cost = (input_tokens / 1_000_000) * 3.0
        output_cost = (output_tokens / 1_000_000) * 15.0

        return input_cost + output_cost

    def _calculate_exploitability(self, analysis: IRISAnalysis) -> float:
        """
        Calculate exploitability score based on IRIS analysis

        Args:
            analysis: IRIS analysis result

        Returns:
            Exploitability score (0.0-1.0)
        """
        score = analysis.confidence

        # Adjust based on exploitation complexity
        if analysis.exploitation_complexity == "LOW":
            score *= 1.2
        elif analysis.exploitation_complexity == "HIGH":
            score *= 0.8

        # Cap at 1.0
        return min(score, 1.0)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get IRIS analyzer statistics

        Returns:
            Dictionary with statistics
        """
        return {
            "total_findings_analyzed": self.total_findings_analyzed,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "uncertain": self.total_findings_analyzed - self.true_positives - self.false_positives,
            "total_cost_usd": round(self.total_cost, 2),
            "average_cost_per_finding": round(
                self.total_cost / max(self.total_findings_analyzed, 1), 4
            ),
            "true_positive_rate": round(
                self.true_positives / max(self.total_findings_analyzed, 1), 2
            )
        }


def load_code_context(file_path: str, line_number: int, lines_before: int = 20, lines_after: int = 20) -> str:
    """
    Load code context around a specific line

    Args:
        file_path: Path to source file
        line_number: Line number of interest
        lines_before: Lines to include before target line
        lines_after: Lines to include after target line

    Returns:
        Code context as string
    """
    try:
        if not os.path.exists(file_path):
            return f"# File not found: {file_path}"

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        # Calculate range
        start = max(0, line_number - lines_before - 1)
        end = min(len(lines), line_number + lines_after)

        # Build context with line numbers
        context_lines = []
        for i in range(start, end):
            line_num = i + 1
            marker = ">>> " if line_num == line_number else "    "
            context_lines.append(f"{marker}{line_num:4d} | {lines[i].rstrip()}")

        return "\n".join(context_lines)

    except Exception as e:
        logger.error(f"Failed to load code context from {file_path}:{line_number}: {e}")
        return f"# Error loading code context: {e}"


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)

    print("IRIS Analyzer Module")
    print("=" * 60)
    print("Based on research: arXiv 2405.17238, 2025")
    print("Multi-step LLM reasoning for vulnerability detection")
    print("=" * 60)
    print("\nThis module is ready for integration into the Argus pipeline.")
    print("Use IRISAnalyzer with your AI provider for semantic analysis.")
