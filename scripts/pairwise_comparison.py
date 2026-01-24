#!/usr/bin/env python3
"""
Pairwise Comparison Engine - Evaluate Argus vs Independent Codex Findings
Implements direct comparison with judge-based scoring to determine which analysis is better

Usage:
    python scripts/pairwise_comparison.py \
        --argus-findings argus_results.json \
        --codex-findings codex_results.json \
        --output comparison_report.json

Features:
- Pairwise evaluation of findings
- Direct comparison prompts with Claude/OpenAI judges
- 1-5 scale scoring for each finding
- Preference aggregation and statistics
- Detailed reasoning capture
"""

import argparse
import json
import logging
import os
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from normalizer.base import Finding
from providers.anthropic_provider import AnthropicProvider


@dataclass
class PairwiseComparison:
    """Comparison of a single finding pair"""

    finding_id: str
    argus_finding: Optional[Dict[str, Any]] = None
    codex_finding: Optional[Dict[str, Any]] = None
    match_type: str = "unmatched"  # matched, argus_only, codex_only

    # Judge scores (1-5 scale)
    argus_score: int = 0  # 1=very poor, 5=excellent
    codex_score: int = 0
    winner: str = "tie"  # argus, codex, tie

    # Detailed reasoning
    judge_reasoning: str = ""
    key_differences: List[str] = field(default_factory=list)
    agreement_aspects: List[str] = field(default_factory=list)
    disagreement_aspects: List[str] = field(default_factory=list)

    # Metrics
    coverage_score: float = 0.0  # How much detail was provided
    accuracy_score: float = 0.0  # Confidence in finding validity
    actionability_score: float = 0.0  # How actionable the recommendations are
    confidence: float = 0.9  # Judge confidence in comparison (0-1)

    # Timestamps
    compared_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class PairwiseAggregation:
    """Aggregated statistics from pairwise comparisons"""

    total_comparisons: int = 0
    matched_findings: int = 0
    argus_only: int = 0
    codex_only: int = 0

    # Win statistics
    argus_wins: int = 0
    codex_wins: int = 0
    ties: int = 0

    # Score aggregation
    avg_argus_score: float = 0.0
    avg_codex_score: float = 0.0
    avg_argus_coverage: float = 0.0
    avg_codex_coverage: float = 0.0
    avg_argus_accuracy: float = 0.0
    avg_codex_accuracy: float = 0.0
    avg_argus_actionability: float = 0.0
    avg_codex_actionability: float = 0.0

    # Preference metrics
    argus_win_rate: float = 0.0  # % of comparisons Argus won
    codex_win_rate: float = 0.0
    tie_rate: float = 0.0

    # Agreement metrics
    perfect_agreement: int = 0  # Both found same issue
    partial_agreement: int = 0  # Found related issues
    disagreement: int = 0  # Found different issues

    # Unique findings
    critical_by_argus: int = 0
    critical_by_codex: int = 0
    high_by_argus: int = 0
    high_by_codex: int = 0

    # Overall winner
    overall_winner: str = "tie"  # argus, codex, tie
    recommendation: str = ""


class FindingMatcher:
    """Matches findings between Argus and Codex results"""

    def __init__(self, match_threshold: float = 0.7):
        """Initialize matcher with configurable threshold

        Args:
            match_threshold: Similarity score (0-1) required to consider findings matched
        """
        self.match_threshold = match_threshold

    def match_findings(
        self,
        argus_findings: List[Dict[str, Any]],
        codex_findings: List[Dict[str, Any]]
    ) -> Tuple[List[Tuple[Dict, Dict]], List[Dict], List[Dict]]:
        """Match findings between two sets based on similarity

        Returns:
            Tuple of (matched_pairs, argus_only, codex_only)
        """
        matched_pairs: List[Tuple[Dict, Dict]] = []
        matched_codex_indices = set()
        unmatched_argus = []

        for agent_finding in argus_findings:
            best_match = None
            best_score = 0.0
            best_index = -1

            for idx, codex_finding in enumerate(codex_findings):
                if idx in matched_codex_indices:
                    continue

                score = self._calculate_similarity(agent_finding, codex_finding)
                if score > best_score:
                    best_score = score
                    best_match = codex_finding
                    best_index = idx

            if best_score >= self.match_threshold:
                matched_pairs.append((agent_finding, best_match))
                matched_codex_indices.add(best_index)
            else:
                unmatched_argus.append(agent_finding)

        unmatched_codex = [
            f for idx, f in enumerate(codex_findings)
            if idx not in matched_codex_indices
        ]

        return matched_pairs, unmatched_argus, unmatched_codex

    def _calculate_similarity(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> float:
        """Calculate similarity score between two findings (0-1)

        Considers:
        - Same file path
        - Same rule/category
        - Similar severity
        - Similar description
        """
        score = 0.0
        weights = {}

        # Path similarity (weight: 0.3)
        path1 = finding1.get("path", "").lower()
        path2 = finding2.get("path", "").lower()
        if path1 and path2:
            if path1 == path2:
                weights["path"] = 1.0
            elif path1.split("/")[-1] == path2.split("/")[-1]:
                weights["path"] = 0.7
            else:
                weights["path"] = 0.0

        # Rule/category similarity (weight: 0.3)
        rule1 = finding1.get("rule_id", finding1.get("category", "")).lower()
        rule2 = finding2.get("rule_id", finding2.get("category", "")).lower()
        if rule1 and rule2:
            weights["rule"] = 1.0 if rule1 == rule2 else 0.5 if rule1 in rule2 or rule2 in rule1 else 0.0

        # Severity similarity (weight: 0.2)
        sev1 = finding1.get("severity", "").lower()
        sev2 = finding2.get("severity", "").lower()
        if sev1 and sev2:
            weights["severity"] = 1.0 if sev1 == sev2 else 0.5

        # Message/description similarity (weight: 0.2)
        msg1 = finding1.get("message", finding1.get("rule_name", "")).lower()
        msg2 = finding2.get("message", finding2.get("rule_name", "")).lower()
        if msg1 and msg2:
            # Simple overlap check
            words1 = set(msg1.split())
            words2 = set(msg2.split())
            overlap = len(words1 & words2) / max(len(words1 | words2), 1)
            weights["message"] = overlap

        # Calculate average similarity score
        if weights:
            score = sum(weights.values()) / len(weights)

        return score


class PairwiseJudge:
    """Judge that evaluates and compares findings"""

    def __init__(self, judge_model: str = "anthropic"):
        """Initialize judge with specified AI model

        Args:
            judge_model: "anthropic" or "openai"
        """
        self.judge_model = judge_model
        self.judge_llm = None
        self._init_judge()

    def _init_judge(self):
        """Initialize judge LLM"""
        if self.judge_model == "anthropic":
            try:
                self.judge_llm = AnthropicProvider()
                logger.info("✅ Judge initialized with Anthropic Claude")
            except Exception as e:
                logger.error(f"Failed to initialize Anthropic judge: {e}")
                raise
        elif self.judge_model == "openai":
            try:
                import openai
                self.judge_llm = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                logger.info("✅ Judge initialized with OpenAI GPT")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI judge: {e}")
                raise
        else:
            raise ValueError(f"Unknown judge model: {self.judge_model}")

    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )
    def compare_matched_findings(
        self,
        argus_finding: Dict[str, Any],
        codex_finding: Dict[str, Any]
    ) -> PairwiseComparison:
        """Compare two matched findings and return detailed comparison

        Args:
            argus_finding: Finding from Argus
            codex_finding: Finding from Codex independent analysis

        Returns:
            PairwiseComparison with scores and reasoning
        """
        comparison_prompt = self._build_comparison_prompt(argus_finding, codex_finding)

        response = self._get_judge_response(comparison_prompt)

        # Parse judge response and extract scores
        comparison = self._parse_judge_response(
            response,
            argus_finding,
            codex_finding,
            "matched"
        )

        return comparison

    def compare_unmatched_finding(
        self,
        finding: Dict[str, Any],
        tool_name: str  # "argus" or "codex"
    ) -> PairwiseComparison:
        """Evaluate an unmatched finding (found by only one tool)

        Args:
            finding: The finding to evaluate
            tool_name: Which tool found this finding

        Returns:
            PairwiseComparison with evaluation
        """
        evaluation_prompt = self._build_evaluation_prompt(finding, tool_name)

        response = self._get_judge_response(evaluation_prompt)

        # Parse response and extract evaluation
        comparison = self._parse_evaluation_response(
            response,
            finding,
            tool_name
        )

        return comparison

    def _build_comparison_prompt(
        self,
        argus_finding: Dict[str, Any],
        codex_finding: Dict[str, Any]
    ) -> str:
        """Build prompt for comparing two matched findings"""
        prompt = f"""You are a security expert evaluating two security analysis reports.
Both tools found a similar security issue. Your job is to compare their analyses and determine which one is better.

ARGUS FINDING (Anthropic Claude):
File: {argus_finding.get('path', 'unknown')}
Severity: {argus_finding.get('severity', 'unknown')}
Rule: {argus_finding.get('rule_id', argus_finding.get('rule_name', 'unknown'))}
Message: {argus_finding.get('message', 'unknown')}
Evidence: {json.dumps(argus_finding.get('evidence', {}), indent=2)}
References: {json.dumps(argus_finding.get('references', []))}
Confidence: {argus_finding.get('confidence', 'unknown')}

CODEX FINDING (Independent Analysis):
File: {codex_finding.get('path', 'unknown')}
Severity: {codex_finding.get('severity', 'unknown')}
Rule: {codex_finding.get('rule_id', codex_finding.get('rule_name', 'unknown'))}
Message: {codex_finding.get('message', 'unknown')}
Evidence: {json.dumps(codex_finding.get('evidence', {}), indent=2)}
References: {json.dumps(codex_finding.get('references', []))}
Confidence: {codex_finding.get('confidence', 'unknown')}

EVALUATION CRITERIA:
1. Coverage (1-5): How comprehensive is the analysis? Does it explain context, impact, and scope?
2. Accuracy (1-5): How confident are you that this finding is correct and represents a real issue?
3. Actionability (1-5): How clear and actionable are the recommendations for remediation?
4. Detail (1-5): Does the finding provide sufficient evidence and proof?
5. Risk Assessment (1-5): Is the severity assessment appropriate and well-justified?

YOUR TASK:
For each tool, rate on the evaluation criteria above. Then determine:
- Which analysis is better overall?
- What are the key differences in their approaches?
- What does each tool do better?
- What could each tool improve?

RESPOND WITH JSON ONLY, no other text:
{{
    "argus_scores": {{
        "coverage": <1-5>,
        "accuracy": <1-5>,
        "actionability": <1-5>,
        "detail": <1-5>,
        "risk_assessment": <1-5>
    }},
    "codex_scores": {{
        "coverage": <1-5>,
        "accuracy": <1-5>,
        "actionability": <1-5>,
        "detail": <1-5>,
        "risk_assessment": <1-5>
    }},
    "winner": "<argus|codex|tie>",
    "reasoning": "<detailed explanation of why one is better>",
    "key_differences": ["<difference 1>", "<difference 2>", ...],
    "agreement_aspects": ["<aspect 1>", "<aspect 2>", ...],
    "disagreement_aspects": ["<aspect 1>", "<aspect 2>", ...],
    "confidence": <0.0-1.0>
}}"""
        return prompt

    def _build_evaluation_prompt(self, finding: Dict[str, Any], tool_name: str) -> str:
        """Build prompt for evaluating an unmatched finding"""
        tool_label = "ARGUS (Anthropic Claude)" if tool_name == "argus" else "CODEX (Independent)"

        prompt = f"""You are a security expert evaluating a security finding found by {tool_label}.

FINDING TO EVALUATE:
File: {finding.get('path', 'unknown')}
Severity: {finding.get('severity', 'unknown')}
Rule: {finding.get('rule_id', finding.get('rule_name', 'unknown'))}
Message: {finding.get('message', 'unknown')}
Evidence: {json.dumps(finding.get('evidence', {}), indent=2)}
References: {json.dumps(finding.get('references', []))}
Confidence: {finding.get('confidence', 'unknown')}

EVALUATION CRITERIA (1-5 scale):
1. Validity: Is this a real security issue or a false positive?
2. Coverage: How well is the issue explained and contextualized?
3. Actionability: How clear are the remediation steps?
4. Severity Accuracy: Is the severity rating appropriate?
5. Completeness: Does it provide sufficient evidence?

YOUR TASK:
Evaluate this finding that was only found by {tool_label}. Consider:
- Is this likely a real vulnerability or false positive?
- How well was it analyzed?
- Why might the other tool have missed this?
- What is the genuine security risk?

RESPOND WITH JSON ONLY:
{{
    "validity_score": <1-5>,
    "coverage_score": <1-5>,
    "actionability_score": <1-5>,
    "severity_accuracy_score": <1-5>,
    "completeness_score": <1-5>,
    "likely_real": <true|false>,
    "reasoning": "<why this finding is important or questionable>",
    "why_other_missed_it": "<potential reason other tool didn't find this>",
    "confidence": <0.0-1.0>
}}"""
        return prompt

    def _get_judge_response(self, prompt: str) -> str:
        """Get response from judge LLM"""
        if self.judge_model == "anthropic":
            return self.judge_llm.generate(
                prompt,
                system_prompt="You are an expert security analyst. Always respond with valid JSON."
            )
        elif self.judge_model == "openai":
            response = self.judge_llm.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=2000,
            )
            return response.choices[0].message.content

    def _parse_judge_response(
        self,
        response: str,
        argus_finding: Dict[str, Any],
        codex_finding: Dict[str, Any],
        match_type: str
    ) -> PairwiseComparison:
        """Parse judge response into PairwiseComparison"""
        try:
            # Extract JSON from response
            import re
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(response)

            # Calculate average scores
            argus_scores = data.get("argus_scores", {})
            codex_scores = data.get("codex_scores", {})

            argus_avg = sum(argus_scores.values()) / max(len(argus_scores), 1)
            codex_avg = sum(codex_scores.values()) / max(len(codex_scores), 1)

            comparison = PairwiseComparison(
                finding_id=argus_finding.get("id", f"comparison_{datetime.now().timestamp()}"),
                argus_finding=argus_finding,
                codex_finding=codex_finding,
                match_type=match_type,
                argus_score=int(argus_avg),
                codex_score=int(codex_avg),
                winner=data.get("winner", "tie"),
                judge_reasoning=data.get("reasoning", ""),
                key_differences=data.get("key_differences", []),
                agreement_aspects=data.get("agreement_aspects", []),
                disagreement_aspects=data.get("disagreement_aspects", []),
                coverage_score=(argus_scores.get("coverage", 0) + codex_scores.get("coverage", 0)) / 2,
                accuracy_score=(argus_scores.get("accuracy", 0) + codex_scores.get("accuracy", 0)) / 2,
                actionability_score=(argus_scores.get("actionability", 0) + codex_scores.get("actionability", 0)) / 2,
                confidence=float(data.get("confidence", 0.9))
            )

            return comparison

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse judge response: {e}")
            # Return neutral comparison
            return PairwiseComparison(
                finding_id=argus_finding.get("id", "unknown"),
                argus_finding=argus_finding,
                codex_finding=codex_finding,
                match_type=match_type,
                argus_score=3,
                codex_score=3,
                winner="tie",
                judge_reasoning=f"Unable to parse judge response: {response[:200]}",
                confidence=0.3
            )

    def _parse_evaluation_response(
        self,
        response: str,
        finding: Dict[str, Any],
        tool_name: str
    ) -> PairwiseComparison:
        """Parse evaluation response for unmatched finding"""
        try:
            import re
            json_match = re.search(r"\{.*\}", response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(response)

            if tool_name == "argus":
                comparison = PairwiseComparison(
                    finding_id=finding.get("id", f"argus_{datetime.now().timestamp()}"),
                    argus_finding=finding,
                    match_type="argus_only",
                    argus_score=int(sum(data.get("validity_score", 0) + data.get("coverage_score", 0) +
                                           data.get("actionability_score", 0)) / 3),
                    codex_score=0,
                    winner="argus" if data.get("likely_real") else "codex",
                    judge_reasoning=data.get("reasoning", ""),
                    confidence=float(data.get("confidence", 0.9))
                )
            else:
                comparison = PairwiseComparison(
                    finding_id=finding.get("id", f"codex_{datetime.now().timestamp()}"),
                    codex_finding=finding,
                    match_type="codex_only",
                    argus_score=0,
                    codex_score=int(sum(data.get("validity_score", 0) + data.get("coverage_score", 0) +
                                        data.get("actionability_score", 0)) / 3),
                    winner="codex" if data.get("likely_real") else "argus",
                    judge_reasoning=data.get("reasoning", ""),
                    confidence=float(data.get("confidence", 0.9))
                )

            return comparison

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse evaluation response: {e}")
            return PairwiseComparison(
                finding_id=finding.get("id", "unknown"),
                argus_finding=finding if tool_name == "argus" else None,
                codex_finding=finding if tool_name == "codex" else None,
                match_type=f"{tool_name}_only",
                argus_score=3 if tool_name == "argus" else 0,
                codex_score=3 if tool_name == "codex" else 0,
                winner="tie",
                confidence=0.3
            )


class PairwiseComparator:
    """Main orchestrator for pairwise comparison"""

    def __init__(
        self,
        argus_findings: List[Dict[str, Any]],
        codex_findings: List[Dict[str, Any]],
        judge_model: str = "anthropic",
        match_threshold: float = 0.7
    ):
        """Initialize comparator

        Args:
            argus_findings: Findings from Argus
            codex_findings: Findings from Codex independent analysis
            judge_model: "anthropic" or "openai"
            match_threshold: Similarity threshold for matching (0-1)
        """
        self.argus_findings = argus_findings
        self.codex_findings = codex_findings
        self.matcher = FindingMatcher(match_threshold=match_threshold)
        self.judge = PairwiseJudge(judge_model=judge_model)
        self.comparisons: List[PairwiseComparison] = []

    def run_comparison(self, max_comparisons: Optional[int] = None) -> PairwiseAggregation:
        """Run complete pairwise comparison

        Args:
            max_comparisons: Max number of comparisons to run (for cost limiting)

        Returns:
            PairwiseAggregation with results
        """
        logger.info(f"\n{'='*80}")
        logger.info(f"Pairwise Comparison Analysis")
        logger.info(f"Argus Findings: {len(self.argus_findings)}")
        logger.info(f"Codex Findings: {len(self.codex_findings)}")
        logger.info(f"{'='*80}\n")

        # Step 1: Match findings
        logger.info("Step 1: Matching findings between Argus and Codex...")
        matched_pairs, argus_only, codex_only = self.matcher.match_findings(
            self.argus_findings,
            self.codex_findings
        )
        logger.info(f"  Matched pairs: {len(matched_pairs)}")
        logger.info(f"  Argus only: {len(argus_only)}")
        logger.info(f"  Codex only: {len(codex_only)}\n")

        # Step 2: Compare matched findings
        logger.info("Step 2: Comparing matched findings with judge...")
        comparison_count = 0
        for argus_finding, codex_finding in matched_pairs:
            if max_comparisons and comparison_count >= max_comparisons:
                logger.info(f"Reached max comparisons ({max_comparisons}), stopping...")
                break

            logger.info(f"  Comparing {comparison_count + 1}/{len(matched_pairs)}...")
            try:
                comparison = self.judge.compare_matched_findings(argus_finding, codex_finding)
                self.comparisons.append(comparison)
                comparison_count += 1
            except Exception as e:
                logger.error(f"Failed to compare findings: {e}")
                # Add a neutral comparison
                self.comparisons.append(
                    PairwiseComparison(
                        finding_id=argus_finding.get("id", f"comparison_{comparison_count}"),
                        argus_finding=argus_finding,
                        codex_finding=codex_finding,
                        match_type="matched",
                        winner="tie",
                        judge_reasoning=f"Comparison failed: {str(e)}",
                        confidence=0.0
                    )
                )

        # Step 3: Evaluate unmatched findings
        logger.info(f"\nStep 3: Evaluating unmatched findings...")

        for finding in argus_only:
            if max_comparisons and len(self.comparisons) >= max_comparisons:
                break
            logger.info(f"  Evaluating Argus finding (not in Codex)...")
            try:
                comparison = self.judge.compare_unmatched_finding(finding, "argus")
                self.comparisons.append(comparison)
            except Exception as e:
                logger.error(f"Failed to evaluate Argus finding: {e}")

        for finding in codex_only:
            if max_comparisons and len(self.comparisons) >= max_comparisons:
                break
            logger.info(f"  Evaluating Codex finding (not in Argus)...")
            try:
                comparison = self.judge.compare_unmatched_finding(finding, "codex")
                self.comparisons.append(comparison)
            except Exception as e:
                logger.error(f"Failed to evaluate Codex finding: {e}")

        # Step 4: Aggregate results
        logger.info(f"\nStep 4: Aggregating results...")
        aggregation = self._aggregate_comparisons()

        return aggregation

    def _aggregate_comparisons(self) -> PairwiseAggregation:
        """Aggregate all comparisons into statistics"""
        agg = PairwiseAggregation()
        agg.total_comparisons = len(self.comparisons)

        if not self.comparisons:
            logger.warning("No comparisons to aggregate")
            return agg

        # Count match types
        agg.matched_findings = sum(1 for c in self.comparisons if c.match_type == "matched")
        agg.argus_only = sum(1 for c in self.comparisons if c.match_type == "argus_only")
        agg.codex_only = sum(1 for c in self.comparisons if c.match_type == "codex_only")

        # Count wins
        agg.argus_wins = sum(1 for c in self.comparisons if c.winner == "argus")
        agg.codex_wins = sum(1 for c in self.comparisons if c.winner == "codex")
        agg.ties = sum(1 for c in self.comparisons if c.winner == "tie")

        # Win rates
        if agg.total_comparisons > 0:
            agg.argus_win_rate = agg.argus_wins / agg.total_comparisons
            agg.codex_win_rate = agg.codex_wins / agg.total_comparisons
            agg.tie_rate = agg.ties / agg.total_comparisons

        # Average scores
        argus_scores = [c.argus_score for c in self.comparisons if c.argus_score > 0]
        codex_scores = [c.codex_score for c in self.comparisons if c.codex_score > 0]

        if argus_scores:
            agg.avg_argus_score = sum(argus_scores) / len(argus_scores)
        if codex_scores:
            agg.avg_codex_score = sum(codex_scores) / len(codex_scores)

        # Coverage/accuracy/actionability scores
        argus_coverage = [c.coverage_score for c in self.comparisons if c.argus_finding]
        codex_coverage = [c.coverage_score for c in self.comparisons if c.codex_finding]
        argus_accuracy = [c.accuracy_score for c in self.comparisons if c.argus_finding]
        codex_accuracy = [c.accuracy_score for c in self.comparisons if c.codex_finding]
        argus_actionability = [c.actionability_score for c in self.comparisons if c.argus_finding]
        codex_actionability = [c.actionability_score for c in self.comparisons if c.codex_finding]

        if argus_coverage:
            agg.avg_argus_coverage = sum(argus_coverage) / len(argus_coverage)
        if codex_coverage:
            agg.avg_codex_coverage = sum(codex_coverage) / len(codex_coverage)
        if argus_accuracy:
            agg.avg_argus_accuracy = sum(argus_accuracy) / len(argus_accuracy)
        if codex_accuracy:
            agg.avg_codex_accuracy = sum(codex_accuracy) / len(codex_accuracy)
        if argus_actionability:
            agg.avg_argus_actionability = sum(argus_actionability) / len(argus_actionability)
        if codex_actionability:
            agg.avg_codex_actionability = sum(codex_actionability) / len(codex_actionability)

        # Count severity findings
        for finding in self.argus_findings:
            severity = finding.get("severity", "").lower()
            if severity == "critical":
                agg.critical_by_argus += 1
            elif severity == "high":
                agg.high_by_argus += 1

        for finding in self.codex_findings:
            severity = finding.get("severity", "").lower()
            if severity == "critical":
                agg.critical_by_codex += 1
            elif severity == "high":
                agg.high_by_codex += 1

        # Determine overall winner
        if agg.avg_argus_score > agg.avg_codex_score + 0.5:
            agg.overall_winner = "argus"
            agg.recommendation = "Argus provided superior analysis overall with higher coverage and accuracy"
        elif agg.avg_codex_score > agg.avg_argus_score + 0.5:
            agg.overall_winner = "codex"
            agg.recommendation = "Codex provided superior analysis overall with higher coverage and accuracy"
        else:
            agg.overall_winner = "tie"
            agg.recommendation = "Both tools provided comparable analysis with different strengths"

        return agg


class ComparisonReportGenerator:
    """Generates detailed comparison reports"""

    @staticmethod
    def generate_json_report(
        comparisons: List[PairwiseComparison],
        aggregation: PairwiseAggregation,
        output_file: str
    ) -> str:
        """Generate JSON report"""
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "aggregation": asdict(aggregation),
            "comparisons": [c.to_dict() for c in comparisons]
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"✅ JSON report written to {output_file}")
        return output_file

    @staticmethod
    def generate_markdown_report(
        comparisons: List[PairwiseComparison],
        aggregation: PairwiseAggregation,
        output_file: str
    ) -> str:
        """Generate Markdown report"""
        report = f"""# Pairwise Comparison Analysis Report
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary

### Overall Result
**Winner**: {aggregation.overall_winner.upper()}
**Recommendation**: {aggregation.recommendation}

### Key Metrics
| Metric | Argus | Codex |
|--------|----------|-------|
| **Wins** | {aggregation.argus_wins} ({aggregation.argus_win_rate*100:.1f}%) | {aggregation.codex_wins} ({aggregation.codex_win_rate*100:.1f}%) |
| **Average Score** | {aggregation.avg_argus_score:.1f}/5 | {aggregation.avg_codex_score:.1f}/5 |
| **Coverage** | {aggregation.avg_argus_coverage:.1f}/5 | {aggregation.avg_codex_coverage:.1f}/5 |
| **Accuracy** | {aggregation.avg_argus_accuracy:.1f}/5 | {aggregation.avg_codex_accuracy:.1f}/5 |
| **Actionability** | {aggregation.avg_argus_actionability:.1f}/5 | {aggregation.avg_codex_actionability:.1f}/5 |
| **Critical Findings** | {aggregation.critical_by_argus} | {aggregation.critical_by_codex} |
| **High Findings** | {aggregation.high_by_argus} | {aggregation.high_by_codex} |

### Comparison Breakdown
- **Matched Findings**: {aggregation.matched_findings}
- **Argus Only**: {aggregation.argus_only}
- **Codex Only**: {aggregation.codex_only}
- **Ties**: {aggregation.ties}
- **Total Comparisons**: {aggregation.total_comparisons}

---

## Detailed Comparisons

"""

        # Add matched comparisons
        matched_comps = [c for c in comparisons if c.match_type == "matched"]
        if matched_comps:
            report += f"### Matched Findings ({len(matched_comps)})\n\n"
            for comp in matched_comps:
                report += ComparisonReportGenerator._format_comparison(comp)

        # Add unmatched comparisons
        argus_only_comps = [c for c in comparisons if c.match_type == "argus_only"]
        if argus_only_comps:
            report += f"\n### Argus Only Findings ({len(argus_only_comps)})\n\n"
            for comp in argus_only_comps:
                report += ComparisonReportGenerator._format_comparison(comp)

        codex_only_comps = [c for c in comparisons if c.match_type == "codex_only"]
        if codex_only_comps:
            report += f"\n### Codex Only Findings ({len(codex_only_comps)})\n\n"
            for comp in codex_only_comps:
                report += ComparisonReportGenerator._format_comparison(comp)

        # Add analysis summary
        report += "\n---\n\n## Analysis Summary\n\n"
        report += ComparisonReportGenerator._generate_analysis_summary(aggregation, comparisons)

        with open(output_file, 'w') as f:
            f.write(report)

        logger.info(f"✅ Markdown report written to {output_file}")
        return output_file

    @staticmethod
    def _format_comparison(comp: PairwiseComparison) -> str:
        """Format a single comparison for markdown"""
        text = f"#### Finding: {comp.finding_id}\n\n"

        if comp.match_type == "matched":
            text += f"**Status**: Both tools found this issue\n\n"
            if comp.argus_finding:
                text += f"**Argus**: Score {comp.argus_score}/5\n"
                text += f"- Severity: {comp.argus_finding.get('severity', 'unknown')}\n"
                text += f"- Rule: {comp.argus_finding.get('rule_id', 'unknown')}\n"
            if comp.codex_finding:
                text += f"\n**Codex**: Score {comp.codex_score}/5\n"
                text += f"- Severity: {comp.codex_finding.get('severity', 'unknown')}\n"
                text += f"- Rule: {comp.codex_finding.get('rule_id', 'unknown')}\n"
        elif comp.match_type == "argus_only":
            text += f"**Status**: Found by Argus only\n\n"
            text += f"**Score**: {comp.argus_score}/5\n"
            if comp.argus_finding:
                text += f"- Severity: {comp.argus_finding.get('severity', 'unknown')}\n"
                text += f"- File: {comp.argus_finding.get('path', 'unknown')}\n"
        else:  # codex_only
            text += f"**Status**: Found by Codex only\n\n"
            text += f"**Score**: {comp.codex_score}/5\n"
            if comp.codex_finding:
                text += f"- Severity: {comp.codex_finding.get('severity', 'unknown')}\n"
                text += f"- File: {comp.codex_finding.get('path', 'unknown')}\n"

        text += f"\n**Winner**: {comp.winner.upper()}\n"
        text += f"**Confidence**: {comp.confidence*100:.0f}%\n\n"

        if comp.judge_reasoning:
            text += f"**Judge Reasoning**:\n{comp.judge_reasoning}\n\n"

        if comp.key_differences:
            text += f"**Key Differences**:\n"
            for diff in comp.key_differences:
                text += f"- {diff}\n"
            text += "\n"

        if comp.agreement_aspects:
            text += f"**Agreement**:\n"
            for aspect in comp.agreement_aspects:
                text += f"- {aspect}\n"
            text += "\n"

        text += "---\n\n"
        return text

    @staticmethod
    def _generate_analysis_summary(aggregation: PairwiseAggregation, comparisons: List[PairwiseComparison]) -> str:
        """Generate analysis summary"""
        summary = ""

        # Winner analysis
        if aggregation.overall_winner == "argus":
            summary += "### Argus Advantage\n\n"
            summary += f"Argus won {aggregation.argus_wins} out of {aggregation.total_comparisons} comparisons "
            summary += f"({aggregation.argus_win_rate*100:.1f}%), with an average score of {aggregation.avg_argus_score:.1f}/5.\n\n"
            summary += "**Strengths**:\n"
            summary += f"- Higher coverage score ({aggregation.avg_argus_coverage:.1f}/5)\n"
            summary += f"- Better accuracy assessment ({aggregation.avg_argus_accuracy:.1f}/5)\n"
            summary += f"- More actionable recommendations ({aggregation.avg_argus_actionability:.1f}/5)\n\n"
        elif aggregation.overall_winner == "codex":
            summary += "### Codex Advantage\n\n"
            summary += f"Codex won {aggregation.codex_wins} out of {aggregation.total_comparisons} comparisons "
            summary += f"({aggregation.codex_win_rate*100:.1f}%), with an average score of {aggregation.avg_codex_score:.1f}/5.\n\n"
            summary += "**Strengths**:\n"
            summary += f"- Higher coverage score ({aggregation.avg_codex_coverage:.1f}/5)\n"
            summary += f"- Better accuracy assessment ({aggregation.avg_codex_accuracy:.1f}/5)\n"
            summary += f"- More actionable recommendations ({aggregation.avg_codex_actionability:.1f}/5)\n\n"
        else:
            summary += "### Comparable Performance\n\n"
            summary += f"Both tools performed similarly with Argus winning {aggregation.argus_wins} comparisons "
            summary += f"and Codex winning {aggregation.codex_wins} comparisons.\n\n"

        # Coverage analysis
        summary += "### Coverage Analysis\n\n"
        summary += f"- Matched findings: {aggregation.matched_findings} ({aggregation.matched_findings/max(aggregation.total_comparisons, 1)*100:.1f}%)\n"
        summary += f"- Argus unique: {aggregation.argus_only} findings\n"
        summary += f"- Codex unique: {aggregation.codex_only} findings\n\n"

        # Severity analysis
        summary += "### Severity Distribution\n\n"
        summary += "**Critical Findings**:\n"
        summary += f"- Argus: {aggregation.critical_by_argus}\n"
        summary += f"- Codex: {aggregation.critical_by_codex}\n\n"
        summary += "**High Severity Findings**:\n"
        summary += f"- Argus: {aggregation.high_by_argus}\n"
        summary += f"- Codex: {aggregation.high_by_codex}\n\n"

        return summary


def load_findings(file_path: str) -> List[Dict[str, Any]]:
    """Load findings from JSON file"""
    with open(file_path, 'r') as f:
        data = json.load(f)

    # Handle different formats
    if isinstance(data, dict):
        if "findings" in data:
            return data["findings"]
        elif "results" in data and isinstance(data["results"], dict) and "findings" in data["results"]:
            return data["results"]["findings"]

    if isinstance(data, list):
        return data

    logger.warning(f"Unexpected findings format in {file_path}")
    return []


def main():
    parser = argparse.ArgumentParser(
        description="Run pairwise comparison of Argus vs Codex findings"
    )
    parser.add_argument(
        "--argus-findings",
        required=True,
        help="Path to Argus findings JSON file"
    )
    parser.add_argument(
        "--codex-findings",
        required=True,
        help="Path to Codex findings JSON file"
    )
    parser.add_argument(
        "--output",
        default="pairwise_comparison_report.json",
        help="Output file path for comparison report (default: pairwise_comparison_report.json)"
    )
    parser.add_argument(
        "--output-markdown",
        help="Optional output path for markdown report"
    )
    parser.add_argument(
        "--judge-model",
        choices=["anthropic", "openai"],
        default="anthropic",
        help="Which AI model to use as judge (default: anthropic)"
    )
    parser.add_argument(
        "--match-threshold",
        type=float,
        default=0.7,
        help="Similarity threshold for matching findings (0-1, default: 0.7)"
    )
    parser.add_argument(
        "--max-comparisons",
        type=int,
        help="Max number of comparisons to run (for cost limiting)"
    )

    args = parser.parse_args()

    # Load findings
    logger.info(f"Loading Argus findings from {args.argus_findings}...")
    argus_findings = load_findings(args.argus_findings)
    logger.info(f"  Loaded {len(argus_findings)} findings")

    logger.info(f"Loading Codex findings from {args.codex_findings}...")
    codex_findings = load_findings(args.codex_findings)
    logger.info(f"  Loaded {len(codex_findings)} findings")

    # Run comparison
    comparator = PairwiseComparator(
        argus_findings=argus_findings,
        codex_findings=codex_findings,
        judge_model=args.judge_model,
        match_threshold=args.match_threshold
    )

    aggregation = comparator.run_comparison(max_comparisons=args.max_comparisons)

    # Generate reports
    logger.info(f"\nGenerating reports...")
    ComparisonReportGenerator.generate_json_report(
        comparator.comparisons,
        aggregation,
        args.output
    )

    if args.output_markdown:
        ComparisonReportGenerator.generate_markdown_report(
            comparator.comparisons,
            aggregation,
            args.output_markdown
        )

    # Print summary
    logger.info(f"\n{'='*80}")
    logger.info(f"PAIRWISE COMPARISON COMPLETE")
    logger.info(f"{'='*80}")
    logger.info(f"\nWinner: {aggregation.overall_winner.upper()}")
    logger.info(f"Argus: {aggregation.avg_argus_score:.1f}/5 ({aggregation.argus_win_rate*100:.0f}% win rate)")
    logger.info(f"Codex: {aggregation.avg_codex_score:.1f}/5 ({aggregation.codex_win_rate*100:.0f}% win rate)")
    logger.info(f"\nMatched Findings: {aggregation.matched_findings}")
    logger.info(f"Argus Only: {aggregation.argus_only}")
    logger.info(f"Codex Only: {aggregation.codex_only}")
    logger.info(f"\n📊 Report: {args.output}")
    if args.output_markdown:
        logger.info(f"📄 Markdown: {args.output_markdown}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
