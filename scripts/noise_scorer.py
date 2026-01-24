#!/usr/bin/env python3
"""
Noise Scoring Engine - Phase 1.2
Uses Claude AI (Anthropic) for ML-based noise detection and historical analysis
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from normalizer.base import Finding
from providers.anthropic_provider import AnthropicProvider


class NoiseScorer:
    """
    Calculates noise scores for findings using:
    1. Historical fix rate analysis
    2. Claude AI ML-based FP prediction
    3. Pattern-based noise detection
    """

    def __init__(self, history_file: str = ".argus/finding_history.jsonl"):
        self.history_file = Path(history_file)
        self.history: list[dict] = []
        self.llm = None

        # Load historical data
        if self.history_file.exists():
            with open(self.history_file) as f:
                self.history = [json.loads(line) for line in f]

        # Initialize Claude AI if available
        try:
            self.llm = AnthropicProvider()
            print("✅ Claude AI (Anthropic) initialized for noise scoring")
        except Exception as e:
            print(f"⚠️  Claude AI not available, using heuristics only: {e}")

    def score_findings(self, findings: list[Finding]) -> list[Finding]:
        """
        Score all findings for noise/false positives

        Returns:
            List of findings with updated noise_score, false_positive_probability, historical_fix_rate
        """
        print(f"\n🔍 Scoring {len(findings)} findings for noise...")

        for finding in findings:
            # 1. Calculate historical fix rate
            finding.historical_fix_rate = self._calculate_historical_fix_rate(finding)

            # 2. Pattern-based noise score
            pattern_noise = self._calculate_pattern_noise(finding)

            # 3. Foundation-Sec ML prediction
            ml_noise = self._calculate_ml_noise(finding) if self.foundation_sec else 0.0

            # Combined noise score (weighted average)
            finding.noise_score = 0.4 * pattern_noise + 0.4 * ml_noise + 0.2 * (1.0 - finding.historical_fix_rate)

            finding.false_positive_probability = ml_noise

            # Update status if high noise
            if finding.noise_score > 0.7:
                finding.status = "suppressed"
                finding.suppression_reason = f"High noise score: {finding.noise_score:.2f}"

        print(f"✅ Scored {len(findings)} findings")
        print(f"   High noise (>0.7): {sum(1 for f in findings if f.noise_score > 0.7)}")
        print(f"   Medium noise (0.4-0.7): {sum(1 for f in findings if 0.4 <= f.noise_score <= 0.7)}")
        print(f"   Low noise (<0.4): {sum(1 for f in findings if f.noise_score < 0.4)}")

        return findings

    def _calculate_historical_fix_rate(self, finding: Finding) -> float:
        """
        Calculate what % of similar findings were actually fixed

        Similar = same rule_id + category + severity
        """
        if not self.history:
            return 0.5  # No history = assume 50%

        # Find similar findings
        similar = [
            h
            for h in self.history
            if h.get("rule_id") == finding.rule_id
            and h.get("category") == finding.category
            and h.get("severity") == finding.severity
        ]

        if not similar:
            return 0.5  # No similar findings

        # Calculate fix rate
        fixed = sum(1 for h in similar if h.get("status") == "fixed")
        total = len(similar)

        return fixed / total if total > 0 else 0.5

    def _calculate_pattern_noise(self, finding: Finding) -> float:
        """
        Pattern-based noise detection (heuristics)

        High noise indicators:
        - Test files
        - Low severity + no CVE
        - Informational findings
        - Deprecated rules
        """
        noise = 0.0

        # Test files are often noisy
        if any(x in finding.path.lower() for x in ["test", "spec", "mock", "__test__"]):
            noise += 0.3

        # Low severity without CVE
        if finding.severity in ["info", "low"] and not finding.cve:
            noise += 0.2

        # Informational findings
        if finding.severity == "info":
            noise += 0.3

        # Dependencies without reachability
        if finding.category == "DEPS" and finding.reachability == "no":
            noise += 0.4

        # Unverified secrets
        if finding.category == "SECRETS" and finding.secret_verified != "true":
            noise += 0.5

        # Low confidence findings
        if finding.confidence < 0.5:
            noise += 0.3

        return min(noise, 1.0)

    def _calculate_ml_noise(self, finding: Finding) -> float:
        """
        Use Foundation-Sec-8B to predict false positive probability

        Sends finding context to model and gets FP prediction
        """
        try:
            # Prepare prompt for Foundation-Sec
            prompt = self._build_fp_prediction_prompt(finding)

            # Get prediction from Foundation-Sec
            response = self.foundation_sec.analyze_code(
                code=finding.evidence.get("snippet", ""), context=prompt, focus="false_positive_analysis"
            )

            # Parse response for FP probability
            fp_prob = self._parse_fp_probability(response)
            return fp_prob

        except Exception as e:
            print(f"⚠️  Foundation-Sec ML prediction failed: {e}")
            return 0.0

    def _build_fp_prediction_prompt(self, finding: Finding) -> str:
        """Build prompt for Foundation-Sec FP prediction"""
        return f"""Analyze this security finding and predict if it's a false positive.

**Finding Details:**
- Rule: {finding.rule_name} ({finding.rule_id})
- Category: {finding.category}
- Severity: {finding.severity}
- Path: {finding.path}
- Line: {finding.line}
- Evidence: {finding.evidence.get("message", "N/A")}

**Historical Context:**
- Historical fix rate for similar findings: {finding.historical_fix_rate:.1%}
- Confidence: {finding.confidence}

**Question:** What is the probability (0.0-1.0) that this is a false positive?

Consider:
1. Is this in test/mock code?
2. Is the vulnerability actually exploitable in this context?
3. Are there mitigating controls?
4. Is this a common false positive pattern?

Respond with ONLY a JSON object:
{{"false_positive_probability": 0.0-1.0, "reasoning": "brief explanation"}}
"""

    def _parse_fp_probability(self, response: str) -> float:
        """Parse Foundation-Sec response for FP probability"""
        try:
            # Try to extract JSON from response
            if "{" in response and "}" in response:
                start = response.index("{")
                end = response.rindex("}") + 1
                json_str = response[start:end]
                data = json.loads(json_str)
                return float(data.get("false_positive_probability", 0.0))
        except Exception:
            pass

        # Fallback: look for probability in text
        if "high probability" in response.lower() or "likely false positive" in response.lower():
            return 0.8
        elif "medium probability" in response.lower() or "possibly false positive" in response.lower():
            return 0.5
        elif "low probability" in response.lower() or "unlikely false positive" in response.lower():
            return 0.2

        return 0.0

    def update_history(self, findings: list[Finding]):
        """
        Update historical database with new findings

        This builds the dataset for future noise scoring
        """
        # Ensure directory exists
        self.history_file.parent.mkdir(parents=True, exist_ok=True)

        # Append new findings
        with open(self.history_file, "a") as f:
            for finding in findings:
                record = {
                    "rule_id": finding.rule_id,
                    "category": finding.category,
                    "severity": finding.severity,
                    "status": finding.status,
                    "noise_score": finding.noise_score,
                    "timestamp": datetime.now().isoformat(),
                }
                f.write(json.dumps(record) + "\n")

        print(f"✅ Updated history with {len(findings)} findings")


def main():
    """CLI interface for noise scoring"""
    import argparse

    parser = argparse.ArgumentParser(description="Score findings for noise/false positives")
    parser.add_argument("--input", "-i", required=True, help="Input findings JSON file")
    parser.add_argument("--output", "-o", required=True, help="Output scored findings JSON file")
    parser.add_argument("--history", default=".argus/finding_history.jsonl", help="Historical findings database")
    parser.add_argument("--update-history", action="store_true", help="Update historical database with these findings")

    args = parser.parse_args()

    # Load findings
    with open(args.input) as f:
        findings_data = json.load(f)

    findings = [Finding.from_dict(f) for f in findings_data]

    # Score findings
    scorer = NoiseScorer(history_file=args.history)
    scored_findings = scorer.score_findings(findings)

    # Update history if requested
    if args.update_history:
        scorer.update_history(scored_findings)

    # Save results
    with open(args.output, "w") as f:
        json.dump([f.to_dict() for f in scored_findings], f, indent=2)

    print(f"\n✅ Scored findings saved to {args.output}")


if __name__ == "__main__":
    main()
