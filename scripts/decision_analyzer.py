#!/usr/bin/env python3
"""
Decision Analyzer for Argus
Analyzes AI triage decisions to discover patterns and suggest improvements

Features:
- Decision quality metrics (suppression rate, confidence distribution)
- Pattern discovery (common suppression reasons, finding types)
- Improvement suggestions (new heuristics, rule refinements)
- Per-scanner analysis
- Trend analysis over time
"""

import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DecisionPattern:
    """Represents a discovered pattern in AI decisions"""

    def __init__(
        self,
        pattern_type: str,
        description: str,
        frequency: int,
        confidence: float,
        examples: List[Dict[str, Any]]
    ):
        """
        Initialize decision pattern

        Args:
            pattern_type: Type of pattern (e.g., "always_suppress_test_files")
            description: Human-readable description
            frequency: How many times pattern occurred
            confidence: Average confidence in decisions matching this pattern
            examples: Example decisions matching this pattern
        """
        self.pattern_type = pattern_type
        self.description = description
        self.frequency = frequency
        self.confidence = confidence
        self.examples = examples

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "pattern_type": self.pattern_type,
            "description": self.description,
            "frequency": self.frequency,
            "confidence": self.confidence,
            "example_count": len(self.examples),
            "examples": self.examples[:3]  # Include first 3 examples
        }


class DecisionAnalyzer:
    """Analyze AI triage decision quality over time"""

    def __init__(self, decision_log_path: str = ".argus-cache/decisions.jsonl"):
        """
        Initialize decision analyzer

        Args:
            decision_log_path: Path to decision log file
        """
        self.decision_log_path = Path(decision_log_path)

    def load_decisions(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        scanner: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Load decisions from log file with optional filtering

        Args:
            start_date: Filter decisions after this date
            end_date: Filter decisions before this date
            scanner: Filter decisions from specific scanner

        Returns:
            List of decision entries
        """
        if not self.decision_log_path.exists():
            logger.warning(f"Decision log not found: {self.decision_log_path}")
            return []

        decisions = []

        try:
            with open(self.decision_log_path, "r") as f:
                for line in f:
                    try:
                        decision = json.loads(line)

                        # Apply filters
                        if start_date:
                            decision_time = datetime.fromisoformat(
                                decision.get("timestamp", "")
                            )
                            if decision_time < start_date:
                                continue

                        if end_date:
                            decision_time = datetime.fromisoformat(
                                decision.get("timestamp", "")
                            )
                            if decision_time > end_date:
                                continue

                        if scanner and decision.get("scanner") != scanner:
                            continue

                        decisions.append(decision)

                    except (json.JSONDecodeError, ValueError) as e:
                        logger.debug(f"Skipping corrupt decision log line: {e}")
                        continue

            logger.info(f"Loaded {len(decisions)} decisions from log")
            return decisions

        except Exception as e:
            logger.error(f"Failed to load decisions: {e}")
            return []

    def analyze_decisions(self, decisions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregate decision logs and compute metrics

        Args:
            decisions: List of decision entries

        Returns:
            Dictionary with analysis results:
            - total_decisions: Total number of decisions
            - suppression_rate: Percentage of findings suppressed
            - escalation_rate: Percentage of findings escalated
            - avg_confidence: Average confidence score
            - confidence_distribution: Histogram of confidence scores
            - by_scanner: Per-scanner breakdown
            - by_finding_type: Per-finding-type breakdown
            - by_decision: Suppress vs escalate counts
            - low_confidence_decisions: Decisions with confidence < 0.6
        """
        if not decisions:
            logger.warning("No decisions to analyze")
            return {}

        total = len(decisions)

        # Count decisions by type
        suppress_count = sum(1 for d in decisions if d.get("decision") == "suppress")
        escalate_count = sum(1 for d in decisions if d.get("decision") == "escalate")

        # Calculate average confidence
        confidences = [d.get("confidence", 0.0) for d in decisions]
        avg_confidence = sum(confidences) / total if total > 0 else 0.0

        # Confidence distribution (buckets: 0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0)
        confidence_dist = {
            "0.0-0.2": sum(1 for c in confidences if 0.0 <= c < 0.2),
            "0.2-0.4": sum(1 for c in confidences if 0.2 <= c < 0.4),
            "0.4-0.6": sum(1 for c in confidences if 0.4 <= c < 0.6),
            "0.6-0.8": sum(1 for c in confidences if 0.6 <= c < 0.8),
            "0.8-1.0": sum(1 for c in confidences if 0.8 <= c <= 1.0),
        }

        # Per-scanner breakdown
        scanner_stats = defaultdict(lambda: {"suppress": 0, "escalate": 0, "total": 0})
        for d in decisions:
            scanner = d.get("scanner", "unknown")
            decision = d.get("decision", "unknown")
            scanner_stats[scanner][decision] = scanner_stats[scanner].get(decision, 0) + 1
            scanner_stats[scanner]["total"] += 1

        # Per-finding-type breakdown
        finding_type_stats = defaultdict(lambda: {"suppress": 0, "escalate": 0, "total": 0})
        for d in decisions:
            finding_type = d.get("finding_type", "unknown")
            decision = d.get("decision", "unknown")
            finding_type_stats[finding_type][decision] = finding_type_stats[finding_type].get(decision, 0) + 1
            finding_type_stats[finding_type]["total"] += 1

        # Low confidence decisions (potential issues)
        low_confidence = [
            {
                "finding_id": d.get("finding_id"),
                "finding_type": d.get("finding_type"),
                "scanner": d.get("scanner"),
                "decision": d.get("decision"),
                "confidence": d.get("confidence"),
                "reasoning": d.get("reasoning", "")[:100],  # First 100 chars
            }
            for d in decisions
            if d.get("confidence", 1.0) < 0.6
        ]

        # Model usage
        model_counter = Counter(d.get("model", "unknown") for d in decisions)

        analysis = {
            "total_decisions": total,
            "suppression_rate": (suppress_count / total * 100) if total > 0 else 0.0,
            "escalation_rate": (escalate_count / total * 100) if total > 0 else 0.0,
            "avg_confidence": avg_confidence,
            "confidence_distribution": confidence_dist,
            "by_decision": {
                "suppress": suppress_count,
                "escalate": escalate_count,
            },
            "by_scanner": dict(scanner_stats),
            "by_finding_type": dict(finding_type_stats),
            "model_usage": dict(model_counter),
            "low_confidence_count": len(low_confidence),
            "low_confidence_decisions": low_confidence[:10],  # First 10
        }

        return analysis

    def identify_patterns(self, decisions: List[Dict[str, Any]]) -> List[DecisionPattern]:
        """
        Find patterns in suppressed findings

        Patterns to detect:
        - Always suppresses test files
        - Always suppresses documentation
        - Consistently suppresses specific finding types
        - High confidence suppressions for specific scanners
        - Common reasoning patterns

        Args:
            decisions: List of decision entries

        Returns:
            List of discovered patterns
        """
        patterns = []

        # Pattern 1: Test file suppressions
        test_file_suppressions = [
            d for d in decisions
            if d.get("decision") == "suppress"
            and any(keyword in d.get("reasoning", "").lower()
                    for keyword in ["test", "spec", "fixture", "mock"])
        ]

        if test_file_suppressions:
            avg_confidence = sum(d.get("confidence", 0) for d in test_file_suppressions) / len(test_file_suppressions)
            patterns.append(DecisionPattern(
                pattern_type="test_file_suppression",
                description="AI consistently suppresses findings in test files",
                frequency=len(test_file_suppressions),
                confidence=avg_confidence,
                examples=test_file_suppressions[:5]
            ))

        # Pattern 2: Documentation suppressions
        doc_suppressions = [
            d for d in decisions
            if d.get("decision") == "suppress"
            and any(keyword in d.get("reasoning", "").lower()
                    for keyword in ["documentation", "example", "readme", "comment"])
        ]

        if doc_suppressions:
            avg_confidence = sum(d.get("confidence", 0) for d in doc_suppressions) / len(doc_suppressions)
            patterns.append(DecisionPattern(
                pattern_type="documentation_suppression",
                description="AI consistently suppresses findings in documentation",
                frequency=len(doc_suppressions),
                confidence=avg_confidence,
                examples=doc_suppressions[:5]
            ))

        # Pattern 3: High confidence suppressions by finding type
        by_finding_type = defaultdict(list)
        for d in decisions:
            if d.get("decision") == "suppress" and d.get("confidence", 0) >= 0.8:
                by_finding_type[d.get("finding_type", "unknown")].append(d)

        for finding_type, type_decisions in by_finding_type.items():
            if len(type_decisions) >= 5:  # At least 5 occurrences
                avg_confidence = sum(d.get("confidence", 0) for d in type_decisions) / len(type_decisions)
                patterns.append(DecisionPattern(
                    pattern_type="high_confidence_type_suppression",
                    description=f"AI confidently suppresses {finding_type} findings",
                    frequency=len(type_decisions),
                    confidence=avg_confidence,
                    examples=type_decisions[:5]
                ))

        # Pattern 4: Common reasoning phrases
        reasoning_phrases = Counter()
        for d in decisions:
            if d.get("decision") == "suppress":
                reasoning = d.get("reasoning", "").lower()
                # Extract key phrases (simplified - could use NLP)
                if "false positive" in reasoning:
                    reasoning_phrases["false_positive"] += 1
                if "low risk" in reasoning or "minimal risk" in reasoning:
                    reasoning_phrases["low_risk"] += 1
                if "configuration" in reasoning:
                    reasoning_phrases["configuration_file"] += 1

        for phrase, count in reasoning_phrases.most_common(5):
            if count >= 3:
                phrase_decisions = [
                    d for d in decisions
                    if d.get("decision") == "suppress" and phrase.replace("_", " ") in d.get("reasoning", "").lower()
                ]
                avg_confidence = sum(d.get("confidence", 0) for d in phrase_decisions) / len(phrase_decisions)
                patterns.append(DecisionPattern(
                    pattern_type=f"reasoning_{phrase}",
                    description=f"AI frequently cites '{phrase.replace('_', ' ')}' as suppression reason",
                    frequency=count,
                    confidence=avg_confidence,
                    examples=phrase_decisions[:5]
                ))

        return patterns

    def suggest_improvements(
        self,
        analysis: Dict[str, Any],
        patterns: List[DecisionPattern]
    ) -> List[str]:
        """
        Recommend new heuristics based on decision patterns

        Args:
            analysis: Analysis results from analyze_decisions()
            patterns: Patterns from identify_patterns()

        Returns:
            List of improvement suggestions
        """
        suggestions = []

        # Suggestion 1: Add heuristic rules for consistent patterns
        for pattern in patterns:
            if pattern.confidence >= 0.85 and pattern.frequency >= 10:
                suggestions.append(
                    f"Add heuristic rule: Auto-suppress {pattern.pattern_type} "
                    f"(AI confidence: {pattern.confidence:.2f}, frequency: {pattern.frequency})"
                )

        # Suggestion 2: Investigate low confidence decisions
        if analysis.get("low_confidence_count", 0) > 10:
            low_conf_pct = (analysis["low_confidence_count"] / analysis["total_decisions"]) * 100
            suggestions.append(
                f"Investigate {analysis['low_confidence_count']} low-confidence decisions "
                f"({low_conf_pct:.1f}% of total) - may need better prompts or few-shot examples"
            )

        # Suggestion 3: Scanner-specific recommendations
        for scanner, stats in analysis.get("by_scanner", {}).items():
            suppress_rate = (stats["suppress"] / stats["total"] * 100) if stats["total"] > 0 else 0
            if suppress_rate > 80:
                suggestions.append(
                    f"Scanner '{scanner}' has {suppress_rate:.0f}% suppression rate - "
                    f"consider adjusting scanner rules or disabling noisy checks"
                )

        # Suggestion 4: Finding type recommendations
        for finding_type, stats in analysis.get("by_finding_type", {}).items():
            suppress_rate = (stats["suppress"] / stats["total"] * 100) if stats["total"] > 0 else 0
            if suppress_rate > 90 and stats["total"] >= 5:
                suggestions.append(
                    f"Finding type '{finding_type}' has {suppress_rate:.0f}% suppression rate - "
                    f"consider adding to suppression allowlist"
                )

        return suggestions

    def generate_report(
        self,
        decisions: Optional[List[Dict[str, Any]]] = None,
        output_format: str = "text"
    ) -> str:
        """
        Generate comprehensive analysis report

        Args:
            decisions: Decision list (if None, loads from log)
            output_format: "text" or "json"

        Returns:
            Formatted report
        """
        if decisions is None:
            decisions = self.load_decisions()

        if not decisions:
            return "No decisions found to analyze."

        analysis = self.analyze_decisions(decisions)
        patterns = self.identify_patterns(decisions)
        suggestions = self.suggest_improvements(analysis, patterns)

        if output_format == "json":
            report = {
                "analysis": analysis,
                "patterns": [p.to_dict() for p in patterns],
                "suggestions": suggestions,
                "generated_at": datetime.now().isoformat(),
            }
            return json.dumps(report, indent=2)

        # Text format
        report_lines = [
            "=" * 80,
            "AI DECISION QUALITY ANALYSIS",
            "=" * 80,
            "",
            f"Analysis Period: {len(decisions)} decisions",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "=" * 80,
            "SUMMARY METRICS",
            "=" * 80,
            f"Total Decisions:    {analysis['total_decisions']}",
            f"Suppression Rate:   {analysis['suppression_rate']:.1f}%",
            f"Escalation Rate:    {analysis['escalation_rate']:.1f}%",
            f"Avg Confidence:     {analysis['avg_confidence']:.3f}",
            f"Low Confidence:     {analysis['low_confidence_count']} ({analysis['low_confidence_count']/analysis['total_decisions']*100:.1f}%)",
            "",
            "=" * 80,
            "CONFIDENCE DISTRIBUTION",
            "=" * 80,
        ]

        for bucket, count in analysis["confidence_distribution"].items():
            pct = (count / analysis["total_decisions"] * 100) if analysis["total_decisions"] > 0 else 0
            bar = "█" * int(pct / 2)  # Visual bar chart
            report_lines.append(f"{bucket}: {count:3d} ({pct:5.1f}%) {bar}")

        report_lines.extend([
            "",
            "=" * 80,
            "BY SCANNER",
            "=" * 80,
        ])

        for scanner, stats in analysis["by_scanner"].items():
            suppress_pct = (stats["suppress"] / stats["total"] * 100) if stats["total"] > 0 else 0
            report_lines.append(
                f"{scanner:20s}: {stats['total']:3d} total, "
                f"{stats['suppress']:3d} suppressed ({suppress_pct:.0f}%), "
                f"{stats['escalate']:3d} escalated"
            )

        report_lines.extend([
            "",
            "=" * 80,
            "BY FINDING TYPE",
            "=" * 80,
        ])

        for finding_type, stats in sorted(
            analysis["by_finding_type"].items(),
            key=lambda x: x[1]["total"],
            reverse=True
        )[:10]:  # Top 10
            suppress_pct = (stats["suppress"] / stats["total"] * 100) if stats["total"] > 0 else 0
            report_lines.append(
                f"{finding_type:30s}: {stats['total']:3d} total, "
                f"{stats['suppress']:3d} suppressed ({suppress_pct:.0f}%)"
            )

        if patterns:
            report_lines.extend([
                "",
                "=" * 80,
                "DISCOVERED PATTERNS",
                "=" * 80,
            ])

            for i, pattern in enumerate(patterns, 1):
                report_lines.extend([
                    f"\n{i}. {pattern.description}",
                    f"   Type: {pattern.pattern_type}",
                    f"   Frequency: {pattern.frequency}",
                    f"   Confidence: {pattern.confidence:.3f}",
                ])

        if suggestions:
            report_lines.extend([
                "",
                "=" * 80,
                "IMPROVEMENT SUGGESTIONS",
                "=" * 80,
            ])

            for i, suggestion in enumerate(suggestions, 1):
                report_lines.append(f"{i}. {suggestion}")

        report_lines.extend([
            "",
            "=" * 80,
        ])

        return "\n".join(report_lines)


def main():
    """CLI interface for decision analysis"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Analyze AI triage decision quality"
    )
    parser.add_argument(
        "--log-file",
        default=".argus-cache/decisions.jsonl",
        help="Path to decision log file"
    )
    parser.add_argument(
        "--scanner",
        help="Filter decisions from specific scanner"
    )
    parser.add_argument(
        "--days",
        type=int,
        help="Analyze decisions from last N days"
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format"
    )

    args = parser.parse_args()

    analyzer = DecisionAnalyzer(args.log_file)

    # Load decisions with filters
    start_date = None
    if args.days:
        start_date = datetime.now() - timedelta(days=args.days)

    decisions = analyzer.load_decisions(
        start_date=start_date,
        scanner=args.scanner
    )

    # Generate report
    report = analyzer.generate_report(decisions, output_format=args.format)
    print(report)


if __name__ == "__main__":
    main()
