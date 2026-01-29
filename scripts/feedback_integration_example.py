#!/usr/bin/env python3
"""
Integration Example: Using Feedback Loop with Enhanced FP Detector

This example demonstrates how to integrate the feedback loop system
with the existing Enhanced False Positive Detector.
"""

import logging
from pathlib import Path
from typing import Dict, Any

from feedback_loop import FeedbackLoop

# Mock imports - replace with actual imports
# from enhanced_fp_detector import EnhancedFalsePositiveDetector


class FeedbackIntegration:
    """
    Integration layer between Enhanced FP Detector and Feedback Loop

    This class shows how to:
    1. Apply learned confidence multipliers during detection
    2. Record human verdicts for continuous learning
    3. Periodically retune the system
    """

    def __init__(self, feedback_dir: str = ".argus/feedback"):
        """
        Initialize feedback integration

        Args:
            feedback_dir: Directory for feedback data
        """
        self.feedback_loop = FeedbackLoop(feedback_dir=feedback_dir)
        self.logger = logging.getLogger(__name__)

    def analyze_with_feedback(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze finding with feedback-adjusted confidence

        Args:
            finding: Finding dictionary from scanner

        Returns:
            Analysis result with adjusted confidence
        """
        # Get base analysis from Enhanced FP Detector
        # In real integration, this would call:
        # detector = EnhancedFalsePositiveDetector()
        # base_result = detector.analyze(finding)

        # Mock base result for example
        base_result = {
            "verdict": "false_positive",
            "confidence": 0.75,
            "pattern_used": "oauth2_localhost_pattern",
            "reasoning": "OAuth2 redirect to localhost",
            "category": "oauth2"
        }

        # Load learned confidence multiplier
        pattern_id = base_result.get("pattern_used")
        if pattern_id:
            multiplier = self.feedback_loop._get_current_multiplier(pattern_id)

            # Apply multiplier to confidence
            original_confidence = base_result["confidence"]
            adjusted_confidence = min(original_confidence * multiplier, 1.0)

            self.logger.info(
                f"Applied feedback multiplier: {multiplier:.2f} "
                f"({original_confidence:.2f} -> {adjusted_confidence:.2f})"
            )

            base_result["confidence"] = adjusted_confidence
            base_result["original_confidence"] = original_confidence
            base_result["confidence_multiplier"] = multiplier

        return base_result

    def record_human_review(
        self,
        finding_id: str,
        automated_result: Dict[str, Any],
        human_verdict: str,
        reasoning: str = ""
    ):
        """
        Record human verdict for a finding

        Args:
            finding_id: Unique finding identifier
            automated_result: Result from analyze_with_feedback()
            human_verdict: Human's decision (confirmed/false_positive)
            reasoning: Human's explanation (optional)
        """
        self.feedback_loop.record_verdict(
            finding_id=finding_id,
            automated_verdict=automated_result["verdict"],
            human_verdict=human_verdict,
            confidence=automated_result.get("original_confidence",
                                          automated_result["confidence"]),
            pattern_used=automated_result.get("pattern_used"),
            finding_category=automated_result.get("category", "unknown"),
            reasoning=reasoning
        )

        self.logger.info(f"Recorded human verdict for {finding_id}")

    def periodic_tuning(self, min_samples: int = 10, auto_apply: bool = False):
        """
        Periodically retune confidence multipliers

        Should be run weekly/monthly to learn from accumulated feedback.

        Args:
            min_samples: Minimum samples required per pattern
            auto_apply: If True, automatically apply adjustments

        Returns:
            List of adjustments
        """
        self.logger.info("Running periodic tuning...")

        # Get statistics
        stats = self.feedback_loop.get_statistics()
        self.logger.info(
            f"Total feedback records: {stats['total_records']}, "
            f"Overall accuracy: {stats['accuracy']:.1%}"
        )

        # Get adjustment recommendations
        adjustments = self.feedback_loop.suggest_confidence_adjustments(
            min_samples=min_samples
        )

        if not adjustments:
            self.logger.info("No patterns with sufficient data for tuning")
            return []

        self.logger.info(f"Found {len(adjustments)} patterns to tune:")
        for adj in adjustments:
            self.logger.info(
                f"  {adj.pattern_id}: {adj.current_multiplier:.2f} -> "
                f"{adj.recommended_multiplier:.2f} ({adj.reasoning})"
            )

        # Apply if requested
        if auto_apply:
            self.feedback_loop.apply_adjustments(adjustments, dry_run=False)
            self.logger.info("Applied adjustments automatically")
        else:
            self.logger.info("Run with auto_apply=True to apply these adjustments")

        return adjustments


# Example Usage 1: Analyze findings with feedback
def example_analyze_with_feedback():
    """Example: Analyze findings using learned confidence multipliers"""
    integration = FeedbackIntegration()

    # Mock finding
    finding = {
        "tool": "semgrep",
        "rule_id": "oauth2-redirect-uri",
        "file": "src/auth.py",
        "line": 42,
        "code": 'redirect_uri = "http://localhost:3000/callback"'
    }

    # Analyze with feedback-adjusted confidence
    result = integration.analyze_with_feedback(finding)

    print(f"Verdict: {result['verdict']}")
    print(f"Confidence: {result['confidence']:.2f}")
    if "confidence_multiplier" in result:
        print(f"Multiplier applied: {result['confidence_multiplier']:.2f}")


# Example Usage 2: Record human verdict
def example_record_verdict():
    """Example: Record human verdict after manual review"""
    integration = FeedbackIntegration()

    # Automated analysis result
    automated_result = {
        "verdict": "false_positive",
        "confidence": 0.82,
        "pattern_used": "oauth2_localhost_pattern",
        "category": "oauth2",
        "reasoning": "OAuth2 redirect to localhost"
    }

    # Human reviewed and agreed it's a false positive
    integration.record_human_review(
        finding_id="semgrep-oauth2-001",
        automated_result=automated_result,
        human_verdict="false_positive",
        reasoning="Confirmed: Development OAuth2 configuration"
    )

    print("Recorded human verdict")


# Example Usage 3: Periodic tuning
def example_periodic_tuning():
    """Example: Run periodic tuning to update confidence multipliers"""
    integration = FeedbackIntegration()

    # Run tuning (dry-run by default)
    adjustments = integration.periodic_tuning(
        min_samples=10,
        auto_apply=False  # Set to True to auto-apply
    )

    print(f"\nRecommended {len(adjustments)} adjustments:")
    for adj in adjustments:
        print(f"  {adj.pattern_id}: {adj.current_multiplier:.2f} -> {adj.recommended_multiplier:.2f}")


# Example Usage 4: Complete workflow
def example_complete_workflow():
    """Example: Complete workflow from analysis to tuning"""
    integration = FeedbackIntegration()

    print("=== Phase 1: Initial Analysis ===")

    # Simulate analyzing 20 findings
    findings_data = [
        {
            "id": f"finding-{i:03d}",
            "automated_verdict": "false_positive",
            "human_verdict": "false_positive" if i < 15 else "confirmed",  # 75% accuracy
            "pattern": "oauth2_localhost_pattern",
            "category": "oauth2"
        }
        for i in range(20)
    ]

    # Record all verdicts
    for data in findings_data:
        integration.feedback_loop.record_verdict(
            finding_id=data["id"],
            automated_verdict=data["automated_verdict"],
            human_verdict=data["human_verdict"],
            confidence=0.75,
            pattern_used=data["pattern"],
            finding_category=data["category"]
        )

    print(f"Recorded {len(findings_data)} verdicts")

    print("\n=== Phase 2: Check Statistics ===")
    stats = integration.feedback_loop.get_statistics()
    print(f"Total records: {stats['total_records']}")
    print(f"Overall accuracy: {stats['accuracy']:.1%}")
    print(f"False negatives: {stats['false_negatives']}")

    print("\n=== Phase 3: Pattern Accuracy ===")
    accuracy = integration.feedback_loop.calculate_pattern_accuracy(
        "oauth2_localhost_pattern",
        "OAuth2 Localhost Pattern"
    )
    print(f"Pattern: {accuracy.pattern_name}")
    print(f"Samples: {accuracy.total_samples}")
    print(f"Accuracy: {accuracy.accuracy:.1%}")
    print(f"Precision: {accuracy.precision:.1%}")
    print(f"Recall: {accuracy.recall:.1%}")

    print("\n=== Phase 4: Tune Confidence ===")
    adjustments = integration.periodic_tuning(min_samples=10, auto_apply=True)

    if adjustments:
        print(f"\nApplied {len(adjustments)} adjustments")
        for adj in adjustments:
            print(f"  {adj.pattern_id}: {adj.current_multiplier:.2f} -> {adj.recommended_multiplier:.2f}")

    print("\n=== Phase 5: Verify Applied ===")
    new_multiplier = integration.feedback_loop._get_current_multiplier("oauth2_localhost_pattern")
    print(f"New multiplier for oauth2_localhost_pattern: {new_multiplier:.2f}")


# Example Usage 5: Integrate with existing pipeline
def example_pipeline_integration():
    """
    Example: How to integrate with existing Argus Security pipeline

    This shows where to add feedback hooks in run_ai_audit.py or similar
    """

    class MockScanner:
        def scan(self):
            return [
                {
                    "id": "finding-001",
                    "tool": "semgrep",
                    "rule_id": "oauth2-redirect",
                    "severity": "high",
                    "file": "auth.py",
                    "line": 42
                }
            ]

    class MockFPDetector:
        def __init__(self, feedback_integration):
            self.feedback = feedback_integration

        def analyze(self, finding):
            # Use feedback-adjusted confidence
            return self.feedback.analyze_with_feedback(finding)

    # Initialize components
    integration = FeedbackIntegration()
    scanner = MockScanner()
    fp_detector = MockFPDetector(integration)

    # Phase 1: Scan
    print("=== Scanning ===")
    findings = scanner.scan()
    print(f"Found {len(findings)} potential issues")

    # Phase 2: FP Detection (with feedback)
    print("\n=== False Positive Detection ===")
    for finding in findings:
        result = fp_detector.analyze(finding)
        print(f"Finding {finding['id']}: {result['verdict']} (confidence: {result['confidence']:.2f})")

        # In production, findings marked as false_positive would be filtered
        if result['verdict'] == 'false_positive':
            print(f"  -> Suppressing (confidence: {result['confidence']:.2f})")

    # Phase 3: Human review (simulated)
    print("\n=== Human Review ===")
    # In production, this would be manual review via UI or CLI
    human_verdict = "false_positive"  # Human confirms it's a false positive

    integration.record_human_review(
        finding_id=findings[0]['id'],
        automated_result=result,
        human_verdict=human_verdict,
        reasoning="Confirmed safe - development OAuth2 config"
    )
    print("Recorded human verdict for continuous learning")

    # Phase 4: Periodic tuning (would run weekly/monthly)
    print("\n=== Periodic Tuning (weekly) ===")
    adjustments = integration.periodic_tuning(min_samples=5, auto_apply=True)
    print(f"Applied {len(adjustments)} confidence adjustments")


if __name__ == "__main__":
    print("Feedback Loop Integration Examples\n")
    print("=" * 50)

    # Run all examples
    print("\n1. Analyze with feedback:")
    example_analyze_with_feedback()

    print("\n2. Record verdict:")
    example_record_verdict()

    print("\n3. Periodic tuning:")
    example_periodic_tuning()

    print("\n4. Complete workflow:")
    example_complete_workflow()

    print("\n5. Pipeline integration:")
    example_pipeline_integration()
