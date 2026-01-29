#!/usr/bin/env python3
"""
Feedback Loop System for Argus Security
Learns from human TP/FP decisions to improve suppression accuracy over time
"""

import json
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class FeedbackRecord:
    """Single feedback record for a finding verdict"""
    finding_id: str
    automated_verdict: str  # What the system predicted
    human_verdict: str  # What the human decided
    confidence: float  # System's confidence
    pattern_used: Optional[str]  # Which suppression pattern was applied
    finding_category: str  # oauth2, file_permission, dev_config, etc.
    timestamp: str
    reasoning: str  # Human's reasoning (optional)

    # Match result
    is_correct: bool  # automated_verdict == human_verdict
    error_type: Optional[str]  # "false_negative" or "false_positive"


@dataclass
class PatternAccuracy:
    """Accuracy metrics for a specific suppression pattern"""
    pattern_id: str
    pattern_name: str
    total_samples: int
    true_positives: int  # Correctly identified as TP
    false_positives: int  # Incorrectly marked as FP
    true_negatives: int  # Correctly identified as FP
    false_negatives: int  # Incorrectly marked as TP

    @property
    def precision(self) -> float:
        """Precision: TP / (TP + FP)"""
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        """Recall: TP / (TP + FN)"""
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        """F1 Score: 2 * (precision * recall) / (precision + recall)"""
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        """Overall accuracy: (TP + TN) / total"""
        correct = self.true_positives + self.true_negatives
        return correct / self.total_samples if self.total_samples > 0 else 0.0


@dataclass
class ConfidenceAdjustment:
    """Recommended confidence adjustment for a pattern"""
    pattern_id: str
    current_multiplier: float  # 1.0 = no adjustment
    recommended_multiplier: float
    reasoning: str
    sample_size: int
    accuracy: float


class FeedbackLoop:
    """
    Feedback loop system for learning from human decisions

    Workflow:
    1. Record human verdict for each finding
    2. Track TP/FP rates per pattern
    3. Calculate pattern accuracy metrics
    4. Suggest confidence adjustments
    5. Optionally auto-apply tuning (with safeguards)
    """

    def __init__(self, feedback_dir: str = ".argus/feedback"):
        """
        Initialize feedback loop

        Args:
            feedback_dir: Directory to store feedback data
        """
        self.feedback_dir = Path(feedback_dir)
        self.feedback_dir.mkdir(parents=True, exist_ok=True)

        self.feedback_file = self.feedback_dir / "feedback_records.jsonl"
        self.adjustments_file = self.feedback_dir / "confidence_adjustments.json"

        self.logger = logging.getLogger(__name__)

    def record_verdict(
        self,
        finding_id: str,
        automated_verdict: str,
        human_verdict: str,
        confidence: float,
        pattern_used: Optional[str],
        finding_category: str,
        reasoning: str = ""
    ) -> FeedbackRecord:
        """
        Record human verdict for learning

        Args:
            finding_id: Unique finding identifier
            automated_verdict: System's verdict (confirmed/false_positive/uncertain)
            human_verdict: Human's verdict (confirmed/false_positive)
            confidence: System's confidence (0.0-1.0)
            pattern_used: Suppression pattern that was applied (if any)
            finding_category: Category (oauth2, file_permission, etc.)
            reasoning: Human's explanation (optional)

        Returns:
            FeedbackRecord object
        """
        # Determine if automated verdict was correct
        is_correct = automated_verdict == human_verdict

        # Classify error type
        error_type = None
        if not is_correct:
            if automated_verdict == "false_positive" and human_verdict == "confirmed":
                error_type = "false_negative"  # Missed a real vulnerability
            elif automated_verdict == "confirmed" and human_verdict == "false_positive":
                error_type = "false_positive"  # Incorrectly flagged

        record = FeedbackRecord(
            finding_id=finding_id,
            automated_verdict=automated_verdict,
            human_verdict=human_verdict,
            confidence=confidence,
            pattern_used=pattern_used,
            finding_category=finding_category,
            timestamp=datetime.now().isoformat(),
            reasoning=reasoning,
            is_correct=is_correct,
            error_type=error_type
        )

        # Append to JSONL file
        with open(self.feedback_file, "a") as f:
            f.write(json.dumps(asdict(record)) + "\n")

        self.logger.info(
            f"Recorded feedback: finding={finding_id}, "
            f"automated={automated_verdict}, human={human_verdict}, "
            f"correct={is_correct}"
        )

        return record

    def get_pattern_feedback(self, pattern_id: str) -> list[FeedbackRecord]:
        """Get all feedback for a specific pattern"""
        if not self.feedback_file.exists():
            return []

        feedback = []
        with open(self.feedback_file, "r") as f:
            for line in f:
                record_dict = json.loads(line)
                record = FeedbackRecord(**record_dict)
                if record.pattern_used == pattern_id:
                    feedback.append(record)

        return feedback

    def calculate_pattern_accuracy(self, pattern_id: str, pattern_name: str) -> PatternAccuracy:
        """
        Calculate accuracy metrics for a pattern

        Args:
            pattern_id: Pattern identifier
            pattern_name: Human-readable pattern name

        Returns:
            PatternAccuracy with metrics
        """
        feedback = self.get_pattern_feedback(pattern_id)

        if not feedback:
            return PatternAccuracy(
                pattern_id=pattern_id,
                pattern_name=pattern_name,
                total_samples=0,
                true_positives=0,
                false_positives=0,
                true_negatives=0,
                false_negatives=0
            )

        # Calculate confusion matrix
        tp = sum(1 for f in feedback
                if f.automated_verdict == "confirmed" and f.human_verdict == "confirmed")
        fp = sum(1 for f in feedback
                if f.automated_verdict == "confirmed" and f.human_verdict == "false_positive")
        tn = sum(1 for f in feedback
                if f.automated_verdict == "false_positive" and f.human_verdict == "false_positive")
        fn = sum(1 for f in feedback
                if f.automated_verdict == "false_positive" and f.human_verdict == "confirmed")

        return PatternAccuracy(
            pattern_id=pattern_id,
            pattern_name=pattern_name,
            total_samples=len(feedback),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn
        )

    def suggest_confidence_adjustments(
        self,
        min_samples: int = 10
    ) -> list[ConfidenceAdjustment]:
        """
        Suggest confidence multiplier adjustments based on accuracy

        Args:
            min_samples: Minimum samples required for recommendation

        Returns:
            List of ConfidenceAdjustment recommendations
        """
        adjustments = []

        # Get all unique patterns from feedback
        patterns = self._get_all_patterns()

        for pattern_id, pattern_name in patterns.items():
            accuracy = self.calculate_pattern_accuracy(pattern_id, pattern_name)

            if accuracy.total_samples < min_samples:
                continue

            # Calculate recommended multiplier based on accuracy
            current_multiplier = self._get_current_multiplier(pattern_id)
            recommended_multiplier = self._calculate_recommended_multiplier(
                accuracy, current_multiplier
            )

            # Generate reasoning
            reasoning = self._generate_adjustment_reasoning(accuracy, recommended_multiplier)

            adjustments.append(ConfidenceAdjustment(
                pattern_id=pattern_id,
                current_multiplier=current_multiplier,
                recommended_multiplier=recommended_multiplier,
                reasoning=reasoning,
                sample_size=accuracy.total_samples,
                accuracy=accuracy.accuracy
            ))

        return adjustments

    def _calculate_recommended_multiplier(
        self,
        accuracy: PatternAccuracy,
        current_multiplier: float
    ) -> float:
        """
        Calculate recommended confidence multiplier

        Strategy:
        - High accuracy (>90%): Increase confidence (up to 1.2x)
        - Good accuracy (70-90%): Keep current
        - Poor accuracy (<70%): Decrease confidence (down to 0.7x)
        - False negatives: Decrease more aggressively (security-first)
        """
        acc = accuracy.accuracy

        # Check for false negatives (missed vulnerabilities)
        fn_rate = accuracy.false_negatives / accuracy.total_samples if accuracy.total_samples > 0 else 0

        if fn_rate > 0.2:  # >20% false negatives (critical!)
            return max(current_multiplier * 0.6, 0.5)

        elif fn_rate > 0.1:  # >10% false negatives
            return max(current_multiplier * 0.8, 0.7)

        elif acc >= 0.95:  # Excellent
            return min(current_multiplier * 1.1, 1.2)

        elif acc >= 0.90:  # Very good
            return min(current_multiplier * 1.05, 1.1)

        elif acc >= 0.70:  # Acceptable
            return current_multiplier  # No change

        else:  # Poor accuracy
            return max(current_multiplier * 0.85, 0.7)

    def _generate_adjustment_reasoning(
        self,
        accuracy: PatternAccuracy,
        recommended_mult: float
    ) -> str:
        """Generate human-readable reasoning for adjustment"""
        parts = []

        parts.append(f"Accuracy: {accuracy.accuracy:.1%} ({accuracy.total_samples} samples)")
        parts.append(f"Precision: {accuracy.precision:.1%}, Recall: {accuracy.recall:.1%}")

        fn_rate = accuracy.false_negatives / accuracy.total_samples if accuracy.total_samples > 0 else 0
        if fn_rate > 0.1:
            parts.append(f"High false negative rate ({fn_rate:.1%}) - reducing confidence")

        if accuracy.accuracy >= 0.9:
            parts.append("High accuracy - can increase confidence")
        elif accuracy.accuracy < 0.7:
            parts.append("Low accuracy - reducing confidence")

        return " | ".join(parts)

    def _get_all_patterns(self) -> dict[str, str]:
        """Get all unique patterns from feedback"""
        if not self.feedback_file.exists():
            return {}

        patterns = {}
        with open(self.feedback_file, "r") as f:
            for line in f:
                record = json.loads(line)
                pattern_id = record.get("pattern_used")
                if pattern_id:
                    patterns[pattern_id] = pattern_id  # Use ID as name for now

        return patterns

    def _get_current_multiplier(self, pattern_id: str) -> float:
        """Get current confidence multiplier for pattern"""
        if not self.adjustments_file.exists():
            return 1.0

        try:
            with open(self.adjustments_file, "r") as f:
                adjustments = json.load(f)
                return adjustments.get(pattern_id, {}).get("multiplier", 1.0)
        except:
            return 1.0

    def apply_adjustments(
        self,
        adjustments: list[ConfidenceAdjustment],
        dry_run: bool = True
    ):
        """
        Apply confidence adjustments

        Args:
            adjustments: List of adjustments to apply
            dry_run: If True, only log changes (don't apply)
        """
        if dry_run:
            self.logger.info("DRY RUN: Would apply the following adjustments:")
            for adj in adjustments:
                self.logger.info(
                    f"  {adj.pattern_id}: {adj.current_multiplier:.2f} -> "
                    f"{adj.recommended_multiplier:.2f} ({adj.reasoning})"
                )
            return

        # Load existing adjustments
        adjustments_dict = {}
        if self.adjustments_file.exists():
            with open(self.adjustments_file, "r") as f:
                adjustments_dict = json.load(f)

        # Apply new adjustments
        for adj in adjustments:
            adjustments_dict[adj.pattern_id] = {
                "multiplier": adj.recommended_multiplier,
                "applied_at": datetime.now().isoformat(),
                "reasoning": adj.reasoning,
                "sample_size": adj.sample_size,
                "accuracy": adj.accuracy
            }

        # Save
        with open(self.adjustments_file, "w") as f:
            json.dump(adjustments_dict, f, indent=2)

        self.logger.info(f"Applied {len(adjustments)} confidence adjustments")

    def get_statistics(self) -> dict:
        """Get overall feedback loop statistics"""
        if not self.feedback_file.exists():
            return {"total_records": 0}

        records = []
        with open(self.feedback_file, "r") as f:
            for line in f:
                records.append(FeedbackRecord(**json.loads(line)))

        correct = sum(1 for r in records if r.is_correct)
        false_negatives = sum(1 for r in records if r.error_type == "false_negative")
        false_positives = sum(1 for r in records if r.error_type == "false_positive")

        return {
            "total_records": len(records),
            "correct": correct,
            "accuracy": correct / len(records) if records else 0.0,
            "false_negatives": false_negatives,
            "false_positives": false_positives,
            "patterns_tracked": len(self._get_all_patterns())
        }
