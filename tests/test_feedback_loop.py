#!/usr/bin/env python3
"""
Test suite for Feedback Loop System
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

# Add parent directory to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from feedback_loop import (
    FeedbackLoop,
    FeedbackRecord,
    PatternAccuracy,
    ConfidenceAdjustment
)


@pytest.fixture
def temp_feedback_dir():
    """Create temporary directory for feedback data"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def feedback_loop(temp_feedback_dir):
    """Create FeedbackLoop instance with temporary directory"""
    return FeedbackLoop(feedback_dir=temp_feedback_dir)


class TestFeedbackRecord:
    """Test FeedbackRecord dataclass"""

    def test_correct_prediction(self):
        """Test when automated verdict matches human verdict"""
        record = FeedbackRecord(
            finding_id="test-001",
            automated_verdict="confirmed",
            human_verdict="confirmed",
            confidence=0.85,
            pattern_used="oauth2_dev_pattern",
            finding_category="oauth2",
            timestamp="2026-01-29T10:00:00",
            reasoning="Legitimate vulnerability",
            is_correct=True,
            error_type=None
        )
        assert record.is_correct is True
        assert record.error_type is None

    def test_false_negative(self):
        """Test when system missed a real vulnerability"""
        record = FeedbackRecord(
            finding_id="test-002",
            automated_verdict="false_positive",
            human_verdict="confirmed",
            confidence=0.65,
            pattern_used="oauth2_dev_pattern",
            finding_category="oauth2",
            timestamp="2026-01-29T10:00:00",
            reasoning="Actually vulnerable",
            is_correct=False,
            error_type="false_negative"
        )
        assert record.is_correct is False
        assert record.error_type == "false_negative"

    def test_false_positive(self):
        """Test when system incorrectly flagged as vulnerable"""
        record = FeedbackRecord(
            finding_id="test-003",
            automated_verdict="confirmed",
            human_verdict="false_positive",
            confidence=0.75,
            pattern_used="file_permission_pattern",
            finding_category="file_permission",
            timestamp="2026-01-29T10:00:00",
            reasoning="Not actually vulnerable",
            is_correct=False,
            error_type="false_positive"
        )
        assert record.is_correct is False
        assert record.error_type == "false_positive"


class TestPatternAccuracy:
    """Test PatternAccuracy metrics"""

    def test_perfect_accuracy(self):
        """Test pattern with 100% accuracy"""
        accuracy = PatternAccuracy(
            pattern_id="perfect_pattern",
            pattern_name="Perfect Pattern",
            total_samples=10,
            true_positives=5,
            false_positives=0,
            true_negatives=5,
            false_negatives=0
        )
        assert accuracy.accuracy == 1.0
        assert accuracy.precision == 1.0
        assert accuracy.recall == 1.0
        assert accuracy.f1_score == 1.0

    def test_zero_accuracy(self):
        """Test pattern with 0% accuracy (worst case)"""
        accuracy = PatternAccuracy(
            pattern_id="bad_pattern",
            pattern_name="Bad Pattern",
            total_samples=10,
            true_positives=0,
            false_positives=5,
            true_negatives=0,
            false_negatives=5
        )
        assert accuracy.accuracy == 0.0
        assert accuracy.precision == 0.0
        assert accuracy.recall == 0.0

    def test_mixed_accuracy(self):
        """Test pattern with mixed results"""
        accuracy = PatternAccuracy(
            pattern_id="mixed_pattern",
            pattern_name="Mixed Pattern",
            total_samples=20,
            true_positives=8,
            false_positives=2,
            true_negatives=7,
            false_negatives=3
        )
        assert accuracy.accuracy == 0.75  # (8 + 7) / 20
        assert accuracy.precision == 0.8  # 8 / (8 + 2)
        assert accuracy.recall == pytest.approx(0.727, rel=0.01)  # 8 / (8 + 3)
        assert accuracy.f1_score == pytest.approx(0.762, rel=0.01)


class TestFeedbackLoop:
    """Test FeedbackLoop system"""

    def test_initialization(self, feedback_loop, temp_feedback_dir):
        """Test feedback loop initialization"""
        assert feedback_loop.feedback_dir == Path(temp_feedback_dir)
        assert feedback_loop.feedback_dir.exists()
        assert feedback_loop.feedback_file == Path(temp_feedback_dir) / "feedback_records.jsonl"

    def test_record_correct_verdict(self, feedback_loop):
        """Test recording a correct automated verdict"""
        record = feedback_loop.record_verdict(
            finding_id="test-001",
            automated_verdict="confirmed",
            human_verdict="confirmed",
            confidence=0.85,
            pattern_used="oauth2_pattern",
            finding_category="oauth2",
            reasoning="Real vulnerability"
        )

        assert record.is_correct is True
        assert record.error_type is None
        assert feedback_loop.feedback_file.exists()

        # Verify written to file
        with open(feedback_loop.feedback_file, "r") as f:
            lines = f.readlines()
            assert len(lines) == 1
            saved_record = json.loads(lines[0])
            assert saved_record["finding_id"] == "test-001"
            assert saved_record["is_correct"] is True

    def test_record_false_negative(self, feedback_loop):
        """Test recording a false negative (missed vulnerability)"""
        record = feedback_loop.record_verdict(
            finding_id="test-002",
            automated_verdict="false_positive",
            human_verdict="confirmed",
            confidence=0.60,
            pattern_used="oauth2_pattern",
            finding_category="oauth2",
            reasoning="Actually vulnerable"
        )

        assert record.is_correct is False
        assert record.error_type == "false_negative"

    def test_record_false_positive(self, feedback_loop):
        """Test recording a false positive (incorrect flag)"""
        record = feedback_loop.record_verdict(
            finding_id="test-003",
            automated_verdict="confirmed",
            human_verdict="false_positive",
            confidence=0.70,
            pattern_used="file_permission_pattern",
            finding_category="file_permission",
            reasoning="Not vulnerable"
        )

        assert record.is_correct is False
        assert record.error_type == "false_positive"

    def test_multiple_records(self, feedback_loop):
        """Test recording multiple verdicts"""
        for i in range(5):
            feedback_loop.record_verdict(
                finding_id=f"test-{i:03d}",
                automated_verdict="confirmed",
                human_verdict="confirmed" if i < 3 else "false_positive",
                confidence=0.80,
                pattern_used="test_pattern",
                finding_category="test"
            )

        with open(feedback_loop.feedback_file, "r") as f:
            lines = f.readlines()
            assert len(lines) == 5

    def test_get_pattern_feedback(self, feedback_loop):
        """Test retrieving feedback for specific pattern"""
        # Record feedback with different patterns
        feedback_loop.record_verdict(
            finding_id="test-001",
            automated_verdict="confirmed",
            human_verdict="confirmed",
            confidence=0.85,
            pattern_used="pattern_a",
            finding_category="test"
        )
        feedback_loop.record_verdict(
            finding_id="test-002",
            automated_verdict="confirmed",
            human_verdict="confirmed",
            confidence=0.90,
            pattern_used="pattern_b",
            finding_category="test"
        )
        feedback_loop.record_verdict(
            finding_id="test-003",
            automated_verdict="false_positive",
            human_verdict="false_positive",
            confidence=0.75,
            pattern_used="pattern_a",
            finding_category="test"
        )

        # Get feedback for pattern_a
        pattern_a_feedback = feedback_loop.get_pattern_feedback("pattern_a")
        assert len(pattern_a_feedback) == 2
        assert all(f.pattern_used == "pattern_a" for f in pattern_a_feedback)

        # Get feedback for pattern_b
        pattern_b_feedback = feedback_loop.get_pattern_feedback("pattern_b")
        assert len(pattern_b_feedback) == 1

    def test_calculate_pattern_accuracy_no_data(self, feedback_loop):
        """Test accuracy calculation with no feedback data"""
        accuracy = feedback_loop.calculate_pattern_accuracy("unknown_pattern", "Unknown")
        assert accuracy.total_samples == 0
        assert accuracy.accuracy == 0.0

    def test_calculate_pattern_accuracy_with_data(self, feedback_loop):
        """Test accuracy calculation with real feedback data"""
        pattern_id = "test_pattern"

        # Record various outcomes
        # TP: automated=confirmed, human=confirmed
        feedback_loop.record_verdict("tp1", "confirmed", "confirmed", 0.85, pattern_id, "test")
        feedback_loop.record_verdict("tp2", "confirmed", "confirmed", 0.90, pattern_id, "test")

        # TN: automated=false_positive, human=false_positive
        feedback_loop.record_verdict("tn1", "false_positive", "false_positive", 0.70, pattern_id, "test")

        # FP: automated=confirmed, human=false_positive
        feedback_loop.record_verdict("fp1", "confirmed", "false_positive", 0.75, pattern_id, "test")

        # FN: automated=false_positive, human=confirmed
        feedback_loop.record_verdict("fn1", "false_positive", "confirmed", 0.65, pattern_id, "test")

        accuracy = feedback_loop.calculate_pattern_accuracy(pattern_id, "Test Pattern")

        assert accuracy.total_samples == 5
        assert accuracy.true_positives == 2
        assert accuracy.true_negatives == 1
        assert accuracy.false_positives == 1
        assert accuracy.false_negatives == 1
        assert accuracy.accuracy == 0.6  # (2 + 1) / 5

    def test_get_statistics_no_data(self, feedback_loop):
        """Test statistics with no feedback data"""
        stats = feedback_loop.get_statistics()
        assert stats["total_records"] == 0

    def test_get_statistics_with_data(self, feedback_loop):
        """Test statistics with feedback data"""
        # Record 10 verdicts: 7 correct, 2 false positives, 1 false negative
        for i in range(7):
            feedback_loop.record_verdict(
                f"correct-{i}",
                "confirmed",
                "confirmed",
                0.85,
                "pattern_a",
                "test"
            )

        feedback_loop.record_verdict(
            "fp1",
            "confirmed",
            "false_positive",
            0.70,
            "pattern_a",
            "test"
        )

        feedback_loop.record_verdict(
            "fp2",
            "confirmed",
            "false_positive",
            0.65,
            "pattern_a",
            "test"
        )

        feedback_loop.record_verdict(
            "fn1",
            "false_positive",
            "confirmed",
            0.60,
            "pattern_a",
            "test"
        )

        stats = feedback_loop.get_statistics()
        assert stats["total_records"] == 10
        assert stats["correct"] == 7
        assert stats["accuracy"] == 0.7
        assert stats["false_positives"] == 2
        assert stats["false_negatives"] == 1

    def test_suggest_adjustments_insufficient_data(self, feedback_loop):
        """Test adjustment suggestions with insufficient data"""
        # Record only 5 samples (below min_samples=10)
        for i in range(5):
            feedback_loop.record_verdict(
                f"test-{i}",
                "confirmed",
                "confirmed",
                0.85,
                "pattern_a",
                "test"
            )

        adjustments = feedback_loop.suggest_confidence_adjustments(min_samples=10)
        assert len(adjustments) == 0

    def test_suggest_adjustments_high_accuracy(self, feedback_loop):
        """Test adjustment for pattern with high accuracy"""
        pattern_id = "high_accuracy_pattern"

        # Record 15 samples with 95% accuracy
        for i in range(14):
            feedback_loop.record_verdict(
                f"correct-{i}",
                "confirmed",
                "confirmed",
                0.85,
                pattern_id,
                "test"
            )

        # 1 error
        feedback_loop.record_verdict(
            "error-1",
            "confirmed",
            "false_positive",
            0.80,
            pattern_id,
            "test"
        )

        adjustments = feedback_loop.suggest_confidence_adjustments(min_samples=10)
        assert len(adjustments) == 1
        adj = adjustments[0]
        assert adj.pattern_id == pattern_id
        # High accuracy should increase multiplier
        assert adj.recommended_multiplier > adj.current_multiplier

    def test_suggest_adjustments_low_accuracy(self, feedback_loop):
        """Test adjustment for pattern with low accuracy"""
        pattern_id = "low_accuracy_pattern"

        # Record 15 samples with only 60% accuracy
        for i in range(9):
            feedback_loop.record_verdict(
                f"correct-{i}",
                "confirmed",
                "confirmed",
                0.85,
                pattern_id,
                "test"
            )

        for i in range(6):
            feedback_loop.record_verdict(
                f"error-{i}",
                "confirmed",
                "false_positive",
                0.80,
                pattern_id,
                "test"
            )

        adjustments = feedback_loop.suggest_confidence_adjustments(min_samples=10)
        assert len(adjustments) == 1
        adj = adjustments[0]
        # Low accuracy should decrease multiplier
        assert adj.recommended_multiplier < adj.current_multiplier

    def test_suggest_adjustments_high_false_negatives(self, feedback_loop):
        """Test adjustment for pattern with high false negative rate"""
        pattern_id = "high_fn_pattern"

        # Record 15 samples with 25% false negative rate (critical!)
        for i in range(8):
            feedback_loop.record_verdict(
                f"correct-{i}",
                "confirmed",
                "confirmed",
                0.85,
                pattern_id,
                "test"
            )

        # 4 false negatives (missed vulnerabilities!)
        for i in range(4):
            feedback_loop.record_verdict(
                f"fn-{i}",
                "false_positive",
                "confirmed",
                0.70,
                pattern_id,
                "test"
            )

        # 3 true negatives
        for i in range(3):
            feedback_loop.record_verdict(
                f"tn-{i}",
                "false_positive",
                "false_positive",
                0.75,
                pattern_id,
                "test"
            )

        adjustments = feedback_loop.suggest_confidence_adjustments(min_samples=10)
        assert len(adjustments) == 1
        adj = adjustments[0]
        # High false negative rate should aggressively reduce multiplier
        assert adj.recommended_multiplier <= 0.7

    def test_apply_adjustments_dry_run(self, feedback_loop):
        """Test applying adjustments in dry-run mode"""
        adjustments = [
            ConfidenceAdjustment(
                pattern_id="pattern_a",
                current_multiplier=1.0,
                recommended_multiplier=1.1,
                reasoning="High accuracy",
                sample_size=20,
                accuracy=0.95
            )
        ]

        # Dry run should not create file
        feedback_loop.apply_adjustments(adjustments, dry_run=True)
        assert not feedback_loop.adjustments_file.exists()

    def test_apply_adjustments_real(self, feedback_loop):
        """Test actually applying adjustments"""
        adjustments = [
            ConfidenceAdjustment(
                pattern_id="pattern_a",
                current_multiplier=1.0,
                recommended_multiplier=1.1,
                reasoning="High accuracy",
                sample_size=20,
                accuracy=0.95
            ),
            ConfidenceAdjustment(
                pattern_id="pattern_b",
                current_multiplier=1.0,
                recommended_multiplier=0.8,
                reasoning="Low accuracy",
                sample_size=15,
                accuracy=0.65
            )
        ]

        feedback_loop.apply_adjustments(adjustments, dry_run=False)
        assert feedback_loop.adjustments_file.exists()

        # Verify saved correctly
        with open(feedback_loop.adjustments_file, "r") as f:
            saved = json.load(f)
            assert "pattern_a" in saved
            assert saved["pattern_a"]["multiplier"] == 1.1
            assert "pattern_b" in saved
            assert saved["pattern_b"]["multiplier"] == 0.8

    def test_get_current_multiplier_default(self, feedback_loop):
        """Test getting multiplier when no adjustments exist"""
        multiplier = feedback_loop._get_current_multiplier("unknown_pattern")
        assert multiplier == 1.0

    def test_get_current_multiplier_existing(self, feedback_loop):
        """Test getting multiplier for existing adjustment"""
        # Apply adjustment
        adjustments = [
            ConfidenceAdjustment(
                pattern_id="pattern_a",
                current_multiplier=1.0,
                recommended_multiplier=1.15,
                reasoning="Test",
                sample_size=20,
                accuracy=0.9
            )
        ]
        feedback_loop.apply_adjustments(adjustments, dry_run=False)

        # Get multiplier
        multiplier = feedback_loop._get_current_multiplier("pattern_a")
        assert multiplier == 1.15

    def test_end_to_end_workflow(self, feedback_loop):
        """Test complete feedback loop workflow"""
        pattern_id = "oauth2_dev_pattern"

        # Phase 1: Record initial feedback (50% accuracy)
        for i in range(10):
            feedback_loop.record_verdict(
                f"finding-{i:03d}",
                "confirmed",
                "confirmed" if i < 5 else "false_positive",
                0.80,
                pattern_id,
                "oauth2"
            )

        # Phase 2: Check statistics
        stats = feedback_loop.get_statistics()
        assert stats["total_records"] == 10
        assert stats["accuracy"] == 0.5

        # Phase 3: Calculate pattern accuracy
        accuracy = feedback_loop.calculate_pattern_accuracy(pattern_id, "OAuth2 Dev Pattern")
        assert accuracy.total_samples == 10
        assert accuracy.accuracy == 0.5

        # Phase 4: Get adjustment recommendations
        adjustments = feedback_loop.suggest_confidence_adjustments(min_samples=5)
        assert len(adjustments) == 1
        adj = adjustments[0]
        assert adj.pattern_id == pattern_id
        # 50% accuracy should reduce confidence
        assert adj.recommended_multiplier < 1.0

        # Phase 5: Apply adjustments
        feedback_loop.apply_adjustments(adjustments, dry_run=False)

        # Phase 6: Verify multiplier updated
        new_multiplier = feedback_loop._get_current_multiplier(pattern_id)
        assert new_multiplier == adj.recommended_multiplier


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
