#!/usr/bin/env python3
"""
Tests for Verdict Taxonomy Module
Tests the granular verdict classification system
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from verdict_taxonomy import (
    VerdictType,
    VerdictClassifier,
    VerdictMetadata,
    create_verdict_with_metadata
)


class TestVerdictType:
    """Test VerdictType enum functionality"""

    def test_verdict_display_names(self):
        """Test display name generation"""
        assert VerdictType.CONFIRMED.get_display_name() == "Confirmed Vulnerability"
        assert VerdictType.LIKELY_TRUE.get_display_name() == "Likely Vulnerability"
        assert VerdictType.UNCERTAIN.get_display_name() == "Uncertain (Needs Review)"
        assert VerdictType.LIKELY_FALSE_POSITIVE.get_display_name() == "Likely False Positive"
        assert VerdictType.FALSE_POSITIVE.get_display_name() == "False Positive"
        assert VerdictType.NEEDS_REVIEW.get_display_name() == "Needs Manual Review"

    def test_verdict_priority_ordering(self):
        """Test triage priority ordering (lower number = higher priority)"""
        assert VerdictType.CONFIRMED.get_priority() == 1
        assert VerdictType.LIKELY_TRUE.get_priority() == 2
        assert VerdictType.UNCERTAIN.get_priority() == 3
        assert VerdictType.NEEDS_REVIEW.get_priority() == 4
        assert VerdictType.LIKELY_FALSE_POSITIVE.get_priority() == 5
        assert VerdictType.FALSE_POSITIVE.get_priority() == 6

    def test_verdict_confidence_ranges(self):
        """Test confidence range mappings"""
        assert VerdictType.CONFIRMED.get_confidence_range() == (0.8, 1.0)
        assert VerdictType.LIKELY_TRUE.get_confidence_range() == (0.7, 0.8)
        assert VerdictType.UNCERTAIN.get_confidence_range() == (0.4, 0.7)
        assert VerdictType.LIKELY_FALSE_POSITIVE.get_confidence_range() == (0.2, 0.4)
        assert VerdictType.FALSE_POSITIVE.get_confidence_range() == (0.0, 0.2)
        assert VerdictType.NEEDS_REVIEW.get_confidence_range() == (0.0, 1.0)


class TestVerdictClassifier:
    """Test VerdictClassifier classification logic"""

    def test_confirmed_classification(self):
        """Test high confidence (0.8-1.0) classification"""
        assert VerdictClassifier.classify_verdict(0.95, True) == VerdictType.CONFIRMED
        assert VerdictClassifier.classify_verdict(0.85, True) == VerdictType.CONFIRMED
        assert VerdictClassifier.classify_verdict(0.80, True) == VerdictType.CONFIRMED
        assert VerdictClassifier.classify_verdict(1.0, True) == VerdictType.CONFIRMED

    def test_likely_true_classification(self):
        """Test likely true (0.7-0.8) classification"""
        assert VerdictClassifier.classify_verdict(0.75, True) == VerdictType.LIKELY_TRUE
        assert VerdictClassifier.classify_verdict(0.70, True) == VerdictType.LIKELY_TRUE
        assert VerdictClassifier.classify_verdict(0.79, True) == VerdictType.LIKELY_TRUE

    def test_uncertain_classification(self):
        """Test uncertain (0.4-0.7) classification"""
        assert VerdictClassifier.classify_verdict(0.55, True) == VerdictType.UNCERTAIN
        assert VerdictClassifier.classify_verdict(0.60, True) == VerdictType.UNCERTAIN
        assert VerdictClassifier.classify_verdict(0.50, True) == VerdictType.UNCERTAIN
        assert VerdictClassifier.classify_verdict(0.40, True) == VerdictType.UNCERTAIN
        assert VerdictClassifier.classify_verdict(0.69, True) == VerdictType.UNCERTAIN

    def test_likely_fp_classification(self):
        """Test likely false positive (0.2-0.4) classification"""
        assert VerdictClassifier.classify_verdict(0.30, True) == VerdictType.LIKELY_FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.25, True) == VerdictType.LIKELY_FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.20, True) == VerdictType.LIKELY_FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.39, True) == VerdictType.LIKELY_FALSE_POSITIVE

    def test_false_positive_classification(self):
        """Test false positive (0.0-0.2) classification"""
        assert VerdictClassifier.classify_verdict(0.10, True) == VerdictType.FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.05, True) == VerdictType.FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.0, True) == VerdictType.FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.19, True) == VerdictType.FALSE_POSITIVE

    def test_analysis_incomplete_always_needs_review(self):
        """Analysis incomplete should always result in NEEDS_REVIEW"""
        # Regardless of confidence, incomplete analysis = needs review
        assert VerdictClassifier.classify_verdict(0.95, False) == VerdictType.NEEDS_REVIEW
        assert VerdictClassifier.classify_verdict(0.75, False) == VerdictType.NEEDS_REVIEW
        assert VerdictClassifier.classify_verdict(0.50, False) == VerdictType.NEEDS_REVIEW
        assert VerdictClassifier.classify_verdict(0.10, False) == VerdictType.NEEDS_REVIEW

    def test_severity_adjusts_thresholds_high(self):
        """High severity should adjust thresholds conservatively"""
        # Medium severity: 0.25 = likely FP (in 0.2-0.4 range)
        assert VerdictClassifier.classify_verdict(0.25, True, "medium") == VerdictType.LIKELY_FALSE_POSITIVE

        # High severity: 0.25 = uncertain (uncertain range extended to 0.15-0.7)
        assert VerdictClassifier.classify_verdict(0.25, True, "high") == VerdictType.UNCERTAIN

        # Critical severity also adjusts
        assert VerdictClassifier.classify_verdict(0.25, True, "critical") == VerdictType.UNCERTAIN

        # At 0.14, should still be FP for high severity
        assert VerdictClassifier.classify_verdict(0.14, True, "high") == VerdictType.FALSE_POSITIVE

    def test_severity_adjusts_thresholds_critical(self):
        """Critical severity should be most conservative"""
        # At 0.45, both medium and critical should be uncertain
        assert VerdictClassifier.classify_verdict(0.45, True, "medium") == VerdictType.UNCERTAIN
        assert VerdictClassifier.classify_verdict(0.45, True, "critical") == VerdictType.UNCERTAIN

        # At 0.37, medium = likely_fp (0.2-0.4), critical = uncertain (0.15-0.7)
        assert VerdictClassifier.classify_verdict(0.37, True, "medium") == VerdictType.LIKELY_FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.37, True, "critical") == VerdictType.UNCERTAIN

        # At 0.20, medium = likely_fp, critical = uncertain
        assert VerdictClassifier.classify_verdict(0.20, True, "medium") == VerdictType.LIKELY_FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.20, True, "critical") == VerdictType.UNCERTAIN

    def test_recommended_actions(self):
        """Test recommended action generation"""
        # Confirmed + critical
        action = VerdictClassifier.get_recommended_action(VerdictType.CONFIRMED, "critical")
        assert "Immediate remediation" in action

        # Confirmed + medium
        action = VerdictClassifier.get_recommended_action(VerdictType.CONFIRMED, "medium")
        assert "Schedule remediation" in action

        # Likely true
        action = VerdictClassifier.get_recommended_action(VerdictType.LIKELY_TRUE, "medium")
        assert "Manual validation" in action

        # Uncertain
        action = VerdictClassifier.get_recommended_action(VerdictType.UNCERTAIN, "medium")
        assert "Human review" in action

        # Needs review
        action = VerdictClassifier.get_recommended_action(VerdictType.NEEDS_REVIEW, "medium")
        assert "Analysis incomplete" in action

        # Likely FP
        action = VerdictClassifier.get_recommended_action(VerdictType.LIKELY_FALSE_POSITIVE, "medium")
        assert "Likely false positive" in action

        # False positive
        action = VerdictClassifier.get_recommended_action(VerdictType.FALSE_POSITIVE, "medium")
        assert "can suppress" in action

    def test_auto_suppress_logic(self):
        """Test auto-suppression decision logic"""
        # Only FALSE_POSITIVE with confidence <= 0.2 should auto-suppress
        assert VerdictClassifier.should_auto_suppress(VerdictType.FALSE_POSITIVE, 0.1) is True
        assert VerdictClassifier.should_auto_suppress(VerdictType.FALSE_POSITIVE, 0.2) is True
        assert VerdictClassifier.should_auto_suppress(VerdictType.FALSE_POSITIVE, 0.21) is False

        # Other verdicts should not auto-suppress
        assert VerdictClassifier.should_auto_suppress(VerdictType.LIKELY_FALSE_POSITIVE, 0.1) is False
        assert VerdictClassifier.should_auto_suppress(VerdictType.UNCERTAIN, 0.1) is False
        assert VerdictClassifier.should_auto_suppress(VerdictType.CONFIRMED, 0.1) is False

    def test_deployment_blocking_logic(self):
        """Test deployment blocking decision logic"""
        # Confirmed + critical/high should block
        assert VerdictClassifier.should_block_deployment(VerdictType.CONFIRMED, "critical") is True
        assert VerdictClassifier.should_block_deployment(VerdictType.CONFIRMED, "high") is True
        assert VerdictClassifier.should_block_deployment(VerdictType.CONFIRMED, "medium") is False
        assert VerdictClassifier.should_block_deployment(VerdictType.CONFIRMED, "low") is False

        # Likely true + critical should block
        assert VerdictClassifier.should_block_deployment(VerdictType.LIKELY_TRUE, "critical") is True
        assert VerdictClassifier.should_block_deployment(VerdictType.LIKELY_TRUE, "high") is False
        assert VerdictClassifier.should_block_deployment(VerdictType.LIKELY_TRUE, "medium") is False

        # Other verdicts should not block
        assert VerdictClassifier.should_block_deployment(VerdictType.UNCERTAIN, "critical") is False
        assert VerdictClassifier.should_block_deployment(VerdictType.NEEDS_REVIEW, "critical") is False
        assert VerdictClassifier.should_block_deployment(VerdictType.FALSE_POSITIVE, "critical") is False


class TestVerdictMetadata:
    """Test VerdictMetadata dataclass"""

    def test_metadata_creation(self):
        """Test creating verdict metadata"""
        metadata = VerdictMetadata(
            confidence=0.85,
            reasoning="This is a real vulnerability",
            review_reason=None,
            recommended_action="Immediate remediation required"
        )

        assert metadata.confidence == 0.85
        assert metadata.reasoning == "This is a real vulnerability"
        assert metadata.review_reason is None
        assert metadata.recommended_action == "Immediate remediation required"

    def test_metadata_with_review_reason(self):
        """Test metadata with review reason"""
        metadata = VerdictMetadata(
            confidence=0.55,
            reasoning="Insufficient information to determine",
            review_reason="Code context missing, framework unclear",
            recommended_action="Human review required"
        )

        assert metadata.confidence == 0.55
        assert metadata.review_reason == "Code context missing, framework unclear"


class TestCreateVerdictWithMetadata:
    """Test the helper function for creating verdict with metadata"""

    def test_create_confirmed_verdict(self):
        """Test creating confirmed verdict with metadata"""
        verdict, metadata = create_verdict_with_metadata(
            confidence=0.9,
            analysis_complete=True,
            severity="high",
            reasoning="Clear SQL injection vulnerability",
            review_reason=None
        )

        assert verdict == VerdictType.CONFIRMED
        assert metadata.confidence == 0.9
        assert metadata.reasoning == "Clear SQL injection vulnerability"
        assert metadata.review_reason is None
        assert "Immediate remediation" in metadata.recommended_action

    def test_create_uncertain_verdict(self):
        """Test creating uncertain verdict with metadata"""
        verdict, metadata = create_verdict_with_metadata(
            confidence=0.55,
            analysis_complete=True,
            severity="medium",
            reasoning="Could be vulnerable depending on configuration",
            review_reason="Configuration not visible in code"
        )

        assert verdict == VerdictType.UNCERTAIN
        assert metadata.confidence == 0.55
        assert metadata.review_reason == "Configuration not visible in code"
        assert "Human review" in metadata.recommended_action

    def test_create_needs_review_verdict(self):
        """Test creating needs_review verdict (analysis incomplete)"""
        verdict, metadata = create_verdict_with_metadata(
            confidence=0.8,  # High confidence but analysis incomplete
            analysis_complete=False,
            severity="high",
            reasoning="Analysis timed out",
            review_reason="Timeout during LLM analysis"
        )

        assert verdict == VerdictType.NEEDS_REVIEW  # Overrides high confidence
        assert metadata.confidence == 0.8
        assert metadata.review_reason == "Timeout during LLM analysis"
        assert "Analysis incomplete" in metadata.recommended_action

    def test_create_false_positive_verdict(self):
        """Test creating false positive verdict with metadata"""
        verdict, metadata = create_verdict_with_metadata(
            confidence=0.1,
            analysis_complete=True,
            severity="low",
            reasoning="Test file with mock credentials",
            review_reason=None
        )

        assert verdict == VerdictType.FALSE_POSITIVE
        assert metadata.confidence == 0.1
        assert "can suppress" in metadata.recommended_action


class TestBoundaryConditions:
    """Test edge cases and boundary conditions"""

    def test_confidence_exactly_at_thresholds(self):
        """Test classification at exact threshold boundaries"""
        # At 0.8 threshold
        assert VerdictClassifier.classify_verdict(0.8, True) == VerdictType.CONFIRMED

        # At 0.7 threshold
        assert VerdictClassifier.classify_verdict(0.7, True) == VerdictType.LIKELY_TRUE

        # At 0.4 threshold
        assert VerdictClassifier.classify_verdict(0.4, True) == VerdictType.UNCERTAIN

        # At 0.2 threshold
        assert VerdictClassifier.classify_verdict(0.2, True) == VerdictType.LIKELY_FALSE_POSITIVE

    def test_confidence_zero(self):
        """Test confidence of exactly 0.0"""
        assert VerdictClassifier.classify_verdict(0.0, True) == VerdictType.FALSE_POSITIVE

    def test_confidence_one(self):
        """Test confidence of exactly 1.0"""
        assert VerdictClassifier.classify_verdict(1.0, True) == VerdictType.CONFIRMED

    def test_case_insensitive_severity(self):
        """Test severity comparison is case-insensitive"""
        # Should all adjust thresholds the same way
        # For high/critical severity, 0.25 should be UNCERTAIN (not likely_fp)
        assert VerdictClassifier.classify_verdict(0.25, True, "HIGH") == VerdictType.UNCERTAIN
        assert VerdictClassifier.classify_verdict(0.25, True, "High") == VerdictType.UNCERTAIN
        assert VerdictClassifier.classify_verdict(0.25, True, "high") == VerdictType.UNCERTAIN

        assert VerdictClassifier.classify_verdict(0.25, True, "CRITICAL") == VerdictType.UNCERTAIN
        assert VerdictClassifier.classify_verdict(0.25, True, "Critical") == VerdictType.UNCERTAIN
        assert VerdictClassifier.classify_verdict(0.25, True, "critical") == VerdictType.UNCERTAIN

        # For medium/low, 0.25 should be LIKELY_FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.25, True, "MEDIUM") == VerdictType.LIKELY_FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.25, True, "medium") == VerdictType.LIKELY_FALSE_POSITIVE
        assert VerdictClassifier.classify_verdict(0.25, True, "LOW") == VerdictType.LIKELY_FALSE_POSITIVE


class TestIntegrationScenarios:
    """Test realistic usage scenarios"""

    def test_secret_scanner_finding_high_confidence(self):
        """Test typical secret scanner finding with high confidence"""
        verdict, metadata = create_verdict_with_metadata(
            confidence=0.92,
            analysis_complete=True,
            severity="critical",
            reasoning="AWS access key found in production code, high entropy match",
            review_reason=None
        )

        assert verdict == VerdictType.CONFIRMED
        assert VerdictClassifier.should_block_deployment(verdict, "critical") is True
        assert VerdictClassifier.should_auto_suppress(verdict, metadata.confidence) is False

    def test_secret_in_test_file(self):
        """Test secret found in test file (likely FP)"""
        verdict, metadata = create_verdict_with_metadata(
            confidence=0.15,
            analysis_complete=True,
            severity="low",
            reasoning="Mock credentials in test fixture file",
            review_reason=None
        )

        assert verdict == VerdictType.FALSE_POSITIVE
        assert VerdictClassifier.should_block_deployment(verdict, "low") is False
        assert VerdictClassifier.should_auto_suppress(verdict, metadata.confidence) is True

    def test_ambiguous_sql_injection(self):
        """Test ambiguous SQL injection finding"""
        verdict, metadata = create_verdict_with_metadata(
            confidence=0.62,
            analysis_complete=True,
            severity="high",
            reasoning="SQL query construction from user input, but parameterization unclear",
            review_reason="Cannot determine if ORM provides protection"
        )

        assert verdict == VerdictType.UNCERTAIN
        assert metadata.review_reason is not None
        assert VerdictClassifier.should_block_deployment(verdict, "high") is False

    def test_timeout_during_analysis(self):
        """Test LLM timeout scenario"""
        verdict, metadata = create_verdict_with_metadata(
            confidence=0.0,  # Default confidence on timeout
            analysis_complete=False,
            severity="medium",
            reasoning="Analysis timeout after 30 seconds",
            review_reason="LLM request timeout"
        )

        assert verdict == VerdictType.NEEDS_REVIEW
        assert "Analysis incomplete" in metadata.recommended_action

    def test_likely_true_cve(self):
        """Test CVE finding with good but not perfect confidence"""
        verdict, metadata = create_verdict_with_metadata(
            confidence=0.75,
            analysis_complete=True,
            severity="high",
            reasoning="Dependency has known CVE, likely exploitable but needs version confirmation",
            review_reason=None
        )

        assert verdict == VerdictType.LIKELY_TRUE
        assert "Manual validation" in metadata.recommended_action


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
