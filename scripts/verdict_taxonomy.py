#!/usr/bin/env python3
"""
Verdict Taxonomy for Argus Security Agent Personas
Provides granular classification of security finding verdicts
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional


class VerdictType(Enum):
    """
    Granular verdict taxonomy with 6 levels

    Confidence Ranges:
    - CONFIRMED: 0.8-1.0 (High confidence vulnerability)
    - LIKELY_TRUE: 0.7-0.8 (Probable vulnerability, needs validation)
    - UNCERTAIN: 0.4-0.7 (Needs human review - could go either way)
    - LIKELY_FALSE_POSITIVE: 0.2-0.4 (Probable false positive)
    - FALSE_POSITIVE: 0.0-0.2 (High confidence false positive)
    - NEEDS_REVIEW: N/A (Analysis incomplete/failed - different from uncertain)
    """

    CONFIRMED = "confirmed"
    LIKELY_TRUE = "likely_true"
    UNCERTAIN = "uncertain"
    LIKELY_FALSE_POSITIVE = "likely_fp"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"

    def get_display_name(self) -> str:
        """Get human-readable display name"""
        return {
            VerdictType.CONFIRMED: "Confirmed Vulnerability",
            VerdictType.LIKELY_TRUE: "Likely Vulnerability",
            VerdictType.UNCERTAIN: "Uncertain (Needs Review)",
            VerdictType.LIKELY_FALSE_POSITIVE: "Likely False Positive",
            VerdictType.FALSE_POSITIVE: "False Positive",
            VerdictType.NEEDS_REVIEW: "Needs Manual Review"
        }[self]

    def get_priority(self) -> int:
        """Get triage priority (1=highest, 6=lowest)"""
        return {
            VerdictType.CONFIRMED: 1,
            VerdictType.LIKELY_TRUE: 2,
            VerdictType.UNCERTAIN: 3,
            VerdictType.NEEDS_REVIEW: 4,
            VerdictType.LIKELY_FALSE_POSITIVE: 5,
            VerdictType.FALSE_POSITIVE: 6
        }[self]

    def get_confidence_range(self) -> tuple[float, float]:
        """Get typical confidence range for this verdict"""
        return {
            VerdictType.CONFIRMED: (0.8, 1.0),
            VerdictType.LIKELY_TRUE: (0.7, 0.8),
            VerdictType.UNCERTAIN: (0.4, 0.7),
            VerdictType.LIKELY_FALSE_POSITIVE: (0.2, 0.4),
            VerdictType.FALSE_POSITIVE: (0.0, 0.2),
            VerdictType.NEEDS_REVIEW: (0.0, 1.0)  # Any confidence if analysis failed
        }[self]


@dataclass
class VerdictMetadata:
    """Additional metadata for verdict decisions"""
    confidence: float
    reasoning: str
    review_reason: Optional[str] = None  # Why uncertain/needs review
    recommended_action: Optional[str] = None


class VerdictClassifier:
    """
    Classifies findings into appropriate verdict categories
    """

    # Confidence thresholds
    CONFIRMED_THRESHOLD = 0.8
    LIKELY_TRUE_THRESHOLD = 0.7
    UNCERTAIN_LOWER_THRESHOLD = 0.4
    LIKELY_FP_THRESHOLD = 0.2

    @classmethod
    def classify_verdict(
        cls,
        confidence: float,
        analysis_complete: bool = True,
        severity: str = "medium"
    ) -> VerdictType:
        """
        Classify finding into verdict category

        Args:
            confidence: Confidence score 0.0-1.0
            analysis_complete: Whether analysis finished successfully
            severity: Finding severity (affects thresholds)

        Returns:
            VerdictType classification
        """
        # If analysis failed/incomplete, always needs review
        if not analysis_complete:
            return VerdictType.NEEDS_REVIEW

        # Adjust thresholds based on severity
        # High/Critical findings: require higher confidence for FP verdict
        # This means we expand the "uncertain" range downward
        if severity.lower() in ["high", "critical"]:
            likely_fp_threshold = 0.15  # More conservative - need lower confidence to be FP
            uncertain_lower = 0.15  # Start uncertain at lower threshold
        else:
            likely_fp_threshold = cls.LIKELY_FP_THRESHOLD
            uncertain_lower = cls.UNCERTAIN_LOWER_THRESHOLD

        # Classify based on confidence
        if confidence >= cls.CONFIRMED_THRESHOLD:
            return VerdictType.CONFIRMED

        elif confidence >= cls.LIKELY_TRUE_THRESHOLD:
            return VerdictType.LIKELY_TRUE

        elif confidence >= uncertain_lower:
            return VerdictType.UNCERTAIN

        elif confidence >= likely_fp_threshold:
            # For high/critical, this range is effectively empty (0.15-0.15)
            # So everything below uncertain goes to FP
            return VerdictType.LIKELY_FALSE_POSITIVE

        else:
            return VerdictType.FALSE_POSITIVE

    @classmethod
    def get_recommended_action(cls, verdict: VerdictType, severity: str) -> str:
        """Get recommended triage action for verdict"""
        if verdict == VerdictType.CONFIRMED:
            if severity.lower() in ["critical", "high"]:
                return "Immediate remediation required"
            else:
                return "Schedule remediation"

        elif verdict == VerdictType.LIKELY_TRUE:
            return "Manual validation recommended, likely true positive"

        elif verdict == VerdictType.UNCERTAIN:
            return "Human review required - insufficient confidence for auto-triage"

        elif verdict == VerdictType.NEEDS_REVIEW:
            return "Analysis incomplete - manual investigation needed"

        elif verdict == VerdictType.LIKELY_FALSE_POSITIVE:
            return "Likely false positive - spot check recommended"

        elif verdict == VerdictType.FALSE_POSITIVE:
            return "High confidence false positive - can suppress"

        return "Unknown verdict"

    @classmethod
    def should_auto_suppress(cls, verdict: VerdictType, confidence: float) -> bool:
        """Determine if finding can be auto-suppressed"""
        return (
            verdict == VerdictType.FALSE_POSITIVE and
            confidence <= 0.2
        )

    @classmethod
    def should_block_deployment(cls, verdict: VerdictType, severity: str) -> bool:
        """Determine if finding should block deployment/PR"""
        if verdict == VerdictType.CONFIRMED:
            return severity.lower() in ["critical", "high"]

        # Conservative: block on likely_true + critical
        if verdict == VerdictType.LIKELY_TRUE:
            return severity.lower() == "critical"

        return False


def create_verdict_with_metadata(
    confidence: float,
    analysis_complete: bool,
    severity: str,
    reasoning: str,
    review_reason: Optional[str] = None
) -> tuple[VerdictType, VerdictMetadata]:
    """
    Create verdict with full metadata

    Args:
        confidence: Confidence score
        analysis_complete: Analysis completion status
        severity: Finding severity
        reasoning: Explanation of verdict
        review_reason: Why uncertain/needs review (if applicable)

    Returns:
        Tuple of (VerdictType, VerdictMetadata)
    """
    verdict = VerdictClassifier.classify_verdict(confidence, analysis_complete, severity)

    metadata = VerdictMetadata(
        confidence=confidence,
        reasoning=reasoning,
        review_reason=review_reason,
        recommended_action=VerdictClassifier.get_recommended_action(verdict, severity)
    )

    return verdict, metadata
