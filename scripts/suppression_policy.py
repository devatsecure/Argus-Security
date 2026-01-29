#!/usr/bin/env python3
"""
Suppression Policy Enforcement for Argus Security
Prevents premature suppression of findings without sufficient evidence
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class EvidenceQuality(Enum):
    """Quality ratings for evidence signals"""
    DIRECT_CODE_MATCH = "direct_code_match"        # 2.0 points
    METADATA_SIGNAL = "metadata_signal"            # 1.5 points
    CONTEXTUAL_INFERENCE = "contextual_inference"  # 1.0 points
    PATH_INDICATOR = "path_indicator"              # 0.5 points
    HEURISTIC = "heuristic"                        # 0.3 points


@dataclass
class SuppressionDecision:
    """Result of suppression policy evaluation"""
    can_suppress: bool
    confidence: float
    evidence_count: int
    evidence_quality_score: float
    reasoning: str
    policy_violations: list[str]


class SuppressionPolicy:
    """
    Enforces minimum evidence requirements for auto-suppression

    Policy Rules:
    1. Minimum 3 evidence items required
    2. Minimum confidence 0.7 required
    3. Minimum evidence quality score 5.0 required
    4. No conflicting signals allowed
    """

    # Configuration
    MIN_EVIDENCE_AUTO_SUPPRESS = 3
    MIN_CONFIDENCE_AUTO_SUPPRESS = 0.7
    MIN_EVIDENCE_QUALITY_SCORE = 5.0

    # Evidence quality weights
    QUALITY_WEIGHTS = {
        EvidenceQuality.DIRECT_CODE_MATCH: 2.0,
        EvidenceQuality.METADATA_SIGNAL: 1.5,
        EvidenceQuality.CONTEXTUAL_INFERENCE: 1.0,
        EvidenceQuality.PATH_INDICATOR: 0.5,
        EvidenceQuality.HEURISTIC: 0.3,
    }

    def __init__(self):
        """Initialize suppression policy"""
        self.logger = logging.getLogger(__name__)

    def evaluate_suppression(
        self,
        analysis: Any,  # EnhancedFPAnalysis
        finding: dict[str, Any]
    ) -> SuppressionDecision:
        """
        Evaluate if finding can be auto-suppressed based on evidence

        Args:
            analysis: EnhancedFPAnalysis result from detector
            finding: Original security finding

        Returns:
            SuppressionDecision with policy evaluation
        """
        violations = []

        # Check confidence threshold
        if analysis.confidence < self.MIN_CONFIDENCE_AUTO_SUPPRESS:
            violations.append(
                f"Confidence {analysis.confidence:.2f} below threshold "
                f"{self.MIN_CONFIDENCE_AUTO_SUPPRESS}"
            )

        # Check evidence count (excluding metadata)
        real_evidence = [e for e in analysis.evidence if not e.startswith("[METADATA]")]
        evidence_count = len(real_evidence)
        if evidence_count < self.MIN_EVIDENCE_AUTO_SUPPRESS:
            violations.append(
                f"Evidence count {evidence_count} below minimum "
                f"{self.MIN_EVIDENCE_AUTO_SUPPRESS}"
            )

        # Calculate evidence quality score (excluding metadata)
        quality_score = self._calculate_evidence_quality(real_evidence)
        if quality_score < self.MIN_EVIDENCE_QUALITY_SCORE:
            violations.append(
                f"Evidence quality score {quality_score:.1f} below minimum "
                f"{self.MIN_EVIDENCE_QUALITY_SCORE}"
            )

        # Check for conflicting signals
        conflicts = self._detect_conflicts(analysis, finding)
        if conflicts:
            violations.extend(conflicts)

        # Make decision
        can_suppress = len(violations) == 0 and analysis.is_false_positive

        reasoning = (
            f"Suppression {'APPROVED' if can_suppress else 'DENIED'}: "
            f"{evidence_count} evidence items, "
            f"quality score {quality_score:.1f}, "
            f"confidence {analysis.confidence:.2f}"
        )

        if violations:
            reasoning += f" | Violations: {'; '.join(violations)}"

        return SuppressionDecision(
            can_suppress=can_suppress,
            confidence=analysis.confidence,
            evidence_count=evidence_count,
            evidence_quality_score=quality_score,
            reasoning=reasoning,
            policy_violations=violations
        )

    def _calculate_evidence_quality(self, evidence_list: list[str]) -> float:
        """
        Calculate quality score based on evidence types

        Args:
            evidence_list: List of evidence strings

        Returns:
            Quality score (sum of weights)
        """
        score = 0.0

        for evidence_item in evidence_list:
            evidence_lower = evidence_item.lower()

            # Classify evidence type and add weight
            if any(term in evidence_lower for term in [
                "code match", "direct match", "pattern found", "mutex detected",
                "pkce flow", "lock mechanism", "properly prevents", "properly secured",
                "in-memory mutex", "file lock", "synchronized", "thread synchronization"
            ]):
                score += self.QUALITY_WEIGHTS[EvidenceQuality.DIRECT_CODE_MATCH]

            elif any(term in evidence_lower for term in [
                "file permissions", "metadata", "gitattributes", ".dockerignore",
                "security.md", "restricted permissions", "only readable by owner",
                "permissions:", "octal"
            ]):
                score += self.QUALITY_WEIGHTS[EvidenceQuality.METADATA_SIGNAL]

            elif any(term in evidence_lower for term in [
                "context", "typically", "appears to be", "suggests",
                "indicates", "likely", "appropriate for", "typical for",
                "public client", "dev-only", "environment conditional"
            ]):
                score += self.QUALITY_WEIGHTS[EvidenceQuality.CONTEXTUAL_INFERENCE]

            elif any(term in evidence_lower for term in [
                "path indicator", "file in", "directory", "location",
                "secure location", "test", "mock", "fixture", "example"
            ]):
                score += self.QUALITY_WEIGHTS[EvidenceQuality.PATH_INDICATOR]

            else:
                # Default to heuristic quality
                score += self.QUALITY_WEIGHTS[EvidenceQuality.HEURISTIC]

        return score

    def _detect_conflicts(self, analysis: Any, finding: dict) -> list[str]:
        """
        Detect conflicting signals that should block suppression

        Args:
            analysis: EnhancedFPAnalysis
            finding: Original finding

        Returns:
            List of conflict descriptions
        """
        conflicts = []

        # Check for high severity + high FP confidence (suspicious)
        severity = finding.get("severity", "").lower()
        if severity in ["critical", "high"] and analysis.confidence > 0.9:
            conflicts.append(
                f"High severity ({severity}) with very high FP confidence "
                f"({analysis.confidence:.2f}) - suspicious"
            )

        # Check for production file paths with dev suppression
        file_path = finding.get("path", finding.get("file_path", ""))
        if analysis.category == "dev_config":
            prod_indicators = ["prod", "production", "release", "main", "master"]
            if any(indicator in file_path.lower() for indicator in prod_indicators):
                conflicts.append(
                    f"Production path indicator in {file_path} conflicts with "
                    f"dev-only suppression"
                )

        # Check for secret findings in non-test paths being suppressed as dev config
        if analysis.category == "dev_config":
            message = finding.get("message", "").lower()
            category = finding.get("category", "").lower()
            if any(term in f"{message} {category}" for term in ["secret", "password", "key", "token", "credential"]):
                test_indicators = ["test", "mock", "fixture", "example", "sample", "demo"]
                if not any(indicator in file_path.lower() for indicator in test_indicators):
                    conflicts.append(
                        f"Secret-related finding in non-test path {file_path} "
                        f"should not be suppressed as dev config"
                    )

        # Check for OAuth2 suppression with actual client_secret present
        if analysis.category == "oauth2_public_client":
            code_snippet = finding.get("evidence", {}).get("snippet", "")
            if "client_secret" in code_snippet.lower():
                conflicts.append(
                    "OAuth2 suppression conflict: client_secret found in code, "
                    "this should not be a public client"
                )

        return conflicts

    def get_policy_summary(self) -> dict:
        """Get current policy configuration"""
        return {
            "min_evidence_count": self.MIN_EVIDENCE_AUTO_SUPPRESS,
            "min_confidence": self.MIN_CONFIDENCE_AUTO_SUPPRESS,
            "min_quality_score": self.MIN_EVIDENCE_QUALITY_SCORE,
            "quality_weights": {
                k.value: v for k, v in self.QUALITY_WEIGHTS.items()
            }
        }
