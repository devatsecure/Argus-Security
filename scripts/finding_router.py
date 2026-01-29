#!/usr/bin/env python3
"""
Intelligent Finding Router for Enhanced False Positive Detection
Routes security findings to specialized analyzers with confidence scoring
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class FindingType(Enum):
    """Structured finding taxonomy"""
    OAUTH2_PUBLIC_CLIENT = "oauth2_public_client"
    FILE_PERMISSION = "file_permission"
    DEV_CONFIG = "dev_config"
    LOCKING_MECHANISM = "locking_mechanism"
    HARDCODED_SECRET = "hardcoded_secret"
    UNKNOWN = "unknown"


@dataclass
class RoutingDecision:
    """Result of routing analysis"""
    finding_type: FindingType
    confidence: float  # 0.0-1.0
    analyzer_method: Optional[str]
    reasoning: str
    fallback_analyzers: list[tuple[str, float]]  # [(method_name, confidence)]


class FindingRouter:
    """Intelligent routing with confidence scoring"""

    def __init__(self):
        """Initialize router with pattern-based routing rules"""
        # Define routing rules with pattern sets
        self.routing_rules = {
            FindingType.OAUTH2_PUBLIC_CLIENT: {
                'required_terms': ['oauth'],  # Only require 'oauth' since 'client' might not always be present
                'supporting_terms': ['client', 'client_id', 'authorization', 'token', 'grant', 'pkce', 'redirect_uri', 'scope'],
                'excluded_terms': ['file', 'permission', 'filesystem', 'chmod'],
                'weight': 1.0
            },
            FindingType.FILE_PERMISSION: {
                'required_terms': [['permission', 'storage', 'access', 'readable', 'writable']],  # Any one of these terms
                'supporting_terms': ['file', 'chmod', 'read', 'write', 'plaintext', 'mode'],
                'excluded_terms': ['oauth', 'client_id'],
                'weight': 1.0
            },
            FindingType.DEV_CONFIG: {
                'required_terms': [],  # Make debug/dev optional but boost if present
                'supporting_terms': ['debug', 'dev', 'config', 'flag', 'environment', 'development', 'test', 'mode', 'enabled'],
                'excluded_terms': ['production', 'deploy'],
                'weight': 1.0,
                'min_support_terms': 2  # Require at least 2 supporting terms
            },
            FindingType.LOCKING_MECHANISM: {
                'required_terms': [['lock', 'race', 'mutex', 'deadlock', 'concurrent']],  # Any one of these terms
                'supporting_terms': ['synchron', 'thread', 'semaphore', 'condition'],
                'excluded_terms': ['unlock', 'key'],
                'weight': 1.0
            },
            FindingType.HARDCODED_SECRET: {
                'required_terms': ['secret', 'password'],
                'supporting_terms': ['hardcoded', 'embedded', 'credential', 'api_key', 'token'],
                'excluded_terms': ['client_id', 'public'],
                'weight': 1.0
            },
        }

    def route_with_confidence(self, finding: dict) -> RoutingDecision:
        """
        Calculate routing confidence for each analyzer
        Returns the best match with confidence score

        Args:
            finding: Security finding dictionary

        Returns:
            RoutingDecision with best analyzer and confidence
        """
        category = finding.get("category", "").lower()
        message = finding.get("message", "").lower()
        rule_id = finding.get("rule_id", "").lower()
        combined_text = f"{category} {message} {rule_id}"

        scores = {}
        for finding_type, rules in self.routing_rules.items():
            confidence = self._calculate_routing_confidence(
                combined_text, rules
            )
            if confidence > 0.3:
                scores[finding_type] = confidence

        if not scores:
            return RoutingDecision(
                finding_type=FindingType.UNKNOWN,
                confidence=0.0,
                analyzer_method=None,
                reasoning="No matching analyzer found",
                fallback_analyzers=[]
            )

        # Get best match
        best_type = max(scores, key=scores.get)
        best_confidence = scores[best_type]

        # Get fallbacks (sorted by confidence, exclude best match)
        fallbacks = [
            (self._get_analyzer_method(ft), conf)
            for ft, conf in sorted(scores.items(), key=lambda x: x[1], reverse=True)[1:3]
        ]

        reasoning = self._generate_reasoning(best_type, best_confidence, combined_text)

        return RoutingDecision(
            finding_type=best_type,
            confidence=best_confidence,
            analyzer_method=self._get_analyzer_method(best_type),
            reasoning=reasoning,
            fallback_analyzers=fallbacks
        )

    def _calculate_routing_confidence(self, text: str, rules: dict) -> float:
        """
        Calculate confidence score for routing decision

        Args:
            text: Combined text from finding (category + message + rule_id)
            rules: Routing rule dictionary

        Returns:
            Confidence score (0.0-1.0)
        """
        confidence = 0.0

        # Check required terms
        required_terms = rules.get('required_terms', [])
        if required_terms:
            # Check if required_terms is a list of alternatives (list of lists)
            # Format: [['term1', 'term2', 'term3']] means ANY one of these terms
            if required_terms and isinstance(required_terms[0], list):
                # Alternative terms: at least one term from the inner list must match
                alternatives = required_terms[0]
                has_match = any(term in text for term in alternatives)
                if not has_match:
                    return 0.0  # Hard requirement not met
                confidence += 0.5
            else:
                # Traditional format: all terms must be present
                required_matches = sum(1 for term in required_terms if term in text)
                if required_matches < len(required_terms):
                    return 0.0  # Hard requirement not met
                confidence += 0.5
        else:
            # No required terms, start with a base confidence
            confidence = 0.2

        # Check supporting terms (boost confidence)
        supporting_terms = rules.get('supporting_terms', [])
        if supporting_terms:
            support_matches = sum(1 for term in supporting_terms if term in text)

            # Check minimum support terms requirement
            min_support_terms = rules.get('min_support_terms', 0)
            if min_support_terms > 0 and support_matches < min_support_terms:
                return 0.0  # Minimum support requirement not met

            support_score = min(support_matches / len(supporting_terms), 1.0) * 0.5
            confidence += support_score

        # Check excluded terms (reduce confidence)
        excluded_terms = rules.get('excluded_terms', [])
        if excluded_terms:
            exclusion_hits = sum(1 for term in excluded_terms if term in text)
            if exclusion_hits > 0:
                confidence *= 0.3  # Severe penalty

        # Apply rule weight
        weight = rules.get('weight', 1.0)
        confidence *= weight

        return min(confidence, 1.0)

    def _get_analyzer_method(self, finding_type: FindingType) -> Optional[str]:
        """
        Map finding type to analyzer method name

        Args:
            finding_type: FindingType enum value

        Returns:
            Analyzer method name or None
        """
        mapping = {
            FindingType.OAUTH2_PUBLIC_CLIENT: "analyze_oauth2_public_client",
            FindingType.FILE_PERMISSION: "analyze_file_permissions",
            FindingType.DEV_CONFIG: "analyze_dev_config_flag",
            FindingType.LOCKING_MECHANISM: "analyze_locking_mechanism",
            FindingType.HARDCODED_SECRET: None,  # No dedicated analyzer yet
            FindingType.UNKNOWN: None,
        }
        return mapping.get(finding_type)

    def _generate_reasoning(self, finding_type: FindingType, confidence: float, text: str) -> str:
        """
        Generate human-readable reasoning for routing decision

        Args:
            finding_type: Selected finding type
            confidence: Confidence score
            text: Combined finding text

        Returns:
            Reasoning string
        """
        type_descriptions = {
            FindingType.OAUTH2_PUBLIC_CLIENT: "OAuth2 public client pattern (SPAs, mobile apps)",
            FindingType.FILE_PERMISSION: "File permission/access control issue",
            FindingType.DEV_CONFIG: "Development-only configuration",
            FindingType.LOCKING_MECHANISM: "Concurrency/locking mechanism",
            FindingType.HARDCODED_SECRET: "Hardcoded secret/credential",
            FindingType.UNKNOWN: "No specific pattern matched",
        }

        description = type_descriptions.get(finding_type, "Unknown")
        return f"Matched {description} with {confidence:.2f} confidence"

    def explain_routing(self, finding: dict) -> dict:
        """
        Provide detailed explanation of routing decision (for debugging)

        Args:
            finding: Security finding dictionary

        Returns:
            Dictionary with routing explanation
        """
        category = finding.get("category", "").lower()
        message = finding.get("message", "").lower()
        rule_id = finding.get("rule_id", "").lower()
        combined_text = f"{category} {message} {rule_id}"

        all_scores = {}
        for finding_type, rules in self.routing_rules.items():
            confidence = self._calculate_routing_confidence(combined_text, rules)

            # Calculate detailed breakdown
            required_terms = rules.get('required_terms', [])
            if required_terms and isinstance(required_terms[0], list):
                # Alternative terms format - flatten and check
                required = [term for term in required_terms[0] if term in combined_text]
            else:
                # Traditional format
                required = [term for term in required_terms if term in combined_text]

            supporting = [term for term in rules.get('supporting_terms', []) if term in combined_text]
            excluded = [term for term in rules.get('excluded_terms', []) if term in combined_text]

            all_scores[finding_type.value] = {
                'confidence': confidence,
                'required_matched': required,
                'supporting_matched': supporting,
                'excluded_matched': excluded,
            }

        decision = self.route_with_confidence(finding)

        return {
            'selected_type': decision.finding_type.value,
            'selected_confidence': decision.confidence,
            'selected_method': decision.analyzer_method,
            'reasoning': decision.reasoning,
            'fallbacks': decision.fallback_analyzers,
            'all_scores': all_scores,
        }
