#!/usr/bin/env python3
"""
Consensus Builder Module

Build consensus across multiple agent opinions with AST-based deduplication.
Aggregates findings from multiple agents, deduplicates similar issues,
and calculates confidence scores based on agreement between agents.

Extracted from run_ai_audit.py for better maintainability.
"""

import logging

from ast_deduplicator import ASTDeduplicator

__all__ = ["ConsensusBuilder"]

logger = logging.getLogger(__name__)


class ConsensusBuilder:
    """Build consensus across multiple agent opinions

    Feature: Consensus Building (from real_multi_agent_review.py)
    This class aggregates findings from multiple agents, deduplicates similar issues,
    and calculates confidence scores based on agreement between agents.

    Enhanced with AST-based deduplication for more accurate grouping:
    - Uses function/class boundaries instead of line buckets
    - Eliminates false duplicates from long functions
    - Maintains backward compatibility with non-parseable files
    """

    def __init__(self, agents: list):
        """Initialize consensus builder

        Args:
            agents: List of agent names that will provide findings
        """
        self.agents = agents
        self.total_agents = len(agents)

        # Initialize AST deduplicator
        self.deduplicator = ASTDeduplicator()
        logger.info("ConsensusBuilder: Using AST-based deduplication for enhanced accuracy")

    def aggregate_findings(self, agent_findings: dict) -> list:
        """Aggregate findings from multiple agents with enhanced AST-based consensus scoring

        This method now uses AST-based deduplication instead of coarse line buckets:
        - OLD: Lines 15 and 45 in same function created separate groups (L10, L40)
        - NEW: Lines 15 and 45 grouped together if in same function

        Args:
            agent_findings: Dictionary mapping agent names to their finding lists

        Returns:
            List of consensus findings with agreement scores
        """
        # Group similar findings by AST-aware key (function/class boundaries)
        grouped = {}

        for agent_name, findings in agent_findings.items():
            for finding in findings:
                # Create enhanced deduplication key using AST context
                # AST-based: Use function/class boundaries
                key = self.deduplicator.create_dedup_key(finding)

                if key not in grouped:
                    grouped[key] = {"agents": [], "findings": [], "votes": 0}

                grouped[key]["agents"].append(agent_name)
                grouped[key]["findings"].append(finding)
                grouped[key]["votes"] += 1

        # Build consensus results
        consensus_findings = []

        for _key, group in grouped.items():
            votes = group["votes"]
            findings = group["findings"]
            agents_agree = group["agents"]

            # Calculate consensus level
            consensus_pct = votes / self.total_agents

            if consensus_pct == 1.0:
                consensus_level = "unanimous"
                confidence = 0.95
            elif consensus_pct >= 0.67:
                consensus_level = "strong"
                confidence = 0.85
            elif consensus_pct >= 0.5:
                consensus_level = "majority"
                confidence = 0.70
            else:
                consensus_level = "weak"
                confidence = 0.50

            # Take the most severe classification
            severity_order = ["critical", "high", "medium", "low", "info"]
            severities = [f.get("severity", "medium") for f in findings]
            most_severe = min(severities, key=lambda s: severity_order.index(s) if s in severity_order else 999)

            # Merge descriptions and recommendations
            descriptions = [f.get("message", "") for f in findings]

            # Create consensus finding
            consensus_finding = findings[0].copy()  # Start with first finding
            consensus_finding["consensus"] = {
                "votes": votes,
                "total_agents": self.total_agents,
                "consensus_level": consensus_level,
                "confidence": confidence,
                "agents_agree": agents_agree,
                "all_descriptions": descriptions,
            }
            consensus_finding["severity"] = most_severe

            # Enhance message with consensus info
            if votes > 1:
                consensus_finding["message"] = f"[{votes}/{self.total_agents} agents agree] {descriptions[0]}"

            consensus_findings.append(consensus_finding)

        # Sort by votes (descending) and confidence (descending)
        consensus_findings.sort(key=lambda x: (x["consensus"]["votes"], x["consensus"]["confidence"]), reverse=True)

        return consensus_findings

    def filter_by_threshold(self, consensus_findings: list, min_confidence: float = 0.5) -> list:
        """Filter findings by minimum confidence threshold

        Args:
            consensus_findings: List of consensus findings
            min_confidence: Minimum confidence score to include (0.0-1.0)

        Returns:
            Filtered list of findings meeting threshold
        """
        return [f for f in consensus_findings if f.get("consensus", {}).get("confidence", 0) >= min_confidence]
