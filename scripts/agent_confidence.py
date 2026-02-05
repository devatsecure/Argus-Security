#!/usr/bin/env python3
"""
Agent Confidence Weighting Module

Weights multi-agent consensus by each agent's historical accuracy per finding
category.  For example, SecretHunter's opinion on SECRETS findings carries
more weight than ThreatModeler's, while ThreatModeler is trusted more on IAC.

Classes:
    AgentAccuracyTracker  -- Maintains (agent, category) -> weight matrix
    WeightedConsensusBuilder -- Drop-in replacement for ConsensusBuilder
    AgentConfidenceStage  -- Pipeline stage (Phase 3.5)

The module works standalone without a feedback database; expert-prior weights
are used when no historical data is available.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Ensure the scripts directory is importable so sibling modules resolve.
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from pipeline.base_stage import BaseStage
from pipeline.protocol import PipelineContext

__all__ = [
    "AgentAccuracyTracker",
    "WeightedConsensusBuilder",
    "AgentConfidenceStage",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The five canonical agent personas.
AGENT_NAMES: List[str] = [
    "SecretHunter",
    "ArchitectureReviewer",
    "ExploitAssessor",
    "FalsePositiveFilter",
    "ThreatModeler",
]

# Known finding categories.
CATEGORIES: List[str] = ["SAST", "SECRETS", "DEPS", "IAC", "DAST"]

# Bayesian smoothing parameters.
SMOOTHING_PRIOR: float = 0.5  # uniform prior accuracy
SMOOTHING_N: int = 10  # pseudo-observations

# Weight clamp range.
WEIGHT_MIN: float = 0.1
WEIGHT_MAX: float = 2.0


# ---------------------------------------------------------------------------
# AgentAccuracyTracker
# ---------------------------------------------------------------------------


class AgentAccuracyTracker:
    """Track and compute per-agent accuracy by finding category.

    Maintains a matrix of ``(agent_name, category) -> accuracy_score``
    based on historical feedback data.
    """

    def __init__(self, feedback_db_path: Optional[str] = None) -> None:
        """
        Args:
            feedback_db_path: Path to feedback SQLite DB.
                If ``None``, uses in-memory expert-prior defaults only.
        """
        self._feedback_db_path = feedback_db_path
        self._weights: Dict[str, Dict[str, float]] = {}

        # Try to compute weights from feedback; fall back to defaults.
        if feedback_db_path and Path(feedback_db_path).exists():
            try:
                computed = self._compute_weights_from_feedback()
                if computed:
                    self._weights = computed
                    logger.info(
                        "Loaded agent weights from feedback DB: %s",
                        feedback_db_path,
                    )
                else:
                    self._weights = self._load_default_weights()
                    logger.info(
                        "No feedback data in DB; using expert-prior defaults"
                    )
            except Exception as exc:
                logger.warning(
                    "Failed to compute weights from feedback DB (%s); "
                    "falling back to defaults",
                    exc,
                )
                self._weights = self._load_default_weights()
        else:
            self._weights = self._load_default_weights()
            if feedback_db_path:
                logger.info(
                    "Feedback DB not found at %s; using expert-prior defaults",
                    feedback_db_path,
                )
            else:
                logger.info(
                    "No feedback DB configured; using expert-prior defaults"
                )

    # -- Public API ---------------------------------------------------------

    def get_agent_weight(self, agent_name: str, category: str) -> float:
        """Get the weight for an agent in a specific finding category.

        Returns a float between 0.1 and 2.0 where:
        - 1.0 = average / no data
        - >1.0 = above average accuracy (agent's opinion counts more)
        - <1.0 = below average accuracy (agent's opinion counts less)

        Category is one of: SAST, SECRETS, DEPS, IAC, DAST, etc.
        """
        category_upper = category.upper() if category else "SAST"
        agent_weights = self._weights.get(agent_name, {})
        weight = agent_weights.get(category_upper, 1.0)
        return max(WEIGHT_MIN, min(WEIGHT_MAX, weight))

    def get_weight_matrix(self) -> Dict[str, Dict[str, float]]:
        """Return the full weight matrix: ``{agent_name: {category: weight}}``."""
        return {
            agent: dict(cats) for agent, cats in self._weights.items()
        }

    def record_outcome(
        self,
        agent_name: str,
        category: str,
        agent_verdict: str,
        actual_verdict: str,
    ) -> None:
        """Record an agent's verdict vs actual outcome for learning.

        Args:
            agent_name: Name of the agent (e.g., ``"SecretHunter"``).
            category: Finding category (e.g., ``"SECRETS"``).
            agent_verdict: What the agent said (e.g., ``"confirmed"``,
                ``"false_positive"``).
            actual_verdict: What actually happened (e.g., ``"true_positive"``,
                ``"false_positive"``).

        If no feedback DB path was configured, the outcome is discarded with
        a warning.
        """
        if not self._feedback_db_path:
            logger.debug(
                "No feedback DB configured; discarding outcome for %s/%s",
                agent_name,
                category,
            )
            return

        try:
            db_path = Path(self._feedback_db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)

            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Ensure the agent_outcomes table exists.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_outcomes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    agent_verdict TEXT NOT NULL,
                    actual_verdict TEXT NOT NULL,
                    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_outcomes_agent_cat
                ON agent_outcomes(agent_name, category)
            """)

            cursor.execute(
                """
                INSERT INTO agent_outcomes
                    (agent_name, category, agent_verdict, actual_verdict)
                VALUES (?, ?, ?, ?)
                """,
                (agent_name, category.upper(), agent_verdict, actual_verdict),
            )

            conn.commit()
            conn.close()

            # Recompute weights after recording.
            try:
                computed = self._compute_weights_from_feedback()
                if computed:
                    self._weights = computed
            except Exception:
                pass  # Keep existing weights on recompute failure.

            logger.debug(
                "Recorded outcome: %s/%s agent=%s actual=%s",
                agent_name,
                category,
                agent_verdict,
                actual_verdict,
            )

        except Exception as exc:
            logger.warning("Failed to record agent outcome: %s", exc)

    # -- Weight computation -------------------------------------------------

    def _compute_weights_from_feedback(self) -> Dict[str, Dict[str, float]]:
        """Compute weights from feedback database.

        Algorithm:
        1. For each ``(agent, category)`` pair, count:
           - correct: agent said TP and it was TP, or agent said FP and it was FP
           - incorrect: agent said TP but was FP, or agent said FP but was TP
        2. ``accuracy = correct / (correct + incorrect)``
        3. ``weight = 0.5 + accuracy`` (range: 0.5 to 1.5)
        4. Apply Bayesian smoothing: use uniform prior with N=10
           pseudo-observations.

        Returns an empty dict if the DB does not contain the
        ``agent_outcomes`` table or has no data.
        """
        if not self._feedback_db_path:
            return {}

        db_path = Path(self._feedback_db_path)
        if not db_path.exists():
            return {}

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Check if agent_outcomes table exists.
        cursor.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='agent_outcomes'"
        )
        if not cursor.fetchone():
            conn.close()
            return {}

        cursor.execute(
            "SELECT agent_name, category, agent_verdict, actual_verdict "
            "FROM agent_outcomes"
        )
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            return {}

        # Accumulate counts per (agent, category).
        counts: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: {"correct": 0, "incorrect": 0})
        )

        for agent_name, category, agent_verdict, actual_verdict in rows:
            agent_said_tp = agent_verdict.lower() in (
                "confirmed",
                "true_positive",
                "tp",
            )
            agent_said_fp = agent_verdict.lower() in (
                "false_positive",
                "fp",
                "noise",
            )
            was_tp = actual_verdict.lower() in ("true_positive", "tp")
            was_fp = actual_verdict.lower() in (
                "false_positive",
                "fp",
                "wont_fix",
                "duplicate",
            )

            if (agent_said_tp and was_tp) or (agent_said_fp and was_fp):
                counts[agent_name][category]["correct"] += 1
            elif (agent_said_tp and was_fp) or (agent_said_fp and was_tp):
                counts[agent_name][category]["incorrect"] += 1
            # else: ambiguous verdicts are ignored.

        # Start from defaults, then overlay computed weights.
        weights = self._load_default_weights()

        for agent_name, cat_counts in counts.items():
            if agent_name not in weights:
                weights[agent_name] = {}
            for category, tallies in cat_counts.items():
                correct = tallies["correct"]
                incorrect = tallies["incorrect"]
                total = correct + incorrect

                if total == 0:
                    continue

                # Bayesian smoothing:
                # smoothed_accuracy = (correct + prior * N) / (total + N)
                smoothed_accuracy = (correct + SMOOTHING_PRIOR * SMOOTHING_N) / (
                    total + SMOOTHING_N
                )

                # Map accuracy to weight: weight = 0.5 + smoothed_accuracy
                weight = 0.5 + smoothed_accuracy

                # Clamp to [WEIGHT_MIN, WEIGHT_MAX].
                weight = max(WEIGHT_MIN, min(WEIGHT_MAX, weight))

                weights[agent_name][category] = weight

        return weights

    def _load_default_weights(self) -> Dict[str, Dict[str, float]]:
        """Expert-prior weights when no feedback data exists.

        These encode domain knowledge about each agent persona's
        strengths and weaknesses across finding categories.
        """
        return {
            "SecretHunter": {
                "SECRETS": 1.8,
                "SAST": 0.8,
                "DEPS": 0.5,
                "IAC": 0.5,
                "DAST": 0.6,
            },
            "ArchitectureReviewer": {
                "SAST": 1.5,
                "IAC": 1.3,
                "DEPS": 1.0,
                "SECRETS": 0.7,
                "DAST": 0.9,
            },
            "ExploitAssessor": {
                "SAST": 1.6,
                "DAST": 1.5,
                "DEPS": 1.2,
                "SECRETS": 0.8,
                "IAC": 0.7,
            },
            "FalsePositiveFilter": {
                "SAST": 1.4,
                "SECRETS": 1.3,
                "DEPS": 1.2,
                "IAC": 1.2,
                "DAST": 1.2,
            },
            "ThreatModeler": {
                "IAC": 1.5,
                "SAST": 1.2,
                "DEPS": 0.9,
                "SECRETS": 0.6,
                "DAST": 1.1,
            },
        }


# ---------------------------------------------------------------------------
# WeightedConsensusBuilder
# ---------------------------------------------------------------------------


class WeightedConsensusBuilder:
    """Build consensus with per-agent, per-category weights.

    Drop-in replacement for ``ConsensusBuilder`` that uses agent weights
    instead of raw vote counts.
    """

    def __init__(
        self,
        agents: List[str],
        tracker: Optional[AgentAccuracyTracker] = None,
    ) -> None:
        """
        Args:
            agents: List of agent names.
            tracker: ``AgentAccuracyTracker`` instance.  A default one (with
                expert-prior weights) is created if ``None``.
        """
        self.agents = agents
        self.total_agents = len(agents)
        self.tracker = tracker or AgentAccuracyTracker()

    def aggregate_findings(
        self, agent_findings: Dict[str, List[Any]]
    ) -> List[Dict[str, Any]]:
        """Aggregate findings using weighted consensus.

        Instead of::

            consensus_pct = votes / total_agents

        Uses::

            weighted_score = sum(agent_weights) / sum(all_possible_weights)

        Steps:
        1. Group findings by dedup key (same logic as ``ConsensusBuilder``).
        2. For each group, compute weighted score using category-specific
           agent weights.
        3. Map weighted score to consensus level and confidence.
        4. Apply severity via same logic as the original.

        Args:
            agent_findings: Mapping of agent name to their finding lists.

        Returns:
            List of consensus findings with weighted agreement scores.
        """
        # Step 1: Group similar findings.
        grouped: Dict[str, Dict[str, Any]] = {}

        for agent_name, findings in agent_findings.items():
            for finding in findings:
                key = self._create_dedup_key(finding)

                if key not in grouped:
                    grouped[key] = {
                        "agents": [],
                        "findings": [],
                        "votes": 0,
                    }

                grouped[key]["agents"].append(agent_name)
                grouped[key]["findings"].append(finding)
                grouped[key]["votes"] += 1

        # Step 2-4: Build consensus results.
        consensus_findings: List[Dict[str, Any]] = []

        for _key, group in grouped.items():
            findings = group["findings"]
            agents_agree = group["agents"]
            votes = group["votes"]

            # Determine the category from the first finding.
            category = self._extract_category(findings[0])

            # Compute weighted score.
            agreeing_weight = sum(
                self.tracker.get_agent_weight(agent, category)
                for agent in agents_agree
            )
            total_possible_weight = sum(
                self.tracker.get_agent_weight(agent, category)
                for agent in self.agents
            )

            if total_possible_weight > 0:
                weighted_score = agreeing_weight / total_possible_weight
            else:
                weighted_score = votes / self.total_agents if self.total_agents else 0

            # Map weighted score to consensus level and confidence.
            consensus_level, confidence = self._score_to_consensus(weighted_score)

            # Take the most severe classification.
            severity_order = ["critical", "high", "medium", "low", "info"]
            severities = [
                self._extract_severity(f) for f in findings
            ]
            most_severe = min(
                severities,
                key=lambda s: (
                    severity_order.index(s)
                    if s in severity_order
                    else 999
                ),
            )

            # Merge descriptions.
            descriptions = [self._extract_message(f) for f in findings]

            # Build consensus finding (start from first finding).
            consensus_finding = self._copy_finding(findings[0])
            consensus_finding["consensus"] = {
                "votes": votes,
                "total_agents": self.total_agents,
                "consensus_level": consensus_level,
                "confidence": confidence,
                "weighted_score": round(weighted_score, 4),
                "agents_agree": agents_agree,
                "all_descriptions": descriptions,
            }
            consensus_finding["severity"] = most_severe

            # Enhance message with consensus info.
            if votes > 1:
                consensus_finding["message"] = (
                    f"[{votes}/{self.total_agents} agents agree, "
                    f"weight={weighted_score:.2f}] {descriptions[0]}"
                )

            consensus_findings.append(consensus_finding)

        # Sort by weighted score (descending), then confidence (descending).
        consensus_findings.sort(
            key=lambda x: (
                x.get("consensus", {}).get("weighted_score", 0),
                x.get("consensus", {}).get("confidence", 0),
            ),
            reverse=True,
        )

        return consensus_findings

    def filter_by_threshold(
        self,
        findings: List[Dict[str, Any]],
        min_confidence: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """Filter findings by minimum confidence threshold.

        Args:
            findings: List of consensus findings.
            min_confidence: Minimum confidence score to include (0.0-1.0).

        Returns:
            Filtered list of findings meeting threshold.
        """
        return [
            f
            for f in findings
            if f.get("consensus", {}).get("confidence", 0) >= min_confidence
        ]

    # -- Internal helpers ---------------------------------------------------

    @staticmethod
    def _score_to_consensus(weighted_score: float) -> tuple:
        """Map a weighted score to consensus level and confidence.

        Returns:
            Tuple of ``(consensus_level, confidence)``.
        """
        if weighted_score >= 0.85:
            return ("unanimous", 0.95)
        elif weighted_score >= 0.65:
            return ("strong", 0.85)
        elif weighted_score >= 0.45:
            return ("majority", 0.70)
        else:
            return ("weak", 0.50)

    @staticmethod
    def _create_dedup_key(finding: Any) -> str:
        """Create a deduplication key for a finding.

        Mirrors the grouping logic in ``ConsensusBuilder``, using
        file path + rule/check ID + approximate line number.
        """
        if isinstance(finding, dict):
            file_path = finding.get("file_path", finding.get("path", "unknown"))
            rule_id = finding.get(
                "rule_id",
                finding.get("check_id", finding.get("id", "unknown")),
            )
            line = finding.get("line", finding.get("line_number", 0))
        else:
            file_path = getattr(
                finding,
                "file_path",
                getattr(finding, "path", "unknown"),
            )
            rule_id = getattr(
                finding,
                "rule_id",
                getattr(finding, "check_id", getattr(finding, "id", "unknown")),
            )
            line = getattr(
                finding, "line", getattr(finding, "line_number", 0)
            )

        # Bucket lines to group nearby issues.
        line_bucket = (int(line) // 10) * 10 if line else 0
        return f"{file_path}:{rule_id}:L{line_bucket}"

    @staticmethod
    def _extract_category(finding: Any) -> str:
        """Extract the finding category, defaulting to ``'SAST'``."""
        if isinstance(finding, dict):
            cat = finding.get("category", "SAST")
        else:
            cat = getattr(finding, "category", "SAST")
        return str(cat).upper() if cat else "SAST"

    @staticmethod
    def _extract_severity(finding: Any) -> str:
        """Extract severity string from a finding."""
        if isinstance(finding, dict):
            return finding.get("severity", "medium")
        return getattr(finding, "severity", "medium")

    @staticmethod
    def _extract_message(finding: Any) -> str:
        """Extract the human-readable message from a finding."""
        if isinstance(finding, dict):
            return finding.get("message", "")
        return getattr(finding, "message", "")

    @staticmethod
    def _copy_finding(finding: Any) -> Dict[str, Any]:
        """Return a dict copy of a finding."""
        if isinstance(finding, dict):
            return dict(finding)
        elif hasattr(finding, "to_dict"):
            return finding.to_dict()
        elif hasattr(finding, "__dataclass_fields__"):
            from dataclasses import asdict

            return asdict(finding)
        else:
            # Best-effort: use __dict__.
            return dict(getattr(finding, "__dict__", {}))


# ---------------------------------------------------------------------------
# Pipeline Stage helpers (finding access)
# ---------------------------------------------------------------------------


def _get_consensus(finding: Any) -> Optional[Dict[str, Any]]:
    """Retrieve the consensus sub-dict from a finding.

    Handles dict findings, attribute-based findings, and mixed types.
    """
    try:
        if isinstance(finding, dict):
            return finding.get("consensus")
        return getattr(finding, "consensus", None)
    except Exception:
        return None


def _get_category(finding: Any) -> str:
    """Retrieve the finding category, defaulting to ``'SAST'``."""
    try:
        if isinstance(finding, dict):
            cat = finding.get("category", "SAST")
        else:
            cat = getattr(finding, "category", "SAST")
        return str(cat).upper() if cat else "SAST"
    except Exception:
        return "SAST"


def _compute_weighted_score(
    consensus: Dict[str, Any],
    category: str,
    tracker: AgentAccuracyTracker,
) -> float:
    """Compute a new weighted score for existing consensus data.

    Uses the ``agents_agree`` list from the consensus dict and the
    tracker's weight matrix.
    """
    agents_agree = consensus.get("agents_agree", [])
    total_agents = consensus.get("total_agents", 5)

    if not agents_agree:
        # Fall back to raw vote ratio.
        votes = consensus.get("votes", 0)
        return votes / total_agents if total_agents else 0.0

    # Sum weights for agreeing agents.
    agreeing_weight = sum(
        tracker.get_agent_weight(agent, category) for agent in agents_agree
    )

    # Sum weights for all agents (use canonical list or total_agents).
    all_agents = AGENT_NAMES if total_agents == len(AGENT_NAMES) else [
        f"Agent{i}" for i in range(total_agents)
    ]
    # If we have the canonical list, use real weights; otherwise estimate.
    if total_agents == len(AGENT_NAMES):
        total_weight = sum(
            tracker.get_agent_weight(agent, category) for agent in AGENT_NAMES
        )
    else:
        # Approximate: use 1.0 per unknown agent.
        total_weight = agreeing_weight + (total_agents - len(agents_agree)) * 1.0

    if total_weight <= 0:
        return 0.0

    return agreeing_weight / total_weight


def _update_consensus(
    finding: Any, weighted_score: float
) -> None:
    """Update a finding's consensus dict with the new weighted score.

    Sets ``weighted_score``, ``confidence``, and ``consensus_level``.
    """
    consensus = _get_consensus(finding)
    if consensus is None:
        return

    # Map score to level and confidence.
    if weighted_score >= 0.85:
        level, confidence = "unanimous", 0.95
    elif weighted_score >= 0.65:
        level, confidence = "strong", 0.85
    elif weighted_score >= 0.45:
        level, confidence = "majority", 0.70
    else:
        level, confidence = "weak", 0.50

    consensus["weighted_score"] = round(weighted_score, 4)
    consensus["confidence"] = confidence
    consensus["consensus_level"] = level


# ---------------------------------------------------------------------------
# AgentConfidenceStage -- Pipeline Stage
# ---------------------------------------------------------------------------


class AgentConfidenceStage(BaseStage):
    """Phase 3.5: Apply weighted consensus after multi-agent review.

    Runs after multi-agent review.  Re-scores consensus results using
    agent confidence weighting so that domain experts' opinions carry
    more weight in their areas of expertise.
    """

    name = "phase3_5_agent_confidence"
    display_name = "Phase 3.5: Agent Confidence Weighting"
    phase_number = 3.5

    @property
    def required_stages(self) -> List[str]:
        return ["phase3_multi_agent_review"]

    def should_run(self, ctx: PipelineContext) -> bool:
        return (
            ctx.config.get("enable_agent_weighting", True)
            and ctx.config.get("enable_multi_agent", True)
            and len(ctx.findings) > 0
        )

    def _execute(self, ctx: PipelineContext) -> Dict[str, Any]:
        # Resolve feedback DB path from config, if any.
        feedback_db = ctx.config.get("feedback_db_path")
        if not feedback_db:
            cache_dir = ctx.config.get("cache_dir", ".argus-cache")
            candidate = Path(cache_dir) / "feedback.db"
            if candidate.exists():
                feedback_db = str(candidate)

        tracker = AgentAccuracyTracker(feedback_db_path=feedback_db)
        builder = WeightedConsensusBuilder(
            agents=list(AGENT_NAMES),
            tracker=tracker,
        )

        # Re-score existing consensus data on each finding.
        rescored = 0
        for finding in ctx.findings:
            consensus = _get_consensus(finding)
            if consensus is not None:
                category = _get_category(finding)
                new_score = _compute_weighted_score(consensus, category, tracker)
                _update_consensus(finding, new_score)
                rescored += 1

        logger.info(
            "Agent confidence weighting: rescored %d/%d findings",
            rescored,
            len(ctx.findings),
        )

        return {
            "rescored": rescored,
            "weight_matrix": tracker.get_weight_matrix(),
        }
