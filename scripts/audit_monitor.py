#!/usr/bin/env python3
"""
Audit Monitor - Historical Tracking and Analysis System
Monitors dual-audit results, detects trends, and alerts on anomalies

Features:
- SQLite database for persistent storage
- Agreement rate tracking over time
- Criteria drift detection using statistical analysis
- Alert system for threshold violations
- Dashboard-ready metrics generation
- Automatic data cleanup and aggregation

Schema:
- audit_runs: Summary of each dual-audit execution
- findings_comparison: Detailed finding-by-finding comparison
- drift_events: Detected changes in evaluation criteria
- alerts: Generated alerts for anomalies
"""

import json
import logging
import sqlite3
import statistics
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class AuditRun:
    """Summary of a dual-audit execution"""
    id: str
    timestamp: str
    repo: str
    project_type: str
    argus_findings_count: int
    codex_findings_count: int
    agreed_findings_count: int
    argus_only_count: int
    codex_only_count: int
    agreement_rate: float
    average_score_difference: float
    severity_distribution: Dict[str, int]
    metadata: Dict[str, Any]


@dataclass
class FindingComparison:
    """Detailed comparison of a single finding"""
    id: str
    audit_run_id: str
    finding_id: str
    argus_score: float
    codex_score: float
    score_difference: float
    agreed: bool
    argus_verdict: str
    codex_verdict: str
    severity: str
    category: str
    metadata: Dict[str, Any]


@dataclass
class DriftEvent:
    """Detected change in evaluation criteria"""
    id: str
    timestamp: str
    audit_run_id: str
    metric_name: str
    metric_type: str  # severity_weighting, category_emphasis, threshold_change
    old_value: float
    new_value: float
    change_magnitude: float
    statistical_significance: float
    confidence: float
    description: str


@dataclass
class Alert:
    """Alert for anomalies or threshold violations"""
    id: str
    timestamp: str
    audit_run_id: str
    alert_type: str  # agreement_drop, drift_detected, outlier_finding, quality_degradation
    severity: str  # info, warning, critical
    message: str
    metric_name: str
    metric_value: float
    threshold: float
    metadata: Dict[str, Any]


class AuditMonitor:
    """
    Comprehensive monitoring system for dual-audit results
    Manages SQLite database, drift detection, and alerting
    """

    def __init__(
        self,
        db_path: str = ".argus/audit_monitor.db",
        agreement_threshold: float = 0.75,
        drift_sensitivity: float = 0.15,
        enable_cleanup: bool = True
    ):
        """
        Initialize audit monitor

        Args:
            db_path: Path to SQLite database
            agreement_threshold: Minimum acceptable agreement rate (0-1)
            drift_sensitivity: Sensitivity for drift detection (0-1, lower = more sensitive)
            enable_cleanup: Enable automatic cleanup of old records
        """
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.agreement_threshold = agreement_threshold
        self.drift_sensitivity = drift_sensitivity
        self.enable_cleanup = enable_cleanup

        # Initialize database
        self._initialize_db()

        logger.info(f"Audit monitor initialized with database: {self.db_path}")

    def _initialize_db(self) -> None:
        """Create database tables if they don't exist"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # audit_runs table: Summary of each dual-audit execution
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_runs (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                repo TEXT NOT NULL,
                project_type TEXT,
                argus_findings_count INTEGER,
                codex_findings_count INTEGER,
                agreed_findings_count INTEGER,
                argus_only_count INTEGER,
                codex_only_count INTEGER,
                agreement_rate REAL NOT NULL,
                average_score_difference REAL,
                severity_distribution TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(repo, timestamp)
            )
            """
        )

        # findings_comparison table: Detailed finding-by-finding comparison
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings_comparison (
                id TEXT PRIMARY KEY,
                audit_run_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                argus_score REAL NOT NULL,
                codex_score REAL NOT NULL,
                score_difference REAL NOT NULL,
                agreed INTEGER NOT NULL,
                argus_verdict TEXT,
                codex_verdict TEXT,
                severity TEXT,
                category TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id),
                UNIQUE(audit_run_id, finding_id)
            )
            """
        )

        # drift_events table: Detected changes in evaluation criteria
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS drift_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                audit_run_id TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                old_value REAL,
                new_value REAL,
                change_magnitude REAL NOT NULL,
                statistical_significance REAL NOT NULL,
                confidence REAL NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
            )
            """
        )

        # alerts table: Generated alerts for anomalies
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                audit_run_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                metric_name TEXT,
                metric_value REAL,
                threshold REAL,
                metadata TEXT,
                acknowledged INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
            )
            """
        )

        # Indexes for performance
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_runs_timestamp ON audit_runs(timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_runs_repo ON audit_runs(repo)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_comparison_audit ON findings_comparison(audit_run_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_drift_events_audit ON drift_events(audit_run_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)"
        )

        conn.commit()
        conn.close()

    def store_audit_run(
        self,
        audit_run: AuditRun,
        findings_comparisons: List[FindingComparison]
    ) -> Tuple[bool, Optional[str]]:
        """
        Store audit run and detailed findings comparison

        Args:
            audit_run: Summary of audit execution
            findings_comparisons: List of individual finding comparisons

        Returns:
            Tuple of (success, error_message)
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Store audit run
            cursor.execute(
                """
                INSERT INTO audit_runs (
                    id, timestamp, repo, project_type,
                    argus_findings_count, codex_findings_count, agreed_findings_count,
                    argus_only_count, codex_only_count, agreement_rate,
                    average_score_difference, severity_distribution, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_run.id,
                    audit_run.timestamp,
                    audit_run.repo,
                    audit_run.project_type,
                    audit_run.argus_findings_count,
                    audit_run.codex_findings_count,
                    audit_run.agreed_findings_count,
                    audit_run.argus_only_count,
                    audit_run.codex_only_count,
                    audit_run.agreement_rate,
                    audit_run.average_score_difference,
                    json.dumps(audit_run.severity_distribution),
                    json.dumps(audit_run.metadata)
                )
            )

            # Store findings comparisons
            for finding in findings_comparisons:
                cursor.execute(
                    """
                    INSERT INTO findings_comparison (
                        id, audit_run_id, finding_id, argus_score, codex_score,
                        score_difference, agreed, argus_verdict, codex_verdict,
                        severity, category, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.id,
                        finding.audit_run_id,
                        finding.finding_id,
                        finding.argus_score,
                        finding.codex_score,
                        finding.score_difference,
                        1 if finding.agreed else 0,
                        finding.argus_verdict,
                        finding.codex_verdict,
                        finding.severity,
                        finding.category,
                        json.dumps(finding.metadata)
                    )
                )

            conn.commit()
            conn.close()

            logger.info(
                f"Stored audit run {audit_run.id} with "
                f"{len(findings_comparisons)} findings comparisons"
            )

            # Perform analysis
            self._analyze_audit_run(audit_run.id)

            return True, None

        except sqlite3.IntegrityError as e:
            logger.warning(f"Audit run already exists: {e}")
            return False, f"Duplicate audit run: {str(e)}"
        except Exception as e:
            logger.error(f"Failed to store audit run: {e}")
            return False, str(e)

    def _analyze_audit_run(self, audit_run_id: str) -> None:
        """
        Analyze new audit run for trends and anomalies

        1. Detect criteria drift
        2. Generate alerts for threshold violations
        3. Calculate trend metrics
        """
        try:
            # Detect drift
            drift_events = self._detect_criteria_drift(audit_run_id)
            if drift_events:
                self._store_drift_events(drift_events)

            # Check agreement threshold
            audit_run = self.get_audit_run(audit_run_id)
            if audit_run and audit_run.agreement_rate < self.agreement_threshold:
                self._generate_agreement_alert(audit_run)

            # Check for outlier findings
            outliers = self._detect_outlier_findings(audit_run_id)
            if outliers:
                self._generate_outlier_alerts(audit_run_id, outliers)

            logger.info(f"Completed analysis for audit run {audit_run_id}")

        except Exception as e:
            logger.error(f"Error analyzing audit run: {e}")

    def _detect_criteria_drift(self, audit_run_id: str) -> List[DriftEvent]:
        """
        Detect changes in evaluation criteria using statistical analysis

        Algorithms:
        1. Category emphasis drift: Compare category distributions over time
        2. Severity weighting drift: Compare severity-agreement correlation
        3. Score distribution drift: Kolmogorov-Smirnov test on score distributions

        Returns:
            List of detected drift events
        """
        drift_events: List[DriftEvent] = []

        try:
            # Get historical audit runs (last 30 days)
            history = self.get_audit_history(days=30, limit=50)

            if len(history) < 2:
                return drift_events

            current_run = self.get_audit_run(audit_run_id)
            if not current_run:
                return drift_events

            # 1. Category Distribution Drift
            categories_current = self._get_category_distribution(audit_run_id)
            categories_historical = self._get_category_distribution_aggregate(
                [r.id for r in history[:-1]]
            )

            for category, current_pct in categories_current.items():
                historical_pct = categories_historical.get(category, 0.0)
                diff = abs(current_pct - historical_pct)

                if diff > self.drift_sensitivity:
                    drift_events.append(
                        DriftEvent(
                            id=self._generate_id("drift"),
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            audit_run_id=audit_run_id,
                            metric_name=f"category_emphasis_{category}",
                            metric_type="category_emphasis",
                            old_value=historical_pct,
                            new_value=current_pct,
                            change_magnitude=diff,
                            statistical_significance=self._calculate_significance(
                                history, category
                            ),
                            confidence=1.0 - (diff / 1.0),
                            description=(
                                f"Category '{category}' distribution shifted from "
                                f"{historical_pct:.1%} to {current_pct:.1%}"
                            )
                        )
                    )

            # 2. Severity Weighting Drift
            severity_agreement_current = self._get_severity_agreement_correlation(
                audit_run_id
            )
            severity_agreement_historical = self._get_severity_agreement_correlation_aggregate(
                [r.id for r in history[:-1]]
            )

            for severity, corr_current in severity_agreement_current.items():
                corr_historical = severity_agreement_historical.get(severity, 0.5)
                diff = abs(corr_current - corr_historical)

                if diff > self.drift_sensitivity:
                    drift_events.append(
                        DriftEvent(
                            id=self._generate_id("drift"),
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            audit_run_id=audit_run_id,
                            metric_name=f"severity_weighting_{severity}",
                            metric_type="severity_weighting",
                            old_value=corr_historical,
                            new_value=corr_current,
                            change_magnitude=diff,
                            statistical_significance=min(1.0, diff * 2.0),
                            confidence=1.0 - (diff / 1.0),
                            description=(
                                f"Agreement rate for '{severity}' severity shifted from "
                                f"{corr_historical:.1%} to {corr_current:.1%}"
                            )
                        )
                    )

            # 3. Score Distribution Drift (Kolmogorov-Smirnov-inspired)
            score_diff_current = self._get_score_differences(audit_run_id)
            score_diff_historical = self._get_score_differences_aggregate(
                [r.id for r in history[:-1]]
            )

            if score_diff_current and score_diff_historical:
                mean_current = statistics.mean(score_diff_current)
                mean_historical = statistics.mean(score_diff_historical)
                diff = abs(mean_current - mean_historical)

                if diff > self.drift_sensitivity:
                    drift_events.append(
                        DriftEvent(
                            id=self._generate_id("drift"),
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            audit_run_id=audit_run_id,
                            metric_name="score_distribution",
                            metric_type="threshold_change",
                            old_value=mean_historical,
                            new_value=mean_current,
                            change_magnitude=diff,
                            statistical_significance=self._ks_statistic(
                                score_diff_current, score_diff_historical
                            ),
                            confidence=1.0 - min(1.0, diff / 2.0),
                            description=(
                                f"Average score difference shifted from "
                                f"{mean_historical:.3f} to {mean_current:.3f}"
                            )
                        )
                    )

            return drift_events

        except Exception as e:
            logger.error(f"Error detecting criteria drift: {e}")
            return drift_events

    def _detect_outlier_findings(self, audit_run_id: str) -> List[Dict[str, Any]]:
        """
        Detect findings that are statistical outliers

        Uses IQR (Interquartile Range) method:
        - Outlier if score_difference > Q3 + 1.5*IQR or < Q1 - 1.5*IQR

        Returns:
            List of outlier findings
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            # Get all score differences
            cursor.execute(
                "SELECT score_difference FROM findings_comparison WHERE audit_run_id = ?",
                (audit_run_id,)
            )
            score_diffs = [row[0] for row in cursor.fetchall()]

            if len(score_diffs) < 4:
                return []

            # Calculate quartiles
            sorted_diffs = sorted(score_diffs)
            q1_idx = len(sorted_diffs) // 4
            q3_idx = (3 * len(sorted_diffs)) // 4

            q1 = sorted_diffs[q1_idx]
            q3 = sorted_diffs[q3_idx]
            iqr = q3 - q1

            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr

            # Find outliers
            cursor.execute(
                """
                SELECT id, finding_id, argus_score, codex_score, score_difference,
                       severity, category FROM findings_comparison
                WHERE audit_run_id = ? AND (score_difference > ? OR score_difference < ?)
                """,
                (audit_run_id, upper_bound, lower_bound)
            )

            outliers = [
                {
                    "id": row[0],
                    "finding_id": row[1],
                    "argus_score": row[2],
                    "codex_score": row[3],
                    "score_difference": row[4],
                    "severity": row[5],
                    "category": row[6],
                    "bound_exceeded": "upper" if row[4] > upper_bound else "lower"
                }
                for row in cursor.fetchall()
            ]

            conn.close()
            return outliers

        except Exception as e:
            logger.error(f"Error detecting outliers: {e}")
            return []

    def _generate_agreement_alert(self, audit_run: AuditRun) -> None:
        """Generate alert when agreement drops below threshold"""
        try:
            alert = Alert(
                id=self._generate_id("alert"),
                timestamp=datetime.now(timezone.utc).isoformat(),
                audit_run_id=audit_run.id,
                alert_type="agreement_drop",
                severity="warning",
                message=(
                    f"Agreement rate ({audit_run.agreement_rate:.1%}) is below "
                    f"threshold ({self.agreement_threshold:.1%})"
                ),
                metric_name="agreement_rate",
                metric_value=audit_run.agreement_rate,
                threshold=self.agreement_threshold,
                metadata={
                    "repo": audit_run.repo,
                    "agreed_findings": audit_run.agreed_findings_count,
                    "total_findings": (
                        audit_run.argus_findings_count + audit_run.codex_only_count
                    )
                }
            )

            self._store_alert(alert)
            logger.warning(
                f"Agreement alert generated: {audit_run.repo} has {audit_run.agreement_rate:.1%} agreement"
            )

        except Exception as e:
            logger.error(f"Error generating agreement alert: {e}")

    def _generate_outlier_alerts(
        self,
        audit_run_id: str,
        outliers: List[Dict[str, Any]]
    ) -> None:
        """Generate alerts for outlier findings"""
        try:
            for outlier in outliers[:5]:  # Limit to 5 alerts per run
                alert = Alert(
                    id=self._generate_id("alert"),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    audit_run_id=audit_run_id,
                    alert_type="outlier_finding",
                    severity="info",
                    message=(
                        f"Finding {outlier['finding_id']} has unusual score difference "
                        f"({outlier['score_difference']:.2f}) in {outlier['bound_exceeded']} bound"
                    ),
                    metric_name="score_difference",
                    metric_value=outlier["score_difference"],
                    threshold=0.5,
                    metadata={
                        "argus_score": outlier["argus_score"],
                        "codex_score": outlier["codex_score"],
                        "severity": outlier["severity"],
                        "category": outlier["category"]
                    }
                )

                self._store_alert(alert)

            if outliers:
                logger.info(f"Generated {len(outliers)} outlier alerts for audit run {audit_run_id}")

        except Exception as e:
            logger.error(f"Error generating outlier alerts: {e}")

    def _store_drift_events(self, drift_events: List[DriftEvent]) -> None:
        """Store detected drift events in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            for event in drift_events:
                cursor.execute(
                    """
                    INSERT INTO drift_events (
                        id, timestamp, audit_run_id, metric_name, metric_type,
                        old_value, new_value, change_magnitude, statistical_significance,
                        confidence, description
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.id,
                        event.timestamp,
                        event.audit_run_id,
                        event.metric_name,
                        event.metric_type,
                        event.old_value,
                        event.new_value,
                        event.change_magnitude,
                        event.statistical_significance,
                        event.confidence,
                        event.description
                    )
                )

            conn.commit()
            conn.close()

            logger.info(f"Stored {len(drift_events)} drift events")

        except Exception as e:
            logger.error(f"Error storing drift events: {e}")

    def _store_alert(self, alert: Alert) -> None:
        """Store alert in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO alerts (
                    id, timestamp, audit_run_id, alert_type, severity, message,
                    metric_name, metric_value, threshold, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    alert.timestamp,
                    alert.audit_run_id,
                    alert.alert_type,
                    alert.severity,
                    alert.message,
                    alert.metric_name,
                    alert.metric_value,
                    alert.threshold,
                    json.dumps(alert.metadata)
                )
            )

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"Error storing alert: {e}")

    def get_audit_run(self, audit_run_id: str) -> Optional[AuditRun]:
        """Retrieve audit run by ID"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM audit_runs WHERE id = ?", (audit_run_id,))
            row = cursor.fetchone()
            conn.close()

            if not row:
                return None

            return AuditRun(
                id=row["id"],
                timestamp=row["timestamp"],
                repo=row["repo"],
                project_type=row["project_type"],
                argus_findings_count=row["argus_findings_count"],
                codex_findings_count=row["codex_findings_count"],
                agreed_findings_count=row["agreed_findings_count"],
                argus_only_count=row["argus_only_count"],
                codex_only_count=row["codex_only_count"],
                agreement_rate=row["agreement_rate"],
                average_score_difference=row["average_score_difference"],
                severity_distribution=json.loads(row["severity_distribution"]),
                metadata=json.loads(row["metadata"])
            )

        except Exception as e:
            logger.error(f"Error retrieving audit run: {e}")
            return None

    def get_audit_history(
        self,
        repo: Optional[str] = None,
        days: int = 30,
        limit: int = 100
    ) -> List[AuditRun]:
        """
        Get historical audit runs

        Args:
            repo: Filter by repository (None = all)
            days: Include last N days
            limit: Maximum number of records

        Returns:
            List of audit runs ordered by timestamp (newest first)
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cutoff_date = (
                datetime.now(timezone.utc) - timedelta(days=days)
            ).isoformat()

            if repo:
                cursor.execute(
                    """
                    SELECT * FROM audit_runs
                    WHERE repo = ? AND timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (repo, cutoff_date, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM audit_runs
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (cutoff_date, limit)
                )

            rows = cursor.fetchall()
            conn.close()

            return [
                AuditRun(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    repo=row["repo"],
                    project_type=row["project_type"],
                    argus_findings_count=row["argus_findings_count"],
                    codex_findings_count=row["codex_findings_count"],
                    agreed_findings_count=row["agreed_findings_count"],
                    argus_only_count=row["argus_only_count"],
                    codex_only_count=row["codex_only_count"],
                    agreement_rate=row["agreement_rate"],
                    average_score_difference=row["average_score_difference"],
                    severity_distribution=json.loads(row["severity_distribution"]),
                    metadata=json.loads(row["metadata"])
                )
                for row in rows
            ]

        except Exception as e:
            logger.error(f"Error retrieving audit history: {e}")
            return []

    def get_agreement_trend(
        self,
        repo: Optional[str] = None,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get agreement rate trend data

        Returns:
            List of [timestamp, agreement_rate] tuples for charting
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cutoff_date = (
                datetime.now(timezone.utc) - timedelta(days=days)
            ).isoformat()

            if repo:
                cursor.execute(
                    """
                    SELECT timestamp, agreement_rate FROM audit_runs
                    WHERE repo = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                    """,
                    (repo, cutoff_date)
                )
            else:
                cursor.execute(
                    """
                    SELECT timestamp, agreement_rate FROM audit_runs
                    WHERE timestamp >= ?
                    ORDER BY timestamp ASC
                    """,
                    (cutoff_date,)
                )

            return [
                {"timestamp": row[0], "agreement_rate": row[1]}
                for row in cursor.fetchall()
            ]

        except Exception as e:
            logger.error(f"Error retrieving agreement trend: {e}")
            return []

    def get_active_alerts(
        self,
        severity: Optional[str] = None,
        limit: int = 50
    ) -> List[Alert]:
        """
        Get unacknowledged alerts

        Args:
            severity: Filter by severity level (None = all)
            limit: Maximum number of alerts

        Returns:
            List of active alerts ordered by timestamp (newest first)
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if severity:
                cursor.execute(
                    """
                    SELECT * FROM alerts
                    WHERE acknowledged = 0 AND severity = ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (severity, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM alerts
                    WHERE acknowledged = 0
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (limit,)
                )

            rows = cursor.fetchall()
            conn.close()

            return [
                Alert(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    audit_run_id=row["audit_run_id"],
                    alert_type=row["alert_type"],
                    severity=row["severity"],
                    message=row["message"],
                    metric_name=row["metric_name"],
                    metric_value=row["metric_value"],
                    threshold=row["threshold"],
                    metadata=json.loads(row["metadata"])
                )
                for row in rows
            ]

        except Exception as e:
            logger.error(f"Error retrieving active alerts: {e}")
            return []

    def get_recent_drift_events(
        self,
        audit_run_id: Optional[str] = None,
        days: int = 7,
        limit: int = 50
    ) -> List[DriftEvent]:
        """
        Get recent drift detection events

        Args:
            audit_run_id: Filter by audit run (None = all)
            days: Include last N days
            limit: Maximum number of events

        Returns:
            List of drift events ordered by timestamp (newest first)
        """
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cutoff_date = (
                datetime.now(timezone.utc) - timedelta(days=days)
            ).isoformat()

            if audit_run_id:
                cursor.execute(
                    """
                    SELECT * FROM drift_events
                    WHERE audit_run_id = ? AND timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (audit_run_id, cutoff_date, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM drift_events
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (cutoff_date, limit)
                )

            rows = cursor.fetchall()
            conn.close()

            return [
                DriftEvent(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    audit_run_id=row["audit_run_id"],
                    metric_name=row["metric_name"],
                    metric_type=row["metric_type"],
                    old_value=row["old_value"],
                    new_value=row["new_value"],
                    change_magnitude=row["change_magnitude"],
                    statistical_significance=row["statistical_significance"],
                    confidence=row["confidence"],
                    description=row["description"]
                )
                for row in rows
            ]

        except Exception as e:
            logger.error(f"Error retrieving drift events: {e}")
            return []

    def generate_dashboard_metrics(
        self,
        repo: Optional[str] = None,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Generate metrics for visualization dashboard

        Returns dashboard-ready metrics including:
        - Current agreement rate
        - Historical trends
        - Drift events summary
        - Active alerts
        - Category/severity distributions
        """
        try:
            history = self.get_audit_history(repo=repo, days=days)

            if not history:
                return {
                    "status": "no_data",
                    "message": "No audit runs found"
                }

            # Current metrics
            current_run = history[0]

            # Calculate trend
            agreement_rates = [r.agreement_rate for r in history]
            agreement_trend = (
                agreement_rates[0] - agreement_rates[-1]
                if len(agreement_rates) > 1
                else 0
            )

            # Drift summary
            drift_events = self.get_recent_drift_events(days=days, limit=100)
            high_confidence_drift = [
                d for d in drift_events if d.confidence > 0.7
            ]

            # Alerts summary
            active_alerts = self.get_active_alerts()
            alerts_by_type = {}
            for alert in active_alerts:
                alerts_by_type[alert.alert_type] = alerts_by_type.get(alert.alert_type, 0) + 1

            # Aggregate statistics
            avg_agreement = statistics.mean(agreement_rates) if agreement_rates else 0.0
            avg_score_diff = statistics.mean(
                [r.average_score_difference for r in history if r.average_score_difference]
            ) if history else 0.0

            return {
                "status": "ok",
                "summary": {
                    "current_agreement_rate": current_run.agreement_rate,
                    "average_agreement_rate": avg_agreement,
                    "agreement_trend": agreement_trend,
                    "agreement_within_threshold": (
                        current_run.agreement_rate >= self.agreement_threshold
                    ),
                    "average_score_difference": avg_score_diff
                },
                "current_run": {
                    "id": current_run.id,
                    "timestamp": current_run.timestamp,
                    "repo": current_run.repo,
                    "argus_findings": current_run.argus_findings_count,
                    "codex_findings": current_run.codex_findings_count,
                    "agreed_findings": current_run.agreed_findings_count,
                    "argus_only": current_run.argus_only_count,
                    "codex_only": current_run.codex_only_count,
                    "severity_distribution": current_run.severity_distribution
                },
                "trends": {
                    "agreement_rates": agreement_rates[-7:],  # Last 7 runs
                    "audit_count": len(history),
                    "time_span_days": days
                },
                "drift": {
                    "total_events": len(drift_events),
                    "high_confidence_events": len(high_confidence_drift),
                    "recent_events": [asdict(e) for e in drift_events[:5]]
                },
                "alerts": {
                    "active_count": len(active_alerts),
                    "by_type": alerts_by_type,
                    "recent_alerts": [asdict(a) for a in active_alerts[:5]]
                },
                "health_score": self._calculate_health_score(
                    current_run.agreement_rate,
                    len(high_confidence_drift),
                    len(active_alerts)
                )
            }

        except Exception as e:
            logger.error(f"Error generating dashboard metrics: {e}")
            return {"status": "error", "message": str(e)}

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark alert as acknowledged"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                (alert_id,)
            )

            conn.commit()
            conn.close()

            return cursor.rowcount > 0

        except Exception as e:
            logger.error(f"Error acknowledging alert: {e}")
            return False

    def cleanup_old_data(self, keep_days: int = 90) -> int:
        """
        Delete audit data older than keep_days

        Returns:
            Number of audit runs deleted
        """
        if not self.enable_cleanup:
            return 0

        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cutoff_date = (
                datetime.now(timezone.utc) - timedelta(days=keep_days)
            ).isoformat()

            # Get audit runs to delete
            cursor.execute(
                "SELECT id FROM audit_runs WHERE timestamp < ?",
                (cutoff_date,)
            )
            audit_ids = [row[0] for row in cursor.fetchall()]

            if not audit_ids:
                return 0

            # Delete cascading records
            for audit_id in audit_ids:
                cursor.execute("DELETE FROM findings_comparison WHERE audit_run_id = ?", (audit_id,))
                cursor.execute("DELETE FROM drift_events WHERE audit_run_id = ?", (audit_id,))
                cursor.execute("DELETE FROM alerts WHERE audit_run_id = ?", (audit_id,))
                cursor.execute("DELETE FROM audit_runs WHERE id = ?", (audit_id,))

            conn.commit()
            conn.close()

            logger.info(f"Cleaned up {len(audit_ids)} old audit runs")
            return len(audit_ids)

        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")
            return 0

    # Helper methods

    def _get_category_distribution(self, audit_run_id: str) -> Dict[str, float]:
        """Get category distribution for audit run"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute(
                "SELECT category, COUNT(*) FROM findings_comparison WHERE audit_run_id = ? GROUP BY category",
                (audit_run_id,)
            )
            counts = dict(cursor.fetchall())
            conn.close()

            total = sum(counts.values())
            return {cat: count / total for cat, count in counts.items()} if total > 0 else {}

        except Exception as e:
            logger.error(f"Error calculating category distribution: {e}")
            return {}

    def _get_category_distribution_aggregate(
        self,
        audit_run_ids: List[str]
    ) -> Dict[str, float]:
        """Get aggregated category distribution"""
        try:
            all_dists = [self._get_category_distribution(aid) for aid in audit_run_ids]
            if not all_dists:
                return {}

            # Average distributions
            all_categories = set()
            for dist in all_dists:
                all_categories.update(dist.keys())

            return {
                cat: statistics.mean([d.get(cat, 0.0) for d in all_dists])
                for cat in all_categories
            }

        except Exception as e:
            logger.error(f"Error calculating aggregated category distribution: {e}")
            return {}

    def _get_severity_agreement_correlation(self, audit_run_id: str) -> Dict[str, float]:
        """Get agreement rate by severity level"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT severity, AVG(agreed) FROM findings_comparison
                WHERE audit_run_id = ? GROUP BY severity
                """,
                (audit_run_id,)
            )

            return dict(cursor.fetchall())

        except Exception as e:
            logger.error(f"Error calculating severity agreement correlation: {e}")
            return {}

    def _get_severity_agreement_correlation_aggregate(
        self,
        audit_run_ids: List[str]
    ) -> Dict[str, float]:
        """Get aggregated severity-agreement correlation"""
        try:
            correlations = [
                self._get_severity_agreement_correlation(aid)
                for aid in audit_run_ids
            ]
            if not correlations:
                return {}

            all_severities = set()
            for corr in correlations:
                all_severities.update(corr.keys())

            return {
                sev: statistics.mean([c.get(sev, 0.5) for c in correlations])
                for sev in all_severities
            }

        except Exception as e:
            logger.error(f"Error calculating aggregated severity correlation: {e}")
            return {}

    def _get_score_differences(self, audit_run_id: str) -> List[float]:
        """Get all score differences for audit run"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute(
                "SELECT score_difference FROM findings_comparison WHERE audit_run_id = ?",
                (audit_run_id,)
            )

            return [row[0] for row in cursor.fetchall()]

        except Exception as e:
            logger.error(f"Error getting score differences: {e}")
            return []

    def _get_score_differences_aggregate(self, audit_run_ids: List[str]) -> List[float]:
        """Get all score differences across multiple audit runs"""
        try:
            return [
                score
                for audit_id in audit_run_ids
                for score in self._get_score_differences(audit_id)
            ]

        except Exception as e:
            logger.error(f"Error getting aggregated score differences: {e}")
            return []

    def _calculate_significance(self, history: List[AuditRun], category: str) -> float:
        """Calculate statistical significance of change"""
        try:
            if len(history) < 2:
                return 0.0

            # Simple metric: based on standard deviation
            category_agreements = [
                self._get_category_distribution(r.id).get(category, 0.0)
                for r in history
            ]

            if not category_agreements or len(category_agreements) < 2:
                return 0.0

            stdev = statistics.stdev(category_agreements)
            mean = statistics.mean(category_agreements)

            return min(1.0, stdev / (mean + 0.001))

        except Exception as e:
            logger.error(f"Error calculating significance: {e}")
            return 0.0

    def _ks_statistic(self, sample1: List[float], sample2: List[float]) -> float:
        """
        Simplified Kolmogorov-Smirnov statistic
        Returns maximum difference between two empirical distributions
        """
        try:
            if not sample1 or not sample2:
                return 0.0

            # Sort both samples
            s1 = sorted(sample1)
            s2 = sorted(sample2)

            # Calculate empirical CDF difference
            max_diff = 0.0
            for i in range(max(len(s1), len(s2))):
                cdf1 = (i + 1) / len(s1) if i < len(s1) else 1.0
                cdf2 = (i + 1) / len(s2) if i < len(s2) else 1.0
                max_diff = max(max_diff, abs(cdf1 - cdf2))

            return min(1.0, max_diff)

        except Exception as e:
            logger.error(f"Error calculating K-S statistic: {e}")
            return 0.0

    def _calculate_health_score(
        self,
        agreement_rate: float,
        drift_event_count: int,
        alert_count: int
    ) -> float:
        """
        Calculate overall system health score (0-100)

        Factors:
        - Agreement rate (40%)
        - Drift events (30%)
        - Active alerts (30%)
        """
        try:
            # Agreement component (0-40)
            agreement_component = agreement_rate * 40.0

            # Drift component (0-30, penalize high drift)
            drift_component = max(0, 30.0 - (drift_event_count * 2.0))

            # Alert component (0-30, penalize high alerts)
            alert_component = max(0, 30.0 - (alert_count * 0.5))

            health_score = agreement_component + drift_component + alert_component
            return min(100.0, max(0.0, health_score))

        except Exception as e:
            logger.error(f"Error calculating health score: {e}")
            return 50.0

    @staticmethod
    def _generate_id(prefix: str) -> str:
        """Generate unique ID with prefix"""
        import uuid
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        unique_part = str(uuid.uuid4())[:8]
        return f"{prefix}-{timestamp}-{unique_part}"


if __name__ == "__main__":
    # Example usage and testing
    monitor = AuditMonitor(
        db_path=".argus/audit_monitor.db",
        agreement_threshold=0.75,
        drift_sensitivity=0.15
    )

    # Example audit run
    example_run = AuditRun(
        id=AuditMonitor._generate_id("audit"),
        timestamp=datetime.now(timezone.utc).isoformat(),
        repo="test-repo",
        project_type="backend-api",
        argus_findings_count=42,
        codex_findings_count=45,
        agreed_findings_count=38,
        argus_only_count=4,
        codex_only_count=7,
        agreement_rate=0.84,
        average_score_difference=0.18,
        severity_distribution={
            "critical": 5,
            "high": 12,
            "medium": 18,
            "low": 7
        },
        metadata={"branch": "main", "commit": "abc123"}
    )

    # Example findings comparisons
    example_comparisons = [
        FindingComparison(
            id=AuditMonitor._generate_id("finding"),
            audit_run_id=example_run.id,
            finding_id="finding-001",
            argus_score=4.5,
            codex_score=4.2,
            score_difference=0.3,
            agreed=True,
            argus_verdict="likely_valid",
            codex_verdict="likely_valid",
            severity="high",
            category="SAST",
            metadata={"rule": "sql-injection"}
        ),
        FindingComparison(
            id=AuditMonitor._generate_id("finding"),
            audit_run_id=example_run.id,
            finding_id="finding-002",
            argus_score=2.1,
            codex_score=3.8,
            score_difference=1.7,
            agreed=False,
            argus_verdict="likely_false_positive",
            codex_verdict="uncertain",
            severity="medium",
            category="SAST",
            metadata={"rule": "hardcoded-password"}
        )
    ]

    # Store example data
    success, error = monitor.store_audit_run(example_run, example_comparisons)
    if success:
        print("Audit run stored successfully")

        # Retrieve and display metrics
        metrics = monitor.generate_dashboard_metrics()
        print("\nDashboard Metrics:")
        print(json.dumps(metrics, indent=2))

        # Get alerts
        alerts = monitor.get_active_alerts()
        print(f"\nActive Alerts: {len(alerts)}")
        for alert in alerts:
            print(f"  - [{alert.severity}] {alert.message}")
    else:
        print(f"Failed to store audit run: {error}")
