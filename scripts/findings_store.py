#!/usr/bin/env python3
"""
Persistent SQLite-Backed Findings Store for Argus Security

Provides cross-scan intelligence by persisting findings, scan history, and
fix records in a local SQLite database.  Enables regression detection,
trend analytics, mean-time-to-fix calculations, false-positive-rate
tracking, and historical context injection for LLM enrichment.

Features:
- Content-based fingerprinting for cross-scan deduplication
- Automatic regression detection (previously fixed findings that reappear)
- Severity trend analytics over configurable time windows
- Mean-time-to-fix and false-positive-rate metrics
- Historical context injection for AI enrichment (Phase 2)
- Thread-safe write operations with a reentrant lock

Usage:
    store = FindingsStore(db_path=".argus/findings.db")
    summary = store.record_scan(scan_id, findings, commit_sha="abc123")
    context = store.get_historical_context(finding)
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = ["FindingsStore", "ScanSummary"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed finding statuses
# ---------------------------------------------------------------------------

VALID_STATUSES = frozenset(
    {"open", "fixed", "false_positive", "accepted_risk", "wont_fix"}
)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ScanSummary:
    """Summary of a single scan recording operation.

    Attributes:
        scan_id: Unique identifier for the scan.
        total_findings: Total number of findings processed.
        new_findings: Findings seen for the first time.
        existing_findings: Findings already known from prior scans.
        fixed_since_last: Findings that were open before but absent now.
        regressions: Previously fixed findings that have reappeared.
        by_severity: Breakdown of total findings by severity level.
    """

    scan_id: str
    total_findings: int
    new_findings: int
    existing_findings: int
    fixed_since_last: int
    regressions: int
    by_severity: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the summary to a plain dictionary."""
        return asdict(self)


# ---------------------------------------------------------------------------
# SQL statements
# ---------------------------------------------------------------------------

_CREATE_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    scan_timestamp TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    file_path TEXT,
    line_number INTEGER,
    cwe TEXT,
    cve TEXT,
    cvss_score REAL,
    source_tool TEXT,
    status TEXT DEFAULT 'open',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER DEFAULT 1,
    fix_verified INTEGER DEFAULT 0,
    title TEXT,
    description TEXT
)
"""

_CREATE_SCAN_HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    commit_sha TEXT,
    branch TEXT,
    total_findings INTEGER,
    new_findings INTEGER DEFAULT 0,
    fixed_findings INTEGER DEFAULT 0,
    regression_findings INTEGER DEFAULT 0,
    critical INTEGER DEFAULT 0,
    high INTEGER DEFAULT 0,
    medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0,
    duration_seconds REAL,
    cost_usd REAL
)
"""

_CREATE_FIX_HISTORY_TABLE = """
CREATE TABLE IF NOT EXISTS fix_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    fix_commit TEXT,
    fix_timestamp TEXT NOT NULL,
    fix_method TEXT,
    retest_passed INTEGER DEFAULT 0,
    regression_detected INTEGER DEFAULT 0,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
)
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)",
    "CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
    "CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type)",
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp)",
]


# ---------------------------------------------------------------------------
# FindingsStore
# ---------------------------------------------------------------------------


class FindingsStore:
    """Persistent SQLite-backed findings store for cross-scan intelligence.

    Maintains a local database of security findings across scans, enabling
    regression detection, trend analysis, and historical context injection
    for LLM-based enrichment.

    Args:
        db_path: Path to the SQLite database file.  Parent directories are
            created automatically if they do not exist.
    """

    def __init__(self, db_path: str = ".argus/findings.db") -> None:
        self.db_path = db_path
        self._lock = threading.RLock()

        # Ensure parent directory exists
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

        self._init_schema()
        logger.info("FindingsStore initialized at %s", db_path)

    # ------------------------------------------------------------------
    # Schema initialization
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create tables and indexes if they do not already exist."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(_CREATE_FINDINGS_TABLE)
            cur.execute(_CREATE_SCAN_HISTORY_TABLE)
            cur.execute(_CREATE_FIX_HISTORY_TABLE)
            for idx_sql in _CREATE_INDEXES:
                cur.execute(idx_sql)
            self._conn.commit()
            logger.debug("Database schema initialized")

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    @staticmethod
    def fingerprint_finding(finding: dict[str, Any]) -> str:
        """Compute a content-based fingerprint for a finding.

        The fingerprint is a deterministic SHA-256 digest of the
        concatenation of ``vuln_type``, ``file_path``, the first 200
        characters of ``code_snippet``, and ``cwe``.

        Args:
            finding: Dictionary containing finding fields.

        Returns:
            The first 16 hex characters of the SHA-256 digest.
        """
        vuln_type = str(finding.get("vuln_type", ""))
        file_path = str(finding.get("file_path", ""))
        snippet = str(finding.get("code_snippet", ""))[:200]
        cwe = str(finding.get("cwe", ""))
        combined = f"{vuln_type}|{file_path}|{snippet}|{cwe}"
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Core CRUD
    # ------------------------------------------------------------------

    def record_scan(
        self,
        scan_id: str,
        findings: list[dict[str, Any]],
        commit_sha: str = "",
        branch: str = "",
        duration: float = 0.0,
        cost: float = 0.0,
    ) -> ScanSummary:
        """Record all findings from a scan, upserting as appropriate.

        For each finding the method computes a fingerprint and checks
        whether a finding with the same fingerprint already exists:

        - **New:** inserted with ``first_seen = last_seen = now``.
        - **Existing:** ``last_seen`` and ``times_seen`` are updated;
          severity and status are refreshed if they changed.
        - **Regression:** a previously *fixed* finding has reappeared;
          its status is reset to ``open``.

        After processing findings, open findings from prior scans that
        are *not* present in this scan are counted as ``fixed_since_last``
        (but their status is not changed automatically -- that requires
        an explicit ``record_fix`` call).

        Args:
            scan_id: Unique identifier for this scan.
            findings: List of finding dictionaries.
            commit_sha: Git commit SHA associated with this scan.
            branch: Git branch name.
            duration: Total scan duration in seconds.
            cost: Estimated LLM cost in USD.

        Returns:
            A :class:`ScanSummary` describing the scan results.
        """
        now = datetime.now(timezone.utc).isoformat()
        new_count = 0
        existing_count = 0
        regression_count = 0
        severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        current_fingerprints: set[str] = set()

        with self._lock:
            cur = self._conn.cursor()

            for finding in findings:
                fp = self.fingerprint_finding(finding)
                current_fingerprints.add(fp)

                severity = str(finding.get("severity", "low")).lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

                # Check for existing finding by fingerprint
                cur.execute(
                    "SELECT id, status, times_seen FROM findings WHERE fingerprint = ?",
                    (fp,),
                )
                row = cur.fetchone()

                if row is not None:
                    existing_id = row["id"]
                    prev_status = row["status"]
                    prev_times = row["times_seen"]

                    # Regression: was fixed, now reappeared
                    if prev_status == "fixed":
                        regression_count += 1
                        new_status = "open"
                        logger.warning(
                            "Regression detected for finding %s (fingerprint=%s)",
                            existing_id,
                            fp,
                        )
                    else:
                        new_status = prev_status
                        existing_count += 1

                    cur.execute(
                        """
                        UPDATE findings
                        SET last_seen = ?,
                            times_seen = ?,
                            severity = ?,
                            status = ?,
                            scan_id = ?,
                            scan_timestamp = ?
                        WHERE id = ?
                        """,
                        (
                            now,
                            prev_times + 1,
                            severity,
                            new_status,
                            scan_id,
                            now,
                            existing_id,
                        ),
                    )
                else:
                    # New finding
                    new_count += 1
                    finding_id = finding.get("id") or str(uuid.uuid4())
                    cur.execute(
                        """
                        INSERT INTO findings (
                            id, fingerprint, scan_id, scan_timestamp,
                            vuln_type, severity, file_path, line_number,
                            cwe, cve, cvss_score, source_tool, status,
                            first_seen, last_seen, times_seen,
                            fix_verified, title, description
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            finding_id,
                            fp,
                            scan_id,
                            now,
                            str(finding.get("vuln_type", "")),
                            severity,
                            finding.get("file_path"),
                            finding.get("line_number"),
                            finding.get("cwe"),
                            finding.get("cve"),
                            finding.get("cvss_score"),
                            finding.get("source_tool"),
                            "open",
                            now,
                            now,
                            1,
                            0,
                            finding.get("title"),
                            finding.get("description"),
                        ),
                    )

            # Count how many previously-open findings are absent from this scan
            if current_fingerprints:
                placeholders = ",".join("?" for _ in current_fingerprints)
                cur.execute(
                    f"""
                    SELECT COUNT(*) AS cnt FROM findings
                    WHERE status = 'open'
                      AND fingerprint NOT IN ({placeholders})
                    """,
                    list(current_fingerprints),
                )
            else:
                cur.execute(
                    "SELECT COUNT(*) AS cnt FROM findings WHERE status = 'open'"
                )
            fixed_since_last = cur.fetchone()["cnt"]

            # Record scan history
            cur.execute(
                """
                INSERT OR REPLACE INTO scan_history (
                    scan_id, timestamp, commit_sha, branch,
                    total_findings, new_findings, fixed_findings,
                    regression_findings,
                    critical, high, medium, low,
                    duration_seconds, cost_usd
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    now,
                    commit_sha,
                    branch,
                    len(findings),
                    new_count,
                    fixed_since_last,
                    regression_count,
                    severity_counts.get("critical", 0),
                    severity_counts.get("high", 0),
                    severity_counts.get("medium", 0),
                    severity_counts.get("low", 0),
                    duration,
                    cost,
                ),
            )

            self._conn.commit()

        summary = ScanSummary(
            scan_id=scan_id,
            total_findings=len(findings),
            new_findings=new_count,
            existing_findings=existing_count,
            fixed_since_last=fixed_since_last,
            regressions=regression_count,
            by_severity=severity_counts,
        )
        logger.info(
            "Scan %s recorded: %d total, %d new, %d existing, %d regressions, %d fixed",
            scan_id,
            summary.total_findings,
            summary.new_findings,
            summary.existing_findings,
            summary.regressions,
            summary.fixed_since_last,
        )
        return summary

    def record_fix(
        self,
        finding_id: str,
        fix_commit: str = "",
        fix_method: str = "manual",
        retest_passed: bool = False,
    ) -> None:
        """Record a fix for a finding.

        Inserts a row into ``fix_history`` and, if ``retest_passed`` is
        ``True``, updates the finding status to ``'fixed'``.

        Args:
            finding_id: ID of the finding that was fixed.
            fix_commit: Git commit SHA of the fix.
            fix_method: How the fix was applied (``autofix``,
                ``manual``, or ``dependency_update``).
            retest_passed: Whether the fix was verified by a retest.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT INTO fix_history (
                    finding_id, fix_commit, fix_timestamp, fix_method, retest_passed
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (finding_id, fix_commit, now, fix_method, int(retest_passed)),
            )
            if retest_passed:
                cur.execute(
                    "UPDATE findings SET status = 'fixed', fix_verified = 1 WHERE id = ?",
                    (finding_id,),
                )
                logger.info(
                    "Finding %s marked as fixed (verified by retest)", finding_id
                )
            else:
                logger.info(
                    "Fix recorded for finding %s (pending retest verification)",
                    finding_id,
                )
            self._conn.commit()

    def update_status(self, finding_id: str, status: str) -> None:
        """Update the status of a finding.

        Args:
            finding_id: ID of the finding to update.
            status: New status.  Must be one of ``open``, ``fixed``,
                ``false_positive``, ``accepted_risk``, or ``wont_fix``.

        Raises:
            ValueError: If *status* is not a recognized value.
        """
        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of: {sorted(VALID_STATUSES)}"
            )
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "UPDATE findings SET status = ? WHERE id = ?",
                (status, finding_id),
            )
            self._conn.commit()
            logger.info("Finding %s status updated to '%s'", finding_id, status)

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        """Retrieve a single finding by its ID.

        Args:
            finding_id: The unique finding identifier.

        Returns:
            A dictionary of finding fields, or ``None`` if not found.
        """
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = cur.fetchone()
        return dict(row) if row else None

    def get_finding_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        """Retrieve a single finding by its content-based fingerprint.

        Args:
            fingerprint: The 16-char hex fingerprint.

        Returns:
            A dictionary of finding fields, or ``None`` if not found.
        """
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM findings WHERE fingerprint = ?", (fingerprint,))
        row = cur.fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def is_regression(self, fingerprint: str) -> bool:
        """Check whether a finding with this fingerprint was previously fixed.

        A regression means the finding had a verified fix recorded in
        ``fix_history`` but has since reappeared (status is no longer
        ``'fixed'``).  This approach is resilient to the transient status
        change that ``record_scan`` performs when it detects a regression
        and resets the status to ``'open'``.

        Args:
            fingerprint: Content-based fingerprint of the finding.

        Returns:
            ``True`` if the finding has a verified fix in history but is
            currently not in ``'fixed'`` status (i.e., it regressed).
        """
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT f.id, f.status FROM findings f
            WHERE f.fingerprint = ?
            """,
            (fingerprint,),
        )
        row = cur.fetchone()
        if row is None:
            return False

        # A finding is a regression if it was previously fixed (has a
        # verified fix record) but its current status is not 'fixed'.
        finding_id = row["id"]
        current_status = row["status"]
        cur.execute(
            """
            SELECT COUNT(*) AS cnt FROM fix_history
            WHERE finding_id = ? AND retest_passed = 1
            """,
            (finding_id,),
        )
        has_verified_fix = cur.fetchone()["cnt"] > 0
        return has_verified_fix and current_status != "fixed"

    def trending(self, days: int = 90) -> dict[str, Any]:
        """Return severity counts per week for the last *days* days.

        Uses ``scan_history`` rows to aggregate weekly counts of critical,
        high, medium, and low findings.

        Args:
            days: Number of days to look back.  Defaults to 90.

        Returns:
            A dictionary keyed by ISO week string (``YYYY-WNN``) with
            severity counts for each week.
        """
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT timestamp, critical, high, medium, low
            FROM scan_history
            WHERE timestamp >= datetime('now', ?)
            ORDER BY timestamp ASC
            """,
            (f"-{days} days",),
        )
        weeks: dict[str, dict[str, int]] = {}
        for row in cur.fetchall():
            try:
                dt = datetime.fromisoformat(row["timestamp"])
                week_key = f"{dt.isocalendar()[0]}-W{dt.isocalendar()[1]:02d}"
            except (ValueError, TypeError):
                continue

            if week_key not in weeks:
                weeks[week_key] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            weeks[week_key]["critical"] += row["critical"] or 0
            weeks[week_key]["high"] += row["high"] or 0
            weeks[week_key]["medium"] += row["medium"] or 0
            weeks[week_key]["low"] += row["low"] or 0

        return weeks

    def mean_time_to_fix(self, severity: str | None = None) -> float | None:
        """Calculate the average time between first_seen and fix for fixed findings.

        Args:
            severity: Optional severity filter (e.g., ``'critical'``).

        Returns:
            Mean time to fix in seconds, or ``None`` if there are no
            qualifying records.
        """
        query = """
            SELECT f.first_seen, fh.fix_timestamp
            FROM findings f
            JOIN fix_history fh ON f.id = fh.finding_id
            WHERE f.status = 'fixed'
              AND fh.retest_passed = 1
        """
        params: list[Any] = []
        if severity:
            query += " AND f.severity = ?"
            params.append(severity.lower())

        cur = self._conn.cursor()
        cur.execute(query, params)

        durations: list[float] = []
        for row in cur.fetchall():
            try:
                first = datetime.fromisoformat(row["first_seen"])
                fixed = datetime.fromisoformat(row["fix_timestamp"])
                delta = (fixed - first).total_seconds()
                if delta >= 0:
                    durations.append(delta)
            except (ValueError, TypeError):
                continue

        if not durations:
            return None
        return sum(durations) / len(durations)

    def false_positive_rate(self, vuln_type: str | None = None) -> float:
        """Calculate the false positive rate for a given vulnerability type.

        Args:
            vuln_type: Optional vulnerability type filter.  If ``None``,
                computes the rate across all findings.

        Returns:
            The ratio of ``false_positive`` findings to total findings,
            or ``0.0`` if there are no findings.
        """
        if vuln_type:
            total_query = "SELECT COUNT(*) AS cnt FROM findings WHERE vuln_type = ?"
            fp_query = (
                "SELECT COUNT(*) AS cnt FROM findings "
                "WHERE vuln_type = ? AND status = 'false_positive'"
            )
            params: list[Any] = [vuln_type]
        else:
            total_query = "SELECT COUNT(*) AS cnt FROM findings"
            fp_query = (
                "SELECT COUNT(*) AS cnt FROM findings WHERE status = 'false_positive'"
            )
            params = []

        cur = self._conn.cursor()
        cur.execute(total_query, params)
        total = cur.fetchone()["cnt"]
        if total == 0:
            return 0.0

        cur.execute(fp_query, params)
        fp_count = cur.fetchone()["cnt"]
        return fp_count / total

    def top_recurring(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the most frequently recurring open findings.

        Args:
            limit: Maximum number of results to return.

        Returns:
            A list of finding dictionaries ordered by ``times_seen``
            descending.
        """
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT * FROM findings
            WHERE status = 'open'
            ORDER BY times_seen DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]

    def scan_history_summary(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent scan history rows.

        Args:
            limit: Maximum number of rows to return.

        Returns:
            A list of scan history dictionaries ordered by timestamp
            descending.
        """
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT * FROM scan_history
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]

    # ------------------------------------------------------------------
    # Context injection (for LLM enrichment)
    # ------------------------------------------------------------------

    def get_historical_context(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Build historical context for a finding to inject into LLM prompts.

        Computes the finding's fingerprint, looks up prior history, and
        returns a context dictionary suitable for Phase 2 AI enrichment.

        Args:
            finding: A finding dictionary.

        Returns:
            A dictionary containing:

            - ``first_seen``: ISO timestamp of the first occurrence.
            - ``times_seen``: How many scans have reported this finding.
            - ``previous_status``: Status from the last scan.
            - ``related_in_file``: Count of other findings in the same file.
            - ``fp_rate_for_type``: False positive rate for this vuln_type.
            - ``is_regression``: Whether this is a regression.
        """
        fp = self.fingerprint_finding(finding)
        existing = self.get_finding_by_fingerprint(fp)

        if existing is None:
            return {
                "first_seen": None,
                "times_seen": 0,
                "previous_status": None,
                "related_in_file": 0,
                "fp_rate_for_type": 0.0,
                "is_regression": False,
            }

        # Count related findings in the same file
        related_count = 0
        file_path = existing.get("file_path")
        if file_path:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT COUNT(*) AS cnt FROM findings WHERE file_path = ? AND fingerprint != ?",
                (file_path, fp),
            )
            related_count = cur.fetchone()["cnt"]

        vuln_type = existing.get("vuln_type", "")
        fp_rate = self.false_positive_rate(vuln_type) if vuln_type else 0.0

        return {
            "first_seen": existing.get("first_seen"),
            "times_seen": existing.get("times_seen", 0),
            "previous_status": existing.get("status"),
            "related_in_file": related_count,
            "fp_rate_for_type": fp_rate,
            "is_regression": self.is_regression(fp),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _count_findings(self) -> int:
        """Return the total number of findings in the database."""
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM findings")
        return cur.fetchone()["cnt"]

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()
        logger.debug("FindingsStore connection closed")


# ---------------------------------------------------------------------------
# CLI demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    store = FindingsStore()
    print(f"Findings store initialized at {store.db_path}")
    print(f"Total findings: {store._count_findings()}")
    print(f"Scan history: {len(store.scan_history_summary())}")
