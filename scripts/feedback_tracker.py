#!/usr/bin/env python3
"""
False Positive Feedback Loop Infrastructure
Tracks developer responses to security findings to improve future scans

Features:
- SQLite-based feedback storage in .argus-cache/feedback.db
- Feedback verdict tracking (true_positive, false_positive, wont_fix, duplicate)
- False positive rate calculation by scanner/category
- Pattern detection for common FP causes
- Integration with GitHub issues and PR comments
- Analytics and improvement metrics over time
- AI-generated rule adjustment suggestions
"""

import json
import logging
import sqlite3
import threading
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class FeedbackEntry:
    """
    Feedback entry for a security finding

    Attributes:
        finding_id: Unique identifier for the finding (e.g., "semgrep-abc123")
        verdict: Developer's assessment (true_positive, false_positive, wont_fix, duplicate)
        reason: Human-readable explanation for the verdict
        timestamp: ISO 8601 timestamp when feedback was recorded
        source: Where feedback came from (github_issue, pr_comment, manual, automated)
        metadata: Additional context (scanner name, category, file_path, etc.)
    """

    finding_id: str
    verdict: str  # true_positive, false_positive, wont_fix, duplicate
    reason: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "manual"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate verdict values"""
        valid_verdicts = {"true_positive", "false_positive", "wont_fix", "duplicate"}
        if self.verdict not in valid_verdicts:
            raise ValueError(
                f"Invalid verdict '{self.verdict}'. Must be one of: {valid_verdicts}"
            )


class FeedbackTracker:
    """
    Tracks and analyzes feedback on security findings

    Storage:
        SQLite database at .argus-cache/feedback.db

    Schema:
        findings_feedback table:
            - finding_id TEXT PRIMARY KEY
            - verdict TEXT NOT NULL
            - reason TEXT NOT NULL
            - timestamp TEXT NOT NULL
            - source TEXT NOT NULL
            - metadata TEXT (JSON)
            - scanner TEXT (indexed, extracted from metadata)
            - category TEXT (indexed, extracted from metadata)
            - file_path TEXT (extracted from metadata)
    """

    def __init__(
        self,
        cache_dir: str = ".argus-cache",
        db_name: str = "feedback.db"
    ):
        """
        Initialize feedback tracker

        Args:
            cache_dir: Directory for cache storage (default: .argus-cache)
            db_name: Database filename (default: feedback.db)
        """
        self.cache_dir = Path(cache_dir).resolve()
        self.db_path = self.cache_dir / db_name

        # Thread safety
        self._lock = threading.RLock()

        # Initialize database
        self._initialize_db()

    def _initialize_db(self) -> None:
        """Create database and schema if they don't exist"""
        try:
            # Ensure cache directory exists
            self.cache_dir.mkdir(parents=True, exist_ok=True)

            with self._lock:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                # Create findings_feedback table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS findings_feedback (
                        finding_id TEXT PRIMARY KEY,
                        verdict TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        source TEXT NOT NULL,
                        metadata TEXT,
                        scanner TEXT,
                        category TEXT,
                        file_path TEXT
                    )
                """)

                # Create indexes for common queries
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_verdict
                    ON findings_feedback(verdict)
                """)

                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_scanner
                    ON findings_feedback(scanner)
                """)

                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_category
                    ON findings_feedback(category)
                """)

                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timestamp
                    ON findings_feedback(timestamp)
                """)

                conn.commit()
                conn.close()

                logger.info(f"Feedback database initialized: {self.db_path}")

        except Exception as e:
            logger.error(f"Failed to initialize feedback database: {e}")
            raise

    def record_feedback(
        self,
        finding_id: str,
        verdict: str,
        reason: str,
        source: str = "manual",
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Record feedback for a finding

        Args:
            finding_id: Unique finding identifier
            verdict: Developer's assessment (true_positive, false_positive, wont_fix, duplicate)
            reason: Explanation for the verdict
            source: Feedback source (github_issue, pr_comment, manual, automated)
            metadata: Additional context (scanner, category, file_path, etc.)

        Returns:
            True if recorded successfully, False otherwise
        """
        try:
            # Create feedback entry
            entry = FeedbackEntry(
                finding_id=finding_id,
                verdict=verdict,
                reason=reason,
                source=source,
                metadata=metadata or {}
            )

            # Extract indexed fields from metadata
            scanner = metadata.get("scanner") if metadata else None
            category = metadata.get("category") if metadata else None
            file_path = metadata.get("file_path") if metadata else None

            with self._lock:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                # Insert or replace feedback
                cursor.execute("""
                    INSERT OR REPLACE INTO findings_feedback
                    (finding_id, verdict, reason, timestamp, source, metadata, scanner, category, file_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.finding_id,
                    entry.verdict,
                    entry.reason,
                    entry.timestamp,
                    entry.source,
                    json.dumps(entry.metadata),
                    scanner,
                    category,
                    file_path
                ))

                conn.commit()
                conn.close()

            logger.info(
                f"Recorded feedback: {finding_id} -> {verdict} "
                f"(source: {source}, reason: {reason[:50]}...)"
            )

            return True

        except ValueError as e:
            logger.error(f"Invalid feedback data: {e}")
            return False

        except Exception as e:
            logger.error(f"Failed to record feedback: {e}")
            return False

    def get_feedback_for_finding(self, finding_id: str) -> Optional[FeedbackEntry]:
        """
        Retrieve feedback for a specific finding

        Args:
            finding_id: Finding identifier

        Returns:
            FeedbackEntry if found, None otherwise
        """
        try:
            with self._lock:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT finding_id, verdict, reason, timestamp, source, metadata
                    FROM findings_feedback
                    WHERE finding_id = ?
                """, (finding_id,))

                row = cursor.fetchone()
                conn.close()

                if not row:
                    return None

                return FeedbackEntry(
                    finding_id=row[0],
                    verdict=row[1],
                    reason=row[2],
                    timestamp=row[3],
                    source=row[4],
                    metadata=json.loads(row[5]) if row[5] else {}
                )

        except Exception as e:
            logger.error(f"Failed to retrieve feedback: {e}")
            return None

    def get_false_positive_rate(
        self,
        scanner: Optional[str] = None,
        category: Optional[str] = None,
        days: Optional[int] = None
    ) -> float:
        """
        Calculate false positive rate

        Args:
            scanner: Filter by scanner name (e.g., 'semgrep', 'trivy')
            category: Filter by finding category (e.g., 'sql-injection', 'xss')
            days: Only include feedback from last N days

        Returns:
            False positive rate (0.0 - 1.0)
        """
        try:
            with self._lock:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                # Build query dynamically based on filters
                query = """
                    SELECT
                        COUNT(*) FILTER (WHERE verdict = 'false_positive') as fp_count,
                        COUNT(*) as total_count
                    FROM findings_feedback
                    WHERE 1=1
                """
                params = []

                if scanner:
                    query += " AND scanner = ?"
                    params.append(scanner)

                if category:
                    query += " AND category = ?"
                    params.append(category)

                if days:
                    cutoff_date = (
                        datetime.now(timezone.utc) - timedelta(days=days)
                    ).isoformat()
                    query += " AND timestamp >= ?"
                    params.append(cutoff_date)

                cursor.execute(query, params)
                row = cursor.fetchone()
                conn.close()

                fp_count = row[0] or 0
                total_count = row[1] or 0

                if total_count == 0:
                    return 0.0

                return fp_count / total_count

        except Exception as e:
            logger.error(f"Failed to calculate FP rate: {e}")
            return 0.0

    def get_all_feedback(
        self,
        limit: Optional[int] = None,
        verdict: Optional[str] = None
    ) -> List[FeedbackEntry]:
        """
        Retrieve all feedback entries

        Args:
            limit: Maximum number of entries (most recent first)
            verdict: Filter by verdict type

        Returns:
            List of FeedbackEntry objects
        """
        try:
            with self._lock:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                query = """
                    SELECT finding_id, verdict, reason, timestamp, source, metadata
                    FROM findings_feedback
                """

                params = []
                if verdict:
                    query += " WHERE verdict = ?"
                    params.append(verdict)

                query += " ORDER BY timestamp DESC"

                if limit:
                    query += " LIMIT ?"
                    params.append(limit)

                cursor.execute(query, params)
                rows = cursor.fetchall()
                conn.close()

                return [
                    FeedbackEntry(
                        finding_id=row[0],
                        verdict=row[1],
                        reason=row[2],
                        timestamp=row[3],
                        source=row[4],
                        metadata=json.loads(row[5]) if row[5] else {}
                    )
                    for row in rows
                ]

        except Exception as e:
            logger.error(f"Failed to retrieve feedback: {e}")
            return []

    def export_feedback(
        self,
        format: str = "json",
        output_file: Optional[str] = None
    ) -> str:
        """
        Export feedback data for analysis

        Args:
            format: Export format ('json', 'csv', 'jsonl')
            output_file: Optional output file path

        Returns:
            Exported data as string
        """
        try:
            feedback_entries = self.get_all_feedback()

            if format == "json":
                output = json.dumps(
                    [asdict(entry) for entry in feedback_entries],
                    indent=2
                )

            elif format == "jsonl":
                output = "\n".join(
                    json.dumps(asdict(entry))
                    for entry in feedback_entries
                )

            elif format == "csv":
                # CSV header
                output = "finding_id,verdict,reason,timestamp,source,scanner,category,file_path\n"

                # CSV rows
                for entry in feedback_entries:
                    scanner = entry.metadata.get("scanner", "")
                    category = entry.metadata.get("category", "")
                    file_path = entry.metadata.get("file_path", "")

                    # Escape CSV fields
                    reason = entry.reason.replace('"', '""')

                    output += (
                        f'"{entry.finding_id}","{entry.verdict}","{reason}",'
                        f'"{entry.timestamp}","{entry.source}",'
                        f'"{scanner}","{category}","{file_path}"\n'
                    )

            else:
                raise ValueError(f"Unsupported format: {format}")

            # Write to file if specified
            if output_file:
                with open(output_file, "w") as f:
                    f.write(output)
                logger.info(f"Exported feedback to {output_file}")

            return output

        except Exception as e:
            logger.error(f"Failed to export feedback: {e}")
            return ""

    def get_patterns(self, min_occurrences: int = 3) -> Dict[str, List[Dict[str, Any]]]:
        """
        Identify common false positive patterns

        Analyzes feedback reasons to find recurring patterns like:
        - "test file" / "test code"
        - "CLI console.log for debugging"
        - "development environment only"
        - "intentional example code"

        Args:
            min_occurrences: Minimum number of occurrences to consider a pattern

        Returns:
            Dictionary mapping pattern names to example findings
        """
        try:
            # Get all false positive feedback
            fp_feedback = self.get_all_feedback(verdict="false_positive")

            # Pattern detection
            patterns = defaultdict(list)

            for entry in fp_feedback:
                reason_lower = entry.reason.lower()

                # Test file patterns
                if any(keyword in reason_lower for keyword in [
                    "test file", "test code", "unit test", "test fixture",
                    "test data", "mock", "stub", "tests/"
                ]):
                    patterns["test_files"].append({
                        "finding_id": entry.finding_id,
                        "reason": entry.reason,
                        "file_path": entry.metadata.get("file_path", "")
                    })

                # CLI/Debug patterns
                if any(keyword in reason_lower for keyword in [
                    "console.log", "debug", "logging", "cli tool",
                    "command line", "print statement"
                ]):
                    patterns["cli_debug"].append({
                        "finding_id": entry.finding_id,
                        "reason": entry.reason,
                        "file_path": entry.metadata.get("file_path", "")
                    })

                # Development environment patterns
                if any(keyword in reason_lower for keyword in [
                    "development only", "dev environment", "local development",
                    "dev mode", "not production"
                ]):
                    patterns["dev_environment"].append({
                        "finding_id": entry.finding_id,
                        "reason": entry.reason,
                        "file_path": entry.metadata.get("file_path", "")
                    })

                # Example/Documentation patterns
                if any(keyword in reason_lower for keyword in [
                    "example", "documentation", "sample code",
                    "tutorial", "demo", "illustration"
                ]):
                    patterns["examples_docs"].append({
                        "finding_id": entry.finding_id,
                        "reason": entry.reason,
                        "file_path": entry.metadata.get("file_path", "")
                    })

                # Intentional/By design patterns
                if any(keyword in reason_lower for keyword in [
                    "intentional", "by design", "expected behavior",
                    "false alarm", "not a vulnerability"
                ]):
                    patterns["intentional"].append({
                        "finding_id": entry.finding_id,
                        "reason": entry.reason,
                        "file_path": entry.metadata.get("file_path", "")
                    })

                # Third-party/vendor code patterns
                if any(keyword in reason_lower for keyword in [
                    "third party", "vendor", "library code",
                    "node_modules", "vendor/", "external"
                ]):
                    patterns["third_party"].append({
                        "finding_id": entry.finding_id,
                        "reason": entry.reason,
                        "file_path": entry.metadata.get("file_path", "")
                    })

            # Filter patterns by minimum occurrences
            filtered_patterns = {
                pattern_name: examples
                for pattern_name, examples in patterns.items()
                if len(examples) >= min_occurrences
            }

            return filtered_patterns

        except Exception as e:
            logger.error(f"Failed to detect patterns: {e}")
            return {}

    def get_improvement_metrics(self, window_days: int = 30) -> Dict[str, Any]:
        """
        Track FP rate improvements over time

        Compares false positive rates across time windows to show improvement trends

        Args:
            window_days: Size of time window for comparison (default: 30 days)

        Returns:
            Dictionary with improvement metrics:
            - current_fp_rate: FP rate in most recent window
            - previous_fp_rate: FP rate in previous window
            - improvement: Percentage improvement (positive = better)
            - trend: "improving", "stable", or "worsening"
            - by_scanner: Per-scanner breakdown
        """
        try:
            # Calculate FP rates for different time windows
            current_fp_rate = self.get_false_positive_rate(days=window_days)
            previous_fp_rate = self.get_false_positive_rate(days=window_days * 2)

            # Calculate improvement
            if previous_fp_rate > 0:
                improvement_pct = (
                    (previous_fp_rate - current_fp_rate) / previous_fp_rate * 100
                )
            else:
                improvement_pct = 0.0

            # Determine trend
            if improvement_pct > 5:
                trend = "improving"
            elif improvement_pct < -5:
                trend = "worsening"
            else:
                trend = "stable"

            # Get per-scanner metrics
            with self._lock:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT DISTINCT scanner
                    FROM findings_feedback
                    WHERE scanner IS NOT NULL
                """)

                scanners = [row[0] for row in cursor.fetchall()]
                conn.close()

            by_scanner = {}
            for scanner in scanners:
                current = self.get_false_positive_rate(scanner=scanner, days=window_days)
                previous = self.get_false_positive_rate(scanner=scanner, days=window_days * 2)

                if previous > 0:
                    improvement = (previous - current) / previous * 100
                else:
                    improvement = 0.0

                by_scanner[scanner] = {
                    "current_fp_rate": round(current, 3),
                    "previous_fp_rate": round(previous, 3),
                    "improvement_pct": round(improvement, 2)
                }

            return {
                "window_days": window_days,
                "current_fp_rate": round(current_fp_rate, 3),
                "previous_fp_rate": round(previous_fp_rate, 3),
                "improvement_pct": round(improvement_pct, 2),
                "trend": trend,
                "by_scanner": by_scanner
            }

        except Exception as e:
            logger.error(f"Failed to calculate improvement metrics: {e}")
            return {}

    def get_top_false_positive_patterns(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Find most common causes of false positives

        Args:
            limit: Number of top patterns to return

        Returns:
            List of patterns with counts, sorted by frequency
        """
        try:
            patterns = self.get_patterns(min_occurrences=1)

            # Count occurrences for each pattern
            pattern_counts = [
                {
                    "pattern": pattern_name,
                    "count": len(examples),
                    "examples": examples[:3]  # Include top 3 examples
                }
                for pattern_name, examples in patterns.items()
            ]

            # Sort by count descending
            pattern_counts.sort(key=lambda x: x["count"], reverse=True)

            return pattern_counts[:limit]

        except Exception as e:
            logger.error(f"Failed to get top patterns: {e}")
            return []

    def suggest_rule_adjustments(self) -> List[Dict[str, Any]]:
        """
        Generate AI-powered suggestions to reduce false positives

        Analyzes feedback patterns and suggests scanner rule adjustments

        Returns:
            List of rule adjustment suggestions with rationale
        """
        try:
            patterns = self.get_patterns(min_occurrences=3)
            suggestions = []

            # Test file exclusions
            if "test_files" in patterns and len(patterns["test_files"]) >= 5:
                test_files = patterns["test_files"]
                test_paths = [ex.get("file_path", "") for ex in test_files]

                # Find common path patterns
                common_patterns = self._find_common_path_patterns(test_paths)

                suggestions.append({
                    "type": "exclude_paths",
                    "rationale": f"Found {len(test_files)} FPs in test files",
                    "action": "Add path exclusions to scanner configuration",
                    "suggested_patterns": common_patterns,
                    "impact": f"Could eliminate ~{len(test_files)} false positives"
                })

            # CLI/Debug code exclusions
            if "cli_debug" in patterns and len(patterns["cli_debug"]) >= 3:
                cli_findings = patterns["cli_debug"]

                suggestions.append({
                    "type": "rule_refinement",
                    "rationale": f"Found {len(cli_findings)} FPs in CLI/debug code",
                    "action": "Refine rules to exclude intentional console output",
                    "suggested_rules": [
                        "Exclude console.log in CLI tools (*.cli.js, bin/*)",
                        "Exclude debug logging in development files"
                    ],
                    "impact": f"Could eliminate ~{len(cli_findings)} false positives"
                })

            # Third-party code exclusions
            if "third_party" in patterns and len(patterns["third_party"]) >= 3:
                third_party = patterns["third_party"]
                vendor_paths = [ex.get("file_path", "") for ex in third_party]

                common_patterns = self._find_common_path_patterns(vendor_paths)

                suggestions.append({
                    "type": "exclude_paths",
                    "rationale": f"Found {len(third_party)} FPs in third-party code",
                    "action": "Exclude vendor/library directories",
                    "suggested_patterns": common_patterns,
                    "impact": f"Could eliminate ~{len(third_party)} false positives"
                })

            # Example/documentation code
            if "examples_docs" in patterns and len(patterns["examples_docs"]) >= 3:
                examples = patterns["examples_docs"]

                suggestions.append({
                    "type": "exclude_paths",
                    "rationale": f"Found {len(examples)} FPs in documentation/examples",
                    "action": "Exclude example and documentation code",
                    "suggested_patterns": ["examples/", "docs/", "*.example.*"],
                    "impact": f"Could eliminate ~{len(examples)} false positives"
                })

            return suggestions

        except Exception as e:
            logger.error(f"Failed to generate suggestions: {e}")
            return []

    def _find_common_path_patterns(self, paths: List[str]) -> List[str]:
        """
        Extract common path patterns from file paths

        Args:
            paths: List of file paths

        Returns:
            List of common path patterns (e.g., "tests/", "node_modules/")
        """
        if not paths:
            return []

        # Count path segments
        segment_counts = defaultdict(int)

        for path in paths:
            if not path:
                continue

            # Extract directory segments
            parts = Path(path).parts

            for i, part in enumerate(parts):
                # Count directory names (not files)
                if i < len(parts) - 1:
                    segment_counts[part + "/"] += 1

        # Find segments that appear in >50% of paths
        min_count = max(len(paths) // 2, 2)
        common_segments = [
            segment for segment, count in segment_counts.items()
            if count >= min_count
        ]

        return sorted(common_segments, key=lambda x: segment_counts[x], reverse=True)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get overall feedback statistics

        Returns:
            Dictionary with summary statistics
        """
        try:
            with self._lock:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                # Total feedback count
                cursor.execute("SELECT COUNT(*) FROM findings_feedback")
                total_count = cursor.fetchone()[0]

                # Verdict breakdown
                cursor.execute("""
                    SELECT verdict, COUNT(*) as count
                    FROM findings_feedback
                    GROUP BY verdict
                    ORDER BY count DESC
                """)
                verdict_counts = {row[0]: row[1] for row in cursor.fetchall()}

                # Scanner breakdown
                cursor.execute("""
                    SELECT scanner, COUNT(*) as count
                    FROM findings_feedback
                    WHERE scanner IS NOT NULL
                    GROUP BY scanner
                    ORDER BY count DESC
                """)
                scanner_counts = {row[0]: row[1] for row in cursor.fetchall()}

                # Source breakdown
                cursor.execute("""
                    SELECT source, COUNT(*) as count
                    FROM findings_feedback
                    GROUP BY source
                    ORDER BY count DESC
                """)
                source_counts = {row[0]: row[1] for row in cursor.fetchall()}

                # Recent feedback (last 7 days)
                cutoff_date = (
                    datetime.now(timezone.utc) - timedelta(days=7)
                ).isoformat()

                cursor.execute("""
                    SELECT COUNT(*)
                    FROM findings_feedback
                    WHERE timestamp >= ?
                """, (cutoff_date,))
                recent_count = cursor.fetchone()[0]

                conn.close()

                # Calculate FP rate
                fp_rate = self.get_false_positive_rate()

                return {
                    "total_feedback": total_count,
                    "verdict_counts": verdict_counts,
                    "scanner_counts": scanner_counts,
                    "source_counts": source_counts,
                    "recent_7_days": recent_count,
                    "overall_fp_rate": round(fp_rate, 3)
                }

        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}

    def clear_feedback(self, finding_id: Optional[str] = None) -> int:
        """
        Clear feedback entries

        Args:
            finding_id: If provided, only clear this finding's feedback.
                       If None, clear all feedback.

        Returns:
            Number of entries deleted
        """
        try:
            with self._lock:
                conn = sqlite3.connect(str(self.db_path))
                cursor = conn.cursor()

                if finding_id:
                    cursor.execute(
                        "DELETE FROM findings_feedback WHERE finding_id = ?",
                        (finding_id,)
                    )
                else:
                    cursor.execute("DELETE FROM findings_feedback")

                deleted_count = cursor.rowcount
                conn.commit()
                conn.close()

                logger.info(f"Cleared {deleted_count} feedback entries")
                return deleted_count

        except Exception as e:
            logger.error(f"Failed to clear feedback: {e}")
            return 0


def print_feedback_stats(tracker: FeedbackTracker) -> None:
    """Print formatted feedback statistics"""
    stats = tracker.get_stats()

    print("\n" + "=" * 60)
    print("FEEDBACK TRACKER STATISTICS")
    print("=" * 60)
    print(f"Total Feedback Entries: {stats.get('total_feedback', 0)}")
    print(f"Recent (7 days):        {stats.get('recent_7_days', 0)}")
    print(f"Overall FP Rate:        {stats.get('overall_fp_rate', 0):.1%}")

    verdict_counts = stats.get('verdict_counts', {})
    if verdict_counts:
        print(f"\nVerdict Breakdown:")
        for verdict, count in verdict_counts.items():
            print(f"  {verdict}: {count}")

    scanner_counts = stats.get('scanner_counts', {})
    if scanner_counts:
        print(f"\nBy Scanner:")
        for scanner, count in scanner_counts.items():
            print(f"  {scanner}: {count}")

    source_counts = stats.get('source_counts', {})
    if source_counts:
        print(f"\nBy Source:")
        for source, count in source_counts.items():
            print(f"  {source}: {count}")

    print("=" * 60 + "\n")


def main():
    """CLI interface for feedback tracking"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Manage security finding feedback"
    )
    parser.add_argument(
        "--cache-dir",
        default=".argus-cache",
        help="Cache directory path (default: .argus-cache)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Record command
    record_parser = subparsers.add_parser("record", help="Record feedback for a finding")
    record_parser.add_argument("finding_id", help="Finding identifier")
    record_parser.add_argument(
        "--verdict",
        required=True,
        choices=["true_positive", "false_positive", "wont_fix", "duplicate"],
        help="Verdict for the finding"
    )
    record_parser.add_argument("--reason", required=True, help="Reason for verdict")
    record_parser.add_argument(
        "--source",
        default="manual",
        help="Feedback source (default: manual)"
    )
    record_parser.add_argument(
        "--scanner",
        help="Scanner name (for metadata)"
    )
    record_parser.add_argument(
        "--category",
        help="Finding category (for metadata)"
    )

    # Stats command
    subparsers.add_parser("stats", help="Show feedback statistics")

    # FP rate command
    fp_rate_parser = subparsers.add_parser("fp-rate", help="Calculate FP rate")
    fp_rate_parser.add_argument("--scanner", help="Filter by scanner")
    fp_rate_parser.add_argument("--category", help="Filter by category")
    fp_rate_parser.add_argument("--days", type=int, help="Last N days")

    # Patterns command
    patterns_parser = subparsers.add_parser("patterns", help="Identify FP patterns")
    patterns_parser.add_argument(
        "--min-occurrences",
        type=int,
        default=3,
        help="Minimum occurrences (default: 3)"
    )

    # Suggest command
    subparsers.add_parser("suggest", help="Suggest rule adjustments")

    # Improvement command
    improvement_parser = subparsers.add_parser(
        "improvement",
        help="Show improvement metrics"
    )
    improvement_parser.add_argument(
        "--window-days",
        type=int,
        default=30,
        help="Time window in days (default: 30)"
    )

    # Export command
    export_parser = subparsers.add_parser("export", help="Export feedback data")
    export_parser.add_argument(
        "--format",
        choices=["json", "csv", "jsonl"],
        default="json",
        help="Export format (default: json)"
    )
    export_parser.add_argument("--output", help="Output file path")

    # Clear command
    clear_parser = subparsers.add_parser("clear", help="Clear feedback")
    clear_parser.add_argument("--finding-id", help="Clear specific finding")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Initialize feedback tracker
    tracker = FeedbackTracker(cache_dir=args.cache_dir)

    if args.command == "record":
        metadata = {}
        if args.scanner:
            metadata["scanner"] = args.scanner
        if args.category:
            metadata["category"] = args.category

        success = tracker.record_feedback(
            finding_id=args.finding_id,
            verdict=args.verdict,
            reason=args.reason,
            source=args.source,
            metadata=metadata
        )

        if success:
            print(f"✓ Recorded feedback for {args.finding_id}")
        else:
            print(f"✗ Failed to record feedback")
            return 1

    elif args.command == "stats":
        print_feedback_stats(tracker)

    elif args.command == "fp-rate":
        fp_rate = tracker.get_false_positive_rate(
            scanner=args.scanner,
            category=args.category,
            days=args.days
        )
        print(f"\nFalse Positive Rate: {fp_rate:.1%}\n")

    elif args.command == "patterns":
        patterns = tracker.get_patterns(min_occurrences=args.min_occurrences)

        print("\n" + "=" * 60)
        print("FALSE POSITIVE PATTERNS")
        print("=" * 60)

        if not patterns:
            print("No patterns found.")
        else:
            for pattern_name, examples in patterns.items():
                print(f"\n{pattern_name.upper()} ({len(examples)} occurrences):")
                for i, example in enumerate(examples[:3], 1):
                    print(f"  {i}. {example['reason'][:60]}")
                    if example.get('file_path'):
                        print(f"     File: {example['file_path']}")

        print("=" * 60 + "\n")

    elif args.command == "suggest":
        suggestions = tracker.suggest_rule_adjustments()

        print("\n" + "=" * 60)
        print("RULE ADJUSTMENT SUGGESTIONS")
        print("=" * 60)

        if not suggestions:
            print("\nNo suggestions available (need more feedback data).\n")
        else:
            for i, suggestion in enumerate(suggestions, 1):
                print(f"\n{i}. {suggestion['type'].upper()}")
                print(f"   Rationale: {suggestion['rationale']}")
                print(f"   Action: {suggestion['action']}")
                print(f"   Impact: {suggestion['impact']}")

                if 'suggested_patterns' in suggestion:
                    print(f"   Suggested patterns: {', '.join(suggestion['suggested_patterns'])}")

                if 'suggested_rules' in suggestion:
                    print(f"   Suggested rules:")
                    for rule in suggestion['suggested_rules']:
                        print(f"     - {rule}")

        print("=" * 60 + "\n")

    elif args.command == "improvement":
        metrics = tracker.get_improvement_metrics(window_days=args.window_days)

        print("\n" + "=" * 60)
        print("IMPROVEMENT METRICS")
        print("=" * 60)
        print(f"Time Window: {metrics.get('window_days')} days")
        print(f"Current FP Rate:  {metrics.get('current_fp_rate', 0):.1%}")
        print(f"Previous FP Rate: {metrics.get('previous_fp_rate', 0):.1%}")
        print(f"Improvement:      {metrics.get('improvement_pct', 0):+.1f}%")
        print(f"Trend:            {metrics.get('trend', 'unknown').upper()}")

        by_scanner = metrics.get('by_scanner', {})
        if by_scanner:
            print(f"\nBy Scanner:")
            for scanner, scanner_metrics in by_scanner.items():
                print(f"  {scanner}:")
                print(f"    Current:     {scanner_metrics['current_fp_rate']:.1%}")
                print(f"    Previous:    {scanner_metrics['previous_fp_rate']:.1%}")
                print(f"    Improvement: {scanner_metrics['improvement_pct']:+.1f}%")

        print("=" * 60 + "\n")

    elif args.command == "export":
        output = tracker.export_feedback(
            format=args.format,
            output_file=args.output
        )

        if args.output:
            print(f"✓ Exported feedback to {args.output}")
        else:
            print(output)

    elif args.command == "clear":
        deleted = tracker.clear_feedback(finding_id=args.finding_id)
        print(f"Cleared {deleted} feedback entries")

    return 0


if __name__ == "__main__":
    exit(main())
