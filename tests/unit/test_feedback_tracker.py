#!/usr/bin/env python3
"""
Unit tests for Feedback Tracker
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import sqlite3

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from feedback_tracker import (
    FeedbackEntry,
    FeedbackTracker,
    print_feedback_stats,
)


class TestFeedbackEntry:
    """Test FeedbackEntry dataclass"""

    def test_valid_feedback_entry(self):
        """Test creating valid feedback entry"""
        entry = FeedbackEntry(
            finding_id="semgrep-abc123",
            verdict="false_positive",
            reason="Test file, not production code",
            source="manual",
            metadata={"scanner": "semgrep", "category": "sql-injection"}
        )

        assert entry.finding_id == "semgrep-abc123"
        assert entry.verdict == "false_positive"
        assert entry.reason == "Test file, not production code"
        assert entry.source == "manual"
        assert entry.metadata["scanner"] == "semgrep"
        assert entry.metadata["category"] == "sql-injection"

    def test_invalid_verdict(self):
        """Test that invalid verdicts raise ValueError"""
        with pytest.raises(ValueError, match="Invalid verdict"):
            FeedbackEntry(
                finding_id="test-123",
                verdict="invalid_verdict",
                reason="Test"
            )

    def test_valid_verdicts(self):
        """Test all valid verdict types"""
        valid_verdicts = ["true_positive", "false_positive", "wont_fix", "duplicate"]

        for verdict in valid_verdicts:
            entry = FeedbackEntry(
                finding_id=f"test-{verdict}",
                verdict=verdict,
                reason="Test reason"
            )
            assert entry.verdict == verdict

    def test_default_timestamp(self):
        """Test that timestamp is auto-generated"""
        entry = FeedbackEntry(
            finding_id="test-123",
            verdict="true_positive",
            reason="Test"
        )

        # Verify timestamp is ISO 8601 format
        timestamp = datetime.fromisoformat(entry.timestamp)
        assert isinstance(timestamp, datetime)

    def test_default_source(self):
        """Test default source is 'manual'"""
        entry = FeedbackEntry(
            finding_id="test-123",
            verdict="true_positive",
            reason="Test"
        )

        assert entry.source == "manual"

    def test_default_metadata(self):
        """Test default metadata is empty dict"""
        entry = FeedbackEntry(
            finding_id="test-123",
            verdict="true_positive",
            reason="Test"
        )

        assert entry.metadata == {}


class TestFeedbackTrackerInitialization:
    """Test FeedbackTracker initialization and database setup"""

    def test_initialization_creates_database(self):
        """Test that initialization creates database file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            db_path = Path(tmpdir) / "feedback.db"
            assert db_path.exists()

    def test_initialization_creates_schema(self):
        """Test that initialization creates correct schema"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            conn = sqlite3.connect(str(tracker.db_path))
            cursor = conn.cursor()

            # Check table exists
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='findings_feedback'
            """)
            assert cursor.fetchone() is not None

            # Check columns
            cursor.execute("PRAGMA table_info(findings_feedback)")
            columns = {row[1] for row in cursor.fetchall()}

            expected_columns = {
                "finding_id", "verdict", "reason", "timestamp",
                "source", "metadata", "scanner", "category", "file_path"
            }
            assert columns == expected_columns

            conn.close()

    def test_initialization_creates_indexes(self):
        """Test that initialization creates indexes"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            conn = sqlite3.connect(str(tracker.db_path))
            cursor = conn.cursor()

            # Check indexes exist
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='index'
            """)
            indexes = {row[0] for row in cursor.fetchall()}

            expected_indexes = {
                "idx_verdict", "idx_scanner", "idx_category", "idx_timestamp"
            }
            assert expected_indexes.issubset(indexes)

            conn.close()

    def test_custom_db_name(self):
        """Test custom database name"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir, db_name="custom.db")

            db_path = Path(tmpdir) / "custom.db"
            assert db_path.exists()


class TestRecordFeedback:
    """Test feedback recording functionality"""

    def test_record_simple_feedback(self):
        """Test recording basic feedback"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            success = tracker.record_feedback(
                finding_id="test-123",
                verdict="false_positive",
                reason="Test file"
            )

            assert success is True

            # Verify stored in database
            entry = tracker.get_feedback_for_finding("test-123")
            assert entry is not None
            assert entry.finding_id == "test-123"
            assert entry.verdict == "false_positive"
            assert entry.reason == "Test file"

    def test_record_feedback_with_metadata(self):
        """Test recording feedback with metadata"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            metadata = {
                "scanner": "semgrep",
                "category": "sql-injection",
                "file_path": "/app/test_db.py"
            }

            success = tracker.record_feedback(
                finding_id="semgrep-abc123",
                verdict="false_positive",
                reason="Test file with mock database",
                source="pr_comment",
                metadata=metadata
            )

            assert success is True

            # Verify metadata stored
            entry = tracker.get_feedback_for_finding("semgrep-abc123")
            assert entry.metadata["scanner"] == "semgrep"
            assert entry.metadata["category"] == "sql-injection"
            assert entry.metadata["file_path"] == "/app/test_db.py"
            assert entry.source == "pr_comment"

    def test_record_feedback_update_existing(self):
        """Test updating existing feedback"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record initial feedback
            tracker.record_feedback(
                finding_id="test-123",
                verdict="false_positive",
                reason="Initial reason"
            )

            # Update feedback
            tracker.record_feedback(
                finding_id="test-123",
                verdict="true_positive",
                reason="Updated reason - this is actually a vulnerability"
            )

            # Verify updated
            entry = tracker.get_feedback_for_finding("test-123")
            assert entry.verdict == "true_positive"
            assert entry.reason == "Updated reason - this is actually a vulnerability"

    def test_record_invalid_verdict(self):
        """Test that invalid verdicts are rejected"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            success = tracker.record_feedback(
                finding_id="test-123",
                verdict="invalid_verdict",
                reason="Test"
            )

            assert success is False

    def test_record_multiple_findings(self):
        """Test recording multiple findings"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            findings = [
                ("test-1", "true_positive", "Real vulnerability"),
                ("test-2", "false_positive", "Test file"),
                ("test-3", "wont_fix", "Low severity"),
                ("test-4", "duplicate", "Same as test-1"),
            ]

            for finding_id, verdict, reason in findings:
                tracker.record_feedback(finding_id, verdict, reason)

            # Verify all stored
            for finding_id, verdict, reason in findings:
                entry = tracker.get_feedback_for_finding(finding_id)
                assert entry is not None
                assert entry.verdict == verdict


class TestGetFeedback:
    """Test feedback retrieval functionality"""

    def test_get_nonexistent_feedback(self):
        """Test getting feedback for non-existent finding"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            entry = tracker.get_feedback_for_finding("nonexistent")
            assert entry is None

    def test_get_all_feedback(self):
        """Test getting all feedback entries"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record multiple entries
            for i in range(5):
                tracker.record_feedback(
                    finding_id=f"test-{i}",
                    verdict="false_positive",
                    reason=f"Reason {i}"
                )

            entries = tracker.get_all_feedback()
            assert len(entries) == 5

    def test_get_all_feedback_with_limit(self):
        """Test getting limited number of entries"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record 10 entries
            for i in range(10):
                tracker.record_feedback(
                    finding_id=f"test-{i}",
                    verdict="false_positive",
                    reason=f"Reason {i}"
                )

            entries = tracker.get_all_feedback(limit=3)
            assert len(entries) == 3

    def test_get_all_feedback_by_verdict(self):
        """Test filtering feedback by verdict"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record mixed verdicts
            tracker.record_feedback("test-1", "true_positive", "Real issue")
            tracker.record_feedback("test-2", "false_positive", "Test file")
            tracker.record_feedback("test-3", "false_positive", "Example code")
            tracker.record_feedback("test-4", "wont_fix", "Low priority")

            fp_entries = tracker.get_all_feedback(verdict="false_positive")
            assert len(fp_entries) == 2

            tp_entries = tracker.get_all_feedback(verdict="true_positive")
            assert len(tp_entries) == 1

    def test_get_all_feedback_ordering(self):
        """Test that feedback is returned in reverse chronological order"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record entries with small delays to ensure different timestamps
            import time
            for i in range(3):
                tracker.record_feedback(
                    finding_id=f"test-{i}",
                    verdict="false_positive",
                    reason=f"Reason {i}"
                )
                time.sleep(0.01)

            entries = tracker.get_all_feedback()

            # Most recent should be first
            assert entries[0].finding_id == "test-2"
            assert entries[1].finding_id == "test-1"
            assert entries[2].finding_id == "test-0"


class TestFalsePositiveRate:
    """Test FP rate calculation"""

    def test_fp_rate_no_data(self):
        """Test FP rate with no feedback data"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            fp_rate = tracker.get_false_positive_rate()
            assert fp_rate == 0.0

    def test_fp_rate_all_true_positives(self):
        """Test FP rate when all findings are true positives"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            for i in range(5):
                tracker.record_feedback(
                    finding_id=f"test-{i}",
                    verdict="true_positive",
                    reason="Real issue"
                )

            fp_rate = tracker.get_false_positive_rate()
            assert fp_rate == 0.0

    def test_fp_rate_all_false_positives(self):
        """Test FP rate when all findings are false positives"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            for i in range(5):
                tracker.record_feedback(
                    finding_id=f"test-{i}",
                    verdict="false_positive",
                    reason="Test file"
                )

            fp_rate = tracker.get_false_positive_rate()
            assert fp_rate == 1.0

    def test_fp_rate_mixed(self):
        """Test FP rate with mixed verdicts"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # 3 FP, 2 TP = 60% FP rate
            tracker.record_feedback("test-1", "false_positive", "Test")
            tracker.record_feedback("test-2", "false_positive", "Test")
            tracker.record_feedback("test-3", "false_positive", "Test")
            tracker.record_feedback("test-4", "true_positive", "Real")
            tracker.record_feedback("test-5", "true_positive", "Real")

            fp_rate = tracker.get_false_positive_rate()
            assert fp_rate == 0.6

    def test_fp_rate_by_scanner(self):
        """Test FP rate filtered by scanner"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Semgrep: 2 FP, 1 TP (66.6% FP)
            tracker.record_feedback(
                "semgrep-1", "false_positive", "Test",
                metadata={"scanner": "semgrep"}
            )
            tracker.record_feedback(
                "semgrep-2", "false_positive", "Test",
                metadata={"scanner": "semgrep"}
            )
            tracker.record_feedback(
                "semgrep-3", "true_positive", "Real",
                metadata={"scanner": "semgrep"}
            )

            # Trivy: 0 FP, 2 TP (0% FP)
            tracker.record_feedback(
                "trivy-1", "true_positive", "Real",
                metadata={"scanner": "trivy"}
            )
            tracker.record_feedback(
                "trivy-2", "true_positive", "Real",
                metadata={"scanner": "trivy"}
            )

            semgrep_fp_rate = tracker.get_false_positive_rate(scanner="semgrep")
            assert abs(semgrep_fp_rate - 0.6667) < 0.01

            trivy_fp_rate = tracker.get_false_positive_rate(scanner="trivy")
            assert trivy_fp_rate == 0.0

    def test_fp_rate_by_category(self):
        """Test FP rate filtered by category"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # SQL injection: 1 FP, 1 TP (50% FP)
            tracker.record_feedback(
                "test-1", "false_positive", "Test",
                metadata={"category": "sql-injection"}
            )
            tracker.record_feedback(
                "test-2", "true_positive", "Real",
                metadata={"category": "sql-injection"}
            )

            # XSS: 0 FP, 1 TP (0% FP)
            tracker.record_feedback(
                "test-3", "true_positive", "Real",
                metadata={"category": "xss"}
            )

            sql_fp_rate = tracker.get_false_positive_rate(category="sql-injection")
            assert sql_fp_rate == 0.5

            xss_fp_rate = tracker.get_false_positive_rate(category="xss")
            assert xss_fp_rate == 0.0

    def test_fp_rate_by_time_window(self):
        """Test FP rate filtered by time window"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record old feedback (40 days ago)
            old_timestamp = (
                datetime.now(timezone.utc) - timedelta(days=40)
            ).isoformat()

            conn = sqlite3.connect(str(tracker.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO findings_feedback
                (finding_id, verdict, reason, timestamp, source, metadata, scanner, category, file_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("old-1", "false_positive", "Old FP", old_timestamp, "manual", "{}", None, None, None))

            conn.commit()
            conn.close()

            # Record recent feedback (5 days ago)
            tracker.record_feedback("recent-1", "true_positive", "Recent TP")
            tracker.record_feedback("recent-2", "true_positive", "Recent TP")

            # Overall FP rate: 33.3%
            overall_fp_rate = tracker.get_false_positive_rate()
            assert abs(overall_fp_rate - 0.3333) < 0.01

            # Last 30 days FP rate: 0% (only recent TPs)
            recent_fp_rate = tracker.get_false_positive_rate(days=30)
            assert recent_fp_rate == 0.0


class TestPatternDetection:
    """Test false positive pattern detection"""

    def test_test_file_pattern(self):
        """Test detection of test file pattern"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record multiple test file FPs
            for i in range(5):
                tracker.record_feedback(
                    f"test-{i}",
                    "false_positive",
                    "This is a test file, not production code"
                )

            patterns = tracker.get_patterns(min_occurrences=3)
            assert "test_files" in patterns
            assert len(patterns["test_files"]) == 5

    def test_cli_debug_pattern(self):
        """Test detection of CLI/debug pattern"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record CLI debug FPs
            tracker.record_feedback(
                "test-1", "false_positive",
                "Intentional console.log in CLI tool"
            )
            tracker.record_feedback(
                "test-2", "false_positive",
                "Debug logging for development"
            )
            tracker.record_feedback(
                "test-3", "false_positive",
                "Print statement for command line output"
            )

            patterns = tracker.get_patterns(min_occurrences=3)
            assert "cli_debug" in patterns
            assert len(patterns["cli_debug"]) == 3

    def test_dev_environment_pattern(self):
        """Test detection of dev environment pattern"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record dev environment FPs
            for i in range(4):
                tracker.record_feedback(
                    f"test-{i}", "false_positive",
                    "Development only, not used in production"
                )

            patterns = tracker.get_patterns(min_occurrences=3)
            assert "dev_environment" in patterns
            assert len(patterns["dev_environment"]) == 4

    def test_examples_docs_pattern(self):
        """Test detection of examples/docs pattern"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record example code FPs
            tracker.record_feedback("test-1", "false_positive", "Example code in documentation")
            tracker.record_feedback("test-2", "false_positive", "Sample code for tutorial")
            tracker.record_feedback("test-3", "false_positive", "Demo application")

            patterns = tracker.get_patterns(min_occurrences=3)
            assert "examples_docs" in patterns

    def test_third_party_pattern(self):
        """Test detection of third-party code pattern"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record third-party FPs
            tracker.record_feedback("test-1", "false_positive", "Third party library code")
            tracker.record_feedback("test-2", "false_positive", "Vendor dependency in node_modules")
            tracker.record_feedback("test-3", "false_positive", "External library, not our code")

            patterns = tracker.get_patterns(min_occurrences=3)
            assert "third_party" in patterns

    def test_min_occurrences_filter(self):
        """Test that min_occurrences filters patterns correctly"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record 2 test file FPs (below min_occurrences=3)
            tracker.record_feedback("test-1", "false_positive", "Test file")
            tracker.record_feedback("test-2", "false_positive", "Unit test")

            # Record 5 CLI debug FPs (above min_occurrences=3)
            for i in range(5):
                tracker.record_feedback(f"cli-{i}", "false_positive", "Console.log in CLI")

            patterns = tracker.get_patterns(min_occurrences=3)

            # test_files should not appear (only 2 occurrences)
            assert "test_files" not in patterns

            # cli_debug should appear (5 occurrences)
            assert "cli_debug" in patterns


class TestExportFeedback:
    """Test feedback export functionality"""

    def test_export_json(self):
        """Test exporting feedback as JSON"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            tracker.record_feedback("test-1", "false_positive", "Test file")
            tracker.record_feedback("test-2", "true_positive", "Real issue")

            output = tracker.export_feedback(format="json")

            # Parse JSON
            data = json.loads(output)
            assert len(data) == 2
            assert isinstance(data, list)

    def test_export_jsonl(self):
        """Test exporting feedback as JSONL"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            tracker.record_feedback("test-1", "false_positive", "Test file")
            tracker.record_feedback("test-2", "true_positive", "Real issue")

            output = tracker.export_feedback(format="jsonl")

            # Parse JSONL
            lines = output.strip().split("\n")
            assert len(lines) == 2

            for line in lines:
                data = json.loads(line)
                assert "finding_id" in data

    def test_export_csv(self):
        """Test exporting feedback as CSV"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            tracker.record_feedback(
                "test-1", "false_positive", "Test file",
                metadata={"scanner": "semgrep", "category": "sql-injection"}
            )

            output = tracker.export_feedback(format="csv")

            # Check CSV structure
            lines = output.strip().split("\n")
            assert len(lines) == 2  # Header + 1 row

            # Check header
            header = lines[0]
            assert "finding_id" in header
            assert "verdict" in header
            assert "scanner" in header

    def test_export_to_file(self):
        """Test exporting to file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            tracker.record_feedback("test-1", "false_positive", "Test file")

            output_file = Path(tmpdir) / "feedback.json"
            tracker.export_feedback(format="json", output_file=str(output_file))

            assert output_file.exists()

            with open(output_file) as f:
                data = json.load(f)
                assert len(data) == 1

    def test_export_invalid_format(self):
        """Test that invalid format returns empty string"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Invalid format should return empty string after logging error
            output = tracker.export_feedback(format="invalid")
            assert output == ""


class TestImprovementMetrics:
    """Test improvement metrics calculation"""

    def test_improvement_metrics_no_data(self):
        """Test improvement metrics with no data"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            metrics = tracker.get_improvement_metrics(window_days=30)

            assert metrics["current_fp_rate"] == 0.0
            assert metrics["previous_fp_rate"] == 0.0
            assert metrics["improvement_pct"] == 0.0
            assert metrics["trend"] == "stable"

    def test_improvement_metrics_improving(self):
        """Test improvement metrics when FP rate is decreasing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Insert old feedback (50 days ago, high FP rate)
            old_timestamp = (
                datetime.now(timezone.utc) - timedelta(days=50)
            ).isoformat()

            conn = sqlite3.connect(str(tracker.db_path))
            cursor = conn.cursor()

            # Old period: 8 FP, 2 TP = 80% FP rate
            for i in range(8):
                cursor.execute("""
                    INSERT INTO findings_feedback
                    (finding_id, verdict, reason, timestamp, source, metadata, scanner, category, file_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (f"old-fp-{i}", "false_positive", "Old FP", old_timestamp, "manual", "{}", None, None, None))

            for i in range(2):
                cursor.execute("""
                    INSERT INTO findings_feedback
                    (finding_id, verdict, reason, timestamp, source, metadata, scanner, category, file_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (f"old-tp-{i}", "true_positive", "Old TP", old_timestamp, "manual", "{}", None, None, None))

            conn.commit()
            conn.close()

            # Recent feedback (10 days ago, low FP rate)
            # 2 FP, 8 TP = 20% FP rate
            for i in range(2):
                tracker.record_feedback(f"recent-fp-{i}", "false_positive", "Recent FP")
            for i in range(8):
                tracker.record_feedback(f"recent-tp-{i}", "true_positive", "Recent TP")

            metrics = tracker.get_improvement_metrics(window_days=30)

            # Improvement: (80% - 20%) / 80% = 75% improvement
            assert metrics["trend"] == "improving"
            assert metrics["improvement_pct"] > 50

    def test_improvement_metrics_worsening(self):
        """Test improvement metrics when FP rate is increasing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Old period: low FP rate
            old_timestamp = (
                datetime.now(timezone.utc) - timedelta(days=50)
            ).isoformat()

            conn = sqlite3.connect(str(tracker.db_path))
            cursor = conn.cursor()

            # Old: 1 FP, 9 TP = 10% FP rate
            cursor.execute("""
                INSERT INTO findings_feedback
                (finding_id, verdict, reason, timestamp, source, metadata, scanner, category, file_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("old-fp", "false_positive", "Old FP", old_timestamp, "manual", "{}", None, None, None))

            for i in range(9):
                cursor.execute("""
                    INSERT INTO findings_feedback
                    (finding_id, verdict, reason, timestamp, source, metadata, scanner, category, file_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (f"old-tp-{i}", "true_positive", "Old TP", old_timestamp, "manual", "{}", None, None, None))

            conn.commit()
            conn.close()

            # Recent: high FP rate
            # 9 FP, 1 TP = 90% FP rate
            for i in range(9):
                tracker.record_feedback(f"recent-fp-{i}", "false_positive", "Recent FP")
            tracker.record_feedback("recent-tp", "true_positive", "Recent TP")

            metrics = tracker.get_improvement_metrics(window_days=30)

            assert metrics["trend"] == "worsening"
            assert metrics["improvement_pct"] < -50

    def test_improvement_metrics_by_scanner(self):
        """Test improvement metrics broken down by scanner"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Recent Semgrep feedback: low FP
            tracker.record_feedback(
                "semgrep-1", "true_positive", "Real",
                metadata={"scanner": "semgrep"}
            )
            tracker.record_feedback(
                "semgrep-2", "true_positive", "Real",
                metadata={"scanner": "semgrep"}
            )

            # Recent Trivy feedback: high FP
            tracker.record_feedback(
                "trivy-1", "false_positive", "FP",
                metadata={"scanner": "trivy"}
            )
            tracker.record_feedback(
                "trivy-2", "false_positive", "FP",
                metadata={"scanner": "trivy"}
            )

            metrics = tracker.get_improvement_metrics(window_days=30)

            assert "by_scanner" in metrics
            assert "semgrep" in metrics["by_scanner"]
            assert "trivy" in metrics["by_scanner"]

            # Semgrep should have low FP rate
            assert metrics["by_scanner"]["semgrep"]["current_fp_rate"] == 0.0

            # Trivy should have high FP rate
            assert metrics["by_scanner"]["trivy"]["current_fp_rate"] == 1.0


class TestRuleAdjustmentSuggestions:
    """Test AI-powered rule adjustment suggestions"""

    def test_suggest_test_file_exclusions(self):
        """Test suggestion for excluding test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record many test file FPs
            for i in range(10):
                tracker.record_feedback(
                    f"test-{i}", "false_positive",
                    "Test file, not production code",
                    metadata={"file_path": f"tests/test_module_{i}.py"}
                )

            suggestions = tracker.suggest_rule_adjustments()

            # Should suggest test file exclusion
            test_exclusion = next(
                (s for s in suggestions if s["type"] == "exclude_paths" and "test" in s["rationale"].lower()),
                None
            )

            assert test_exclusion is not None
            assert "tests/" in test_exclusion["suggested_patterns"]

    def test_suggest_cli_debug_refinement(self):
        """Test suggestion for CLI debug code refinement"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record CLI debug FPs
            for i in range(5):
                tracker.record_feedback(
                    f"cli-{i}", "false_positive",
                    "Console.log in CLI tool"
                )

            suggestions = tracker.suggest_rule_adjustments()

            # Should suggest rule refinement
            cli_refinement = next(
                (s for s in suggestions if s["type"] == "rule_refinement"),
                None
            )

            assert cli_refinement is not None

    def test_suggest_third_party_exclusions(self):
        """Test suggestion for excluding third-party code"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record third-party FPs
            for i in range(5):
                tracker.record_feedback(
                    f"vendor-{i}", "false_positive",
                    "Third party library code",
                    metadata={"file_path": f"node_modules/pkg-{i}/index.js"}
                )

            suggestions = tracker.suggest_rule_adjustments()

            # Should suggest vendor exclusion
            vendor_exclusion = next(
                (s for s in suggestions if "third-party" in s["rationale"].lower()),
                None
            )

            assert vendor_exclusion is not None
            assert any("node_modules" in p for p in vendor_exclusion["suggested_patterns"])

    def test_no_suggestions_with_insufficient_data(self):
        """Test that no suggestions are made with insufficient data"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record only 1-2 FPs (below threshold)
            tracker.record_feedback("test-1", "false_positive", "Test file")
            tracker.record_feedback("test-2", "false_positive", "CLI debug")

            suggestions = tracker.suggest_rule_adjustments()

            # Should have no suggestions (need min 3 occurrences per pattern)
            assert len(suggestions) == 0


class TestStatistics:
    """Test statistics and analytics"""

    def test_get_stats_empty(self):
        """Test stats with empty database"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            stats = tracker.get_stats()

            assert stats["total_feedback"] == 0
            assert stats["overall_fp_rate"] == 0.0

    def test_get_stats_with_data(self):
        """Test stats with feedback data"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record various feedback
            tracker.record_feedback(
                "test-1", "false_positive", "FP",
                metadata={"scanner": "semgrep"}
            )
            tracker.record_feedback(
                "test-2", "true_positive", "TP",
                metadata={"scanner": "semgrep"}
            )
            tracker.record_feedback(
                "test-3", "wont_fix", "WF",
                metadata={"scanner": "trivy"}
            )

            stats = tracker.get_stats()

            assert stats["total_feedback"] == 3
            assert "verdict_counts" in stats
            assert stats["verdict_counts"]["false_positive"] == 1
            assert stats["verdict_counts"]["true_positive"] == 1
            assert stats["verdict_counts"]["wont_fix"] == 1

            assert "scanner_counts" in stats
            assert stats["scanner_counts"]["semgrep"] == 2
            assert stats["scanner_counts"]["trivy"] == 1

    def test_get_stats_source_breakdown(self):
        """Test stats with source breakdown"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            tracker.record_feedback("test-1", "false_positive", "FP", source="manual")
            tracker.record_feedback("test-2", "true_positive", "TP", source="pr_comment")
            tracker.record_feedback("test-3", "false_positive", "FP", source="github_issue")

            stats = tracker.get_stats()

            assert "source_counts" in stats
            assert stats["source_counts"]["manual"] == 1
            assert stats["source_counts"]["pr_comment"] == 1
            assert stats["source_counts"]["github_issue"] == 1

    def test_recent_7_days(self):
        """Test recent feedback count (last 7 days)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record old feedback (10 days ago)
            old_timestamp = (
                datetime.now(timezone.utc) - timedelta(days=10)
            ).isoformat()

            conn = sqlite3.connect(str(tracker.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO findings_feedback
                (finding_id, verdict, reason, timestamp, source, metadata, scanner, category, file_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ("old-1", "false_positive", "Old", old_timestamp, "manual", "{}", None, None, None))

            conn.commit()
            conn.close()

            # Record recent feedback
            tracker.record_feedback("recent-1", "true_positive", "Recent")
            tracker.record_feedback("recent-2", "false_positive", "Recent")

            stats = tracker.get_stats()

            # Should only count recent feedback
            assert stats["recent_7_days"] == 2


class TestClearFeedback:
    """Test feedback clearing functionality"""

    def test_clear_all_feedback(self):
        """Test clearing all feedback"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Record feedback
            for i in range(5):
                tracker.record_feedback(f"test-{i}", "false_positive", "Test")

            # Verify exists
            assert len(tracker.get_all_feedback()) == 5

            # Clear all
            deleted = tracker.clear_feedback()
            assert deleted == 5

            # Verify cleared
            assert len(tracker.get_all_feedback()) == 0

    def test_clear_specific_finding(self):
        """Test clearing specific finding"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            tracker.record_feedback("test-1", "false_positive", "Test")
            tracker.record_feedback("test-2", "true_positive", "Real")

            # Clear specific finding
            deleted = tracker.clear_feedback(finding_id="test-1")
            assert deleted == 1

            # Verify only test-1 cleared
            assert tracker.get_feedback_for_finding("test-1") is None
            assert tracker.get_feedback_for_finding("test-2") is not None


class TestTopFalsePositivePatterns:
    """Test identifying top FP patterns"""

    def test_top_patterns_sorted_by_frequency(self):
        """Test that top patterns are sorted by frequency"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # 10 test file FPs
            for i in range(10):
                tracker.record_feedback(f"test-{i}", "false_positive", "Test file")

            # 5 CLI debug FPs
            for i in range(5):
                tracker.record_feedback(f"cli-{i}", "false_positive", "Console.log in CLI")

            # 3 example code FPs
            for i in range(3):
                tracker.record_feedback(f"example-{i}", "false_positive", "Example code")

            top_patterns = tracker.get_top_false_positive_patterns(limit=10)

            # Should be sorted by count descending
            assert top_patterns[0]["pattern"] == "test_files"
            assert top_patterns[0]["count"] == 10

            assert top_patterns[1]["pattern"] == "cli_debug"
            assert top_patterns[1]["count"] == 5

            assert top_patterns[2]["pattern"] == "examples_docs"
            assert top_patterns[2]["count"] == 3

    def test_top_patterns_limit(self):
        """Test that limit is respected"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            # Create multiple pattern types
            for i in range(5):
                tracker.record_feedback(f"test-{i}", "false_positive", "Test file")
            for i in range(5):
                tracker.record_feedback(f"cli-{i}", "false_positive", "Console.log")
            for i in range(5):
                tracker.record_feedback(f"dev-{i}", "false_positive", "Development only")

            top_patterns = tracker.get_top_false_positive_patterns(limit=2)

            assert len(top_patterns) == 2

    def test_top_patterns_include_examples(self):
        """Test that top patterns include example findings"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            for i in range(5):
                tracker.record_feedback(
                    f"test-{i}", "false_positive",
                    f"Test file {i}"
                )

            top_patterns = tracker.get_top_false_positive_patterns()

            # Should include up to 3 examples
            assert len(top_patterns[0]["examples"]) <= 3
            assert "reason" in top_patterns[0]["examples"][0]


class TestPrintFeedbackStats:
    """Test stats printing function"""

    def test_print_stats(self, capsys):
        """Test that stats are printed correctly"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tracker = FeedbackTracker(cache_dir=tmpdir)

            tracker.record_feedback(
                "test-1", "false_positive", "FP",
                metadata={"scanner": "semgrep"}
            )
            tracker.record_feedback(
                "test-2", "true_positive", "TP",
                metadata={"scanner": "trivy"}
            )

            print_feedback_stats(tracker)

            captured = capsys.readouterr()
            output = captured.out

            assert "FEEDBACK TRACKER STATISTICS" in output
            assert "Total Feedback Entries: 2" in output
            assert "Verdict Breakdown:" in output
            assert "By Scanner:" in output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
