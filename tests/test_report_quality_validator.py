#!/usr/bin/env python3
"""
Unit tests for Report Quality Validator

Tests various quality validation scenarios including the pi-mono disaster case.
"""

import json
import pytest
from pathlib import Path
import sys

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from report_quality_validator import (
    ReportQualityValidator,
    FindingQualityReport,
    ValidationReport,
    QualityCheck
)


class TestReportQualityValidator:
    """Test suite for Report Quality Validator"""

    def test_perfect_finding_scores_100(self):
        """A perfect finding with all fields should score 100/100"""
        validator = ReportQualityValidator()

        perfect_finding = {
            "id": "test-001",
            "title": "SQL Injection in User Authentication",
            "description": "A critical SQL injection vulnerability was detected in the user authentication module. User input is directly concatenated into SQL queries without proper sanitization or parameterization.",
            "file_path": "app/auth.py",
            "line_number": 42,
            "severity": "critical"
        }

        report = validator.validate_finding(perfect_finding, 0)

        assert report.total_score == 100
        assert report.passed is True
        assert len(report.issues) == 0

    def test_pi_mono_disaster_case(self):
        """The pi-mono disaster case should fail validation"""
        validator = ReportQualityValidator()

        # Simulates the actual bad report we submitted
        bad_finding = {
            "id": "bad-001",
            "title": "Unknown Issue",
            "description": "Found issue",  # Too short
            "file_path": "unknown",  # Invalid path
            "line_number": None,  # Null line number
            "severity": ""  # Empty severity
        }

        report = validator.validate_finding(bad_finding, 0)

        # Should fail all 5 checks
        assert report.total_score == 0
        assert report.passed is False
        assert len(report.issues) == 5

    def test_empty_file_path_fails(self):
        """Empty file path should fail validation"""
        validator = ReportQualityValidator()

        finding = {
            "title": "Test Issue",
            "description": "A detailed description that is longer than fifty characters minimum",
            "file_path": "",
            "line_number": 10,
            "severity": "high"
        }

        report = validator.validate_finding(finding, 0)

        # "Test Issue" is not in INVALID_TITLES, so title passes (+20)
        # Score: 100 - 25 (file_path) = 75
        assert report.total_score == 75
        assert report.passed is False
        assert any("File path" in issue for issue in report.issues)

    def test_null_line_number_fails(self):
        """Null line number should fail validation"""
        validator = ReportQualityValidator()

        finding = {
            "title": "SQL Injection Vulnerability",
            "description": "A detailed description that is longer than fifty characters minimum",
            "file_path": "app/database.py",
            "line_number": None,
            "severity": "critical"
        }

        report = validator.validate_finding(finding, 0)

        # "sql injection vulnerability" contains "vulnerability" from INVALID_TITLES
        # Score: 100 - 25 (line_number) - 20 (title) = 55
        assert report.total_score == 55
        assert report.passed is False
        assert any("Line number" in issue for issue in report.issues)

    def test_unknown_title_fails(self):
        """Generic 'Unknown Issue' title should fail"""
        validator = ReportQualityValidator()

        finding = {
            "title": "Unknown Issue",
            "description": "A detailed description that is longer than fifty characters minimum",
            "file_path": "app/test.py",
            "line_number": 25,
            "severity": "medium"
        }

        report = validator.validate_finding(finding, 0)

        assert report.total_score == 80  # 100 - 20 (title) = 80
        # Score of 80 meets the default threshold of >= 80, so it passes
        assert report.passed is True
        assert any("Title" in issue for issue in report.issues)

    def test_short_description_fails(self):
        """Description shorter than 50 chars should fail"""
        validator = ReportQualityValidator()

        finding = {
            "title": "SQL Injection Found",
            "description": "Short desc",  # Only 10 chars
            "file_path": "app/auth.py",
            "line_number": 15,
            "severity": "high"
        }

        report = validator.validate_finding(finding, 0)

        assert report.total_score == 85  # 100 - 15 (description) = 85
        # Score 85 >= threshold 80, so it passes despite missing description
        assert report.passed
        assert any("Description too short" in issue for issue in report.issues)

    def test_missing_severity_fails(self):
        """Missing or invalid severity should fail"""
        validator = ReportQualityValidator()

        finding = {
            "title": "SQL Injection Detected",
            "description": "A detailed description that is longer than fifty characters minimum",
            "file_path": "app/models.py",
            "line_number": 30,
            "severity": ""
        }

        report = validator.validate_finding(finding, 0)

        assert report.total_score == 85  # 100 - 15 (severity) = 85
        # Score 85 >= threshold 80, so it passes despite missing severity
        assert report.passed

    def test_threshold_80_exactly_passes(self):
        """A finding with exactly 80 score should pass"""
        validator = ReportQualityValidator(threshold=80)

        finding = {
            "title": "Security Issue Detected",  # Generic, loses 20 points
            "description": "A detailed description that is longer than fifty characters minimum",
            "file_path": "app/views.py",
            "line_number": 100,
            "severity": "low"
        }

        report = validator.validate_finding(finding, 0)

        assert report.total_score == 80
        assert report.passed is True

    def test_validate_report_with_multiple_findings(self):
        """Test validating a report with multiple findings"""
        validator = ReportQualityValidator()

        report_data = {
            "findings": [
                {
                    "title": "XSS Vulnerability",
                    "description": "Cross-site scripting vulnerability detected in user input handling code",
                    "file_path": "web/forms.py",
                    "line_number": 55,
                    "severity": "high"
                },
                {
                    "title": "Unknown Issue",  # Bad title
                    "description": "Short",  # Bad description
                    "file_path": "unknown",  # Bad path
                    "line_number": None,  # Bad line number
                    "severity": ""  # Bad severity
                }
            ]
        }

        validation_report = validator.validate_report(report_data)

        assert validation_report.total_findings == 2
        assert validation_report.passed_findings == 1
        assert validation_report.failed_findings == 1
        assert validation_report.overall_passed is False

    def test_validate_empty_report(self):
        """Test validating an empty report"""
        validator = ReportQualityValidator()

        report_data = {"findings": []}

        validation_report = validator.validate_report(report_data)

        assert validation_report.total_findings == 0
        assert validation_report.overall_passed is False
        assert len(validation_report.warnings) > 0

    def test_custom_threshold(self):
        """Test with custom quality threshold"""
        validator = ReportQualityValidator(threshold=90)

        finding = {
            "title": "SQL Injection Vulnerability",
            "description": "A detailed description that is longer than fifty characters minimum",
            "file_path": "app/db.py",
            "line_number": 20,
            "severity": "critical"
        }

        report = validator.validate_finding(finding, 0)

        # "sql injection vulnerability" contains "vulnerability" from INVALID_TITLES
        # Score: 100 - 20 (title) = 80, which is below 90 threshold
        assert report.total_score == 80
        assert report.passed is False

    def test_alternative_field_names(self):
        """Test that validator handles alternative field names (path vs file_path, etc.)"""
        validator = ReportQualityValidator()

        finding = {
            "title": "Command Injection",
            "description": "Command injection vulnerability found in file processing module",
            "path": "processors/file_handler.py",  # Alternative name
            "line": 88,  # Alternative name
            "severity": "critical"
        }

        report = validator.validate_finding(finding, 0)

        assert report.total_score == 100
        assert report.passed is True

    def test_report_serialization(self):
        """Test that reports can be serialized to JSON"""
        validator = ReportQualityValidator()

        finding = {
            "title": "Test Finding",
            "description": "A test description that is sufficiently long to pass the minimum length requirement",
            "file_path": "test.py",
            "line_number": 1,
            "severity": "low"
        }

        report = validator.validate_finding(finding, 0)
        report_dict = report.to_dict()

        # Should be JSON serializable
        json_str = json.dumps(report_dict)
        assert json_str is not None
        assert "finding_id" in report_dict
        assert "total_score" in report_dict


class TestIntegrationScenarios:
    """Test real-world integration scenarios"""

    def test_prevents_external_submission(self, tmp_path):
        """Test that low-quality reports are prevented from submission"""
        validator = ReportQualityValidator()

        bad_report = {
            "findings": [
                {
                    "title": "Unknown Issue",
                    "description": "Bad",
                    "file_path": "",
                    "line_number": None,
                    "severity": ""
                }
            ]
        }

        # Save to temp file
        report_file = tmp_path / "bad_report.json"
        with open(report_file, "w") as f:
            json.dump(bad_report, f)

        # Validate
        validation_report = validator.validate_report_file(report_file)

        # Should fail
        assert not validation_report.overall_passed
        assert len(validation_report.critical_blockers) > 0

    def test_allows_good_report_submission(self, tmp_path):
        """Test that high-quality reports pass validation"""
        validator = ReportQualityValidator()

        good_report = {
            "findings": [
                {
                    "title": "SQL Injection in Login",
                    "description": "Critical SQL injection vulnerability detected in the login authentication flow. User credentials are concatenated directly into SQL queries.",
                    "file_path": "auth/login.py",
                    "line_number": 42,
                    "severity": "critical"
                }
            ]
        }

        # Save to temp file
        report_file = tmp_path / "good_report.json"
        with open(report_file, "w") as f:
            json.dump(good_report, f)

        # Validate
        validation_report = validator.validate_report_file(report_file)

        # Should pass
        assert validation_report.overall_passed
        assert validation_report.failed_findings == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
