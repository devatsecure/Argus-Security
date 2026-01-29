#!/usr/bin/env python3
"""
Report Quality Validator for Argus Security

Prevents incidents like the pi-mono disaster where we submitted low-quality reports
with empty file paths, null line numbers, and "Unknown Issue" titles.

This validator enforces strict quality standards before allowing report submission.

Quality Scoring (0-100):
- file_path present & non-empty: +25 points
- line_number present & non-null: +25 points
- title meaningful (not "Unknown"): +20 points
- description >= 50 chars: +15 points
- severity set (not empty): +15 points
- THRESHOLD: Score must be >= 80 to pass

Features:
- Validates JSON reports from hybrid_analyzer
- Generates detailed quality report with pass/fail per finding
- Blocks submission if any finding scores < 80
- CLI interface for manual validation
- Integration hooks for automated validation

Author: Argus Security Team
Version: 1.0.0
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class QualityCheck:
    """Individual quality check result"""
    name: str
    passed: bool
    points_awarded: int
    max_points: int
    message: str


@dataclass
class FindingQualityReport:
    """Quality report for a single finding"""
    finding_id: str
    finding_title: str
    checks: List[QualityCheck] = field(default_factory=list)
    total_score: int = 0
    max_score: int = 100
    passed: bool = False
    issues: List[str] = field(default_factory=list)

    def add_check(self, check: QualityCheck) -> None:
        """Add a quality check result"""
        self.checks.append(check)
        self.total_score += check.points_awarded
        if not check.passed:
            self.issues.append(check.message)

    def finalize(self, threshold: int = 80) -> None:
        """Finalize the report and determine pass/fail"""
        self.passed = self.total_score >= threshold

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "total_score": self.total_score,
            "max_score": self.max_score,
            "passed": self.passed,
            "checks": [
                {
                    "name": c.name,
                    "passed": c.passed,
                    "points": f"{c.points_awarded}/{c.max_points}",
                    "message": c.message
                }
                for c in self.checks
            ],
            "issues": self.issues
        }


@dataclass
class ValidationReport:
    """Overall validation report for all findings"""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_findings: int = 0
    passed_findings: int = 0
    failed_findings: int = 0
    overall_passed: bool = False
    finding_reports: List[FindingQualityReport] = field(default_factory=list)
    critical_blockers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_finding_report(self, report: FindingQualityReport) -> None:
        """Add a finding quality report"""
        self.finding_reports.append(report)
        self.total_findings += 1
        if report.passed:
            self.passed_findings += 1
        else:
            self.failed_findings += 1
            # Track critical blockers
            if report.total_score < 50:
                self.critical_blockers.append(
                    f"Finding '{report.finding_title}' has critically low quality score: {report.total_score}/100"
                )

    def finalize(self) -> None:
        """Finalize the report"""
        # Report passes only if ALL findings pass
        self.overall_passed = self.failed_findings == 0 and self.total_findings > 0

        # Add warnings for edge cases
        if self.total_findings == 0:
            self.warnings.append("No findings to validate - this may indicate an empty report")
        if self.failed_findings > 0:
            self.warnings.append(
                f"{self.failed_findings}/{self.total_findings} findings failed quality checks"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "timestamp": self.timestamp,
            "summary": {
                "total_findings": self.total_findings,
                "passed": self.passed_findings,
                "failed": self.failed_findings,
                "overall_passed": self.overall_passed
            },
            "critical_blockers": self.critical_blockers,
            "warnings": self.warnings,
            "finding_reports": [fr.to_dict() for fr in self.finding_reports]
        }


class ReportQualityValidator:
    """
    Validates security finding reports for quality before submission.

    Prevents embarrassing incidents like submitting reports with:
    - Empty or "unknown" file paths
    - Null or missing line numbers
    - "Unknown Issue" as titles
    - Very short or missing descriptions
    - Unset severity levels
    """

    # Quality thresholds
    PASS_THRESHOLD = 80  # Minimum score to pass (out of 100)
    CRITICAL_THRESHOLD = 50  # Below this is critically bad

    # Point values for each check
    POINTS_FILE_PATH = 25
    POINTS_LINE_NUMBER = 25
    POINTS_TITLE = 20
    POINTS_DESCRIPTION = 15
    POINTS_SEVERITY = 15

    # Validation rules
    MIN_DESCRIPTION_LENGTH = 50
    INVALID_TITLES = ["unknown issue", "unknown", "issue found", "security issue", "vulnerability"]
    INVALID_PATHS = ["unknown", ".", "", "none", "n/a"]
    VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"]

    def __init__(self, threshold: int = PASS_THRESHOLD):
        """Initialize validator with custom threshold if needed"""
        self.threshold = threshold

    def validate_finding(self, finding: Dict[str, Any], index: int) -> FindingQualityReport:
        """
        Validate a single finding and generate quality report.

        Args:
            finding: Finding dictionary from scanner output
            index: Finding index (for identification if no ID present)

        Returns:
            FindingQualityReport with detailed quality assessment
        """
        finding_id = finding.get("id", f"finding-{index}")
        finding_title = finding.get("title", finding.get("message", "Untitled Finding"))

        report = FindingQualityReport(
            finding_id=finding_id,
            finding_title=finding_title
        )

        # Check 1: File path validation
        file_path = finding.get("file_path", finding.get("path", ""))
        file_path_str = str(file_path).lower().strip()

        if file_path and file_path_str not in self.INVALID_PATHS and len(file_path_str) > 1:
            report.add_check(QualityCheck(
                name="file_path",
                passed=True,
                points_awarded=self.POINTS_FILE_PATH,
                max_points=self.POINTS_FILE_PATH,
                message="File path is present and valid"
            ))
        else:
            report.add_check(QualityCheck(
                name="file_path",
                passed=False,
                points_awarded=0,
                max_points=self.POINTS_FILE_PATH,
                message=f"CRITICAL: File path is empty, invalid, or 'unknown' (got: '{file_path_str}')"
            ))

        # Check 2: Line number validation
        line_number = finding.get("line_number", finding.get("line", None))

        if line_number is not None and isinstance(line_number, int) and line_number > 0:
            report.add_check(QualityCheck(
                name="line_number",
                passed=True,
                points_awarded=self.POINTS_LINE_NUMBER,
                max_points=self.POINTS_LINE_NUMBER,
                message="Line number is present and valid"
            ))
        else:
            report.add_check(QualityCheck(
                name="line_number",
                passed=False,
                points_awarded=0,
                max_points=self.POINTS_LINE_NUMBER,
                message=f"CRITICAL: Line number is null, missing, or invalid (got: {line_number})"
            ))

        # Check 3: Title validation
        title = finding.get("title", finding.get("message", "")).lower().strip()

        if title and not any(invalid in title for invalid in self.INVALID_TITLES):
            report.add_check(QualityCheck(
                name="title",
                passed=True,
                points_awarded=self.POINTS_TITLE,
                max_points=self.POINTS_TITLE,
                message="Title is meaningful and descriptive"
            ))
        else:
            report.add_check(QualityCheck(
                name="title",
                passed=False,
                points_awarded=0,
                max_points=self.POINTS_TITLE,
                message=f"Title is generic or 'Unknown Issue' (got: '{title}')"
            ))

        # Check 4: Description validation
        description = finding.get("description", finding.get("evidence", {}).get("message", ""))
        if isinstance(description, dict):
            description = str(description)
        description = str(description).strip()

        if len(description) >= self.MIN_DESCRIPTION_LENGTH:
            report.add_check(QualityCheck(
                name="description",
                passed=True,
                points_awarded=self.POINTS_DESCRIPTION,
                max_points=self.POINTS_DESCRIPTION,
                message=f"Description is detailed ({len(description)} chars)"
            ))
        else:
            report.add_check(QualityCheck(
                name="description",
                passed=False,
                points_awarded=0,
                max_points=self.POINTS_DESCRIPTION,
                message=f"Description too short ({len(description)} chars, need >= {self.MIN_DESCRIPTION_LENGTH})"
            ))

        # Check 5: Severity validation
        severity = finding.get("severity", "").lower().strip()

        if severity and severity in self.VALID_SEVERITIES:
            report.add_check(QualityCheck(
                name="severity",
                passed=True,
                points_awarded=self.POINTS_SEVERITY,
                max_points=self.POINTS_SEVERITY,
                message=f"Severity is set to '{severity}'"
            ))
        else:
            report.add_check(QualityCheck(
                name="severity",
                passed=False,
                points_awarded=0,
                max_points=self.POINTS_SEVERITY,
                message=f"Severity is missing or invalid (got: '{severity}')"
            ))

        # Finalize the report
        report.finalize(self.threshold)

        return report

    def validate_report(self, report_data: Dict[str, Any]) -> ValidationReport:
        """
        Validate an entire report containing multiple findings.

        Args:
            report_data: Report dictionary (typically from hybrid_analyzer JSON)

        Returns:
            ValidationReport with overall assessment
        """
        validation_report = ValidationReport()

        # Extract findings from report
        findings = report_data.get("findings", [])

        if not findings:
            # Check if report_data itself is a list of findings
            if isinstance(report_data, list):
                findings = report_data
            else:
                logger.warning("No findings found in report")
                validation_report.warnings.append("No findings found in report")

        # Validate each finding
        for idx, finding in enumerate(findings):
            finding_report = self.validate_finding(finding, idx)
            validation_report.add_finding_report(finding_report)

        # Finalize overall report
        validation_report.finalize()

        return validation_report

    def validate_report_file(self, report_path: Path) -> ValidationReport:
        """
        Validate a report from a JSON file.

        Args:
            report_path: Path to JSON report file

        Returns:
            ValidationReport

        Raises:
            FileNotFoundError: If report file doesn't exist
            json.JSONDecodeError: If report is invalid JSON
        """
        if not report_path.exists():
            raise FileNotFoundError(f"Report file not found: {report_path}")

        logger.info(f"Validating report: {report_path}")

        with open(report_path, "r") as f:
            report_data = json.load(f)

        return self.validate_report(report_data)

    def print_validation_report(self, validation_report: ValidationReport) -> None:
        """
        Print a human-readable validation report to console.

        Args:
            validation_report: ValidationReport to print
        """
        print("\n" + "=" * 80)
        print("ARGUS SECURITY - REPORT QUALITY VALIDATION")
        print("=" * 80)
        print(f"\nTimestamp: {validation_report.timestamp}")
        print(f"\nOverall Status: {'✅ PASSED' if validation_report.overall_passed else '❌ FAILED'}")
        print(f"\nFindings Summary:")
        print(f"  Total Findings: {validation_report.total_findings}")
        print(f"  Passed: {validation_report.passed_findings}")
        print(f"  Failed: {validation_report.failed_findings}")

        # Print critical blockers
        if validation_report.critical_blockers:
            print(f"\n{'⛔' * 3} CRITICAL BLOCKERS {'⛔' * 3}")
            for blocker in validation_report.critical_blockers:
                print(f"  • {blocker}")

        # Print warnings
        if validation_report.warnings:
            print(f"\n⚠️  WARNINGS:")
            for warning in validation_report.warnings:
                print(f"  • {warning}")

        # Print individual finding reports
        if validation_report.failed_findings > 0:
            print(f"\n{'-' * 80}")
            print("FAILED FINDINGS (Details):")
            print("-" * 80)

            for finding_report in validation_report.finding_reports:
                if not finding_report.passed:
                    print(f"\n❌ {finding_report.finding_title}")
                    print(f"   ID: {finding_report.finding_id}")
                    print(f"   Quality Score: {finding_report.total_score}/{finding_report.max_score}")
                    print(f"   Issues:")
                    for issue in finding_report.issues:
                        print(f"     • {issue}")
                    print(f"   Check Details:")
                    for check in finding_report.checks:
                        status = "✓" if check.passed else "✗"
                        print(f"     {status} {check.name}: {check.points_awarded}/{check.max_points} points")

        # Print success summary for passed findings
        if validation_report.passed_findings > 0:
            print(f"\n{'-' * 80}")
            print(f"✅ {validation_report.passed_findings} findings passed quality checks")
            print("-" * 80)

        print("\n" + "=" * 80)

        if validation_report.overall_passed:
            print("✅ VALIDATION PASSED - Report meets quality standards")
        else:
            print("❌ VALIDATION FAILED - Report does NOT meet quality standards")
            print("⚠️  DO NOT submit this report to external repositories!")
        print("=" * 80 + "\n")

    def save_validation_report(self, validation_report: ValidationReport, output_path: Path) -> None:
        """
        Save validation report to JSON file.

        Args:
            validation_report: ValidationReport to save
            output_path: Path to save JSON report
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(validation_report.to_dict(), f, indent=2)

        logger.info(f"Validation report saved to: {output_path}")


def integrate_with_hybrid_analyzer(report_path: Path, fail_on_low_quality: bool = True) -> bool:
    """
    Integration hook for hybrid_analyzer to validate reports before submission.

    Args:
        report_path: Path to generated report JSON
        fail_on_low_quality: If True, raise exception on validation failure

    Returns:
        bool: True if validation passed, False otherwise

    Raises:
        ValueError: If validation fails and fail_on_low_quality is True
    """
    validator = ReportQualityValidator()
    validation_report = validator.validate_report_file(report_path)

    # Save validation report alongside the original report
    validation_output = report_path.parent / f"{report_path.stem}_quality_report.json"
    validator.save_validation_report(validation_report, validation_output)

    # Print summary
    validator.print_validation_report(validation_report)

    # Check if validation passed
    if not validation_report.overall_passed:
        error_msg = (
            f"Report quality validation FAILED: {validation_report.failed_findings}/"
            f"{validation_report.total_findings} findings below quality threshold. "
            f"See {validation_output} for details."
        )

        if fail_on_low_quality:
            raise ValueError(error_msg)
        else:
            logger.warning(error_msg)
            return False

    logger.info("✅ Report quality validation PASSED")
    return True


def main():
    """CLI entry point for report quality validation"""
    parser = argparse.ArgumentParser(
        description="Validate Argus Security report quality before submission",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate a report
  python report_quality_validator.py results.json

  # Validate with custom threshold
  python report_quality_validator.py results.json --threshold 90

  # Save validation report to specific file
  python report_quality_validator.py results.json --output validation.json

  # Warn only (don't fail)
  python report_quality_validator.py results.json --warn-only

Quality Scoring (0-100):
  - file_path present & non-empty: +25 points
  - line_number present & non-null: +25 points
  - title meaningful (not "Unknown"): +20 points
  - description >= 50 chars: +15 points
  - severity set: +15 points
  - THRESHOLD: Score must be >= 80 to pass
        """
    )

    parser.add_argument(
        "report_file",
        type=Path,
        help="Path to JSON report file to validate"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=ReportQualityValidator.PASS_THRESHOLD,
        help=f"Quality score threshold (default: {ReportQualityValidator.PASS_THRESHOLD})"
    )

    parser.add_argument(
        "--output",
        type=Path,
        help="Path to save validation report (default: <report_file>_quality_report.json)"
    )

    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="Only warn about quality issues, don't fail"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output, only return exit code"
    )

    args = parser.parse_args()

    # Validate the report
    try:
        validator = ReportQualityValidator(threshold=args.threshold)
        validation_report = validator.validate_report_file(args.report_file)

        # Determine output path
        output_path = args.output or args.report_file.parent / f"{args.report_file.stem}_quality_report.json"

        # Save validation report
        validator.save_validation_report(validation_report, output_path)

        # Print report (unless quiet mode)
        if not args.quiet:
            validator.print_validation_report(validation_report)

        # Exit based on validation result
        if not validation_report.overall_passed:
            if args.warn_only:
                logger.warning("Report quality validation failed, but continuing due to --warn-only flag")
                sys.exit(0)
            else:
                logger.error("Report quality validation FAILED")
                sys.exit(1)
        else:
            logger.info("Report quality validation PASSED")
            sys.exit(0)

    except FileNotFoundError as e:
        logger.error(f"Error: {e}")
        sys.exit(2)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in report file: {e}")
        sys.exit(2)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
