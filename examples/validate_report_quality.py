#!/usr/bin/env python3
"""
Example: How to use the Report Quality Validator

This script demonstrates how to validate security reports to prevent
low-quality submissions like the pi-mono disaster.
"""

import json
import sys
from pathlib import Path

# Add scripts to path
SCRIPT_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

from report_quality_validator import ReportQualityValidator


def example_1_validate_good_report():
    """Example 1: Validate a high-quality report"""
    print("\n" + "=" * 80)
    print("EXAMPLE 1: Validating a HIGH-QUALITY Report")
    print("=" * 80)

    good_report = {
        "findings": [
            {
                "id": "sec-001",
                "title": "SQL Injection in User Login",
                "description": (
                    "Critical SQL injection vulnerability found in the user authentication "
                    "module. User-supplied input from the login form is directly concatenated "
                    "into SQL queries without sanitization, allowing attackers to bypass "
                    "authentication and access sensitive data."
                ),
                "file_path": "app/auth/login.py",
                "line_number": 42,
                "severity": "critical"
            }
        ]
    }

    validator = ReportQualityValidator()
    validation_report = validator.validate_report(good_report)

    print(f"\nValidation Result: {'✅ PASSED' if validation_report.overall_passed else '❌ FAILED'}")
    print(f"Score: {validation_report.passed_findings}/{validation_report.total_findings} findings passed")

    return validation_report.overall_passed


def example_2_validate_bad_report():
    """Example 2: Validate a low-quality report (pi-mono disaster case)"""
    print("\n" + "=" * 80)
    print("EXAMPLE 2: Validating a LOW-QUALITY Report (Pi-Mono Disaster)")
    print("=" * 80)

    bad_report = {
        "findings": [
            {
                "id": "bad-001",
                "title": "Unknown Issue",
                "description": "Found issue",
                "file_path": "unknown",
                "line_number": None,
                "severity": ""
            }
        ]
    }

    validator = ReportQualityValidator()
    validation_report = validator.validate_report(bad_report)

    print(f"\nValidation Result: {'✅ PASSED' if validation_report.overall_passed else '❌ FAILED'}")
    print(f"Score: {validation_report.passed_findings}/{validation_report.total_findings} findings passed")

    if validation_report.failed_findings > 0:
        print("\nISSUES DETECTED:")
        for finding_report in validation_report.finding_reports:
            if not finding_report.passed:
                print(f"\n  Finding: {finding_report.finding_title}")
                print(f"  Quality Score: {finding_report.total_score}/100")
                for issue in finding_report.issues:
                    print(f"    • {issue}")

    return validation_report.overall_passed


def example_3_custom_threshold():
    """Example 3: Use custom quality threshold"""
    print("\n" + "=" * 80)
    print("EXAMPLE 3: Custom Quality Threshold (90 instead of 80)")
    print("=" * 80)

    # This report would normally pass (80+ score) but we want stricter quality
    report = {
        "findings": [
            {
                "id": "med-001",
                "title": "Potential Security Issue",  # Generic title (-20 points)
                "description": (
                    "A potential security issue was detected in the configuration file. "
                    "This should be reviewed to ensure proper security settings."
                ),
                "file_path": "config/settings.py",
                "line_number": 10,
                "severity": "medium"
            }
        ]
    }

    # Standard threshold (80)
    validator_standard = ReportQualityValidator(threshold=80)
    report_standard = validator_standard.validate_report(report)

    # Strict threshold (90)
    validator_strict = ReportQualityValidator(threshold=90)
    report_strict = validator_strict.validate_report(report)

    finding_score = report_standard.finding_reports[0].total_score

    print(f"\nFinding Quality Score: {finding_score}/100")
    print(f"Standard Threshold (80): {'✅ PASSED' if report_standard.overall_passed else '❌ FAILED'}")
    print(f"Strict Threshold (90):   {'✅ PASSED' if report_strict.overall_passed else '❌ FAILED'}")

    return report_standard.overall_passed != report_strict.overall_passed


def example_4_validate_from_file():
    """Example 4: Validate report from JSON file"""
    print("\n" + "=" * 80)
    print("EXAMPLE 4: Validating Report from JSON File")
    print("=" * 80)

    # Create a temporary report file
    report_file = Path("/tmp/example_report.json")
    report_data = {
        "findings": [
            {
                "id": "xss-001",
                "title": "Cross-Site Scripting in User Profile",
                "description": (
                    "User-generated profile content is rendered without proper HTML escaping, "
                    "allowing attackers to inject malicious JavaScript that executes in "
                    "other users' browsers, potentially stealing session cookies or credentials."
                ),
                "file_path": "web/views/profile.py",
                "line_number": 89,
                "severity": "high"
            }
        ]
    }

    with open(report_file, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"\nReport saved to: {report_file}")

    validator = ReportQualityValidator()
    validation_report = validator.validate_report_file(report_file)

    # Save validation report
    validation_output = Path("/tmp/example_validation_report.json")
    validator.save_validation_report(validation_report, validation_output)

    print(f"Validation report saved to: {validation_output}")
    print(f"\nValidation Result: {'✅ PASSED' if validation_report.overall_passed else '❌ FAILED'}")

    return validation_report.overall_passed


def example_5_integration_hook():
    """Example 5: Integration hook for blocking bad reports"""
    print("\n" + "=" * 80)
    print("EXAMPLE 5: Integration Hook - Prevent External Submission")
    print("=" * 80)

    bad_report = {
        "findings": [
            {
                "title": "Issue",
                "description": "Bad",
                "file_path": "",
                "line_number": None,
                "severity": ""
            }
        ]
    }

    validator = ReportQualityValidator()
    validation_report = validator.validate_report(bad_report)

    # Simulate external submission workflow
    if validation_report.overall_passed:
        print("\n✅ Quality check passed - Proceeding with external submission...")
        return True
    else:
        print("\n❌ Quality check FAILED - BLOCKING external submission!")
        print("⚠️  This report would have caused another pi-mono disaster!")
        print(f"⚠️  {validation_report.failed_findings} findings failed quality checks")
        return False


def main():
    """Run all examples"""
    print("\n")
    print("╔════════════════════════════════════════════════════════════════════════════╗")
    print("║                     REPORT QUALITY VALIDATOR EXAMPLES                      ║")
    print("║                    Preventing Pi-Mono Disasters Since 2026                 ║")
    print("╚════════════════════════════════════════════════════════════════════════════╝")

    results = []

    # Run all examples
    results.append(("Good Report Validation", example_1_validate_good_report()))
    results.append(("Bad Report Detection", not example_2_validate_bad_report()))
    results.append(("Custom Threshold", example_3_custom_threshold()))
    results.append(("File-Based Validation", example_4_validate_from_file()))
    results.append(("Integration Hook", not example_5_integration_hook()))

    # Summary
    print("\n" + "=" * 80)
    print("EXAMPLES SUMMARY")
    print("=" * 80)

    for name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{name:.<60} {status}")

    all_passed = all(passed for _, passed in results)
    print("\n" + "=" * 80)
    if all_passed:
        print("✅ All examples completed successfully!")
        print("💡 The validator is working correctly and preventing low-quality reports.")
    else:
        print("⚠️  Some examples had unexpected results.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
