# Report Quality Validator

## Overview

The Report Quality Validator prevents low-quality security reports from being submitted to external repositories. This system was created in response to the **pi-mono disaster** where we submitted a report with empty file paths, null line numbers, and "Unknown Issue" titles, resulting in Argus being banned from the repository.

**Never again.**

## The Pi-Mono Disaster

On an undisclosed date, Argus Security submitted a security report to `badlogic/pi-mono` with the following issues:

- Empty or "unknown" file paths
- Null line numbers
- Generic "Unknown Issue" titles
- Minimal or missing descriptions
- Unset severity levels

The maintainer's response:

> "You and your equally untalented clanker are banned now."

This validator ensures we never submit such low-quality reports again.

## Quality Scoring System

Each finding is scored out of **100 points** across 5 categories:

| Check | Points | Requirement |
|-------|--------|-------------|
| **file_path** | 25 | Non-empty, valid path (not "unknown", ".", "") |
| **line_number** | 25 | Present, non-null, positive integer |
| **title** | 20 | Meaningful (not "Unknown Issue", "Issue Found", etc.) |
| **description** | 15 | At least 50 characters long |
| **severity** | 15 | Set to valid value (critical/high/medium/low/info) |

**Pass Threshold**: 80/100 or higher

**Critical Threshold**: Below 50 indicates critically poor quality

## Usage

### Command Line Interface

```bash
# Basic validation
python scripts/report_quality_validator.py results.json

# Custom threshold (stricter)
python scripts/report_quality_validator.py results.json --threshold 90

# Warn only (don't fail)
python scripts/report_quality_validator.py results.json --warn-only

# Save validation report to specific location
python scripts/report_quality_validator.py results.json --output /path/to/validation.json

# Quiet mode (only exit code)
python scripts/report_quality_validator.py results.json --quiet
```

### Python API

```python
from report_quality_validator import ReportQualityValidator

# Initialize validator
validator = ReportQualityValidator(threshold=80)

# Validate a report file
validation_report = validator.validate_report_file("results.json")

# Check if passed
if validation_report.overall_passed:
    print("✅ Report quality is acceptable")
else:
    print("❌ Report quality is too low")
    print(f"Failed: {validation_report.failed_findings}/{validation_report.total_findings}")

# Print detailed report
validator.print_validation_report(validation_report)

# Save validation report
validator.save_validation_report(validation_report, "quality_report.json")
```

### Integration with Hybrid Analyzer

The validator is automatically integrated into `hybrid_analyzer.py`. When reports are generated, quality validation runs automatically:

```python
from report_quality_validator import integrate_with_hybrid_analyzer

# Validate report and raise exception if quality is low
integrate_with_hybrid_analyzer("results.json", fail_on_low_quality=True)

# Validate but only warn (don't fail)
integrate_with_hybrid_analyzer("results.json", fail_on_low_quality=False)
```

## Output Examples

### Failed Validation (Pi-Mono Disaster Case)

```
================================================================================
ARGUS SECURITY - REPORT QUALITY VALIDATION
================================================================================

Timestamp: 2026-01-29T11:29:47.400229+00:00

Overall Status: ❌ FAILED

Findings Summary:
  Total Findings: 2
  Passed: 0
  Failed: 2

⛔⛔⛔ CRITICAL BLOCKERS ⛔⛔⛔
  • Finding 'Unknown Issue' has critically low quality score: 0/100

⚠️  WARNINGS:
  • 2/2 findings failed quality checks

--------------------------------------------------------------------------------
FAILED FINDINGS (Details):
--------------------------------------------------------------------------------

❌ Unknown Issue
   ID: bad-001
   Quality Score: 0/100
   Issues:
     • CRITICAL: File path is empty, invalid, or 'unknown' (got: 'unknown')
     • CRITICAL: Line number is null, missing, or invalid (got: None)
     • Title is generic or 'Unknown Issue' (got: 'unknown issue')
     • Description too short (11 chars, need >= 50)
     • Severity is missing or invalid (got: '')

================================================================================
❌ VALIDATION FAILED - Report does NOT meet quality standards
⚠️  DO NOT submit this report to external repositories!
================================================================================
```

### Passed Validation

```
================================================================================
ARGUS SECURITY - REPORT QUALITY VALIDATION
================================================================================

Timestamp: 2026-01-29T11:29:56.735302+00:00

Overall Status: ✅ PASSED

Findings Summary:
  Total Findings: 2
  Passed: 2
  Failed: 0

--------------------------------------------------------------------------------
✅ 2 findings passed quality checks
--------------------------------------------------------------------------------

================================================================================
✅ VALIDATION PASSED - Report meets quality standards
================================================================================
```

## Validation Report JSON Structure

```json
{
  "timestamp": "2026-01-29T11:29:56.735302+00:00",
  "summary": {
    "total_findings": 2,
    "passed": 2,
    "failed": 0,
    "overall_passed": true
  },
  "critical_blockers": [],
  "warnings": [],
  "finding_reports": [
    {
      "finding_id": "good-001",
      "finding_title": "SQL Injection in User Authentication",
      "total_score": 100,
      "max_score": 100,
      "passed": true,
      "checks": [
        {
          "name": "file_path",
          "passed": true,
          "points": "25/25",
          "message": "File path is present and valid"
        },
        {
          "name": "line_number",
          "passed": true,
          "points": "25/25",
          "message": "Line number is present and valid"
        },
        {
          "name": "title",
          "passed": true,
          "points": "20/20",
          "message": "Title is meaningful and descriptive"
        },
        {
          "name": "description",
          "passed": true,
          "points": "15/15",
          "message": "Description is detailed (233 chars)"
        },
        {
          "name": "severity",
          "passed": true,
          "points": "15/15",
          "message": "Severity is set to 'critical'"
        }
      ],
      "issues": []
    }
  ]
}
```

## Common Quality Issues

### Issue 1: Empty or Generic File Paths

**Bad:**
```json
{
  "file_path": "unknown",
  "file_path": "",
  "file_path": "."
}
```

**Good:**
```json
{
  "file_path": "app/auth/login.py",
  "file_path": "web/controllers/user_controller.js",
  "file_path": "src/main/java/com/example/Security.java"
}
```

### Issue 2: Null or Missing Line Numbers

**Bad:**
```json
{
  "line_number": null,
  "line_number": 0,
  "line_number": -1
}
```

**Good:**
```json
{
  "line_number": 42,
  "line_number": 156,
  "line_number": 1
}
```

### Issue 3: Generic Titles

**Bad:**
```json
{
  "title": "Unknown Issue",
  "title": "Issue Found",
  "title": "Security Issue",
  "title": "Vulnerability"
}
```

**Good:**
```json
{
  "title": "SQL Injection in User Authentication",
  "title": "Cross-Site Scripting (XSS) in Comment System",
  "title": "Insecure Deserialization in Session Handler"
}
```

### Issue 4: Short Descriptions

**Bad:**
```json
{
  "description": "Bad",
  "description": "Found issue",
  "description": "Security problem"
}
```

**Good:**
```json
{
  "description": "A critical SQL injection vulnerability was detected in the user authentication module. User input is directly concatenated into SQL queries without proper sanitization or parameterization, allowing attackers to bypass authentication and access unauthorized data."
}
```

### Issue 5: Missing Severity

**Bad:**
```json
{
  "severity": "",
  "severity": null,
  "severity": "unknown"
}
```

**Good:**
```json
{
  "severity": "critical",
  "severity": "high",
  "severity": "medium",
  "severity": "low"
}
```

## Best Practices

1. **Always Run Validation**: Never submit reports without running the validator first
2. **Aim for 100/100**: While 80 is passing, strive for perfect scores
3. **Descriptive Titles**: Use specific vulnerability types and affected components
4. **Detailed Descriptions**: Include impact, root cause, and attack scenarios (min 50 chars)
5. **Precise Locations**: Always include accurate file paths and line numbers
6. **Proper Severity**: Use the correct severity based on exploitability and impact

## Integration Points

The validator is automatically integrated at these points:

1. **hybrid_analyzer.py**: Automatically validates after report generation
2. **run_ai_audit.py**: Can be enabled via `--validate-quality` flag (future)
3. **GitHub Actions**: Validates before PR comments (future)
4. **External Submissions**: Blocks low-quality reports before sending (future)

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Validation passed |
| 1 | Validation failed (quality below threshold) |
| 2 | Error (file not found, invalid JSON, etc.) |

## Future Enhancements

- [ ] Machine learning to predict false positive likelihood
- [ ] Integration with GitHub PR submission workflow
- [ ] Automatic quality improvement suggestions
- [ ] Historical quality tracking and trends
- [ ] Team-level quality scorecards
- [ ] Webhook notifications for low-quality reports

## Contributing

To improve the validator:

1. Add new quality checks to `ReportQualityValidator` class
2. Update point values in class constants
3. Add tests to `tests/test_report_quality_validator.py`
4. Update this documentation

## Support

For issues or questions:

- GitHub Issues: https://github.com/devatsecure/Argus-Security/issues
- Documentation: https://github.com/devatsecure/Argus-Security/docs

---

**Remember:** Quality over quantity. One well-documented finding is worth more than 100 "Unknown Issues".

**Never forget pi-mono.** 🚫
