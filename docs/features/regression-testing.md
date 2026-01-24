# Security Regression Testing

## Overview

Security Regression Testing ensures that fixed vulnerabilities stay fixed. It automatically generates test cases for every vulnerability fix and alerts when previously fixed issues reappear in the codebase.

**Problem:** 15-20% of security fixes regress in later commits due to refactoring, merges, or copy-paste errors.

**Solution:** Automated regression tests that run on every commit.

## How It Works

The regression tester:

1. **Tracks Fixed Vulnerabilities**:
   - Records all security findings and their fixes
   - Stores vulnerability signatures
   - Maintains historical fix database

2. **Generates Regression Tests**:
   - Creates exploit test cases for each vulnerability
   - Generates verification tests for fixes
   - Adds tests to regression test suite

3. **Detects Regressions**:
   - Compares current findings with historical fixes
   - Alerts when fixed vulnerabilities reappear
   - Escalates regressions to high severity

## Usage

### CLI Usage

```bash
# Generate regression test suite from fixed findings
./scripts/argus regression-test generate --fixed-findings fixed.json

# Run regression tests to detect if vulnerabilities returned
./scripts/argus regression-test run --path /path/to/repo

# Regression testing is automatically enabled during scans (default)
python scripts/run_ai_audit.py --enable-regression-testing
```

### Python API

```python
from hybrid_analyzer import HybridSecurityAnalyzer

# Create analyzer with regression testing enabled (default)
analyzer = HybridSecurityAnalyzer(
    enable_regression_testing=True  # Enabled by default
)

# Run analysis - regression tests run automatically
result = analyzer.analyze(target_path="/path/to/repo")

# Regressions are flagged with high severity
for finding in result.findings:
    if finding.category == "regression":
        print(f"REGRESSION DETECTED: {finding.title}")
```

### Standalone Usage

```python
from regression_tester import SecurityRegressionTester

tester = SecurityRegressionTester()

# Generate regression test suite from fixed findings
test_cases = tester.generate_regression_tests(fixed_findings)

print(f"Generated {len(test_cases)} regression test cases")

# Detect regressions
regressions = tester.detect_regression(
    current_findings=current_scan_results,
    target_path="/path/to/repo"
)

if regressions:
    print(f"⚠️  {len(regressions)} regressions detected!")
```

## Configuration

Regression testing is **enabled by default**. To disable:

```bash
python scripts/run_ai_audit.py --enable-regression-testing=false
```

## Output Format

### Regression Finding

```json
{
  "finding_id": "regression-sql-injection-001",
  "source_tool": "regression-testing",
  "severity": "high",
  "category": "regression",
  "title": "Security Regression: SQL Injection in user_login",
  "description": "Previously fixed SQL injection vulnerability has reappeared in login.py:42. Original fix date: 2026-01-10. This vulnerability was fixed in commit abc123 but has returned.",
  "file_path": "app/login.py",
  "line_number": 42,
  "cwe_id": "CWE-89",
  "cve_id": null,
  "recommendation": "Review recent changes to login.py. Re-apply original fix: use parameterized queries.",
  "references": [
    "Original fix commit: abc123",
    "Fix date: 2026-01-10",
    "Original finding ID: semgrep-sql-injection-042"
  ],
  "confidence": 1.0,
  "original_fix_date": "2026-01-10",
  "original_finding_id": "semgrep-sql-injection-042"
}
```

## Integration

Regression testing runs as part of Phase 1 in the hybrid analyzer workflow:

1. **Phase 1**: Scanners detect current vulnerabilities
2. **Regression Check**: Compare with historical fixed vulnerabilities
3. **Alert on Regressions**: Flag any reappeared vulnerabilities
4. **High Priority**: Regressions are always marked as high severity
5. **Reporting**: Included in scan results and PR comments

## How Regression Detection Works

### Vulnerability Signatures

Each vulnerability is identified by:

- **File path**: Exact file location
- **CWE ID**: Vulnerability type (e.g., CWE-89 for SQL injection)
- **Pattern**: Code pattern that caused the vulnerability
- **Line context**: Surrounding code for verification

### Detection Algorithm

```python
def detect_regression(current_findings, historical_fixes):
    regressions = []

    for fix in historical_fixes:
        # Check if same vulnerability reappeared
        for current in current_findings:
            if (current.file_path == fix.file_path and
                current.cwe_id == fix.cwe_id and
                similarity(current.pattern, fix.pattern) > 0.8):

                # Regression detected!
                regressions.append({
                    "current_finding": current,
                    "original_fix": fix,
                    "regression_date": now(),
                    "original_fix_date": fix.fix_date
                })

    return regressions
```

## Regression Test Suite

Auto-generated regression tests are added to `tests/security/test_security_regressions.py`:

```python
import pytest
from app.login import authenticate_user

def test_sql_injection_regression_001():
    """
    Regression test for SQL injection in authenticate_user()

    Original vulnerability: semgrep-sql-injection-042
    Fixed: 2026-01-10 (commit abc123)
    CWE: CWE-89 (SQL Injection)

    This test ensures the SQL injection fix stays applied.
    """
    # Attempt SQL injection
    malicious_input = "admin' OR '1'='1"

    # Should safely reject malicious input
    result = authenticate_user(username=malicious_input, password="anything")

    # Vulnerability is present if authentication succeeds
    assert result is None, "SQL injection vulnerability has regressed!"

def test_xss_regression_002():
    """
    Regression test for XSS in render_profile()

    Original vulnerability: semgrep-xss-019
    Fixed: 2026-01-12 (commit def456)
    CWE: CWE-79 (XSS)
    """
    from app.profile import render_profile

    # Attempt XSS injection
    xss_payload = "<script>alert('XSS')</script>"

    # Should safely escape output
    html = render_profile(name=xss_payload)

    # Vulnerability is present if <script> tag is unescaped
    assert "<script>" not in html, "XSS vulnerability has regressed!"
    assert "&lt;script&gt;" in html, "Output should be HTML-escaped"
```

## Best Practices

1. **Run on Every Commit**: Add regression tests to CI/CD pipeline
2. **Track All Fixes**: Record every security fix in the fix database
3. **Review Regressions Immediately**: Regressions indicate recent code changes broke fixes
4. **Automate Test Generation**: Let Argus generate tests automatically
5. **Maintain Test Suite**: Remove obsolete tests, update for code refactoring

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Regression Tests
on: [push, pull_request]

jobs:
  regression:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run security regression tests
        run: |
          python scripts/run_ai_audit.py --enable-regression-testing

      - name: Fail on regressions
        run: |
          if grep -q '"category": "regression"' findings.json; then
            echo "⚠️  Security regressions detected!"
            exit 1
          fi
```

### pytest Integration

```bash
# Run regression test suite
pytest tests/security/test_security_regressions.py -v

# Run as part of full test suite
pytest tests/ -k "regression" -v
```

## Example Output

```
🧪 Security Regression Testing:
   Tracked fixes: 47
   Current findings: 23
   Regressions detected: 2

   ⚠️  REGRESSIONS:

   1. SQL Injection in app/login.py:42
      - Original fix: 2026-01-10 (commit abc123)
      - Regressed in: Last 7 days
      - Impact: High - Authentication bypass
      - Action: Re-apply parameterized query fix

   2. XSS in app/profile.py:108
      - Original fix: 2026-01-12 (commit def456)
      - Regressed in: Last 2 days
      - Impact: High - Session hijacking risk
      - Action: Re-apply HTML escaping fix

   Generated regression tests: 47
   Location: tests/security/test_security_regressions.py
```

## Fix Database Format

Fixes are stored in `.argus/fixed_vulnerabilities.jsonl`:

```jsonl
{"finding_id": "semgrep-sql-injection-042", "file_path": "app/login.py", "line_number": 42, "cwe_id": "CWE-89", "fix_date": "2026-01-10", "fix_commit": "abc123", "pattern": "f\"SELECT * FROM users WHERE username = '{username}'\"", "status": "fixed"}
{"finding_id": "semgrep-xss-019", "file_path": "app/profile.py", "line_number": 108, "cwe_id": "CWE-79", "fix_date": "2026-01-12", "fix_commit": "def456", "pattern": "innerHTML = userInput", "status": "fixed"}
```

## Troubleshooting

**Q: Why are regressions not detected?**

A: Ensure `.argus/fixed_vulnerabilities.jsonl` exists and contains historical fixes. Run an initial scan to populate the database.

**Q: False positive regression?**

A: Code refactoring may trigger false positives. Review pattern similarity threshold in `regression_tester.py`.

**Q: How do I mark a regression as intentional?**

A: Add exception in `.argus/regression_exceptions.json`:

```json
{
  "exceptions": [
    {
      "finding_id": "semgrep-sql-injection-042",
      "reason": "Intentional revert for performance testing",
      "expires": "2026-02-01"
    }
  ]
}
```

**Q: Can I use this for non-security bugs?**

A: Yes! Extend `SecurityRegressionTester` to track any type of bug fix.

## Performance

- **Overhead**: ~0.5-1 second per tracked fix
- **Storage**: ~1KB per fix in database
- **Test Generation**: ~2-3 seconds per fix

## Metrics

Track regression testing effectiveness:

- **Regression Rate**: % of fixes that regress
- **Detection Time**: How quickly regressions are caught
- **Test Coverage**: % of fixes with regression tests
- **False Positive Rate**: % of false regression alerts

```bash
# View regression metrics
python scripts/decision_analyzer.py --category regression --format json
```

---

**Related Documentation:**
- [Security Test Generation](../security-test-generator.md)
- [Hybrid Analyzer](../architecture/overview.md)
- [Best Practices](../best-practices.md)
- [CI/CD Integration](../integration-guide-sast-dast.md)
