# Security Regression Testing Framework

## Overview

The Security Regression Testing framework ensures that fixed vulnerabilities don't reappear in your codebase. It automatically generates test cases from fixed security findings and runs them continuously in CI/CD.

## Key Features

- **Automatic test generation** from fixed security findings
- **Multi-language support** (Python, JavaScript/TypeScript, Go, Java)
- **Comprehensive test templates** for common vulnerabilities (SQLi, XSS, Command Injection, Path Traversal, etc.)
- **CI/CD integration** with exit codes and JSON reports
- **Organized test storage** by vulnerability type
- **Metadata tracking** (CVE, CWE, severity, date fixed)
- **Detailed reporting** with pass/fail statistics

## Quick Start

### 1. Generate Tests from Fixed Findings

```bash
# Create a JSON file with fixed findings
cat > fixed_findings.json <<EOF
[
  {
    "type": "sql-injection",
    "path": "app/database.py",
    "function": "get_user_by_id",
    "cwe": "CWE-89",
    "cve": "CVE-2024-1234",
    "severity": "critical",
    "description": "SQL injection in user lookup - fixed by parameterized queries"
  }
]
EOF

# Generate regression tests
python scripts/regression_tester.py --mode generate --fixed-findings fixed_findings.json
```

### 2. Run Regression Tests

```bash
# Run all tests
python scripts/regression_tester.py --mode run

# Run tests for specific vulnerability type
python scripts/regression_tester.py --mode run --vuln-type sql-injection

# Enable debug logging
python scripts/regression_tester.py --mode run --debug
```

### 3. View Statistics

```bash
python scripts/regression_tester.py --mode stats
```

## Directory Structure

```
tests/security_regression/
├── sql_injection/
│   ├── test_4c836ec2a25f.py      # Generated pytest test
│   └── test_4c836ec2a25f.json    # Test metadata
├── xss/
│   ├── test_933e48c4c5ee.py
│   └── test_933e48c4c5ee.json
├── command_injection/
│   ├── test_bc3479c5fafb.py
│   └── test_bc3479c5fafb.json
├── path_traversal/
│   ├── test_d2d143e19f2d.py
│   └── test_d2d143e19f2d.json
└── latest_results.json            # Last test run results
```

## Supported Vulnerability Types

The framework includes comprehensive test templates for:

### Injection Vulnerabilities
- **SQL Injection** (CWE-89) - Tests parameterized queries and input validation
- **Command Injection** (CWE-78) - Tests shell=False and command sanitization
- **LDAP Injection** (CWE-90) - Tests LDAP query escaping
- **XPath Injection** (CWE-643) - Tests XPath parameter binding

### Cross-Site Scripting (XSS)
- **Reflected XSS** (CWE-79) - Tests HTML escaping and CSP
- **Stored XSS** (CWE-79) - Tests persistent data sanitization
- **DOM XSS** - Tests client-side output encoding

### Path & File Vulnerabilities
- **Path Traversal** (CWE-22) - Tests path validation and canonicalization
- **File Upload** (CWE-434) - Tests file type validation and storage

### Server-Side Vulnerabilities
- **SSRF** (CWE-918) - Tests URL validation and allowlisting
- **XXE** (CWE-611) - Tests XML parser hardening

### Authentication & Session
- **CSRF** (CWE-352) - Tests CSRF token validation
- **Session Fixation** (CWE-384) - Tests session regeneration

### Other
- **Open Redirect** (CWE-601) - Tests URL validation
- **Insecure Deserialization** (CWE-502) - Tests safe deserialization

## Test Structure

Each generated test includes:

### 1. Regression Test
Verifies the vulnerability is still fixed by testing with exploit payloads:

```python
def test_sql_injection_regression():
    """Regression test: Ensure SQL injection is still fixed"""
    malicious_input = "' OR '1'='1"

    try:
        result = get_user_by_id(malicious_input)
        # Verify injection didn't work
        assert "1'='1" not in str(result), "SQL injection vulnerability returned!"
    except ValueError:
        # Expected: should reject malicious input
        pass
```

### 2. Functionality Test
Ensures the fix doesn't break normal behavior:

```python
def test_sql_injection_normal_input():
    """Ensure fix doesn't break normal functionality"""
    normal_input = "valid_user_123"
    result = get_user_by_id(normal_input)
    assert result is not None, "Function broken for normal input"
```

### 3. Metadata
Tracks context and provenance:

```json
{
  "test_id": "4c836ec2a25f",
  "vulnerability_type": "sql-injection",
  "cve_id": "CVE-2024-1234",
  "cwe_id": "CWE-89",
  "file_path": "app/database.py",
  "function_name": "get_user_by_id",
  "date_fixed": "2026-01-15T03:57:04.152727",
  "severity": "critical",
  "exploit_payload": "' OR '1'='1",
  "expected_behavior": "should_use_parameterized_query"
}
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Regression Tests

on:
  pull_request:
  push:
    branches: [main, develop]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  regression-tests:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov

      - name: Run regression tests
        run: |
          python scripts/regression_tester.py --mode run

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: regression-test-results
          path: tests/security_regression/latest_results.json
```

### Exit Codes

- `0` - All tests passed
- `1` - Tests failed (vulnerabilities may have returned)
- `2` - Test errors occurred

## Workflow Integration

### After Fixing a Vulnerability

1. **Fix the vulnerability** in your code
2. **Extract finding details** from your security scan
3. **Generate regression test**:
   ```bash
   python scripts/regression_tester.py --mode generate --fixed-findings finding.json
   ```
4. **Commit the test** to version control
5. **Run in CI/CD** to prevent regression

### Example Finding Format

```json
{
  "type": "sql-injection",
  "path": "src/handlers/user.py",
  "function": "search_users",
  "cwe": "CWE-89",
  "cve": null,
  "severity": "high",
  "description": "User search vulnerable to SQL injection",
  "snippet": "def search_users(query):\n    return db.execute(f'SELECT * FROM users WHERE name = {query}')"
}
```

## Advanced Usage

### Custom Test Directory

```bash
python scripts/regression_tester.py \
  --mode generate \
  --fixed-findings findings.json \
  --test-dir custom/test/dir
```

### Filtering Tests

```bash
# Run only critical severity tests
python scripts/regression_tester.py --mode run --severity critical

# Run only specific vulnerability type
python scripts/regression_tester.py --mode run --vuln-type xss
```

### Programmatic Usage

```python
from pathlib import Path
from scripts.regression_tester import RegressionTester

# Initialize tester
tester = RegressionTester(test_dir=Path("tests/security_regression"))

# Generate test from finding
finding = {
    "type": "xss",
    "path": "app/views.py",
    "function": "render_comment",
    "cwe": "CWE-79",
    "severity": "high"
}

test = tester.generate_regression_test(finding)
print(f"Generated test: {test.test_id}")

# Run all tests
results = tester.run_all_tests()
print(f"Passed: {results['passed']}, Failed: {results['failed']}")

# Get statistics
stats = tester.get_stats()
print(f"Total tests: {stats['total_tests']}")
```

## Best Practices

### 1. Test Every Fixed Vulnerability
Generate regression tests for all security fixes, not just critical ones. Even low-severity bugs can resurface.

### 2. Run Tests Continuously
Include regression tests in:
- Pre-commit hooks
- Pull request checks
- Nightly builds
- Release gates

### 3. Keep Tests Updated
When refactoring code:
- Update test imports if file paths change
- Regenerate tests if function signatures change
- Archive tests for removed functionality

### 4. Review Generated Tests
While tests are auto-generated, review them to:
- Verify exploit payloads are realistic
- Add edge cases
- Ensure assertions are correct

### 5. Track Test Coverage
Monitor which vulnerability types have regression tests:
```bash
python scripts/regression_tester.py --mode stats
```

## Troubleshooting

### Tests Not Running

**Problem**: `pytest not found`
```bash
pip install pytest
```

**Problem**: Import errors in generated tests
- Verify file paths in findings are correct
- Check that tested modules are importable
- Update PYTHONPATH if needed

### Tests Failing

**Problem**: All tests fail
- Check if dependencies are installed
- Verify test runner (pytest/jest) is available
- Review test logs with `--debug`

**Problem**: Specific test fails
- Review test output to identify issue
- Check if vulnerability actually returned
- Update test if function signature changed

### False Positives

If tests fail but vulnerability isn't present:
1. Review the generated test code
2. Update assertions if behavior changed
3. Regenerate test if needed

## Integration with Argus

Regression tests integrate with Argus workflows:

```bash
# After running security scan and fixing findings
python scripts/run_ai_audit.py --output findings.json

# Extract fixed findings (findings marked as resolved)
jq '[.[] | select(.status == "fixed")]' findings.json > fixed_findings.json

# Generate regression tests
python scripts/regression_tester.py --mode generate --fixed-findings fixed_findings.json

# Add to CI/CD
git add tests/security_regression/
git commit -m "Add regression tests for fixed vulnerabilities"
```

## Metrics & Reporting

Test results are saved to `tests/security_regression/latest_results.json`:

```json
{
  "total": 10,
  "passed": 9,
  "failed": 1,
  "errors": 0,
  "skipped": 0,
  "failures": [
    {
      "test_id": "abc123",
      "vulnerability": "sql-injection",
      "file": "app/database.py",
      "severity": "critical",
      "output": "AssertionError: SQL injection vulnerability returned!"
    }
  ],
  "timestamp": "2026-01-15T03:57:04.152727"
}
```

## Future Enhancements

Planned features:
- **Test mutation** - Automatically generate variant tests
- **Coverage analysis** - Track which code paths are tested
- **Historical tracking** - Trend analysis of regression test results
- **Integration with SAST** - Auto-generate tests from scanner findings
- **Multi-framework support** - pytest, unittest, nose, jest, mocha, etc.

## Contributing

To add support for a new vulnerability type:

1. Add exploit payload to `_get_exploit_payload()`
2. Add expected behavior to `_get_expected_behavior()`
3. Add test template to `_generate_python_test()` or respective language method
4. Test with sample finding
5. Submit PR

## License

Part of Argus Security Action - MIT License
