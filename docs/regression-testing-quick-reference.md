# Security Regression Testing - Quick Reference

## Essential Commands

### Generate Tests
```bash
# From fixed findings JSON
python scripts/regression_tester.py --mode generate --fixed-findings fixed.json

# With custom test directory
python scripts/regression_tester.py --mode generate --fixed-findings fixed.json --test-dir custom/dir
```

### Run Tests
```bash
# Run all tests
python scripts/regression_tester.py --mode run

# Run specific vulnerability type
python scripts/regression_tester.py --mode run --vuln-type sql-injection

# With debug output
python scripts/regression_tester.py --mode run --debug
```

### View Statistics
```bash
# Show test statistics
python scripts/regression_tester.py --mode stats
```

## Exit Codes

- `0` - All tests passed (safe to proceed)
- `1` - Tests failed (vulnerabilities may have returned - BLOCK)
- `2` - Test errors occurred (investigate)

## Finding Format

```json
{
  "type": "sql-injection",           // Required: vulnerability type
  "path": "app/database.py",         // Required: file path
  "function": "get_user",            // Optional: function name
  "cwe": "CWE-89",                   // Optional: CWE ID
  "cve": "CVE-2024-1234",           // Optional: CVE ID
  "severity": "critical",            // Optional: critical/high/medium/low
  "description": "Fixed by..."       // Optional: fix description
}
```

## Supported Vulnerability Types

| Type | CWE | Test Template |
|------|-----|---------------|
| `sql-injection` | CWE-89 | ✅ Full |
| `xss` | CWE-79 | ✅ Full |
| `command-injection` | CWE-78 | ✅ Full |
| `path-traversal` | CWE-22 | ✅ Full |
| `xxe` | CWE-611 | ⚠️ Generic |
| `ssrf` | CWE-918 | ⚠️ Generic |
| `ldap-injection` | CWE-90 | ⚠️ Generic |
| `csrf` | CWE-352 | ⚠️ Generic |
| `open-redirect` | CWE-601 | ⚠️ Generic |

## Directory Structure

```
tests/security_regression/
├── sql_injection/
│   ├── test_<id>.py          # Generated pytest
│   └── test_<id>.json        # Metadata
├── xss/
│   ├── test_<id>.py
│   └── test_<id>.json
└── latest_results.json       # Test run results
```

## CI/CD Integration

### GitHub Actions (Workflow Already Created)
`.github/workflows/security-regression.yml`

**Triggers:**
- Pull requests (code changes)
- Push to main/develop
- Daily at 2 AM UTC
- Manual dispatch

**Output:**
- Test results in job summary
- PR comment with pass/fail
- Artifact: `latest_results.json`

### Manual CI/CD Commands

```bash
# In CI pipeline
python scripts/regression_tester.py --mode run || exit 1

# With specific tests
python scripts/regression_tester.py --mode run --vuln-type xss || exit 1
```

## Common Workflows

### After Fixing a Vulnerability

1. Extract finding details
2. Generate test: `python scripts/regression_tester.py --mode generate --fixed-findings finding.json`
3. Run test: `python scripts/regression_tester.py --mode run`
4. Commit: `git add tests/security_regression/ && git commit -m "test: Add regression test"`
5. Push: Tests run automatically in CI

### Investigating Failures

```bash
# Run with debug logging
python scripts/regression_tester.py --mode run --debug

# Check results file
cat tests/security_regression/latest_results.json | jq '.failures'

# Run specific test manually
pytest tests/security_regression/sql_injection/test_<id>.py -v
```

### Bulk Test Generation

```bash
# From Argus scan results (extract fixed findings)
jq '[.[] | select(.status == "fixed")]' scan_results.json > fixed.json
python scripts/regression_tester.py --mode generate --fixed-findings fixed.json
```

## Test Maintenance

### Update Test After Refactoring

If function signature or path changes:

1. Update metadata: `tests/security_regression/<type>/test_<id>.json`
2. Regenerate test or edit manually
3. Re-run: `python scripts/regression_tester.py --mode run`

### Archive Old Tests

```bash
# Move to archive directory
mkdir -p tests/security_regression/_archive
mv tests/security_regression/sql_injection/test_old_*.* tests/security_regression/_archive/
```

### Clean Up Test Directory

```bash
# Remove result cache
rm tests/security_regression/latest_results.json

# Remove all tests (use with caution!)
rm -rf tests/security_regression/*/
```

## Troubleshooting

### Issue: Tests Not Running

**Solution:** Check test runner installed
```bash
pip install pytest pytest-cov
```

### Issue: Import Errors

**Solution:** Verify file paths and PYTHONPATH
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
python scripts/regression_tester.py --mode run
```

### Issue: All Tests Failing

**Solution:** Check dependencies and test environment
```bash
pip install -r requirements.txt
python scripts/regression_tester.py --mode run --debug
```

### Issue: False Positive Failures

**Solution:** Review and update test assertions
```bash
# View test
cat tests/security_regression/<type>/test_<id>.py

# Edit if needed
vim tests/security_regression/<type>/test_<id>.py

# Regenerate
python scripts/regression_tester.py --mode generate --fixed-findings updated.json
```

## Advanced Usage

### Programmatic Access

```python
from scripts.regression_tester import RegressionTester

tester = RegressionTester()

# Generate test
finding = {"type": "xss", "path": "app.py", "function": "render"}
test = tester.generate_regression_test(finding)

# Run tests
results = tester.run_all_tests()
print(f"Passed: {results['passed']}, Failed: {results['failed']}")

# Get stats
stats = tester.get_stats()
```

### Custom Test Templates

Edit `scripts/regression_tester.py` and add to the template dictionary in:
- `_generate_python_test()` - for Python
- `_generate_javascript_test()` - for JavaScript/TypeScript
- `_generate_go_test()` - for Go

## Performance Tips

- **Parallel execution**: Use `pytest -n auto` for parallel test runs
- **Selective running**: Use `--vuln-type` to run specific categories
- **Incremental generation**: Only generate tests for new fixes

## Integration with Argus

```bash
# Full workflow
python scripts/run_ai_audit.py --output scan.json
# Fix vulnerabilities
jq '[.[] | select(.status == "fixed")]' scan.json > fixed.json
python scripts/regression_tester.py --mode generate --fixed-findings fixed.json
python scripts/regression_tester.py --mode run
```

## Metrics to Track

- **Total regression tests**: Growing = good
- **Test pass rate**: Should be 100%
- **Coverage by type**: Track which vulnerability types have tests
- **Test execution time**: Monitor for slowdowns

## Best Practices

1. ✅ Generate test immediately after fixing vulnerability
2. ✅ Run tests in pre-commit hooks
3. ✅ Include in CI/CD (already configured)
4. ✅ Review generated tests before committing
5. ✅ Keep tests updated when code changes
6. ✅ Monitor for test failures (= regression)
7. ❌ Don't skip failed tests
8. ❌ Don't delete tests without investigation

## Resources

- **Full Documentation**: `docs/regression-testing.md`
- **Example Workflow**: `examples/regression_testing_workflow.sh`
- **Sample Findings**: `examples/fixed_findings_sample.json`
- **CI Workflow**: `.github/workflows/security-regression.yml`

---

**Remember**: A failed regression test means a vulnerability may have returned. Investigate immediately!
