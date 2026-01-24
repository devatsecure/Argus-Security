#!/bin/bash
# Example workflow: Security Scan → Fix → Generate Regression Tests → CI/CD Integration
# This demonstrates the complete regression testing workflow with Argus

set -e

echo "========================================="
echo "Security Regression Testing Workflow"
echo "========================================="
echo ""

# Step 1: Run initial security scan
echo "Step 1: Running security scan..."
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --ai-provider anthropic \
  --output-file initial_scan.json \
  --semgrep-enabled \
  --trivy-enabled \
  --gitleaks-enabled

echo "✅ Security scan complete"
echo ""

# Step 2: Developer fixes vulnerabilities
echo "Step 2: Simulating vulnerability fixes..."
echo "(In practice, developer would fix the code here)"

# Create sample fixed findings
cat > fixed_findings.json <<'EOF'
[
  {
    "type": "sql-injection",
    "path": "app/database.py",
    "function": "get_user_by_id",
    "cwe": "CWE-89",
    "cve": "CVE-2024-1234",
    "severity": "critical",
    "description": "SQL injection in user lookup - fixed by using parameterized queries",
    "fix_commit": "abc123",
    "fixed_by": "developer@example.com",
    "snippet": "# Before: db.execute(f'SELECT * FROM users WHERE id = {user_id}')\n# After: db.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
  },
  {
    "type": "xss",
    "path": "app/templates.py",
    "function": "render_comment",
    "cwe": "CWE-79",
    "severity": "high",
    "description": "XSS in comment rendering - fixed by HTML escaping",
    "fix_commit": "def456",
    "fixed_by": "developer@example.com"
  },
  {
    "type": "command-injection",
    "path": "app/file_processor.py",
    "function": "convert_file",
    "cwe": "CWE-78",
    "severity": "critical",
    "description": "Command injection in file conversion - fixed by using subprocess.run() with list arguments",
    "fix_commit": "ghi789",
    "fixed_by": "developer@example.com"
  }
]
EOF

echo "✅ Vulnerabilities fixed (sample data created)"
echo ""

# Step 3: Generate regression tests
echo "Step 3: Generating regression tests..."
python scripts/regression_tester.py \
  --mode generate \
  --fixed-findings fixed_findings.json \
  --debug

echo "✅ Regression tests generated"
echo ""

# Step 4: View test statistics
echo "Step 4: Regression test statistics..."
python scripts/regression_tester.py --mode stats
echo ""

# Step 5: Run regression tests
echo "Step 5: Running regression tests..."
if python scripts/regression_tester.py --mode run; then
    echo "✅ All regression tests passed"
else
    echo "❌ Some regression tests failed - vulnerabilities may have returned!"
    exit 1
fi
echo ""

# Step 6: Commit tests to version control
echo "Step 6: Committing regression tests..."
git add tests/security_regression/
git status tests/security_regression/
echo ""
echo "To commit these tests, run:"
echo "  git commit -m 'test: Add security regression tests for fixed vulnerabilities'"
echo "  git push"
echo ""

# Step 7: Show example of checking specific vulnerability
echo "Step 7: Testing specific vulnerability type..."
python scripts/regression_tester.py \
  --mode run \
  --vuln-type sql-injection
echo ""

# Step 8: Integration with CI/CD
echo "Step 8: CI/CD Integration"
echo "The regression tests will now run automatically in:"
echo "  - Pull requests (see .github/workflows/security-regression.yml)"
echo "  - Main branch pushes"
echo "  - Daily scheduled runs"
echo "  - Manual workflow dispatch"
echo ""

# Step 9: Show results file
echo "Step 9: Latest test results..."
if [ -f "tests/security_regression/latest_results.json" ]; then
    echo "Results file: tests/security_regression/latest_results.json"
    cat tests/security_regression/latest_results.json | jq '.'
else
    echo "No results file found"
fi
echo ""

# Step 10: Cleanup
echo "Step 10: Cleanup example files..."
echo "Keeping regression tests for demonstration"
echo ""

echo "========================================="
echo "✅ Workflow Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Review generated tests in tests/security_regression/"
echo "2. Commit tests to version control"
echo "3. Tests will run automatically in CI/CD"
echo "4. Monitor for test failures (= vulnerability returned)"
echo ""
echo "To view a generated test:"
echo "  cat tests/security_regression/sql_injection/test_*.py"
echo ""
