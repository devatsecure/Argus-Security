# Automated Remediation

## Overview

The Automated Remediation feature uses AI to generate fix suggestions for security vulnerabilities. It provides code patches, explanations, and testing recommendations to help developers quickly fix security issues.

## How It Works

For each security finding, the remediation engine:

1. **Analyzes the Vulnerability**:
   - Reads vulnerability description and CWE mapping
   - Examines vulnerable code snippet
   - Understands language-specific patterns

2. **Generates Fix Suggestions**:
   - AI-powered code patch generation
   - Context-aware fixes (understands codebase patterns)
   - Language-specific best practices
   - Security hardening recommendations

3. **Provides Testing Guidance**:
   - Test cases to verify fix
   - Regression test suggestions
   - Security test recommendations

## Usage

### CLI Usage

```bash
# Generate remediation suggestions for all findings
./scripts/argus remediate --findings findings.json --output fixes.md

# With specific AI provider
./scripts/argus remediate --findings findings.json --ai-provider anthropic --output fixes.md

# Remediation is automatically applied during scans when enabled (default)
python scripts/run_ai_audit.py --enable-remediation
```

### Python API

```python
from hybrid_analyzer import HybridSecurityAnalyzer

# Create analyzer with remediation enabled (default)
analyzer = HybridSecurityAnalyzer(
    enable_remediation=True,  # Enabled by default
    ai_provider="anthropic"
)

# Run analysis - remediation suggestions automatically generated
result = analyzer.analyze(target_path="/path/to/repo")

# Access remediation suggestions
for finding in result.findings:
    print(f"Finding: {finding.title}")
    print(f"Fix: {finding.recommendation}")
```

### Standalone Usage

```python
from remediation_engine import RemediationEngine

engine = RemediationEngine(ai_provider="anthropic")

# Generate fix for a specific finding
suggestion = engine.suggest_fix(finding)

print(f"Fix Explanation: {suggestion['fix_explanation']}")
print(f"Code Patch:\n{suggestion['code_patch']}")
print(f"Testing: {suggestion['testing_recommendations']}")
```

## Configuration

Remediation is **enabled by default** and uses the same AI provider as triage. To disable:

```bash
python scripts/run_ai_audit.py --enable-remediation=false
```

## Output Format

### Markdown Report

```markdown
# Security Remediation Suggestions

## SQL Injection in login.py

**Finding ID:** semgrep-sql-injection-001

**Fix:**
Replace string concatenation with parameterized queries to prevent SQL injection.

**Code Patch:**
\```python
# Before (vulnerable):
query = f"SELECT * FROM users WHERE username = '{username}'"

# After (secure):
query = "SELECT * FROM users WHERE username = %s"
cursor.execute(query, (username,))
\```

**Testing:**
1. Test with normal input: `username='admin'`
2. Test with malicious input: `username="admin' OR '1'='1"`
3. Verify malicious input is safely escaped
4. Add pytest test case for SQL injection prevention

---
```

### JSON Format

```json
{
  "finding_id": "semgrep-sql-injection-001",
  "fix_explanation": "Replace string concatenation with parameterized queries...",
  "code_patch": "query = \"SELECT * FROM users WHERE username = %s\"...",
  "testing_recommendations": "1. Test with normal input...",
  "confidence": 0.95,
  "estimated_effort": "5-10 minutes"
}
```

## Integration

Remediation runs automatically as **Phase 2.5** in the hybrid analyzer workflow:

1. **Phase 1**: Scanners detect vulnerabilities
2. **Phase 2**: AI triages findings
3. **Phase 2.5** (Remediation): AI generates fix suggestions
4. **Phase 3+**: Argus review, sandbox validation, output

## Best Practices

1. **Review AI-Generated Fixes**: Always review code patches before applying
2. **Test Thoroughly**: Run suggested tests plus your own edge cases
3. **Context Matters**: AI understands code patterns but may need adjustments
4. **Iterative Refinement**: Use feedback to improve fix suggestions over time
5. **Security First**: Verify fixes don't introduce new vulnerabilities

## Example Output

```
🔧 Automated Remediation:
   Total findings: 23
   Remediation suggestions: 23
   Output: fixes.md

   Fix Categories:
   - SQL Injection: 5 fixes (parameterized queries, ORM usage)
   - XSS: 7 fixes (input sanitization, output encoding)
   - Path Traversal: 3 fixes (path validation, allowlisting)
   - Hardcoded Secrets: 4 fixes (env vars, secret managers)
   - CSRF: 4 fixes (CSRF tokens, SameSite cookies)
```

## Supported Vulnerability Types

The remediation engine provides fixes for:

- **Injection Flaws**: SQL injection, command injection, LDAP injection
- **XSS**: Reflected, stored, DOM-based XSS
- **Broken Authentication**: Session fixation, weak passwords, JWT issues
- **Sensitive Data Exposure**: Hardcoded secrets, insecure storage
- **XXE**: XML external entity attacks
- **Broken Access Control**: IDOR, missing authorization checks
- **Security Misconfiguration**: Insecure defaults, verbose errors
- **CSRF**: Cross-site request forgery
- **Path Traversal**: Directory traversal, file inclusion
- **Deserialization**: Insecure object deserialization

## Language Support

AI-powered remediation supports:

- **Python**: Django, Flask, FastAPI patterns
- **JavaScript/TypeScript**: React, Express, Node.js
- **Java**: Spring Boot, Jakarta EE
- **Go**: Standard library, Gin, Echo
- **Ruby**: Rails, Sinatra
- **PHP**: Laravel, Symfony

## Troubleshooting

**Q: Why are some findings not remediated?**

A: Findings with good existing recommendations (>100 chars) are skipped. Also, some vulnerability types may not have AI-generated fixes yet.

**Q: Can I customize fix templates?**

A: Yes! Extend `RemediationEngine` class to add custom fix templates or override AI prompts.

**Q: How accurate are AI-generated fixes?**

A: ~85-90% accuracy for common vulnerability types. Always review and test before applying.

**Q: Does this modify my code automatically?**

A: No! Remediation only generates suggestions. You must manually review and apply fixes.

## Performance

- **Speed**: ~2-5 seconds per finding (with AI provider)
- **Cost**: ~$0.01-0.03 per finding (Claude Sonnet)
- **Caching**: Identical findings reuse cached fix suggestions

## Example Fix Suggestions

### SQL Injection

**Before:**
```python
query = f"SELECT * FROM users WHERE email = '{email}'"
cursor.execute(query)
```

**After:**
```python
query = "SELECT * FROM users WHERE email = %s"
cursor.execute(query, (email,))
```

### XSS

**Before:**
```javascript
document.getElementById('output').innerHTML = userInput;
```

**After:**
```javascript
document.getElementById('output').textContent = userInput;
// Or use a sanitization library for HTML content
```

### Hardcoded Secret

**Before:**
```python
API_KEY = "sk-1234567890abcdef"
```

**After:**
```python
import os
API_KEY = os.getenv('API_KEY')
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")
```

---

**Related Documentation:**
- [AI Triage Strategy](../adrs/0003-ai-triage-strategy.md)
- [Hybrid Analyzer](../architecture/overview.md)
- [Best Practices](../best-practices.md)
