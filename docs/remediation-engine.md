# Automated Remediation Engine

The Automated Remediation Engine is an AI-powered component of Argus that generates fix suggestions and patches for security vulnerabilities detected by scanners.

## Overview

The Remediation Engine analyzes security findings and produces:
- **Code patches** in unified diff format for easy application
- **Detailed explanations** of what each fix does and why it's secure
- **Testing recommendations** to verify the fix works correctly
- **CWE references** for compliance and tracking
- **Confidence scores** to help prioritize fixes

## Features

### 🤖 AI-Powered Fix Generation

When LLMManager is available (with Anthropic/OpenAI/Ollama), the engine:
- Analyzes vulnerable code in context
- Generates language-specific secure fixes
- Provides detailed security explanations
- Suggests comprehensive testing approaches

### 📝 Template-Based Fallback

For common vulnerability types or when AI is unavailable:
- Uses battle-tested fix templates
- Provides language-specific examples
- Includes industry best practices
- Works offline without API costs

### 🛡️ Supported Vulnerability Types

| Vulnerability | Fix Strategy | CWE |
|--------------|--------------|-----|
| SQL Injection | Parameterized queries | CWE-89 |
| XSS | Output escaping, CSP | CWE-79 |
| Command Injection | Avoid shell=True, sanitize | CWE-78 |
| Path Traversal | Path validation, normalization | CWE-22 |
| SSRF | URL whitelisting | CWE-918 |
| XXE | Disable external entities | CWE-611 |
| Hard-coded Secrets | Environment variables | CWE-798 |
| Insecure Crypto | Modern algorithms | CWE-327 |
| Insecure Deserialization | Safe serialization | CWE-502 |
| CSRF | Token validation | CWE-352 |

### 🌐 Multi-Language Support

Supports fixes for:
- Python
- JavaScript/TypeScript
- Java
- Go
- Ruby
- PHP
- C#
- C/C++
- Rust
- Kotlin
- Swift
- And more...

## Usage

### Command Line

```bash
# Basic usage
python scripts/remediation_engine.py \
  --findings findings.json \
  --output remediation_report.md

# JSON output
python scripts/remediation_engine.py \
  --findings findings.json \
  --output fixes.json \
  --format json

# Limit number of findings
python scripts/remediation_engine.py \
  --findings findings.json \
  --max-findings 10

# Debug mode
python scripts/remediation_engine.py \
  --findings findings.json \
  --debug
```

### Programmatic API

```python
from remediation_engine import RemediationEngine

# Initialize engine
engine = RemediationEngine()

# Process findings
findings = [
    {
        "id": "sql-001",
        "type": "sql_injection",
        "path": "app/database.py",
        "line": 45,
        "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")'
    }
]

# Generate fixes
suggestions = engine.generate_batch_fixes(findings)

# Export report
engine.export_as_markdown(suggestions, "report.md")
engine.export_as_json(suggestions, "fixes.json")

# Access individual suggestions
for suggestion in suggestions:
    print(f"Fix for {suggestion.vulnerability_type}")
    print(f"Confidence: {suggestion.confidence}")
    print(f"Diff:\n{suggestion.diff}")
```

## Input Format

The engine accepts findings in a flexible JSON format:

```json
[
  {
    "id": "unique-finding-id",
    "type": "vulnerability-type",
    "path": "path/to/file.py",
    "line": 45,
    "severity": "high",
    "message": "Description of the issue",
    "code_snippet": "vulnerable code here"
  }
]
```

Or as a wrapper object:

```json
{
  "findings": [...],
  "results": [...],
  "vulnerabilities": [...]
}
```

The engine is compatible with:
- Argus normalized findings
- Semgrep SARIF output
- Trivy JSON output
- TruffleHog JSON output
- Gitleaks JSON output
- Custom scanner outputs

## Output Formats

### Markdown Report

Human-readable report with:
- Summary statistics
- Confidence distribution
- Individual fix recommendations with:
  - Original vs. fixed code
  - Unified diff
  - Explanation
  - Testing recommendations
  - CWE references

Example:
```markdown
# Security Remediation Recommendations

**Total Vulnerabilities:** 5
**Confidence Distribution:**
- High: 2
- Medium: 3
- Low: 0

---

## 1. sql_injection

**File:** `app/database.py:45`
**Confidence:** HIGH
**CWE:** CWE-89

### Explanation
Use parameterized queries to prevent SQL injection...

### Original Code
```python
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
```

### Fixed Code
```python
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
```

### Diff
```diff
--- a/app/database.py
+++ b/app/database.py
@@ -1 +1 @@
-cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
+cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
```

### Testing Recommendations
- Test with SQL injection payloads (e.g., ' OR 1=1 --)
- Verify parameterized queries are used
- Run SQLMap to verify fix
```

### JSON Output

Machine-readable format for automation:

```json
{
  "generated_at": "2026-01-15T12:00:00Z",
  "total_suggestions": 5,
  "suggestions": [
    {
      "finding_id": "sql-001",
      "vulnerability_type": "sql_injection",
      "file_path": "app/database.py",
      "line_number": 45,
      "original_code": "...",
      "fixed_code": "...",
      "diff": "...",
      "explanation": "...",
      "testing_recommendations": [...],
      "confidence": "high",
      "cwe_references": ["CWE-89"],
      "metadata": {
        "generator": "ai",
        "provider": "anthropic",
        "model": "claude-sonnet-4-5-20250929"
      }
    }
  ]
}
```

## Confidence Levels

The engine assigns confidence levels to each fix:

- **High (90-100%)**: AI-generated fix with comprehensive context, or perfect template match
- **Medium (70-90%)**: Template-based fix for known vulnerability pattern
- **Low (<70%)**: Generic suggestion requiring manual review

### Recommended Actions by Confidence

```python
# Filter by confidence
high_confidence = [s for s in suggestions if s.confidence == "high"]
medium_confidence = [s for s in suggestions if s.confidence == "medium"]
low_confidence = [s for s in suggestions if s.confidence == "low"]

# Apply high confidence fixes automatically (with review)
for suggestion in high_confidence:
    apply_patch(suggestion.diff)
    create_pr(suggestion)

# Review medium confidence fixes
for suggestion in medium_confidence:
    request_manual_review(suggestion)

# Manually assess low confidence fixes
for suggestion in low_confidence:
    assign_to_security_team(suggestion)
```

## Integration with Argus Workflow

### 1. After Security Scan

```bash
# Run security scan
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --output-file findings.json

# Generate remediation suggestions
python scripts/remediation_engine.py \
  --findings findings.json \
  --output remediation_report.md
```

### 2. In GitHub Actions

```yaml
- name: Security Scan
  uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    output-file: findings.json

- name: Generate Fixes
  run: |
    python scripts/remediation_engine.py \
      --findings findings.json \
      --output fixes.json \
      --format json

- name: Create PR with Fixes
  run: |
    # Parse fixes.json and create PR with patches
    gh pr create --title "Security Fixes" --body-file remediation_report.md
```

### 3. With CI/CD Pipeline

```bash
#!/bin/bash
# remediation-pipeline.sh

# 1. Run scanners
python scripts/run_ai_audit.py --output findings.json

# 2. Generate fixes
python scripts/remediation_engine.py \
  --findings findings.json \
  --output fixes.json \
  --format json

# 3. Filter high confidence fixes
jq '.suggestions[] | select(.confidence == "high")' fixes.json > auto_fixes.json

# 4. Apply patches automatically
while read -r suggestion; do
  diff=$(echo "$suggestion" | jq -r '.diff')
  echo "$diff" | patch -p1
done < auto_fixes.json

# 5. Commit and push
git add -u
git commit -m "chore: Auto-apply security fixes"
git push
```

## AI Provider Configuration

The engine supports multiple AI providers:

### Anthropic (Claude)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export AI_PROVIDER="anthropic"
```

### OpenAI (GPT-4)

```bash
export OPENAI_API_KEY="sk-..."
export AI_PROVIDER="openai"
```

### Ollama (Local)

```bash
export OLLAMA_ENDPOINT="http://localhost:11434"
export AI_PROVIDER="ollama"
```

### Auto-Detection

If `AI_PROVIDER` is not set, the engine auto-detects based on available keys:
1. Anthropic (preferred for security)
2. OpenAI
3. Ollama (local/free)
4. Template-only (fallback)

## Examples

See `/home/user/argus-action/examples/remediation_example.py` for comprehensive examples:
- Basic usage
- Single finding processing
- Export formats
- Filtering by confidence

## Advanced Usage

### Custom Templates

Add custom templates for organization-specific patterns:

```python
from remediation_engine import RemediationEngine

engine = RemediationEngine()

# Add custom template
engine.FIX_TEMPLATES["custom_pattern"] = {
    "pattern": r"dangerous_function\(",
    "template": "Use safe alternative",
    "example": {
        "python": {
            "before": "dangerous_function(input)",
            "after": "safe_function(sanitize(input))"
        }
    },
    "testing": ["Test with malicious input"]
}
```

### Custom AI Prompts

```python
# Override AI generation with custom prompt
def custom_ai_generate(finding):
    prompt = f"""
    Fix this {finding['type']} vulnerability using our internal
    security library SecureLib:

    {finding['code_snippet']}
    """
    # ... call LLM with custom prompt

engine._ai_generate_fix = custom_ai_generate
```

## Limitations

- AI-generated fixes require manual review before production
- Template fixes may need language-specific adaptation
- Complex vulnerabilities may require architectural changes
- Context-dependent fixes may not capture all edge cases

## Best Practices

1. **Always review fixes before applying**
   - Even high-confidence fixes should be reviewed
   - Test thoroughly in non-production environment

2. **Use confidence scores wisely**
   - Automate high-confidence fixes with human review
   - Manually assess medium/low confidence fixes

3. **Validate with testing**
   - Follow testing recommendations
   - Run security scanners after applying fixes
   - Perform integration testing

4. **Track fix effectiveness**
   - Monitor false positive rates
   - Collect feedback on fix quality
   - Iterate on templates and prompts

## Troubleshooting

### "LLMManager not available"

**Cause**: Missing dependencies or API keys

**Solution**:
```bash
pip install anthropic openai tenacity
export ANTHROPIC_API_KEY="your-key"
```

### "No fixes generated"

**Cause**: Input format mismatch or empty findings

**Solution**: Verify input JSON format matches expected structure

### "Low confidence fixes"

**Cause**: Uncommon vulnerability type or insufficient context

**Solution**: Use AI provider for better fixes, or create custom template

## Performance

- **Template fixes**: ~10ms per finding
- **AI fixes**: ~2-5 seconds per finding (depending on provider)
- **Batch processing**: Parallelizable (future enhancement)

## Cost Estimation

Using AI providers (per fix):
- Anthropic Claude: ~$0.01-0.03
- OpenAI GPT-4: ~$0.02-0.05
- Ollama: Free (local)

For 100 findings: ~$1-5 USD

## Roadmap

Future enhancements:
- [ ] Parallel batch processing for faster throughput
- [ ] Auto-apply patches with git integration
- [ ] PR creation with fix commits
- [ ] Learning from feedback (fix quality improvement)
- [ ] Multi-file context awareness
- [ ] Integration with IDE extensions
- [ ] Real-time fix suggestions

## Contributing

To add support for new vulnerability types:

1. Add template to `FIX_TEMPLATES` dict
2. Add CWE mapping to `CWE_MAP`
3. Add language-specific examples
4. Add comprehensive testing recommendations

Example:
```python
"new_vuln_type": {
    "pattern": r"regex_pattern",
    "template": "Description of fix",
    "example": {
        "python": {
            "before": "vulnerable code",
            "after": "fixed code"
        }
    },
    "testing": ["Test case 1", "Test case 2"]
}
```

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [NIST Secure Coding Guidelines](https://www.nist.gov/programs-projects/secure-coding)
- [Argus Documentation](../README.md)
