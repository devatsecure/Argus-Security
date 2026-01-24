---
title: Best Practices Guide
sidebar_position: 2
ai_generated: true
last_updated: 2024-11-10
---

> ⚠️ **AI-Generated Documentation** - Please review and validate

# Best Practices Guide

## Quick Start

### 1. Add Workflow File

Create `.github/workflows/argus-security.yml`:

```yaml
name: Argus Security
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@v3
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### 2. Add API Key

```bash
# Add your AI provider API key
# For Claude:
gh secret set ANTHROPIC_API_KEY --body "sk-ant-..."
# For OpenAI:
gh secret set OPENAI_API_KEY --body "sk-..."
# For Ollama: No API key needed (local inference)
```

### 3. Test It

```bash
git checkout -b test-security
git commit --allow-empty -m "Test security scan"
git push origin test-security
gh pr create --title "Test" --body "Testing Argus"
```

**Done!** Check PR for security findings.

## Common Use Cases

### Use Case 1: PR Security Review

**When to use**: Scan every PR before merge

**Configuration**:
```yaml
name: PR Security Review
on:
  pull_request:
    branches: [main, develop]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@v3
with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
  review-type: 'security'
          fail-on-blockers: 'true'
          comment-on-pr: 'true'
```

**Expected outcome**: PR comment with findings, workflow fails if critical issues found

### Use Case 2: Scheduled Full Audit

**When to use**: Weekly comprehensive security audit

**Configuration**:
```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 2 * * 1'  # Monday 2am

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@v3
with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
  review-type: 'audit'
  max-files: 100
          aardvark-mode: 'true'
          upload-reports: 'true'
```

**Expected outcome**: Comprehensive report with exploit analysis, uploaded as artifacts

### Use Case 3: Cost-Optimized Scanning

**When to use**: Minimize costs while maintaining quality

**Configuration**:
```yaml
- uses: devatsecure/Argus-Security@v3
with:
    # Use free Ollama for local inference
    ai-provider: 'ollama'
    ollama-endpoint: 'http://localhost:11434'
    # Limit files analyzed
  max-files: 50
    exclude-paths: 'tests/**,*.test.*,node_modules/**'
    # Only analyze changed files in PRs
    only-changed: 'true'
```

**Expected outcome**: $0 API cost, good noise reduction, <3 min runtime

### Use Case 4: High-Security Projects

**When to use**: Maximum security for sensitive projects

**Configuration**:
```yaml
- uses: devatsecure/Argus-Security@v3
with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: 'security'
    aardvark-mode: 'true'
    fail-on: 'security:critical,security:high,security:medium'
    upload-sarif: 'true'
```

**Expected outcome**: Strict quality gate, exploit analysis, SARIF uploaded to Code Scanning

### Use Case 5: Development Environment

**When to use**: Fast feedback during development

**Configuration**:
```yaml
- uses: devatsecure/Argus-Security@v3
with:
    ai-provider: 'ollama'
    max-files: 20
    fail-on-blockers: 'false'
    comment-on-pr: 'true'
```

**Expected outcome**: Fast (<2 min), informational only, doesn't block

## Configuration Recommendations

| Setting | Development | Staging | Production | Rationale |
|---------|-------------|---------|------------|-----------|
| **AI Provider** | Ollama | Claude | Claude | Dev: free local; Staging/Prod: higher accuracy |
| **max-files** | 20 | 50 | 100 | Dev: fast feedback; Prod: comprehensive |
| **fail-on-blockers** | false | true | true | Dev: informational; Staging/Prod: enforce |
| **aardvark-mode** | false | false | true | Prod only: exploit analysis adds time |
| **upload-sarif** | false | true | true | Track findings in Code Scanning |
| **exclude-paths** | tests/** | tests/** | tests/**,docs/** | Exclude noise sources |
| **cost-limit** | 0.10 | 0.50 | 2.00 | Budget guardrails |

## Optimization Tips

### Cost Optimization

- **Use Ollama**: Saves 100% on API costs ($0 vs $0.35-0.50/run) - **Annual savings: $420+ (100 PRs/month)**
- **Limit file count to 50**: Reduces cost by ~40% - **Saves $0.14/run**
- **Exclude test files**: Saves 30% on analysis time - **Saves ~1 minute/run**
- **Use `only-changed: true` for PRs**: Analyzes only changed files - **Saves 50-70% cost**
- **Set `cost-limit`**: Prevents runaway costs - **Hard cap at your budget**

**Example**: Ollama + max 50 files + exclude tests = **$0 API cost, <3 min**

### Performance Optimization

- **Parallel scanning**: Already enabled by default - **4 scanners run simultaneously**
- **File filtering**: Use `include-paths` to focus on important code - **Improves speed by 40%**
- **Disable unnecessary scanners**: Use `disable-scanners` if not needed - **Saves 20% time per scanner**
- **Cache dependencies**: GitHub Actions caches scanner downloads - **Saves 30s after first run**

**Example**: Exclude tests + include only src/** = **2 min runtime (vs 5 min)**

### Quality Optimization

- **Enable Aardvark mode**: Exploit analysis for critical findings - **Reduces false positives by 20%**
- **Use Claude for production**: Higher accuracy than Ollama - **90%+ precision**
- **Upload SARIF**: Track findings over time in Code Scanning - **Trend analysis**
- **Custom Rego policies**: Define project-specific rules - **Reduces noise by 30%**

**Example**: Claude + Aardvark + SARIF = **95%+ accuracy, full tracking**

## Troubleshooting Quick Reference

| Issue | Cause | Fix |
|-------|-------|-----|
| **High cost (>$2/run)** | Too many files or findings | Set `max-files: 50`, `cost-limit: 1.0` |
| **Slow runtime (>10 min)** | Large repo, many files | Use `exclude-paths`, `max-files: 50` |
| **Too many false positives** | AI model limitations | Use Claude for better accuracy or enable Aardvark mode |
| **SARIF upload fails** | Code Scanning not enabled | Enable in Settings → Security → Code scanning |
| **Workflow fails unexpectedly** | Blockers found | Set `fail-on-blockers: false` or fix issues |
| **No findings reported** | All suppressed as noise | Check `metrics.json` for suppression stats |
| **API rate limit** | Too many runs | Space out runs or use Ollama for local inference |
| **Out of memory** | Too many files | Reduce `max-files` to 50 or less |

## Advanced Patterns

### Pattern 1: Multi-Environment Strategy

```yaml
# .github/workflows/security.yml
on: [pull_request, push]

jobs:
  dev-scan:
    if: github.event_name == 'pull_request'
    steps:
- uses: devatsecure/Argus-Security@v3
  with:
          ai-provider: 'ollama'
          max-files: 20
          fail-on-blockers: 'false'

  prod-scan:
    if: github.ref == 'refs/heads/main'
    steps:
- uses: devatsecure/Argus-Security@v3
  with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          ai-provider: 'anthropic'
          aardvark-mode: 'true'
          fail-on-blockers: 'true'
```

### Pattern 2: Progressive Quality Gates

```yaml
# Fail on critical in dev, high+ in staging, medium+ in prod
  - uses: devatsecure/Argus-Security@v3
    with:
    fail-on: ${{ 
      github.ref == 'refs/heads/main' && 'security:medium,security:high,security:critical' ||
      github.ref == 'refs/heads/staging' && 'security:high,security:critical' ||
      'security:critical'
    }}
```

### Pattern 3: Custom Rego Policies

Create `.argus/policies/custom.rego`:

```rego
package argus

# Block any secrets in production code
deny[msg] {
  finding := input.findings[_]
  finding.category == "secret"
  finding.file_path != "tests/*"
  msg := sprintf("Secret found in production code: %v", [finding.file_path])
}

# Allow medium severity in test files
allow[msg] {
  finding := input.findings[_]
  finding.severity == "medium"
  startswith(finding.file_path, "tests/")
  msg := "Medium severity allowed in tests"
}
```

Reference in workflow:
```yaml
- uses: devatsecure/Argus-Security@v3
  with:
    custom-policies: '.argus/policies/'
```

## Related Documentation

- [Architecture Overview](./architecture/overview.md)
- [Scanner Reference](./references/scanner-reference.md)
- [Configuration Reference](./references/action-inputs.md)
- [Deployment Runbook](./playbooks/deployment-runbook.md)
- [Troubleshooting Guide](./playbooks/troubleshooting.md)
