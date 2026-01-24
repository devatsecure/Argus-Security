---
title: Introduction
sidebar_position: 1
slug: /
---

# Argus Security Platform Documentation

Welcome to the comprehensive documentation for **Argus** - an AI-powered security platform that orchestrates multiple security scanners, applies intelligent triage to reduce false positives, and enforces policy gates.

## 🎯 What is Argus?

Argus is a production-ready security platform that runs as a GitHub Action, CLI tool, or deployed service. It uses advanced AI models (Claude, OpenAI, or Ollama) to provide:

- **Multi-Scanner Orchestration**: TruffleHog, Gitleaks, Semgrep, Trivy, Checkov, API Security, DAST
- **AI Triage & Noise Reduction**: 60-70% false positive suppression
- **SAST-DAST Correlation**: AI verifies if static findings are exploitable
- **Security Test Generation**: Auto-generate pytest/Jest tests for vulnerabilities
- **Supply Chain Security**: Dependency attack detection and fuzzing
- **Intelligent Caching**: 10-100x faster repeat scans
- **Observability Dashboard**: Real-time AI decision quality visualization
- **Continuous Learning**: Feedback-driven improvement

## 🚀 Quick Start

### 1. Add to Your Workflow

```yaml
name: AI Code Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      security-events: write
    
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@v3
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: 'audit'
          max-files: 50
          cost-limit: '1.0'
```

### 2. Configure Secrets

Add your AI provider API key to GitHub Secrets (or use Ollama for free):
- Go to Settings → Secrets and variables → Actions
- For Claude: Add `ANTHROPIC_API_KEY` ([Get key](https://console.anthropic.com))
- For OpenAI: Add `OPENAI_API_KEY` ([Get key](https://platform.openai.com/api-keys))
- For Ollama: No API key needed ([Setup guide](OLLAMA_SETUP.md))

### 3. Run Your First Scan

- Create a pull request or push to trigger the workflow
- Review the generated report in `.argus/reviews/`
- Check the PR comment for actionable findings (noise auto-suppressed)
- View SARIF report in GitHub Security tab

## 📚 Documentation Structure

### Architecture
Understand the system design and components:
- [Architecture Overview](./architecture/overview.md) - System design and data flow
- Component documentation for each specialized agent

### ADRs (Architecture Decision Records)
Learn about key technical decisions:
- [ADR-0001: Use Anthropic Claude](./adrs/0001-use-anthropic-claude.md)
- [ADR-0002: Multi-Agent Architecture](./adrs/001-multi-agent-architecture.md)

### Runbooks
Operational guides for deployment and maintenance:
- [GitHub Action Deployment](./playbooks/github-action-deployment.md)
- Troubleshooting and incident response guides

### References
Complete configuration and API references:
- [Action Inputs Reference](./references/action-inputs.md)
- Environment variables and configuration

## 🎨 Key Features

### 🔒 Security First
- **7 Security Scanners**: TruffleHog, Gitleaks, Semgrep, Trivy, Checkov, API Security, DAST
- **OWASP Coverage**: Top 10 Web + API Top 10
- **AI-Powered Triage**: 60-70% false positive reduction
- **SAST-DAST Correlation**: Verify exploitability
- **Security Test Generation**: Auto-generate tests for found vulnerabilities

### 💰 Cost Effective
- **Ollama (free)**: $0.00 per run, 100% local processing
- **Claude**: ~$0.35 per run (best accuracy)
- **OpenAI**: ~$0.50 per run (alternative)
- **Intelligent caching**: 10-100x faster repeat scans
- **Cost limits**: Hard cap to prevent overruns

### ⚡ Fast & Efficient
- **Parallel scanning**: 4+ scanners run simultaneously
- **Smart caching**: <1 minute for cached scans
- **Incremental analysis**: Only scan changed files
- **Progress bars**: Real-time feedback

### 🎯 Actionable Insights
- Clear severity ratings (critical/high/medium/low)
- Exploitability scoring (trivial/moderate/complex/theoretical)
- Detailed remediation guidance
- Code examples and references

### 🔧 Flexible Configuration
- Multiple AI providers (Claude, OpenAI, Ollama)
- Customizable review types (audit, security, review)
- Project-type aware analysis
- Path inclusion/exclusion patterns

## 📊 Example Output

### Metrics
```json
{
  "version": "1.0.16",
  "files_reviewed": 25,
  "lines_analyzed": 3500,
  "cost_usd": 0.285,
  "duration_seconds": 145,
  "findings": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8
  }
}
```

### Finding Example
```markdown
## 🔴 CRITICAL: SQL Injection Vulnerability

**File**: `api/users.py:45`  
**Category**: Security  
**Exploitability**: Trivial

### Issue
User input directly concatenated into SQL query without sanitization.

### Impact
Attacker can execute arbitrary SQL commands, potentially accessing or modifying all database data.

### Remediation
Use parameterized queries or ORM methods:

\`\`\`python
# Before (vulnerable)
query = f"SELECT * FROM users WHERE id = {user_id}"

# After (secure)
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
\`\`\`

### References
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
```

## 🛠️ Common Use Cases

### PR Reviews
```yaml
on:
  pull_request:
    branches: [main]

with:
  only-changed: true
  comment-on-pr: true
  fail-on: 'security:critical,security:high'
```

### Scheduled Security Audits
```yaml
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2am

with:
  review-type: 'security'
  aardvark-mode: true
  max-files: 100
```

### Pre-Release Quality Gate
```yaml
on:
  push:
    tags:
      - 'v*'

with:
  review-type: 'audit'
  fail-on-blockers: true
  upload-reports: true
```

## 🔗 External Resources

- **GitHub Repository**: [devatsecure/Argus-Security](https://github.com/devatsecure/Argus-Security)
- **Anthropic Claude**: [anthropic.com](https://www.anthropic.com/)
- **SARIF Format**: [SARIF Spec](https://sarifweb.azurewebsites.net/)
- **GitHub Code Scanning**: [Docs](https://docs.github.com/en/code-security/code-scanning)

## 🤝 Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on:
- Reporting issues
- Submitting pull requests
- Development setup
- Testing procedures

## 📄 License

MIT License - see [LICENSE](../LICENSE) for details.

## 🆘 Need Help?

- **Documentation**: Browse the sections in the sidebar
- **Issues**: [GitHub Issues](https://github.com/devatsecure/Argus-Security/issues)
- **FAQ**: [Frequently Asked Questions](../docs/FAQ.md)
- **Troubleshooting**: [Troubleshooting Guide](../docs/TROUBLESHOOTING.md)

---

> ⚠️ **AI-Generated Documentation Notice**
> 
> Parts of this documentation were generated using AI agents from the Agent Doc Creator system. All AI-generated content is marked with disclaimers and should be reviewed by humans before being treated as canonical documentation.
