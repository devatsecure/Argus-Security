# ⚡ 5-Minute Quick Start Guide

Get Argus running in 5 minutes or less!

---

## 🎯 Choose Your Path

### 🐳 Option 1: Docker (Fastest - 2 Minutes)

**No installation required!** Just Docker and an API key.

```bash
# 1. Get your API key (choose one):
#    - Anthropic: https://console.anthropic.com/
#    - OpenAI: https://platform.openai.com/api-keys

# 2. Run security audit on any repository
docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=your_key_here \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit

# 3. Check results
cat .argus/reviews/audit-report.md
```

**That's it!** ✅

---

### ⚙️ Option 2: GitHub Actions (Best for CI/CD - 3 Minutes)

Add to `.github/workflows/security.yml`:

```yaml
name: Security Review

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: AI Security Review
        uses: devatsecure/argus-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          severity_threshold: high
```

**Add your API key:**
1. Go to: `Settings → Secrets → Actions`
2. Add: `ANTHROPIC_API_KEY`
3. Commit and push!

---

### 🐍 Option 3: Python CLI (Most Flexible - 5 Minutes)

```bash
# 1. Install via pip
pip install git+https://github.com/devatsecure/argus-action.git

# 2. Set API key
export ANTHROPIC_API_KEY=your_key_here

# 3. Run audit
argus /path/to/repo audit

# 4. View results
cat .argus/reviews/audit-report.md
```

---

## 🎬 See It In Action

### Live Demo
Try it on our demo repository:

```bash
# Clone demo repo with intentional vulnerabilities
git clone https://github.com/devatsecure/vulnerable-demo-app
cd vulnerable-demo-app

# Run Argus
docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=your_key_here \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit
```

**Expected output:**
```
📊 Analysis Complete:
   🔴 3 SQL Injection vulnerabilities (High)
   🟠 5 XSS findings (Medium)
   ⚠️  12 Dependency CVEs (8 High, 4 Critical)
   ✅ 2 findings auto-suppressed (false positives)
   
💰 Cost: $0.42
⏱️  Duration: 3.2 minutes
```

### Video Tutorial
[![Watch Quick Start](https://img.shields.io/badge/▶️-Watch_Tutorial-red?style=for-the-badge)](https://youtube.com/placeholder)

---

## 📝 Example Use Cases

### Use Case 1: PR Review Automation

**Before Argus:**
```
1. Developer creates PR
2. Wait for security team review (2-3 days)
3. Back-and-forth on findings
4. Finally merge after 1 week
```

**After Argus:**
```
1. Developer creates PR
2. Argus reviews in 5 minutes
3. Clear findings with fix suggestions
4. Merge same day ✅
```

**Time saved:** 95%

---

### Use Case 2: Daily Security Scans

```yaml
# .github/workflows/nightly-scan.yml
on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM daily

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/argus-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          create_issue: true  # Auto-create GitHub issues
```

---

### Use Case 3: Pre-Commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash

echo "🔍 Running Argus security check..."

docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit --fail-on-critical

if [ $? -ne 0 ]; then
  echo "❌ Critical security issues found. Fix before committing."
  exit 1
fi

echo "✅ Security check passed!"
```

---

## 🎛️ Configuration Options

### Basic Configuration

Create `.argus.yml` in your repo root:

```yaml
# Minimal configuration
ai_provider: anthropic  # or: openai, foundation-sec

severity_threshold: medium  # block PRs on medium+ findings

enabled_scanners:
  - semgrep
  - gitleaks
  - trivy

excluded_paths:
  - tests/
  - vendor/
  - node_modules/
```

### Advanced Configuration

```yaml
# Advanced options
ai_provider: anthropic
model: claude-3-5-sonnet-20241022

# Cost controls
max_tokens: 10000
cost_limit: 5.00  # USD

# File selection
max_files: 50
file_patterns:
  - "*.py"
  - "*.js"
  - "*.go"

# Features
enable_threat_modeling: true
enable_sandbox_validation: false
enable_auto_fix: true

# Noise reduction
noise_threshold: 0.7  # suppress findings with 70%+ noise probability
use_historical_data: true

# Outputs
sarif_output: true
json_output: true
markdown_report: true
create_github_issues: true

# Policy enforcement
fail_on_severity: high
fail_on_blockers: true
block_on_secrets: true

# Notifications
slack_webhook: https://hooks.slack.com/services/YOUR/WEBHOOK
email_notifications:
  - security@company.com
```

---

## 🚨 Common Issues & Solutions

### Issue 1: "API key not found"

```bash
# Solution: Set environment variable
export ANTHROPIC_API_KEY=sk-ant-...

# Or pass directly
docker run -e ANTHROPIC_API_KEY=sk-ant-... ...
```

### Issue 2: "Permission denied"

```bash
# Solution: Fix volume mount permissions
docker run --rm \
  -v $(pwd):/workspace:rw \  # Add :rw
  -e ANTHROPIC_API_KEY=... \
  ghcr.io/devatsecure/argus-action:latest
```

### Issue 3: "Rate limit exceeded"

```yaml
# Solution: Add rate limiting in config
rate_limit:
  requests_per_minute: 10
  max_retries: 3
  backoff_factor: 2
```

### Issue 4: "Docker not found"

```bash
# Install Docker:
# macOS: brew install docker
# Linux: curl -fsSL https://get.docker.com | sh
# Windows: https://docs.docker.com/desktop/install/windows-install/
```

---

## 📊 Understanding Results

### Output Files

After running Argus:

```
.argus/
├── reviews/
│   ├── audit-report.md          # Human-readable report
│   ├── security-findings.json   # Machine-readable findings
│   └── security-findings.sarif  # SARIF format (GitHub compatible)
├── metrics/
│   ├── cost-report.json         # API costs
│   └── performance.json         # Timing metrics
└── artifacts/
    ├── sbom.json                # Software Bill of Materials
    └── threat-model.md          # Threat modeling results
```

### Reading the Report

```markdown
## 🔴 Critical Findings (2)

### 1. SQL Injection in user_controller.py
**Severity:** Critical | **Confidence:** High | **Noise Score:** 0.12

**Location:** `app/controllers/user_controller.py:45`

**Issue:**
User input directly concatenated into SQL query without sanitization.

**Exploit Scenario:**
Attacker can inject SQL to dump entire database.

**Recommendation:**
Use parameterized queries:
\```python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
\```

**Auto-fix available:** Yes
```

---

## 🎓 Learning Resources

### Tutorials
- [Video: Argus in 5 Minutes](https://youtube.com/placeholder)
- [Blog: Reducing False Positives by 60%](https://blog.placeholder.com)
- [Case Study: How Company X Uses Argus](https://example.com)

### Documentation
- [Full Documentation](./README.md)
- [Configuration Reference](./docs/configuration.md)
- [API Documentation](./docs/api.md)
- [Agent Profiles](./profiles/default/)

### Community
- [GitHub Discussions](https://github.com/devatsecure/argus-action/discussions)
- [Discord Server](https://discord.gg/placeholder)
- [Stack Overflow Tag](https://stackoverflow.com/questions/tagged/argus)

---

## 🚀 Next Steps

1. ✅ **Run your first scan** (you just did!)
2. 📖 **Read the [full README](./README.md)** for advanced features
3. ⚙️ **Configure** `.argus.yml` for your needs
4. 🔄 **Add to CI/CD** (GitHub Actions, GitLab, Jenkins)
5. 📊 **Set up dashboards** for tracking metrics
6. 👥 **Join the community** (Discord, GitHub Discussions)
7. 🎯 **Fine-tune** noise reduction with your data
8. 🔐 **Enable advanced features** (threat modeling, sandbox)

---

## 💡 Pro Tips

### Tip 1: Start Small
```bash
# First run: scan just one file
docker run --rm \
  -v $(pwd)/src/app.py:/workspace/app.py \
  -e ANTHROPIC_API_KEY=... \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace app.py
```

### Tip 2: Use Cost Limits
```yaml
cost_limit: 1.00  # Stop after $1
max_files: 20     # Scan only 20 files
```

### Tip 3: Cache Results
```bash
# Results cached in .argus/
# Re-run is instant if no code changed
```

### Tip 4: Integrate with Jira
```yaml
integrations:
  jira:
    url: https://your-company.atlassian.net
    project: SEC
    auto_create_tickets: true
```

### Tip 5: Use in Pre-commit
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: argus
        name: Argus Security Check
        entry: docker run --rm -v $(pwd):/workspace -e ANTHROPIC_API_KEY ghcr.io/devatsecure/argus-action:latest /workspace
        language: system
        pass_filenames: false
```

---

## 🆘 Need Help?

- 🐛 **Bug?** [Open an issue](https://github.com/devatsecure/argus-action/issues)
- 💬 **Question?** [GitHub Discussions](https://github.com/devatsecure/argus-action/discussions)
- 💼 **Enterprise?** [Contact us](mailto:devatsecure@users.noreply.github.com)
- 📖 **Documentation?** [Read the docs](./README.md)

---

**You're all set!** 🎉

Start securing your code with AI-powered analysis.
