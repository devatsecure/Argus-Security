# Platform Integration Quick Reference

**One-page cheat sheet for integrating Argus with GitHub, GitLab, and Bitbucket**

---

## ⚡ Quick Start (Copy & Paste)

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [pull_request, push]
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@v4.0.0
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: security
          fail-on-blockers: true
```

### GitLab CI/CD

```yaml
# .gitlab-ci.yml
argus:
  image: python:3.11
  script:
    - git clone https://github.com/devatsecure/Argus-Security
    - cd argus-action && pip install -r requirements.txt
    - python scripts/run_ai_audit.py --output-file ../results.json
  artifacts:
    reports:
      sast: results.sarif
```

### Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
image: python:3.11
pipelines:
  pull-requests:
    '**':
      - step:
          name: Security Scan
          script:
            - git clone https://github.com/devatsecure/Argus-Security
            - cd argus-action && pip install -r requirements.txt
            - python scripts/run_ai_audit.py --output-file ../results.json
          artifacts:
            - results.json
```

---

## 🎯 All Features Enabled

### GitHub Actions (Full)

```yaml
- uses: devatsecure/Argus-Security@v4.0.0
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    semgrep-enabled: true
    enable-trufflehog: true
    enable-gitleaks: true
    enable-trivy: true
    enable-checkov: true
    enable-api-security: true
    enable-supply-chain: true
    enable-threat-intel: true
    enable-remediation: true
    enable-regression-testing: true
    enable-exploit-analysis: true
    only-changed: true  # PR mode
```

### GitLab/Bitbucket (Full)

```bash
python scripts/run_ai_audit.py \
  --ai-provider anthropic \
  --semgrep-enabled true \
  --enable-trufflehog true \
  --enable-gitleaks true \
  --enable-trivy true \
  --enable-checkov true \
  --enable-api-security true \
  --enable-supply-chain true \
  --enable-threat-intel true \
  --enable-remediation true \
  --enable-regression-testing true \
  --enable-exploit-analysis true \
  --only-changed true \
  --output-file results.json
```

---

## 📝 Individual Feature Commands

### API Security Testing

```bash
# All platforms (after installing Argus)
./scripts/argus api-security --path . --output api-findings.json
```

### Supply Chain Security

```bash
# Check for typosquatting and malicious packages
./scripts/argus supply-chain diff --base main --head HEAD

# Full dependency scan
./scripts/argus supply-chain scan --path .
```

### DAST Scanning

```bash
# Requires running application
./scripts/argus dast --target http://localhost:8080 \
  --openapi openapi.yaml --output dast-results.json
```

### Threat Intelligence

```bash
# Enrich findings with CISA KEV, EPSS, NVD, GitHub, OSV
./scripts/argus threat-intel enrich \
  --findings findings.json --output enriched.json
```

### Auto-Remediation

```bash
# Generate AI-powered fixes
./scripts/argus remediate \
  --findings findings.json --output fixes.md
```

### Fuzzing

```bash
# API fuzzing
./scripts/argus fuzz api --spec openapi.yaml --duration 60

# Function fuzzing
./scripts/argus fuzz function --target src/parser.py \
  --function parse_xml --duration 30
```

### Regression Testing

```bash
# Run security regression tests
./scripts/argus regression-test run --path . --output results.json
```

### SAST-DAST Correlation

```bash
# Correlate static and dynamic findings
./scripts/argus correlate --sast sast.json --dast dast.json
```

---

## 🔐 Secret Configuration

### GitHub
```
Settings → Secrets and variables → Actions
Add: ANTHROPIC_API_KEY or OPENAI_API_KEY
```

### GitLab
```yaml
# Settings → CI/CD → Variables
variables:
  ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY  # Protected, Masked
```

### Bitbucket
```
Repository settings → Pipelines → Repository variables
Add: ANTHROPIC_API_KEY (Secured: ✓)
```

---

## 📊 Platform Comparison

| Feature | GitHub | GitLab | Bitbucket |
|---------|--------|--------|-----------|
| **Setup** | Native Action | Docker | Docker |
| **SARIF Upload** | ✅ Security tab | ✅ Dashboard | ⚠️ Artifacts |
| **PR Comments** | ✅ Auto | ✅ Auto | 🔧 API |
| **Caching** | ✅ | ✅ | ✅ |
| **Matrix Builds** | ✅ | ✅ | ✅ |
| **Scheduled** | ✅ Cron | ✅ Schedules | ✅ Schedules |

---

## 🚀 Common Patterns

### PR-Only Scanning

**GitHub:**
```yaml
on:
  pull_request:
    branches: [main]
```

**GitLab:**
```yaml
only:
  - merge_requests
```

**Bitbucket:**
```yaml
pipelines:
  pull-requests:
    '**':
```

### Upload SARIF

**GitHub:**
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: security-results.sarif
```

**GitLab:**
```yaml
artifacts:
  reports:
    sast: security-results.sarif
```

**Bitbucket:**
```yaml
artifacts:
  - security-results.sarif  # Manual download
```

### Post PR Comment

**GitHub (Native):**
```yaml
with:
  comment-on-pr: true
```

**GitLab (API):**
```bash
curl --request POST \
  --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  --data "{\"body\": \"$REPORT\"}" \
  "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/merge_requests/${CI_MERGE_REQUEST_IID}/notes"
```

**Bitbucket (API):**
```bash
curl -X POST \
  -u "$BITBUCKET_USERNAME:$BITBUCKET_APP_PASSWORD" \
  -d "{\"content\": {\"raw\": \"$REPORT\"}}" \
  "https://api.bitbucket.org/2.0/repositories/$REPO/pullrequests/$PR_ID/comments"
```

---

## 🎯 Performance Optimization

### For Large Repos

```yaml
# Scan only changed files
--only-changed true

# Limit file count
--max-files 500

# Limit file size
--max-file-size 100000

# Use faster model
--model claude-haiku-4
```

### Caching

**GitHub:**
```yaml
- uses: actions/cache@v4
  with:
    path: .argus-cache
    key: argus-${{ hashFiles('**/*.py') }}
```

**GitLab:**
```yaml
cache:
  key: argus-${CI_COMMIT_REF_SLUG}
  paths:
    - .argus-cache/
```

**Bitbucket:**
```yaml
definitions:
  caches:
    agent-cache: .argus-cache
```

---

## 🔧 Troubleshooting

### Issue: Out of Memory

**Solution:**
```yaml
# GitHub: Use larger runner
runs-on: ubuntu-latest-4-cores

# GitLab: Increase size
size: 2x

# Bitbucket: Increase memory
size: 2x
```

### Issue: Timeout

**Solution:**
```yaml
# Increase timeout
timeout-minutes: 30  # GitHub
timeout: 30m         # GitLab/Bitbucket

# Or reduce scope
--max-files 200
--only-changed true
```

### Issue: API Rate Limits

**Solution:**
```bash
# Use caching
--cache-enabled true

# Reduce AI calls
--ai-provider ollama  # Local LLM
```

---

## 📚 Full Documentation

- **Complete Guide:** [docs/PLATFORM_INTEGRATIONS.md](./PLATFORM_INTEGRATIONS.md)
- **GitHub Examples:** [.github/workflows/](./.github/workflows/)
- **Argus Docs:** [docs/](./docs/)

---

**Quick Links:**
- [GitHub Actions Marketplace](https://github.com/marketplace/actions/argus-security-action)
- [Argus Repository](https://github.com/devatsecure/Argus-Security)
- [Report Issues](https://github.com/devatsecure/Argus-Security/issues)

**Version:** 4.0.0 | **Updated:** 2026-01-15
