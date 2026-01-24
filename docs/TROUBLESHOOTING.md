# Argus Troubleshooting Guide

**Version:** 1.0.15
**Last Updated:** January 2026
**Status:** Production

This comprehensive guide covers error codes, common issues, and solutions for Argus Security Action.

---

## Table of Contents

- [Error Code Reference](#error-code-reference)
- [Common Issues by Category](#common-issues-by-category)
  - [Installation Issues](#installation-issues)
  - [Configuration Issues](#configuration-issues)
  - [API Key Issues](#api-key-issues)
  - [Scanner Issues](#scanner-issues)
  - [AI Triage Issues](#ai-triage-issues)
  - [Performance Issues](#performance-issues)
  - [Cost Issues](#cost-issues)
- [Platform-Specific Troubleshooting](#platform-specific-troubleshooting)
  - [GitHub Actions](#github-actions)
  - [GitLab CI/CD](#gitlab-cicd)
  - [Bitbucket Pipelines](#bitbucket-pipelines)
- [Scanner-Specific Issues](#scanner-specific-issues)
- [Debug Mode](#debug-mode)
- [Getting Help](#getting-help)

---

## Error Code Reference

### ERR-001: No AI API Key Provided

**Description:** Required AI provider API key is missing from environment variables

**Common Causes:**
1. `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` not set in repository secrets
2. Typo in secret name (case-sensitive)
3. Secret not accessible to workflow (org-level vs repo-level)

**Solutions:**
1. Add API key to repository secrets:
   ```yaml
   # In GitHub Actions
   env:
     ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
   ```

2. Verify secret name matches exactly (no typos):
   ```bash
   # Check your workflow file
   grep -r "ANTHROPIC_API_KEY" .github/workflows/
   ```

3. Use Ollama for local/free inference (no API key needed):
   ```yaml
   with:
     ai-provider: 'ollama'
     ollama-endpoint: 'http://localhost:11434'
   ```

**Prevention:**
- Test API keys locally before pushing to CI
- Use environment variable validation in workflows
- Document required secrets in README

**Example:**
```yaml
# Working GitHub Actions configuration
- uses: devatsecure/Argus-Security@v1
  with:
    ai-provider: 'anthropic'
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

---

### ERR-002: Invalid API Key Format

**Description:** API key exists but has incorrect format or is corrupted

**Common Causes:**
1. API key copied with extra whitespace or newlines
2. Partial API key (truncated during copy/paste)
3. Wrong API key for provider (Claude key used with OpenAI provider)

**Solutions:**
1. Regenerate API key from provider dashboard:
   - **Anthropic:** https://console.anthropic.com/settings/keys
   - **OpenAI:** https://platform.openai.com/api-keys

2. Verify key format:
   - Anthropic: Starts with `sk-ant-api03-`
   - OpenAI: Starts with `sk-proj-` or `sk-`

3. Check for whitespace:
   ```bash
   # Test locally
   export ANTHROPIC_API_KEY="your-key-here"
   echo "$ANTHROPIC_API_KEY" | wc -c  # Should match expected length
   ```

**Prevention:**
- Copy API keys directly from provider dashboard
- Use secure password managers
- Test authentication before saving secrets

**Example:**
```bash
# Valid Anthropic API key format
sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Valid OpenAI API key format
sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

### ERR-003: API Rate Limit Exceeded

**Description:** Too many API requests sent to AI provider in short time period

**Common Causes:**
1. Running multiple concurrent scans
2. Large repository with many findings (100+ findings = 100+ API calls)
3. Insufficient rate limit tier for usage

**Solutions:**
1. Add rate limiting to scans:
   ```yaml
   with:
     max-files: '50'  # Limit files analyzed
     cost-limit: '1.0'  # Set budget cap
   ```

2. Use caching to reduce redundant calls:
   ```yaml
   - uses: actions/cache@v4
     with:
       path: .argus-cache/
       key: argus-cache-${{ hashFiles('**/*.py', '**/*.js') }}
   ```

3. Upgrade API tier or add delays:
   ```python
   # For local usage
   --cost-limit 2.0  # Higher budget
   ```

4. Switch to Ollama for unlimited local inference

**Prevention:**
- Monitor API usage dashboards
- Set cost limits proactively
- Use `only-changed: 'true'` for PR scans
- Enable caching

**Example:**
```yaml
# Rate-limit friendly configuration
- uses: devatsecure/Argus-Security@v1
  with:
    only-changed: 'true'  # Only scan changed files in PRs
    max-files: '50'       # Cap file count
    cost-limit: '1.0'     # Budget protection
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

---

### ERR-004: Scanner Execution Failed

**Description:** A security scanner (Semgrep, Trivy, TruffleHog, Checkov) failed to execute

**Common Causes:**
1. Scanner binary not installed
2. Scanner version incompatibility
3. Target path does not exist
4. Permission denied on target files

**Solutions:**
1. Verify scanner installation:
   ```bash
   semgrep --version
   trivy --version
   trufflehog --version
   checkov --version
   ```

2. Install missing scanners:
   ```bash
   # Semgrep
   pip install semgrep

   # Trivy
   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

   # TruffleHog
   brew install trufflehog  # macOS
   # OR
   curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh

   # Checkov
   pip install checkov
   ```

3. Check target path:
   ```bash
   ls -la /path/to/target  # Verify path exists
   ```

**Prevention:**
- Use GitHub Actions with pre-installed tools
- Add installation steps to CI workflows
- Test locally before pushing

**Example:**
```yaml
# Ensure scanners are installed
- name: Install Security Tools
  run: |
    pip install semgrep checkov
    bash scripts/install_security_tools.sh
```

---

### ERR-005: File Parsing Error

**Description:** Scanner failed to parse a file (syntax error, unsupported format, corrupted file)

**Common Causes:**
1. Invalid syntax in source file
2. Binary file scanned as text
3. Encoding issues (non-UTF-8)
4. File too large (>10MB)

**Solutions:**
1. Exclude problematic files:
   ```yaml
   with:
     exclude-paths: 'vendor/**,node_modules/**,*.min.js'
   ```

2. Fix syntax errors in source files:
   ```bash
   # Validate Python syntax
   python -m py_compile file.py

   # Validate JavaScript
   node --check file.js
   ```

3. Set file size limits:
   ```yaml
   with:
     max-file-size: '50000'  # 50KB limit
   ```

**Prevention:**
- Run linters before security scans
- Exclude generated/minified code
- Use `.gitignore` patterns for exclusions

**Example:**
```yaml
# Exclude common problem patterns
with:
  exclude-paths: |
    vendor/**
    node_modules/**
    *.min.js
    *.min.css
    dist/**
    build/**
```

---

### ERR-006: Timeout Expired

**Description:** Scanner or operation exceeded maximum allowed time

**Common Causes:**
1. Very large repository (>10K files)
2. Network issues downloading dependencies
3. Deadlocked subprocess
4. Infinite loop in analysis

**Solutions:**
1. Increase timeout:
   ```yaml
   # GitHub Actions
   jobs:
     security:
       timeout-minutes: 30  # Default: 10
   ```

2. Scan fewer files:
   ```yaml
   with:
     only-changed: 'true'
     max-files: '50'
   ```

3. Split scan into multiple jobs:
   ```yaml
   strategy:
     matrix:
       path: ['src/', 'tests/', 'lib/']
   ```

**Prevention:**
- Use incremental scanning for PRs
- Set appropriate timeouts for repository size
- Monitor scan duration trends

**Example:**
```yaml
# Optimized for large repos
jobs:
  security:
    timeout-minutes: 45
    steps:
      - uses: devatsecure/Argus-Security@v1
        with:
          only-changed: 'true'
          max-files: '100'
          exclude-paths: 'vendor/**,node_modules/**'
```

**Scanner-Specific Timeouts:**
- **Semgrep:** 300 seconds (5 minutes)
- **Trivy:** 300-600 seconds (5-10 minutes)
- **TruffleHog:** 600 seconds (10 minutes)
- **Checkov:** 600 seconds (10 minutes)

---

### ERR-007: Memory Limit Exceeded (OOM)

**Description:** Process killed due to excessive memory usage

**Common Causes:**
1. Scanning very large files (>100MB)
2. Too many files analyzed concurrently
3. Memory leak in scanner
4. Insufficient runner memory

**Solutions:**
1. Exclude large files:
   ```yaml
   with:
     max-file-size: '50000'  # 50KB per file
   ```

2. Use larger runners:
   ```yaml
   # GitHub Actions
   runs-on: ubuntu-latest-8-cores  # More memory
   ```

3. Process files in batches:
   ```bash
   # CLI usage
   python scripts/run_ai_audit.py --max-files 50 /path/to/repo
   ```

4. Clear caches:
   ```bash
   rm -rf .argus-cache/
   ```

**Prevention:**
- Exclude binary files and assets
- Monitor memory usage trends
- Use incremental scanning

**Example:**
```yaml
# Memory-efficient configuration
runs-on: ubuntu-latest
steps:
  - uses: devatsecure/Argus-Security@v1
    with:
      max-files: '50'
      max-file-size: '50000'
      exclude-paths: '*.zip,*.tar.gz,*.pdf,*.jpg,*.png'
```

**Memory Usage Guidelines:**
- **Small repo (<1K files):** 2GB
- **Medium repo (1K-5K files):** 4GB
- **Large repo (>5K files):** 8GB+

---

### ERR-008: Cost Limit Exceeded

**Description:** AI API costs exceeded configured budget limit

**Common Causes:**
1. Too many findings triggered expensive AI analysis
2. Large files sent to LLM
3. No cost limit set (default: unlimited)

**Solutions:**
1. Set cost limits:
   ```yaml
   with:
     cost-limit: '1.0'  # $1.00 USD maximum
   ```

2. Reduce files analyzed:
   ```yaml
   with:
     max-files: '50'
     only-changed: 'true'
   ```

3. Use Ollama for free inference:
   ```yaml
   with:
     ai-provider: 'ollama'
   ```

4. Filter findings before AI triage:
   ```yaml
   with:
     severity-filter: 'critical,high'  # Skip low/medium
   ```

**Prevention:**
- Always set cost-limit in production
- Monitor spend in provider dashboards
- Use caching to reduce redundant calls

**Example:**
```yaml
# Cost-protected configuration
- uses: devatsecure/Argus-Security@v1
  with:
    cost-limit: '2.0'        # Max $2.00
    max-files: '100'         # Limit scope
    only-changed: 'true'     # PRs only
    severity-filter: 'critical,high'
```

**Estimated Costs:**
- **Small repo (<50 findings):** $0.10-0.30
- **Medium repo (50-200 findings):** $0.30-1.00
- **Large repo (>200 findings):** $1.00-5.00

---

### ERR-009: Model Not Found

**Description:** Requested AI model is not accessible or does not exist

**Common Causes:**
1. Model name typo (e.g., `claude-sonnet-4` instead of `claude-sonnet-4-5-20250929`)
2. Model not available in API tier
3. Model deprecated or renamed

**Solutions:**
1. Use default models:
   ```yaml
   with:
     ai-provider: 'anthropic'  # Uses latest Sonnet by default
   ```

2. Check available models:
   ```bash
   # Anthropic models
   curl https://api.anthropic.com/v1/models \
     -H "x-api-key: $ANTHROPIC_API_KEY"
   ```

3. Update to latest Argus version:
   ```bash
   # In GitHub Actions
   uses: devatsecure/Argus-Security@v1  # Latest stable
   ```

**Prevention:**
- Don't hardcode model names
- Use provider defaults
- Follow Argus release notes for model updates

**Example:**
```yaml
# Recommended: Use defaults
- uses: devatsecure/Argus-Security@v1
  with:
    ai-provider: 'anthropic'  # Auto-selects best model

# Advanced: Specify model
- uses: devatsecure/Argus-Security@v1
  with:
    ai-provider: 'anthropic'
    model: 'claude-sonnet-4-5-20250929'
```

---

### ERR-010: JSON Parse Failure

**Description:** Failed to parse JSON output from scanner or AI response

**Common Causes:**
1. Scanner output corrupted
2. AI response not valid JSON
3. Incomplete output (timeout mid-response)

**Solutions:**
1. Re-run scan:
   ```bash
   # Force fresh scan
   rm -rf .argus-cache/
   python scripts/run_ai_audit.py /path/to/repo
   ```

2. Enable debug logging:
   ```yaml
   with:
     debug: 'true'
   ```

3. Check scanner versions:
   ```bash
   semgrep --version  # Should be 1.100.0+
   ```

**Prevention:**
- Keep scanners updated
- Use stable Argus releases
- Enable debug mode for investigation

---

### ERR-011: Permission Denied

**Description:** Insufficient permissions to read files or execute scanners

**Common Causes:**
1. File permissions too restrictive (chmod 000)
2. SELinux/AppArmor blocking access
3. Running as wrong user
4. Repository submodules not accessible

**Solutions:**
1. Fix file permissions:
   ```bash
   chmod -R u+r /path/to/repo
   ```

2. Run with appropriate user:
   ```bash
   # In Docker
   docker run -u $(id -u):$(id -g) argus
   ```

3. Checkout submodules:
   ```yaml
   - uses: actions/checkout@v4
     with:
       submodules: recursive
   ```

**Prevention:**
- Set correct permissions in CI
- Test locally with same user
- Document permission requirements

---

### ERR-012: Network Connection Failed

**Description:** Unable to reach external services (AI APIs, download sources)

**Common Causes:**
1. Firewall blocking outbound connections
2. Proxy configuration incorrect
3. DNS resolution failure
4. API endpoint unreachable

**Solutions:**
1. Configure proxy:
   ```bash
   export HTTP_PROXY=http://proxy.example.com:8080
   export HTTPS_PROXY=http://proxy.example.com:8080
   ```

2. Check connectivity:
   ```bash
   curl -I https://api.anthropic.com
   ```

3. Use air-gapped mode with Ollama:
   ```yaml
   with:
     ai-provider: 'ollama'
     ollama-endpoint: 'http://internal-ollama:11434'
   ```

**Prevention:**
- Test network connectivity in CI
- Document proxy requirements
- Have offline fallback (Ollama)

---

### ERR-013: Configuration Validation Failed

**Description:** Invalid configuration parameters provided

**Common Causes:**
1. Invalid project-type value
2. Typo in parameter names
3. Conflicting options
4. Missing required parameters

**Solutions:**
1. Check valid project types:
   ```yaml
   # Valid values
   project-type: 'backend-api'
   project-type: 'frontend-spa'
   project-type: 'mobile-app'
   project-type: 'infrastructure'
   project-type: 'library'
   ```

2. Validate YAML syntax:
   ```bash
   yamllint .github/workflows/security.yml
   ```

3. Use example configurations:
   ```bash
   cp examples/workflows/basic-workflow.yml .github/workflows/
   ```

**Prevention:**
- Use schema validation
- Start with example configs
- Test locally first

---

### ERR-014: Git Repository Not Found

**Description:** Target path is not a valid git repository

**Common Causes:**
1. `.git` directory missing
2. Shallow clone without history
3. Not inside repository directory
4. Corrupted git repository

**Solutions:**
1. Initialize git repo:
   ```bash
   git init
   ```

2. Clone with full history:
   ```yaml
   - uses: actions/checkout@v4
     with:
       fetch-depth: 0  # Full history
   ```

3. Verify repository:
   ```bash
   git status
   git log --oneline -5
   ```

**Prevention:**
- Always use `fetch-depth: 0` for security scans
- Test git operations before scanning

---

### ERR-015: Dependency Resolution Failed

**Description:** Unable to resolve project dependencies for analysis

**Common Causes:**
1. Missing `package.json`, `requirements.txt`, `go.mod`
2. Private registry credentials not configured
3. Incompatible dependency versions
4. Network issues downloading packages

**Solutions:**
1. Install dependencies first:
   ```yaml
   # Python
   - run: pip install -r requirements.txt

   # Node.js
   - run: npm install

   # Go
   - run: go mod download
   ```

2. Configure private registries:
   ```yaml
   - run: |
       npm config set registry https://registry.company.com
       npm config set //registry.company.com/:_authToken=${{ secrets.NPM_TOKEN }}
   ```

3. Skip dependency scanning if needed:
   ```yaml
   with:
     trivy-enabled: 'false'  # Skip CVE scanning
   ```

**Prevention:**
- Document dependency setup
- Test dependency installation locally
- Use dependency caching

---

### ERR-020: Semgrep Not Installed

**Description:** Semgrep binary not found in PATH

**Solutions:**
```bash
# Install via pip
pip install semgrep

# Or via GitHub Actions
- uses: actions/setup-python@v6
  with:
    python-version: '3.11'
- run: pip install semgrep
```

**See:** [Scanner-Specific Issues - Semgrep](#semgrep)

---

### ERR-021: Trivy Not Installed

**Description:** Trivy binary not found in PATH

**Solutions:**
```bash
# Install script
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Or via Homebrew
brew install trivy
```

**See:** [Scanner-Specific Issues - Trivy](#trivy)

---

### ERR-022: TruffleHog Not Installed

**Description:** TruffleHog binary not found in PATH

**Solutions:**
```bash
# macOS
brew install trufflehog

# Linux
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Docker
docker pull trufflesecurity/trufflehog:latest
```

**See:** [Scanner-Specific Issues - TruffleHog](#trufflehog)

---

### ERR-023: Checkov Not Installed

**Description:** Checkov binary not found in PATH

**Solutions:**
```bash
# Install via pip
pip install checkov

# Verify installation
checkov --version
```

**See:** [Scanner-Specific Issues - Checkov](#checkov)

---

### ERR-030: Authentication Failed

**Description:** API authentication rejected by provider

**Causes:**
- Invalid API key
- Expired API key
- Wrong provider for key

**Solutions:**
1. Regenerate API key from provider dashboard
2. Verify key matches provider:
   - Anthropic keys start with `sk-ant-`
   - OpenAI keys start with `sk-proj-` or `sk-`
3. Test authentication:
   ```bash
   curl https://api.anthropic.com/v1/models \
     -H "x-api-key: $ANTHROPIC_API_KEY"
   ```

---

### ERR-040: No Findings Generated

**Description:** Scan completed but produced zero findings

**Common Causes:**
1. All files excluded by patterns
2. Scanners not finding issues (good!)
3. Scanner configuration too strict
4. Wrong target path

**Solutions:**
1. Verify target path:
   ```bash
   ls -la /path/to/target
   ```

2. Check exclude patterns:
   ```yaml
   with:
     exclude-paths: ''  # Scan everything
   ```

3. Lower severity threshold:
   ```yaml
   with:
     severity-filter: 'critical,high,medium,low'
   ```

**Note:** Zero findings might be correct! Verify manually.

---

## Common Issues by Category

### Installation Issues

#### Issue: "Command not found: semgrep"

**Cause:** Semgrep not installed or not in PATH

**Solution:**
```bash
pip install semgrep

# Verify
semgrep --version
```

**For CI:**
```yaml
- name: Install Semgrep
  run: pip install semgrep
```

---

#### Issue: "Python version incompatible"

**Cause:** Argus requires Python 3.9+

**Solution:**
```yaml
- uses: actions/setup-python@v6
  with:
    python-version: '3.11'  # Recommended
```

---

#### Issue: "ModuleNotFoundError: No module named 'anthropic'"

**Cause:** Python dependencies not installed

**Solution:**
```bash
pip install -r requirements.txt

# Or specific package
pip install anthropic>=0.40.0
```

---

### Configuration Issues

#### Issue: "Invalid project-type"

**Valid Values:**
- `backend-api`
- `frontend-spa`
- `mobile-app`
- `infrastructure`
- `library`
- `monorepo`

**Example:**
```yaml
with:
  project-type: 'backend-api'
```

---

#### Issue: "YAML syntax error"

**Cause:** Invalid YAML in workflow file

**Solution:**
```bash
# Validate YAML
yamllint .github/workflows/security.yml

# Or use online validator
# https://www.yamllint.com/
```

**Common YAML mistakes:**
```yaml
# ❌ Wrong: Incorrect indentation
with:
ai-provider: 'anthropic'

# ✅ Correct: Proper indentation
with:
  ai-provider: 'anthropic'
```

---

#### Issue: "Exclude patterns not working"

**Cause:** Incorrect glob pattern syntax

**Correct Patterns:**
```yaml
with:
  exclude-paths: |
    vendor/**
    node_modules/**
    *.min.js
    dist/**
```

**Note:** Use YAML multiline `|` for multiple patterns

---

### API Key Issues

#### Issue: "API key not set"

**Solution for GitHub Actions:**
```yaml
env:
  ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

**Solution for CLI:**
```bash
export ANTHROPIC_API_KEY="your-key"
python scripts/run_ai_audit.py /path
```

---

#### Issue: "Invalid API key format"

**Check key format:**
- **Anthropic:** `sk-ant-api03-...` (84 characters)
- **OpenAI:** `sk-proj-...` or `sk-...` (51+ characters)

**Solution:** Regenerate key from provider dashboard

---

### Scanner Issues

See [Scanner-Specific Issues](#scanner-specific-issues) for detailed troubleshooting.

---

### AI Triage Issues

#### Issue: "AI response not valid JSON"

**Cause:** Model output included markdown or extra text

**Solution:**
1. Try again (retry logic should handle this)
2. Update to latest Argus version
3. Report issue with debug logs

**Debug:**
```yaml
with:
  debug: 'true'
```

---

#### Issue: "Model takes too long to respond"

**Cause:** Large context sent to model

**Solution:**
```yaml
with:
  max-files: '50'       # Reduce context size
  max-file-size: '50000'  # Skip large files
```

---

### Performance Issues

#### Issue: "Scan takes >30 minutes"

**Causes:**
- Large repository (>10K files)
- No file filtering
- Network slowness

**Solutions:**
```yaml
with:
  only-changed: 'true'     # PRs: scan only changed files
  max-files: '100'         # Limit total files
  exclude-paths: 'vendor/**,node_modules/**,dist/**'
```

---

#### Issue: "Out of memory in GitHub Actions"

**Solutions:**
1. Use larger runner:
   ```yaml
   runs-on: ubuntu-latest-8-cores
   ```

2. Reduce file count:
   ```yaml
   with:
     max-files: '50'
     max-file-size: '50000'
   ```

3. Split into multiple jobs:
   ```yaml
   strategy:
     matrix:
       path: ['src/', 'lib/', 'tests/']
   ```

---

### Cost Issues

#### Issue: "AI costs too high"

**Solutions:**
1. Set budget limit:
   ```yaml
   with:
     cost-limit: '1.0'  # $1 max
   ```

2. Reduce scope:
   ```yaml
   with:
     only-changed: 'true'
     max-files: '50'
     severity-filter: 'critical,high'
   ```

3. Use Ollama (free):
   ```yaml
   with:
     ai-provider: 'ollama'
   ```

4. Enable caching:
   ```yaml
   - uses: actions/cache@v4
     with:
       path: .argus-cache/
       key: argus-${{ hashFiles('**/*.py') }}
   ```

**Cost Tracking:**
```bash
# View cost report in scan output
grep "Total Cost" .argus/reviews/report.md
```

---

## Platform-Specific Troubleshooting

### GitHub Actions

#### Issue: "Workflow fails on private repository"

**Cause:** GitHub token doesn't have sufficient permissions

**Solution:**
```yaml
permissions:
  contents: read
  security-events: write  # For SARIF upload
  pull-requests: write    # For PR comments
```

---

#### Issue: "SARIF upload fails"

**Causes:**
- No `security-events: write` permission
- SARIF file too large (>10MB)
- Invalid SARIF format

**Solutions:**
1. Check permissions (see above)
2. Reduce findings:
   ```yaml
   with:
     severity-filter: 'critical,high'
   ```
3. Validate SARIF:
   ```bash
   jq . .argus/reviews/report.sarif
   ```

---

#### Issue: "Artifacts not uploaded"

**Solution:**
```yaml
- uses: actions/upload-artifact@v4
  if: always()  # Upload even on failure
  with:
    name: security-report
    path: .argus/reviews/
```

---

### GitLab CI/CD

#### Issue: "Runner timeout"

**Solution:**
```yaml
security-scan:
  timeout: 45m  # Default: 1h
  script:
    - python scripts/run_ai_audit.py .
```

---

#### Issue: "Cache not working"

**Solution:**
```yaml
security-scan:
  cache:
    key: argus-${CI_COMMIT_REF_SLUG}
    paths:
      - .argus-cache/
  script:
    - python scripts/run_ai_audit.py .
```

---

### Bitbucket Pipelines

#### Issue: "Memory limit exceeded"

**Solution:**
```yaml
pipelines:
  default:
    - step:
        name: Security Scan
        size: 2x  # Double memory (4GB)
        script:
          - python scripts/run_ai_audit.py .
```

---

## Scanner-Specific Issues

### Semgrep

#### Issue: "Semgrep scan timeout"

**Default Timeout:** 300 seconds (5 minutes)

**Solutions:**
1. Exclude large files:
   ```yaml
   with:
     exclude-paths: '*.min.js,dist/**'
   ```

2. Use faster rules:
   ```bash
   semgrep --config=p/security-audit  # Instead of p/default
   ```

---

#### Issue: "Semgrep finds no issues"

**Causes:**
- Language not supported
- Custom rules needed
- Files excluded

**Solutions:**
1. Check supported languages:
   ```bash
   semgrep --show-supported-languages
   ```

2. Add custom rules:
   ```bash
   # Create .semgrep/rules.yml
   semgrep --config=.semgrep/rules.yml .
   ```

---

#### Issue: "Too many false positives from Semgrep"

**Solutions:**
1. Use AI triage (default enabled)
2. Add suppressions:
   ```yaml
   # .semgrep.yml
   rules:
     - id: python.lang.security.audit.exec-used
       paths:
         exclude:
           - tests/
   ```

---

### Trivy

#### Issue: "Trivy database download fails"

**Cause:** Network connectivity or disk space

**Solutions:**
1. Pre-download database:
   ```bash
   trivy image --download-db-only
   ```

2. Use cache:
   ```yaml
   - uses: actions/cache@v4
     with:
       path: ~/.cache/trivy
       key: trivy-db-${{ runner.os }}
   ```

3. Skip DB update:
   ```bash
   trivy filesystem --skip-db-update .
   ```

---

#### Issue: "Trivy reports CVEs with no fix"

**Expected Behavior:** Trivy reports all CVEs, including those without fixes

**Solutions:**
1. Filter by fixable only:
   ```bash
   trivy filesystem --ignore-unfixed .
   ```

2. Adjust policy to allow unfixable CVEs:
   ```rego
   # policy/rego/pr.rego
   allow if {
     finding.fixed_version == null
   }
   ```

---

#### Issue: "Trivy scans too slow"

**Solutions:**
1. Scan specific paths:
   ```bash
   trivy filesystem --scanners vuln requirements.txt
   ```

2. Reduce severity:
   ```bash
   trivy filesystem --severity CRITICAL,HIGH .
   ```

---

### TruffleHog

#### Issue: "TruffleHog finds too many false positives"

**Solutions:**
1. Use verified-only mode (default):
   ```yaml
   # Already enabled by default
   # TruffleHog only reports API-verified secrets
   ```

2. Exclude test files:
   ```bash
   trufflehog filesystem . --exclude-paths tests/
   ```

---

#### Issue: "TruffleHog scan very slow"

**Default Timeout:** 600 seconds (10 minutes)

**Solutions:**
1. Limit scan depth (git mode):
   ```bash
   trufflehog git file://. --max-depth 100
   ```

2. Use filesystem mode instead of git mode:
   ```bash
   trufflehog filesystem .  # Faster than git mode
   ```

---

#### Issue: "TruffleHog exit code 183"

**Note:** Exit code 183 means secrets were found (this is normal!)

**Solutions:**
1. Review findings in report
2. Revoke exposed secrets
3. Add to allowlist if false positive

---

### Checkov

#### Issue: "Checkov finds too many IaC issues"

**Solutions:**
1. Filter by severity:
   ```bash
   checkov -d . --check-severity CRITICAL,HIGH
   ```

2. Skip specific checks:
   ```bash
   checkov -d . --skip-check CKV_AWS_19,CKV_AWS_20
   ```

3. Use suppressions:
   ```hcl
   # In Terraform file
   resource "aws_s3_bucket" "example" {
     #checkov:skip=CKV_AWS_18:Logging not required for dev
     bucket = "my-bucket"
   }
   ```

---

#### Issue: "Checkov fails on Terraform 1.5+"

**Cause:** Checkov version incompatibility

**Solution:**
```bash
pip install --upgrade checkov
checkov --version  # Should be 3.0+
```

---

## Debug Mode

### Enabling Debug Logging

#### GitHub Actions:
```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    debug: 'true'
  env:
    ACTIONS_STEP_DEBUG: 'true'
```

#### CLI:
```bash
python scripts/run_ai_audit.py --debug /path/to/repo
```

---

### Reading Debug Logs

**Key sections to check:**
1. **Scanner execution:** Look for exit codes and stderr
2. **AI API calls:** Check request/response payloads
3. **File filtering:** Verify which files were included/excluded
4. **Cost tracking:** Monitor per-operation costs

**Example debug output:**
```
DEBUG - Running: ['semgrep', '--config', 'p/security-audit', '--json', ...]
DEBUG - Semgrep exit code: 0
DEBUG - Semgrep found 47 findings
DEBUG - Calling Claude API (model: claude-sonnet-4-5-20250929)
DEBUG - AI response received (tokens: 1234, cost: $0.0045)
DEBUG - Total cost so far: $0.15 (limit: $1.00)
```

---

### Collecting Debug Information

For bug reports, include:

```bash
# System info
uname -a
python --version

# Scanner versions
semgrep --version
trivy --version
trufflehog --version
checkov --version

# Argus version
grep "version:" action.yml

# Configuration (sanitized)
cat .github/workflows/security.yml

# Debug logs
# (Redact any secrets or sensitive data)
```

---

### Common Debug Scenarios

#### Debugging Cost Issues:
```yaml
with:
  debug: 'true'
  cost-limit: '0.10'  # Low limit to trigger quickly
```

**Look for:**
- Which operations are most expensive
- How many API calls were made
- Token counts per call

---

#### Debugging False Positives:
```yaml
with:
  debug: 'true'
  severity-filter: 'critical'  # Focus on one finding
```

**Look for:**
- Why AI marked finding as true positive
- Noise score calculation
- Context sent to AI

---

#### Debugging Timeouts:
```bash
# Add timeout logging
python scripts/run_ai_audit.py --debug . 2>&1 | tee debug.log

# Check where timeout occurred
grep -A5 "Timeout" debug.log
```

---

## Getting Help

### Before Opening an Issue

1. **Search existing issues:** https://github.com/devatsecure/Argus-Security/issues
2. **Check FAQ:** [docs/FAQ.md](/docs/FAQ.md)
3. **Read documentation:** [PLATFORM.md](/PLATFORM.md)
4. **Try debug mode:** See [Debug Mode](#debug-mode)

---

### Opening a Bug Report

**Include:**
1. Argus version
2. Platform (GitHub Actions, GitLab CI, CLI)
3. Scanner versions
4. Minimal reproduction steps
5. Full error message
6. Debug logs (redact secrets)
7. Configuration file (sanitized)

**Template:**
```markdown
**Argus Version:** v1.0.15
**Platform:** GitHub Actions
**Error Code:** ERR-006

**Description:**
Scan times out after 15 minutes on medium-sized repo (2K files)

**Steps to Reproduce:**
1. Clone repo: https://github.com/example/repo
2. Run: python scripts/run_ai_audit.py .
3. Wait ~15 minutes
4. Timeout error appears

**Configuration:**
```yaml
# .github/workflows/security.yml (sanitized)
...
```

**Error Message:**
```
TimeoutExpired: Command 'semgrep' timed out after 300 seconds
```

**Debug Logs:**
```
# Attach debug.log (redact secrets)
```
```

---

### Community Support

- **GitHub Discussions:** https://github.com/devatsecure/Argus-Security/discussions
- **Discord:** (coming soon)
- **Stack Overflow:** Tag `argus`

---

### Enterprise Support

For SLA-backed support:
- **Email:** enterprise@argus.io
- **Includes:**
  - 24/7 support
  - Priority bug fixes
  - Custom integrations
  - Dedicated Slack channel

---

## Quick Reference

### Most Common Issues

| Issue | Error Code | Quick Fix |
|-------|------------|-----------|
| No API key | ERR-001 | Add to secrets: `ANTHROPIC_API_KEY` |
| Scanner not found | ERR-004, ERR-020-023 | `pip install semgrep trivy checkov` |
| Timeout | ERR-006 | Add `only-changed: 'true'`, increase timeout |
| Cost too high | ERR-008 | Set `cost-limit: '1.0'` |
| OOM | ERR-007 | Set `max-files: '50'`, exclude large files |
| Rate limit | ERR-003 | Enable caching, reduce max-files |
| Parse error | ERR-005, ERR-010 | Exclude problematic files, update scanners |

---

### Health Check Commands

```bash
# Verify installation
which semgrep trivy trufflehog checkov
python --version

# Test API keys
curl https://api.anthropic.com/v1/models \
  -H "x-api-key: $ANTHROPIC_API_KEY"

# Validate configuration
yamllint .github/workflows/security.yml

# Clear caches
rm -rf .argus-cache/

# Test scan (dry run)
python scripts/run_ai_audit.py --debug --max-files 5 .
```

---

### Performance Tuning

**For speed:**
```yaml
with:
  only-changed: 'true'
  max-files: '50'
  exclude-paths: 'vendor/**,node_modules/**'
  severity-filter: 'critical,high'
```

**For thoroughness:**
```yaml
with:
  only-changed: 'false'
  max-files: '1000'
  severity-filter: 'critical,high,medium,low'
  enable-sandbox: 'true'
```

**For cost efficiency:**
```yaml
with:
  cost-limit: '0.50'
  max-files: '50'
  ai-provider: 'ollama'  # Free
```

---

## Appendix: Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success, no issues found |
| 1 | Success, findings reported |
| 2 | Configuration error |
| 3 | Scanner installation error |
| 4 | API authentication error |
| 5 | Cost limit exceeded |
| 6 | Timeout |
| 7 | Out of memory |
| 183 | TruffleHog found secrets (normal) |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-16 | Initial comprehensive troubleshooting guide |

---

**Need more help?** See [FAQ.md](/docs/FAQ.md) or open an issue.
