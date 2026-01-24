# Argus Requirements & Prerequisites

Complete checklist of everything needed to run Argus on GitHub, GitLab, and Bitbucket.

**Last Updated:** 2026-01-16
**Version:** 4.0.0

---

## ✅ Quick Checklist

**Minimum Requirements (Free):**
- [ ] Python 3.9+ environment
- [ ] Git repository
- [ ] At least ONE AI provider API key (Anthropic/OpenAI) OR Ollama locally
- [ ] Internet connection (for cloud AI providers)

**Optional (Enables All Features):**
- [ ] Nuclei (for DAST scanning)
- [ ] Falco (for runtime security)
- [ ] Docker (for sandbox validation)

---

## 🎯 Core Requirements

### 1. **Platform Requirements**

| Platform | Requirement | Notes |
|----------|-------------|-------|
| **GitHub Actions** | GitHub.com account | Free for public repos, minutes quota for private |
| **GitLab CI/CD** | GitLab.com or self-hosted | Free tier: 400 compute minutes/month |
| **Bitbucket Pipelines** | Bitbucket Cloud account | Free tier: 50 build minutes/month |

**All platforms provide:**
- ✅ Python 3.9+ runners (free)
- ✅ Git access (built-in)
- ✅ Secret storage (encrypted)
- ✅ Artifact storage (included)

---

### 2. **Runtime Requirements**

#### Python Environment
```bash
# Required: Python 3.9 or higher
python --version
# Output: Python 3.9.0 or higher

# All platforms provide this by default:
# - GitHub Actions: python:3.11 available
# - GitLab CI/CD: python:3.11 image
# - Bitbucket: python:3.11 image
```

#### Python Dependencies (Automatic)
```bash
# These are installed automatically from requirements.txt
pip install -r requirements.txt

# Core dependencies (~40 packages):
anthropic>=0.40.0          # Claude AI
openai>=1.56.0             # OpenAI GPT
semgrep>=1.100.0           # SAST scanning
pytm>=1.3.0                # Threat modeling
tenacity>=9.0.0            # Retry logic
pyyaml>=6.0.2              # Config parsing
rich>=13.0.0               # Progress bars
requests>=2.31.0           # HTTP client
```

**Installation Time:** ~2-3 minutes on first run
**Caching:** Subsequent runs take ~10 seconds

---

### 3. **AI Provider Requirements**

#### Required: Choose ONE of the following

**Option A: Anthropic Claude (Recommended) ✅**
```bash
# What you need:
- Anthropic API key (get at: https://console.anthropic.com/)
- Cost: ~$0.35 per scan (pay-as-you-go)
- Models: claude-sonnet-4, claude-opus-4, claude-haiku-4

# Get your API key:
1. Visit: https://console.anthropic.com/
2. Sign up / Log in
3. Go to: API Keys
4. Create key
5. Copy: sk-ant-api03-xxx...

# Add to platform secrets:
ANTHROPIC_API_KEY=sk-ant-api03-xxx...
```

**Option B: OpenAI GPT**
```bash
# What you need:
- OpenAI API key (get at: https://platform.openai.com/)
- Cost: ~$0.50 per scan (pay-as-you-go)
- Models: gpt-4-turbo, gpt-4, gpt-3.5-turbo

# Get your API key:
1. Visit: https://platform.openai.com/api-keys
2. Sign up / Log in
3. Create API key
4. Copy: sk-xxx...

# Add to platform secrets:
OPENAI_API_KEY=sk-xxx...
```

**Option C: Ollama (Free, Local)**
```bash
# What you need:
- Self-hosted runner (GitHub/GitLab/Bitbucket)
- Ollama installed locally
- Model downloaded (llama3, mistral, etc.)

# Setup:
1. Install Ollama: https://ollama.ai/download
2. Download model: ollama pull llama3
3. Start server: ollama serve
4. Set endpoint: OLLAMA_ENDPOINT=http://localhost:11434

# Cost: FREE (runs on your hardware)
# Note: Requires self-hosted runner
```

**Which Should You Choose?**
- **Small teams, public repos:** Anthropic Claude (best quality/cost)
- **Enterprise, high volume:** OpenAI GPT-4
- **Cost-sensitive, self-hosted:** Ollama (free but slower)

---

### 4. **Scanner Requirements**

#### Built-in Scanners (Included, No Setup)

These work out-of-the-box on all platforms:

| Scanner | Purpose | Included | Setup Required |
|---------|---------|----------|----------------|
| **Semgrep** | SAST (2000+ rules) | ✅ pip install | ❌ None |
| **TruffleHog** | Secret detection | ✅ pip install | ❌ None |
| **Gitleaks** | Secret scanning | ✅ Binary in repo | ❌ None |
| **Trivy** | CVE/dependency | ✅ Auto-download | ❌ None |
| **Checkov** | IaC security | ✅ pip install | ❌ None |

**Total Setup Time:** 0 minutes (automatic)

#### Optional Scanners (Enable Advanced Features)

**Nuclei (for DAST scanning)** - Optional
```bash
# Install on runner (one-time):
# GitHub Actions:
- name: Install Nuclei
  run: |
    wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip
    unzip nuclei_3.1.0_linux_amd64.zip
    sudo mv nuclei /usr/local/bin/

# GitLab/Bitbucket:
before_script:
  - wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip
  - unzip nuclei_3.1.0_linux_amd64.zip
  - mv nuclei /usr/local/bin/

# Required for:
- enable-dast: true
- ./scripts/argus dast

# If NOT installed:
- DAST features will be skipped (no error)
- Other features work normally
```

**Falco (for runtime security)** - Optional
```bash
# Install on runner (advanced):
# Only needed for production runtime monitoring
curl -s https://falco.org/repo/falcosecurity-packages.asc | sudo apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update
sudo apt-get install -y falco

# Required for:
- enable-runtime-security: true
- ./scripts/argus runtime-security

# If NOT installed:
- Runtime security features will be skipped
- Other features work normally
```

**Docker (for sandbox validation)** - Optional
```bash
# Usually pre-installed on CI/CD runners:
# GitHub Actions: ✅ Pre-installed
# GitLab CI/CD: ✅ Use docker:dind service
# Bitbucket: ✅ Pre-installed

# Required for:
- Exploit validation in sandbox
- Container scanning

# If NOT installed:
- Sandbox validation will be skipped
- Other features work normally
```

---

## 📦 Platform-Specific Setup

### GitHub Actions

**Required:**
```yaml
# 1. Repository with .github/workflows/security.yml
# 2. Permissions in workflow:
permissions:
  contents: read           # Read code
  security-events: write   # Upload SARIF
  pull-requests: write     # Comment on PRs

# 3. Secrets configured:
# Settings → Secrets → Actions → New secret
ANTHROPIC_API_KEY or OPENAI_API_KEY
```

**Optional (for better experience):**
```yaml
# Enable GitHub Advanced Security (free for public repos)
# Settings → Security → Code security and analysis
# - Enable: Dependency graph
# - Enable: Dependabot alerts
# - Enable: Code scanning (SARIF integration)
```

**Quotas (Free Tier):**
- Public repos: ✅ Unlimited minutes
- Private repos: 2,000 minutes/month (more than enough)
- Storage: 500 MB artifacts

---

### GitLab CI/CD

**Required:**
```yaml
# 1. Repository with .gitlab-ci.yml
# 2. CI/CD Variables:
# Settings → CI/CD → Variables → Add variable
ANTHROPIC_API_KEY or OPENAI_API_KEY (Masked: ✓)

# 3. Permissions:
# Maintainer role (to push SARIF to Security Dashboard)
```

**Optional (for better experience):**
```yaml
# Enable Security Dashboard (free in GitLab Free tier)
# Settings → Security & Compliance
# - Ultimate: Full dashboard
# - Free: Basic SAST/dependency scanning
```

**Quotas (Free Tier):**
- CI/CD minutes: 400/month
- Storage: 5 GB
- Shared runners: ✅ Available

---

### Bitbucket Pipelines

**Required:**
```yaml
# 1. Repository with bitbucket-pipelines.yml
# 2. Pipelines enabled:
# Settings → Pipelines → Settings → Enable Pipelines

# 3. Repository variables:
# Settings → Pipelines → Repository variables
ANTHROPIC_API_KEY or OPENAI_API_KEY (Secured: ✓)
```

**Optional (for better experience):**
```yaml
# API credentials for PR comments:
# Settings → App passwords → Create app password
BITBUCKET_USERNAME=your-username
BITBUCKET_APP_PASSWORD=your-app-password
```

**Quotas (Free Tier):**
- Build minutes: 50/month (increase with paid plan)
- Storage: 1 GB
- Shared runners: ✅ Available

---

## 🔧 Verification Steps

### Test Your Setup

**Step 1: Test Python Environment**
```bash
# All platforms (in pipeline)
- run: python --version
- run: pip --version

# Expected output:
Python 3.9+ ✅
pip 20.0+ ✅
```

**Step 2: Test Argus Installation**
```bash
- run: git clone https://github.com/devatsecure/Argus-Security
- run: cd argus-action && pip install -r requirements.txt
- run: python scripts/run_ai_audit.py --help

# Expected: Help text showing all options ✅
```

**Step 3: Test AI Provider**
```bash
# Test Anthropic
- run: |
    python -c "
    import anthropic
    client = anthropic.Anthropic(api_key='$ANTHROPIC_API_KEY')
    print('✅ Anthropic configured')
    "

# Test OpenAI
- run: |
    python -c "
    import openai
    client = openai.OpenAI(api_key='$OPENAI_API_KEY')
    print('✅ OpenAI configured')
    "
```

**Step 4: Run Quick Scan**
```bash
# Minimal scan to verify everything works
- run: |
    cd argus-action
    python scripts/run_ai_audit.py \
      --project-path . \
      --max-files 10 \
      --output-file test-results.json

# Expected: JSON file with findings ✅
```

---

## 💰 Cost Breakdown

### Free Tier (All Platforms)

**What's Free:**
- ✅ All scanners (Semgrep, TruffleHog, Gitleaks, Trivy, Checkov)
- ✅ CI/CD compute (within quotas)
- ✅ GitHub public repos: Unlimited
- ✅ GitLab Free: 400 minutes/month
- ✅ Bitbucket Free: 50 minutes/month

**What Costs Money:**
- 💰 AI API calls:
  - Anthropic Claude: ~$0.35 per full scan
  - OpenAI GPT-4: ~$0.50 per full scan
  - Ollama: FREE (self-hosted)
- 💰 Private repo CI minutes (above free tier)
- 💰 Additional storage (rarely needed)

**Typical Monthly Cost (Small Team):**
```
Scenario: 20 PRs/month + 4 weekly scans
- PRs (20 scans): 20 × $0.35 = $7.00
- Weekly (4 scans): 4 × $0.35 = $1.40
Total: ~$8.40/month

Compare to commercial tools:
- Snyk: $98/month
- Checkmarx: $5,000+/year
- Veracode: $10,000+/year

Argus: 90%+ cost savings ✅
```

---

## 🚨 Troubleshooting Common Issues

### Issue 1: "No module named 'anthropic'"
```bash
# Solution: Install dependencies
pip install -r requirements.txt

# GitHub Actions: Add this step
- name: Install dependencies
  run: |
    cd argus-action
    pip install -r requirements.txt
```

### Issue 2: "API key not found"
```bash
# Solution: Check secret configuration
# GitHub: Settings → Secrets → Actions
# GitLab: Settings → CI/CD → Variables
# Bitbucket: Settings → Pipelines → Repository variables

# Verify in pipeline:
- run: echo "API key length: ${#ANTHROPIC_API_KEY}"
# Expected: Non-zero length
```

### Issue 3: "Command not found: nuclei"
```bash
# Solution: DAST is optional
# Either:
1. Install Nuclei (see above)
2. Disable DAST: enable-dast: false

# DAST is NOT required for other features
```

### Issue 4: "Permission denied: SARIF upload"
```bash
# GitHub: Add permissions to workflow
permissions:
  security-events: write

# GitLab: User must have Maintainer role
```

### Issue 5: "Out of memory"
```bash
# Solution: Use larger runner
# GitHub:
runs-on: ubuntu-latest-4-cores

# GitLab/Bitbucket:
size: 2x

# Or reduce scope:
--max-files 200
--only-changed true
```

---

## ✅ Final Checklist Before Running

**Pre-flight Check:**
- [ ] Python 3.9+ available on platform
- [ ] Repository has workflow/pipeline file
- [ ] AI provider API key configured as secret
- [ ] Permissions set (security-events: write for GitHub)
- [ ] Requirements.txt accessible
- [ ] Internet connection available (for cloud AI)

**Optional Enhancements:**
- [ ] Nuclei installed (for DAST)
- [ ] Falco installed (for runtime security)
- [ ] Docker available (for sandbox)
- [ ] Caching configured (for faster runs)

---

## 🎯 Minimum Working Example

**The absolute minimum to get started:**

### GitHub Actions
```yaml
# .github/workflows/security.yml
name: Security
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@v4.0.0
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

**That's it! Just:**
1. Create this file
2. Add ANTHROPIC_API_KEY secret
3. Create a PR
4. Watch it scan ✅

### GitLab CI/CD
```yaml
# .gitlab-ci.yml
test:
  image: python:3.11
  script:
    - git clone https://github.com/devatsecure/Argus-Security
    - cd argus-action && pip install -r requirements.txt
    - python scripts/run_ai_audit.py --output-file ../results.json
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
```

### Bitbucket Pipelines
```yaml
# bitbucket-pipelines.yml
image: python:3.11
pipelines:
  pull-requests:
    '**':
      - step:
          script:
            - git clone https://github.com/devatsecure/Argus-Security
            - cd argus-action && pip install -r requirements.txt
            - python scripts/run_ai_audit.py --output-file ../results.json
```

---

## 📚 Additional Resources

- [Platform Integration Guide](./PLATFORM_INTEGRATIONS.md) - Complete setup
- [Quick Reference](./PLATFORM_QUICK_REFERENCE.md) - Cheat sheet
- [Argus Documentation](./index.md) - Full docs
- [Troubleshooting Guide](../README.md#troubleshooting) - Common issues

---

## ❓ FAQ

**Q: Do I need ALL the scanners installed?**
A: No! Built-in scanners (Semgrep, TruffleHog, Gitleaks, Trivy, Checkov) install automatically. Optional scanners (Nuclei, Falco) enable specific features but aren't required.

**Q: Can I run without AI?**
A: No, AI is core to Argus. But you can use free Ollama locally instead of paid APIs.

**Q: How much does it cost?**
A: ~$0.35 per scan with Claude, or FREE with Ollama (self-hosted).

**Q: Do I need a self-hosted runner?**
A: No! Works on free shared runners (GitHub/GitLab/Bitbucket).

**Q: What if I hit quota limits?**
A: Use caching, `--only-changed`, and `--max-files` to reduce compute time.

**Q: Can I use in private repos?**
A: Yes! Works in private repos (uses your CI/CD minutes quota).

---

**Ready to get started?** Check the [Quick Reference](./PLATFORM_QUICK_REFERENCE.md) for copy-paste examples!

**Version:** 4.0.0 | **Updated:** 2026-01-16
