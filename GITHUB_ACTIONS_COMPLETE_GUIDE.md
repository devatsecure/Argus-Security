# 🚀 Running Complete 6-Phase Argus Security on GitHub Actions

## ✅ YES! All 6 Phases Run on GitHub Actions

Argus Security is specifically designed to run the complete 6-phase pipeline on GitHub Actions with zero infrastructure setup required.

---

## 📊 Complete 6-Phase Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ PHASE 1: Fast Deterministic Scanning (30-60 sec)                │
│   ├─ Semgrep (SAST - 2,000+ rules)                              │
│   ├─ Trivy (CVE/Dependencies)                                   │
│   ├─ Checkov (IaC security)                                     │
│   ├─ TruffleHog (Verified secrets)                              │
│   └─ Gitleaks (Pattern-based secrets)                           │
├─────────────────────────────────────────────────────────────────┤
│ PHASE 2: AI Enrichment (2-5 min)                                │
│   ├─ Claude/OpenAI/Ollama analysis                              │
│   ├─ Noise scoring & false positive prediction                  │
│   ├─ CWE mapping & risk scoring                                 │
│   └─ Threat Model Generation (pytm + AI)                        │
├─────────────────────────────────────────────────────────────────┤
│ PHASE 2.5: Automated Remediation                                │
│   └─ AI-Generated Fix Suggestions                               │
│       - SQL Injection → Parameterized queries                   │
│       - XSS → Output escaping, CSP                              │
│       - Command Injection → Input sanitization                  │
│       - Path Traversal, SSRF, XXE, CSRF, etc.                   │
├─────────────────────────────────────────────────────────────────┤
│ PHASE 2.6: Spontaneous Discovery                                │
│   └─ Find issues BEYOND scanner rules                           │
│       - Architecture risk analysis (missing auth, weak crypto)  │
│       - Hidden vulnerability detection (race conditions, logic) │
│       - Configuration security checks                           │
│       - Data security analysis (PII exposure)                   │
│       - Result: +15-20% more real findings                      │
├─────────────────────────────────────────────────────────────────┤
│ PHASE 3: Multi-Agent Persona Review                             │
│   ├─ SecretHunter      - API keys, credentials expert           │
│   ├─ ArchitectureReviewer - Design flaws, security gaps         │
│   ├─ ExploitAssessor   - Real-world exploitability analysis     │
│   ├─ FalsePositiveFilter - Noise suppression, test code ID      │
│   └─ ThreatModeler     - Attack chains, threat scenarios        │
├─────────────────────────────────────────────────────────────────┤
│ PHASE 4: Sandbox Validation                                     │
│   └─ Docker-based Exploit Validation                            │
│       - Isolated container execution                            │
│       - Multi-language support (Python, JS, Java, Go)           │
│       - 14 exploit types supported                              │
│       - Results: EXPLOITABLE, NOT_EXPLOITABLE, PARTIAL          │
├─────────────────────────────────────────────────────────────────┤
│ PHASE 5: Policy Gates                                           │
│   └─ Rego/OPA policy evaluation → PASS/FAIL                     │
├─────────────────────────────────────────────────────────────────┤
│ PHASE 6: Reporting                                              │
│   ├─ SARIF (GitHub code scanning)                               │
│   ├─ JSON (programmatic access)                                 │
│   └─ Markdown (PR comments)                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Quick Start Examples

### Example 1: Simple Security Scan (Fastest)

```yaml
name: Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Argus Security
        uses: devatsecure/Argus-Security@v4.2.0
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          enable-multi-agent: 'true'
          enable-spontaneous-discovery: 'true'
          enable-remediation: 'true'
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .argus/reviews/results.sarif
```

**Duration:** 2-3 minutes  
**Cost:** ~$0.30-0.60 per scan

---

### Example 2: Complete 6-Phase Pipeline (Most Comprehensive)

See the complete workflow file: [`COMPLETE-6-PHASE-WORKFLOW.yml`](./COMPLETE-6-PHASE-WORKFLOW.yml)

**Features:**
- ✅ All 6 phases enabled
- ✅ 5 specialized AI agents
- ✅ Docker-based sandbox validation
- ✅ Automated GitHub issue creation
- ✅ Slack/Discord notifications
- ✅ Cost guardrails
- ✅ PR comments
- ✅ SARIF upload to Code Scanning

**Duration:** 3-5 minutes  
**Cost:** ~$0.80-1.50 per scan

---

### Example 3: Docker-Based Scan (Alternative Approach)

```yaml
name: Security Scan (Docker)
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Argus with Docker
        run: |
          docker run --rm \
            -v $(pwd):/workspace:ro \
            -v $(pwd)/output:/output \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -e ANTHROPIC_API_KEY=${{ secrets.ANTHROPIC_API_KEY }} \
            -e ENABLE_MULTI_AGENT=true \
            -e ENABLE_SPONTANEOUS_DISCOVERY=true \
            -e ENABLE_REMEDIATION=true \
            -e SEMGREP_ENABLED=true \
            -e TRIVY_ENABLED=true \
            -e CHECKOV_ENABLED=true \
            ghcr.io/devatsecure/argus-security:latest \
            /workspace \
            --enable-ai-enrichment \
            --ai-provider anthropic \
            --output-dir /output
```

**Duration:** 2-4 minutes  
**Cost:** ~$0.40-0.80 per scan

---

## 🔑 Required Setup

### 1. Add API Key Secret

Go to your repository settings:

1. **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `ANTHROPIC_API_KEY`
4. Value: Your Anthropic API key from https://console.anthropic.com/

**Alternative providers:**
- `OPENAI_API_KEY` - For GPT-4
- `OLLAMA_ENDPOINT` - For local/self-hosted LLMs

### 2. Set Permissions

Add to your workflow:

```yaml
permissions:
  contents: read          # Read repository
  pull-requests: write    # Comment on PRs
  security-events: write  # Upload SARIF
  issues: write          # Create security issues
```

### 3. Create Workflow File

Copy one of the examples to: `.github/workflows/security.yml`

---

## 📊 Phase-by-Phase Breakdown

### Phase 1: Static Analysis ✅
**What runs:**
- Semgrep SAST (2,000+ security rules)
- Trivy CVE scanner (vulnerability database)
- Checkov IaC security (Terraform, K8s, Docker)
- TruffleHog (verified secrets with API validation)
- Gitleaks (pattern-based secret detection)

**Duration:** 15-30 seconds  
**Cost:** FREE (no AI calls)  
**GitHub Actions Compatible:** ✅ Yes

---

### Phase 2: AI Enrichment ✅
**What runs:**
- Claude Sonnet 4.5 / GPT-4 / Ollama analysis
- False positive prediction
- CWE mapping and risk scoring
- Threat model generation (pytm + AI)

**Duration:** 20-60 seconds  
**Cost:** ~$0.15-0.40 (depending on findings)  
**GitHub Actions Compatible:** ✅ Yes

---

### Phase 2.5: Automated Remediation ✅
**What runs:**
- AI-generated code fixes
- Unified diff patches
- Step-by-step remediation guides

**Duration:** 5-15 seconds  
**Cost:** ~$0.05-0.15  
**GitHub Actions Compatible:** ✅ Yes

**Example output:**
```diff
- sql = "SELECT * FROM users WHERE id = " + user_id
+ sql = "SELECT * FROM users WHERE id = ?"
+ cursor.execute(sql, (user_id,))
```

---

### Phase 2.6: Spontaneous Discovery ✅
**What runs:**
- Architecture risk analysis
- Hidden vulnerability detection
- Configuration security checks
- Data security analysis

**Duration:** 10-30 seconds  
**Cost:** ~$0.10-0.25  
**GitHub Actions Compatible:** ✅ Yes

**Discovers:**
- Missing authentication on endpoints
- Weak cryptography implementations
- Logic flaws and race conditions
- Implicit trust assumptions

---

### Phase 3: Multi-Agent Review ✅
**What runs:**
- 5 specialized AI agents analyze findings:
  1. **SecretHunter** - Credentials expert
  2. **ArchitectureReviewer** - Design security
  3. **ExploitAssessor** - Exploitability analysis
  4. **FalsePositiveFilter** - Noise reduction
  5. **ThreatModeler** - Attack chain mapping

**Duration:** 30-90 seconds (sequential mode)  
**Cost:** ~$0.30-0.60 (5 agents × $0.06-0.12 each)  
**GitHub Actions Compatible:** ✅ Yes

**Benefits:**
- 60-70% fewer false positives
- Deeper security insights
- Expert-level analysis per domain

---

### Phase 4: Sandbox Validation ✅
**What runs:**
- Docker-based exploit validation
- Isolated container execution
- Multi-language support (Python, Node.js, Java, Go)
- 14 exploit types tested

**Duration:** 10-30 seconds (if exploits found)  
**Cost:** FREE (no AI calls)  
**GitHub Actions Compatible:** ✅ Yes (requires Docker)

**Setup for GitHub Actions:**
```yaml
services:
  docker:
    image: docker:dind
    options: --privileged
```

Or mount Docker socket:
```yaml
- run: docker run -v /var/run/docker.sock:/var/run/docker.sock ...
```

---

### Phase 5: Policy Gates ✅
**What runs:**
- Rego/OPA policy evaluation
- Custom security policies
- Compliance checks (PCI-DSS, HIPAA, SOC 2)

**Duration:** 1-5 seconds  
**Cost:** FREE (no AI calls)  
**GitHub Actions Compatible:** ✅ Yes

**Example policy:**
```rego
# Block PRs with critical vulnerabilities
deny[msg] {
  input.findings[_].severity == "critical"
  msg = "Critical vulnerabilities found - cannot merge"
}
```

---

### Phase 6: Reporting ✅
**What runs:**
- SARIF generation (GitHub Code Scanning)
- JSON output (programmatic access)
- Markdown report (PR comments)

**Duration:** 2-5 seconds  
**Cost:** FREE  
**GitHub Actions Compatible:** ✅ Yes

**Output formats:**
- `.argus/reviews/results.sarif` → Upload to GitHub Security
- `.argus/reviews/results.json` → CI/CD integration
- `.argus/reviews/security-report.md` → Human-readable

---

## 💰 Cost Analysis

### Per-Scan Costs (Claude Sonnet 4.5)

| Repository Size | Typical Cost | With Multi-Agent |
|----------------|--------------|------------------|
| Small (<50 files) | $0.30-0.60 | $0.50-1.00 |
| Medium (50-200 files) | $0.60-1.20 | $1.00-1.80 |
| Large (200+ files) | $1.20-2.50 | $1.80-3.50 |

### Monthly Cost Estimates

| Usage Pattern | Scans/Month | Cost/Month |
|--------------|-------------|------------|
| 10 PRs/week | ~40 | $12-25 |
| 50 PRs/week | ~200 | $60-125 |
| 200 PRs/week | ~800 | $240-500 |

### Cost Optimization Tips

1. **Use `only-changed: true` for PRs**
   ```yaml
   only-changed: 'true'  # Only scan changed files
   ```

2. **Limit file count**
   ```yaml
   max-files: 50  # Scan top 50 most changed files
   ```

3. **Set cost limits**
   ```yaml
   cost-limit: '1.0'  # Max $1 per scan
   ```

4. **Schedule deep scans**
   ```yaml
   on:
     schedule:
       - cron: '0 9 * * 1'  # Monday only (weekly deep scan)
   ```

5. **Disable expensive features for PR checks**
   ```yaml
   enable-collaborative-reasoning: 'false'  # Saves 40% on Phase 3
   enable-fuzzing: 'false'  # Skip for fast PR feedback
   ```

---

## ⚡ Performance Benchmarks

### Typical Scan Times

| Phase | Duration | Parallelizable |
|-------|----------|----------------|
| Phase 1 (Static) | 15-30s | ✅ Yes |
| Phase 2 (AI) | 20-60s | ✅ Batch |
| Phase 2.5 (Remediation) | 5-15s | ✅ Yes |
| Phase 2.6 (Discovery) | 10-30s | ✅ Yes |
| Phase 3 (Multi-Agent) | 30-90s | ✅ Parallel mode |
| Phase 4 (Sandbox) | 10-30s | ✅ Yes |
| Phase 5 (Policy) | 1-5s | ✅ Yes |
| Phase 6 (Reporting) | 2-5s | N/A |
| **Total** | **2-5 min** | |

### Optimization Strategies

**For PR Reviews (Fast Feedback):**
```yaml
only-changed: 'true'
max-files: 30
enable-collaborative-reasoning: 'false'
multi-agent-mode: 'single'  # Skip multi-agent for speed
```
**Result:** 1-2 minutes, $0.20-0.40 per scan

**For Scheduled Scans (Deep Analysis):**
```yaml
only-changed: 'false'
max-files: 200
enable-collaborative-reasoning: 'true'
multi-agent-mode: 'parallel'
enable-fuzzing: 'true'
```
**Result:** 5-10 minutes, $1.50-3.00 per scan

---

## 🔧 Configuration Options

### Complete Configuration Reference

```yaml
- uses: devatsecure/Argus-Security@v4.2.0
  with:
    # ═══════════════════════════════════════════════════════════
    # AI PROVIDER (Required)
    # ═══════════════════════════════════════════════════════════
    ai-provider: 'anthropic'  # or 'openai', 'ollama', 'auto'
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    # openai-api-key: ${{ secrets.OPENAI_API_KEY }}
    # ollama-endpoint: 'http://localhost:11434'
    model: 'auto'  # or specific model like 'claude-sonnet-4'
    
    # ═══════════════════════════════════════════════════════════
    # PHASE 1: STATIC ANALYSIS
    # ═══════════════════════════════════════════════════════════
    semgrep-enabled: 'true'              # SAST scanning
    enable-api-security: 'true'          # OWASP API Top 10
    enable-supply-chain: 'true'          # Dependency analysis
    enable-threat-intel: 'true'          # CISA KEV, EPSS, NVD
    enable-regression-testing: 'true'    # Regression detection
    
    # ═══════════════════════════════════════════════════════════
    # PHASE 2-3: AI ANALYSIS
    # ═══════════════════════════════════════════════════════════
    enable-multi-agent: 'true'           # 5 specialized agents
    multi-agent-mode: 'sequential'       # or 'parallel'
    enable-spontaneous-discovery: 'true' # Hidden vulnerabilities
    enable-collaborative-reasoning: 'false'  # +30-40% less FP, +40% cost
    
    # ═══════════════════════════════════════════════════════════
    # PHASE 2.5-2.6: ADVANCED FEATURES
    # ═══════════════════════════════════════════════════════════
    enable-remediation: 'true'           # AI-generated fixes
    enable-exploit-analysis: 'true'      # Exploit chain analysis
    generate-security-tests: 'true'      # Auto-generate tests
    
    # ═══════════════════════════════════════════════════════════
    # OPTIONAL FEATURES
    # ═══════════════════════════════════════════════════════════
    enable-dast: 'false'                 # Dynamic testing
    dast-target-url: ''                  # Required if DAST enabled
    enable-fuzzing: 'false'              # AI-guided fuzzing
    fuzzing-duration: '300'              # Seconds
    enable-runtime-security: 'false'     # Container monitoring
    
    # ═══════════════════════════════════════════════════════════
    # COST & PERFORMANCE GUARDRAILS
    # ═══════════════════════════════════════════════════════════
    only-changed: 'true'                 # PR mode: only changed files
    max-files: 100
    max-tokens: 8000
    cost-limit: '2.0'                    # Max USD per run
    max-file-size: '100000'              # 100KB
    
    # ═══════════════════════════════════════════════════════════
    # POLICY & FAILURE CONDITIONS
    # ═══════════════════════════════════════════════════════════
    fail-on-blockers: 'true'
    fail-on: 'security:critical,security:high'
    exploitability-threshold: 'trivial'
    
    # ═══════════════════════════════════════════════════════════
    # REPORTING
    # ═══════════════════════════════════════════════════════════
    upload-reports: 'true'
    comment-on-pr: 'true'
    
    # ═══════════════════════════════════════════════════════════
    # FILE FILTERING
    # ═══════════════════════════════════════════════════════════
    exclude-paths: |
      .github/**
      node_modules/**
      vendor/**
      *.lock
      *.min.js
      test/**
```

---

## 📁 Output Files

After the scan completes, these files are generated:

```
.argus/
├── reviews/
│   ├── results.sarif          # ← Upload to GitHub Security
│   ├── results.json           # ← Machine-readable
│   ├── security-report.md     # ← Human-readable
│   ├── metrics.json           # ← Cost & performance
│   ├── context-tracking.json  # ← Scan metadata
│   └── agents/                # ← Individual agent reports
│       ├── secret-hunter.json
│       ├── architecture-reviewer.json
│       ├── exploit-assessor.json
│       ├── false-positive-filter.json
│       └── threat-modeler.json
├── threat-model.json          # ← STRIDE threat analysis
└── tests/                     # ← Auto-generated security tests
    └── test_security_*.py
```

---

## 🔗 Integration Examples

### 1. Upload SARIF to GitHub Security

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: .argus/reviews/results.sarif
    category: argus-security
```

**View results:** Security tab → Code scanning alerts

---

### 2. Comment on Pull Requests

```yaml
with:
  comment-on-pr: 'true'
```

**Result:** Automated comment with findings on every PR

---

### 3. Create GitHub Issues

```yaml
- name: Create Security Issue
  if: steps.scan.outputs.blockers > 0
  uses: actions/github-script@v7
  with:
    script: |
      await github.rest.issues.create({
        owner: context.repo.owner,
        repo: context.repo.repo,
        title: '🔒 Security: ${{ steps.scan.outputs.blockers }} Vulnerabilities',
        body: '...',
        labels: ['security', 'vulnerability']
      });
```

---

### 4. Send Slack Notifications

```yaml
- name: Notify Slack
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "🚨 Security Alert: ${{ steps.scan.outputs.blockers }} issues found"
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

---

### 5. Block Merges on Critical Issues

```yaml
- name: Fail on Critical Issues
  if: steps.scan.outputs.blockers > 0
  run: exit 1
```

---

## 🎓 Best Practices

### 1. Use Different Configurations for Different Triggers

```yaml
# Fast PR checks
on:
  pull_request:
    # Quick scan: only changed files
    
# Deep scheduled scans
on:
  schedule:
    - cron: '0 9 * * 1'  # Monday 9 AM
    # Full scan: all files, all features
```

### 2. Progressive Security

```yaml
# PR Review: Fast feedback
only-changed: 'true'
enable-collaborative-reasoning: 'false'

# Release Gate: Comprehensive
only-changed: 'false'
enable-collaborative-reasoning: 'true'
enable-fuzzing: 'true'
```

### 3. Cost Management

```yaml
# Set hard limits
cost-limit: '1.0'
max-files: 50

# Use caching
- uses: actions/cache@v4
  with:
    path: ~/.argus/cache
    key: argus-${{ hashFiles('**/requirements.txt') }}
```

### 4. Notification Strategy

```yaml
# Critical: Always notify
if: steps.scan.outputs.exploitability-trivial > 0

# High: Notify on main branch only
if: github.ref == 'refs/heads/main' && steps.scan.outputs.blockers > 0

# Medium: Only in artifacts
if: always()
```

---

## 🐛 Troubleshooting

### Issue: "API key not found"

**Solution:**
```yaml
# Verify secret is set
- run: echo "API Key: ${ANTHROPIC_API_KEY:0:10}..."
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Issue: "Docker socket permission denied"

**Solution:**
```yaml
# Add Docker service
services:
  docker:
    image: docker:dind
    options: --privileged
```

### Issue: "Scan timeout"

**Solution:**
```yaml
# Increase timeout
timeout-minutes: 30

# Or reduce scope
max-files: 50
only-changed: 'true'
```

### Issue: "Cost limit exceeded"

**Solution:**
```yaml
# Increase limit or optimize
cost-limit: '5.0'  # Increase

# OR reduce scope
max-files: 30  # Fewer files
enable-collaborative-reasoning: 'false'  # Disable expensive features
```

---

## 📚 Additional Resources

- **Complete Workflow Example:** [`COMPLETE-6-PHASE-WORKFLOW.yml`](./COMPLETE-6-PHASE-WORKFLOW.yml)
- **Action Reference:** [`action.yml`](./action.yml)
- **Example Workflows:** [`examples/workflows/`](./examples/workflows/)
- **Docker Guide:** [`DOCKER_QUICKSTART.md`](./DOCKER_QUICKSTART.md)
- **Documentation:** [`docs/`](./docs/)

---

## ✅ Summary

**YES - All 6 phases run perfectly on GitHub Actions!**

| Phase | GitHub Actions Compatible | Setup Required |
|-------|--------------------------|----------------|
| Phase 1: Static Analysis | ✅ Yes | None |
| Phase 2: AI Enrichment | ✅ Yes | API key secret |
| Phase 2.5: Remediation | ✅ Yes | API key secret |
| Phase 2.6: Discovery | ✅ Yes | API key secret |
| Phase 3: Multi-Agent | ✅ Yes | API key secret |
| Phase 4: Sandbox | ✅ Yes | Docker service |
| Phase 5: Policy Gates | ✅ Yes | None |
| Phase 6: Reporting | ✅ Yes | None |

**Total setup time:** 5 minutes  
**First scan duration:** 2-5 minutes  
**Typical cost:** $0.30-1.50 per scan  
**Infrastructure required:** None (GitHub provides everything)

---

**Ready to get started?** Copy the [`COMPLETE-6-PHASE-WORKFLOW.yml`](./COMPLETE-6-PHASE-WORKFLOW.yml) to your repository!
