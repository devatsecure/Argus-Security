# 🔒 Argus Security - Complete Docker Guide

## ⚠️ ALWAYS USE DOCKER FOR SCANS ⚠️

**Why Docker?**
- ✅ All dependencies pre-installed (tenacity, networkx, etc.)
- ✅ All features included (DAST, Vulnerability Chaining, 6 Phases)
- ✅ Consistent environment across all systems
- ✅ No environment/dependency issues
- ✅ Isolated and secure execution

---

## 🚀 Quick Start

### 1. Build the Complete Image (First Time Only)

```bash
cd /Users/waseem.ahmed/Repos/Argus-Security
docker build -f Dockerfile.complete -t argus:complete --platform linux/amd64 .
```

**Build time:** ~5-10 minutes (one-time setup)

### 2. Run Complete Scan

#### Option A: Using the Scan Script (Recommended)

```bash
# Full scan of a local repository
./scan-complete-docker.sh /path/to/repo

# Full scan with DAST
./scan-complete-docker.sh /path/to/repo --dast-url http://localhost:8080

# Scan a remote GitHub repository
./scan-complete-docker.sh https://github.com/user/repo

# Custom output directory
./scan-complete-docker.sh /path/to/repo --output-dir /tmp/my-scan-results
```

#### Option B: Direct Docker Command

```bash
export ANTHROPIC_API_KEY="your-api-key"

docker run --rm \
  -v /path/to/repo:/workspace:ro \
  -v /tmp/scan-results:/output \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e ENABLE_VULNERABILITY_CHAINING=true \
  -e CHAIN_MAX_LENGTH=4 \
  argus:complete \
  /workspace \
  --output-dir /output \
  --enable-semgrep \
  --enable-trivy \
  --enable-checkov \
  --enable-api-security \
  --enable-supply-chain \
  --enable-threat-intel \
  --enable-ai-enrichment \
  --enable-remediation \
  --enable-regression-testing \
  --ai-provider anthropic
```

---

## 📊 What's Included

### Phase 1: Static Analysis
- ✅ **Semgrep** - SAST with 2,000+ security rules
- ✅ **Trivy** - CVE scanning (150,000+ vulnerabilities)
- ✅ **Checkov** - IaC security (Terraform, K8s, Docker)
- ✅ **TruffleHog** - Verified secrets detection
- ✅ **Gitleaks** - Pattern-based secrets detection
- ✅ **API Security** - OWASP API Top 10 testing
- ✅ **Supply Chain** - Dependency threat analysis
- ✅ **Threat Intel** - KEV enrichment (1,499 exploits)

### Phase 2: AI Enrichment
- ✅ **Claude Sonnet 4.5** or OpenAI analysis
- ✅ CWE mapping & risk scoring
- ✅ False positive prediction
- ✅ Exploitability assessment

### Phase 2.5: Automated Remediation
- ✅ AI-generated fix suggestions
- ✅ Multi-language support

### Phase 2.6: Spontaneous Discovery
- ✅ Finds 15-20% more issues beyond scanner rules
- ✅ Architecture risk analysis
- ✅ Logic flaw detection

### Phase 3: Multi-Agent Persona Review
- ✅ **SecretHunter** - API keys, credentials expert
- ✅ **ArchitectureReviewer** - Design flaw analysis
- ✅ **ExploitAssessor** - Real-world exploitability
- ✅ **FalsePositiveFilter** - Noise suppression
- ✅ **ThreatModeler** - Attack chain scenarios

### Phase 4: Sandbox Validation
- ✅ Docker-based exploit validation
- ✅ 14 exploit types supported
- ✅ Isolated execution

### Phase 5: Policy Gates
- ✅ Rego/OPA policy evaluation
- ✅ PASS/FAIL compliance checks

### Phase 5.5: Vulnerability Chaining
- ✅ **Attack graph construction** (NetworkX)
- ✅ **Chain detection algorithms** (DFS, BFS)
- ✅ **Risk amplification calculations**
- ✅ **Visual reports** (attack flow diagrams)

### DAST (Dynamic Application Security Testing)
- ✅ **Nuclei** - 3,000+ templates
- ✅ **OWASP ZAP** - Active/passive scanning
- ✅ **Multi-agent orchestration**
- ✅ **SAST-DAST correlation**

---

## 🔧 Features Included in Docker

| Feature | Included | Version |
|---------|----------|---------|
| Python | ✅ | 3.11 |
| Semgrep | ✅ | Latest |
| Trivy | ✅ | Latest |
| Checkov | ✅ | Latest |
| TruffleHog | ✅ | Latest |
| Gitleaks | ✅ | 8.18.1 |
| Nuclei | ✅ | 3.1.0 |
| OWASP ZAP | ✅ | 2.14.0 |
| Anthropic SDK | ✅ | >=0.40.0 |
| OpenAI SDK | ✅ | >=1.56.0 |
| tenacity | ✅ | >=9.0.0 |
| networkx | ✅ | >=3.0 |
| Docker SDK | ✅ | >=7.0.0 |
| PyTM | ✅ | >=1.3.0 |

---

## 📝 Examples

### Example 1: Scan GitHub Copilot CLI

```bash
./scan-complete-docker.sh https://github.com/github/copilot-cli
```

### Example 2: Scan with DAST (Streamlit App)

```bash
# Terminal 1: Start the app
cd /path/to/streamlit-app
streamlit run app.py

# Terminal 2: Scan with DAST
./scan-complete-docker.sh /path/to/streamlit-app \
  --dast-url http://host.docker.internal:8501
```

### Example 3: Scan AI Data Science Team

```bash
./scan-complete-docker.sh https://github.com/business-science/ai-data-science-team \
  --output-dir /tmp/ai-ds-scan-results
```

---

## 🎯 Output Files

After the scan completes, you'll find:

```
/tmp/scan-results/
├── hybrid-scan-TIMESTAMP.json       # Detailed findings (JSON)
├── hybrid-scan-TIMESTAMP.sarif      # GitHub code scanning format
├── hybrid-scan-TIMESTAMP.md         # Human-readable report
├── attack-chains-TIMESTAMP.json     # Vulnerability chaining results
└── attack-graph-TIMESTAMP.png       # Visual attack graph (if chains found)
```

---

## 🔐 API Keys

Set your API key before running:

```bash
# For Anthropic (Claude)
export ANTHROPIC_API_KEY="sk-ant-api03-xxx"

# For OpenAI (GPT)
export OPENAI_API_KEY="sk-xxx"

# Then run the scan
./scan-complete-docker.sh /path/to/repo
```

---

## 🚨 Troubleshooting

### Issue: Docker image not found

```bash
# Rebuild the image
docker build -f Dockerfile.complete -t argus:complete --platform linux/amd64 .
```

### Issue: Permission denied on scan-complete-docker.sh

```bash
chmod +x scan-complete-docker.sh
```

### Issue: Cannot connect to Docker daemon

```bash
# Make sure Docker is running
docker ps

# Check Docker socket
ls -la /var/run/docker.sock
```

### Issue: API key not working

```bash
# Verify API key is set
echo $ANTHROPIC_API_KEY

# Re-export if needed
export ANTHROPIC_API_KEY="sk-ant-api03-xxx"
```

---

## 📚 Advanced Usage

### Custom Scan Configuration

```bash
docker run --rm \
  -v /path/to/repo:/workspace:ro \
  -v /tmp/results:/output \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  -e ENABLE_VULNERABILITY_CHAINING=true \
  -e CHAIN_MAX_LENGTH=5 \
  -e CHAIN_MIN_RISK=7.0 \
  argus:complete \
  /workspace \
  --output-dir /output \
  --enable-semgrep \
  --enable-trivy \
  --enable-checkov \
  --enable-dast \
  --dast-target-url http://host.docker.internal:8080 \
  --severity-filter CRITICAL,HIGH \
  --ai-provider anthropic
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Claude API key | - |
| `OPENAI_API_KEY` | OpenAI API key | - |
| `ENABLE_VULNERABILITY_CHAINING` | Enable Phase 5.5 | `true` |
| `CHAIN_MAX_LENGTH` | Max chain length | `4` |
| `CHAIN_MIN_RISK` | Minimum risk score | `5.0` |

---

## 🎉 Success Criteria

A complete scan should show:

```
✅ Phase 1: Static Analysis (Deterministic)
✅ Phase 2: AI Enrichment (Claude/OpenAI)
✅ Phase 2.5: Automated Remediation
✅ Phase 2.6: Spontaneous Discovery
✅ Phase 3: Multi-Agent Persona Review
✅ Phase 4: Sandbox Validation (Docker)
✅ Phase 5: Policy Gate Evaluation
✅ Phase 5.5: Vulnerability Chaining Analysis
✅ DAST: Dynamic Security Testing (if enabled)
```

**If any phase is skipped, check:**
1. API key is set correctly
2. Docker image includes all dependencies
3. No environment issues (use Docker!)

---

## 🔄 Rebuilding After Updates

Whenever new features are added (like DAST or Vulnerability Chaining):

```bash
# 1. Rebuild Docker image
docker build -f Dockerfile.complete -t argus:complete --platform linux/amd64 .

# 2. Run scan with new features
./scan-complete-docker.sh /path/to/repo
```

---

## 💡 Best Practices

1. **Always use Docker** - Ensures consistent environment
2. **Set API keys** - Enables AI enrichment (Phases 2, 2.6, 3)
3. **Use DAST for web apps** - Include `--dast-url` for runtime testing
4. **Check all phases run** - Verify no phases are skipped
5. **Review attack chains** - Check vulnerability chaining results for multi-stage attacks

---

## 📞 Support

- **Documentation:** `/Users/waseem.ahmed/Repos/Argus-Security/docs/`
- **Examples:** `/Users/waseem.ahmed/Repos/Argus-Security/examples/`
- **Issues:** Create GitHub issue with scan logs

---

**Remember: ALWAYS USE DOCKER! 🐳**
