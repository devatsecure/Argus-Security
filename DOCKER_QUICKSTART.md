# 🐳 Argus Docker Quick Start

Run complete 6-phase security scans without installing dependencies!

## ✨ Features

- **All Dependencies Pre-installed**: Semgrep, Trivy, Checkov, Python packages, etc.
- **Complete 6-Phase Pipeline**: All phases ready to execute
- **One Command Scan**: Just clone target repo and scan
- **Persistent Cache**: Faster subsequent scans
- **Docker Sandbox Support**: Phase 4 validation included

---

## 📋 Prerequisites

1. **Docker installed and running**
2. **Anthropic or OpenAI API key**

```bash
# Check Docker
docker --version

# Set API key
export ANTHROPIC_API_KEY=your-key-here
# OR
export OPENAI_API_KEY=your-key-here
```

---

## 🚀 Quick Start (3 Steps)

### 1. Build the Image (First Time Only)

```bash
docker-compose build
```

**Build time:** ~5-10 minutes (includes downloading all security tools)

### 2. Scan Any Repository

```bash
# Make script executable
chmod +x scan-repo.sh

# Scan current directory
./scan-repo.sh

# Scan specific repository
./scan-repo.sh /path/to/target/repo

# Scan with custom output directory
./scan-repo.sh /path/to/repo /path/to/output
```

### 3. View Results

```bash
ls output/
# hybrid-scan-YYYYMMDD-HHMMSS.json   - Machine-readable
# hybrid-scan-YYYYMMDD-HHMMSS.sarif  - GitHub integration
# hybrid-scan-YYYYMMDD-HHMMSS.md     - Human-readable report
```

---

## 🔧 Complete 6-Phase Pipeline

The Docker container runs **all 6 phases automatically**:

### ✅ Phase 1: Static Analysis (15-25s)
- **Semgrep SAST** - Pattern-based code analysis
- **Trivy CVE Scanner** - Known vulnerabilities
- **Checkov IaC** - Infrastructure security
- **API Security** - REST/GraphQL analysis
- **Supply Chain** - Dependency threats
- **Threat Intel** - CISA KEV correlation (1,493 entries)
- **Regression Testing** - Security regression detection

### ✅ Phase 2: AI Enrichment (20-30s)
- **Claude Sonnet 4.5** - Deep code analysis
- **CWE Mapping** - Weakness classification
- **Exploitability Assessment** - Risk scoring

### ✅ Phase 2.5: Automated Remediation (0-1s)
- **AI-Generated Fixes** - Code patches
- **Remediation Guidance** - Step-by-step fixes

### ✅ Phase 2.6: Spontaneous Discovery (0-1s)
- **Beyond-Rules Detection** - Novel vulnerabilities
- **Architecture Analysis** - Design flaws

### ✅ Phase 3: Multi-Agent Persona Review (40-50s)
- **SecretHunter** - Credential detection
- **ArchitectureReviewer** - Design security
- **ExploitAssessor** - Exploitability analysis
- **FalsePositiveFilter** - Noise reduction
- **ThreatModeler** - STRIDE analysis

### ✅ Phase 4: Sandbox Validation (0-10s)
- **Docker-based Validation** - Exploit testing
- **Proof-of-Concept** - Vulnerability verification

### ⚠️ Phase 5: Policy Gate Evaluation (0-1s) - **AMD64 Only**
- **Rego/OPA Enforcement** - Policy compliance
- **PR/Release Gates** - Automated blocking

**Note:** OPA (Open Policy Agent) prebuilt binaries have compatibility issues on ARM64 Linux containers. Phase 5 will be skipped on ARM64 (Apple Silicon M1/M2/M3).

**Workaround for ARM64:**
```bash
# Install OPA on host (macOS ARM64)
brew install opa

# Mount OPA binary into container
docker run --rm \
  -v $(which opa):/usr/local/bin/opa \
  -v /path/to/repo:/workspace:ro \
  ... argus-scanner:latest
```

Alternatively, run scans directly on the host without Docker to enable all 6 phases.

---

## 💡 Usage Examples

### Example 1: Scan GitHub Repository

```bash
# Clone and scan
git clone https://github.com/openai/tiktoken /tmp/tiktoken
./scan-repo.sh /tmp/tiktoken ./tiktoken-results
```

### Example 2: Scan with Docker Compose

```bash
# Set variables
export TARGET_REPO=/path/to/your/repo
export OUTPUT_DIR=./scan-results
export ANTHROPIC_API_KEY=your-key

# Run scan
docker-compose run --rm argus-scanner \
  /workspace \
  --enable-ai-enrichment \
  --ai-provider anthropic \
  --enable-semgrep \
  --enable-trivy \
  --enable-checkov \
  --enable-api-security \
  --enable-supply-chain \
  --enable-threat-intel \
  --enable-remediation \
  --enable-regression-testing
```

### Example 3: Manual Docker Run

```bash
docker run --rm \
  -v /path/to/repo:/workspace:ro \
  -v $(pwd)/output:/output \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  argus-scanner:latest \
  /workspace \
  --enable-ai-enrichment \
  --ai-provider anthropic \
  --enable-semgrep \
  --enable-trivy \
  --enable-checkov \
  --enable-api-security \
  --enable-supply-chain \
  --enable-threat-intel \
  --enable-remediation \
  --enable-regression-testing \
  --output-dir /output
```

---

## 🛠️ Pre-installed Tools

The container includes:

| Tool | Version | Purpose |
|------|---------|---------|
| **Python** | 3.11 | Runtime |
| **Semgrep** | 1.100.0 | SAST |
| **Trivy** | 0.58.1 | CVE scanning |
| **Checkov** | 3.2.491 | IaC security |
| **GitHub CLI** | Latest | Issue reporting |
| **Docker CLI** | Latest | Sandbox validation |
| **Argus** | Latest | All Python deps |

---

## ⚙️ Configuration

### Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...        # Claude API key
# OR
OPENAI_API_KEY=sk-...               # OpenAI API key

# Optional
ENABLE_REMEDIATION=true             # Phase 2.5
ENABLE_THREAT_INTEL=true            # Threat intelligence
ENABLE_MULTI_AGENT=true             # Phase 3 (5 agents)
ENABLE_SANDBOX=true                 # Phase 4
ENABLE_SPONTANEOUS_DISCOVERY=true   # Phase 2.6
SEMGREP_ENABLED=true                # Semgrep SAST
TRIVY_ENABLED=true                  # Trivy CVE
CHECKOV_ENABLED=true                # Checkov IaC
```

### Volume Mounts

```yaml
volumes:
  - /path/to/repo:/workspace:ro          # Target (read-only)
  - /path/to/output:/output              # Results (read-write)
  - /var/run/docker.sock:/var/run/docker.sock  # Phase 4 sandbox
  - argus-cache:/cache                # Persistent cache
```

---

## 📊 Performance

**First Scan:**
- Build time: 5-10 minutes (one-time)
- Scan time: 80-120 seconds

**Subsequent Scans:**
- Build time: 0 seconds (cached)
- Scan time: 60-90 seconds (with cache)

**Cache Benefits:**
- Trivy DB cached (no re-download)
- AI responses cached (duplicate findings)
- Threat intel cached (CISA KEV)

---

## 🐛 Troubleshooting

### Docker Socket Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Port Already in Use

```bash
# Change ports in docker-compose.yml or stop conflicting services
docker ps  # Check running containers
```

### Out of Memory

```bash
# Increase Docker memory limit
# Docker Desktop -> Settings -> Resources -> Memory -> 8GB
```

### Trivy DB Download Issues

```bash
# Pre-download DB
docker run --rm argus-scanner:latest \
  trivy image --download-db-only
```

---

## 🔒 Security Considerations

1. **Read-Only Mounts**: Target repo mounted as read-only (`:ro`)
2. **Non-Root User**: Container runs as `agentuser` (UID 1000)
3. **Resource Limits**: CPU and memory limits configured
4. **Docker Socket**: Required for Phase 4, consider security implications
5. **API Keys**: Passed via environment variables (not baked into image)

---

## 🚦 What's Next?

After scanning:

1. **Review Findings**: Open `.md` report for human-readable results
2. **Import to GitHub**: Upload `.sarif` to GitHub Security tab
3. **Automate**: Integrate into CI/CD pipeline
4. **Fix Issues**: Follow remediation guidance in report

---

## 📚 Additional Resources

- [Full Documentation](./README.md)
- [Argus GitHub](https://github.com/devatsecure/Argus-Security)
- [6-Phase Pipeline Details](./docs/architecture/6-phase-pipeline.md)

---

**Questions?** Open an issue or check the main README!
