# Argus Security

**Enterprise-grade AI Security Platform** — Orchestrate security scanners with intelligent triage and multi-agent analysis

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![AI-Powered](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI-blue.svg)](#ai-triage)
[![Multi-Agent](https://img.shields.io/badge/Architecture-Multi--Agent-purple.svg)](#multi-agent-analysis)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](#docker)

---

## What is Argus?

**Argus** is an AI-powered security platform that orchestrates multiple security scanners and uses specialized AI personas to analyze vulnerabilities with unprecedented accuracy.

### 🎯 NEW: Context-Aware Security Analysis

**70% False Positive Reduction** achieved through project context detection:
- ✅ Auto-detects CLI tools vs web apps vs libraries
- ✅ Context-specific vulnerability analysis (e.g., console.log in CLI ≠ XSS)
- ✅ Smart remediation tailored to project type
- ✅ Continuous learning from developer feedback

See [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md) for details.

### Key Benefits

| Challenge | Argus Solution |
|-----------|----------------|
| Too many false positives | **70% reduction** via context-aware AI triage |
| Scanners miss real issues | +15-20% more findings via spontaneous discovery |
| Manual triage takes hours | Automated multi-agent analysis |
| No learning over time | Self-improving from your feedback |

---

## Quick Start

### Option 1: GitHub Action

```yaml
name: Argus Security
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Option 2: Docker

```bash
# Pull the image
docker pull ghcr.io/devatsecure/argus-security:latest

# Run security scan
docker run -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY="your-key" \
  ghcr.io/devatsecure/argus-security:latest \
  --project-type backend-api

# Run with custom options
docker run -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY="your-key" \
  ghcr.io/devatsecure/argus-security:latest \
  --enable-multi-agent \
  --enable-spontaneous-discovery \
  --output-file /workspace/report.json
```

**Docker Compose:**

```yaml
version: '3.8'
services:
  argus:
    image: ghcr.io/devatsecure/argus-security:latest
    volumes:
      - .:/workspace
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    command: ["--project-type", "backend-api", "--output-file", "/workspace/report.json"]
```

### Option 3: Local CLI

```bash
git clone https://github.com/devatsecure/Argus-Security.git
cd Argus-Security
pip install -r requirements.txt
export ANTHROPIC_API_KEY="your-key"

python scripts/run_ai_audit.py --project-type backend-api
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  ARGUS SECURITY PLATFORM                                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  PHASE 1: Multi-Scanner Orchestration                       │
│  ├─ TruffleHog (secrets with API verification)             │
│  ├─ Semgrep (SAST - 2000+ rules)                           │
│  ├─ Trivy (CVE scanning)                                   │
│  ├─ Checkov (IaC security)                                 │
│  └─ Gitleaks (pattern-based secrets)                       │
│                                                             │
│  PHASE 2: AI Enrichment                                     │
│  ├─ Claude/OpenAI/Ollama triage                            │
│  ├─ Noise scoring & false positive prediction              │
│  └─ Threat intelligence enrichment                         │
│                                                             │
│  PHASE 2.5: Remediation Engine                              │
│  └─ AI-generated fix suggestions                           │
│                                                             │
│  PHASE 2.6: Spontaneous Discovery                           │
│  └─ Find issues beyond scanner rules                       │
│                                                             │
│  PHASE 2.7: Deep Analysis (AISLE-inspired)                  │
│  ├─ Semantic Code Twin (AST-based intent analysis)         │
│  ├─ Proactive AI Scanner (autonomous reasoning)            │
│  ├─ Taint Analyzer (inter-procedural data flow)            │
│  └─ Zero-Day Hypothesizer (novel vulnerability discovery)  │
│                                                             │
│  PHASE 3: Multi-Agent Persona Review                        │
│  ├─ SecretHunter - credentials expert                      │
│  ├─ ArchitectureReviewer - design flaws                    │
│  ├─ ExploitAssessor - exploitability analysis              │
│  ├─ FalsePositiveFilter - noise elimination                │
│  └─ ThreatModeler - attack chain mapping                   │
│                                                             │
│  PHASE 4: Sandbox Validation (Docker-based)                 │
│                                                             │
│  PHASE 5: Policy Gates (Rego/OPA)                           │
│                                                             │
│  PHASE 6: Reporting (SARIF/JSON/Markdown)                   │
│                                                             │
│  ═══════════════════════════════════════════════════════   │
│  ADDITIONAL FEATURES (Standalone Tools)                     │
│  ═══════════════════════════════════════════════════════   │
│                                                             │
│  🌐 DAST Integration (Runtime Security Testing)             │
│  ├─ Nuclei Agent (template-based scanning)                 │
│  ├─ ZAP Agent (spider + active scan)                       │
│  ├─ SAST-DAST Correlation (30-40% FP reduction)            │
│  └─ Intelligent orchestration & tech stack detection       │
│                                                             │
│  🔗 Vulnerability Chaining (Attack Path Discovery)          │
│  ├─ Multi-step attack scenario discovery                   │
│  ├─ Attack graph generation                                │
│  ├─ Exploitability scoring                                 │
│  └─ Attack complexity analysis                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Multi-Agent Analysis

Argus deploys **5 specialized AI personas**, each expert in a specific security domain:

| Agent | Focus | What It Finds |
|-------|-------|---------------|
| **SecretHunter** | Credentials | API keys, tokens, passwords in code/configs |
| **ArchitectureReviewer** | Design | Auth bypass, missing controls, IAM issues |
| **ExploitAssessor** | Exploitability | Real-world attack viability |
| **FalsePositiveFilter** | Noise | Test code, mocks, documentation |
| **ThreatModeler** | Attack Chains | STRIDE threats, attack paths |

### Spontaneous Discovery

Beyond scanner rules, Argus **proactively finds hidden issues**:
- Missing authentication on endpoints
- Architectural vulnerabilities
- Configuration mistakes
- Supply chain risks

**Result:** +15-20% more real issues discovered

---

## DAST Integration (Runtime Security Testing)

Argus includes **standalone DAST tools** for runtime application security testing:

### Quick Start

```bash
# Basic DAST scan with Nuclei + ZAP
python scripts/dast_orchestrator.py --target https://example.com

# With SAST-DAST correlation
python scripts/dast_orchestrator.py \
  --target https://example.com \
  --sast-findings .argus/reviews/results.json \
  --enable-correlation
```

### Features

- **Parallel Execution**: Nuclei + ZAP run concurrently
- **Tech Stack Detection**: Auto-selects relevant templates
- **SAST-DAST Correlation**: Confirms exploitability (30-40% FP reduction)
- **Multi-Agent Orchestration**: Intelligent routing & failure handling

### Example Workflow

```yaml
# .github/workflows/dast.yml
- name: Run DAST Scan
  run: |
    python scripts/dast_orchestrator.py \
      --target ${{ env.STAGING_URL }} \
      --output dast-results.json
```

**Documentation**: `DAST_MVP_DELIVERY_SUMMARY.md`, `docs/references/dast-scanner-reference.md`

---

## Vulnerability Chaining (Attack Path Discovery)

Discover **multi-step attack scenarios** by chaining individual vulnerabilities:

### Quick Start

```bash
# Analyze findings for attack chains
python scripts/vulnerability_chaining_engine.py \
  --findings .argus/reviews/results.json \
  --output attack-chains.json

# Generate attack graph visualization
python scripts/chain_visualizer.py \
  --chains attack-chains.json \
  --output attack-graph.html
```

### Features

- **Attack Graph Generation**: Visualize multi-step attack paths
- **Exploitability Scoring**: CRITICAL, HIGH, MODERATE, LOW, UNLIKELY
- **Attack Complexity Analysis**: TRIVIAL, LOW, MEDIUM, HIGH
- **Chain Prioritization**: Focus on highest-impact attack scenarios

### Example: SQL Injection → RCE Chain

```json
{
  "chain_id": "chain_001",
  "exploitability": "CRITICAL",
  "complexity": "LOW",
  "steps": [
    {"vuln_id": "sql-001", "severity": "high", "type": "SQL Injection"},
    {"vuln_id": "file-002", "severity": "medium", "type": "Arbitrary File Write"},
    {"vuln_id": "exec-003", "severity": "critical", "type": "Remote Code Execution"}
  ]
}
```

**Documentation**: `CHAINING_QUICKSTART.md`

---

## Docker

### Build Locally

```bash
# Build the image
docker build -t argus-security .

# Build complete image with all scanners
docker build -f Dockerfile.complete -t argus-security:complete .
```

### Run Scans

```bash
# Basic scan
docker run -v $(pwd):/workspace argus-security

# With AI triage
docker run -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY="your-key" \
  argus-security --project-type backend-api

# Full scan with all features
docker run -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY="your-key" \
  argus-security:complete \
  --enable-multi-agent \
  --enable-spontaneous-discovery \
  --enable-sandbox-validation
```

### Docker Compose (Production)

```yaml
version: '3.8'
services:
  argus:
    image: ghcr.io/devatsecure/argus-security:latest
    volumes:
      - ./src:/workspace:ro
      - ./reports:/reports
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - ARGUS_CACHE_DIR=/cache
    command: 
      - "--project-type"
      - "backend-api"
      - "--output-file"
      - "/reports/security-report.json"
      - "--enable-multi-agent"
    
  # Optional: Run dashboard
  dashboard:
    image: ghcr.io/devatsecure/argus-security:latest
    ports:
      - "8501:8501"
    volumes:
      - ./reports:/reports:ro
    command: ["dashboard", "--report", "/reports/security-report.json"]
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Multi-Scanner** | TruffleHog, Semgrep, Trivy, Checkov, Gitleaks |
| **AI Triage** | Claude/OpenAI/Ollama for intelligent analysis |
| **Enhanced FP Detection** | OAuth2 public clients, file permissions, dev configs, mutex/locks |
| **60-70% FP Reduction** | ML noise scoring + AI triage + pattern intelligence |
| **Phase 2.7 Deep Analysis** | AISLE-inspired semantic analysis with 4 AI modules |
| **Spontaneous Discovery** | Find issues beyond scanner rules |
| **DAST Integration** | Nuclei + ZAP runtime testing with SAST correlation |
| **Vulnerability Chaining** | Multi-step attack path discovery and visualization |
| **Self-Improving** | Learns from your feedback |
| **Threat Intelligence** | CVE, CISA KEV, EPSS enrichment |
| **Auto-Remediation** | AI-generated fix suggestions |
| **Policy Gates** | Rego-based enforcement |
| **10-100x Caching** | Fast repeat scans |
| **Docker Ready** | Full containerized deployment |

---

## CLI Commands

| Command | Purpose |
|---------|---------|
| `python scripts/run_ai_audit.py` | Run full security audit (6-phase pipeline) |
| `python scripts/run_ai_audit.py --deep-analysis-mode=conservative` | Run with Phase 2.7 Deep Analysis |
| `python scripts/dast_orchestrator.py --target URL` | Run DAST scan (Nuclei + ZAP) |
| `python scripts/vulnerability_chaining_engine.py --findings FILE` | Discover attack chains |
| `./scripts/argus gate --stage pr` | Apply policy gate |
| `./scripts/argus feedback record` | Mark findings as TP/FP |
| `./scripts/argus dashboard` | Launch observability dashboard |

---

## Configuration

### Environment Variables

```bash
export ANTHROPIC_API_KEY="your-key"    # Claude (recommended)
export OPENAI_API_KEY="your-key"       # OpenAI (alternative)
export OLLAMA_ENDPOINT="http://localhost:11434"  # Ollama (free)
```

### GitHub Action Inputs

```yaml
- uses: devatsecure/Argus-Security@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

    # Multi-Agent Features
    enable-multi-agent: 'true'
    enable-spontaneous-discovery: 'true'
    enable-collaborative-reasoning: 'false'

    # Phase 2.7: Deep Analysis (NEW)
    deep-analysis-mode: 'conservative'  # off, semantic-only, conservative, full
    max-files-deep-analysis: '50'
    deep-analysis-cost-ceiling: '5.0'
    deep-analysis-timeout: '300'
    benchmark: 'true'

    # Core Features
          enable-threat-intel: 'true'
          enable-remediation: 'true'

    # Optional
    fail-on-blockers: 'true'
    only-changed: 'true'
```

#### Phase 2.7 Deep Analysis Examples

**Basic with Phase 2.7:**
```yaml
- uses: devatsecure/Argus-Security@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    deep-analysis-mode: conservative
    benchmark: true
```

**Semantic Analysis Only:**
```yaml
- uses: devatsecure/Argus-Security@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    deep-analysis-mode: semantic-only
    max-files-deep-analysis: 100
    deep-analysis-cost-ceiling: 3.0
    deep-analysis-timeout: 180
```

**Full Deep Analysis:**
```yaml
- uses: devatsecure/Argus-Security@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    deep-analysis-mode: full
    max-files-deep-analysis: 200
    deep-analysis-cost-ceiling: 10.0
    deep-analysis-timeout: 600
    benchmark: true
```

---

## Performance

| Metric | Value |
|--------|-------|
| **Scan Time** | 3-5 minutes (first run) |
| **Cached Repeat** | 30-90 seconds |
| **False Positive Reduction** | 60-70% |
| **Additional Findings** | +15-20% |
| **Cost per Scan** | ~$0.35 (Claude) |

---

## Documentation

### 📊 Project Status & Roadmap
| Doc | Description |
|-----|-------------|
| **[PROJECT_STATUS.md](PROJECT_STATUS.md)** | **Master status report, metrics, and roadmap** |
| [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md) | Context-aware security implementation (70% FP reduction) |
| [PHASE_VERIFICATION_REPORT.md](PHASE_VERIFICATION_REPORT.md) | 6-phase pipeline verification report |
| [STATE_OF_THE_ART_RECOMMENDATIONS.md](STATE_OF_THE_ART_RECOMMENDATIONS.md) | Research-backed feature roadmap (15 features) |

### 📚 Guides & References
| Doc | Description |
|-----|-------------|
| [CLAUDE.md](CLAUDE.md) | AI agent context file |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | 5-minute guide |
| [docs/MULTI_AGENT_GUIDE.md](docs/MULTI_AGENT_GUIDE.md) | Multi-agent details |
| [docs/enhanced-fp-detection.md](docs/enhanced-fp-detection.md) | Enhanced false positive detection |
| [docs/deep-analysis-migration.md](docs/deep-analysis-migration.md) | Phase 2.7 Deep Analysis rollout guide |
| [DEEP_ANALYSIS_EXAMPLES.md](DEEP_ANALYSIS_EXAMPLES.md) | Phase 2.7 usage examples |
| [DAST_MVP_DELIVERY_SUMMARY.md](DAST_MVP_DELIVERY_SUMMARY.md) | DAST integration guide |
| [CHAINING_QUICKSTART.md](CHAINING_QUICKSTART.md) | Vulnerability chaining guide |
| [docs/DOCKER_TESTING_GUIDE.md](docs/DOCKER_TESTING_GUIDE.md) | Docker deployment |
| [docs/FAQ.md](docs/FAQ.md) | Common questions |

---

## Contributing

```bash
git clone https://github.com/devatsecure/Argus-Security.git
cd Argus-Security
pip install -r requirements.txt -r requirements-dev.txt
pytest tests/
```

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Acknowledgments

Built on: TruffleHog, Semgrep, Trivy, Checkov, Claude (Anthropic), OpenAI, Ollama, OPA

---

<div align="center">

**Argus Security** — Enterprise-grade AI Security Platform

[Quick Start](#quick-start) · [Docker](#docker) · [Documentation](docs/) · [Issues](https://github.com/devatsecure/Argus-Security/issues)

</div>
