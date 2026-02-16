# Argus Security

**Enterprise-grade AI Security Platform** -- Orchestrate security scanners with AI-powered triage and multi-agent analysis.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![AI-Powered](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI%20%7C%20Ollama-blue.svg)](#ai-providers)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](#docker)

---

## What is Argus?

Argus runs a **6-phase security pipeline** that combines traditional scanners with Claude AI-powered triage, achieving **60-70% false positive reduction** and **+15-20% more findings** via heuristic-based discovery.

| Challenge | Argus Solution |
|-----------|----------------|
| Too many false positives | 60-70% reduction via AI triage + noise scoring |
| Scanners miss real issues | +15-20% findings via heuristic pattern matching |
| Manual triage takes hours | Automated multi-agent analysis with 5 AI personas |
| No actionable next steps | AI-generated fix suggestions + compliance mapping |

---

## Quick Start

### GitHub Action (Recommended)

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
          pipeline-mode: fast   # or "full" for 6-phase pipeline
```

### Docker

```bash
# Full 6-phase pipeline (Dockerfile.complete entrypoint: hybrid_analyzer.py)
docker build -f Dockerfile.complete -t argus:complete .
docker run -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY="your-key" \
  argus:complete /workspace

# With Docker-in-Docker for Phase 4 sandbox validation
docker run -v $(pwd):/workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add $(stat -c '%g' /var/run/docker.sock) \
  -e ANTHROPIC_API_KEY="your-key" \
  argus:complete /workspace
```

### Local CLI

```bash
git clone https://github.com/devatsecure/Argus-Security.git
cd Argus-Security && pip install -r requirements.txt
export ANTHROPIC_API_KEY="your-key"

# Fast AI code review (Semgrep + 2-3 LLM calls)
python scripts/run_ai_audit.py --project-type backend-api

# Full 6-phase pipeline (all scanners + AI enrichment)
python scripts/hybrid_analyzer.py /path/to/project
```

---

## 6-Phase Pipeline

```
Phase 1: Scanner Orchestration (30-60s)
  Semgrep (SAST, 2000+ rules) | Trivy (CVE/deps) | Checkov (IaC) | TruffleHog (verified secrets) | Gitleaks (pattern secrets)

Phase 2: AI Enrichment (2-5 min)
  Claude/OpenAI/Ollama triage | Noise scoring | CWE mapping | Heuristic discovery (regex)

Phase 3: Multi-Agent Review
  5 AI personas: SecretHunter, ArchitectureReviewer, ExploitAssessor, FalsePositiveFilter, ThreatModeler
  Quality agents run in parallel via ThreadPoolExecutor

Phase 4: Sandbox Validation
  Docker-based exploit verification | LLM-generated PoC exploits (opt-in)

Phase 5: Policy Gates
  Rego/OPA enforcement | PR gates block verified secrets + critical CVEs

Phase 6: Reporting
  SARIF (GitHub code scanning) | JSON | Markdown
```

### Two Orchestrators

| Orchestrator | Use Case | Scanners |
|-------------|----------|----------|
| `run_ai_audit.py` | Fast AI code review (GitHub Action default) | Semgrep + 2-3 LLM calls |
| `hybrid_analyzer.py` | Full 6-phase pipeline (Docker default) | All 5 scanners + full enrichment |

---

## Enrichment Features

All features are wired into both orchestrators and toggled via config/env vars.

| Feature | Config Key | Default | Description |
|---------|-----------|---------|-------------|
| EPSS Scoring | `enable_epss_scoring` | `True` | FIRST.org exploit probability (24h cache, batch 100) |
| Fix Version Tracking | `enable_fix_version_tracking` | `True` | Semver upgrade paths (PATCH/MINOR/MAJOR) |
| VEX Support | `enable_vex` | `True` | OpenVEX, CycloneDX, CSAF document parsing |
| Vuln Deduplication | `enable_vuln_deduplication` | `True` | Cross-scanner merge via {VulnID, Pkg, Version, Path} |
| Advanced Suppression | `enable_advanced_suppression` | `True` | `.argus-ignore.yml` with time-based expiration |
| Compliance Mapping | `enable_compliance_mapping` | `True` | NIST 800-53, PCI DSS 4.0, OWASP Top 10, SOC 2, ISO 27001 |
| License Risk Scoring | `enable_license_risk_scoring` | `True` | 5-tier SPDX classification (32 identifiers) |
| Heuristic Scanner | `enable_heuristics` | `True` | Pre-LLM regex pattern matching for extra findings |
| Phase Gating | `enable_phase_gating` | `True` | Schema validation between pipeline phases |
| Smart Retry | `enable_smart_retry` | `True` | Classified retry strategies per error type |
| Audit Trail | `enable_audit_trail` | `True` | Per-agent cost/duration tracking, session.json |
| Parallel Agents | `enable_parallel_agents` | `True` | Quality agents run concurrently (~60% faster Phase 3) |
| Deep Analysis | `deep_analysis_mode` | `off` | AISLE-inspired semantic analysis (off/semantic-only/conservative/full) |
| Proof-by-Exploitation | `enable_proof_by_exploitation` | `False` | LLM-generated PoCs in Docker sandbox (opt-in) |
| MCP Server | `enable_mcp_server` | `False` | Expose Argus as MCP tools for Claude Code |
| Temporal Orchestration | `enable_temporal` | `False` | Durable workflow wrapping for crash recovery |

---

## Configuration

### Layered Config Precedence

```
hardcoded defaults < profile YAML < .argus.yml < env vars < CLI args
```

### Environment Variables

```bash
# AI Providers (at least one required for AI features)
export ANTHROPIC_API_KEY="your-key"         # Claude (recommended)
export OPENAI_API_KEY="your-key"            # OpenAI (alternative)
export OLLAMA_ENDPOINT="http://localhost:11434"  # Ollama (free, local)

# Scanner toggles
export ENABLE_SEMGREP=true
export ENABLE_TRIVY=true
export ENABLE_CHECKOV=true
export ENABLE_GITLEAKS=true

# Feature toggles (all boolean, set "true" or "false")
export ENABLE_EPSS_SCORING=true
export ENABLE_VEX=true
export ENABLE_VULN_DEDUPLICATION=true
export ENABLE_ADVANCED_SUPPRESSION=true
export ENABLE_COMPLIANCE_MAPPING=true
export ENABLE_LICENSE_RISK_SCORING=true

# Limits
export MAX_FILES=50
export COST_LIMIT=1.0
export MAX_TOKENS=8000
```

### Config Profiles

8 built-in profiles in `profiles/`:

| Profile | Purpose |
|---------|---------|
| `standard` | Balanced defaults for most projects |
| `backend-api` | Backend/API-focused scanning |
| `frontend` | Frontend/UI-focused scanning |
| `infrastructure` | IaC and cloud config scanning |
| `deep` | Full deep analysis enabled |
| `quick` | Minimal scanning for fast feedback |
| `secrets-only` | Secret detection only (TruffleHog + Gitleaks) |
| `dast-authenticated` | DAST with auth config |

Usage: `python scripts/hybrid_analyzer.py /project --profile backend-api`

---

## GitHub Action

The Action supports two pipeline modes:

| Input | Default | Description |
|-------|---------|-------------|
| `pipeline-mode` | `fast` | `fast` (run_ai_audit.py) or `full` (hybrid_analyzer.py) |
| `anthropic-api-key` | -- | Anthropic API key for Claude |
| `openai-api-key` | -- | OpenAI API key (alternative) |
| `ai-provider` | `auto` | `anthropic`, `openai`, `ollama`, or `auto` |
| `review-type` | `audit` | `audit`, `security`, or `review` |
| `project-type` | `auto` | `backend-api`, `dashboard-ui`, `data-pipeline`, `infrastructure`, `auto` |
| `fail-on-blockers` | `true` | Fail workflow on critical/high findings |
| `enable-multi-agent` | `true` | Enable 5 AI persona analysis |
| `enable-spontaneous-discovery` | `true` | Heuristic pattern discovery |
| `enable-sandbox` | `false` | Docker sandbox validation (full mode) |
| `enable-proof-by-exploitation` | `false` | LLM PoC generation (full mode) |
| `enable-dast` | `false` | DAST scanning (requires `dast-target-url`) |
| `deep-analysis-mode` | `off` | `off`, `semantic-only`, `conservative`, `full` |
| `only-changed` | `false` | Only analyze changed files (PR mode) |
| `max-files` | `50` | Max files to analyze |
| `cost-limit` | `1.0` | Max cost in USD per run |
| `severity-filter` | -- | Comma-separated severity levels to include |

### Full Pipeline Example

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    pipeline-mode: full
    enable-multi-agent: 'true'
    deep-analysis-mode: conservative
    fail-on-blockers: 'true'
```

### Action Outputs

| Output | Description |
|--------|-------------|
| `review-completed` | Whether review completed successfully |
| `blockers-found` | Number of critical+high findings |
| `suggestions-found` | Number of medium+low findings |
| `report-path` | Path to generated report |
| `sarif-path` | Path to SARIF file for Code Scanning |
| `cost-estimate` | Estimated cost in USD |
| `total-findings` | Total findings (full mode) |
| `scanners-used` | Scanners that ran (full mode) |

---

## CLI Commands

| Command | Purpose |
|---------|---------|
| `python scripts/run_ai_audit.py [path] [type]` | Fast AI code review |
| `python scripts/hybrid_analyzer.py [path]` | Full 6-phase pipeline |
| `./scripts/argus gate --stage pr --input findings.json` | Apply policy gate |
| `./scripts/argus feedback record <id> --mark fp` | Record false positive feedback |

---

## Performance

| Metric | Value |
|--------|-------|
| Scan Time (first run) | 3-5 minutes |
| Cached Repeat | 30-90 seconds |
| False Positive Reduction | 60-70% |
| Additional Findings | +15-20% |
| Cost per Scan | ~$0.35 (Claude) |

---

## Development

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -v --cov=scripts          # Run tests
ruff check scripts/ && ruff format scripts/   # Lint and format
mypy scripts/*.py                # Type check
```

---

## Documentation

| Doc | Description |
|-----|-------------|
| [CLAUDE.md](CLAUDE.md) | AI agent context and project overview |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | 5-minute getting started guide |
| [docs/MULTI_AGENT_GUIDE.md](docs/MULTI_AGENT_GUIDE.md) | Multi-agent analysis details |
| [docs/PHASE_27_DEEP_ANALYSIS.md](docs/PHASE_27_DEEP_ANALYSIS.md) | Deep Analysis rollout guide |
| [docs/FAQ.md](docs/FAQ.md) | Common questions |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

---

## License

MIT License -- see [LICENSE](LICENSE)

---

**Argus Security** -- Enterprise-grade AI Security Platform

[Quick Start](#quick-start) | [Pipeline](#6-phase-pipeline) | [Configuration](#configuration) | [GitHub Action](#github-action) | [Documentation](#documentation)
