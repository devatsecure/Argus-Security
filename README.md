# Argus Security

**AI-powered security pipeline that orchestrates scanners, triages findings with LLMs, and cuts false positives by 60-70%.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![AI-Powered](https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI%20%7C%20Ollama-blue.svg)](#ai-providers)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](#docker)
[![Scanners](https://img.shields.io/badge/Scanners-5%20integrated-green.svg)](#scanners)
[![Enrichment](https://img.shields.io/badge/Enrichment-20%2B%20modules-purple.svg)](#enrichment-features)

---

## The Problem

Traditional security scanners generate hundreds of findings. Most are noise. Teams waste hours triaging, miss real issues buried in false positives, and get zero actionable remediation guidance.

## How Argus Solves It

Argus runs **5 scanners in parallel**, then passes findings through **AI-powered triage** with **5 specialized agent personas** that debate severity, filter false positives, and generate fix suggestions.

| Before Argus | After Argus |
|--------------|-------------|
| 500+ raw findings, mostly noise | 60-70% false positive reduction |
| Scanners miss logic bugs | +15-20% more findings via heuristic + AI discovery |
| Manual triage takes hours | Automated multi-agent analysis in minutes |
| No fix guidance | AI-generated remediation + compliance mapping |
| Point-in-time scans | Persistent findings store with regression detection |

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
docker build -f Dockerfile.complete -t argus:complete .
docker run -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY="your-key" \
  argus:complete /workspace
```

<details>
<summary>With Docker-in-Docker (Phase 4 sandbox validation)</summary>

```bash
docker run -v $(pwd):/workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add $(stat -c '%g' /var/run/docker.sock) \
  -e ANTHROPIC_API_KEY="your-key" \
  argus:complete /workspace
```
</details>

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
  ├── Semgrep         SAST with 2000+ rules
  ├── Trivy           CVE and dependency scanning
  ├── Checkov         IaC security (Terraform, K8s, CloudFormation)
  ├── TruffleHog      Verified secret detection (API-confirmed)
  ├── Gitleaks        Pattern-based secret detection
  ├── Nuclei          Source-aware DAST template analysis
  └── ZAP Baseline    Passive security checks (opt-in)

Phase 2: AI Enrichment (2-5 min)
  ├── Claude/OpenAI/Ollama triage with noise scoring
  ├── CWE mapping and risk scoring
  ├── Heuristic discovery (regex pattern matching)
  └── IRIS semantic analysis (arXiv 2405.17238)

Phase 3: Multi-Agent Review
  ├── SecretHunter           Secret validation specialist
  ├── ArchitectureReviewer   Design flaw detection
  ├── ExploitAssessor        Exploitability analysis
  ├── FalsePositiveFilter    Noise elimination
  ├── ThreatModeler          Attack surface mapping
  └── Collaborative reasoning with multi-agent debate

Phase 4: Sandbox Validation
  ├── Docker-based exploit verification
  └── LLM-generated PoC exploits (opt-in)

Phase 5: Policy Gates
  └── Rego/OPA enforcement — block verified secrets + critical CVEs

Phase 6: Reporting
  ├── SARIF (GitHub Code Scanning integration)
  ├── JSON (programmatic access)
  └── Markdown (PR comments)
```

### Two Orchestrators

| Orchestrator | Use Case | What Runs |
|-------------|----------|-----------|
| `run_ai_audit.py` | Fast AI code review (GitHub Action default) | Semgrep + heuristics + 2-3 LLM calls |
| `hybrid_analyzer.py` | Full 6-phase pipeline (Docker default) | All scanners + full enrichment pipeline |

---

## Scanners

5 scanners are fully wired and run in parallel during Phase 1:

| Scanner | Detection Type | Default |
|---------|---------------|---------|
| **Semgrep** | SAST — code patterns, injection flaws, auth issues | On |
| **Trivy** | SCA — CVEs, outdated dependencies, license risks | On |
| **Checkov** | IaC — Terraform, K8s, CloudFormation misconfigs | On |
| **TruffleHog** | Secrets — API-verified credential detection | On |
| **Gitleaks** | Secrets — pattern-based detection (complements TruffleHog) | On |

Optional DAST scanners (require target URL or binary):

| Scanner | Detection Type | Default |
|---------|---------------|---------|
| **Nuclei** | Source-aware DAST template analysis | On |
| **ZAP Baseline** | Passive security header/config checks | Off |
| **DAST Orchestrator** | Coordinated Nuclei + ZAP scanning | Off |

---

## Enrichment Features

These modules enrich findings after scanner results are collected. All are wired into `hybrid_analyzer.py` and toggled via config/env vars.

| Feature | Config Key | Default | What It Does |
|---------|-----------|---------|--------------|
| EPSS Scoring | `enable_epss_scoring` | On | FIRST.org exploit probability scores (24h cache, batch 100) |
| Fix Version Tracking | `enable_fix_version_tracking` | On | Semver upgrade paths — PATCH/MINOR/MAJOR effort classification |
| VEX Support | `enable_vex` | On | OpenVEX, CycloneDX, CSAF document parsing |
| Vuln Deduplication | `enable_vuln_deduplication` | On | Cross-scanner merge via {VulnID, Pkg, Version, Path} |
| Advanced Suppression | `enable_advanced_suppression` | On | `.argus-ignore.yml` with time-based expiration, path globs, CWE match |
| Compliance Mapping | `enable_compliance_mapping` | On | NIST 800-53, PCI DSS 4.0, OWASP Top 10, SOC 2, ISO 27001 |
| License Risk Scoring | `enable_license_risk_scoring` | On | 5-tier SPDX classification (32 identifiers) |
| Heuristic Scanner | `enable_heuristics` | On | Pre-LLM regex pattern matching for findings beyond scanner rules |
| Phase Gating | `enable_phase_gating` | On | Schema validation between pipeline phases |
| Smart Retry | `enable_smart_retry` | On | Classified retry strategies per error type |
| Audit Trail | `enable_audit_trail` | On | Per-agent cost/duration tracking, session.json |
| Parallel Agents | `enable_parallel_agents` | On | Quality agents run concurrently (~60% faster Phase 3) |
| IRIS Semantic Analysis | `enable_iris` | On | Research-proven semantic analysis (arXiv 2405.17238) |
| Collaborative Reasoning | `enable_collaborative_reasoning` | On | Multi-agent debate for contested findings |
| Deep Analysis | `deep_analysis_mode` | off | AISLE-inspired semantic analysis (off/semantic-only/conservative/full) |
| Proof-by-Exploitation | `enable_proof_by_exploitation` | Off | LLM-generated PoCs validated in Docker sandbox |
| MCP Server | `enable_mcp_server` | Off | Expose Argus as MCP tools for Claude Code |
| Temporal Orchestration | `enable_temporal` | Off | Durable workflow wrapping for crash recovery |
| Skills Knowledge | `enable_skills_knowledge` | On | Inject 734 cybersecurity runbooks as context into Phase 3 agent prompts (auto-discovers repo) |

### Continuous Security (v3.0)

| Feature | Config Key | Default | What It Does |
|---------|-----------|---------|--------------|
| Diff-Intelligent Scoping | `enable_diff_scoping` | On | Scope scanners to changed files + blast radius expansion |
| Application Context | `enable_app_context` | On | Auto-detect framework, auth, cloud, IaC for context-aware scanning |
| Persistent Findings Store | `enable_findings_store` | On | SQLite cross-scan intelligence with regression detection and MTTF |
| Cross-Component Analysis | `enable_cross_component_analysis` | On | Detect dangerous vuln combinations across architecture boundaries |
| Agent Chain Discovery | `enable_agent_chain_discovery` | Off | LLM-powered multi-step attack chain reasoning |
| AutoFix PR Generation | `enable_autofix_pr` | Off | Generate merge-ready fix PRs with closed-loop verification |
| SAST-to-DAST Validation | `enable_live_validation` | Off | Validate SAST findings against live staging targets |

### Deployment-Triggered Scanning

- **Post-Deploy Scan** (`.github/workflows/post-deploy-scan.yml`) — Triggers on successful deployments. Runs diff-scoped SAST + DAST against the deployment URL.
- **Retest After Fix** (`.github/workflows/argus-retest.yml`) — Triggers when `argus/fix-*` branches merge. Re-scans to verify fixes hold, updates FindingsStore, posts results as PR comments.

### Cybersecurity Skills Knowledge

Integrates 734 cybersecurity runbooks from [Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) as additional context for Phase 3 agent personas. When an agent analyzes a finding, matching skills (selected by CWE, tags, and keyword scoring) are injected into the LLM prompt — giving agents expert procedures, verification steps, and tool-specific workflows.

**On by default.** Auto-discovers the repo in sibling directories, `~/Repos/`, or home directory. Just clone it nearby:

```bash
# Clone next to Argus-Security — auto-discovered, no config needed
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git

# Or set the path explicitly
export ARGUS_SKILLS_REPO_PATH=/path/to/Anthropic-Cybersecurity-Skills
```

Skills coverage: web-security, cloud-security, malware-analysis, incident-response, threat-hunting, container-security, identity-access-management, cryptography, and 15+ more subdomains.

---

## Audited Projects

Argus has been used to scan real-world open-source projects. Table ordered by GitHub stars (descending).

| Repo | Findings | Key Issues |
|------|----------|------------|
| **affaan-m/everything-claude-code** | 3 Critical | Command injection (CWE-78) in `utils.js` — `commandExists()` and `runCommand()` using unsanitized `execSync` with user-controlled input |
| **thedotmack/claude-mem** | 8 (2 Critical, 4 High) | SQL injection (dynamic query), path traversal in ObservationCompiler; command injection in ProcessManager, ReDoS in tag-stripping, missing auth on admin endpoints, resource exhaustion in token calculator |
| **KeygraphHQ/shannon** | 18 (5 Critical, 7 High) | Command injection in tool filtering, path traversal in save-deliverable, weak TOTP validation, secret exposure in error logs, prototype pollution via YAML parsing; dangerous patterns, TOCTOU in queue validation |
| **anthropics/chrome-devtools-mcp** | 1 (medium) | Missing security headers |
| **DVWA** | Full pentest | Comprehensive vulnerability assessment |
| **juice-shop/juice-shop** | 1 (high) | Unquoted XSS attribute in template |
| **MoonshotAI/kimi-cli** | 35 (5 high) | IDOR on session endpoints, 7 dependency CVEs |
| **OpenBMB/UltraRAG** | 31 (7 Critical, 11 High) | SQL/NoSQL injection in Milvus backend, path traversal in corpus builders, SSTI in Jinja2 prompts, command injection risk, SHA-1 usage, debug mode in production; missing auth on MCP, rate limiting, unsafe deserialization |

Reports include SARIF, JSON, Markdown, and responsible disclosure templates.

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
export ENABLE_TRUFFLEHOG=true
export ENABLE_GITLEAKS=true

# Feature toggles (all boolean)
export ENABLE_EPSS_SCORING=true
export ENABLE_VEX=true
export ENABLE_VULN_DEDUPLICATION=true
export ENABLE_ADVANCED_SUPPRESSION=true
export ENABLE_COMPLIANCE_MAPPING=true
export ENABLE_LICENSE_RISK_SCORING=true

# Continuous security (v3.0)
export ENABLE_DIFF_SCOPING=true
export ENABLE_APP_CONTEXT=true
export ENABLE_FINDINGS_STORE=true
export ENABLE_CROSS_COMPONENT_ANALYSIS=true
export ENABLE_AGENT_CHAIN_DISCOVERY=false    # opt-in, uses AI credits
export ENABLE_AUTOFIX_PR=false               # opt-in
export ENABLE_LIVE_VALIDATION=false          # opt-in, requires staging target

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

<details>
<summary>Full Pipeline Example</summary>

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    pipeline-mode: full
    enable-multi-agent: 'true'
    deep-analysis-mode: conservative
    fail-on-blockers: 'true'
```
</details>

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

## CLI

| Command | Purpose |
|---------|---------|
| `python scripts/run_ai_audit.py [path] [type]` | Fast AI code review |
| `python scripts/hybrid_analyzer.py [path]` | Full 6-phase pipeline |
| `./scripts/argus gate --stage pr --input findings.json` | Apply policy gate |
| `./scripts/argus feedback record <id> --mark fp` | Record false positive |

---

## Performance

| Metric | Fast Mode | Full Pipeline |
|--------|-----------|---------------|
| Scan Time | 30-90 seconds | 3-5 minutes (first run) |
| AI Calls | 2-3 LLM calls | Full enrichment + multi-agent |
| False Positive Reduction | Basic | 60-70% |
| Additional Findings | Heuristic only | +15-20% (heuristic + AI) |
| Cost per Scan | ~$0.10 | ~$0.35 (Claude) |

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
| [docs/CONTINUOUS_SECURITY_TESTING_GUIDE.md](docs/CONTINUOUS_SECURITY_TESTING_GUIDE.md) | Continuous security testing architecture |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

---

## License

MIT License -- see [LICENSE](LICENSE)

---

**Argus Security** -- AI-powered security pipeline for real-world vulnerability detection.

[Quick Start](#quick-start) | [Pipeline](#6-phase-pipeline) | [Scanners](#scanners) | [Configuration](#configuration) | [Audited Projects](#audited-projects)
