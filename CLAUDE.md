# CLAUDE.md - Argus Security

> Enterprise-grade AI Security Platform with 6-phase analysis pipeline.

## What This Does

Argus Security runs a **6-phase security pipeline** that combines traditional scanners with Claude AI-powered triage:

```
Phase 1: Scanner Orchestration    → TruffleHog, Gitleaks, Semgrep, Trivy, Checkov
Phase 2: AI Enrichment            → Claude/OpenAI analysis, noise scoring, CWE mapping
Phase 3: Multi-Agent Review       → 5 specialized AI personas analyze findings
Phase 4: Sandbox Validation       → Docker-based exploit verification
Phase 5: Policy Gates             → Rego/OPA pass/fail enforcement
Phase 6: Reporting                → SARIF, JSON, Markdown outputs
```

**Results:** 60-70% false positive reduction, +15-20% more findings via spontaneous discovery.

---

## Quick Start

```bash
# Install
git clone https://github.com/devatsecure/Argus-Security
cd Argus-Security && pip install -r requirements.txt
export ANTHROPIC_API_KEY="your-key"

# Run full 6-phase audit
python scripts/run_ai_audit.py --project-type backend-api
```

---

## Commands for Claude Code

| Command | Purpose |
|---------|---------|
| `python scripts/run_ai_audit.py --project-type backend-api` | Full 6-phase security audit |
| `./scripts/argus gate --stage pr --input findings.json` | Apply policy gate |
| `./scripts/argus feedback record <id> --mark fp` | Record false positive feedback |
| `pytest -v --cov=scripts` | Run tests |

---

## 6-Phase Pipeline Details

### Phase 1: Scanner Orchestration (30-60 sec)
Runs 5 scanners in parallel:
- **Semgrep** - SAST with 2000+ rules
- **Trivy** - CVE/dependency scanning
- **Checkov** - IaC security (Terraform, K8s)
- **TruffleHog** - Verified secret detection
- **Gitleaks** - Pattern-based secrets

### Phase 2: AI Enrichment (2-5 min)
- Claude/OpenAI/Ollama triage
- Noise scoring & false positive prediction
- CWE mapping & risk scoring

### Phase 3: Multi-Agent Review
5 specialized AI personas run with **parallel execution** for quality agents:
- Security agents run sequentially (context dependencies)
- Quality agents (performance, testing, quality) run in parallel via `ThreadPoolExecutor`
- Toggle: `enable_parallel_agents=True`, `parallel_agent_workers=3`

### Phase 4: Sandbox Validation + Proof-by-Exploitation
Docker-based exploit verification with LLM-powered PoC generation:
- `ExploitGenerator`: Uses LLM to generate targeted exploit code from findings
- `ProofByExploitation`: Orchestrates generation + sandbox validation
- Safety blocklist prevents dangerous operations in generated exploits
- Toggle: `enable_proof_by_exploitation=False` (opt-in, uses LLM credits)

### Phase 5: Policy Gates
Rego/OPA policies enforce pass/fail:
- PR gates block verified secrets, critical CVEs
- Release gates require SBOM + signature

### Phase 6: Reporting
- **SARIF** - GitHub code scanning integration
- **JSON** - Programmatic access
- **Markdown** - PR comments

---

## Advanced Features

### Smart Retry & Error Classification
Replaces blanket retry with classified retry strategies per error type (`scripts/error_classifier.py`):
- **billing**: retryable, 60s+ backoff
- **rate_limit**: retryable, 30s+ backoff
- **auth/config**: NOT retryable (fail immediately)
- **transient**: retryable, exponential backoff with jitter
- **validation**: retryable, max 3 attempts
- Toggle: `enable_smart_retry=True`

### Per-Agent Audit Trail
Tracks per-agent cost/duration/attempts with rendered prompt archival (`scripts/audit_trail.py`):
- Atomic `session.json` writes (temp+rename)
- Append-only per-agent log files
- Phase-level cost/duration aggregation
- Toggle: `enable_audit_trail=True`

### Phase Gating
Validates phase output structure before pipeline progression (`scripts/phase_gate.py`):
- Schema validation for all 6 phases
- Strict mode (stop on failure) vs lenient mode (warn and continue)
- Toggle: `enable_phase_gating=True`, `phase_gate_strict=False`

### MCP Server
Exposes Argus capabilities as MCP tools for Claude Code (`scripts/mcp_server.py`):
- `save_finding` - Store security findings
- `get_scan_status` - Pipeline metrics
- `check_policy_gate` - Gate evaluation
- `trigger_remediation` - CWE-based remediation
- Toggle: `enable_mcp_server=False` (opt-in)

### Config-Driven DAST Auth
YAML-based auth config for authenticated DAST scanning (`scripts/dast_auth_config.py`):
- Login types: form, SSO, API, basic, bearer
- RFC 6238 TOTP generation for MFA
- Login flow variable substitution ($username, $password, $totp)
- Security validation (blocks path traversal, injection)

### Temporal Orchestration
Optional durable workflow wrapping (`scripts/temporal_orchestrator.py`):
- Crash recovery via Temporal activities
- Environment-specific retry policies (production/testing/development)
- Non-retryable error classification
- Toggle: `enable_temporal=False` (opt-in, requires `temporalio`)

### License Risk Scoring (Trivy-ported)
Classifies SBOM component licenses into 5 severity tiers (`scripts/license_risk_scorer.py`):
- Forbidden (AGPL, SSPL) -> Critical, Restricted (GPL) -> High, Reciprocal (MPL, EPL) -> Medium
- 32 SPDX identifiers in static DB, case-insensitive
- Policy violation generation (block forbidden, warn restricted)
- Toggle: `enable_license_risk_scoring=True`

### EPSS Scoring (Trivy-ported)
Fetches EPSS exploit probability scores from FIRST.org API (`scripts/epss_scorer.py`):
- Batch CVE lookups (groups of 100), 24h file cache
- Risk categories: critical (>0.5), high (>0.2), medium (>0.05), low (<=0.05)
- Graceful degradation on API failure
- Toggle: `enable_epss_scoring=True`

### Fix Version Tracking (Trivy-ported)
Extracts fix versions from Trivy output with upgrade path info (`scripts/fix_version_tracker.py`):
- Detects PATCH/MINOR/MAJOR upgrades, flags breaking changes
- Prioritizes fixes by effort (patch first, major last)
- Toggle: `enable_fix_version_tracking=True`

### VEX Support (Trivy-ported)
Parses VEX documents to filter findings as not_affected (`scripts/vex_processor.py`):
- Supports OpenVEX, CycloneDX VEX, CSAF formats
- Auto-discovers VEX docs in `.argus/vex/`
- Matches findings via CVE ID + PURL
- Toggle: `enable_vex=True`

### Vulnerability Deduplication (Trivy-ported)
Multi-level dedup across scanners (`scripts/vuln_deduplicator.py`):
- Multi-key strategy: {VulnID, PkgName, Version, Path}
- Cross-scanner merge (Semgrep + Trivy same CVE -> single finding)
- Strategies: auto, strict, standard, relaxed
- Toggle: `enable_vuln_deduplication=True`

### Advanced Suppression (Trivy-ported)
Enhanced finding suppression with `.argus-ignore.yml` (`scripts/advanced_suppression.py`):
- Match types: CVE, rule_id, PURL (wildcards), path pattern (glob), CWE, severity
- Time-based expiration with audit warnings
- VEX integration + EPSS auto-suppress (score < 0.01)
- Toggle: `enable_advanced_suppression=True`

### Compliance Mapping (Trivy-ported)
Maps findings to compliance framework controls (`scripts/compliance_mapper.py`):
- NIST 800-53, PCI DSS 4.0, OWASP Top 10 2021, SOC 2, CIS K8s, ISO 27001
- CWE-based primary mapping + category fallback
- Coverage percentage calculation, markdown report generation
- Toggle: `enable_compliance_mapping=True`

---

## Project Structure

```
Argus-Security/
├── scripts/
│   ├── run_ai_audit.py           # Main orchestrator (all 6 phases)
│   ├── error_classifier.py       # Smart retry + error classification
│   ├── audit_trail.py            # Per-agent metrics + audit logging
│   ├── phase_gate.py             # Phase output validation
│   ├── mcp_server.py             # Custom MCP server for Claude Code
│   ├── mcp_server_runner.py      # MCP server CLI entry point
│   ├── dast_auth_config.py       # DAST auth config + TOTP
│   ├── temporal_orchestrator.py  # Temporal workflow orchestration
│   ├── temporal_worker.py        # Temporal worker CLI
│   ├── license_risk_scorer.py    # SBOM license risk classification
│   ├── epss_scorer.py            # EPSS exploit probability scoring
│   ├── fix_version_tracker.py    # Fix version extraction + upgrade paths
│   ├── vex_processor.py          # VEX document parsing (OpenVEX/CycloneDX/CSAF)
│   ├── vuln_deduplicator.py      # Multi-level finding deduplication
│   ├── advanced_suppression.py   # .argus-ignore.yml suppression engine
│   ├── compliance_mapper.py      # Compliance framework mapping (NIST/PCI/OWASP/SOC2)
│   ├── heuristic_scanner.py      # Pre-LLM code scanning
│   ├── consensus_builder.py      # Multi-agent finding aggregation
│   ├── analysis_helpers.py       # Context tracking, validation, chunking
│   ├── review_metrics.py         # Observability metrics
│   ├── hybrid_analyzer.py        # Multi-scanner coordination
│   ├── agent_personas.py         # Phase 3: Multi-agent review
│   ├── sandbox_validator.py      # Phase 4: Docker validation + Proof-by-Exploitation
│   ├── remediation_engine.py     # Auto-fix generation
│   └── argus                     # CLI entry point
├── policy/rego/                  # Phase 5: OPA policies
├── profiles/                     # Config profiles (dast-authenticated.yml)
├── tests/                        # Test suite (2,200+ tests)
└── action.yml                    # GitHub Action definition
```

---

## GitHub Action

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    fail-on-blockers: true
```

---

## Docker

```bash
# Build
docker build -t argus .

# Run 6-phase audit
docker run -v $(pwd):/workspace -e ANTHROPIC_API_KEY argus --project-type backend-api
```

---

## Development

```bash
# Lint and format
ruff check scripts/ && ruff format scripts/

# Run tests
pytest -v --cov=scripts

# Type check
mypy scripts/*.py
```
