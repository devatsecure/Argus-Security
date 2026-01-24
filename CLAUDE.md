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
5 specialized AI personas:
- 🕵️ **SecretHunter** - Credentials expert
- 🏗️ **ArchitectureReviewer** - Design flaws
- ⚔️ **ExploitAssessor** - Exploitability analysis
- 🎯 **FalsePositiveFilter** - Noise elimination
- 🔍 **ThreatModeler** - Attack chain mapping

### Phase 4: Sandbox Validation
Docker-based exploit verification:
- Isolated container execution
- Multi-language support (Python, JS, Java, Go)
- Results: EXPLOITABLE, NOT_EXPLOITABLE, PARTIAL

### Phase 5: Policy Gates
Rego/OPA policies enforce pass/fail:
- PR gates block verified secrets, critical CVEs
- Release gates require SBOM + signature

### Phase 6: Reporting
- **SARIF** - GitHub code scanning integration
- **JSON** - Programmatic access
- **Markdown** - PR comments

---

## Project Structure

```
Argus-Security/
├── scripts/
│   ├── run_ai_audit.py       # Main orchestrator (all 6 phases)
│   ├── hybrid_analyzer.py    # Multi-scanner coordination
│   ├── agent_personas.py     # Phase 3: Multi-agent review
│   ├── sandbox_validator.py  # Phase 4: Docker validation
│   ├── remediation_engine.py # Auto-fix generation
│   └── argus                 # CLI entry point
├── policy/rego/              # Phase 5: OPA policies
├── tests/                    # Test suite
└── action.yml                # GitHub Action definition
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
