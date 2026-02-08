# CLAUDE.md - Argus Security

> Enterprise-grade AI Security Platform with 6-phase analysis pipeline.

## What This Does

Argus Security runs a **6-phase security pipeline** combining traditional scanners with Claude AI-powered triage:

```
Phase 1: Scanner Orchestration    → TruffleHog, Gitleaks, Semgrep, Trivy, Checkov
Phase 2: AI Enrichment            → Claude/OpenAI analysis, noise scoring, CWE mapping
Phase 3: Multi-Agent Review       → 5 specialized AI personas analyze findings
Phase 4: Sandbox Validation       → Docker-based exploit verification
Phase 5: Policy Gates             → Rego/OPA pass/fail enforcement
Phase 6: Reporting                → SARIF, JSON, Markdown outputs
```

**Results:** 60-70% false positive reduction, +15-20% more findings via spontaneous discovery.

## Quick Start

```bash
git clone https://github.com/devatsecure/Argus-Security
cd Argus-Security && pip install -r requirements.txt
export ANTHROPIC_API_KEY="your-key"
python scripts/run_ai_audit.py --project-type backend-api
```

## Commands

| Command | Purpose |
|---------|---------|
| `python scripts/run_ai_audit.py --project-type backend-api` | Full 6-phase security audit |
| `./scripts/argus gate --stage pr --input findings.json` | Apply policy gate |
| `./scripts/argus feedback record <id> --mark fp` | Record false positive feedback |
| `pytest -v --cov=scripts` | Run tests |
| `ruff check scripts/ && ruff format scripts/` | Lint and format |
| `mypy scripts/*.py` | Type check |

## Key Files

| File | Role |
|------|------|
| `scripts/run_ai_audit.py` | Main orchestrator (all 6 phases) |
| `scripts/hybrid_analyzer.py` | Multi-scanner coordination |
| `scripts/config_loader.py` | All configuration + env vars |
| `scripts/agent_personas.py` | Phase 3: multi-agent review |
| `scripts/sandbox_validator.py` | Phase 4: Docker validation |
| `policy/rego/` | Phase 5: OPA policies |

## Extended Documentation

Details moved to scoped rule files (auto-loaded when editing relevant files):
- `.claude/rules/pipeline.md` — 6-phase pipeline architecture
- `.claude/rules/features.md` — Advanced feature modules + config toggles
- `.claude/rules/development.md` — Docker, GitHub Action, project structure
