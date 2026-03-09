# CLAUDE.md - Argus Security

> Enterprise-grade AI Security Platform with 6-phase analysis pipeline and continuous autonomous security testing.

## What This Does

Argus Security runs a **6-phase security pipeline** combining traditional scanners with Claude AI-powered triage:

```
Phase 1: Scanner Orchestration    → Semgrep, Trivy, Checkov, TruffleHog, Gitleaks (verified + pattern-based secrets)
Phase 2: AI Enrichment            → Claude/OpenAI analysis, noise scoring, CWE mapping
Phase 3: Multi-Agent Review       → 5 specialized AI personas analyze findings
Phase 4: Sandbox Validation       → Docker-based exploit verification
Phase 5: Policy Gates             → Rego/OPA pass/fail enforcement
Phase 6: Reporting                → SARIF, JSON, Markdown outputs
```

**Results:** 60-70% false positive reduction, +15-20% more findings via heuristic-based spontaneous discovery (regex pattern matching, not AI-powered).

**v3.0 Continuous Security:**
- Diff-intelligent scanner scoping with blast radius expansion
- Persistent cross-scan findings store with regression detection
- Application context auto-detection for context-aware scanning
- LLM-powered attack chain discovery + cross-component analysis
- AutoFix PR generation with closed-loop find-fix-verify
- SAST-to-DAST live validation against staging targets
- Deployment-triggered scanning via GitHub Actions workflows

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
| `scripts/hybrid_analyzer.py` | Full 6-phase pipeline orchestrator (Docker entrypoint) |
| `scripts/run_ai_audit.py` | Fast AI code review (Semgrep + 2-3 LLM calls, GitHub Action) |
| `scripts/config_loader.py` | All configuration + env vars |
| `scripts/agent_personas.py` | Phase 3: multi-agent review |
| `scripts/sandbox_validator.py` | Phase 4: Docker validation |
| `policy/rego/` | Phase 5: OPA policies |
| `scripts/diff_impact_analyzer.py` | v3.0: Diff-intelligent scanner scoping |
| `scripts/findings_store.py` | v3.0: SQLite persistent findings store |
| `scripts/app_context_builder.py` | v3.0: Application context auto-detection |
| `scripts/agent_chain_discovery.py` | v3.0: LLM attack chain discovery |
| `scripts/autofix_pr_generator.py` | v3.0: AutoFix PR generation + closed loop |
| `scripts/sast_dast_validator.py` | v3.0: SAST-to-DAST live validation |

## Extended Documentation

Details moved to scoped rule files (auto-loaded when editing relevant files):
- `.claude/rules/pipeline.md` — 6-phase pipeline architecture
- `.claude/rules/features.md` — Advanced feature modules + config toggles (incl. v3.0)
- `.claude/rules/development.md` — Docker, GitHub Action, project structure
- `docs/CONTINUOUS_SECURITY_TESTING_GUIDE.md` — v3.0 architecture and gap analysis
