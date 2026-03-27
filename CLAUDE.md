# CLAUDE.md - Argus Security

> Enterprise-grade AI Security Platform with 6-phase analysis pipeline and continuous autonomous security testing.

## What This Does

Argus Security runs a **6-phase security pipeline** combining traditional scanners with AI-powered triage:

```
Phase 1: Scanner Orchestration    → Semgrep, Trivy, Checkov, TruffleHog, Gitleaks (verified + pattern-based secrets)
Phase 2: AI Enrichment            → Claude/OpenAI/OpenRouter analysis, noise scoring, CWE mapping + skills knowledge context
Phase 3: Multi-Agent Review       → 5 specialized AI personas analyze findings + skills knowledge context
Phase 4: Sandbox Validation       → Docker-based exploit verification + skill-based verification commands
Phase 5: Policy Gates             → Rego/OPA pass/fail enforcement
Phase 6: Reporting                → SARIF, JSON, Markdown outputs + related skills references per finding
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
- Cybersecurity skills knowledge (734 runbooks from Anthropic-Cybersecurity-Skills, auto-discovered, used in Phase 2/3/4/6)

## AI Providers

Argus supports 5 AI providers. Set via `AI_PROVIDER` env var or `--ai-provider` CLI flag:

| Provider | Env Var | Models | Notes |
|----------|---------|--------|-------|
| **Anthropic** (default) | `ANTHROPIC_API_KEY` | Claude Sonnet 4.5, Opus 4.6, Haiku 4.5 | Best for security, auto-fallback chain |
| **OpenRouter** | `OPENROUTER_API_KEY` + `OPENROUTER_MODEL` | DeepSeek v3.2, Xiaomi MiMo v2 Pro, Qwen, 200+ models | Multi-model via single API |
| **OpenAI** | `OPENAI_API_KEY` | GPT-4 Turbo | |
| **Ollama** | `OLLAMA_ENDPOINT` | Llama 3.2, any local model | Free, local inference |
| **Claude CLI** | (uses subscription) | Via `claude` binary | Claude Code subscription |

Auto-detect priority: Anthropic > OpenAI > OpenRouter > Ollama > Claude CLI

macOS Keychain fallback: if env vars aren't set, Argus checks macOS Keychain for `anthropic-api-key`, `openai-api-key`, `openrouter-api-key`.

## Quick Start

```bash
git clone https://github.com/devatsecure/Argus-Security
cd Argus-Security && pip install -r requirements.txt
# Pick one provider:
export ANTHROPIC_API_KEY="your-key"
# Or: export OPENROUTER_API_KEY="your-key" OPENROUTER_MODEL="deepseek/deepseek-v3.2"
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
| `scripts/skills_knowledge.py` | Skills knowledge: index loading, matching, content injection, runbook extraction (734 skills, used in Phase 2/3/4/6) |
| `scripts/sandbox_validator.py` | Phase 4: Docker validation |
| `policy/rego/` | Phase 5: OPA policies |
| `scripts/diff_impact_analyzer.py` | v3.0: Diff-intelligent scanner scoping |
| `scripts/findings_store.py` | v3.0: SQLite persistent findings store |
| `scripts/app_context_builder.py` | v3.0: Application context auto-detection |
| `scripts/agent_chain_discovery.py` | v3.0: LLM attack chain discovery |
| `scripts/autofix_pr_generator.py` | v3.0: AutoFix PR generation + closed loop |
| `scripts/sast_dast_validator.py` | v3.0: SAST-to-DAST live validation |
| `scripts/orchestrator/llm_manager.py` | Unified LLM provider management (Anthropic, OpenAI, OpenRouter, Ollama, Claude CLI) |

## Docker (ARM64 native)

```bash
# Build native ARM64 image (all 7 scanners + AI SDKs)
docker build -f Dockerfile.complete -t argus-complete .

# Run full 6-phase scan with OpenRouter/DeepSeek
docker run --rm \
  -v /path/to/target:/workspace \
  -v /path/to/output:/output \
  -v ~/.docker/run/docker.sock:/var/run/docker.sock --group-add 0 \
  -e OPENROUTER_API_KEY="your-key" -e AI_PROVIDER=openrouter \
  argus-complete /workspace --output-dir /output
```

Dockerfile.complete is multi-arch (ARM64 + AMD64) via `TARGETARCH` for all binary downloads.

## Extended Documentation

Details moved to scoped rule files (auto-loaded when editing relevant files):
- `.claude/rules/pipeline.md` — 6-phase pipeline architecture
- `.claude/rules/features.md` — Advanced feature modules + config toggles (incl. v3.0)
- `.claude/rules/development.md` — Docker, GitHub Action, project structure
- `docs/CONTINUOUS_SECURITY_TESTING_GUIDE.md` — v3.0 architecture and gap analysis
- `docs/V3_CONTINUOUS_SECURITY_MODULES.md` — v3 module summary (diff scope, findings store, app context, autofix)
- `docs/adrs/0004-v3-continuous-security.md` — ADR for v3 findings store / continuous security
- `docs/CONFIG_REFERENCE.md` — All 49+ config keys and env vars
