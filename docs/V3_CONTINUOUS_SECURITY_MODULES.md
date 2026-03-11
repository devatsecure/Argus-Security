# Continuous Security (v3) — Module Summary

One-place overview of v3 modules. For full architecture, see [CONTINUOUS_SECURITY_TESTING_GUIDE.md](CONTINUOUS_SECURITY_TESTING_GUIDE.md).

---

## Modules

| Module | Script | Config toggles | Purpose |
|--------|--------|----------------|---------|
| **Diff-intelligent scoping** | `scripts/diff_impact_analyzer.py` | enable_diff_scoping, diff_expand_impact_radius | Scope scanners to changed files; expand blast radius (e.g. if auth middleware changed, scan all files that import it). |
| **Persistent findings store** | `scripts/findings_store.py` | enable_findings_store, findings_db_path, inject_historical_context | SQLite-backed cross-scan store; regression detection; historical context into LLM prompts. |
| **Application context** | `scripts/app_context_builder.py` | enable_app_context | Detect framework, auth, cloud, IaC; generate context string for LLM. |
| **AutoFix PR generation** | `scripts/autofix_pr_generator.py` | enable_autofix_pr, autofix_confidence_threshold, autofix_max_prs_per_scan | Generate branches/PRs from remediation suggestions; path-validated file writes. |
| **Agent chain discovery** | `scripts/agent_chain_discovery.py` | enable_agent_chain_discovery | LLM-powered multi-step attack chain discovery. |
| **Cross-component analysis** | (in agent_chain_discovery) | enable_cross_component_analysis | Detect dangerous finding combinations across boundaries. |
| **SAST-to-DAST validation** | `scripts/sast_dast_validator.py` | enable_live_validation, live_validation_environment | Validate SAST findings against live (staging) targets. |

---

## Quick links

- [CONTINUOUS_SECURITY_TESTING_GUIDE.md](CONTINUOUS_SECURITY_TESTING_GUIDE.md) — Architecture and gap analysis  
- [ADR-0004](adrs/0004-v3-continuous-security.md) — Decisions and trade-offs  
- [.claude/rules/features.md](../.claude/rules/features.md) — Feature toggles and config keys  
- [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md) — All config keys and env vars
