---
title: ADR-0004 - v3 Continuous Security (Findings Store, Diff Scoping, App Context, AutoFix)
status: Accepted
date: 2026-03
---

# ADR-0004: v3 Continuous Security

## Status

**Accepted** | Date: 2026-03

## Context

Post–Phase 6 we need:

- **Cross-scan intelligence** — Know what was fixed, what regressed, and feed history into triage.
- **Efficient rescans** — Scope to changed code and blast radius instead of full repo every time.
- **Context-aware triage** — LLM should know framework, auth, and deployment context.
- **Closed-loop remediation** — Generate fix branches/PRs from suggestions with safety (path validation, no arbitrary writes).

## Decision

Introduce **v3 continuous security** modules, all opt-in or default-on with safe defaults:

1. **Persistent findings store** — SQLite at `.argus/findings.db`; content-based fingerprinting; regression detection; optional historical context injection into Phase 2 prompts. Toggle: `enable_findings_store`, `inject_historical_context`.
2. **Diff-intelligent scoping** — Classify changed files by security relevance; expand to dependents (e.g. callers of changed auth). Drive Semgrep/scan include paths. Toggles: `enable_diff_scoping`, `diff_expand_impact_radius`.
3. **Application context builder** — Detect framework, auth, cloud, IaC; produce a context string for LLM. Toggle: `enable_app_context`.
4. **AutoFix PR generator** — Create branches and apply fixes from remediation suggestions; **path validation** so `file_path` never escapes project root. Toggles: `enable_autofix_pr`, `autofix_confidence_threshold`, `autofix_max_prs_per_scan`.
5. **Agent chain discovery** — LLM-powered attack chain discovery. Toggle: `enable_agent_chain_discovery` (opt-in, uses credits).
6. **SAST-to-DAST live validation** — Optional validation against staging; never production by default. Toggles: `enable_live_validation`, `live_validation_environment`.

## Consequences

- **Positive:** Regression visibility, faster rescans, better triage, safe autofix, optional live validation.
- **Operational:** SQLite and `.argus/` directory; config surface increases (see CONFIG_REFERENCE).
- **Security:** Path validation in AutoFix and optional `project_root` in advanced_suppression; no execution of user-controlled paths without validation.

## References

- [CONTINUOUS_SECURITY_TESTING_GUIDE.md](../CONTINUOUS_SECURITY_TESTING_GUIDE.md)
- [V3_CONTINUOUS_SECURITY_MODULES.md](../V3_CONTINUOUS_SECURITY_MODULES.md)
- [CONFIG_REFERENCE.md](../CONFIG_REFERENCE.md)
