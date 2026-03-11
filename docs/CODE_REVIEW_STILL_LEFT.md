# Code Review — What’s Still Left

**Date:** March 2026  
**Context:** Follow-up to the audit fixes (path traversal, Ruff, test robustness, docs). This document lists **remaining** items: not yet done, or optional improvements.

---

## Already fixed (no action needed)

- **Path traversal in AutoFix** — `_apply_fix()` validates `file_path` via `validate_path_safe()`; empty and out-of-project paths rejected.
- **Ruff** — Lint and format applied across `scripts/`.
- **Fixtures doc** — `tests/fixtures/README.md`; test_remediation_fixes_apply_cleanly.py docstring states that `subprocess.run(cmd, shell=True)` appears only in fixture/file content and is never executed by the test runner.
- **Production security** — No `shell=True` with user input in production; parameterized SQL; `yaml.safe_load()` in production code.
- **validate_path_safe** — Uses `os.path.commonpath()` for portability (e.g. Windows). advanced_suppression optional `project_root` validation added.
- **Config reference** — `docs/CONFIG_REFERENCE.md` lists 47+ config keys and env vars.
- **v3 summary** — `docs/V3_CONTINUOUS_SECURITY_MODULES.md` and CLAUDE.md link diff scope, findings store, app context, autofix.
- **ADR v3** — `docs/adrs/0004-v3-continuous-security.md`.
- **HybridSecurityAnalyzer** — Scanner/feature loading extracted to `_load_scanners_and_features()`.
- **run_ai_audit** — `_run_single_path_audit()` and `_run_multi_agent_audit()` extracted; `run_audit()` delegates to them.
- **Shared SQLite helper** — `scripts/utils/db_connection.py`; audit_monitor and feedback_tracker use `with db_connection(...)` throughout.
- **Shared retry policies** — `scripts/utils/retry_policies.py`; run_ai_audit, threat_intel_enricher, dast_scanner, supply_chain_analyzer use them.
- **Scanner runner harness** — `run_scanner_guarded()` in `scripts/hybrid/scanner_runners.py`; run_semgrep, run_trivy, run_checkov, run_api_security, run_supply_chain, run_fuzzing, run_runtime_security, run_regression_testing, run_dast, run_gitleaks all use it. run_threat_intel and run_remediation are enrichment-style (return original list on exception) and can stay as-is or use a variant harness.
- **Fixture comments** — conftest and test_phase1_integration: short comments/docstrings state that fixture content written to disk is vulnerable-by-design for scanners only and must not be executed with untrusted input.
- **advanced_suppression config_path** — Optional `project_root` validation: when set, `config_path` is validated against project root via `validate_path_safe`; on failure a warning is logged and a safe default is used.
- **Unit tests** — test_autofix_pr_generator.py, test_agent_chain_discovery.py, test_findings_store.py, test_app_context_builder.py added.

---

## 1. Security (optional)

### 1.1 Test and fixture code

- **test_remediation_fixes_apply_cleanly.py** — The `subprocess.run(cmd, shell=True)` occurrences are inside **string literals** (fixture content / file content for scanners). The test runner never executes subprocess with shell=True. Docstring updated; no code change required.
- **conftest / test_phase1** — Done: comments/docstrings added that fixture content written to disk is vulnerable-by-design for scanners only and must not be executed with untrusted input.
- **advanced_suppression** — Done: optional `project_root` validation for `config_path` when set from config.

---

## 2. Architecture and code quality (remaining)

### 2.1 Done

- Scanner loader in hybrid_analyzer (`_load_scanners_and_features`).
- run_audit split (`_run_single_path_audit`, `_run_multi_agent_audit`).
- Shared db_connection and retry_policies.
- Scanner runner harness (`run_scanner_guarded`); run_semgrep, run_trivy, run_checkov, run_api_security, run_supply_chain, run_fuzzing, run_runtime_security, run_regression_testing, run_dast, run_gitleaks all migrated. run_threat_intel and run_remediation are enrichment-style and optionally can use a variant that returns the original list on exception.

### 2.2 Still optional

- **Large-file splits** — run_ai_audit, supply_chain_analyzer, audit_monitor, etc. remain single large files. Splitting by feature/phase is long-term (> 5 days).
- **Enrichment runners** — run_threat_intel and run_remediation could use a guarded variant that returns the original findings list on exception (optional).

---

## 3. Testing

- **autofix_pr_generator** — `tests/unit/test_autofix_pr_generator.py` (path validation, mocked git).
- **agent_chain_discovery** — `tests/unit/test_agent_chain_discovery.py` (mocked LLM).
- **FindingsStore** — `tests/unit/test_findings_store.py` (edge cases: empty scan, get_finding missing, fingerprint).
- **AppContextBuilder** — `tests/unit/test_app_context_builder.py` (empty dir, to_prompt_context, nonexistent path).

---

## 4. Summary table

| Category              | Done | Still left |
|-----------------------|------|------------|
| **Security (critical)** | Path traversal, path validation, fixture comments, advanced_suppression config_path | — |
| **Security (production)** | Subprocess, SQL, YAML OK | — |
| **Architecture**      | Scanner loader, run_audit split, db_connection, retry_policies, scanner harness | Large-file splits (long-term) |
| **Config / v3 docs**  | CONFIG_REFERENCE, v3 summary, ADR 0004 | — |
| **Tests**             | autofix, agent_chain, FindingsStore, AppContextBuilder | — |
| **Maintainability**   | ADR v3, shared SQLite, retry policies | — |

---

## References

- [CODE_AUDIT_REPORT.md](CODE_AUDIT_REPORT.md) — Full audit and action plan  
- [CODE_REVIEW_FINDINGS.md](CODE_REVIEW_FINDINGS.md) — Security-focused review  
- [CLAUDE.md](../CLAUDE.md) — Project overview  
- [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md) — Config keys and env vars  
- [V3_CONTINUOUS_SECURITY_MODULES.md](V3_CONTINUOUS_SECURITY_MODULES.md) — v3 module summary  
- [adrs/0004-v3-continuous-security.md](adrs/0004-v3-continuous-security.md) — ADR v3  
