# Code Audit Report — Argus Security

**Audit date:** March 2026  
**Scope:** Full codebase (architecture, code quality, security, performance, testing, maintainability)  
**Reference:** [CLAUDE.md](../CLAUDE.md), [.claude/rules/features.md](../.claude/rules/features.md), Code Auditor skill.

---

## Executive Summary

| Metric | Value |
|--------|--------|
| **Overall health score** | 7/10 (Good, with focused improvements) |
| **Critical issues** | 1 (path traversal in AutoFix) |
| **High-priority issues** | 4 (complexity, test/fixture safety, path validation) |
| **Medium-priority issues** | 6 (refactors, duplication, docs, lint) |

**Top 3 priorities**

1. **Fix path traversal in AutoFix** — `scripts/autofix_pr_generator.py` `_apply_fix()`: validate `file_path` against project root before any read/write (use `utils/io.validate_path_safe`).
2. **Reduce god-files and init complexity** — Split `run_ai_audit.py` (~2030 LOC) and `hybrid_analyzer.py` init (~480 lines of scanner/feature loading) into smaller modules or loader helpers.
3. **Harden test/fixture code** — Ensure `shell=True` and `yaml.load()` in tests/fixtures are never executed with untrusted input; prefer list-args and `yaml.safe_load` in test code that runs in CI.

---

## Findings by Category

### Architecture & Design

#### High priority

- **HybridSecurityAnalyzer.__init__ is a 480+ line feature loader**  
  **Location:** `scripts/hybrid_analyzer.py` ~324–720  
  **Impact:** Repeated “try import → set self.*_scanner or disable” for 20+ components; hard to test and extend.  
  **Recommendation:** Extract a `_load_scanners()` / `_load_optional_features()` helper or a small `scanner_loader` module that returns a dict of enabled components; keep `__init__` thin.

- **run_ai_audit.run_audit() branches heavily**  
  **Location:** `scripts/run_ai_audit.py` ~1767–2017  
  **Impact:** Multi-agent vs single-path, deep analysis, phase gates, cost checks all in one function; high cognitive load and regression risk.  
  **Recommendation:** Extract `_run_single_path_audit()` and `_run_multi_agent_audit()` and call from `run_audit()` after a single branching point.

#### Medium priority

- **No single config reference doc**  
  **Impact:** 47+ keys live in `config_loader.get_default_config()`; new contributors must read code to discover toggles.  
  **Recommendation:** Add `docs/CONFIG_REFERENCE.md` (or a section in QUICKSTART) generated from or listing all default keys and env vars.

- **v3.0 modules not summarized in one place**  
  **Impact:** Diff scope, findings store, app context, autofix are documented in multiple places; no single “v3 modules” entry.  
  **Recommendation:** Add a short “Continuous Security (v3) modules” section to CLAUDE.md or CONTINUOUS_SECURITY_TESTING_GUIDE that links to each module.

---

### Code Quality

#### High priority

- **Many files over 500 lines (complexity hotspots)**  
  **Locations (largest first):**  
  - `scripts/run_ai_audit.py` ~2030  
  - `scripts/supply_chain_analyzer.py` ~1807  
  - `scripts/audit_monitor.py` ~1445  
  - `scripts/hybrid_analyzer.py` ~1440  
  - `scripts/feedback_tracker.py` ~1139  
  - `scripts/agent_personas.py` ~1194  
  - `scripts/spontaneous_discovery.py` ~1200  
  - `scripts/zap_baseline_scanner.py` ~1228  
  - `scripts/fuzzing_engine.py` ~1299  
  - `scripts/api_security_scanner.py` ~1318  
  - `scripts/heuristic_scanner.py` ~1035  
  - `scripts/remediation_engine.py` ~1066  
  - `scripts/pairwise_comparison.py` ~1050  
  **Impact:** Maintainability and defect risk; refactors are higher effort.  
  **Recommendation:** Prioritize splitting `run_ai_audit.py` and `supply_chain_analyzer.py`; introduce boundaries by feature or phase.

#### Medium priority

- **Duplication: scanner init and runner pattern**  
  **Locations:**  
  - `scripts/hybrid/scanner_runners.py`: each `run_*` (Semgrep, Trivy, Checkov, Gitleaks, …) follows the same shape (get scanner, run, convert to HybridFinding, handle exceptions).  
  **Recommendation:** Consider a small runner harness + per-scanner adapters to reduce copy-paste.

- **Duplication: SQLite open/execute in audit_monitor and feedback_tracker**  
  **Locations:** `scripts/audit_monitor.py`, `scripts/feedback_tracker.py` — repeated “conn = sqlite3.connect(...); cursor = conn.cursor(); execute; commit; close” (or similar).  
  **Recommendation:** Introduce a shared context manager or helper (e.g. `with db_connection(path) as cur`) and standardize WAL/row_factory if desired.

- **Ruff lint issues (12 reported)**  
  **Locations:** Unused imports (e.g. `agent_chain_discovery.py:28`, `sast_dast_validator.py:28,36,37`, `hybrid_analyzer.py:156`); unnecessary mode `"r"` (`autofix_pr_generator.py:337`); f-strings without placeholders (`autofix_pr_generator.py:462–463`); return condition simplification (`autofix_pr_generator.py:847`); import sort (`epss_scorer.py:23`); N817 camelCase (`zap_baseline_scanner.py:32`); unused variable (`sast_dast_validator.py:434`).  
  **Recommendation:** Run `ruff check scripts --fix` and address remaining items; keep in CI.

---

### Security

#### Critical

- **Path traversal in AutoFix PR generator**  
  **Location:** `scripts/autofix_pr_generator.py` — `_apply_fix()` lines 333–358  
  **Impact:** `file_path` from suggestion dict is joined with `self.project_path` and used for read/write without ensuring the resolved path stays under the project root. A malicious or bad `file_path` (e.g. `"../../../etc/passwd"`) could read or overwrite files outside the repo when AutoFix is enabled.  
  **Recommendation:** Before any `open()` or `Path()` use, resolve and validate with `scripts/utils/io.py::validate_path_safe(file_path, base_dir=Path(project_path).resolve())`; reject (return `False` or raise) if validation fails.  
  **Reference:** [CODE_REVIEW_FINDINGS.md](CODE_REVIEW_FINDINGS.md).

#### High priority

- **Test/fixture code uses shell=True and unsafe YAML**  
  **Locations:**  
  - `tests/integration/conftest.py` 76–77: `subprocess.call("bash " + script_name, shell=True)` — fixture content; ensure script_name is never from untrusted input.  
  - `tests/integration/test_remediation_fixes_apply_cleanly.py` 53, 329: `subprocess.run(cmd, shell=True)` in test code.  
  - `tests/integration/test_phase1_integration.py` 67: `subprocess.call("bash " + script_name, shell=True)`.  
  - conftest fixture content uses `yaml.load(yaml_str)` without Loader (unsafe if that code were ever executed with untrusted YAML).  
  **Impact:** If any test or fixture ever ran with user-controlled input, risk of command injection or deserialization.  
  **Recommendation:** (1) Use list-based subprocess calls in test code where possible; (2) ensure script_name and YAML in fixtures are fixed test data only; (3) document that vulnerable_app and fixture content are intentionally vulnerable for scanner tests and must not be used as a library with untrusted input.

#### Medium priority (positive)

- **Production subprocess usage:** No `shell=True` with user input; list args and `shell=False` used (e.g. `subprocess_utils.run_command_safe`, trufflehog, gitleaks, preflight_checker).  
- **Production YAML:** `yaml.safe_load()` used in config_loader, dast_auth_config, health_check, advanced_suppression.  
- **Production SQL:** findings_store, feedback_tracker, audit_monitor use parameterized queries.  
- **Secrets:** API keys from env/config; log sanitization in logging_utils and subprocess_utils.

---

### Performance

#### Medium priority

- **No shared retry policy**  
  **Location:** Multiple scripts (e.g. run_ai_audit, dast_scanner) use tenacity with local decorators.  
  **Recommendation:** Centralize in `scripts/utils/retry_policies.py` (e.g. by error type: billing, rate_limit, transient) for consistency and easier tuning.

- **EPSS/cache and FindingsStore**  
  **Location:** `scripts/epss_scorer.py` (24h cache), `scripts/findings_store.py` (SQLite with WAL).  
  **Impact:** Already reasonable; no critical performance issues identified. Optional: add simple metrics for DB query times if regressions appear.

---

### Testing

#### High priority

- **autofix_pr_generator has no dedicated test file**  
  **Impact:** High-value target (git commands, path handling, PR creation); only indirect coverage via hybrid pipeline.  
  **Recommendation:** Add `tests/unit/test_autofix_pr_generator.py` with unit tests for `_apply_fix` (including path validation), branch creation, and error handling (no real git required for all cases; mock or temp repos).

- **agent_chain_discovery has no dedicated test file**  
  **Impact:** Coverage only if exercised via hybrid path.  
  **Recommendation:** Add `tests/unit/test_agent_chain_discovery.py` for chain discovery and cross-component logic (with mocks for LLM).

#### Medium priority

- **FindingsStore / AppContextBuilder**  
  **Location:** Covered in `tests/test_continuous_security.py` and `tests/unit/test_mcp_server.py`; no dedicated `test_findings_store.py` or `test_app_context_builder.py`.  
  **Recommendation:** Optional dedicated unit tests for clearer ownership and edge cases.

- **Fixtures documentation**  
  **Impact:** `tests/fixtures/` contains vulnerable_app, scanner_outputs, python_cli, web_app; no central doc of which fixture is for which test type.  
  **Recommendation:** Add a short `tests/fixtures/README.md` describing each fixture and that vulnerable_app is intentionally vulnerable for scanner tests only.

---

### Maintainability

#### Medium priority

- **ADR gap for v3**  
  **Location:** `docs/adrs/` has 0002 (multi-scanner), 0003 (AI triage); no ADR for v3 continuous security or findings store.  
  **Recommendation:** Add ADR for “Persistent findings store and continuous security (v3)” to record decisions and trade-offs.

- **Onboarding**  
  **Impact:** Architecture and pipeline are documented (CLAUDE.md, pipeline.md, CONTINUOUS_SECURITY_TESTING_GUIDE); config reference and v3 summary would shorten onboarding.

---

## Prioritized Action Plan

### Quick wins (< 1 day)

1. **Fix path traversal in AutoFix** — Add `validate_path_safe()` in `autofix_pr_generator._apply_fix()` before any file I/O; reject paths outside project root.  
2. **Fix ruff issues** — Run `ruff check scripts --fix` and fix remaining 12 items (unused imports, mode, f-strings, SIM103, import sort, N817, unused variable).  
3. **Document fixtures** — Add `tests/fixtures/README.md` stating purpose of each fixture and that vulnerable_app is for scanner tests only.

### Medium-term (1–5 days)

4. **Extract scanner/feature loader** — Move hybrid_analyzer init logic for scanners and optional features into a `_load_scanners()` / loader helper or small module.  
5. **Add unit tests for autofix_pr_generator** — Path validation, branch/commit behavior, error handling (mocked git where needed).  
6. **Replace shell=True in test code** — In `test_remediation_fixes_apply_cleanly.py` and integration conftest/phase1, use list-args subprocess where possible; document that remaining uses are fixed test data only.  
7. **Add config reference** — Single doc (or section) listing all config keys and env vars (from get_default_config and env mapping).

### Long-term (> 5 days)

8. **Split run_ai_audit.py** — Extract `_run_single_path_audit()` and `_run_multi_agent_audit()`; reduce `run_audit()` to a single branch point and delegation.  
9. **Split supply_chain_analyzer.py** — Introduce submodules or feature-boundary files to bring the largest script below ~800 LOC per file.  
10. **Shared SQLite helper and retry policies** — `with db_connection(path)` for audit_monitor/feedback_tracker; `scripts/utils/retry_policies.py` for tenacity.  
11. **ADR for v3** — Document decisions for findings store and continuous security features.

---

## Metrics

| Metric | Value |
|--------|--------|
| **Python files (scripts)** | 143 |
| **Total lines (scripts)** | ~74,400 (incl. hybrid/, orchestrator/, etc.) |
| **Test files** | 147 (unit, integration, security_regression, fixtures) |
| **Largest files** | run_ai_audit.py 2030, supply_chain_analyzer.py 1807, audit_monitor.py 1445, hybrid_analyzer.py 1440 |
| **Ruff errors (scripts)** | 12 (8 fixable with --fix) |
| **Test coverage** | Run `pytest --cov=scripts` in CI for current % (audit did not wait for full run) |
| **Complexity hotspots** | hybrid_analyzer __init__, run_ai_audit run_audit, supply_chain_analyzer, audit_monitor, feedback_tracker |

---

## References

- [CLAUDE.md](../CLAUDE.md) — Project overview and key files  
- [CODE_REVIEW_FINDINGS.md](CODE_REVIEW_FINDINGS.md) — Security-focused code review (path traversal, subprocess, SQL, YAML)  
- [.claude/rules/features.md](../.claude/rules/features.md) — Feature toggles and modules  
- [docs/CONTINUOUS_SECURITY_TESTING_GUIDE.md](CONTINUOUS_SECURITY_TESTING_GUIDE.md) — v3 architecture  
- [scripts/utils/io.py](../scripts/utils/io.py) — `validate_path_safe()`
