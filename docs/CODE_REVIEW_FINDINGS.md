# Code Review Findings — Argus Security

**Review date:** 2026-03  
**Scope:** Full codebase (scripts/, config, pipeline).  
**Reference:** [CLAUDE.md](CLAUDE.md), [.claude/rules/features.md](.claude/rules/features.md).

---

## Summary

| Severity | Count |
|----------|--------|
| High     | 1     |
| Medium   | 0     |
| Low / Info | 2   |

**Overall:** One high-severity issue (path traversal in AutoFix); otherwise the codebase follows secure patterns (no `shell=True` with user input, parameterized SQL, `yaml.safe_load`, log sanitization).

---

## High severity

### 1. Path traversal in AutoFix PR generator when applying fixes

**File:** `scripts/autofix_pr_generator.py`  
**Location:** `_apply_fix()` — `file_path` from the suggestion dict is joined with `self.project_path` and used to read/write files without validating that the resolved path stays under the project root.

**Code (lines 333–358):**

```python
abs_path = os.path.join(self.project_path, file_path)
# ...
with open(abs_path, "r") as fh:
    content = fh.read()
# ...
with open(abs_path, "w") as fh:
    fh.write(fixed_code)
# Fallback: overwrite entire file content
Path(abs_path).parent.mkdir(parents=True, exist_ok=True)
with open(abs_path, "w") as fh:
    fh.write(fixed_code)
```

**Risk:** If `suggestion["file_path"]` is attacker-controlled or comes from a compromised LLM (e.g. `"../../../etc/passwd"` or an absolute path), the process could read or overwrite files outside the project directory. AutoFix is opt-in (`enable_autofix_pr=False` by default) but when enabled it should not allow path escape.

**Recommendation:** Before any `open()` or `Path()` use:

- Resolve the path and restrict it to the project root using the existing helper.
- Use `scripts/utils/io.py::validate_path_safe()` (or equivalent logic): resolve `Path(project_path) / file_path` and ensure the resolved path is under `Path(project_path).resolve()`. Reject (e.g. return `False` or raise) if validation fails.

Example:

```python
from utils.io import validate_path_safe

# In _apply_fix, after file_path = suggestion.get("file_path", ""):
base = Path(self.project_path).resolve()
try:
    abs_path = validate_path_safe(os.path.join(self.project_path, file_path), base_dir=base)
except ValueError:
    logger.error("Rejected path outside project: %s", file_path)
    return False
# then use abs_path for all file operations
```

---

## Low / informational

### 2. Subprocess and shell usage

**Finding:** No unsafe use of `shell=True` with user-controlled input was found. Scanners and utilities use list-based arguments and `shell=False` (e.g. `scripts/utils/subprocess_utils.py`, trivy, checkov, trufflehog, nuclei, preflight_checker, autofix git commands). `subprocess_utils.run_command_safe()` correctly rejects string commands and documents the security requirement.

**Recommendation:** Keep enforcing list-only commands and `shell=False` in any new code that runs external commands.

---

### 3. SQL and YAML usage

**Finding:**  
- **findings_store.py:** Queries use parameterized placeholders (`?`, `(fp,)`, etc.). The only f-string in SQL builds the `NOT IN (?,?,?)` placeholder list from `len(current_fingerprints)`; values are passed in the parameter list, so there is no SQL injection.  
- **config_loader.py / dast_scanner.py:** YAML is loaded with `yaml.safe_load()` (or equivalent), reducing deserialization risk.

**Recommendation:** Continue using parameterized queries and `safe_load` for any new YAML or SQL.

---

## Positive practices observed

- **Logging:** `utils/logging_utils.py` and `utils/error_handling.py` sanitize error messages and log content; `subprocess_utils._sanitize_command()` redacts sensitive args before logging.
- **Remediation engine:** Documents path traversal and command-injection patterns and suggests safe alternatives (e.g. path validation, no `shell=True` with user input).
- **Sandbox:** Exploit validation runs in Docker; `sandbox_integration.py` uses `exec`/`eval` only inside payload strings for intentional vulnerability demos, not at module import.
- **Config:** Layered config (defaults, profile YAML, `.argus.yml`, env, CLI) and `get_default_config()` give a single place for defaults and toggles.

---

## Not in scope / assumed handled elsewhere

- Build, typecheck, and lint (e.g. ruff, mypy) are assumed to run in CI.
- Test coverage and functional tests were not re-run as part of this review.
- Dependency and container image security (Trivy, etc.) are assumed to be covered by existing tooling.

---

## References

- [CLAUDE.md](../CLAUDE.md) — Project overview and key files.
- [.claude/rules/features.md](../.claude/rules/features.md) — Feature toggles and modules.
- [scripts/utils/io.py](../scripts/utils/io.py) — `validate_path_safe()`.
- [scripts/remediation_engine.py](../scripts/remediation_engine.py) — Path traversal remediation template.
