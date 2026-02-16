# Next Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the CheckovScanResult bug, eliminate all ruff errors in both orchestrators, align max_files default, address Falco infrastructure gap, and add test coverage for key untested modules.

**Architecture:** 4 sequential waves. Each wave verified before proceeding. Agents work on independent files within each wave.

**Tech Stack:** Python 3.9+, pytest, ruff, dataclasses

---

## Wave 1: Bug Fix

### Task 1: Fix CheckovScanResult not iterable in pipeline/stages.py

**Files:**
- Modify: `scripts/pipeline/stages.py:126-134`
- Reference: `scripts/hybrid/scanner_runners.py:154-183` (correct pattern)
- Reference: `scripts/checkov_scanner.py:30-48` (CheckovFinding dataclass)
- Test: `tests/test_pipeline_stages.py` (create)

**Context:**
`_run_checkov()` at line 131 returns `scanner.scan(target_path)` which is a `CheckovScanResult` dataclass (not a list). Line 100 does `ctx.findings.extend(findings)` which fails with `TypeError: 'CheckovScanResult' object is not iterable`. The correct handling is in `scanner_runners.py:163` which iterates `checkov_result.findings` and converts each `CheckovFinding` to a dict.

**Step 1: Write the failing test**

Create `tests/test_pipeline_stages.py`:

```python
"""Tests for scripts/pipeline/stages.py — CheckovScanResult handling."""

from unittest.mock import MagicMock, patch

import pytest


class TestScannerOrchestrationCheckov:
    """Verify _run_checkov returns a list of dicts, not a CheckovScanResult."""

    def test_run_checkov_returns_list_of_dicts(self):
        """_run_checkov should extract .findings and convert to dicts."""
        from pipeline.stages import ScannerOrchestrationStage

        # Create mock CheckovFinding with to_dict()
        mock_finding = MagicMock()
        mock_finding.to_dict.return_value = {
            "check_id": "CKV_DOCKER_1",
            "check_name": "Ensure the base image uses a non latest version tag",
            "severity": "HIGH",
            "file_path": "Dockerfile",
            "resource": "Dockerfile.",
            "resource_type": "dockerfile",
            "file_line_range": [1, 1],
            "guideline": "https://docs.prismacloud.io/en/...",
            "description": "Non-latest tag required",
            "code_block": ["FROM ubuntu:latest"],
            "check_result": {"result": "FAILED"},
            "framework": "dockerfile",
        }

        # Create mock CheckovScanResult with .findings list
        mock_result = MagicMock()
        mock_result.findings = [mock_finding]

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = mock_result

        stage = ScannerOrchestrationStage()
        result = stage._run_checkov("/tmp/target")

        # Should return a list of dicts, not a CheckovScanResult
        assert isinstance(result, list)
        assert len(result) == 1
        assert isinstance(result[0], dict)
        assert result[0]["check_id"] == "CKV_DOCKER_1"

    def test_run_checkov_empty_findings(self):
        """_run_checkov with no findings returns empty list."""
        from pipeline.stages import ScannerOrchestrationStage

        mock_result = MagicMock()
        mock_result.findings = []

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = mock_result

        stage = ScannerOrchestrationStage()
        with patch("pipeline.stages.CheckovScanner", return_value=mock_scanner):
            result = stage._run_checkov("/tmp/target")

        assert isinstance(result, list)
        assert len(result) == 0

    def test_run_checkov_import_failure_returns_empty(self):
        """_run_checkov returns [] when CheckovScanner import fails."""
        from pipeline.stages import ScannerOrchestrationStage

        stage = ScannerOrchestrationStage()
        with patch.dict("sys.modules", {"checkov_scanner": None}):
            result = stage._run_checkov("/tmp/target")

        assert result == []
```

**Step 2: Run test to verify it fails**

Run: `cd scripts && python -m pytest ../tests/test_pipeline_stages.py -v`
Expected: FAIL — `_run_checkov` returns `CheckovScanResult` not a list of dicts

**Step 3: Fix _run_checkov to extract .findings and convert to dicts**

Replace `scripts/pipeline/stages.py:126-134`:

```python
    def _run_checkov(self, target_path: str) -> list:
        """Run Checkov and return findings as list of dicts."""
        try:
            from checkov_scanner import CheckovScanner
            scanner = CheckovScanner()
            result = scanner.scan(target_path)
            # CheckovScanner.scan() returns a CheckovScanResult dataclass,
            # not a list.  Extract .findings and convert each to a dict.
            return [f.to_dict() for f in result.findings]
        except (ImportError, Exception) as exc:
            logger.warning("Checkov scan failed: %s", exc)
            return []
```

**Step 4: Run test to verify it passes**

Run: `cd scripts && python -m pytest ../tests/test_pipeline_stages.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add scripts/pipeline/stages.py tests/test_pipeline_stages.py
git commit -m "fix: Extract .findings from CheckovScanResult in pipeline/stages.py"
```

---

## Wave 2: Ruff Cleanup + Config Fix

### Task 2: Fix ruff errors in run_ai_audit.py (28 errors → 0)

**Files:**
- Modify: `scripts/run_ai_audit.py`

**Context:**
28 ruff errors: 18 F401 (unused imports), 4 E402 (import not at top), 2 I001 (unsorted imports), 2 F541 (f-string without placeholders), 1 F841 (unused variable `summary` at line 889), 1 SIM108 (simplifiable conditional at line 1877).

**Step 1: Run ruff auto-fix for safe fixes (F401, I001, F541)**

Run: `ruff check scripts/run_ai_audit.py --fix`
This fixes ~22 of 28 errors automatically.

**Step 2: Fix remaining manual errors**

- **E402** (4 errors at lines 66, 78, 79, 80): These imports are after `sys.path.insert`. Move the `sys.path.insert` block before ALL imports at the top of the file, or use `# noqa: E402` if the path manipulation must stay where it is.
- **F841** (line 889): Remove or use the unused `summary` variable.
- **SIM108** (line 1877): Replace the if/else block with a ternary:
  ```python
  json_output_meta = {"enrichment": enrichment_meta} if enrichment_meta else {}
  ```

**Step 3: Verify zero errors**

Run: `ruff check scripts/run_ai_audit.py`
Expected: no errors

**Step 4: Run existing tests to verify nothing broke**

Run: `cd scripts && python -m pytest ../tests/test_run_ai_audit.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add scripts/run_ai_audit.py
git commit -m "chore: Fix all 28 ruff errors in run_ai_audit.py"
```

### Task 3: Fix ruff errors in hybrid_analyzer.py (8 errors → 0)

**Files:**
- Modify: `scripts/hybrid_analyzer.py`

**Context:**
8 ruff errors:
- Line 65: F401 — `os` imported but unused
- Line 79: I001 — unsorted imports
- Lines 88: F401 — `IRISFinding`, `load_code_context` imported but unused (imported for availability check — review if actually needed or use `importlib.util.find_spec`)
- Line 152: I001 — unsorted imports
- Line 336: I001 — unsorted imports
- Line 619: N806 — `_HEURISTIC_EXTS` in function should be lowercase
- Line 622: SIM105 — Use `contextlib.suppress(Exception)` instead of `try`-`except`-`pass`

**Step 1: Run ruff auto-fix for safe fixes (F401 os, I001)**

Run: `ruff check scripts/hybrid_analyzer.py --fix`
Fixes ~4 errors.

**Step 2: Fix remaining manual errors**

- **F401 iris imports** (line 88): These are imported so `_IRIS_OK` flag gets set to True. Replace the import with `importlib.util.find_spec("iris_analyzer")`:
  ```python
  try:
      import importlib.util
      _IRIS_OK = importlib.util.find_spec("iris_analyzer") is not None
  except Exception:
      _IRIS_OK = False
  ```
  Or, if the imports are truly needed elsewhere, keep them and add `# noqa: F401`.
- **N806** (line 619): Rename `_HEURISTIC_EXTS` to `_heuristic_exts` (it's a local variable inside a function).
- **SIM105** (line 622): Replace `try: ... except Exception: pass` with `with contextlib.suppress(Exception):` and add `import contextlib` if not present.

**Step 3: Verify zero errors**

Run: `ruff check scripts/hybrid_analyzer.py`
Expected: no errors

**Step 4: Run existing tests**

Run: `cd scripts && python -m pytest ../tests/test_phase_modules.py ../tests/test_hybrid_cli.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add scripts/hybrid_analyzer.py
git commit -m "chore: Fix all 8 ruff errors in hybrid_analyzer.py"
```

### Task 4: Fix max_files default mismatch

**Files:**
- Modify: `scripts/orchestrator/config.py:46`
- Reference: `scripts/config_loader.py:95` (canonical source, default=50)

**Context:**
`config_loader.py:95` defaults `max_files` to `50` (int). `orchestrator/config.py:46` defaults to `"100"` (string). The config_loader is the canonical source; align orchestrator to `"50"`.

**Step 1: Write test to verify alignment**

Add to existing `tests/test_config_loader.py`:

```python
def test_max_files_default_matches_across_modules():
    """max_files default should be consistent between config_loader and orchestrator/config."""
    from config_loader import ConfigLoader
    from orchestrator.config import load_config_from_env

    cl_config = ConfigLoader().config
    orch_config = load_config_from_env()

    assert int(cl_config.get("max_files", 0)) == int(orch_config.get("max_files", 0))
```

**Step 2: Fix the mismatch**

In `scripts/orchestrator/config.py:46`, change `"100"` to `"50"`:

```python
"max_files": os.environ.get("MAX_FILES", os.environ.get("INPUT_MAX_FILES", "50")),
```

**Step 3: Run test**

Run: `cd scripts && python -m pytest ../tests/test_config_loader.py::test_max_files_default_matches_across_modules -v`
Expected: PASS

**Step 4: Commit**

```bash
git add scripts/orchestrator/config.py tests/test_config_loader.py
git commit -m "fix: Align max_files default to 50 in orchestrator/config.py"
```

---

## Wave 3: Infrastructure — Falco Warning

### Task 5: Enhance Falco skip message in runtime_security_monitor.py

**Files:**
- Modify: `scripts/runtime_security_monitor.py:188-189`

**Context:**
Falco is not installed in any Dockerfile. The module already handles this gracefully at line 188-189 with `logger.warning("Falco not installed - runtime monitoring unavailable")`. However, `monitor_realtime()` at line 229-231 logs `logger.error("Falco not available - cannot monitor")` at ERROR level which is misleading (not an error, just not installed).

Adding Falco to Dockerfile.complete is complex (requires kernel modules, privileged mode). Better approach: downgrade the error to warning, make the skip message more informative.

**Step 1: Fix the error-level log to warning-level**

In `scripts/runtime_security_monitor.py:229-231`, change:

```python
        if not self._check_falco_installed():
            logger.error("Falco not available - cannot monitor")
            return []
```

to:

```python
        if not self._check_falco_installed():
            logger.warning(
                "Falco binary not found — runtime monitoring skipped. "
                "Install Falco (https://falco.org/docs/install-operate/installation/) "
                "to enable container runtime threat detection."
            )
            return []
```

**Step 2: Verify ruff clean**

Run: `ruff check scripts/runtime_security_monitor.py`

**Step 3: Commit**

```bash
git add scripts/runtime_security_monitor.py
git commit -m "fix: Downgrade Falco missing from error to warning with install guidance"
```

---

## Wave 4: Test Coverage

### Task 6: Write tests for pipeline/stages.py (beyond Checkov fix)

**Files:**
- Modify: `tests/test_pipeline_stages.py` (created in Task 1)
- Reference: `scripts/pipeline/stages.py`

**Context:**
Test the `ScannerOrchestrationStage._execute()` method and the other scanner wrappers (`_run_semgrep`, `_run_trivy`). Verify that scanner failures are caught and don't crash the pipeline.

**Step 1: Add tests**

```python
class TestScannerOrchestrationExecute:
    """Test the full _execute method."""

    def test_execute_with_no_scanners_enabled(self):
        """When all scanners are disabled, returns empty scanners_run."""
        from pipeline.stages import ScannerOrchestrationStage, PipelineContext

        ctx = PipelineContext(
            target_path="/tmp/test",
            config={
                "enable_semgrep": False,
                "enable_trivy": False,
                "enable_checkov": False,
            },
        )
        stage = ScannerOrchestrationStage()
        result = stage._execute(ctx)

        assert result["scanners_run"] == []
        assert ctx.findings == []

    def test_semgrep_failure_doesnt_crash_pipeline(self):
        """If Semgrep raises, pipeline continues."""
        from pipeline.stages import ScannerOrchestrationStage

        stage = ScannerOrchestrationStage()
        with patch("pipeline.stages.SemgrepScanner", side_effect=RuntimeError("boom")):
            result = stage._run_semgrep("/tmp/target")
        assert result == []

    def test_trivy_failure_doesnt_crash_pipeline(self):
        """If Trivy raises, pipeline continues."""
        from pipeline.stages import ScannerOrchestrationStage

        stage = ScannerOrchestrationStage()
        with patch("pipeline.stages.TrivyScanner", side_effect=RuntimeError("boom")):
            result = stage._run_trivy("/tmp/target")
        assert result == []
```

**Step 2: Run tests**

Run: `cd scripts && python -m pytest ../tests/test_pipeline_stages.py -v`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/test_pipeline_stages.py
git commit -m "test: Add pipeline/stages.py scanner orchestration tests"
```

### Task 7: Write tests for scanner_runners.py

**Files:**
- Create: `tests/test_scanner_runners.py`
- Reference: `scripts/hybrid/scanner_runners.py`

**Context:**
`scanner_runners.py` has `run_semgrep`, `run_trivy`, `run_checkov`, `run_api_security`, `run_dast` — all convert scanner-specific results to `HybridFinding` format. No tests exist. Focus on `run_checkov` (highest bug risk due to dataclass conversion) and `run_semgrep` (most used).

**Step 1: Write tests**

```python
"""Tests for scripts/hybrid/scanner_runners.py."""

import logging
from unittest.mock import MagicMock

from hybrid.scanner_runners import run_checkov, run_semgrep
from hybrid.models import HybridFinding


class TestRunCheckov:
    """Tests for run_checkov scanner runner."""

    def test_run_checkov_converts_findings(self):
        """CheckovFinding objects are converted to HybridFinding."""
        mock_finding = MagicMock()
        mock_finding.check_id = "CKV_DOCKER_1"
        mock_finding.check_name = "Non-latest tag"
        mock_finding.severity = "HIGH"
        mock_finding.file_path = "Dockerfile"
        mock_finding.file_line_range = [1, 3]
        mock_finding.description = "Use specific tag"
        mock_finding.guideline = "https://example.com"
        mock_finding.framework = "dockerfile"

        mock_result = MagicMock()
        mock_result.findings = [mock_finding]

        scanner = MagicMock()
        scanner.scan.return_value = mock_result

        findings = run_checkov(scanner, "/tmp/target", logging.getLogger())

        assert len(findings) == 1
        assert isinstance(findings[0], HybridFinding)
        assert findings[0].source_tool == "checkov"
        assert findings[0].severity == "high"

    def test_run_checkov_empty_results(self):
        """Empty scan results return empty list."""
        mock_result = MagicMock()
        mock_result.findings = []

        scanner = MagicMock()
        scanner.scan.return_value = mock_result

        findings = run_checkov(scanner, "/tmp/target", logging.getLogger())
        assert findings == []

    def test_run_checkov_exception_returns_empty(self):
        """Scanner exception returns empty list, doesn't crash."""
        scanner = MagicMock()
        scanner.scan.side_effect = RuntimeError("checkov crashed")

        findings = run_checkov(scanner, "/tmp/target", logging.getLogger())
        assert findings == []


class TestRunSemgrep:
    """Tests for run_semgrep scanner runner."""

    def test_run_semgrep_converts_findings(self):
        """Semgrep dict results are converted to HybridFinding."""
        scanner = MagicMock()
        scanner.scan.return_value = [
            {
                "check_id": "python.lang.security.audit.exec-detected",
                "severity": "WARNING",
                "path": "app.py",
                "start": {"line": 10},
                "extra": {"message": "exec() detected", "metadata": {}},
            }
        ]

        findings = run_semgrep(scanner, "/tmp/target", logging.getLogger())

        assert len(findings) >= 1
        assert isinstance(findings[0], HybridFinding)
        assert findings[0].source_tool == "semgrep"
```

**Step 2: Run tests**

Run: `cd scripts && python -m pytest ../tests/test_scanner_runners.py -v`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/test_scanner_runners.py
git commit -m "test: Add scanner_runners.py conversion tests"
```

### Task 8: Write tests for config_loader.py edge cases

**Files:**
- Modify: `tests/test_config_loader.py`
- Reference: `scripts/config_loader.py`

**Context:**
`test_config_loader.py` exists but may not cover env var override paths, type coercion (`"int"`, `"float"`, `"bool"` casting in `_ENV_MAPPINGS`), or profile loading. Add targeted edge-case tests.

**Step 1: Write tests**

```python
class TestConfigLoaderEnvOverrides:
    """Test environment variable overrides via _ENV_MAPPINGS."""

    def test_max_files_env_override(self, monkeypatch):
        """MAX_FILES env var overrides the default."""
        monkeypatch.setenv("MAX_FILES", "200")
        from config_loader import ConfigLoader
        config = ConfigLoader().config
        assert config["max_files"] == 200

    def test_bool_env_var_parsing(self, monkeypatch):
        """Boolean env vars parse 'true'/'false' strings correctly."""
        monkeypatch.setenv("ENABLE_EPSS_SCORING", "false")
        from config_loader import ConfigLoader
        config = ConfigLoader().config
        assert config["enable_epss_scoring"] is False

    def test_float_env_var_parsing(self, monkeypatch):
        """Float env vars parse numeric strings correctly."""
        monkeypatch.setenv("COST_LIMIT", "5.50")
        from config_loader import ConfigLoader
        config = ConfigLoader().config
        assert config["cost_limit"] == 5.50

class TestConfigLoaderValidation:
    """Test config validation edge cases."""

    def test_max_files_below_one_is_invalid(self):
        """max_files < 1 should produce a validation error."""
        from config_loader import ConfigLoader
        cl = ConfigLoader()
        cl.config["max_files"] = 0
        issues = cl.validate()
        assert any("max_files" in str(i).lower() for i in issues)
```

**Step 2: Run tests**

Run: `cd scripts && python -m pytest ../tests/test_config_loader.py -v`
Expected: PASS

**Step 3: Commit**

```bash
git add tests/test_config_loader.py
git commit -m "test: Add config_loader env override and validation edge-case tests"
```

---

## Verification

After all waves:

```bash
# Zero ruff errors in both orchestrators
ruff check scripts/run_ai_audit.py scripts/hybrid_analyzer.py

# All tests pass
cd scripts && python -m pytest ../tests/ -v --tb=short

# CheckovScanResult bug confirmed fixed
cd scripts && python -m pytest ../tests/test_pipeline_stages.py -v
```
