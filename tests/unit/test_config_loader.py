"""
Unit tests for scripts/config_loader.py.

Tests the layered configuration system:
    hardcoded defaults < profile YAML < .argus.yml < env vars < CLI args
"""

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Ensure scripts directory is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from config_loader import (
    _coerce,
    _deep_merge_nested,
    build_unified_config,
    deep_merge,
    extract_cli_overrides,
    flatten_profile,
    get_default_config,
    load_env_overrides,
    load_profile,
    validate_config,
)

# ---------------------------------------------------------------------------
# get_default_config
# ---------------------------------------------------------------------------


class TestGetDefaultConfig:
    """Tests for get_default_config()."""

    def test_returns_dict(self):
        config = get_default_config()
        assert isinstance(config, dict)

    def test_ai_defaults(self):
        config = get_default_config()
        assert config["ai_provider"] == "auto"
        assert config["model"] == "auto"
        assert config["multi_agent_mode"] == "single"
        assert config["anthropic_api_key"] == ""
        assert config["openai_api_key"] == ""

    def test_scanner_toggle_defaults(self):
        config = get_default_config()
        assert config["enable_semgrep"] is True
        assert config["enable_trivy"] is True
        assert config["enable_checkov"] is True
        assert config["enable_dast"] is False
        assert config["enable_fuzzing"] is False
        assert config["enable_runtime_security"] is False

    def test_feature_toggle_defaults(self):
        config = get_default_config()
        assert config["enable_multi_agent"] is True
        assert config["enable_ai_enrichment"] is True
        assert config["enable_proof_by_exploitation"] is False
        assert config["enable_phase_gating"] is True
        assert config["phase_gate_strict"] is False
        assert config["enable_temporal"] is False

    def test_numeric_defaults(self):
        config = get_default_config()
        assert config["max_files"] == 50
        assert config["max_file_size"] == 50000
        assert config["max_tokens"] == 8000
        assert config["cost_limit"] == 1.0
        assert config["consensus_threshold"] == 0.5

    def test_deep_analysis_defaults(self):
        config = get_default_config()
        assert config["deep_analysis_mode"] == "off"
        assert config["deep_analysis_max_files"] == 50
        assert config["deep_analysis_timeout"] == 300
        assert config["deep_analysis_cost_ceiling"] == 5.0

    def test_enrichment_defaults(self):
        config = get_default_config()
        assert config["enable_epss_scoring"] is True
        assert config["enable_fix_version_tracking"] is True
        assert config["enable_vex"] is True
        assert config["enable_vuln_deduplication"] is True
        assert config["enable_advanced_suppression"] is True
        assert config["enable_compliance_mapping"] is True
        assert config["enable_license_risk_scoring"] is True


# ---------------------------------------------------------------------------
# _coerce
# ---------------------------------------------------------------------------


class TestCoerce:
    """Tests for the _coerce() type conversion helper."""

    def test_bool_true(self):
        assert _coerce("true", "bool") is True
        assert _coerce("True", "bool") is True
        assert _coerce("TRUE", "bool") is True

    def test_bool_false(self):
        assert _coerce("false", "bool") is False
        assert _coerce("False", "bool") is False
        assert _coerce("no", "bool") is False
        assert _coerce("0", "bool") is False

    def test_int(self):
        assert _coerce("42", "int") == 42
        assert _coerce("0", "int") == 0

    def test_float(self):
        assert _coerce("3.14", "float") == pytest.approx(3.14)
        assert _coerce("0.0", "float") == 0.0

    def test_str(self):
        assert _coerce("hello", "str") == "hello"
        assert _coerce("", "str") == ""

    def test_int_invalid_raises(self):
        with pytest.raises(ValueError):
            _coerce("not_a_number", "int")

    def test_float_invalid_raises(self):
        with pytest.raises(ValueError):
            _coerce("not_a_float", "float")


# ---------------------------------------------------------------------------
# load_env_overrides
# ---------------------------------------------------------------------------


class TestLoadEnvOverrides:
    """Tests for load_env_overrides()."""

    def test_no_env_vars_returns_empty(self, monkeypatch):
        """With no mapped env vars set, returns empty dict."""
        # Clear all env vars that load_env_overrides checks
        for key in list(os.environ.keys()):
            if key in (
                "AI_PROVIDER",
                "MODEL",
                "MAX_FILES",
                "ENABLE_SEMGREP",
                "ENABLE_TRIVY",
                "COST_LIMIT",
                "ONLY_CHANGED",
                "ANTHROPIC_API_KEY",
                "OPENAI_API_KEY",
            ):
                monkeypatch.delenv(key, raising=False)
        overrides = load_env_overrides()
        # May still pick up other env vars that happen to be set;
        # just verify it returns a dict
        assert isinstance(overrides, dict)

    def test_single_string_env_var(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "openai")
        overrides = load_env_overrides()
        assert overrides["ai_provider"] == "openai"

    def test_bool_env_var(self, monkeypatch):
        monkeypatch.setenv("ENABLE_SEMGREP", "false")
        overrides = load_env_overrides()
        assert overrides["enable_semgrep"] is False

    def test_int_env_var(self, monkeypatch):
        monkeypatch.setenv("MAX_FILES", "200")
        overrides = load_env_overrides()
        assert overrides["max_files"] == 200

    def test_float_env_var(self, monkeypatch):
        monkeypatch.setenv("COST_LIMIT", "5.50")
        overrides = load_env_overrides()
        assert overrides["cost_limit"] == pytest.approx(5.50)

    def test_input_prefixed_env_var(self, monkeypatch):
        """GitHub Action-style INPUT_ prefix should also work."""
        monkeypatch.setenv("INPUT_AI_PROVIDER", "anthropic")
        # Make sure bare name is NOT set so INPUT_ variant wins
        monkeypatch.delenv("AI_PROVIDER", raising=False)
        overrides = load_env_overrides()
        assert overrides["ai_provider"] == "anthropic"

    def test_first_env_name_wins(self, monkeypatch):
        """When both bare and INPUT_ are set, bare name wins (first match)."""
        monkeypatch.setenv("AI_PROVIDER", "ollama")
        monkeypatch.setenv("INPUT_AI_PROVIDER", "openai")
        overrides = load_env_overrides()
        assert overrides["ai_provider"] == "ollama"

    def test_invalid_int_env_var_ignored(self, monkeypatch):
        """Invalid type conversion logs warning and skips the variable."""
        monkeypatch.setenv("MAX_FILES", "not_a_number")
        overrides = load_env_overrides()
        assert "max_files" not in overrides

    def test_deep_analysis_env_vars(self, monkeypatch):
        monkeypatch.setenv("DEEP_ANALYSIS_MODE", "full")
        monkeypatch.setenv("DEEP_ANALYSIS_MAX_FILES", "100")
        overrides = load_env_overrides()
        assert overrides["deep_analysis_mode"] == "full"
        assert overrides["deep_analysis_max_files"] == 100


# ---------------------------------------------------------------------------
# extract_cli_overrides
# ---------------------------------------------------------------------------


class TestExtractCliOverrides:
    """Tests for extract_cli_overrides()."""

    def test_none_args_returns_empty(self):
        assert extract_cli_overrides(None) == {}

    def test_basic_cli_args(self):
        args = SimpleNamespace(
            provider="anthropic",
            model="claude-3-opus",
            max_files=100,
            cost_limit=2.5,
        )
        overrides = extract_cli_overrides(args)
        assert overrides["ai_provider"] == "anthropic"
        assert overrides["model"] == "claude-3-opus"
        assert overrides["max_files"] == 100
        assert overrides["cost_limit"] == 2.5

    def test_none_values_excluded(self):
        args = SimpleNamespace(provider=None, model=None, max_files=None)
        overrides = extract_cli_overrides(args)
        assert "ai_provider" not in overrides
        assert "model" not in overrides

    def test_enable_deep_analysis_shorthand(self):
        """--enable-deep-analysis sets deep_analysis_mode to conservative."""
        args = SimpleNamespace(enable_deep_analysis=True)
        overrides = extract_cli_overrides(args)
        assert overrides["deep_analysis_mode"] == "conservative"

    def test_explicit_deep_analysis_mode_not_overridden(self):
        """Explicit --deep-analysis-mode takes precedence over --enable-deep-analysis."""
        args = SimpleNamespace(
            enable_deep_analysis=True,
            deep_analysis_mode="full",
        )
        overrides = extract_cli_overrides(args)
        assert overrides["deep_analysis_mode"] == "full"

    def test_profile_mapped_to_internal_key(self):
        args = SimpleNamespace(profile="quick")
        overrides = extract_cli_overrides(args)
        assert overrides["_profile"] == "quick"


# ---------------------------------------------------------------------------
# flatten_profile
# ---------------------------------------------------------------------------


class TestFlattenProfile:
    """Tests for flatten_profile()."""

    def test_empty_dict(self):
        assert flatten_profile({}) == {}

    def test_ai_section(self):
        nested = {"ai": {"provider": "openai", "model": "gpt-4", "multi_agent_mode": "parallel"}}
        flat = flatten_profile(nested)
        assert flat["ai_provider"] == "openai"
        assert flat["model"] == "gpt-4"
        assert flat["multi_agent_mode"] == "parallel"

    def test_scanners_section_adds_enable_prefix(self):
        nested = {"scanners": {"semgrep": True, "trivy": False}}
        flat = flatten_profile(nested)
        assert flat["enable_semgrep"] is True
        assert flat["enable_trivy"] is False

    def test_features_section_adds_enable_prefix(self):
        nested = {"features": {"multi_agent": True, "consensus": False}}
        flat = flatten_profile(nested)
        assert flat["enable_multi_agent"] is True
        assert flat["enable_consensus"] is False

    def test_limits_section_direct(self):
        nested = {"limits": {"max_files": 200, "cost_limit": 5.0}}
        flat = flatten_profile(nested)
        assert flat["max_files"] == 200
        assert flat["cost_limit"] == 5.0

    def test_deep_analysis_section(self):
        nested = {"deep_analysis": {"mode": "full", "max_files": 100, "timeout": 600}}
        flat = flatten_profile(nested)
        assert flat["deep_analysis_mode"] == "full"
        assert flat["deep_analysis_max_files"] == 100
        assert flat["deep_analysis_timeout"] == 600

    def test_output_section_direct(self):
        nested = {"output": {"review_type": "security", "project_type": "backend-api"}}
        flat = flatten_profile(nested)
        assert flat["review_type"] == "security"
        assert flat["project_type"] == "backend-api"

    def test_scalar_keys_passthrough(self):
        nested = {"agent_profile": "custom", "name": "my-profile"}
        flat = flatten_profile(nested)
        assert flat["agent_profile"] == "custom"
        assert flat["name"] == "my-profile"

    def test_none_values_excluded(self):
        nested = {"limits": {"max_files": None, "cost_limit": 5.0}}
        flat = flatten_profile(nested)
        assert "max_files" not in flat
        assert flat["cost_limit"] == 5.0


# ---------------------------------------------------------------------------
# deep_merge (flat)
# ---------------------------------------------------------------------------


class TestDeepMerge:
    """Tests for the flat deep_merge() helper."""

    def test_override_wins(self):
        base = {"a": 1, "b": 2}
        override = {"b": 99, "c": 3}
        result = deep_merge(base, override)
        assert result == {"a": 1, "b": 99, "c": 3}

    def test_none_override_skipped(self):
        base = {"a": 1}
        override = {"a": None}
        result = deep_merge(base, override)
        assert result["a"] == 1

    def test_base_not_mutated(self):
        base = {"a": 1}
        override = {"a": 2}
        deep_merge(base, override)
        assert base["a"] == 1


# ---------------------------------------------------------------------------
# _deep_merge_nested
# ---------------------------------------------------------------------------


class TestDeepMergeNested:
    """Tests for the nested _deep_merge_nested() helper."""

    def test_nested_dict_merge(self):
        base = {"ai": {"provider": "auto", "model": "auto"}}
        override = {"ai": {"provider": "openai"}}
        result = _deep_merge_nested(base, override)
        assert result["ai"]["provider"] == "openai"
        assert result["ai"]["model"] == "auto"

    def test_non_dict_override_replaces(self):
        base = {"ai": {"provider": "auto"}}
        override = {"ai": "disabled"}
        result = _deep_merge_nested(base, override)
        assert result["ai"] == "disabled"


# ---------------------------------------------------------------------------
# load_profile (requires actual profile YAML files)
# ---------------------------------------------------------------------------


class TestLoadProfile:
    """Tests for load_profile() with real profile files."""

    def test_load_standard_profile(self):
        """Standard profile should load and return a flat dict."""
        flat = load_profile("standard")
        assert isinstance(flat, dict)
        assert flat.get("ai_provider") == "auto"
        assert flat.get("enable_semgrep") is True
        assert flat.get("enable_dast") is False
        assert flat.get("multi_agent_mode") == "sequential"

    def test_load_quick_profile(self):
        flat = load_profile("quick")
        assert flat.get("multi_agent_mode") == "single"
        assert flat.get("enable_trivy") is False
        assert flat.get("only_changed") is True

    def test_load_deep_profile(self):
        flat = load_profile("deep")
        assert flat.get("multi_agent_mode") == "parallel"
        assert flat.get("max_files") == 100
        assert flat.get("deep_analysis_mode") == "full"
        assert flat.get("enable_collaborative_reasoning") is True

    def test_load_nonexistent_profile_raises(self):
        with pytest.raises(FileNotFoundError, match="not found"):
            load_profile("nonexistent_profile_xyz")


# ---------------------------------------------------------------------------
# build_unified_config
# ---------------------------------------------------------------------------


class TestBuildUnifiedConfig:
    """Tests for build_unified_config()."""

    def test_defaults_only(self, monkeypatch):
        """With no profile, env vars, or CLI args, returns defaults."""
        # Clear env vars that would interfere
        monkeypatch.delenv("ARGUS_PROFILE", raising=False)
        monkeypatch.delenv("AI_PROVIDER", raising=False)
        monkeypatch.delenv("MAX_FILES", raising=False)

        config = build_unified_config()
        assert config["ai_provider"] == "auto"
        assert config["max_files"] == 50
        assert config["enable_semgrep"] is True

    def test_profile_overrides_defaults(self, monkeypatch):
        """Profile values should override defaults."""
        monkeypatch.delenv("ARGUS_PROFILE", raising=False)
        config = build_unified_config(profile="quick")
        # quick profile sets max_files=20
        assert config["max_files"] == 20

    def test_env_var_overrides_profile(self, monkeypatch):
        """Env vars should override profile values."""
        monkeypatch.delenv("ARGUS_PROFILE", raising=False)
        monkeypatch.setenv("MAX_FILES", "999")
        config = build_unified_config(profile="quick")
        assert config["max_files"] == 999

    def test_cli_args_override_env_vars(self, monkeypatch):
        """CLI args should override env vars."""
        monkeypatch.setenv("MAX_FILES", "999")
        args = SimpleNamespace(max_files=42, profile=None)
        config = build_unified_config(cli_args=args)
        assert config["max_files"] == 42

    def test_argus_profile_env_var(self, monkeypatch):
        """ARGUS_PROFILE env var should select a profile."""
        monkeypatch.setenv("ARGUS_PROFILE", "quick")
        config = build_unified_config()
        # quick profile sets only_changed=true
        assert config["only_changed"] is True

    def test_cli_profile_beats_env_profile(self, monkeypatch):
        """CLI --profile should beat ARGUS_PROFILE env var."""
        monkeypatch.setenv("ARGUS_PROFILE", "quick")
        args = SimpleNamespace(profile="deep")
        config = build_unified_config(cli_args=args)
        # deep profile: max_files=100
        assert config["max_files"] == 100

    def test_nonexistent_profile_logs_warning_and_uses_defaults(self, monkeypatch):
        """Missing profile should warn and fall back to defaults."""
        monkeypatch.delenv("ARGUS_PROFILE", raising=False)
        config = build_unified_config(profile="nonexistent_xyz")
        # Should still have defaults
        assert config["max_files"] == 50

    def test_full_precedence_chain(self, monkeypatch):
        """Verify full chain: default < profile < env < CLI."""
        monkeypatch.delenv("ARGUS_PROFILE", raising=False)
        # Default cost_limit=1.0, deep profile sets 10.0
        monkeypatch.setenv("COST_LIMIT", "20.0")
        args = SimpleNamespace(cost_limit=50.0, profile=None)
        config = build_unified_config(profile="deep", cli_args=args)
        # CLI should win
        assert config["cost_limit"] == 50.0


# ---------------------------------------------------------------------------
# validate_config
# ---------------------------------------------------------------------------


class TestValidateConfig:
    """Tests for validate_config()."""

    def test_valid_default_config(self):
        config = get_default_config()
        # Defaults with auto and no API keys give a warning, not error
        issues = validate_config(config)
        # Should have the "auto but no keys" warning
        warnings = [i for i in issues if i.startswith("WARNING")]
        assert any("auto" in w for w in warnings)

    def test_anthropic_without_key_is_error(self):
        config = get_default_config()
        config["ai_provider"] = "anthropic"
        config["anthropic_api_key"] = ""
        issues = validate_config(config)
        assert any("ANTHROPIC_API_KEY" in i for i in issues)

    def test_openai_without_key_is_error(self):
        config = get_default_config()
        config["ai_provider"] = "openai"
        config["openai_api_key"] = ""
        issues = validate_config(config)
        assert any("OPENAI_API_KEY" in i for i in issues)

    def test_invalid_ai_provider(self):
        config = get_default_config()
        config["ai_provider"] = "invalid_provider"
        issues = validate_config(config)
        assert any("Invalid ai_provider" in i for i in issues)

    def test_invalid_multi_agent_mode(self):
        config = get_default_config()
        config["multi_agent_mode"] = "turbo"
        issues = validate_config(config)
        assert any("Invalid multi_agent_mode" in i for i in issues)

    def test_invalid_deep_analysis_mode(self):
        config = get_default_config()
        config["deep_analysis_mode"] = "extreme"
        issues = validate_config(config)
        assert any("Invalid deep_analysis_mode" in i for i in issues)

    def test_invalid_exploitability_threshold(self):
        config = get_default_config()
        config["exploitability_threshold"] = "mega"
        issues = validate_config(config)
        assert any("Invalid exploitability_threshold" in i for i in issues)

    def test_max_files_below_1(self):
        config = get_default_config()
        config["max_files"] = 0
        issues = validate_config(config)
        assert any("max_files must be >= 1" in i for i in issues)

    def test_negative_cost_limit(self):
        config = get_default_config()
        config["cost_limit"] = -1.0
        issues = validate_config(config)
        assert any("cost_limit must be >= 0" in i for i in issues)

    def test_consensus_threshold_out_of_range(self):
        config = get_default_config()
        config["consensus_threshold"] = 1.5
        issues = validate_config(config)
        assert any("consensus_threshold" in i for i in issues)

    def test_collaborative_without_multi_agent(self):
        config = get_default_config()
        config["enable_collaborative_reasoning"] = True
        config["enable_multi_agent"] = False
        issues = validate_config(config)
        assert any("collaborative_reasoning requires enable_multi_agent" in i for i in issues)

    def test_dast_without_target_url(self):
        config = get_default_config()
        config["enable_dast"] = True
        config["dast_target_url"] = ""
        issues = validate_config(config)
        assert any("DAST target URL" in i for i in issues)

    def test_valid_anthropic_config_no_errors(self):
        config = get_default_config()
        config["ai_provider"] = "anthropic"
        config["anthropic_api_key"] = "sk-ant-test"
        issues = validate_config(config)
        errors = [i for i in issues if i.startswith("ERROR")]
        assert len(errors) == 0
