"""
Tests for Feature 3: Configuration Profiles

Tests config_loader.py: profile loading, inheritance, flattening,
env var overrides, CLI overrides, and the full merge chain.
"""

import os
import sys
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from config_loader import (
    build_unified_config,
    deep_merge,
    extract_cli_overrides,
    flatten_profile,
    get_default_config,
    list_available_profiles,
    load_env_overrides,
    load_profile,
    validate_config,
)


# ============================================================================
# Test get_default_config
# ============================================================================


class TestGetDefaultConfig:
    def test_returns_dict(self):
        config = get_default_config()
        assert isinstance(config, dict)

    def test_all_keys_present(self):
        config = get_default_config()
        required_keys = [
            "ai_provider", "model", "multi_agent_mode",
            "enable_semgrep", "enable_trivy", "enable_checkov",
            "enable_multi_agent", "enable_ai_enrichment",
            "max_files", "max_file_size", "cost_limit",
            "deep_analysis_mode", "review_type",
        ]
        for key in required_keys:
            assert key in config, f"Missing key: {key}"

    def test_sensible_defaults(self):
        config = get_default_config()
        assert config["ai_provider"] == "auto"
        assert config["enable_semgrep"] is True
        assert config["enable_dast"] is False
        assert config["max_files"] == 50
        assert config["cost_limit"] == 1.0
        assert config["deep_analysis_mode"] == "off"


# ============================================================================
# Test flatten_profile
# ============================================================================


class TestFlattenProfile:
    def test_ai_section(self):
        nested = {
            "ai": {
                "provider": "anthropic",
                "model": "claude-sonnet-4-5-20250929",
                "multi_agent_mode": "sequential",
            }
        }
        flat = flatten_profile(nested)
        assert flat["ai_provider"] == "anthropic"
        assert flat["model"] == "claude-sonnet-4-5-20250929"
        assert flat["multi_agent_mode"] == "sequential"

    def test_scanners_section(self):
        nested = {"scanners": {"semgrep": True, "trivy": False, "dast": True}}
        flat = flatten_profile(nested)
        assert flat["enable_semgrep"] is True
        assert flat["enable_trivy"] is False
        assert flat["enable_dast"] is True

    def test_features_section(self):
        nested = {"features": {"multi_agent": True, "consensus": False}}
        flat = flatten_profile(nested)
        assert flat["enable_multi_agent"] is True
        assert flat["enable_consensus"] is False

    def test_features_no_prefix_keys(self):
        """generate_security_tests should NOT get enable_ prefix."""
        nested = {"features": {"generate_security_tests": False, "multi_agent": True}}
        flat = flatten_profile(nested)
        assert flat["generate_security_tests"] is False
        assert "enable_generate_security_tests" not in flat
        assert flat["enable_multi_agent"] is True

    def test_limits_section(self):
        nested = {"limits": {"max_files": 100, "cost_limit": 5.0}}
        flat = flatten_profile(nested)
        assert flat["max_files"] == 100
        assert flat["cost_limit"] == 5.0

    def test_deep_analysis_section(self):
        nested = {"deep_analysis": {"mode": "full", "timeout": 600}}
        flat = flatten_profile(nested)
        assert flat["deep_analysis_mode"] == "full"
        assert flat["deep_analysis_timeout"] == 600

    def test_none_values_excluded(self):
        nested = {"scanners": {"semgrep": True, "trivy": None}}
        flat = flatten_profile(nested)
        assert "enable_semgrep" in flat
        assert "enable_trivy" not in flat

    def test_top_level_scalars(self):
        nested = {"agent_profile": "lite", "secrets_scanners_only": True}
        flat = flatten_profile(nested)
        assert flat["agent_profile"] == "lite"
        assert flat["secrets_scanners_only"] is True


# ============================================================================
# Test load_profile
# ============================================================================


class TestLoadProfile:
    def test_load_quick_profile(self):
        profile = load_profile("quick")
        assert profile.get("enable_semgrep") is True
        assert profile.get("enable_trivy") is False
        assert profile.get("enable_multi_agent") is False

    def test_load_standard_profile(self):
        profile = load_profile("standard")
        assert profile.get("enable_semgrep") is True
        assert profile.get("enable_trivy") is True
        assert profile.get("multi_agent_mode") == "sequential"

    def test_load_deep_profile(self):
        profile = load_profile("deep")
        assert profile.get("cost_limit") == 10.0
        assert profile.get("deep_analysis_mode") == "full"
        assert profile.get("multi_agent_mode") == "parallel"

    def test_load_backend_api_inherits_standard(self):
        profile = load_profile("backend-api")
        # Should inherit standard's enable_semgrep
        assert profile.get("enable_semgrep") is True
        # Should override with its own settings
        assert profile.get("enable_fuzzing") is True

    def test_load_frontend_inherits_standard(self):
        profile = load_profile("frontend")
        assert profile.get("enable_checkov") is False

    def test_load_infrastructure_inherits_standard(self):
        profile = load_profile("infrastructure")
        assert profile.get("enable_checkov") is True
        assert profile.get("enable_runtime_security") is True

    def test_load_secrets_only_profile(self):
        profile = load_profile("secrets-only")
        assert profile.get("enable_ai_enrichment") is False
        assert profile.get("enable_semgrep") is False
        assert profile.get("enable_heuristics") is True

    def test_nonexistent_profile(self):
        with pytest.raises(FileNotFoundError):
            load_profile("nonexistent_profile_xyz")

    def test_all_profiles_loadable(self):
        profiles = list_available_profiles()
        for name in profiles:
            profile = load_profile(name)
            assert isinstance(profile, dict)


# ============================================================================
# Test load_env_overrides
# ============================================================================


class TestLoadEnvOverrides:
    def test_empty_when_no_env(self):
        """No env vars set -> empty dict."""
        with patch.dict(os.environ, {}, clear=True):
            overrides = load_env_overrides()
            # May contain system env vars, but should not crash
            assert isinstance(overrides, dict)

    def test_string_env_var(self):
        with patch.dict(os.environ, {"AI_PROVIDER": "openai"}, clear=False):
            overrides = load_env_overrides()
            assert overrides.get("ai_provider") == "openai"

    def test_bool_env_var(self):
        with patch.dict(os.environ, {"ENABLE_DAST": "true"}, clear=False):
            overrides = load_env_overrides()
            assert overrides.get("enable_dast") is True

    def test_bool_false(self):
        with patch.dict(os.environ, {"ENABLE_SEMGREP": "false"}, clear=False):
            overrides = load_env_overrides()
            assert overrides.get("enable_semgrep") is False

    def test_int_env_var(self):
        with patch.dict(os.environ, {"MAX_FILES": "200"}, clear=False):
            overrides = load_env_overrides()
            assert overrides.get("max_files") == 200

    def test_float_env_var(self):
        with patch.dict(os.environ, {"COST_LIMIT": "5.5"}, clear=False):
            overrides = load_env_overrides()
            assert overrides.get("cost_limit") == 5.5

    def test_input_prefix(self):
        with patch.dict(os.environ, {"INPUT_AI_PROVIDER": "ollama"}, clear=False):
            overrides = load_env_overrides()
            assert overrides.get("ai_provider") == "ollama"

    def test_first_match_wins(self):
        """Direct env var takes precedence over INPUT_ prefixed."""
        with patch.dict(
            os.environ,
            {"AI_PROVIDER": "anthropic", "INPUT_AI_PROVIDER": "openai"},
            clear=False,
        ):
            overrides = load_env_overrides()
            assert overrides["ai_provider"] == "anthropic"

    def test_invalid_int_ignored(self):
        with patch.dict(os.environ, {"MAX_FILES": "not_a_number"}, clear=False):
            overrides = load_env_overrides()
            assert "max_files" not in overrides  # Should be skipped


# ============================================================================
# Test extract_cli_overrides
# ============================================================================


class TestExtractCliOverrides:
    def test_none_args(self):
        assert extract_cli_overrides(None) == {}

    def test_explicit_args(self):
        args = Namespace(provider="anthropic", model="claude-sonnet-4-5-20250929", max_files=100)
        overrides = extract_cli_overrides(args)
        assert overrides["ai_provider"] == "anthropic"
        assert overrides["model"] == "claude-sonnet-4-5-20250929"
        assert overrides["max_files"] == 100

    def test_none_values_excluded(self):
        args = Namespace(provider=None, model=None, max_files=None)
        overrides = extract_cli_overrides(args)
        assert "ai_provider" not in overrides
        assert "model" not in overrides

    def test_enable_deep_analysis_shorthand(self):
        args = Namespace(enable_deep_analysis=True, deep_analysis_mode=None)
        overrides = extract_cli_overrides(args)
        assert overrides["deep_analysis_mode"] == "conservative"

    def test_explicit_mode_overrides_shorthand(self):
        args = Namespace(enable_deep_analysis=True, deep_analysis_mode="full")
        overrides = extract_cli_overrides(args)
        assert overrides["deep_analysis_mode"] == "full"


# ============================================================================
# Test deep_merge
# ============================================================================


class TestDeepMerge:
    def test_basic_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_none_skipped(self):
        base = {"a": 1, "b": 2}
        override = {"a": None, "b": 3}
        result = deep_merge(base, override)
        assert result["a"] == 1  # None was skipped
        assert result["b"] == 3

    def test_base_unchanged(self):
        base = {"a": 1}
        override = {"a": 2}
        deep_merge(base, override)
        assert base["a"] == 1  # Original not modified


# ============================================================================
# Test build_unified_config
# ============================================================================


class TestBuildUnifiedConfig:
    def test_defaults_only(self):
        config = build_unified_config()
        assert config["ai_provider"] == "auto"
        assert config["enable_semgrep"] is True

    def test_with_profile(self):
        config = build_unified_config(profile="quick")
        assert config["enable_trivy"] is False
        assert config["enable_multi_agent"] is False

    def test_env_overrides_profile(self):
        with patch.dict(os.environ, {"ENABLE_SEMGREP": "false"}, clear=False):
            config = build_unified_config(profile="quick")
            # quick.yml enables semgrep, but env var disables it
            assert config["enable_semgrep"] is False

    def test_cli_overrides_env(self):
        args = Namespace(provider="openai", max_files=200)
        with patch.dict(os.environ, {"AI_PROVIDER": "anthropic"}, clear=False):
            config = build_unified_config(cli_args=args)
            # CLI should win over env
            assert config["ai_provider"] == "openai"
            assert config["max_files"] == 200

    def test_full_merge_chain(self):
        """Profile + env + CLI all participate."""
        args = Namespace(cost_limit=2.0)
        with patch.dict(os.environ, {"ENABLE_DAST": "true"}, clear=False):
            config = build_unified_config(profile="quick", cli_args=args)
            assert config["enable_dast"] is True  # from env
            assert config["cost_limit"] == 2.0  # from CLI (overrides profile's 0.15)

    def test_argus_profile_env_var(self):
        """ARGUS_PROFILE env var should select profile."""
        with patch.dict(os.environ, {"ARGUS_PROFILE": "deep"}, clear=False):
            config = build_unified_config()
            assert config["cost_limit"] == 10.0

    def test_nonexistent_profile_warning(self):
        """Nonexistent profile should not crash, just warn."""
        config = build_unified_config(profile="totally_fake")
        # Should fall back to defaults
        assert config["ai_provider"] == "auto"


# ============================================================================
# Test validate_config
# ============================================================================


class TestValidateConfig:
    def test_valid_config(self):
        config = get_default_config()
        config["anthropic_api_key"] = "test-key"
        config["ai_provider"] = "anthropic"
        issues = validate_config(config)
        assert all("ERROR" not in i for i in issues)

    def test_missing_api_key(self):
        config = get_default_config()
        config["ai_provider"] = "anthropic"
        config["anthropic_api_key"] = ""
        issues = validate_config(config)
        assert any("ANTHROPIC_API_KEY" in i for i in issues)

    def test_invalid_provider(self):
        config = get_default_config()
        config["ai_provider"] = "invalid_provider"
        issues = validate_config(config)
        assert any("Invalid ai_provider" in i for i in issues)

    def test_invalid_multi_agent_mode(self):
        config = get_default_config()
        config["multi_agent_mode"] = "invalid"
        issues = validate_config(config)
        assert any("multi_agent_mode" in i for i in issues)

    def test_collaborative_without_multi_agent(self):
        config = get_default_config()
        config["enable_collaborative_reasoning"] = True
        config["enable_multi_agent"] = False
        issues = validate_config(config)
        assert any("collaborative_reasoning" in i for i in issues)

    def test_negative_cost_limit(self):
        config = get_default_config()
        config["cost_limit"] = -1.0
        issues = validate_config(config)
        assert any("cost_limit" in i for i in issues)


# ============================================================================
# Test list_available_profiles
# ============================================================================


class TestListAvailableProfiles:
    def test_returns_list(self):
        profiles = list_available_profiles()
        assert isinstance(profiles, list)

    def test_built_in_profiles_found(self):
        profiles = list_available_profiles()
        expected = ["quick", "standard", "deep", "backend-api", "frontend",
                     "infrastructure", "secrets-only"]
        for name in expected:
            assert name in profiles, f"Profile '{name}' not found"

    def test_sorted(self):
        profiles = list_available_profiles()
        assert profiles == sorted(profiles)


# ============================================================================
# Test E2E: Profile -> Config -> Validation
# ============================================================================


class TestE2EConfigProfiles:
    def test_every_profile_produces_valid_config(self):
        """Every built-in profile should produce a valid config (no ERRORs)."""
        for profile_name in list_available_profiles():
            config = build_unified_config(profile=profile_name)
            issues = validate_config(config)
            errors = [i for i in issues if i.startswith("ERROR")]
            # Allow warnings (e.g., no API key), but no structural errors
            # except API key warnings which are expected in test env
            non_key_errors = [
                e for e in errors
                if "API_KEY" not in e and "ANTHROPIC_API_KEY" not in e
                and "OPENAI_API_KEY" not in e
            ]
            assert not non_key_errors, (
                f"Profile '{profile_name}' has config errors: {non_key_errors}"
            )

    def test_quick_is_cheaper_than_deep(self):
        quick = build_unified_config(profile="quick")
        deep = build_unified_config(profile="deep")
        assert quick["cost_limit"] < deep["cost_limit"]
        assert quick["max_files"] < deep["max_files"]

    def test_secrets_only_disables_everything(self):
        config = build_unified_config(profile="secrets-only")
        assert config["enable_semgrep"] is False
        assert config["enable_trivy"] is False
        assert config["enable_ai_enrichment"] is False
        assert config["enable_multi_agent"] is False
        # Regression: generate_security_tests must NOT get enable_ prefix
        assert config["generate_security_tests"] is False
