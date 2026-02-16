"""Tests to ensure config defaults are consistent across all config sources.

Validates that scripts/config_loader.py (canonical source) and
scripts/orchestrator/config.py agree on shared default values,
preventing silent mismatches that affect runtime behavior.
"""

import os
import sys
from unittest.mock import patch

# Ensure project root is on the path so imports resolve correctly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))


def _get_canonical_defaults():
    """Load defaults from config_loader.py (the canonical source)."""
    from config_loader import get_default_config

    return get_default_config()


def _get_orchestrator_defaults():
    """Load defaults from orchestrator/config.py by calling load_config_from_env
    with no env vars set for the keys we care about.
    """
    # Clear all env vars that could influence config defaults
    env_vars_to_clear = [
        "MAX_FILES",
        "INPUT_MAX_FILES",
        "MAX_FILE_SIZE",
        "INPUT_MAX_FILE_SIZE",
        "MAX_TOKENS",
        "INPUT_MAX_TOKENS",
        "COST_LIMIT",
        "INPUT_COST_LIMIT",
        "AI_PROVIDER",
        "INPUT_AI_PROVIDER",
        "MODEL",
        "INPUT_MODEL",
        "MULTI_AGENT_MODE",
        "INPUT_MULTI_AGENT_MODE",
        "ONLY_CHANGED",
        "INPUT_ONLY_CHANGED",
        "INCLUDE_PATHS",
        "INPUT_INCLUDE_PATHS",
        "EXCLUDE_PATHS",
        "INPUT_EXCLUDE_PATHS",
        "FAIL_ON",
        "INPUT_FAIL_ON",
        "CONSENSUS_THRESHOLD",
        "ENABLE_THREAT_MODELING",
        "ENABLE_SANDBOX_VALIDATION",
        "ENABLE_HEURISTICS",
        "ENABLE_CONSENSUS",
        "SEMGREP_ENABLED",
    ]

    clean_env = {k: v for k, v in os.environ.items() if k not in env_vars_to_clear}

    with patch.dict(os.environ, clean_env, clear=True):
        from orchestrator.config import load_config_from_env

        return load_config_from_env()


class TestConfigDefaultsAlignment:
    """Ensure config_loader.py and orchestrator/config.py agree on defaults."""

    def test_max_files_default_matches(self):
        """max_files must be 50 in both config sources."""
        canonical = _get_canonical_defaults()
        orchestrator = _get_orchestrator_defaults()

        # config_loader stores as int, orchestrator stores as string
        assert canonical["max_files"] == 50, (
            f"config_loader.py max_files default should be 50, got {canonical['max_files']}"
        )
        assert int(orchestrator["max_files"]) == 50, (
            f"orchestrator/config.py max_files default should be 50, got {orchestrator['max_files']}"
        )

    def test_max_file_size_default_matches(self):
        """max_file_size must agree across config sources."""
        canonical = _get_canonical_defaults()
        orchestrator = _get_orchestrator_defaults()

        assert canonical["max_file_size"] == 50000
        assert int(orchestrator["max_file_size"]) == 50000

    def test_max_tokens_default_matches(self):
        """max_tokens must agree across config sources."""
        canonical = _get_canonical_defaults()
        orchestrator = _get_orchestrator_defaults()

        assert canonical["max_tokens"] == 8000
        assert int(orchestrator["max_tokens"]) == 8000

    def test_cost_limit_default_matches(self):
        """cost_limit must agree across config sources."""
        canonical = _get_canonical_defaults()
        orchestrator = _get_orchestrator_defaults()

        assert canonical["cost_limit"] == 1.0
        assert float(orchestrator["cost_limit"]) == 1.0

    def test_ai_provider_default_matches(self):
        """ai_provider must be 'auto' in both config sources."""
        canonical = _get_canonical_defaults()
        orchestrator = _get_orchestrator_defaults()

        assert canonical["ai_provider"] == "auto"
        assert orchestrator["ai_provider"] == "auto"

    def test_consensus_threshold_default_matches(self):
        """consensus_threshold must agree across config sources."""
        canonical = _get_canonical_defaults()
        orchestrator = _get_orchestrator_defaults()

        assert canonical["consensus_threshold"] == 0.5
        assert float(orchestrator["consensus_threshold"]) == 0.5

    def test_multi_agent_mode_default_matches(self):
        """multi_agent_mode must be 'single' in both config sources."""
        canonical = _get_canonical_defaults()
        orchestrator = _get_orchestrator_defaults()

        assert canonical["multi_agent_mode"] == "single"
        assert orchestrator["multi_agent_mode"] == "single"


class TestCanonicalConfigCompleteness:
    """Verify canonical config_loader.py has all expected keys."""

    def test_max_files_is_integer(self):
        """max_files should be stored as int in canonical config."""
        canonical = _get_canonical_defaults()
        assert isinstance(canonical["max_files"], int)

    def test_all_shared_keys_present_in_canonical(self):
        """Every key in orchestrator config must exist in canonical config."""
        canonical = _get_canonical_defaults()
        orchestrator = _get_orchestrator_defaults()

        # Keys that exist only in orchestrator (not in canonical) -- known exceptions
        orchestrator_only_keys = {
            "foundation_sec_enabled",
            "foundation_sec_model",
            "foundation_sec_device",
            "category_passes",
        }

        for key in orchestrator:
            if key in orchestrator_only_keys:
                continue
            assert key in canonical, (
                f"Key '{key}' exists in orchestrator/config.py but not in "
                f"config_loader.py get_default_config(). Add it to the canonical source."
            )
