"""Tests for config_loader.py — profile precedence, env overrides, extends."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import config_loader


class TestProfileSearchPaths:
    """_profile_search_paths returns paths in correct priority order."""

    def test_project_local_first(self):
        paths = config_loader._profile_search_paths("standard")
        path_strs = [str(p) for p in paths]
        # First path should be project-local (.argus/profiles/...)
        assert ".argus" in path_strs[0] and "profiles" in path_strs[0]
        # It should NOT start with the project root's profiles/ dir
        assert not path_strs[0].startswith(str(config_loader.PROJECT_ROOT / "profiles"))

    def test_builtin_last(self):
        paths = config_loader._profile_search_paths("standard")
        # Last path should be the built-in (PROJECT_ROOT/profiles/...)
        assert str(paths[-1]).startswith(str(config_loader.PROJECT_ROOT))

    def test_returns_three_paths(self):
        paths = config_loader._profile_search_paths("deep")
        assert len(paths) == 3


class TestProfilePrecedence:
    """Verify that project-local profiles override built-in profiles."""

    def test_project_local_overrides_builtin(self, tmp_path):
        project_profile = tmp_path / ".argus" / "profiles" / "test-profile.yml"
        project_profile.parent.mkdir(parents=True)
        project_profile.write_text(
            yaml.dump({"scanners": {"semgrep": False}, "limits": {"max_files": 999}})
        )

        builtin_profile = tmp_path / "builtin" / "profiles" / "test-profile.yml"
        builtin_profile.parent.mkdir(parents=True)
        builtin_profile.write_text(
            yaml.dump({"scanners": {"semgrep": True}, "limits": {"max_files": 50}})
        )

        def mock_search_paths(name):
            return [
                tmp_path / ".argus" / "profiles" / f"{name}.yml",
                tmp_path / "user" / "profiles" / f"{name}.yml",
                tmp_path / "builtin" / "profiles" / f"{name}.yml",
            ]

        with patch.object(config_loader, "_profile_search_paths", mock_search_paths):
            flat = config_loader.load_profile("test-profile")

        assert flat["enable_semgrep"] is False, "Project-local should override built-in"
        assert flat["max_files"] == 999

    def test_builtin_used_when_no_local(self, tmp_path):
        builtin_profile = tmp_path / "builtin" / "profiles" / "test-profile.yml"
        builtin_profile.parent.mkdir(parents=True)
        builtin_profile.write_text(
            yaml.dump({"scanners": {"semgrep": True}})
        )

        def mock_search_paths(name):
            return [
                tmp_path / ".argus" / "profiles" / f"{name}.yml",
                tmp_path / "user" / "profiles" / f"{name}.yml",
                tmp_path / "builtin" / "profiles" / f"{name}.yml",
            ]

        with patch.object(config_loader, "_profile_search_paths", mock_search_paths):
            flat = config_loader.load_profile("test-profile")

        assert flat["enable_semgrep"] is True

    def test_user_overrides_builtin(self, tmp_path):
        user_profile = tmp_path / "user" / "profiles" / "test-profile.yml"
        user_profile.parent.mkdir(parents=True)
        user_profile.write_text(
            yaml.dump({"limits": {"max_files": 500}})
        )

        builtin_profile = tmp_path / "builtin" / "profiles" / "test-profile.yml"
        builtin_profile.parent.mkdir(parents=True)
        builtin_profile.write_text(
            yaml.dump({"limits": {"max_files": 50}})
        )

        def mock_search_paths(name):
            return [
                tmp_path / ".argus" / "profiles" / f"{name}.yml",
                tmp_path / "user" / "profiles" / f"{name}.yml",
                tmp_path / "builtin" / "profiles" / f"{name}.yml",
            ]

        with patch.object(config_loader, "_profile_search_paths", mock_search_paths):
            flat = config_loader.load_profile("test-profile")

        assert flat["max_files"] == 500


class TestExtendsInheritance:
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

        assert flat["enable_semgrep"] is False
        assert flat["enable_trivy"] is True
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
    def test_env_overrides_value(self):
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
    def test_defaults_present(self):
        config = config_loader.build_unified_config()
        assert "enable_semgrep" in config
        assert config["enable_semgrep"] is True

    def test_env_overrides_defaults(self):
        with patch.dict(os.environ, {"ENABLE_SEMGREP": "false"}, clear=False):
            config = config_loader.build_unified_config()
        assert config["enable_semgrep"] is False


def test_max_files_default_matches_across_modules():
    """max_files default should be consistent between config_loader and orchestrator/config."""
    from config_loader import get_default_config
    from orchestrator.config import load_config_from_env

    cl_config = get_default_config()
    orch_config = load_config_from_env()

    assert int(cl_config.get("max_files", 0)) == int(orch_config.get("max_files", 0))


class TestConfigLoaderEnvOverrideTypes:
    """Verify env var overrides are coerced to the correct Python types."""

    def test_max_files_env_override_int(self, monkeypatch):
        """MAX_FILES env var should be coerced to int, not remain a string."""
        # Clean any pre-existing env vars that might interfere
        monkeypatch.delenv("MAX_FILES", raising=False)
        monkeypatch.delenv("INPUT_MAX_FILES", raising=False)
        monkeypatch.delenv("ARGUS_PROFILE", raising=False)

        monkeypatch.setenv("MAX_FILES", "200")
        config = config_loader.build_unified_config()
        assert config["max_files"] == 200
        assert isinstance(config["max_files"], int)

    def test_bool_env_true_parsing(self, monkeypatch):
        """ENABLE_EPSS_SCORING=true should parse to Python True (bool)."""
        monkeypatch.delenv("ENABLE_EPSS_SCORING", raising=False)
        monkeypatch.delenv("ARGUS_PROFILE", raising=False)

        monkeypatch.setenv("ENABLE_EPSS_SCORING", "true")
        config = config_loader.build_unified_config()
        assert config["enable_epss_scoring"] is True

    def test_bool_env_false_parsing(self, monkeypatch):
        """ENABLE_EPSS_SCORING=false should parse to Python False (bool)."""
        monkeypatch.delenv("ENABLE_EPSS_SCORING", raising=False)
        monkeypatch.delenv("ARGUS_PROFILE", raising=False)

        monkeypatch.setenv("ENABLE_EPSS_SCORING", "false")
        config = config_loader.build_unified_config()
        assert config["enable_epss_scoring"] is False

    def test_float_env_parsing(self, monkeypatch):
        """COST_LIMIT=5.50 should parse to Python float 5.50."""
        monkeypatch.delenv("COST_LIMIT", raising=False)
        monkeypatch.delenv("INPUT_COST_LIMIT", raising=False)
        monkeypatch.delenv("ARGUS_PROFILE", raising=False)

        monkeypatch.setenv("COST_LIMIT", "5.50")
        config = config_loader.build_unified_config()
        assert config["cost_limit"] == 5.50
        assert isinstance(config["cost_limit"], float)


class TestConfigValidationEdgeCases:
    """Edge-case validation: boundary values that should be flagged."""

    def test_max_files_zero_is_invalid(self):
        """max_files=0 should produce a validation error (must be >= 1)."""
        issues = config_loader.validate_config({"max_files": 0})
        assert any("max_files" in issue for issue in issues), (
            f"Expected an error about max_files, got: {issues}"
        )

    def test_negative_cost_limit_is_invalid(self):
        """cost_limit=-1 should produce a validation error (must be >= 0)."""
        issues = config_loader.validate_config({"cost_limit": -1})
        assert any("cost_limit" in issue for issue in issues), (
            f"Expected an error about cost_limit, got: {issues}"
        )
