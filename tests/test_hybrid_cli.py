"""Tests for hybrid/cli.py — flag semantics, env var resolution, defaults."""

import argparse
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from hybrid.cli import get_bool_env


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

    def test_last_flag_wins(self, parser):
        args = parser.parse_args([".", "--enable-dast", "--no-enable-dast"])
        assert args.enable_dast is False


class TestFlagResolution:
    """Verify: CLI > env var > config_loader default."""

    def test_cli_true_overrides_env_false(self):
        cli_val = True
        with patch.dict(os.environ, {"ENABLE_SEMGREP": "false"}):
            result = cli_val if cli_val is not None else get_bool_env("ENABLE_SEMGREP", True)
        assert result is True

    def test_cli_false_overrides_env_true(self):
        cli_val = False
        with patch.dict(os.environ, {"ENABLE_SEMGREP": "true"}):
            result = cli_val if cli_val is not None else get_bool_env("ENABLE_SEMGREP", True)
        assert result is False

    def test_absent_cli_falls_to_env(self):
        cli_val = None
        with patch.dict(os.environ, {"ENABLE_DAST": "true"}):
            result = cli_val if cli_val is not None else get_bool_env("ENABLE_DAST", False)
        assert result is True

    def test_absent_cli_and_env_falls_to_default(self):
        cli_val = None
        env = {k: v for k, v in os.environ.items() if k != "ENABLE_DAST"}
        with patch.dict(os.environ, env, clear=True):
            result = cli_val if cli_val is not None else get_bool_env("ENABLE_DAST", False)
        assert result is False


class TestDefaultAlignment:
    """CLI defaults should match config_loader for expensive features."""

    def test_dast_defaults_off(self):
        from config_loader import get_default_config
        assert get_default_config()["enable_dast"] is False

    def test_fuzzing_defaults_off(self):
        from config_loader import get_default_config
        assert get_default_config()["enable_fuzzing"] is False

    def test_runtime_security_defaults_off(self):
        from config_loader import get_default_config
        assert get_default_config()["enable_runtime_security"] is False

    def test_collaborative_reasoning_defaults_off(self):
        from config_loader import get_default_config
        assert get_default_config()["enable_collaborative_reasoning"] is False


class TestCLISourceFileIntegrity:
    """Verify the actual cli.py file has correct patterns."""

    @pytest.fixture(scope="class")
    def cli_source(self):
        return Path(__file__).resolve().parents[1] / "scripts" / "hybrid" / "cli.py"

    def test_no_store_true_with_default_true(self, cli_source):
        content = cli_source.read_text()
        import re
        # Find store_true with default=True — these are broken flags
        matches = re.findall(
            r'action="store_true".*default=True|default=True.*action="store_true"',
            content
        )
        assert not matches, (
            f"Found {len(matches)} store_true+default=True flags (permanently stuck on):\n"
            + "\n".join(matches)
        )

    def test_uses_boolean_optional_action(self, cli_source):
        content = cli_source.read_text()
        assert "BooleanOptionalAction" in content, (
            "cli.py should use argparse.BooleanOptionalAction for toggle flags"
        )

    def test_no_args_dot_enable_in_analyzer_constructor(self, cli_source):
        content = cli_source.read_text()
        import re
        # After the fix, the analyzer constructor should not use args.enable_*
        # Find the HybridSecurityAnalyzer( block
        match = re.search(
            r'HybridSecurityAnalyzer\((.*?)\)', content, re.DOTALL
        )
        if match:
            constructor_block = match.group(1)
            args_refs = re.findall(r'args\.enable_\w+', constructor_block)
            assert not args_refs, (
                f"Analyzer constructor still uses args.enable_* directly "
                f"(bypasses env var layer): {args_refs}"
            )
