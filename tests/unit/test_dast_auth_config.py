"""Tests for dast_auth_config module.

Covers DASTAuthConfig (TOTP generation, login flow rendering),
validate_config_security (injection detection), load_dast_auth_config
(YAML loading), and DASTRules dataclass.
"""
import sys
from pathlib import Path

# Add scripts directory to path
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import os
import tempfile

import pytest
import yaml

from dast_auth_config import (
    DASTAuthConfig,
    DASTRules,
    VALID_LOGIN_TYPES,
    VALID_SEVERITIES,
    DANGEROUS_PATTERNS,
    load_dast_auth_config,
    validate_config_security,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(tmp_path: Path, data: dict, filename: str = "auth.yml") -> str:
    """Write a dict to a YAML file and return its path as a string."""
    filepath = tmp_path / filename
    filepath.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
    return str(filepath)


# ---------------------------------------------------------------------------
# TestDASTAuthConfig
# ---------------------------------------------------------------------------


class TestDASTAuthConfig:
    """Tests for the DASTAuthConfig dataclass."""

    def test_defaults(self):
        """Default values should be safe no-op settings."""
        config = DASTAuthConfig()
        assert config.login_type == "none"
        assert config.login_url == ""
        assert config.credentials == {}
        assert config.login_flow == []
        assert config.success_condition == {}
        assert config.headers == {}
        assert config.cookies == {}

    def test_has_totp_with_secret(self):
        """has_totp returns True when a totp_secret is present."""
        config = DASTAuthConfig(credentials={"totp_secret": "JBSWY3DPEHPK3PXP"})
        assert config.has_totp() is True

    def test_has_totp_without_secret(self):
        """has_totp returns False when no totp_secret is present."""
        config = DASTAuthConfig(credentials={"username": "admin"})
        assert config.has_totp() is False

    def test_has_totp_empty_secret(self):
        """has_totp returns False for an empty string secret."""
        config = DASTAuthConfig(credentials={"totp_secret": ""})
        assert config.has_totp() is False

    def test_generate_totp_deterministic(self):
        """TOTP generation with a known secret and timestamp is deterministic."""
        config = DASTAuthConfig(
            credentials={"totp_secret": "JBSWY3DPEHPK3PXP"}
        )
        code = config.generate_totp(timestamp=1234567890)
        assert code == "742275"

    def test_generate_totp_returns_six_digits(self):
        """TOTP code is always exactly 6 characters, zero-padded."""
        config = DASTAuthConfig(
            credentials={"totp_secret": "JBSWY3DPEHPK3PXP"}
        )
        code = config.generate_totp(timestamp=1234567890)
        assert len(code) == 6
        assert code.isdigit()

    def test_generate_totp_different_timestamps_differ(self):
        """Different time steps produce different codes (with high probability)."""
        config = DASTAuthConfig(
            credentials={"totp_secret": "JBSWY3DPEHPK3PXP"}
        )
        code_a = config.generate_totp(timestamp=1234567890)
        code_b = config.generate_totp(timestamp=1234567890 + 30)
        # They could theoretically collide, but for these known values they differ.
        assert code_a != code_b

    def test_generate_totp_no_secret_raises(self):
        """generate_totp raises ValueError when no secret is configured."""
        config = DASTAuthConfig(credentials={})
        with pytest.raises(ValueError, match="No TOTP secret configured"):
            config.generate_totp()

    def test_generate_totp_invalid_secret_raises(self):
        """generate_totp raises ValueError for a non-base32 secret."""
        config = DASTAuthConfig(credentials={"totp_secret": "not!valid!base32"})
        with pytest.raises(ValueError, match="Invalid base32 TOTP secret"):
            config.generate_totp()

    def test_generate_totp_secret_with_padding(self):
        """TOTP generation works even if secret has trailing padding."""
        config = DASTAuthConfig(
            credentials={"totp_secret": "JBSWY3DPEHPK3PXP="}
        )
        # Should not raise — padding is acceptable base32
        code = config.generate_totp(timestamp=1234567890)
        assert len(code) == 6
        assert code.isdigit()

    def test_render_login_flow_substitution(self):
        """Variables in login_flow steps are replaced with credential values."""
        config = DASTAuthConfig(
            credentials={
                "username": "admin",
                "password": "s3cret",
                "totp_secret": "JBSWY3DPEHPK3PXP",
            },
            login_flow=[
                "Navigate to login page",
                "Enter $username in the username field",
                "Enter $password in the password field",
                "Enter $totp in the MFA field",
                "Click Login",
            ],
        )
        rendered = config.render_login_flow()

        assert len(rendered) == 5
        assert rendered[0] == "Navigate to login page"
        assert rendered[1] == "Enter admin in the username field"
        assert rendered[2] == "Enter s3cret in the password field"
        # $totp is replaced with a 6-digit code
        assert "$totp" not in rendered[3]
        assert "Enter " in rendered[3]
        assert " in the MFA field" in rendered[3]
        assert rendered[4] == "Click Login"

    def test_render_login_flow_without_totp(self):
        """Login flow renders correctly when there is no TOTP secret."""
        config = DASTAuthConfig(
            credentials={"username": "user1", "password": "pass1"},
            login_flow=[
                "Type $username",
                "Type $password",
                "Submit",
            ],
        )
        rendered = config.render_login_flow()

        assert rendered[0] == "Type user1"
        assert rendered[1] == "Type pass1"
        assert rendered[2] == "Submit"

    def test_render_login_flow_empty(self):
        """Empty login_flow produces empty list."""
        config = DASTAuthConfig()
        assert config.render_login_flow() == []

    def test_render_login_flow_no_variables(self):
        """Steps without variable placeholders are returned unchanged."""
        config = DASTAuthConfig(
            login_flow=["Open browser", "Navigate to /app"]
        )
        rendered = config.render_login_flow()
        assert rendered == ["Open browser", "Navigate to /app"]


# ---------------------------------------------------------------------------
# TestValidateConfigSecurity
# ---------------------------------------------------------------------------


class TestValidateConfigSecurity:
    """Tests for validate_config_security."""

    def test_clean_config_passes(self):
        """A normal config with no dangerous patterns returns no errors."""
        config = {
            "login_type": "form",
            "login_url": "https://example.com/login",
            "credentials": {"username": "admin", "password": "hunter2"},
        }
        errors = validate_config_security(config)
        assert errors == []

    def test_path_traversal_blocked(self):
        """Path traversal sequences are detected."""
        config = {"login_url": "https://example.com/../etc/passwd"}
        errors = validate_config_security(config)
        assert len(errors) >= 1
        assert any("Dangerous pattern" in e for e in errors)

    def test_windows_path_traversal_blocked(self):
        """Windows-style path traversal is detected."""
        config = {"login_url": "https://example.com/..\\windows\\system32"}
        errors = validate_config_security(config)
        assert len(errors) >= 1

    def test_script_injection_blocked(self):
        """XSS script tags are detected."""
        config = {"login_url": "<script>alert(1)</script>"}
        errors = validate_config_security(config)
        assert len(errors) >= 1
        assert any("<script" in e for e in errors)

    def test_javascript_uri_blocked(self):
        """javascript: URIs are detected."""
        config = {"login_url": "javascript:alert(1)"}
        errors = validate_config_security(config)
        assert len(errors) >= 1

    def test_command_substitution_blocked(self):
        """Shell command substitution is detected."""
        config = {"credentials": {"username": "$(whoami)"}}
        errors = validate_config_security(config)
        assert len(errors) >= 1

    def test_backtick_blocked(self):
        """Backtick command substitution is detected."""
        config = {"credentials": {"username": "`id`"}}
        errors = validate_config_security(config)
        assert len(errors) >= 1

    def test_command_injection_rm_blocked(self):
        """Command injection with rm is detected."""
        config = {"login_url": "https://example.com; rm -rf /"}
        errors = validate_config_security(config)
        assert len(errors) >= 1

    def test_pipe_to_shell_blocked(self):
        """Piping output to sh is detected."""
        config = {"login_url": "https://example.com | sh"}
        errors = validate_config_security(config)
        assert len(errors) >= 1

    def test_nested_dict_values_checked(self):
        """Dangerous values in nested dicts are detected."""
        config = {
            "credentials": {
                "username": "admin",
                "password": "safe",
                "notes": {"comment": "../../../etc/shadow"},
            }
        }
        errors = validate_config_security(config)
        assert len(errors) >= 1
        assert any("credentials.notes.comment" in e for e in errors)

    def test_list_values_checked(self):
        """Dangerous values in lists are detected."""
        config = {
            "login_flow": [
                "Go to login",
                "<script>steal(cookies)</script>",
            ]
        }
        errors = validate_config_security(config)
        assert len(errors) >= 1
        assert any("login_flow[1]" in e for e in errors)

    def test_non_string_values_ignored(self):
        """Non-string values (ints, bools) don't cause errors."""
        config = {
            "port": 8080,
            "enabled": True,
            "timeout": 30.5,
        }
        errors = validate_config_security(config)
        assert errors == []

    def test_multiple_errors_reported(self):
        """Multiple dangerous patterns produce multiple error entries."""
        config = {
            "url": "../../../etc/passwd",
            "payload": "<script>x</script>",
            "cmd": "$(cat /etc/shadow)",
        }
        errors = validate_config_security(config)
        assert len(errors) >= 3


# ---------------------------------------------------------------------------
# TestLoadDASTAuthConfig
# ---------------------------------------------------------------------------


class TestLoadDASTAuthConfig:
    """Tests for load_dast_auth_config."""

    def test_loads_valid_yaml(self, tmp_path):
        """Valid YAML is loaded into a DASTAuthConfig with correct fields."""
        data = {
            "login_type": "form",
            "login_url": "https://app.example.com/login",
            "credentials": {
                "username": "testuser",
                "password": "testpass",
            },
            "login_flow": [
                "Enter $username",
                "Enter $password",
                "Click Submit",
            ],
            "success_condition": {"type": "url_contains", "value": "/dashboard"},
            "headers": {"X-Custom": "value"},
            "cookies": {"session_hint": "abc123"},
        }
        path = _write_yaml(tmp_path, data)

        config = load_dast_auth_config(path)

        assert config.login_type == "form"
        assert config.login_url == "https://app.example.com/login"
        assert config.credentials["username"] == "testuser"
        assert config.credentials["password"] == "testpass"
        assert len(config.login_flow) == 3
        assert config.success_condition["type"] == "url_contains"
        assert config.headers["X-Custom"] == "value"
        assert config.cookies["session_hint"] == "abc123"

    def test_file_not_found_raises(self):
        """FileNotFoundError raised for missing config path."""
        with pytest.raises(FileNotFoundError, match="DAST auth config not found"):
            load_dast_auth_config("/nonexistent/path/dast-auth.yml")

    def test_invalid_login_type_raises(self, tmp_path):
        """ValueError raised for unrecognised login_type."""
        data = {"login_type": "kerberos"}
        path = _write_yaml(tmp_path, data)

        with pytest.raises(ValueError, match="Invalid login_type"):
            load_dast_auth_config(path)

    def test_security_validation_catches_dangerous_values(self, tmp_path):
        """YAML with dangerous patterns is rejected."""
        data = {
            "login_type": "form",
            "login_url": "https://example.com/../../../etc/passwd",
        }
        path = _write_yaml(tmp_path, data)

        with pytest.raises(ValueError, match="Security validation failed"):
            load_dast_auth_config(path)

    def test_non_mapping_yaml_raises(self, tmp_path):
        """ValueError raised when YAML root is not a mapping."""
        filepath = tmp_path / "bad.yml"
        filepath.write_text("- just\n- a\n- list\n", encoding="utf-8")

        with pytest.raises(ValueError, match="YAML mapping"):
            load_dast_auth_config(str(filepath))

    @pytest.mark.parametrize("login_type", sorted(VALID_LOGIN_TYPES))
    def test_all_login_types_accepted(self, tmp_path, login_type):
        """Every value in VALID_LOGIN_TYPES is accepted without error."""
        data = {"login_type": login_type}
        path = _write_yaml(tmp_path, data)

        config = load_dast_auth_config(path)
        assert config.login_type == login_type

    def test_defaults_for_missing_keys(self, tmp_path):
        """Missing optional keys get their default values."""
        data = {"login_type": "none"}
        path = _write_yaml(tmp_path, data)

        config = load_dast_auth_config(path)
        assert config.login_url == ""
        assert config.credentials == {}
        assert config.login_flow == []
        assert config.success_condition == {}
        assert config.headers == {}
        assert config.cookies == {}

    def test_totp_secret_in_loaded_config(self, tmp_path):
        """A loaded config with totp_secret has working TOTP generation."""
        data = {
            "login_type": "form",
            "credentials": {"totp_secret": "JBSWY3DPEHPK3PXP"},
        }
        path = _write_yaml(tmp_path, data)

        config = load_dast_auth_config(path)
        assert config.has_totp() is True
        code = config.generate_totp(timestamp=1234567890)
        assert code == "742275"


# ---------------------------------------------------------------------------
# TestDASTRules
# ---------------------------------------------------------------------------


class TestDASTRules:
    """Tests for the DASTRules dataclass."""

    def test_default_empty_lists(self):
        """Default DASTRules has empty avoid and focus lists."""
        rules = DASTRules()
        assert rules.avoid == []
        assert rules.focus == []

    def test_avoid_populated(self):
        """avoid list can hold path-skip rules."""
        rules = DASTRules(
            avoid=[
                {"path": "/admin", "reason": "out of scope"},
                {"path": "/logout", "reason": "breaks session"},
            ]
        )
        assert len(rules.avoid) == 2
        assert rules.avoid[0]["path"] == "/admin"

    def test_focus_populated(self):
        """focus list can hold priority path rules."""
        rules = DASTRules(
            focus=[
                {"path": "/api/v1", "reason": "primary API surface"},
            ]
        )
        assert len(rules.focus) == 1
        assert rules.focus[0]["path"] == "/api/v1"

    def test_avoid_and_focus_independent(self):
        """Setting avoid does not affect focus and vice versa."""
        rules = DASTRules(
            avoid=[{"path": "/health"}],
            focus=[{"path": "/api"}],
        )
        assert len(rules.avoid) == 1
        assert len(rules.focus) == 1
        assert rules.avoid[0]["path"] != rules.focus[0]["path"]


# ---------------------------------------------------------------------------
# TestConstants
# ---------------------------------------------------------------------------


class TestConstants:
    """Verify module-level constants are defined correctly."""

    def test_valid_login_types(self):
        """VALID_LOGIN_TYPES has the expected members."""
        expected = {"form", "sso", "api", "basic", "bearer", "none"}
        assert VALID_LOGIN_TYPES == expected

    def test_valid_severities(self):
        """VALID_SEVERITIES has the expected members."""
        expected = {"critical", "high", "medium", "low", "info"}
        assert VALID_SEVERITIES == expected

    def test_dangerous_patterns_non_empty(self):
        """DANGEROUS_PATTERNS is a non-empty list of regex strings."""
        assert len(DANGEROUS_PATTERNS) >= 8
        for p in DANGEROUS_PATTERNS:
            assert isinstance(p, str)
