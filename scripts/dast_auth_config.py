"""Config-Driven DAST Authentication for Argus Security Pipeline.

Provides YAML-based auth configuration for DAST scanning with TOTP support.

Usage:
    from dast_auth_config import load_dast_auth_config, DASTAuthConfig

    config = load_dast_auth_config(".argus/dast-auth.yml")
    if config.has_totp():
        code = config.generate_totp()
    steps = config.render_login_flow()
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import struct
import time
from base64 import b32decode
from dataclasses import dataclass, field
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Valid login types — aligned with zap_agent.AuthType plus SSO/API variants
VALID_LOGIN_TYPES = {"form", "sso", "api", "basic", "bearer", "none"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# Security patterns to block in config values
DANGEROUS_PATTERNS = [
    r"\.\./",           # path traversal
    r"\.\.\\",          # path traversal (windows)
    r"<script",         # XSS
    r"javascript:",     # XSS
    r"\$\(",            # command substitution
    r"`",               # backtick command substitution
    r";\s*rm\s",        # command injection
    r"\|\s*sh",         # pipe to shell
]


@dataclass
class DASTAuthConfig:
    """DAST authentication configuration.

    Attributes:
        login_type: Authentication method (form, sso, api, basic, bearer, none).
        login_url: URL of the login page or auth endpoint.
        credentials: Dict with username, password, and optional totp_secret.
        login_flow: Natural-language steps describing the login sequence.
        success_condition: Dict with type/value describing how to verify login.
        headers: Custom HTTP headers to inject into authenticated requests.
        cookies: Pre-set cookies for session establishment.
    """

    login_type: str = "none"
    login_url: str = ""
    credentials: dict[str, str] = field(default_factory=dict)
    login_flow: list[str] = field(default_factory=list)
    success_condition: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def has_totp(self) -> bool:
        """Check if TOTP secret is configured."""
        return bool(self.credentials.get("totp_secret"))

    def generate_totp(self, timestamp: float | None = None) -> str:
        """Generate TOTP code using RFC 6238.

        Args:
            timestamp: Unix timestamp (default: current time). Used for testing.

        Returns:
            6-digit TOTP code string.

        Raises:
            ValueError: If no TOTP secret is configured or secret is invalid.
        """
        secret = self.credentials.get("totp_secret", "")
        if not secret:
            raise ValueError("No TOTP secret configured")

        # Validate base32 encoding
        if not re.match(r"^[A-Z2-7]+=*$", secret.upper()):
            raise ValueError("Invalid base32 TOTP secret")

        # RFC 6238 TOTP implementation
        if timestamp is None:
            timestamp = time.time()

        time_step = int(timestamp) // 30
        # Strip existing padding before adding computed padding
        stripped = secret.upper().rstrip("=")
        key = b32decode(stripped + "=" * (-len(stripped) % 8))
        msg = struct.pack(">Q", time_step)
        hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        truncated = (
            struct.unpack(">I", hmac_hash[offset : offset + 4])[0] & 0x7FFFFFFF
        )
        code = truncated % 1_000_000
        return f"{code:06d}"

    def render_login_flow(self) -> list[str]:
        """Substitute $username, $password, $totp into login_flow steps.

        Returns:
            List of rendered step strings with variables replaced.
        """
        rendered: list[str] = []
        totp_code = self.generate_totp() if self.has_totp() else ""

        substitutions = {
            "$username": self.credentials.get("username", ""),
            "$password": self.credentials.get("password", ""),
            "$totp": totp_code,
        }

        for step in self.login_flow:
            rendered_step = step
            for var, value in substitutions.items():
                rendered_step = rendered_step.replace(var, value)
            rendered.append(rendered_step)

        return rendered


@dataclass
class DASTRules:
    """DAST scanning rules: paths to avoid or focus on.

    Attributes:
        avoid: Paths or subdomains the scanner should skip.
        focus: Paths or subdomains the scanner should prioritise.
    """

    avoid: list[dict[str, str]] = field(default_factory=list)
    focus: list[dict[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Security validation
# ---------------------------------------------------------------------------


def validate_config_security(config_dict: dict[str, Any]) -> list[str]:
    """Check config values for security issues (injection, traversal).

    Args:
        config_dict: Raw parsed YAML dictionary.

    Returns:
        List of error strings. Empty list means no issues found.
    """
    errors: list[str] = []

    def _check_value(key: str, value: Any) -> None:
        if isinstance(value, str):
            for pattern in DANGEROUS_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    errors.append(
                        f"Dangerous pattern in '{key}': matches '{pattern}'"
                    )
        elif isinstance(value, dict):
            for k, v in value.items():
                _check_value(f"{key}.{k}", v)
        elif isinstance(value, list):
            for i, v in enumerate(value):
                _check_value(f"{key}[{i}]", v)

    for key, value in config_dict.items():
        _check_value(key, value)

    return errors


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_dast_auth_config(config_path: str) -> DASTAuthConfig:
    """Load and validate DAST auth config from YAML file.

    Args:
        config_path: Path to the YAML auth config file.

    Returns:
        Validated DASTAuthConfig instance.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        ValueError: If config has security issues or invalid values.
    """
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"DAST auth config not found: {config_path}")

    with open(config_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError("DAST auth config must be a YAML mapping")

    # Security validation
    security_errors = validate_config_security(raw)
    if security_errors:
        raise ValueError(
            f"Security validation failed: {'; '.join(security_errors)}"
        )

    # Validate login_type
    login_type = raw.get("login_type", "none")
    if login_type not in VALID_LOGIN_TYPES:
        raise ValueError(
            f"Invalid login_type: {login_type}. "
            f"Must be one of: {VALID_LOGIN_TYPES}"
        )

    return DASTAuthConfig(
        login_type=login_type,
        login_url=raw.get("login_url", ""),
        credentials=raw.get("credentials", {}),
        login_flow=raw.get("login_flow", []),
        success_condition=raw.get("success_condition", {}),
        headers=raw.get("headers", {}),
        cookies=raw.get("cookies", {}),
    )
