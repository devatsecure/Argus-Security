"""Lightweight schema validation for external data in the Argus Security pipeline.

Validates LLM responses, scanner output, and security findings from untrusted
sources without any external dependencies (no jsonschema, no pydantic).

Usage::

    from schema_validator import validate_finding, validate_scanner_output

    finding = validate_finding({"severity": "HIGH", "message": "SQL injection"})
    output = validate_scanner_output(raw_data, scanner_name="semgrep")
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

VALID_SEVERITIES: set[str] = {"critical", "high", "medium", "low", "info"}


class ValidationError(Exception):
    """Raised when external data fails schema validation."""


def validate_finding(data: dict[str, Any]) -> dict[str, Any]:
    """Validate a security finding has required fields.

    Normalizes severity to lowercase; defaults unknown values to ``"medium"``.
    """
    if not isinstance(data, dict):
        raise ValidationError(f"Finding must be a dict, got {type(data).__name__}")
    for key in ("severity", "message"):
        if key not in data:
            raise ValidationError(f"Finding missing required field: {key}")
    severity = str(data["severity"]).lower().strip()
    if severity not in VALID_SEVERITIES:
        logger.warning("Unknown severity %r, defaulting to 'medium'", data["severity"])
        severity = "medium"
    return {**data, "severity": severity}


def validate_scanner_output(data: dict[str, Any], scanner_name: str) -> dict[str, Any]:
    """Validate scanner output is a dict with an optional ``findings`` list."""
    if not isinstance(data, dict):
        raise ValidationError(
            f"Scanner output from {scanner_name} must be a dict, got {type(data).__name__}"
        )
    if "findings" in data and not isinstance(data["findings"], list):
        raise ValidationError(
            f"Scanner {scanner_name}: 'findings' must be a list, "
            f"got {type(data['findings']).__name__}"
        )
    return data


def validate_llm_response(
    data: Any, expected_keys: set[str] | None = None
) -> dict[str, Any]:
    """Validate a parsed LLM JSON response is a dict.

    Warns about any *expected_keys* that are absent from the response.
    """
    if not isinstance(data, dict):
        raise ValidationError(
            f"LLM response must be a dict, got {type(data).__name__}"
        )
    if expected_keys:
        missing = expected_keys - data.keys()
        if missing:
            logger.warning("LLM response missing expected keys: %s", sorted(missing))
    return data
