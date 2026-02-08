#!/usr/bin/env python3
"""
Error Classification + Smart Retry for Argus Security Pipeline.

Classifies LLM API errors into types with different retry strategies:
- billing: retryable, long backoff (60s base)
- rate_limit: retryable, medium backoff (30s base)
- auth: NOT retryable
- config: NOT retryable
- validation: retryable, max 3 attempts
- transient: retryable, exponential backoff (2s base)
- permanent: NOT retryable (fail-safe default)

Usage:
    from error_classifier import classify_llm_error, smart_retry, is_retryable_error

    # Classify an error
    classified = classify_llm_error(some_exception, provider="anthropic")

    # Use as a decorator
    @smart_retry(max_attempts=3, provider="anthropic")
    def call_api():
        ...

    # Check retryability
    if is_retryable_error(error, provider="anthropic"):
        ...
"""

from __future__ import annotations

import functools
import logging
import math
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Error type constants
# ---------------------------------------------------------------------------

ERROR_TYPE_BILLING = "billing"
ERROR_TYPE_RATE_LIMIT = "rate_limit"
ERROR_TYPE_AUTH = "auth"
ERROR_TYPE_CONFIG = "config"
ERROR_TYPE_VALIDATION = "validation"
ERROR_TYPE_TRANSIENT = "transient"
ERROR_TYPE_PERMANENT = "permanent"

# ---------------------------------------------------------------------------
# Pattern registries for error classification
# ---------------------------------------------------------------------------

BILLING_PATTERNS: list[str] = [
    "billing_error",
    "credit balance",
    "insufficient credits",
    "spending cap",
    "spending limit",
    "payment required",
    "quota exceeded",
    "billing",
    "insufficient_quota",
]

RATE_LIMIT_PATTERNS: list[str] = [
    "rate limit",
    "429",
    "too many requests",
    "rate_limit_error",
    "throttled",
    "request limit",
    "requests per minute",
]

AUTH_PATTERNS: list[str] = [
    "invalid api key",
    "authentication",
    "unauthorized",
    "invalid_api_key",
    "permission denied",
    "forbidden",
    "401",
    "403",
    "access denied",
    "invalid x-api-key",
]

CONFIG_PATTERNS: list[str] = [
    "enoent",
    "no such file",
    "configuration",
    "invalid config",
    "not found",
    "missing required",
    "invalid model",
    "model not found",
]

VALIDATION_PATTERNS: list[str] = [
    "output validation failed",
    "invalid response",
    "malformed",
    "invalid json",
    "parse error",
    "schema validation",
    "content filter",
]

TRANSIENT_PATTERNS: list[str] = [
    "network",
    "connection",
    "timeout",
    "timed out",
    "econnreset",
    "econnrefused",
    "server error",
    "5xx",
    "internal server error",
    "service unavailable",
    "overloaded",
    "503",
    "502",
    "500",
    "temporarily unavailable",
    "bad gateway",
    "gateway timeout",
    "504",
]

# Ordered list for classification priority: more specific patterns first
_PATTERN_REGISTRY: list[tuple[str, list[str], bool]] = [
    # (error_type, patterns, retryable)
    (ERROR_TYPE_AUTH, AUTH_PATTERNS, False),
    (ERROR_TYPE_CONFIG, CONFIG_PATTERNS, False),
    (ERROR_TYPE_BILLING, BILLING_PATTERNS, True),
    (ERROR_TYPE_RATE_LIMIT, RATE_LIMIT_PATTERNS, True),
    (ERROR_TYPE_VALIDATION, VALIDATION_PATTERNS, True),
    (ERROR_TYPE_TRANSIENT, TRANSIENT_PATTERNS, True),
]


# ---------------------------------------------------------------------------
# ClassifiedError dataclass
# ---------------------------------------------------------------------------


@dataclass
class ClassifiedError:
    """A classified LLM API error with retry metadata.

    Attributes:
        error_type: One of billing, auth, rate_limit, transient, validation,
                    config, permanent.
        retryable:  Whether this error type should be retried.
        original:   The original exception instance.
        context:    Additional context about the error (e.g. HTTP status).
        provider:   The LLM provider that raised the error.
    """

    error_type: str
    retryable: bool
    original: Exception
    context: dict[str, Any] = field(default_factory=dict)
    provider: str = ""

    def __str__(self) -> str:
        retry_label = "retryable" if self.retryable else "non-retryable"
        return (
            f"ClassifiedError(type={self.error_type}, {retry_label}, "
            f"provider={self.provider!r}, original={self.original!r})"
        )


# ---------------------------------------------------------------------------
# Classification function
# ---------------------------------------------------------------------------


def classify_llm_error(
    error: Exception,
    provider: str = "",
) -> ClassifiedError:
    """Classify an LLM error by pattern-matching the error message.

    The error message (and class name) are matched against known patterns
    in priority order.  If no pattern matches the error is classified as
    ``permanent`` (not retryable) as a fail-safe default.

    Parameters
    ----------
    error:
        The exception to classify.
    provider:
        The LLM provider name (e.g. ``"anthropic"``, ``"openai"``).

    Returns
    -------
    ClassifiedError
        The classified error with type and retryability.
    """
    error_msg = str(error).lower()
    error_class = type(error).__name__.lower()
    combined = f"{error_class} {error_msg}"

    context: dict[str, Any] = {
        "error_class": type(error).__name__,
        "message_length": len(str(error)),
    }

    # Check HTTP status code if available (common in API client exceptions)
    status_code = getattr(error, "status_code", None)
    if status_code is not None:
        context["status_code"] = status_code

    # Pattern matching against known error types (checked first so that
    # specific patterns like "permission denied" or "no such file" are
    # classified correctly before the broad isinstance fallback).
    for error_type, patterns, retryable in _PATTERN_REGISTRY:
        for pattern in patterns:
            if pattern in combined:
                return ClassifiedError(
                    error_type=error_type,
                    retryable=retryable,
                    original=error,
                    context=context,
                    provider=provider,
                )

    # Fallback: network-level connection errors are transient
    if isinstance(error, ConnectionError):
        return ClassifiedError(
            error_type=ERROR_TYPE_TRANSIENT,
            retryable=True,
            original=error,
            context=context,
            provider=provider,
        )

    # Fail-safe: unknown errors are classified as permanent (not retryable)
    return ClassifiedError(
        error_type=ERROR_TYPE_PERMANENT,
        retryable=False,
        original=error,
        context=context,
        provider=provider,
    )


# ---------------------------------------------------------------------------
# Retry delay calculation
# ---------------------------------------------------------------------------


def get_retry_delay(classified: ClassifiedError, attempt: int) -> float:
    """Calculate retry delay based on error type and attempt number.

    Parameters
    ----------
    classified:
        The classified error.
    attempt:
        The attempt number (1-based).

    Returns
    -------
    float
        Delay in seconds before the next retry.
    """
    if classified.error_type == ERROR_TYPE_BILLING:
        # Billing errors: long backoff, max 300s
        delay = 60.0 + attempt * 30.0
        return min(delay, 300.0)

    if classified.error_type == ERROR_TYPE_RATE_LIMIT:
        # Rate limit: medium backoff, max 120s
        delay = 30.0 + attempt * 10.0
        return min(delay, 120.0)

    if classified.error_type == ERROR_TYPE_TRANSIENT:
        # Transient: exponential backoff with jitter, max 30s
        base_delay = math.pow(2, attempt)
        jitter = random.uniform(0, 1)  # noqa: S311
        delay = base_delay + jitter
        return min(delay, 30.0)

    if classified.error_type == ERROR_TYPE_VALIDATION:
        # Validation: fixed 5s delay
        return 5.0

    # Non-retryable types should not reach here, but return 0 as safety
    return 0.0


# ---------------------------------------------------------------------------
# Helper: is_retryable_error
# ---------------------------------------------------------------------------


def is_retryable_error(error: Exception, provider: str = "") -> bool:
    """Check if an error should be retried based on classification.

    Parameters
    ----------
    error:
        The exception to check.
    provider:
        The LLM provider name.

    Returns
    -------
    bool
        True if the error is retryable.
    """
    classified = classify_llm_error(error, provider)
    return classified.retryable


# ---------------------------------------------------------------------------
# Smart retry decorator
# ---------------------------------------------------------------------------


def smart_retry(
    max_attempts: int = 3,
    classifier_fn: Callable[..., ClassifiedError] = classify_llm_error,
    provider: str = "",
) -> Callable:
    """Decorator that replaces @tenacity.retry with classified retry logic.

    If the classified error is not retryable, the error is raised immediately.
    If retryable, the decorator sleeps for ``get_retry_delay()`` seconds and
    retries.  After *max_attempts* total attempts the original error is raised.

    Parameters
    ----------
    max_attempts:
        Maximum number of attempts (including the first call).
    classifier_fn:
        Function to classify errors (default: ``classify_llm_error``).
    provider:
        Default provider name passed to the classifier.

    Returns
    -------
    Callable
        The decorated function with smart retry behaviour.

    Example
    -------
    ::

        @smart_retry(max_attempts=3, provider="anthropic")
        def call_anthropic(prompt):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_error: Exception | None = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    last_error = exc
                    classified = classifier_fn(exc, provider)

                    if not classified.retryable:
                        logger.error(
                            "Non-retryable error (%s) on attempt %d/%d: %s",
                            classified.error_type,
                            attempt,
                            max_attempts,
                            exc,
                        )
                        raise

                    if attempt >= max_attempts:
                        logger.error(
                            "Max attempts (%d) reached for %s error: %s",
                            max_attempts,
                            classified.error_type,
                            exc,
                        )
                        raise

                    delay = get_retry_delay(classified, attempt)
                    logger.warning(
                        "Retryable error (%s) on attempt %d/%d, retrying in %.1fs: %s",
                        classified.error_type,
                        attempt,
                        max_attempts,
                        delay,
                        exc,
                    )
                    time.sleep(delay)

            # Should not be reached, but raise last error as safety net
            if last_error is not None:
                raise last_error  # pragma: no cover

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Tenacity integration helpers
# ---------------------------------------------------------------------------


def classified_retry_predicate(provider: str = "") -> Callable[[Exception], bool]:
    """Return a predicate suitable for tenacity's ``retry`` parameter.

    Usage with tenacity::

        from tenacity import retry, retry_if_exception

        @retry(retry=retry_if_exception(classified_retry_predicate("anthropic")))
        def call_api():
            ...
    """

    def _predicate(error: Exception) -> bool:
        return is_retryable_error(error, provider)

    return _predicate


def classified_wait(provider: str = "") -> Callable:
    """Return a wait function suitable for tenacity's ``wait`` parameter.

    Usage with tenacity::

        @retry(wait=classified_wait("anthropic"))
        def call_api():
            ...
    """

    def _wait(retry_state: Any) -> float:
        exc = retry_state.outcome.exception()
        if exc is None:
            return 0.0
        classified = classify_llm_error(exc, provider)
        return get_retry_delay(classified, retry_state.attempt_number)

    return _wait


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ClassifiedError",
    "classify_llm_error",
    "get_retry_delay",
    "is_retryable_error",
    "smart_retry",
    "classified_retry_predicate",
    "classified_wait",
    "ERROR_TYPE_BILLING",
    "ERROR_TYPE_RATE_LIMIT",
    "ERROR_TYPE_AUTH",
    "ERROR_TYPE_CONFIG",
    "ERROR_TYPE_VALIDATION",
    "ERROR_TYPE_TRANSIENT",
    "ERROR_TYPE_PERMANENT",
    "BILLING_PATTERNS",
    "RATE_LIMIT_PATTERNS",
    "AUTH_PATTERNS",
    "CONFIG_PATTERNS",
    "VALIDATION_PATTERNS",
    "TRANSIENT_PATTERNS",
]
