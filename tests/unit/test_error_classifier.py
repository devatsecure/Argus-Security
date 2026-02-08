#!/usr/bin/env python3
"""
Comprehensive tests for the error_classifier module.

Tests error classification, retry delay calculation, the smart_retry
decorator, the is_retryable_error helper, and backward compatibility.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure scripts directory is on the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from error_classifier import (
    AUTH_PATTERNS,
    BILLING_PATTERNS,
    CONFIG_PATTERNS,
    ERROR_TYPE_AUTH,
    ERROR_TYPE_BILLING,
    ERROR_TYPE_CONFIG,
    ERROR_TYPE_PERMANENT,
    ERROR_TYPE_RATE_LIMIT,
    ERROR_TYPE_TRANSIENT,
    ERROR_TYPE_VALIDATION,
    RATE_LIMIT_PATTERNS,
    TRANSIENT_PATTERNS,
    VALIDATION_PATTERNS,
    ClassifiedError,
    classified_retry_predicate,
    classified_wait,
    classify_llm_error,
    get_retry_delay,
    is_retryable_error,
    smart_retry,
)

# ---------------------------------------------------------------------------
# ClassifiedError dataclass tests
# ---------------------------------------------------------------------------


class TestClassifiedError:
    """Test the ClassifiedError dataclass."""

    def test_creation_with_defaults(self):
        exc = ValueError("test")
        classified = ClassifiedError(
            error_type="transient",
            retryable=True,
            original=exc,
        )
        assert classified.error_type == "transient"
        assert classified.retryable is True
        assert classified.original is exc
        assert classified.context == {}
        assert classified.provider == ""

    def test_creation_with_all_fields(self):
        exc = RuntimeError("api error")
        classified = ClassifiedError(
            error_type="billing",
            retryable=True,
            original=exc,
            context={"status_code": 402},
            provider="anthropic",
        )
        assert classified.error_type == "billing"
        assert classified.provider == "anthropic"
        assert classified.context["status_code"] == 402

    def test_str_retryable(self):
        exc = ValueError("test")
        classified = ClassifiedError(
            error_type="transient",
            retryable=True,
            original=exc,
            provider="openai",
        )
        s = str(classified)
        assert "retryable" in s
        assert "transient" in s
        assert "openai" in s

    def test_str_non_retryable(self):
        exc = ValueError("test")
        classified = ClassifiedError(
            error_type="auth",
            retryable=False,
            original=exc,
        )
        s = str(classified)
        assert "non-retryable" in s
        assert "auth" in s


# ---------------------------------------------------------------------------
# classify_llm_error tests
# ---------------------------------------------------------------------------


class TestClassifyLLMError:
    """Test classify_llm_error with various error messages."""

    # -- Billing errors --

    @pytest.mark.parametrize(
        "message",
        [
            "billing_error: your account has no credits",
            "Insufficient credit balance to complete request",
            "Your spending cap has been reached",
            "spending limit exceeded",
            "insufficient credits remaining",
            "Payment required for this request",
            "Quota exceeded for this billing period",
        ],
    )
    def test_billing_errors(self, message):
        exc = Exception(message)
        classified = classify_llm_error(exc, provider="anthropic")
        assert classified.error_type == ERROR_TYPE_BILLING
        assert classified.retryable is True
        assert classified.provider == "anthropic"

    # -- Auth errors --

    @pytest.mark.parametrize(
        "message",
        [
            "Invalid API key provided",
            "Authentication failed",
            "Unauthorized access",
            "invalid_api_key: key is not valid",
            "Permission denied for this resource",
            "Forbidden: you do not have access",
            "401 Unauthorized",
            "403 Forbidden",
            "Access denied to this endpoint",
        ],
    )
    def test_auth_errors(self, message):
        exc = Exception(message)
        classified = classify_llm_error(exc, provider="openai")
        assert classified.error_type == ERROR_TYPE_AUTH
        assert classified.retryable is False

    # -- Rate limit errors --

    @pytest.mark.parametrize(
        "message",
        [
            "Rate limit exceeded",
            "429 Too Many Requests",
            "rate_limit_error: slow down",
            "You have been throttled",
            "Too many requests in the last minute",
        ],
    )
    def test_rate_limit_errors(self, message):
        exc = Exception(message)
        classified = classify_llm_error(exc, provider="anthropic")
        assert classified.error_type == ERROR_TYPE_RATE_LIMIT
        assert classified.retryable is True

    # -- Transient / network errors --

    @pytest.mark.parametrize(
        "message",
        [
            "Network error occurred",
            "Connection refused",
            "Request timed out",
            "ECONNRESET: connection was reset",
            "ECONNREFUSED: cannot connect",
            "Internal server error",
            "Service unavailable",
            "The server is currently overloaded",
            "503 Service Unavailable",
            "502 Bad Gateway",
            "504 Gateway Timeout",
        ],
    )
    def test_transient_errors(self, message):
        exc = Exception(message)
        classified = classify_llm_error(exc, provider="anthropic")
        assert classified.error_type == ERROR_TYPE_TRANSIENT
        assert classified.retryable is True

    def test_connection_error_by_type(self):
        """ConnectionError should be classified as transient regardless of message."""
        exc = ConnectionError("something weird")
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_TRANSIENT
        assert classified.retryable is True

    def test_timeout_error_by_type(self):
        """TimeoutError should be classified as transient regardless of message."""
        exc = TimeoutError("took too long")
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_TRANSIENT
        assert classified.retryable is True

    def test_os_error_by_type(self):
        """OSError (network issues) should be classified as transient."""
        exc = OSError("network is unreachable")
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_TRANSIENT
        assert classified.retryable is True

    # -- Validation errors --

    @pytest.mark.parametrize(
        "message",
        [
            "Output validation failed: unexpected format",
            "Invalid response from model",
            "Malformed JSON in response",
            "Invalid JSON returned",
            "Parse error in output",
        ],
    )
    def test_validation_errors(self, message):
        exc = Exception(message)
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_VALIDATION
        assert classified.retryable is True

    # -- Config errors --

    @pytest.mark.parametrize(
        "message",
        [
            "ENOENT: file not found",
            "No such file or directory",
            "Invalid configuration detected",
            "Invalid config: missing key 'model'",
            "Model not found: claude-99",
        ],
    )
    def test_config_errors(self, message):
        exc = Exception(message)
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_CONFIG
        assert classified.retryable is False

    # -- Unknown / permanent errors --

    def test_unknown_error_classified_as_permanent(self):
        exc = Exception("something completely unexpected happened")
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_PERMANENT
        assert classified.retryable is False

    def test_empty_message_classified_as_permanent(self):
        exc = Exception("")
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_PERMANENT
        assert classified.retryable is False

    # -- Context extraction --

    def test_status_code_extracted(self):
        exc = Exception("rate limit")
        exc.status_code = 429  # type: ignore[attr-defined]
        classified = classify_llm_error(exc)
        assert classified.context.get("status_code") == 429

    def test_error_class_in_context(self):
        exc = ValueError("something")
        classified = classify_llm_error(exc)
        assert classified.context["error_class"] == "ValueError"

    def test_provider_preserved(self):
        exc = Exception("timeout")
        classified = classify_llm_error(exc, provider="ollama")
        assert classified.provider == "ollama"


# ---------------------------------------------------------------------------
# get_retry_delay tests
# ---------------------------------------------------------------------------


class TestGetRetryDelay:
    """Test retry delay calculation for each error type."""

    def _make_classified(self, error_type, retryable=True):
        return ClassifiedError(
            error_type=error_type,
            retryable=retryable,
            original=Exception("test"),
        )

    def test_billing_delay_attempt_1(self):
        classified = self._make_classified(ERROR_TYPE_BILLING)
        delay = get_retry_delay(classified, 1)
        assert delay == 90.0  # 60 + 1 * 30

    def test_billing_delay_attempt_2(self):
        classified = self._make_classified(ERROR_TYPE_BILLING)
        delay = get_retry_delay(classified, 2)
        assert delay == 120.0  # 60 + 2 * 30

    def test_billing_delay_capped_at_300(self):
        classified = self._make_classified(ERROR_TYPE_BILLING)
        delay = get_retry_delay(classified, 100)
        assert delay == 300.0

    def test_rate_limit_delay_attempt_1(self):
        classified = self._make_classified(ERROR_TYPE_RATE_LIMIT)
        delay = get_retry_delay(classified, 1)
        assert delay == 40.0  # 30 + 1 * 10

    def test_rate_limit_delay_attempt_2(self):
        classified = self._make_classified(ERROR_TYPE_RATE_LIMIT)
        delay = get_retry_delay(classified, 2)
        assert delay == 50.0  # 30 + 2 * 10

    def test_rate_limit_delay_capped_at_120(self):
        classified = self._make_classified(ERROR_TYPE_RATE_LIMIT)
        delay = get_retry_delay(classified, 100)
        assert delay == 120.0

    def test_transient_delay_exponential(self):
        classified = self._make_classified(ERROR_TYPE_TRANSIENT)
        delay = get_retry_delay(classified, 1)
        # 2^1 + jitter (0-1) = 2.0 to 3.0
        assert 2.0 <= delay <= 3.0

    def test_transient_delay_attempt_2(self):
        classified = self._make_classified(ERROR_TYPE_TRANSIENT)
        delay = get_retry_delay(classified, 2)
        # 2^2 + jitter (0-1) = 4.0 to 5.0
        assert 4.0 <= delay <= 5.0

    def test_transient_delay_capped_at_30(self):
        classified = self._make_classified(ERROR_TYPE_TRANSIENT)
        delay = get_retry_delay(classified, 10)
        assert delay == 30.0  # 2^10 = 1024, capped at 30

    def test_validation_delay_fixed(self):
        classified = self._make_classified(ERROR_TYPE_VALIDATION)
        delay1 = get_retry_delay(classified, 1)
        delay2 = get_retry_delay(classified, 5)
        assert delay1 == 5.0
        assert delay2 == 5.0

    def test_non_retryable_returns_zero(self):
        classified = self._make_classified(ERROR_TYPE_AUTH, retryable=False)
        delay = get_retry_delay(classified, 1)
        assert delay == 0.0

    def test_permanent_returns_zero(self):
        classified = self._make_classified(ERROR_TYPE_PERMANENT, retryable=False)
        delay = get_retry_delay(classified, 1)
        assert delay == 0.0


# ---------------------------------------------------------------------------
# is_retryable_error tests
# ---------------------------------------------------------------------------


class TestIsRetryableError:
    """Test the is_retryable_error helper."""

    def test_retryable_transient(self):
        assert is_retryable_error(ConnectionError("refused")) is True

    def test_retryable_rate_limit(self):
        assert is_retryable_error(Exception("rate limit exceeded")) is True

    def test_retryable_billing(self):
        assert is_retryable_error(Exception("billing_error")) is True

    def test_not_retryable_auth(self):
        assert is_retryable_error(Exception("invalid api key")) is False

    def test_not_retryable_config(self):
        assert is_retryable_error(Exception("invalid config")) is False

    def test_not_retryable_unknown(self):
        assert is_retryable_error(Exception("random failure xyz")) is False

    def test_provider_passthrough(self):
        # Provider should not change retryability logic
        assert is_retryable_error(Exception("timeout"), "anthropic") is True
        assert is_retryable_error(Exception("invalid api key"), "openai") is False


# ---------------------------------------------------------------------------
# smart_retry decorator tests
# ---------------------------------------------------------------------------


class TestSmartRetry:
    """Test the smart_retry decorator."""

    def test_successful_call_no_retry(self):
        call_count = 0

        @smart_retry(max_attempts=3)
        def success():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = success()
        assert result == "ok"
        assert call_count == 1

    @patch("error_classifier.time.sleep")
    def test_retries_on_transient_error(self, mock_sleep):
        call_count = 0

        @smart_retry(max_attempts=3)
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("network blip")
            return "recovered"

        result = flaky()
        assert result == "recovered"
        assert call_count == 3
        assert mock_sleep.call_count == 2  # 2 retries

    @patch("error_classifier.time.sleep")
    def test_raises_immediately_on_non_retryable(self, mock_sleep):
        call_count = 0

        @smart_retry(max_attempts=3)
        def auth_fail():
            nonlocal call_count
            call_count += 1
            raise Exception("invalid api key")

        with pytest.raises(Exception, match="invalid api key"):
            auth_fail()

        assert call_count == 1  # No retries for auth errors
        assert mock_sleep.call_count == 0

    @patch("error_classifier.time.sleep")
    def test_raises_after_max_attempts(self, mock_sleep):
        call_count = 0

        @smart_retry(max_attempts=2)
        def always_fails():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("still failing")

        with pytest.raises(ConnectionError, match="still failing"):
            always_fails()

        assert call_count == 2
        assert mock_sleep.call_count == 1  # Only 1 retry before giving up

    @patch("error_classifier.time.sleep")
    def test_custom_classifier(self, mock_sleep):
        """Test smart_retry with a custom classifier function."""

        def custom_classifier(error, provider=""):
            return ClassifiedError(
                error_type="custom",
                retryable=True,
                original=error,
                provider=provider,
            )

        call_count = 0

        @smart_retry(max_attempts=2, classifier_fn=custom_classifier)
        def custom_fail():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("custom error")
            return "ok"

        result = custom_fail()
        assert result == "ok"
        assert call_count == 2

    @patch("error_classifier.time.sleep")
    def test_provider_passed_to_classifier(self, mock_sleep):
        """Test that provider is passed through to the classifier."""
        captured_providers = []

        def tracking_classifier(error, provider=""):
            captured_providers.append(provider)
            return ClassifiedError(
                error_type="transient",
                retryable=True,
                original=error,
                provider=provider,
            )

        @smart_retry(
            max_attempts=2,
            classifier_fn=tracking_classifier,
            provider="anthropic",
        )
        def always_fails():
            raise Exception("fail")

        with pytest.raises(Exception, match="fail"):
            always_fails()

        assert all(p == "anthropic" for p in captured_providers)

    def test_preserves_function_metadata(self):
        @smart_retry(max_attempts=3)
        def documented_func():
            """This is documented."""
            return 42

        assert documented_func.__name__ == "documented_func"
        assert documented_func.__doc__ == "This is documented."

    @patch("error_classifier.time.sleep")
    def test_rate_limit_retry(self, mock_sleep):
        """Test that rate limit errors are retried with appropriate delay."""
        call_count = 0

        @smart_retry(max_attempts=3)
        def rate_limited():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("rate limit exceeded")
            return "success"

        result = rate_limited()
        assert result == "success"
        assert call_count == 2
        # Verify sleep was called with rate_limit delay (30 + 1*10 = 40)
        mock_sleep.assert_called_once()
        delay = mock_sleep.call_args[0][0]
        assert delay == 40.0

    @patch("error_classifier.time.sleep")
    def test_billing_error_long_backoff(self, mock_sleep):
        """Test that billing errors get long backoff."""
        call_count = 0

        @smart_retry(max_attempts=3)
        def billing_fail():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("billing_error: no credits")
            return "ok"

        result = billing_fail()
        assert result == "ok"
        delay = mock_sleep.call_args[0][0]
        assert delay == 90.0  # 60 + 1*30


# ---------------------------------------------------------------------------
# Tenacity integration helpers tests
# ---------------------------------------------------------------------------


class TestTenacityIntegration:
    """Test the tenacity-compatible helper functions."""

    def test_classified_retry_predicate_retryable(self):
        predicate = classified_retry_predicate("anthropic")
        assert predicate(ConnectionError("network fail")) is True

    def test_classified_retry_predicate_not_retryable(self):
        predicate = classified_retry_predicate("anthropic")
        assert predicate(Exception("invalid api key")) is False

    def test_classified_wait_returns_delay(self):
        wait_fn = classified_wait("anthropic")

        # Create a mock retry_state
        mock_state = MagicMock()
        mock_state.outcome.exception.return_value = Exception("rate limit hit")
        mock_state.attempt_number = 1

        delay = wait_fn(mock_state)
        assert delay == 40.0  # rate_limit: 30 + 1*10

    def test_classified_wait_no_exception(self):
        wait_fn = classified_wait("anthropic")

        mock_state = MagicMock()
        mock_state.outcome.exception.return_value = None

        delay = wait_fn(mock_state)
        assert delay == 0.0


# ---------------------------------------------------------------------------
# Backward compatibility tests
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    """Test that the module integrates cleanly with existing code."""

    def test_module_imports_without_side_effects(self):
        """Importing the module should not perform I/O or modify state."""
        import importlib

        mod = importlib.import_module("error_classifier")
        assert hasattr(mod, "classify_llm_error")
        assert hasattr(mod, "smart_retry")
        assert hasattr(mod, "is_retryable_error")

    def test_all_exports_listed(self):
        """All public names should be in __all__."""
        import error_classifier

        for name in error_classifier.__all__:
            assert hasattr(error_classifier, name), f"{name} listed in __all__ but not defined"

    def test_classified_error_is_dataclass(self):
        """ClassifiedError should be a proper dataclass."""
        import dataclasses

        assert dataclasses.is_dataclass(ClassifiedError)

    def test_pattern_lists_are_non_empty(self):
        """All pattern registries should contain at least one pattern."""
        assert len(BILLING_PATTERNS) > 0
        assert len(RATE_LIMIT_PATTERNS) > 0
        assert len(AUTH_PATTERNS) > 0
        assert len(CONFIG_PATTERNS) > 0
        assert len(VALIDATION_PATTERNS) > 0
        assert len(TRANSIENT_PATTERNS) > 0

    def test_error_type_constants(self):
        """Error type constants should be stable strings."""
        assert ERROR_TYPE_BILLING == "billing"
        assert ERROR_TYPE_RATE_LIMIT == "rate_limit"
        assert ERROR_TYPE_AUTH == "auth"
        assert ERROR_TYPE_CONFIG == "config"
        assert ERROR_TYPE_VALIDATION == "validation"
        assert ERROR_TYPE_TRANSIENT == "transient"
        assert ERROR_TYPE_PERMANENT == "permanent"


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Test edge cases and unusual inputs."""

    def test_exception_subclass(self):
        """Custom exception subclasses should still be classified."""

        class CustomAPIError(Exception):
            pass

        exc = CustomAPIError("rate limit reached")
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_RATE_LIMIT

    def test_nested_exception_message(self):
        """Errors with nested messages should still match patterns."""
        exc = Exception("Error: The server returned: 503 Service Unavailable")
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_TRANSIENT

    def test_case_insensitive_matching(self):
        """Pattern matching should be case-insensitive."""
        exc = Exception("RATE LIMIT EXCEEDED")
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_RATE_LIMIT

    def test_multiple_patterns_first_wins(self):
        """When message matches multiple types, priority order wins.

        Auth patterns are checked before rate_limit patterns in the registry.
        """
        # "unauthorized" matches auth, "rate limit" matches rate_limit
        # Auth is checked first in _PATTERN_REGISTRY
        exc = Exception("unauthorized rate limit")
        classified = classify_llm_error(exc)
        assert classified.error_type == ERROR_TYPE_AUTH

    @patch("error_classifier.time.sleep")
    def test_smart_retry_with_max_attempts_1(self, mock_sleep):
        """With max_attempts=1, no retries should happen."""

        @smart_retry(max_attempts=1)
        def fail():
            raise ConnectionError("network")

        with pytest.raises(ConnectionError):
            fail()

        assert mock_sleep.call_count == 0

    def test_classify_preserves_original_exception(self):
        """The original exception should be stored by reference."""
        original = ValueError("the original")
        classified = classify_llm_error(original)
        assert classified.original is original

    def test_empty_provider(self):
        """Empty provider should not cause errors."""
        exc = Exception("timeout")
        classified = classify_llm_error(exc, provider="")
        assert classified.provider == ""
        assert classified.error_type == ERROR_TYPE_TRANSIENT
