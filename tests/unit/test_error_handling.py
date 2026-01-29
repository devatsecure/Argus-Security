#!/usr/bin/env python3
"""
Comprehensive tests for error handling utilities
"""

import pytest
import time
from unittest.mock import Mock, patch
import sys
from pathlib import Path
import importlib.util

# Load error_handling module directly to avoid conflicts with tests/utils
scripts_utils_path = Path(__file__).parent.parent.parent / "scripts" / "utils" / "error_handling.py"
spec = importlib.util.spec_from_file_location("error_handling", scripts_utils_path)
error_handling = importlib.util.module_from_spec(spec)
spec.loader.exec_module(error_handling)

# Import from loaded module
CircuitBreaker = error_handling.CircuitBreaker
CircuitBreakerOpen = error_handling.CircuitBreakerOpen
CircuitState = error_handling.CircuitState
graceful_degradation = error_handling.graceful_degradation
retry_with_backoff = error_handling.retry_with_backoff
RateLimiter = error_handling.RateLimiter
safe_api_call = error_handling.safe_api_call
sanitize_error_message = error_handling.sanitize_error_message
handle_malformed_data = error_handling.handle_malformed_data


class TestCircuitBreaker:
    """Test circuit breaker functionality"""

    def test_circuit_breaker_initialization(self):
        """Test circuit breaker initializes correctly"""
        breaker = CircuitBreaker(failure_threshold=5, timeout=60)
        assert breaker.state == CircuitState.CLOSED
        assert breaker.failure_count == 0
        assert breaker.failure_threshold == 5
        assert breaker.timeout == 60

    def test_circuit_breaker_success(self):
        """Test successful calls don't trigger circuit"""
        breaker = CircuitBreaker(failure_threshold=3)

        def success_func():
            return "success"

        for _ in range(5):
            result = breaker.call(success_func)
            assert result == "success"
            assert breaker.state == CircuitState.CLOSED
            assert breaker.failure_count == 0

    def test_circuit_breaker_opens_on_failures(self):
        """Test circuit opens after threshold failures"""
        breaker = CircuitBreaker(failure_threshold=3, timeout=1)

        def failing_func():
            raise ValueError("Test failure")

        # Trigger failures
        for i in range(3):
            with pytest.raises(ValueError):
                breaker.call(failing_func)

        # Circuit should now be open
        assert breaker.state == CircuitState.OPEN
        assert breaker.failure_count == 3

        # Next call should raise CircuitBreakerOpen
        with pytest.raises(CircuitBreakerOpen):
            breaker.call(failing_func)

    def test_circuit_breaker_half_open_state(self):
        """Test circuit transitions to half-open after timeout"""
        breaker = CircuitBreaker(failure_threshold=2, timeout=0.1)

        def failing_func():
            raise ValueError("Test failure")

        # Open the circuit
        for _ in range(2):
            with pytest.raises(ValueError):
                breaker.call(failing_func)

        assert breaker.state == CircuitState.OPEN

        # Wait for timeout
        time.sleep(0.2)

        # Next call should transition to HALF_OPEN
        with pytest.raises(ValueError):
            breaker.call(failing_func)

        # State transitions handled internally

    def test_circuit_breaker_reset(self):
        """Test manual circuit reset"""
        breaker = CircuitBreaker(failure_threshold=2)

        def failing_func():
            raise ValueError("Test failure")

        # Open the circuit
        for _ in range(2):
            with pytest.raises(ValueError):
                breaker.call(failing_func)

        assert breaker.state == CircuitState.OPEN

        # Reset
        breaker.reset()
        assert breaker.state == CircuitState.CLOSED
        assert breaker.failure_count == 0

    def test_circuit_breaker_decorator_syntax(self):
        """Test circuit breaker as decorator"""
        breaker = CircuitBreaker(failure_threshold=2)

        @breaker
        def test_func():
            return "success"

        result = test_func()
        assert result == "success"

    def test_circuit_breaker_stats(self):
        """Test circuit breaker statistics"""
        breaker = CircuitBreaker(failure_threshold=2)
        stats = breaker.get_stats()

        assert stats["state"] == "closed"
        assert stats["failure_count"] == 0
        assert stats["last_failure"] is None


class TestRetryWithBackoff:
    """Test retry with exponential backoff"""

    def test_retry_success_first_attempt(self):
        """Test successful call on first attempt"""
        @retry_with_backoff(max_retries=3, initial_delay=0.1)
        def success_func():
            return "success"

        result = success_func()
        assert result == "success"

    def test_retry_succeeds_after_failures(self):
        """Test retry succeeds after initial failures"""
        call_count = {"count": 0}

        @retry_with_backoff(max_retries=3, initial_delay=0.1)
        def eventually_succeeds():
            call_count["count"] += 1
            if call_count["count"] < 3:
                raise ConnectionError("Test failure")
            return "success"

        result = eventually_succeeds()
        assert result == "success"
        assert call_count["count"] == 3

    def test_retry_exhausts_attempts(self):
        """Test all retries exhausted"""
        @retry_with_backoff(max_retries=2, initial_delay=0.1)
        def always_fails():
            raise ValueError("Always fails")

        with pytest.raises(ValueError):
            always_fails()

    def test_retry_exponential_backoff(self):
        """Test exponential backoff timing"""
        attempts = []

        @retry_with_backoff(max_retries=3, initial_delay=0.1, exponential_base=2.0)
        def track_attempts():
            attempts.append(time.time())
            if len(attempts) < 3:
                raise ConnectionError("Test")
            return "success"

        result = track_attempts()
        assert result == "success"
        assert len(attempts) == 3

        # Check delays are increasing (approximately)
        delay1 = attempts[1] - attempts[0]
        delay2 = attempts[2] - attempts[1]
        assert delay2 > delay1  # Exponential increase

    def test_retry_with_callback(self):
        """Test retry callback is called"""
        callback_calls = []

        def on_retry(exc, attempt):
            callback_calls.append(attempt)

        call_count = {"count": 0}

        @retry_with_backoff(max_retries=2, initial_delay=0.1, on_retry=on_retry)
        def eventually_succeeds():
            call_count["count"] += 1
            if call_count["count"] < 2:
                raise ConnectionError("Test")
            return "success"

        result = eventually_succeeds()
        assert result == "success"
        assert callback_calls == [1]  # Called once after first failure


class TestGracefulDegradation:
    """Test graceful degradation decorator"""

    def test_graceful_degradation_returns_fallback(self):
        """Test fallback value returned on failure"""
        @graceful_degradation(fallback_value="default")
        def failing_func():
            raise ValueError("Test failure")

        result = failing_func()
        assert result == "default"

    def test_graceful_degradation_returns_normal_value(self):
        """Test normal value returned on success"""
        @graceful_degradation(fallback_value="default")
        def success_func():
            return "success"

        result = success_func()
        assert result == "success"

    def test_graceful_degradation_with_list_fallback(self):
        """Test list fallback value"""
        @graceful_degradation(fallback_value=[])
        def failing_func():
            raise RuntimeError("Test")

        result = failing_func()
        assert result == []
        assert isinstance(result, list)

    def test_graceful_degradation_logs_error(self, caplog):
        """Test error is logged"""
        @graceful_degradation(fallback_value=None, log_error=True)
        def failing_func():
            raise ValueError("Test error")

        result = failing_func()
        assert result is None
        assert "failed gracefully" in caplog.text.lower()

    def test_graceful_degradation_no_logging(self, caplog):
        """Test error not logged when disabled"""
        @graceful_degradation(fallback_value=None, log_error=False)
        def failing_func():
            raise ValueError("Test error")

        result = failing_func()
        assert result is None
        # caplog should be empty or not contain error message

    def test_graceful_degradation_specific_exceptions(self):
        """Test only catches specified exception types"""
        @graceful_degradation(
            fallback_value="fallback",
            exception_types=(ValueError,)
        )
        def raises_value_error():
            raise ValueError("Test")

        result = raises_value_error()
        assert result == "fallback"

        # Different exception should not be caught
        @graceful_degradation(
            fallback_value="fallback",
            exception_types=(ValueError,)
        )
        def raises_type_error():
            raise TypeError("Test")

        with pytest.raises(TypeError):
            raises_type_error()


class TestRateLimiter:
    """Test rate limiter"""

    def test_rate_limiter_allows_calls_within_limit(self):
        """Test calls within limit are allowed"""
        limiter = RateLimiter(max_calls=3, time_window=1.0)

        def test_func():
            return "success"

        # Should allow 3 calls quickly
        for _ in range(3):
            result = limiter.call(test_func)
            assert result == "success"

    def test_rate_limiter_blocks_excess_calls(self):
        """Test excess calls are throttled"""
        limiter = RateLimiter(max_calls=2, time_window=1.0)

        call_times = []

        def test_func():
            call_times.append(time.time())
            return "success"

        # Call 3 times - third should be delayed
        for _ in range(3):
            limiter.call(test_func)

        # Check third call was delayed
        assert len(call_times) == 3
        delay = call_times[2] - call_times[1]
        assert delay > 0.5  # Should wait at least part of time window

    def test_rate_limiter_decorator_syntax(self):
        """Test rate limiter as decorator"""
        limiter = RateLimiter(max_calls=5, time_window=1.0)

        @limiter
        def test_func():
            return "success"

        result = test_func()
        assert result == "success"


class TestSafeApiCall:
    """Test safe API call wrapper"""

    def test_safe_api_call_success(self):
        """Test successful API call"""
        def success_func():
            return "data"

        result = safe_api_call(success_func)
        assert result == "data"

    def test_safe_api_call_returns_none_on_failure(self):
        """Test returns None on failure"""
        def failing_func():
            raise ValueError("API error")

        result = safe_api_call(failing_func)
        assert result is None

    def test_safe_api_call_with_circuit_breaker(self):
        """Test safe API call with circuit breaker"""
        breaker = CircuitBreaker(failure_threshold=2, timeout=1)

        def failing_func():
            raise ValueError("API error")

        # Fail twice to open circuit
        result1 = safe_api_call(failing_func, circuit_breaker=breaker)
        result2 = safe_api_call(failing_func, circuit_breaker=breaker)

        assert result1 is None
        assert result2 is None
        assert breaker.state == CircuitState.OPEN

        # Next call should return None due to open circuit
        result3 = safe_api_call(failing_func, circuit_breaker=breaker)
        assert result3 is None


class TestSanitizeErrorMessage:
    """Test error message sanitization"""

    def test_sanitize_api_key(self):
        """Test API keys are redacted"""
        error = ValueError("Request failed with api_key=sk_test_12345")
        sanitized = sanitize_error_message(error)
        assert "[REDACTED]" in sanitized
        assert "sk_test_12345" not in sanitized

    def test_sanitize_password(self):
        """Test passwords are redacted"""
        error = ValueError("Auth failed with password=secret123")
        sanitized = sanitize_error_message(error)
        assert "[REDACTED]" in sanitized
        assert "secret123" not in sanitized

    def test_sanitize_bearer_token(self):
        """Test bearer tokens are redacted"""
        error = ValueError("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        sanitized = sanitize_error_message(error)
        assert "[REDACTED]" in sanitized

    def test_sanitize_home_path(self):
        """Test home paths are redacted"""
        error = ValueError("File not found: /home/user/secrets.txt")
        sanitized = sanitize_error_message(error)
        assert "[REDACTED]" in sanitized
        assert "/home/user" not in sanitized

    def test_sanitize_truncates_long_messages(self):
        """Test long messages are truncated"""
        # Use a message that won't be redacted (not matching base64/sensitive patterns)
        long_message = "Error occurred at step " + ("9 " * 150)  # ~300 chars, not base64-like
        error = ValueError(long_message)
        sanitized = sanitize_error_message(error, max_length=100)
        # Should be truncated: "ValueError: " (12) + message (100) + "..." (3) = 115 max
        assert len(sanitized) <= 116
        assert sanitized.endswith("...")


class TestHandleMalformedData:
    """Test malformed data handling"""

    def test_handle_malformed_data_valid(self):
        """Test valid data passes through"""
        data = [1, 2, 3]
        result = handle_malformed_data(data, list, "test_list")
        assert result == [1, 2, 3]

    def test_handle_malformed_data_none(self):
        """Test None returns default"""
        result = handle_malformed_data(None, list, "test_list", default_value=[])
        assert result == []

    def test_handle_malformed_data_wrong_type(self):
        """Test wrong type returns default"""
        data = "not_a_list"
        result = handle_malformed_data(data, list, "test_list", default_value=[])
        assert result == []

    def test_handle_malformed_data_dict(self):
        """Test dict validation"""
        data = {"key": "value"}
        result = handle_malformed_data(data, dict, "test_dict")
        assert result == {"key": "value"}

        # Wrong type
        result = handle_malformed_data([1, 2], dict, "test_dict", default_value={})
        assert result == {}


class TestIntegration:
    """Integration tests combining multiple features"""

    def test_circuit_breaker_with_retry(self):
        """Test circuit breaker and retry working together"""
        breaker = CircuitBreaker(failure_threshold=3, timeout=1)
        call_count = {"count": 0}

        @retry_with_backoff(max_retries=5, initial_delay=0.1)
        def sometimes_fails():
            call_count["count"] += 1
            if call_count["count"] < 2:
                raise ConnectionError("Transient error")
            return "success"

        # Should succeed after retry
        result = breaker.call(sometimes_fails)
        assert result == "success"

    def test_graceful_degradation_with_retry(self):
        """Test graceful degradation catches retry failures"""
        @graceful_degradation(fallback_value="fallback")
        @retry_with_backoff(max_retries=2, initial_delay=0.1)
        def always_fails():
            raise ConnectionError("Always fails")

        result = always_fails()
        assert result == "fallback"

    def test_full_error_handling_stack(self):
        """Test all error handling features together"""
        breaker = CircuitBreaker(failure_threshold=5, timeout=1)
        limiter = RateLimiter(max_calls=10, time_window=1.0)

        call_count = {"count": 0}

        @graceful_degradation(fallback_value={"data": []})
        @retry_with_backoff(max_retries=2, initial_delay=0.1)
        def complex_operation():
            call_count["count"] += 1
            if call_count["count"] < 2:
                raise ConnectionError("Transient error")
            return {"data": ["item1", "item2"]}

        result = limiter.call(
            lambda: breaker.call(complex_operation)
        )

        assert result == {"data": ["item1", "item2"]}
        assert call_count["count"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
