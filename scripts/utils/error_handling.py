#!/usr/bin/env python3
"""
Error Handling Utilities for Argus

Provides circuit breakers, graceful degradation, and retry logic with exponential backoff
to improve reliability and prevent cascading failures.

Features:
- Circuit breaker pattern for API calls
- Retry decorator with exponential backoff
- Graceful degradation decorator
- Rate limiting support
- Structured error logging
- User-friendly error messages
"""

import functools
import logging
import time
import traceback
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Optional, TypeVar, Union

logger = logging.getLogger(__name__)

# Type variable for decorators
T = TypeVar("T")


class CircuitState(Enum):
    """Circuit breaker states"""

    CLOSED = "closed"  # Normal operation, requests allowed
    OPEN = "open"  # Too many failures, requests blocked
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreakerOpen(Exception):
    """Exception raised when circuit breaker is open"""

    def __init__(self, message: str = "Circuit breaker is open - too many failures"):
        self.message = message
        super().__init__(self.message)


class CircuitBreaker:
    """
    Circuit breaker for API calls to prevent cascading failures.

    The circuit breaker has three states:
    - CLOSED: Normal operation, all requests pass through
    - OPEN: Too many failures, all requests blocked immediately
    - HALF_OPEN: Testing if service recovered, limited requests allowed

    Example:
        breaker = CircuitBreaker(failure_threshold=5, timeout=60)

        @breaker.call
        def make_api_call():
            return api.get_data()

        # Or use directly:
        result = breaker.call(lambda: api.get_data())
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        timeout: int = 60,
        expected_exception: type[Exception] = Exception,
    ):
        """
        Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            timeout: Seconds to wait before transitioning to half-open
            expected_exception: Exception type to catch (default: Exception)
        """
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.expected_exception = expected_exception

        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.state = CircuitState.CLOSED

        logger.debug(
            f"Circuit breaker initialized: threshold={failure_threshold}, timeout={timeout}s"
        )

    def call(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """
        Execute function with circuit breaker protection.

        Args:
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Function result

        Raises:
            CircuitBreakerOpen: If circuit is open
            Exception: Original exception if call fails
        """
        # Check circuit state before proceeding
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                logger.info("Circuit breaker transitioning to HALF_OPEN state")
                self.state = CircuitState.HALF_OPEN
            else:
                elapsed = (datetime.now() - self.last_failure_time).total_seconds()
                remaining = self.timeout - elapsed
                raise CircuitBreakerOpen(
                    f"Circuit breaker open - service unavailable. "
                    f"Try again in {remaining:.0f} seconds "
                    f"({self.failure_count} consecutive failures)"
                )

        try:
            # Execute the function
            result = func(*args, **kwargs)

            # Success - update state
            self._on_success()
            return result

        except self.expected_exception as e:
            # Failure - update state
            self._on_failure()

            # Re-raise the exception
            raise

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """
        Decorator syntax support.

        Usage:
            breaker = CircuitBreaker()

            @breaker
            def my_function():
                ...
        """

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            return self.call(func, *args, **kwargs)

        return wrapper

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if not self.last_failure_time:
            return False

        elapsed = (datetime.now() - self.last_failure_time).total_seconds()
        return elapsed >= self.timeout

    def _on_success(self) -> None:
        """Handle successful call"""
        self.failure_count = 0

        if self.state == CircuitState.HALF_OPEN:
            logger.info("Circuit breaker transitioning to CLOSED state (service recovered)")
            self.state = CircuitState.CLOSED
            self.success_count = 0

    def _on_failure(self) -> None:
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = datetime.now()

        logger.warning(
            f"Circuit breaker failure count: {self.failure_count}/{self.failure_threshold}"
        )

        if self.failure_count >= self.failure_threshold:
            if self.state != CircuitState.OPEN:
                logger.error(
                    f"Circuit breaker OPENED after {self.failure_count} failures. "
                    f"Blocking requests for {self.timeout} seconds"
                )
                self.state = CircuitState.OPEN

    def reset(self) -> None:
        """Manually reset the circuit breaker"""
        logger.info("Circuit breaker manually reset")
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        """Check if circuit is open"""
        return self.state == CircuitState.OPEN

    def get_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics"""
        return {
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure": self.last_failure_time.isoformat()
            if self.last_failure_time
            else None,
        }


def retry_with_backoff(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable[[Exception, int], None]] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Retry decorator with exponential backoff.

    Example:
        @retry_with_backoff(max_retries=3, initial_delay=1.0)
        def fetch_data():
            return api.get_data()

    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        exponential_base: Base for exponential backoff
        exceptions: Tuple of exceptions to catch and retry
        on_retry: Optional callback called on each retry: on_retry(exception, attempt_num)

    Returns:
        Decorated function with retry logic
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception: Optional[Exception] = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)

                except exceptions as e:
                    last_exception = e

                    if attempt < max_retries:
                        # Calculate delay with exponential backoff
                        delay = min(
                            initial_delay * (exponential_base**attempt), max_delay
                        )

                        logger.warning(
                            f"Attempt {attempt + 1}/{max_retries + 1} failed for {func.__name__}: "
                            f"{type(e).__name__}: {str(e)[:100]}. "
                            f"Retrying in {delay:.1f}s..."
                        )

                        # Call retry callback if provided
                        if on_retry:
                            try:
                                on_retry(e, attempt + 1)
                            except Exception as callback_error:
                                logger.error(
                                    f"Error in retry callback: {callback_error}"
                                )

                        time.sleep(delay)
                    else:
                        logger.error(
                            f"All {max_retries + 1} attempts failed for {func.__name__}: "
                            f"{type(e).__name__}: {str(e)[:200]}"
                        )

            # All retries exhausted
            if last_exception:
                raise last_exception
            else:
                raise RuntimeError(
                    f"Function {func.__name__} failed without raising an exception"
                )

        return wrapper

    return decorator


def graceful_degradation(
    fallback_value: Any = None,
    log_error: bool = True,
    exception_types: tuple[type[Exception], ...] = (Exception,),
) -> Callable[[Callable[..., T]], Callable[..., Union[T, Any]]]:
    """
    Decorator for graceful degradation - return fallback value on failure.

    Example:
        @graceful_degradation(fallback_value=[])
        def fetch_optional_data():
            return api.get_data()

        # If fetch_optional_data() fails, returns [] instead of crashing

    Args:
        fallback_value: Value to return on failure
        log_error: Whether to log the error
        exception_types: Tuple of exceptions to catch

    Returns:
        Decorated function that returns fallback_value on failure
    """

    def decorator(func: Callable[..., T]) -> Callable[..., Union[T, Any]]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Union[T, Any]:
            try:
                return func(*args, **kwargs)

            except exception_types as e:
                if log_error:
                    # Log user-friendly error message
                    error_msg = sanitize_error_message(e)
                    logger.warning(
                        f"Function {func.__name__} failed gracefully: {error_msg}. "
                        f"Returning fallback value: {fallback_value}"
                    )

                    # Log full traceback at debug level
                    logger.debug(f"Full traceback: {traceback.format_exc()}")

                return fallback_value

        return wrapper

    return decorator


def safe_api_call(
    func: Callable[..., T],
    *args: Any,
    timeout: Optional[float] = None,
    circuit_breaker: Optional[CircuitBreaker] = None,
    **kwargs: Any,
) -> Optional[T]:
    """
    Safely execute an API call with timeout and circuit breaker protection.

    Example:
        breaker = CircuitBreaker()
        result = safe_api_call(api.get_data, timeout=30, circuit_breaker=breaker)
        if result is None:
            # Handle failure gracefully
            pass

    Args:
        func: Function to call
        *args: Positional arguments for function
        timeout: Timeout in seconds (optional)
        circuit_breaker: CircuitBreaker instance (optional)
        **kwargs: Keyword arguments for function

    Returns:
        Function result or None on failure
    """
    try:
        # Apply circuit breaker if provided
        if circuit_breaker:
            return circuit_breaker.call(func, *args, **kwargs)

        # Apply timeout if provided
        if timeout:
            import signal

            def timeout_handler(signum, frame):
                raise TimeoutError(f"API call timed out after {timeout}s")

            # Set up signal handler (Unix-only)
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(int(timeout))

            try:
                result = func(*args, **kwargs)
                signal.alarm(0)  # Cancel alarm
                return result
            finally:
                signal.signal(signal.SIGALRM, old_handler)

        # No protection - just call the function
        return func(*args, **kwargs)

    except CircuitBreakerOpen as e:
        logger.warning(f"Circuit breaker open for {func.__name__}: {e.message}")
        return None

    except TimeoutError as e:
        logger.error(f"API call {func.__name__} timed out: {e}")
        return None

    except Exception as e:
        error_msg = sanitize_error_message(e)
        logger.error(f"API call {func.__name__} failed: {error_msg}")
        logger.debug(f"Full traceback: {traceback.format_exc()}")
        return None


def sanitize_error_message(error: Exception, max_length: int = 200) -> str:
    """
    Sanitize error message for user-facing output.

    Removes sensitive information and internal implementation details.

    Args:
        error: Exception to sanitize
        max_length: Maximum length of message

    Returns:
        Sanitized error message
    """
    # Get error type and message
    error_type = type(error).__name__
    error_msg = str(error)

    # Remove common sensitive patterns
    sensitive_patterns = [
        r"(api[_-]?key|token|secret|password|credential)[=:\s]+[^\s&]+",
        r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64-like strings
        r"/home/[^/\s]+",  # Home directory paths
        r"\/Users\/[^\/\s]+",  # Mac user paths
        r"C:\\Users\\[^\\s]+",  # Windows user paths
    ]

    import re

    sanitized_msg = error_msg
    for pattern in sensitive_patterns:
        sanitized_msg = re.sub(pattern, "[REDACTED]", sanitized_msg, flags=re.IGNORECASE)

    # Truncate if too long
    if len(sanitized_msg) > max_length:
        sanitized_msg = sanitized_msg[:max_length] + "..."

    # Construct user-friendly message
    if sanitized_msg:
        return f"{error_type}: {sanitized_msg}"
    else:
        return error_type


class RateLimiter:
    """
    Simple rate limiter for API calls.

    Example:
        limiter = RateLimiter(max_calls=10, time_window=60)

        @limiter
        def api_call():
            return api.get_data()
    """

    def __init__(self, max_calls: int = 10, time_window: float = 60.0):
        """
        Initialize rate limiter.

        Args:
            max_calls: Maximum number of calls allowed
            time_window: Time window in seconds
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.call_times: list[float] = []

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator syntax support"""

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            return self.call(func, *args, **kwargs)

        return wrapper

    def call(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Execute function with rate limiting"""
        now = time.time()

        # Remove calls outside time window
        self.call_times = [t for t in self.call_times if now - t < self.time_window]

        # Check if rate limit exceeded
        if len(self.call_times) >= self.max_calls:
            oldest_call = self.call_times[0]
            wait_time = self.time_window - (now - oldest_call)

            logger.warning(
                f"Rate limit reached ({self.max_calls} calls per {self.time_window}s). "
                f"Waiting {wait_time:.1f}s..."
            )

            time.sleep(wait_time)

            # Retry after waiting
            return self.call(func, *args, **kwargs)

        # Record this call
        self.call_times.append(now)

        # Execute function
        return func(*args, **kwargs)


def handle_malformed_data(
    data: Any,
    expected_type: type,
    field_name: str = "data",
    default_value: Any = None,
) -> Any:
    """
    Safely handle potentially malformed data with validation.

    Example:
        # Validate JSON response
        findings = handle_malformed_data(
            response.json(),
            list,
            "findings",
            default_value=[]
        )

    Args:
        data: Data to validate
        expected_type: Expected type
        field_name: Name of field for error messages
        default_value: Value to return if validation fails

    Returns:
        Validated data or default_value
    """
    if data is None:
        logger.warning(f"{field_name} is None, using default value")
        return default_value

    if not isinstance(data, expected_type):
        logger.warning(
            f"{field_name} has wrong type: expected {expected_type.__name__}, "
            f"got {type(data).__name__}. Using default value"
        )
        return default_value

    return data


# Example usage and testing
if __name__ == "__main__":
    import logging

    logging.basicConfig(
        level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    print("=== Testing Circuit Breaker ===")
    breaker = CircuitBreaker(failure_threshold=3, timeout=5)

    def failing_function():
        raise ValueError("Simulated failure")

    # Test failures
    for i in range(5):
        try:
            breaker.call(failing_function)
        except ValueError:
            print(f"Attempt {i + 1}: Caught expected ValueError")
        except CircuitBreakerOpen as e:
            print(f"Attempt {i + 1}: Circuit breaker opened - {e.message}")

    print(f"\nCircuit breaker stats: {breaker.get_stats()}")

    print("\n=== Testing Retry with Backoff ===")

    @retry_with_backoff(max_retries=2, initial_delay=0.5)
    def sometimes_fails(fail_count=2):
        if sometimes_fails.attempts < fail_count:
            sometimes_fails.attempts += 1
            raise ConnectionError(f"Attempt {sometimes_fails.attempts} failed")
        return "Success!"

    sometimes_fails.attempts = 0
    result = sometimes_fails(fail_count=2)
    print(f"Result: {result}")

    print("\n=== Testing Graceful Degradation ===")

    @graceful_degradation(fallback_value="default_value")
    def may_fail():
        raise RuntimeError("Simulated error")

    result = may_fail()
    print(f"Result: {result}")

    print("\n=== Testing Rate Limiter ===")
    limiter = RateLimiter(max_calls=3, time_window=2.0)

    @limiter
    def rate_limited_function():
        print(f"Called at {time.time()}")
        return "success"

    # This should trigger rate limiting
    for i in range(5):
        result = rate_limited_function()

    print("\n=== Testing Error Message Sanitization ===")
    error = ValueError("API key=sk_test_12345678 failed with password=secret123")
    sanitized = sanitize_error_message(error)
    print(f"Sanitized: {sanitized}")
