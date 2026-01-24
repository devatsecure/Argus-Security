#!/usr/bin/env python3
"""
Logging Utilities for Argus
Structured logging with sanitization and performance tracking.

This module provides standardized logging setup with automatic
secret sanitization and performance timing decorators.
"""

import functools
import logging
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

# Patterns for sensitive data that should be redacted
SENSITIVE_PATTERNS = [
    # API Keys and tokens
    (re.compile(r'(api[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9_\-]{20,})(["\']?)', re.IGNORECASE), r'\1***REDACTED***\3'),
    (re.compile(r'(token\s*[=:]\s*["\']?)([a-zA-Z0-9_\-]{20,})(["\']?)', re.IGNORECASE), r'\1***REDACTED***\3'),
    (re.compile(r'(bearer\s+)([a-zA-Z0-9_\-\.]{20,})', re.IGNORECASE), r'\1***REDACTED***'),

    # Authorization headers
    (re.compile(r'(Authorization:\s*Bearer\s+)([a-zA-Z0-9_\-\.]+)', re.IGNORECASE), r'\1***REDACTED***'),
    (re.compile(r'(Authorization:\s*Basic\s+)([a-zA-Z0-9+/=]+)', re.IGNORECASE), r'\1***REDACTED***'),

    # AWS credentials
    (re.compile(r'(AKIA[0-9A-Z]{16})', re.IGNORECASE), r'***REDACTED_AWS_KEY***'),
    (re.compile(r'(aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9/+=]{40})(["\']?)', re.IGNORECASE), r'\1***REDACTED***\3'),

    # GitHub tokens
    (re.compile(r'(gh[pousr]_[a-zA-Z0-9]{36,})', re.IGNORECASE), r'***REDACTED_GITHUB_TOKEN***'),

    # Passwords
    (re.compile(r'(password\s*[=:]\s*["\']?)([^"\']{8,})(["\']?)', re.IGNORECASE), r'\1***REDACTED***\3'),
    (re.compile(r'(passwd\s*[=:]\s*["\']?)([^"\']{8,})(["\']?)', re.IGNORECASE), r'\1***REDACTED***\3'),

    # Private keys (SSH, PGP, etc.)
    (re.compile(r'(-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----)', re.IGNORECASE), r'***REDACTED_PRIVATE_KEY***'),

    # Credit card numbers (basic pattern)
    (re.compile(r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b'), r'***REDACTED_CC***'),

    # Generic secrets
    (re.compile(r'(secret\s*[=:]\s*["\']?)([a-zA-Z0-9_\-]{16,})(["\']?)', re.IGNORECASE), r'\1***REDACTED***\3'),
]


class SanitizingFormatter(logging.Formatter):
    """
    Custom log formatter that redacts sensitive information

    This formatter automatically sanitizes log messages to prevent
    accidental leakage of secrets, API keys, passwords, and other
    sensitive data.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with sanitization

        Args:
            record: Log record to format

        Returns:
            Formatted and sanitized log message
        """
        # Format the message normally first
        original_msg = super().format(record)

        # Apply sanitization patterns
        sanitized_msg = original_msg
        for pattern, replacement in SENSITIVE_PATTERNS:
            sanitized_msg = pattern.sub(replacement, sanitized_msg)

        return sanitized_msg


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    json_format: bool = False,
    sanitize: bool = True
) -> None:
    """
    Setup standardized logging configuration

    Args:
        level: Logging level (default: INFO)
        log_file: Optional file path for log output
        json_format: Use JSON format for structured logging (default: False)
        sanitize: Enable log sanitization (default: True)

    Example:
        setup_logging(level=logging.DEBUG, log_file=Path("audit.log"))
    """
    # Create handlers
    handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    handlers.append(console_handler)

    # File handler (if specified)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        handlers.append(file_handler)

    # Choose formatter
    if json_format:
        formatter = StructuredJsonFormatter()
    elif sanitize:
        formatter = SanitizingFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    # Apply formatter to all handlers
    for handler in handlers:
        handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add new handlers
    for handler in handlers:
        root_logger.addHandler(handler)


class StructuredJsonFormatter(logging.Formatter):
    """
    JSON formatter for structured logging

    Outputs log records as JSON for easy parsing by log aggregation systems.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON

        Args:
            record: Log record to format

        Returns:
            JSON-formatted log message
        """
        import json

        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        # Sanitize before JSON encoding
        message_str = json.dumps(log_data)
        for pattern, replacement in SENSITIVE_PATTERNS:
            message_str = pattern.sub(replacement, message_str)

        return message_str


def timed(func: Optional[Callable] = None, *, log_level: int = logging.INFO) -> Callable:
    """
    Decorator to time function execution

    Args:
        func: Function to decorate
        log_level: Logging level for timing message (default: INFO)

    Returns:
        Decorated function

    Example:
        @timed
        def slow_function():
            time.sleep(1)

        @timed(log_level=logging.DEBUG)
        def fast_function():
            pass
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(f.__module__)
            start_time = time.time()

            logger.log(log_level, f"Starting {f.__name__}")

            try:
                result = f(*args, **kwargs)
                elapsed = time.time() - start_time
                logger.log(
                    log_level,
                    f"Completed {f.__name__} in {elapsed:.3f}s"
                )
                return result

            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(
                    f"Failed {f.__name__} after {elapsed:.3f}s: {type(e).__name__}: {e}"
                )
                raise

        return wrapper

    if func is None:
        return decorator
    return decorator(func)


class PerformanceTimer:
    """
    Context manager for timing code blocks

    Example:
        with PerformanceTimer("database_query"):
            result = db.query(...)
        # Logs: "database_query completed in 0.523s"
    """

    def __init__(self, name: str, log_level: int = logging.INFO):
        """
        Initialize timer

        Args:
            name: Name of the operation being timed
            log_level: Logging level (default: INFO)
        """
        self.name = name
        self.log_level = log_level
        self.logger = logging.getLogger(__name__)
        self.start_time: Optional[float] = None

    def __enter__(self):
        """Start timer"""
        self.start_time = time.time()
        self.logger.log(self.log_level, f"Starting {self.name}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop timer and log elapsed time"""
        if self.start_time is not None:
            elapsed = time.time() - self.start_time

            if exc_type is None:
                self.logger.log(
                    self.log_level,
                    f"Completed {self.name} in {elapsed:.3f}s"
                )
            else:
                self.logger.error(
                    f"Failed {self.name} after {elapsed:.3f}s: "
                    f"{exc_type.__name__}: {exc_val}"
                )

        return False  # Don't suppress exceptions


def sanitize_message(message: str) -> str:
    """
    Manually sanitize a message to remove sensitive data

    Args:
        message: Message to sanitize

    Returns:
        Sanitized message

    Example:
        safe_msg = sanitize_message(f"API call with key: {api_key}")
    """
    sanitized = message
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def log_function_call(
    logger: logging.Logger,
    level: int = logging.DEBUG,
    log_args: bool = True,
    log_result: bool = False
) -> Callable:
    """
    Decorator to log function calls with arguments and results

    Args:
        logger: Logger instance to use
        level: Logging level (default: DEBUG)
        log_args: Log function arguments (default: True)
        log_result: Log function result (default: False)

    Returns:
        Decorated function

    Example:
        @log_function_call(logger, log_result=True)
        def process_data(data):
            return data.upper()
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_name = f"{func.__module__}.{func.__name__}"

            # Log function call
            if log_args:
                # Sanitize arguments
                args_str = ", ".join(repr(arg) for arg in args)
                kwargs_str = ", ".join(f"{k}={repr(v)}" for k, v in kwargs.items())
                all_args = ", ".join(filter(None, [args_str, kwargs_str]))
                safe_args = sanitize_message(all_args)
                logger.log(level, f"Calling {func_name}({safe_args})")
            else:
                logger.log(level, f"Calling {func_name}")

            # Execute function
            result = func(*args, **kwargs)

            # Log result
            if log_result:
                safe_result = sanitize_message(repr(result))
                logger.log(level, f"{func_name} returned: {safe_result}")

            return result

        return wrapper

    return decorator


class LoggingContext:
    """
    Context manager to temporarily change log level

    Example:
        with LoggingContext(logging.DEBUG):
            # Debug logging enabled
            do_detailed_work()
        # Back to original log level
    """

    def __init__(self, level: int, logger: Optional[logging.Logger] = None):
        """
        Initialize logging context

        Args:
            level: Temporary log level
            logger: Logger to modify (default: root logger)
        """
        self.level = level
        self.logger = logger or logging.getLogger()
        self.original_level = self.logger.level

    def __enter__(self):
        """Set temporary log level"""
        self.logger.setLevel(self.level)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore original log level"""
        self.logger.setLevel(self.original_level)
        return False


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    """
    Get a logger with standardized configuration

    Args:
        name: Logger name (typically __name__)
        level: Optional logging level override

    Returns:
        Configured logger instance

    Example:
        logger = get_logger(__name__)
        logger.info("Processing started")
    """
    logger = logging.getLogger(name)

    if level is not None:
        logger.setLevel(level)

    return logger
