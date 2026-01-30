#!/usr/bin/env python3
"""
Argus Security Exceptions Module

Custom exception classes for the Argus security platform.
Centralized exception definitions for consistent error handling.
"""

__all__ = [
    "ArgusError",
    "CostLimitExceededError",
    "CostLimitExceeded",
    "ScannerError",
    "ValidationError",
]


class ArgusError(Exception):
    """Base exception for all Argus-related errors"""
    pass


class CostLimitExceededError(ArgusError):
    """Raised when cost limit would be exceeded by an operation"""
    pass


# Alias for backwards compatibility
CostLimitExceeded = CostLimitExceededError


class ScannerError(ArgusError):
    """Raised when a security scanner fails"""
    pass


class ValidationError(ArgusError):
    """Raised when validation of findings or output fails"""
    pass
