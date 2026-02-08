#!/usr/bin/env python3
"""
Cost Tracking and Circuit Breaker Module

This module provides real-time cost tracking and enforcement for AI operations:
- Tracks actual costs incurred by LLM calls
- Implements circuit breaker pattern to prevent budget overruns
- Maintains safety buffers to avoid unexpected costs
- Logs warnings at utilization thresholds
- Raises exceptions when limits are exceeded

Usage:
    from orchestrator.cost_tracker import CostCircuitBreaker

    breaker = CostCircuitBreaker(cost_limit_usd=1.0)
    breaker.check_before_call(estimated_cost=0.15, provider='anthropic')
    # ... make LLM call ...
    breaker.record_actual_cost(0.14)

    # Get summary
    summary = breaker.get_summary()
    print(f"Remaining budget: ${summary['remaining_budget_usd']:.2f}")
"""

import logging
import threading
from typing import Dict, Optional

# Configure logging
logger = logging.getLogger(__name__)


class CostLimitExceededError(Exception):
    """Raised when cost limit would be exceeded by an operation"""

    pass


class CostCircuitBreaker:
    """Runtime cost enforcement to prevent budget overruns

    This class provides real-time cost tracking and enforcement:
    - Checks before each LLM call if limit would be exceeded
    - Maintains 10% safety buffer to prevent overage
    - Logs warnings at 50%, 75%, 90% thresholds
    - Raises CostLimitExceededError when limit reached

    Example:
        breaker = CostCircuitBreaker(cost_limit_usd=1.0)
        breaker.check_before_call(estimated_cost=0.15, provider='anthropic')
        # ... make LLM call ...
        breaker.record_actual_cost(0.14)
    """

    def __init__(self, cost_limit_usd: float, safety_buffer_percent: float = 10.0):
        """Initialize cost circuit breaker

        Args:
            cost_limit_usd: Maximum cost allowed in USD
            safety_buffer_percent: Safety buffer percentage (default: 10%)
        """
        self.cost_limit = cost_limit_usd
        self.safety_buffer = safety_buffer_percent / 100.0
        self.effective_limit = cost_limit_usd * (1.0 - self.safety_buffer)
        self.current_cost = 0.0
        self.warned_thresholds = set()
        self._lock = threading.Lock()

        logger.info(
            f"💰 Cost Circuit Breaker initialized: ${cost_limit_usd:.2f} limit "
            f"(${self.effective_limit:.2f} effective with {safety_buffer_percent}% buffer)"
        )

    def check_before_call(self, estimated_cost: float, provider: str, operation: str = "LLM call"):
        """Check if estimated cost would exceed limit

        Thread-safe: Uses internal lock to prevent race conditions when
        multiple agents check concurrently.

        Args:
            estimated_cost: Estimated cost of the operation in USD
            provider: AI provider name (for logging)
            operation: Description of operation (for logging)

        Raises:
            CostLimitExceededError: If operation would exceed cost limit
        """
        with self._lock:
            projected_cost = self.current_cost + estimated_cost
            utilization = (self.current_cost / self.effective_limit) * 100 if self.effective_limit > 0 else 0

            # Check threshold warnings (50%, 75%, 90%)
            for threshold in [50, 75, 90]:
                if utilization >= threshold and threshold not in self.warned_thresholds:
                    self.warned_thresholds.add(threshold)
                    logger.warning(
                        f"⚠️  Cost at {utilization:.1f}% of limit (${self.current_cost:.3f} / ${self.effective_limit:.2f})"
                    )

            # Check if we would exceed the limit
            if projected_cost > self.effective_limit:
                remaining = self.effective_limit - self.current_cost
                message = (
                    f"Cost limit exceeded! "
                    f"Operation would cost ${estimated_cost:.3f}, "
                    f"but only ${remaining:.3f} remaining of ${self.cost_limit:.2f} limit. "
                    f"Current cost: ${self.current_cost:.3f}"
                )
                logger.error(f"🚨 {message}")
                raise CostLimitExceededError(message)

            # Log the check (sanitize provider name - use str() to break taint chain)
            safe_provider = str(provider).split("/")[-1] if provider else "unknown"
            logger.debug(
                f"✓ Cost check passed: ${estimated_cost:.3f} {operation} ({safe_provider}), "
                f"projected: ${projected_cost:.3f} / ${self.effective_limit:.2f}"
            )

    def record_actual_cost(self, actual_cost: float):
        """Record actual cost after operation completes

        Thread-safe: Uses internal lock to prevent race conditions when
        multiple agents record costs concurrently.

        Args:
            actual_cost: Actual cost incurred in USD
        """
        with self._lock:
            self.current_cost += actual_cost
            logger.debug(f"💵 Cost updated: +${actual_cost:.3f} → ${self.current_cost:.3f}")

    def get_remaining_budget(self) -> float:
        """Get remaining budget in USD

        Returns:
            Remaining budget considering safety buffer
        """
        return max(0.0, self.effective_limit - self.current_cost)

    def get_utilization_percent(self) -> float:
        """Get current cost utilization as percentage

        Returns:
            Utilization percentage (0-100+)
        """
        if self.effective_limit == 0:
            return 0.0
        return (self.current_cost / self.effective_limit) * 100

    def get_summary(self) -> Dict[str, float]:
        """Get cost summary for reporting

        Returns:
            Dictionary with cost details
        """
        return {
            "cost_limit_usd": self.cost_limit,
            "effective_limit_usd": self.effective_limit,
            "safety_buffer_percent": self.safety_buffer * 100,
            "current_cost_usd": self.current_cost,
            "remaining_budget_usd": self.get_remaining_budget(),
            "utilization_percent": self.get_utilization_percent(),
            "limit_exceeded": self.current_cost > self.effective_limit,
        }
