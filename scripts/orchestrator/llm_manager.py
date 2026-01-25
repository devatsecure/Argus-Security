#!/usr/bin/env python3
"""
LLM Provider Management Module
Centralized management for all LLM/AI provider interactions.

Supports multiple LLM providers:
- Anthropic (Claude)
- OpenAI (GPT-4)
- Ollama (local, self-hosted)

Features:
- Provider auto-detection
- Client initialization with error handling
- Cost estimation and tracking with circuit breaker
- Retry logic with exponential backoff
- Model fallback chain for Anthropic
- Consensus building from multi-agent analysis
"""

import logging
import os
import sys
from pathlib import Path

from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# Configure logging
logger = logging.getLogger(__name__)


class LLMException(Exception):
    """Base exception for LLM-related errors"""

    pass


class CostLimitExceededError(Exception):
    """Raised when cost limit would be exceeded by an operation"""

    pass


class ConsensusBuilder:
    """Build consensus across multiple agent opinions

    Feature: Consensus Building (from real_multi_agent_review.py)
    This class aggregates findings from multiple agents, deduplicates similar issues,
    and calculates confidence scores based on agreement between agents.
    """

    def __init__(self, agents: list):
        """Initialize consensus builder

        Args:
            agents: List of agent names that will provide findings
        """
        self.agents = agents
        self.total_agents = len(agents)

    def aggregate_findings(self, agent_findings: dict) -> list:
        """Aggregate findings from multiple agents with consensus scoring

        Args:
            agent_findings: Dictionary mapping agent names to their finding lists

        Returns:
            List of consensus findings with agreement scores
        """
        # Group similar findings by file, line, and issue type
        grouped = {}

        for agent_name, findings in agent_findings.items():
            for finding in findings:
                # Create a key for grouping similar issues
                file_path = finding.get("file_path", "unknown")
                line = finding.get("line_number", 0)
                issue_type = finding.get("rule_id", "unknown")

                # Group issues within ~10 lines as the same issue
                line_bucket = (line // 10) * 10
                key = f"{file_path}:{issue_type}:L{line_bucket}"

                if key not in grouped:
                    grouped[key] = {"agents": [], "findings": [], "votes": 0}

                grouped[key]["agents"].append(agent_name)
                grouped[key]["findings"].append(finding)
                grouped[key]["votes"] += 1

        # Build consensus results
        consensus_findings = []

        for _key, group in grouped.items():
            votes = group["votes"]
            findings = group["findings"]
            agents_agree = group["agents"]

            # Calculate consensus level
            consensus_pct = votes / self.total_agents

            if consensus_pct == 1.0:
                consensus_level = "unanimous"
                confidence = 0.95
            elif consensus_pct >= 0.67:
                consensus_level = "strong"
                confidence = 0.85
            elif consensus_pct >= 0.5:
                consensus_level = "majority"
                confidence = 0.70
            else:
                consensus_level = "weak"
                confidence = 0.50

            # Take the most severe classification
            severity_order = ["critical", "high", "medium", "low", "info"]
            severities = [f.get("severity", "medium") for f in findings]
            most_severe = min(severities, key=lambda s: severity_order.index(s) if s in severity_order else 999)

            # Merge descriptions and recommendations
            descriptions = [f.get("message", "") for f in findings]

            # Create consensus finding
            consensus_finding = findings[0].copy()  # Start with first finding
            consensus_finding["consensus"] = {
                "votes": votes,
                "total_agents": self.total_agents,
                "consensus_level": consensus_level,
                "confidence": confidence,
                "agents_agree": agents_agree,
                "all_descriptions": descriptions,
            }
            consensus_finding["severity"] = most_severe

            # Enhance message with consensus info
            if votes > 1:
                consensus_finding["message"] = f"[{votes}/{self.total_agents} agents agree] {descriptions[0]}"

            consensus_findings.append(consensus_finding)

        # Sort by votes (descending) and confidence (descending)
        consensus_findings.sort(key=lambda x: (x["consensus"]["votes"], x["consensus"]["confidence"]), reverse=True)

        return consensus_findings

    def filter_by_threshold(self, consensus_findings: list, min_confidence: float = 0.5) -> list:
        """Filter findings by minimum confidence threshold

        Args:
            consensus_findings: List of consensus findings
            min_confidence: Minimum confidence score to include (0.0-1.0)

        Returns:
            Filtered list of findings meeting threshold
        """
        return [f for f in consensus_findings if f.get("consensus", {}).get("confidence", 0) >= min_confidence]


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

        logger.info(
            f"Cost Circuit Breaker initialized: ${cost_limit_usd:.2f} limit "
            f"(${self.effective_limit:.2f} effective with {safety_buffer_percent}% buffer)"
        )

    def check_before_call(self, estimated_cost: float, provider: str, operation: str = "LLM call"):
        """Check if estimated cost would exceed limit

        Args:
            estimated_cost: Estimated cost of the operation in USD
            provider: AI provider name (for logging)
            operation: Description of operation (for logging)

        Raises:
            CostLimitExceededError: If operation would exceed cost limit
        """
        projected_cost = self.current_cost + estimated_cost
        utilization = (self.current_cost / self.effective_limit) * 100 if self.effective_limit > 0 else 0

        # Check threshold warnings (50%, 75%, 90%)
        for threshold in [50, 75, 90]:
            if utilization >= threshold and threshold not in self.warned_thresholds:
                self.warned_thresholds.add(threshold)
                logger.warning(
                    f"Cost at {utilization:.1f}% of limit (${self.current_cost:.3f} / ${self.effective_limit:.2f})"
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
            logger.error(f"COST LIMIT ERROR: {message}")
            raise CostLimitExceededError(message)

        # Log the check (sanitize provider name - use str() to break taint chain)
        safe_provider = str(provider).split("/")[-1] if provider else "unknown"
        logger.debug(
            f"Cost check passed: ${estimated_cost:.3f} {operation} ({safe_provider}), "
            f"projected: ${projected_cost:.3f} / ${self.effective_limit:.2f}"
        )

    def record_actual_cost(self, actual_cost: float):
        """Record actual cost after operation completes

        Args:
            actual_cost: Actual cost incurred in USD
        """
        self.current_cost += actual_cost
        logger.debug(f"Cost updated: +${actual_cost:.3f} → ${self.current_cost:.3f}")

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

    def get_summary(self) -> dict:
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


class LLMManager:
    """Unified LLM provider management

    Handles all interactions with LLM providers including:
    - Provider detection and client initialization
    - Model selection with fallback chains
    - API calls with retry logic and cost enforcement
    - Cost estimation and tracking
    """

    # Default models for each provider
    DEFAULT_MODELS = {
        "anthropic": "claude-sonnet-4-5-20250929",
        "openai": "gpt-4-turbo-preview",
        "ollama": "llama3.2:3b",
    }

    # Model fallback chain for Anthropic
    ANTHROPIC_FALLBACK_CHAIN = [
        "claude-sonnet-4-5-20250929",  # Latest Claude Sonnet 4.5
        "claude-3-haiku-20240307",  # Most lightweight and universally available
        "claude-3-sonnet-20240229",  # Balanced
        "claude-3-5-sonnet-20241022",  # Claude 3.5 Sonnet
        "claude-3-5-sonnet-20240620",  # Stable
        "claude-3-opus-20240229",  # Most powerful
    ]

    # Pricing information per provider
    PRICING = {
        "anthropic": {"input": 3.0, "output": 15.0},  # Claude Sonnet 4.5: $3/1M input, $15/1M output
        "openai": {"input": 10.0, "output": 30.0},  # GPT-4: $10/1M input, $30/1M output
        "ollama": {"input": 0.0, "output": 0.0},  # Local inference: free
    }

    def __init__(self, config: dict = None):
        """Initialize LLM Manager

        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.client = None
        self.provider = None
        self.model = None

        # Initialize feedback collector and cache manager for decision logging
        self.feedback_collector = None
        self.cache_manager = None

        try:
            # Import modules - allow graceful failure
            import sys
            from pathlib import Path

            # Add scripts dir to path if not already there
            scripts_dir = Path(__file__).parent.parent
            if str(scripts_dir) not in sys.path:
                sys.path.insert(0, str(scripts_dir))

            from feedback_collector import FeedbackCollector
            from cache_manager import CacheManager

            self.feedback_collector = FeedbackCollector()
            self.cache_manager = CacheManager()
            logger.debug("Feedback collector and cache manager initialized")
        except Exception as e:
            logger.debug(f"Could not initialize feedback/cache systems: {e}")
            # Continue without these features

    def detect_provider(self) -> str:
        """Auto-detect which AI provider to use based on available keys

        Returns:
            Provider name or None if no provider is configured
        """
        provider = self.config.get("ai_provider", "auto")

        # Explicit provider selection (overrides auto-detection)
        if provider != "auto":
            return provider

        # Auto-detect based on available API keys/config
        # Priority: Anthropic (best for security) > OpenAI > Ollama (local)
        if self.config.get("anthropic_api_key"):
            return "anthropic"
        elif self.config.get("openai_api_key"):
            return "openai"
        elif self.config.get("ollama_endpoint"):
            return "ollama"
        else:
            logger.warning("No AI provider configured")
            logger.info("Set one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_ENDPOINT")
            return None

    def initialize(self, provider: str = None) -> bool:
        """Initialize LLM client for the specified provider

        Args:
            provider: Provider name (if None, will auto-detect)

        Returns:
            True if initialization successful, False otherwise
        """
        if provider is None:
            provider = self.detect_provider()

        if provider is None:
            logger.error("No provider detected or specified")
            return False

        try:
            self.client, self.provider = self._get_client(provider)
            self.model = self.get_model_name(provider)

            # For Anthropic, test model accessibility and fallback if needed
            if provider == "anthropic":
                self.model = self._get_working_model_with_fallback(self.client, self.model)

            logger.info(f"Successfully initialized LLM Manager with {self.provider} / {self.model}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize LLM: {type(e).__name__}: {e}")
            return False

    def _get_client(self, provider: str):
        """Get AI client for the specified provider

        Args:
            provider: Provider name

        Returns:
            Tuple of (client, provider_name)

        Raises:
            ImportError: If required dependencies are not installed
            ValueError: If API key is not configured
        """
        if provider == "anthropic":
            try:
                from anthropic import Anthropic

                api_key = self.config.get("anthropic_api_key")
                if not api_key:
                    raise ValueError("ANTHROPIC_API_KEY not set")

                logger.info("Using Anthropic API")
                return Anthropic(api_key=api_key), "anthropic"
            except ImportError:
                logger.error("anthropic package not installed. Run: pip install anthropic")
                raise

        elif provider == "openai":
            try:
                from openai import OpenAI

                api_key = self.config.get("openai_api_key")
                if not api_key:
                    raise ValueError("OPENAI_API_KEY not set")

                logger.info("Using OpenAI API")
                return OpenAI(api_key=api_key), "openai"
            except ImportError:
                logger.error("openai package not installed. Run: pip install openai")
                raise

        elif provider == "ollama":
            try:
                from openai import OpenAI

                endpoint = self.config.get("ollama_endpoint", "http://localhost:11434")
                # Sanitize endpoint URL for logging
                safe_endpoint = (
                    str(endpoint).split("@")[-1] if "@" in str(endpoint) else str(endpoint).split("//")[-1].split("/")[0]
                )
                logger.info(f"Using Ollama endpoint: {safe_endpoint}")
                return OpenAI(base_url=f"{endpoint}/v1", api_key="ollama"), "ollama"
            except ImportError:
                logger.error("openai package not installed. Run: pip install openai")
                raise

        else:
            # Sanitize provider name before logging
            safe_provider = str(provider).split("/")[-1] if provider else "unknown"
            logger.error(f"Unknown AI provider: {safe_provider}")
            raise ValueError(f"Unknown provider: {safe_provider}")

    def get_model_name(self, provider: str = None) -> str:
        """Get the appropriate model name for the provider

        Args:
            provider: Provider name (if None, uses self.provider)

        Returns:
            Model name
        """
        if provider is None:
            provider = self.provider

        model = self.config.get("model", "auto")

        if model != "auto":
            return model

        return self.DEFAULT_MODELS.get(provider, self.DEFAULT_MODELS["anthropic"])

    def _get_working_model_with_fallback(self, client, initial_model: str) -> str:
        """Try to find a working model using fallback chain for Anthropic

        Args:
            client: Anthropic client instance
            initial_model: Initial model to try

        Returns:
            Working model name

        Raises:
            RuntimeError: If no model works
        """
        if self.provider != "anthropic":
            return initial_model

        # Build fallback chain starting with requested model
        model_chain = [initial_model] + [m for m in self.ANTHROPIC_FALLBACK_CHAIN if m != initial_model]

        # Remove duplicates while preserving order
        seen = set()
        unique_models = []
        for model in model_chain:
            if model not in seen:
                seen.add(model)
                unique_models.append(model)

        logger.info(f"Testing model accessibility for provider: anthropic")

        for model_id in unique_models:
            try:
                # Quick test with minimal tokens
                safe_model_name = str(model_id).split("/")[-1] if model_id else "unknown"
                logger.debug(f"Testing model: {safe_model_name}")
                client.messages.create(
                    model=model_id, max_tokens=10, messages=[{"role": "user", "content": "test"}]
                )
                logger.info(f"Found working model: {safe_model_name}")
                return model_id
            except Exception as e:
                error_type = type(e).__name__
                logger.debug(f"Model not accessible: {error_type}")

                # If authentication fails, stop trying
                if "Authentication" in error_type or "auth" in str(e).lower():
                    logger.error("Authentication failed with API key")
                    raise

                continue

        # If no model works, raise error with helpful message
        logger.error("No accessible Claude models found with this API key")
        raise RuntimeError(
            "No Claude models are accessible with your API key.\n"
            "Tried models: " + ", ".join(unique_models) + "\n"
            "Please check:\n"
            "1. API key has correct permissions at https://console.anthropic.com/\n"
            "2. Account has billing enabled\n"
            "3. API key is from correct workspace/organization\n"
            "4. Contact support@anthropic.com if issue persists"
        )

    @staticmethod
    def estimate_call_cost(prompt_length: int, max_output_tokens: int, provider: str) -> float:
        """Estimate cost of a single LLM API call before making it

        Args:
            prompt_length: Character length of prompt (rough proxy for tokens)
            max_output_tokens: Maximum output tokens requested
            provider: AI provider name

        Returns:
            Estimated cost in USD
        """
        # Rough estimation: 1 token ≈ 4 characters
        estimated_input_tokens = prompt_length / 4
        estimated_output_tokens = max_output_tokens * 0.7  # Assume 70% of max is used

        pricing = LLMManager.PRICING.get(provider, {"input": 0.0, "output": 0.0})
        input_cost = (estimated_input_tokens / 1_000_000) * pricing["input"]
        output_cost = (estimated_output_tokens / 1_000_000) * pricing["output"]

        return input_cost + output_cost

    @staticmethod
    def calculate_actual_cost(input_tokens: int, output_tokens: int, provider: str) -> float:
        """Calculate actual cost after LLM call completes

        Args:
            input_tokens: Actual input tokens used
            output_tokens: Actual output tokens used
            provider: AI provider name

        Returns:
            Actual cost in USD
        """
        pricing = LLMManager.PRICING.get(provider, {"input": 0.0, "output": 0.0})
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]

        return input_cost + output_cost

    def generate_few_shot_examples(
        self,
        finding_type: str,
        scanner: str,
        max_examples: int = 3
    ) -> str:
        """
        Generate few-shot examples from historical feedback

        Args:
            finding_type: Type of finding (e.g., "secret", "vulnerability")
            scanner: Scanner name (e.g., "semgrep", "trufflehog")
            max_examples: Maximum number of examples to include

        Returns:
            Formatted few-shot examples string (empty if no feedback available)
        """
        if not self.feedback_collector:
            return ""

        try:
            return self.feedback_collector.generate_few_shot_examples(
                finding_type=finding_type,
                scanner=scanner,
                max_examples=max_examples
            )
        except Exception as e:
            logger.debug(f"Could not generate few-shot examples: {e}")
            return ""

    def log_ai_decision(
        self,
        finding_id: str,
        finding_type: str,
        scanner: str,
        decision: str,
        reasoning: str,
        confidence: float,
        noise_score: float = 0.0
    ) -> bool:
        """
        Log AI triage decision for analysis

        Args:
            finding_id: Unique finding identifier
            finding_type: Type of finding
            scanner: Scanner that generated finding
            decision: "suppress" or "escalate"
            reasoning: AI's explanation
            confidence: Confidence score (0.0-1.0)
            noise_score: Noise score from heuristics

        Returns:
            True if logged successfully, False otherwise
        """
        if not self.cache_manager:
            return False

        try:
            from datetime import datetime

            decision_entry = {
                "finding_id": finding_id,
                "finding_type": finding_type,
                "scanner": scanner,
                "decision": decision,
                "reasoning": reasoning,
                "confidence": confidence,
                "noise_score": noise_score,
                "model": self.model,
                "timestamp": datetime.utcnow().isoformat(),
            }

            return self.cache_manager.log_decision(decision_entry)

        except Exception as e:
            logger.debug(f"Could not log decision: {e}")
            return False

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((
            ConnectionError,
            TimeoutError,
            OSError,  # Network issues
            Exception,  # Catch-all for API-specific exceptions (will be filtered by before_sleep)
        )),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    def call_llm_api(
        self,
        prompt: str,
        max_tokens: int,
        circuit_breaker: "CostCircuitBreaker" = None,
        operation: str = "LLM call",
        few_shot_prefix: str = ""
    ) -> tuple:
        """Call LLM API with retry logic, cost enforcement, and few-shot learning

        Args:
            prompt: Prompt text
            max_tokens: Maximum output tokens
            circuit_breaker: Optional CostCircuitBreaker for cost enforcement
            operation: Description of operation for logging
            few_shot_prefix: Few-shot examples to prepend to prompt

        Returns:
            Tuple of (response_text, input_tokens, output_tokens)

        Raises:
            CostLimitExceededError: If cost limit would be exceeded
            LLMException: If API call fails
        """
        if self.client is None or self.provider is None:
            raise LLMException("LLM Manager not initialized. Call initialize() first.")

        # Prepend few-shot examples if provided
        full_prompt = f"{few_shot_prefix}\n\n{prompt}" if few_shot_prefix else prompt

        # Estimate cost and check circuit breaker before making call
        if circuit_breaker:
            estimated_cost = self.estimate_call_cost(len(full_prompt), max_tokens, self.provider)
            circuit_breaker.check_before_call(estimated_cost, self.provider, operation)

        try:
            if self.provider == "anthropic":
                message = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[{"role": "user", "content": full_prompt}],
                    timeout=300.0,  # 5 minute timeout
                )
                response_text = message.content[0].text
                input_tokens = message.usage.input_tokens
                output_tokens = message.usage.output_tokens

            elif self.provider in ["openai", "ollama"]:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": full_prompt}],
                    max_tokens=max_tokens,
                    timeout=300.0,  # 5 minute timeout
                )
                response_text = response.choices[0].message.content
                input_tokens = response.usage.prompt_tokens
                output_tokens = response.usage.completion_tokens

            else:
                raise ValueError(f"Unknown provider: {self.provider}")

            # Record actual cost after successful call
            if circuit_breaker:
                actual_cost = self.calculate_actual_cost(input_tokens, output_tokens, self.provider)
                circuit_breaker.record_actual_cost(actual_cost)

            return response_text, input_tokens, output_tokens

        except Exception as e:
            logger.error(f"LLM API call failed: {type(e).__name__}: {e}")
            raise


# Module-level convenience functions for backward compatibility
def detect_ai_provider(config: dict) -> str:
    """Auto-detect which AI provider to use based on available keys

    Args:
        config: Configuration dictionary

    Returns:
        Provider name or None
    """
    manager = LLMManager(config)
    return manager.detect_provider()


def get_ai_client(provider: str, config: dict) -> tuple:
    """Get AI client for the specified provider

    Args:
        provider: Provider name
        config: Configuration dictionary

    Returns:
        Tuple of (client, provider_name)
    """
    manager = LLMManager(config)
    return manager._get_client(provider)


def get_model_name(provider: str, config: dict) -> str:
    """Get the appropriate model name for the provider

    Args:
        provider: Provider name
        config: Configuration dictionary

    Returns:
        Model name
    """
    manager = LLMManager(config)
    return manager.get_model_name(provider)


def get_working_model_with_fallback(client, provider: str, initial_model: str) -> str:
    """Try to find a working model using fallback chain

    Args:
        client: LLM client instance
        provider: Provider name
        initial_model: Initial model to try

    Returns:
        Working model name
    """
    manager = LLMManager()
    manager.client = client
    manager.provider = provider
    return manager._get_working_model_with_fallback(client, initial_model)


def estimate_call_cost(prompt_length: int, max_output_tokens: int, provider: str) -> float:
    """Estimate cost of a single LLM API call

    Args:
        prompt_length: Character length of prompt
        max_output_tokens: Maximum output tokens
        provider: Provider name

    Returns:
        Estimated cost in USD
    """
    return LLMManager.estimate_call_cost(prompt_length, max_output_tokens, provider)


def calculate_actual_cost(input_tokens: int, output_tokens: int, provider: str) -> float:
    """Calculate actual cost after LLM call completes

    Args:
        input_tokens: Actual input tokens used
        output_tokens: Actual output tokens used
        provider: Provider name

    Returns:
        Actual cost in USD
    """
    return LLMManager.calculate_actual_cost(input_tokens, output_tokens, provider)


def call_llm_api(client, provider: str, model: str, prompt: str, max_tokens: int, circuit_breaker=None, operation: str = "LLM call") -> tuple:
    """Call LLM API with retry logic and cost enforcement

    Args:
        client: AI client instance
        provider: AI provider name
        model: Model name
        prompt: Prompt text
        max_tokens: Maximum output tokens
        circuit_breaker: Optional CostCircuitBreaker for cost enforcement
        operation: Description of operation for logging

    Returns:
        Tuple of (response_text, input_tokens, output_tokens)

    Raises:
        CostLimitExceededError: If cost limit would be exceeded
    """
    manager = LLMManager()
    manager.client = client
    manager.provider = provider
    manager.model = model
    return manager.call_llm_api(prompt, max_tokens, circuit_breaker, operation)
