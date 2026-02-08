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
    retry_if_exception,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from error_classifier import (
    classify_llm_error,
    classified_retry_predicate,
    classified_wait,
    is_retryable_error,
)

# Configure logging
logger = logging.getLogger(__name__)


class LLMException(Exception):
    """Base exception for LLM-related errors"""

    pass


# CostLimitExceededError consolidated into exceptions module
from exceptions import CostLimitExceededError


# ConsensusBuilder consolidated into consensus_builder.py (has AST-based dedup)
from consensus_builder import ConsensusBuilder


# CostCircuitBreaker consolidated into cost_tracker.py
from orchestrator.cost_tracker import CostCircuitBreaker


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

        # Apply retry strategy based on config
        self._apply_retry_strategy()

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

    def _apply_retry_strategy(self):
        """Apply retry wrapper to call_llm_api based on config.

        If ``enable_smart_retry`` is True (default), wraps ``call_llm_api``
        with the classified smart retry decorator that uses error
        classification to decide whether and how long to wait.

        If False, uses the legacy tenacity-based retry for backward
        compatibility.
        """
        enable_smart = self.config.get("enable_smart_retry", True)
        max_attempts = self.config.get("retry_max_attempts", 3)

        if enable_smart:
            from error_classifier import smart_retry

            self.call_llm_api = smart_retry(
                max_attempts=max_attempts,
                provider=self.config.get("ai_provider", ""),
            )(self.call_llm_api)
            logger.debug(
                "Smart retry enabled (max_attempts=%d)", max_attempts,
            )
        else:
            # Legacy tenacity retry for backward compatibility
            self.call_llm_api = retry(
                stop=stop_after_attempt(max_attempts),
                wait=wait_exponential(multiplier=1, min=4, max=10),
                retry=retry_if_exception_type((
                    ConnectionError,
                    TimeoutError,
                    OSError,
                    Exception,
                )),
                before_sleep=before_sleep_log(logger, logging.WARNING),
                reraise=True,
            )(self.call_llm_api)
            logger.debug(
                "Legacy tenacity retry enabled (max_attempts=%d)", max_attempts,
            )

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
            classified = classify_llm_error(e, self.provider or "")
            logger.error(
                "LLM API call failed: %s (retryable=%s): %s",
                classified.error_type,
                classified.retryable,
                e,
            )
            raise

    def analyze(self, prompt: str, max_tokens: int = 4096) -> "LLMResponse":
        """Analyze prompt and return an LLM response object.

        Convenience wrapper around call_llm_api that returns a response object
        compatible with IRISAnalyzer and other consumers that expect raw-API-style
        attributes (.content, .usage.input_tokens, .usage.output_tokens).
        """
        text, inp, out = self.call_llm_api(prompt, max_tokens=max_tokens)
        return LLMResponse(text=text, input_tokens=inp, output_tokens=out)

    def generate(self, user_prompt: str, system_prompt: str = "", max_tokens: int = 4096) -> str:
        """Generate a response given user and optional system prompts.

        Used by CollaborativeReasoning agent personas which call
        ``self.llm.generate(user_prompt, system_prompt)``.

        Returns:
            Response text string.
        """
        if system_prompt:
            combined = f"{system_prompt}\n\n{user_prompt}"
        else:
            combined = user_prompt
        text, _inp, _out = self.call_llm_api(combined, max_tokens=max_tokens)
        return text


class _Usage:
    """Minimal usage object matching Anthropic/OpenAI response.usage."""
    __slots__ = ("input_tokens", "output_tokens")

    def __init__(self, input_tokens: int, output_tokens: int):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class LLMResponse:
    """Lightweight response wrapper compatible with IRISAnalyzer._parse_llm_response."""
    __slots__ = ("content", "usage")

    def __init__(self, text: str, input_tokens: int = 0, output_tokens: int = 0):
        self.content = text  # plain string – _parse_llm_response falls through to str()
        self.usage = _Usage(input_tokens, output_tokens)

    def __str__(self) -> str:
        return self.content


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
