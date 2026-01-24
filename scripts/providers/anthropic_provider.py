"""
Anthropic Claude Provider for Argus
Replaces deprecated Foundation-Sec-8B with Claude Sonnet for ML-based analysis
"""

import json
import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AnthropicProvider:
    """Claude AI via Anthropic API for security analysis"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-5-20250929",
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ):
        """
        Initialize Anthropic provider

        Args:
            api_key: Anthropic API key (or set ANTHROPIC_API_KEY env var)
            model: Claude model to use
            max_tokens: Max tokens to generate
            temperature: Sampling temperature (0.0 = deterministic, 1.0 = creative)
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.client = None

        if not self.api_key:
            raise ValueError("Anthropic API key required. Set ANTHROPIC_API_KEY env var or pass api_key")

        self._init_client()

    def _init_client(self):
        """Initialize Anthropic client"""
        try:
            import anthropic

            self.client = anthropic.Anthropic(api_key=self.api_key)
            logger.info(f"✅ Anthropic provider initialized with model {self.model}")
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Generate response from Claude

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt for context

        Returns:
            Generated text response
        """
        try:
            # Build messages
            messages = [{"role": "user", "content": prompt}]

            # Call Claude API
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=system_prompt if system_prompt else "You are a security analysis expert.",
                messages=messages,
            )

            # Extract text from response
            if response.content and len(response.content) > 0:
                return response.content[0].text
            else:
                return ""

        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise

    def analyze_json(self, prompt: str, system_prompt: Optional[str] = None) -> dict:
        """
        Generate JSON response from Claude

        Args:
            prompt: User prompt requesting JSON output
            system_prompt: Optional system prompt

        Returns:
            Parsed JSON dict
        """
        # Ensure prompt asks for JSON
        if "json" not in prompt.lower():
            prompt += "\n\nRespond with valid JSON only, no other text."

        response_text = self.generate(prompt, system_prompt)

        # Extract JSON from response (handle markdown code blocks)
        try:
            # Try direct parse first
            return json.loads(response_text)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code block
            import re

            json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            else:
                # Try to find any JSON object
                json_match = re.search(r"\{.*\}", response_text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(0))
                else:
                    raise ValueError(f"No valid JSON found in response: {response_text[:200]}")

    def batch_analyze(self, prompts: list[str], system_prompt: Optional[str] = None) -> list[str]:
        """
        Analyze multiple prompts (sequential for now, could be parallelized)

        Args:
            prompts: List of prompts
            system_prompt: Optional system prompt

        Returns:
            List of responses
        """
        responses = []
        for prompt in prompts:
            response = self.generate(prompt, system_prompt)
            responses.append(response)
        return responses
