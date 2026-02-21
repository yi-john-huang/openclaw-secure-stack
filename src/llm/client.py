"""LLM client for governance plan generation."""

from __future__ import annotations

import os
import logging

from anthropic import Anthropic, AuthenticationError, APIError

logger = logging.getLogger(__name__)

# Default model - can be overridden via environment variable
DEFAULT_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
DEFAULT_TIMEOUT = int(os.getenv("ANTHROPIC_TIMEOUT_SECONDS", "60"))


class LLMClientError(Exception):
    """Raised when LLM client encounters an error."""
    pass


class LLMClient:
    """Simple LLM client wrapper with error handling."""

    def __init__(
        self,
        model: str | None = None,
        timeout_seconds: int | None = None,
    ):
        """Initialize LLM client.

        Args:
            model: Model name. Defaults to ANTHROPIC_MODEL env var or claude-sonnet-4-20250514.
            timeout_seconds: Request timeout. Defaults to ANTHROPIC_TIMEOUT_SECONDS env var or 60.

        Raises:
            LLMClientError: If ANTHROPIC_API_KEY is not set.
        """
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise LLMClientError(
                "ANTHROPIC_API_KEY environment variable is not set. "
                "Set it to your Anthropic API key to enable plan enhancement."
            )

        self.model_name = model or DEFAULT_MODEL
        self.timeout_seconds = timeout_seconds or DEFAULT_TIMEOUT

        try:
            self.client = Anthropic(timeout=self.timeout_seconds)
        except AuthenticationError as e:
            raise LLMClientError(f"Invalid ANTHROPIC_API_KEY: {e}") from e

    def complete(self, prompt: str, temperature: float = 0) -> str:
        """Complete a prompt using the LLM.

        Args:
            prompt: The prompt to complete.
            temperature: Sampling temperature (0 = deterministic).

        Returns:
            The completion text.

        Raises:
            LLMClientError: If the API call fails or returns empty response.
        """
        try:
            response = self.client.messages.create(
                model=self.model_name,
                max_tokens=4096,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}],
            )

            if not response.content:
                raise LLMClientError("LLM returned empty response")

            return response.content[0].text

        except APIError as e:
            logger.error("LLM API error: %s", e)
            raise LLMClientError(f"LLM API call failed: {e}") from e