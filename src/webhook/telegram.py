"""Telegram webhook relay — FR-2.1 through FR-2.8.

Handles Telegram Bot API webhook updates: verification, extraction,
protocol translation, and response delivery with retry logic.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_CAP_SECONDS = 30


class TelegramRelay:
    """Handles Telegram Bot API webhook updates."""

    def __init__(self, bot_token: str) -> None:
        self._bot_token = bot_token
        self._secret_hash = hashlib.sha256(bot_token.encode()).hexdigest()

    def verify_webhook(self, headers: dict[str, str]) -> bool:
        """Verify Telegram webhook using secret token header.

        FR-2.6: Uses SHA-256 hash of bot token.
        NFR-3: Constant-time comparison via hmac.compare_digest.
        """
        secret = headers.get("x-telegram-bot-api-secret-token", "")
        if not secret:
            return False
        return hmac.compare_digest(secret, self._secret_hash)

    def extract_message(self, update: dict[str, Any]) -> tuple[int, str, int]:
        """Extract update_id, message text, and chat_id from Telegram update.

        Returns (update_id, text, chat_id). Handles both message and edited_message.
        """
        update_id: int = update["update_id"]
        message = update.get("message") or update.get("edited_message") or {}
        text: str = message.get("text", "")
        chat: dict[str, Any] = message.get("chat", {})
        chat_id: int = chat.get("id", 0)
        return update_id, text, chat_id

    def to_openclaw_request(self, text: str, chat_id: int) -> dict[str, Any]:
        """Translate Telegram message to OpenAI-compatible format (FR-2.1)."""
        return {
            "model": "default",
            "messages": [{"role": "user", "content": text}],
            "metadata": {"source": "telegram", "chat_id": chat_id},
        }

    async def send_response(self, chat_id: int, text: str) -> None:
        """Send response back via Telegram Bot API.

        NFR-9: TLS certificate verification enabled.
        FR-2.5/FR-2.8: Retry on 429/5xx with exponential backoff capped at 30s.
        """
        url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": text}

        async with httpx.AsyncClient(verify=True) as client:
            for attempt in range(_MAX_RETRIES + 1):
                resp = await client.post(url, json=payload)

                if resp.status_code < 400:
                    return
                if not self._should_retry(resp.status_code):
                    return
                if attempt < _MAX_RETRIES:
                    delay = min(2 ** attempt, _BACKOFF_CAP_SECONDS)
                    await asyncio.sleep(delay)

    @staticmethod
    def _should_retry(status_code: int) -> bool:
        """FR-2.8: Only retry on 429 (rate limit) or 5xx (server error)."""
        return status_code == 429 or status_code >= 500
