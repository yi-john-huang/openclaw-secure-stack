"""WhatsApp webhook relay — FR-3.1 through FR-3.8.

Handles WhatsApp Business API webhook updates: HMAC verification,
Meta verification challenge, message extraction, protocol translation,
and response delivery with retry logic.
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
_WHATSAPP_API_BASE = "https://graph.facebook.com/v18.0"


class WhatsAppRelay:
    """Handles WhatsApp Business API webhook updates."""

    def __init__(
        self,
        app_secret: str,
        verify_token: str,
        phone_number_id: str,
        access_token: str,
    ) -> None:
        self._app_secret = app_secret
        self._verify_token = verify_token
        self._phone_number_id = phone_number_id
        self._access_token = access_token

    def verify_signature(self, headers: dict[str, str], body: bytes) -> bool:
        """Verify WhatsApp webhook HMAC-SHA256 signature.

        FR-3.5: HMAC-SHA256 verification.
        NFR-3: Constant-time comparison via hmac.compare_digest.
        """
        signature = headers.get("x-hub-signature-256", "")
        if not signature.startswith("sha256="):
            return False

        expected = hmac.new(
            self._app_secret.encode(), body, hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(signature[7:], expected)

    def handle_verification(
        self, params: dict[str, str],
    ) -> dict[str, Any] | None:
        """Handle Meta webhook verification challenge (GET).

        FR-3.6: Returns challenge on valid subscribe, 403 on invalid token.
        Returns None for non-subscribe modes.
        """
        mode = params.get("hub.mode")
        if mode != "subscribe":
            return None

        token = params.get("hub.verify_token", "")
        if hmac.compare_digest(token, self._verify_token):
            return {
                "status_code": 200,
                "content": params.get("hub.challenge", ""),
            }
        return {"status_code": 403, "error": "Invalid verify token"}

    def extract_messages(
        self, payload: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Extract text messages from WhatsApp Business API webhook payload.

        FR-3.1: Extracts sender phone, text, and timestamp.
        Ignores status updates (delivered, read, etc.).
        """
        messages: list[dict[str, Any]] = []
        for entry in payload.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                for msg in value.get("messages", []):
                    if msg.get("type") != "text":
                        continue
                    messages.append({
                        "sender_phone": msg.get("from", ""),
                        "text": msg.get("text", {}).get("body", ""),
                        "timestamp": int(msg.get("timestamp", "0")),
                        "message_id": msg.get("id", ""),
                    })
        return messages

    def to_openclaw_request(
        self, text: str, sender_phone: str,
    ) -> dict[str, Any]:
        """Translate WhatsApp message to OpenAI-compatible format (FR-3.1)."""
        return {
            "model": "default",
            "messages": [{"role": "user", "content": text}],
            "metadata": {
                "source": "whatsapp",
                "sender_phone": sender_phone,
            },
        }

    async def send_response(self, recipient_phone: str, text: str) -> None:
        """Send response back via WhatsApp Business API.

        NFR-9: TLS certificate verification enabled.
        FR-3.8: Retry on 429/5xx with exponential backoff capped at 30s.
        """
        url = f"{_WHATSAPP_API_BASE}/{self._phone_number_id}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "to": recipient_phone,
            "type": "text",
            "text": {"body": text},
        }
        headers = {"Authorization": f"Bearer {self._access_token}"}

        async with httpx.AsyncClient(verify=True) as client:
            for attempt in range(_MAX_RETRIES + 1):
                resp = await client.post(url, json=payload, headers=headers)

                if resp.status_code < 400:
                    return
                if not self._should_retry(resp.status_code):
                    return
                if attempt < _MAX_RETRIES:
                    delay = min(2 ** attempt, _BACKOFF_CAP_SECONDS)
                    await asyncio.sleep(delay)

    @staticmethod
    def _should_retry(status_code: int) -> bool:
        """FR-3.8: Only retry on 429 (rate limit) or 5xx (server error)."""
        return status_code == 429 or status_code >= 500
