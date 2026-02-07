"""Tests for WhatsApp webhook relay — FR-3.1 through FR-3.8, NFR-3, NFR-9."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.webhook.whatsapp import WhatsAppRelay


def _make_whatsapp_relay(**kwargs: Any) -> WhatsAppRelay:
    defaults = {
        "app_secret": "test_secret",
        "verify_token": "test_verify",
        "phone_number_id": "123456",
        "access_token": "test_access_token",
    }
    defaults.update(kwargs)
    return WhatsAppRelay(**defaults)


def _sign_body(app_secret: str, body: bytes) -> str:
    sig = hmac_mod.new(app_secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


class TestWhatsAppSignatureVerification:
    """FR-3.4, FR-3.5: HMAC-SHA256 signature verification."""

    def test_valid_signature_accepted(self) -> None:
        relay = _make_whatsapp_relay(app_secret="my_secret")
        body = b'{"test": "data"}'
        sig = _sign_body("my_secret", body)
        headers = {"x-hub-signature-256": sig}
        assert relay.verify_signature(headers, body) is True

    def test_invalid_signature_rejected(self) -> None:
        relay = _make_whatsapp_relay(app_secret="my_secret")
        body = b'{"test": "data"}'
        headers = {"x-hub-signature-256": "sha256=wrong"}
        assert relay.verify_signature(headers, body) is False

    def test_missing_signature_rejected(self) -> None:
        relay = _make_whatsapp_relay()
        assert relay.verify_signature({}, b"body") is False

    def test_malformed_signature_prefix_rejected(self) -> None:
        """Signature without 'sha256=' prefix rejected."""
        relay = _make_whatsapp_relay()
        headers = {"x-hub-signature-256": "abc123"}
        assert relay.verify_signature(headers, b"body") is False

    def test_constant_time_comparison(self) -> None:
        """NFR-3: Uses hmac.compare_digest."""
        relay = _make_whatsapp_relay(app_secret="s")
        body = b"data"
        sig = _sign_body("s", body)
        headers = {"x-hub-signature-256": sig}
        with patch("src.webhook.whatsapp.hmac.compare_digest", return_value=True) as mock_cmp:
            relay.verify_signature(headers, body)
            mock_cmp.assert_called_once()


class TestWhatsAppVerificationChallenge:
    """FR-3.6: Meta webhook verification handshake."""

    def test_valid_subscribe_returns_challenge(self) -> None:
        relay = _make_whatsapp_relay(verify_token="my_verify")
        params = {
            "hub.mode": "subscribe",
            "hub.verify_token": "my_verify",
            "hub.challenge": "challenge_string_123",
        }
        result = relay.handle_verification(params)
        assert result is not None
        assert result["status_code"] == 200
        assert result["content"] == "challenge_string_123"

    def test_invalid_verify_token_returns_403(self) -> None:
        relay = _make_whatsapp_relay(verify_token="correct")
        params = {
            "hub.mode": "subscribe",
            "hub.verify_token": "wrong",
            "hub.challenge": "ch",
        }
        result = relay.handle_verification(params)
        assert result is not None
        assert result["status_code"] == 403

    def test_non_subscribe_mode_returns_none(self) -> None:
        relay = _make_whatsapp_relay()
        params = {"hub.mode": "unsubscribe"}
        result = relay.handle_verification(params)
        assert result is None

    def test_missing_mode_returns_none(self) -> None:
        relay = _make_whatsapp_relay()
        result = relay.handle_verification({})
        assert result is None


class TestWhatsAppMessageExtraction:
    """FR-3.1: Extract and translate WhatsApp messages."""

    def _make_webhook_payload(
        self,
        text: str = "hello",
        phone: str = "+1234567890",
        timestamp: str = "1234567890",
    ) -> dict[str, Any]:
        return {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "id": "BUSINESS_ID",
                    "changes": [
                        {
                            "value": {
                                "messaging_product": "whatsapp",
                                "metadata": {"phone_number_id": "PHONE_ID"},
                                "messages": [
                                    {
                                        "from": phone,
                                        "id": "msg_id",
                                        "timestamp": timestamp,
                                        "type": "text",
                                        "text": {"body": text},
                                    }
                                ],
                            },
                            "field": "messages",
                        }
                    ],
                }
            ],
        }

    def test_extracts_text_message(self) -> None:
        relay = _make_whatsapp_relay()
        payload = self._make_webhook_payload(text="hello world")
        messages = relay.extract_messages(payload)
        assert len(messages) == 1
        assert messages[0]["text"] == "hello world"

    def test_extracts_phone_number(self) -> None:
        relay = _make_whatsapp_relay()
        payload = self._make_webhook_payload(phone="+15551234567")
        messages = relay.extract_messages(payload)
        assert messages[0]["sender_phone"] == "+15551234567"

    def test_extracts_message_timestamp(self) -> None:
        relay = _make_whatsapp_relay()
        payload = self._make_webhook_payload(timestamp="1700000000")
        messages = relay.extract_messages(payload)
        assert messages[0]["timestamp"] == 1700000000

    def test_handles_status_updates_gracefully(self) -> None:
        """Status webhooks (delivered, read) are not messages."""
        relay = _make_whatsapp_relay()
        payload = {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "id": "BID",
                    "changes": [
                        {
                            "value": {
                                "messaging_product": "whatsapp",
                                "metadata": {"phone_number_id": "PID"},
                                "statuses": [
                                    {"id": "msg1", "status": "delivered"}
                                ],
                            },
                            "field": "messages",
                        }
                    ],
                }
            ],
        }
        messages = relay.extract_messages(payload)
        assert len(messages) == 0

    def test_handles_empty_entry(self) -> None:
        relay = _make_whatsapp_relay()
        payload = {"object": "whatsapp_business_account", "entry": []}
        messages = relay.extract_messages(payload)
        assert len(messages) == 0


class TestWhatsAppProtocolTranslation:
    """FR-3.1: Translate to OpenAI-compatible format."""

    def test_to_openclaw_request_format(self) -> None:
        relay = _make_whatsapp_relay()
        result = relay.to_openclaw_request("hello", sender_phone="+1234567890")
        assert result["messages"][0]["role"] == "user"
        assert result["messages"][0]["content"] == "hello"
        assert result["metadata"]["source"] == "whatsapp"
        assert result["metadata"]["sender_phone"] == "+1234567890"

    def test_model_is_default(self) -> None:
        relay = _make_whatsapp_relay()
        result = relay.to_openclaw_request("test", sender_phone="+1")
        assert result["model"] == "default"


class TestWhatsAppResponseSending:
    """FR-3.3, FR-3.8: Send response via WhatsApp API."""

    @pytest.mark.asyncio
    async def test_sends_response_with_tls(self) -> None:
        """NFR-9: TLS verification."""
        relay = _make_whatsapp_relay()
        mock_response = MagicMock(status_code=200)

        with patch("src.webhook.whatsapp.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await relay.send_response(recipient_phone="+1234567890", text="reply")

            mock_client_cls.assert_called_once_with(verify=True)
            mock_client.post.assert_called_once()
            call_kwargs = mock_client.post.call_args
            assert call_kwargs[1]["json"]["to"] == "+1234567890"
            assert call_kwargs[1]["json"]["text"]["body"] == "reply"

    @pytest.mark.asyncio
    async def test_retries_on_429_and_5xx(self) -> None:
        """FR-3.8: Selective retry."""
        relay = _make_whatsapp_relay()
        mock_429 = MagicMock(status_code=429)
        mock_200 = MagicMock(status_code=200)

        with patch("src.webhook.whatsapp.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.side_effect = [mock_429, mock_200]
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with patch("src.webhook.whatsapp.asyncio.sleep", new_callable=AsyncMock):
                await relay.send_response(recipient_phone="+1", text="hi")

            assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_no_retry_on_4xx(self) -> None:
        """FR-3.8: No retry on client errors except 429."""
        relay = _make_whatsapp_relay()
        mock_400 = MagicMock(status_code=400)

        with patch("src.webhook.whatsapp.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_400
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await relay.send_response(recipient_phone="+1", text="hi")

            assert mock_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_backoff_capped_at_30_seconds(self) -> None:
        """FR-3.8: Cap at 30s."""
        relay = _make_whatsapp_relay()
        mock_500 = MagicMock(status_code=500)

        sleep_times: list[float] = []

        async def capture_sleep(t: float) -> None:
            sleep_times.append(t)

        with patch("src.webhook.whatsapp.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_500
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with patch("src.webhook.whatsapp.asyncio.sleep", side_effect=capture_sleep):
                await relay.send_response(recipient_phone="+1", text="hi")

            assert all(t <= 30 for t in sleep_times)

    @pytest.mark.asyncio
    async def test_max_3_retries(self) -> None:
        """FR-3.8: Max 3 retries."""
        relay = _make_whatsapp_relay()
        mock_500 = MagicMock(status_code=500)

        with patch("src.webhook.whatsapp.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_500
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with patch("src.webhook.whatsapp.asyncio.sleep", new_callable=AsyncMock):
                await relay.send_response(recipient_phone="+1", text="hi")

            assert mock_client.post.call_count == 4  # 1 + 3 retries
