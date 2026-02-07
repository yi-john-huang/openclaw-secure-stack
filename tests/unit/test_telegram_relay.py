"""Tests for Telegram webhook relay — FR-2.1 through FR-2.8, NFR-3, NFR-9."""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.webhook.telegram import TelegramRelay


def _make_secret_hash(bot_token: str) -> str:
    return hashlib.sha256(bot_token.encode()).hexdigest()


class TestTelegramWebhookVerification:
    """FR-2.4, FR-2.6: Webhook signature verification."""

    def test_valid_secret_token_accepted(self) -> None:
        bot_token = "123:ABC"
        relay = TelegramRelay(bot_token=bot_token)
        secret_hash = _make_secret_hash(bot_token)
        headers = {"x-telegram-bot-api-secret-token": secret_hash}
        assert relay.verify_webhook(headers) is True

    def test_missing_secret_token_rejected(self) -> None:
        relay = TelegramRelay(bot_token="123:ABC")
        assert relay.verify_webhook({}) is False

    def test_invalid_secret_token_rejected(self) -> None:
        relay = TelegramRelay(bot_token="123:ABC")
        headers = {"x-telegram-bot-api-secret-token": "wrong_token"}
        assert relay.verify_webhook(headers) is False

    def test_verification_uses_constant_time_comparison(self) -> None:
        """NFR-3: Constant-time comparison for token verification."""
        relay = TelegramRelay(bot_token="123:ABC")
        with patch("src.webhook.telegram.hmac.compare_digest", return_value=True) as mock_cmp:
            headers = {"x-telegram-bot-api-secret-token": "anything"}
            relay.verify_webhook(headers)
            mock_cmp.assert_called_once()

    def test_empty_secret_token_rejected(self) -> None:
        relay = TelegramRelay(bot_token="123:ABC")
        headers = {"x-telegram-bot-api-secret-token": ""}
        assert relay.verify_webhook(headers) is False


class TestTelegramMessageExtraction:
    """FR-2.1: Extract and translate Telegram messages."""

    def test_extracts_text_message(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 123,
            "message": {
                "message_id": 1,
                "chat": {"id": 456},
                "text": "hello world",
            },
        }
        update_id, text, chat_id = relay.extract_message(update)
        assert text == "hello world"
        assert chat_id == 456

    def test_extracts_update_id(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 999,
            "message": {"chat": {"id": 1}, "text": "hi"},
        }
        update_id, _, _ = relay.extract_message(update)
        assert update_id == 999

    def test_handles_missing_text(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 123,
            "message": {"chat": {"id": 1}},
        }
        _, text, _ = relay.extract_message(update)
        assert text == ""

    def test_handles_edited_message(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 123,
            "edited_message": {
                "chat": {"id": 789},
                "text": "edited text",
            },
        }
        _, text, chat_id = relay.extract_message(update)
        assert text == "edited text"
        assert chat_id == 789

    def test_no_message_returns_empty(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {"update_id": 123}
        update_id, text, chat_id = relay.extract_message(update)
        assert update_id == 123
        assert text == ""
        assert chat_id == 0


class TestTelegramProtocolTranslation:
    """FR-2.1: Translate to OpenAI-compatible format."""

    def test_to_openclaw_request_format(self) -> None:
        relay = TelegramRelay(bot_token="test")
        result = relay.to_openclaw_request("hello", chat_id=12345)
        assert result["messages"][0]["role"] == "user"
        assert result["messages"][0]["content"] == "hello"
        assert result["metadata"]["source"] == "telegram"
        assert result["metadata"]["chat_id"] == 12345

    def test_model_is_default(self) -> None:
        relay = TelegramRelay(bot_token="test")
        result = relay.to_openclaw_request("test", chat_id=1)
        assert result["model"] == "default"


class TestTelegramResponseSending:
    """FR-2.3, FR-2.5, FR-2.8: Send response back via Telegram API."""

    @pytest.mark.asyncio
    async def test_sends_response_with_tls_verification(self) -> None:
        """NFR-9: TLS certificate verification enabled."""
        relay = TelegramRelay(bot_token="123:ABC")
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("src.webhook.telegram.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await relay.send_response(chat_id=12345, text="reply text")

            mock_client_cls.assert_called_once_with(verify=True)
            mock_client.post.assert_called_once()
            call_kwargs = mock_client.post.call_args
            assert "api.telegram.org" in call_kwargs[0][0]
            assert call_kwargs[1]["json"]["chat_id"] == 12345
            assert call_kwargs[1]["json"]["text"] == "reply text"

    @pytest.mark.asyncio
    async def test_retries_on_429(self) -> None:
        """FR-2.8: Retry on rate limit."""
        relay = TelegramRelay(bot_token="123:ABC")
        mock_429 = MagicMock(status_code=429)
        mock_200 = MagicMock(status_code=200)

        with patch("src.webhook.telegram.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.side_effect = [mock_429, mock_200]
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with patch("src.webhook.telegram.asyncio.sleep", new_callable=AsyncMock):
                await relay.send_response(chat_id=1, text="hi")

            assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_retries_on_5xx(self) -> None:
        """FR-2.8: Retry on server error."""
        relay = TelegramRelay(bot_token="123:ABC")
        mock_500 = MagicMock(status_code=500)
        mock_200 = MagicMock(status_code=200)

        with patch("src.webhook.telegram.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.side_effect = [mock_500, mock_200]
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with patch("src.webhook.telegram.asyncio.sleep", new_callable=AsyncMock):
                await relay.send_response(chat_id=1, text="hi")

            assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_no_retry_on_4xx(self) -> None:
        """FR-2.8: No retry on client errors (except 429)."""
        relay = TelegramRelay(bot_token="123:ABC")
        mock_400 = MagicMock(status_code=400)

        with patch("src.webhook.telegram.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_400
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await relay.send_response(chat_id=1, text="hi")

            assert mock_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_max_3_retries(self) -> None:
        """FR-2.5: Max 3 retries."""
        relay = TelegramRelay(bot_token="123:ABC")
        mock_500 = MagicMock(status_code=500)

        with patch("src.webhook.telegram.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_500
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with patch("src.webhook.telegram.asyncio.sleep", new_callable=AsyncMock):
                await relay.send_response(chat_id=1, text="hi")

            # 1 initial + 3 retries = 4 total
            assert mock_client.post.call_count == 4

    @pytest.mark.asyncio
    async def test_backoff_capped_at_30_seconds(self) -> None:
        """FR-2.8: Backoff capped at 30s."""
        relay = TelegramRelay(bot_token="123:ABC")
        mock_500 = MagicMock(status_code=500)

        sleep_times: list[float] = []

        async def capture_sleep(t: float) -> None:
            sleep_times.append(t)

        with patch("src.webhook.telegram.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_500
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with patch("src.webhook.telegram.asyncio.sleep", side_effect=capture_sleep):
                await relay.send_response(chat_id=1, text="hi")

            assert all(t <= 30 for t in sleep_times)
