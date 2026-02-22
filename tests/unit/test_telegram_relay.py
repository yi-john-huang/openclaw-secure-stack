"""Tests for Telegram webhook relay — FR-2.1 through FR-2.8, NFR-3, NFR-9."""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.webhook.models import AttachmentType
from src.webhook.telegram import TelegramFileInfo, TelegramRelay


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
        extraction = relay.extract_message(update)
        assert extraction.text == "hello world"
        assert extraction.chat_id == 456

    def test_extracts_update_id(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 999,
            "message": {"chat": {"id": 1}, "text": "hi"},
        }
        extraction = relay.extract_message(update)
        assert extraction.update_id == 999

    def test_handles_missing_text(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 123,
            "message": {"chat": {"id": 1}},
        }
        extraction = relay.extract_message(update)
        assert extraction.text == ""

    def test_handles_edited_message(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 123,
            "edited_message": {
                "chat": {"id": 789},
                "text": "edited text",
            },
        }
        extraction = relay.extract_message(update)
        assert extraction.text == "edited text"
        assert extraction.chat_id == 789

    def test_no_message_returns_empty(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {"update_id": 123}
        extraction = relay.extract_message(update)
        assert extraction.update_id == 123
        assert extraction.text == ""
        assert extraction.chat_id == 0


class TestTelegramFileExtraction:
    """Extraction of file metadata from Telegram message types."""

    def test_photo_picks_largest_resolution(self) -> None:
        """Telegram sends multiple photo sizes; we pick the last (largest)."""
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 1,
            "message": {
                "chat": {"id": 1},
                "photo": [
                    {"file_id": "small", "file_size": 1000, "width": 90, "height": 90},
                    {"file_id": "medium", "file_size": 5000, "width": 320, "height": 240},
                    {"file_id": "large", "file_size": 20000, "width": 1280, "height": 960},
                ],
            },
        }
        extraction = relay.extract_message(update)
        assert len(extraction.file_infos) == 1
        assert extraction.file_infos[0].file_id == "large"
        assert extraction.file_infos[0].file_type == AttachmentType.IMAGE

    def test_document_extraction(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 1,
            "message": {
                "chat": {"id": 1},
                "document": {
                    "file_id": "doc_abc",
                    "file_name": "report.pdf",
                    "mime_type": "application/pdf",
                    "file_size": 50000,
                },
            },
        }
        extraction = relay.extract_message(update)
        assert len(extraction.file_infos) == 1
        info = extraction.file_infos[0]
        assert info.file_id == "doc_abc"
        assert info.file_type == AttachmentType.DOCUMENT
        assert info.mime_type == "application/pdf"
        assert info.file_name == "report.pdf"

    def test_audio_extraction(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 1,
            "message": {
                "chat": {"id": 1},
                "audio": {
                    "file_id": "audio_xyz",
                    "file_name": "song.mp3",
                    "mime_type": "audio/mpeg",
                    "file_size": 3000000,
                },
            },
        }
        extraction = relay.extract_message(update)
        assert len(extraction.file_infos) == 1
        assert extraction.file_infos[0].file_type == AttachmentType.AUDIO

    def test_voice_extraction(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 1,
            "message": {
                "chat": {"id": 1},
                "voice": {
                    "file_id": "voice_123",
                    "mime_type": "audio/ogg",
                    "file_size": 50000,
                },
            },
        }
        extraction = relay.extract_message(update)
        assert len(extraction.file_infos) == 1
        info = extraction.file_infos[0]
        assert info.file_type == AttachmentType.VOICE
        assert info.file_name == "voice.ogg"

    def test_video_extraction(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 1,
            "message": {
                "chat": {"id": 1},
                "video": {
                    "file_id": "vid_456",
                    "mime_type": "video/mp4",
                    "file_size": 5000000,
                },
            },
        }
        extraction = relay.extract_message(update)
        assert len(extraction.file_infos) == 1
        assert extraction.file_infos[0].file_type == AttachmentType.VIDEO

    def test_sticker_extraction(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 1,
            "message": {
                "chat": {"id": 1},
                "sticker": {
                    "file_id": "sticker_789",
                    "file_size": 10000,
                },
            },
        }
        extraction = relay.extract_message(update)
        assert len(extraction.file_infos) == 1
        info = extraction.file_infos[0]
        assert info.file_type == AttachmentType.STICKER
        assert info.mime_type == "image/webp"

    def test_caption_used_as_text(self) -> None:
        """Message captions (accompanying files) are treated as text."""
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 1,
            "message": {
                "chat": {"id": 1},
                "photo": [{"file_id": "p1", "file_size": 5000}],
                "caption": "Here is the receipt",
            },
        }
        extraction = relay.extract_message(update)
        assert extraction.text == "Here is the receipt"
        assert len(extraction.file_infos) == 1

    def test_no_file_returns_empty_list(self) -> None:
        relay = TelegramRelay(bot_token="test")
        update = {
            "update_id": 1,
            "message": {"chat": {"id": 1}, "text": "plain text only"},
        }
        extraction = relay.extract_message(update)
        assert extraction.file_infos == []


class TestTelegramFileDownload:
    """File download logic: getFile → download bytes, size enforcement."""

    @pytest.mark.asyncio
    async def test_successful_download(self) -> None:
        """Two-step download: getFile → CDN fetch."""
        file_content = b"PDF content here"

        get_file_response = MagicMock()
        get_file_response.raise_for_status = MagicMock()
        get_file_response.json.return_value = {
            "ok": True,
            "result": {"file_path": "documents/file_42.pdf", "file_size": 16},
        }

        download_response = MagicMock()
        download_response.raise_for_status = MagicMock()
        download_response.content = file_content

        mock_client = AsyncMock()
        mock_client.get.side_effect = [get_file_response, download_response]

        # B2: inject mock client directly — no need to patch httpx.AsyncClient
        relay = TelegramRelay(bot_token="bot123", http_client=mock_client)
        result = await relay.download_file("file_id_42")

        assert result == file_content
        assert mock_client.get.call_count == 2
        # First call: getFile endpoint
        first_url = mock_client.get.call_args_list[0][0][0]
        assert "getFile" in first_url
        assert "file_id_42" in first_url
        # Second call: CDN download
        second_url = mock_client.get.call_args_list[1][0][0]
        assert "documents/file_42.pdf" in second_url

    @pytest.mark.asyncio
    async def test_file_too_large_raises(self) -> None:
        """Files exceeding 20MB are rejected before download."""
        large_size = 21 * 1024 * 1024  # 21MB

        get_file_response = MagicMock()
        get_file_response.raise_for_status = MagicMock()
        get_file_response.json.return_value = {
            "ok": True,
            "result": {"file_path": "big/file.mp4", "file_size": large_size},
        }

        mock_client = AsyncMock()
        mock_client.get.return_value = get_file_response

        relay = TelegramRelay(bot_token="bot123", http_client=mock_client)
        with pytest.raises(ValueError, match="File too large"):
            await relay.download_file("big_file_id")

    @pytest.mark.asyncio
    async def test_api_error_raises(self) -> None:
        """Non-ok Telegram API response raises ValueError."""
        error_response = MagicMock()
        error_response.raise_for_status = MagicMock()
        error_response.json.return_value = {"ok": False, "description": "file not found"}

        mock_client = AsyncMock()
        mock_client.get.return_value = error_response

        relay = TelegramRelay(bot_token="bot123", http_client=mock_client)
        with pytest.raises(ValueError, match="not-ok"):
            await relay.download_file("bad_file_id")

    @pytest.mark.asyncio
    async def test_build_attachments_skips_failures(self) -> None:
        """A download failure for one file does not prevent others from succeeding."""
        relay = TelegramRelay(bot_token="bot123")

        file_infos = [
            TelegramFileInfo(
                file_id="good_id",
                file_type=AttachmentType.IMAGE,
                mime_type="image/jpeg",
                file_name="photo.jpg",
                file_size=1000,
            ),
            TelegramFileInfo(
                file_id="bad_id",
                file_type=AttachmentType.DOCUMENT,
                mime_type="application/pdf",
                file_name="doc.pdf",
                file_size=2000,
            ),
        ]

        async def mock_download(file_id: str) -> bytes:
            if file_id == "good_id":
                return b"image bytes"
            raise httpx.ConnectError("network failure")

        import httpx

        with patch.object(relay, "download_file", side_effect=mock_download):
            attachments = await relay.build_attachments(file_infos)

        # Only the successful download is returned
        assert len(attachments) == 1
        assert attachments[0].file_id == "good_id"
        assert attachments[0].data == b"image bytes"


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
    async def test_sends_response_to_correct_endpoint(self) -> None:
        """Sends to api.telegram.org/sendMessage with correct chat_id and text.

        NFR-9: TLS verification is enforced at client creation time (verify=True
        in the default AsyncClient constructor in TelegramRelay.__init__).
        """
        mock_client = AsyncMock()
        mock_client.post.return_value = MagicMock(status_code=200)

        # B2: inject mock client directly — no need to patch httpx.AsyncClient
        relay = TelegramRelay(bot_token="123:ABC", http_client=mock_client)
        await relay.send_response(chat_id=12345, text="reply text")

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert "api.telegram.org" in call_args[0][0]
        assert call_args[1]["json"]["chat_id"] == 12345
        assert call_args[1]["json"]["text"] == "reply text"

    @pytest.mark.asyncio
    async def test_retries_on_429(self) -> None:
        """FR-2.8: Retry on rate limit."""
        mock_client = AsyncMock()
        mock_client.post.side_effect = [MagicMock(status_code=429), MagicMock(status_code=200)]
        relay = TelegramRelay(bot_token="123:ABC", http_client=mock_client)

        with patch("src.webhook.telegram.asyncio.sleep", new_callable=AsyncMock):
            await relay.send_response(chat_id=1, text="hi")

        assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_retries_on_5xx(self) -> None:
        """FR-2.8: Retry on server error."""
        mock_client = AsyncMock()
        mock_client.post.side_effect = [MagicMock(status_code=500), MagicMock(status_code=200)]
        relay = TelegramRelay(bot_token="123:ABC", http_client=mock_client)

        with patch("src.webhook.telegram.asyncio.sleep", new_callable=AsyncMock):
            await relay.send_response(chat_id=1, text="hi")

        assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_no_retry_on_4xx(self) -> None:
        """FR-2.8: No retry on client errors (except 429)."""
        mock_client = AsyncMock()
        mock_client.post.return_value = MagicMock(status_code=400)
        relay = TelegramRelay(bot_token="123:ABC", http_client=mock_client)

        await relay.send_response(chat_id=1, text="hi")

        assert mock_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_max_3_retries(self) -> None:
        """FR-2.5: Max 3 retries."""
        mock_client = AsyncMock()
        mock_client.post.return_value = MagicMock(status_code=500)
        relay = TelegramRelay(bot_token="123:ABC", http_client=mock_client)

        with patch("src.webhook.telegram.asyncio.sleep", new_callable=AsyncMock):
            await relay.send_response(chat_id=1, text="hi")

        # 1 initial + 3 retries = 4 total
        assert mock_client.post.call_count == 4

    @pytest.mark.asyncio
    async def test_backoff_capped_at_30_seconds(self) -> None:
        """FR-2.8: Backoff capped at 30s."""
        mock_client = AsyncMock()
        mock_client.post.return_value = MagicMock(status_code=500)
        relay = TelegramRelay(bot_token="123:ABC", http_client=mock_client)

        sleep_times: list[float] = []

        async def capture_sleep(t: float) -> None:
            sleep_times.append(t)

        with patch("src.webhook.telegram.asyncio.sleep", side_effect=capture_sleep):
            await relay.send_response(chat_id=1, text="hi")

        assert all(t <= 30 for t in sleep_times)
