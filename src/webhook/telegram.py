"""Telegram webhook relay — FR-2.1 through FR-2.8.

Handles Telegram Bot API webhook updates: verification, extraction,
protocol translation, and response delivery with retry logic.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from src.models import AuditEventType, RiskLevel
from src.webhook.models import Attachment, AttachmentType

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_CAP_SECONDS = 30
_MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB Telegram file size limit


@dataclass
class TelegramFileInfo:
    """Metadata for a file attached to a Telegram message."""

    file_id: str
    file_type: AttachmentType
    mime_type: str
    file_name: str
    file_size: int


@dataclass
class TelegramExtraction:
    """Result of extracting a Telegram update."""

    update_id: int
    text: str
    chat_id: int
    file_infos: list[TelegramFileInfo] = field(default_factory=list)


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

    def extract_message(self, update: dict[str, Any]) -> TelegramExtraction:
        """Extract update_id, text, chat_id, and file metadata from a Telegram update.

        Handles both message and edited_message. Reads text from message.text
        OR message.caption (captions accompany files). Detects all attachment
        types: photo, document, audio, voice, video, sticker.
        """
        update_id: int = update["update_id"]
        message = update.get("message") or update.get("edited_message") or {}
        chat: dict[str, Any] = message.get("chat", {})
        chat_id: int = chat.get("id", 0)

        # Text can be in "text" or "caption" (captions accompany file messages)
        text: str = message.get("text") or message.get("caption") or ""

        file_infos = self._extract_file_infos(message)
        return TelegramExtraction(
            update_id=update_id,
            text=text,
            chat_id=chat_id,
            file_infos=file_infos,
        )

    def _extract_file_infos(self, message: dict[str, Any]) -> list[TelegramFileInfo]:
        """Extract file metadata from all attachment types in a message."""
        infos: list[TelegramFileInfo] = []

        # Photos: array of sizes; pick the last (largest) one
        photos = message.get("photo")
        if photos:
            photo = photos[-1]
            infos.append(TelegramFileInfo(
                file_id=photo["file_id"],
                file_type=AttachmentType.IMAGE,
                mime_type="image/jpeg",
                file_name="photo.jpg",
                file_size=photo.get("file_size", 0),
            ))

        # Document (PDF, ZIP, etc.)
        doc = message.get("document")
        if doc:
            infos.append(TelegramFileInfo(
                file_id=doc["file_id"],
                file_type=AttachmentType.DOCUMENT,
                mime_type=doc.get("mime_type", "application/octet-stream"),
                file_name=doc.get("file_name", "document"),
                file_size=doc.get("file_size", 0),
            ))

        # Audio file
        audio = message.get("audio")
        if audio:
            infos.append(TelegramFileInfo(
                file_id=audio["file_id"],
                file_type=AttachmentType.AUDIO,
                mime_type=audio.get("mime_type", "audio/mpeg"),
                file_name=audio.get("file_name", "audio.mp3"),
                file_size=audio.get("file_size", 0),
            ))

        # Voice message (OGG/Opus)
        voice = message.get("voice")
        if voice:
            infos.append(TelegramFileInfo(
                file_id=voice["file_id"],
                file_type=AttachmentType.VOICE,
                mime_type=voice.get("mime_type", "audio/ogg"),
                file_name="voice.ogg",
                file_size=voice.get("file_size", 0),
            ))

        # Video
        video = message.get("video")
        if video:
            infos.append(TelegramFileInfo(
                file_id=video["file_id"],
                file_type=AttachmentType.VIDEO,
                mime_type=video.get("mime_type", "video/mp4"),
                file_name=video.get("file_name", "video.mp4"),
                file_size=video.get("file_size", 0),
            ))

        # Sticker (WebP)
        sticker = message.get("sticker")
        if sticker:
            infos.append(TelegramFileInfo(
                file_id=sticker["file_id"],
                file_type=AttachmentType.STICKER,
                mime_type="image/webp",
                file_name="sticker.webp",
                file_size=sticker.get("file_size", 0),
            ))

        return infos

    async def download_file(self, file_id: str) -> bytes:
        """Download a file from Telegram by file_id.

        Two-step process:
        1. GET /bot{token}/getFile?file_id=... → get file_path
        2. GET /file/bot{token}/{file_path} → download bytes

        Security: TLS verification enabled, 20MB size cap enforced both
        pre-download (via metadata) and post-download (on actual bytes).
        URLs are constructed from hardcoded api.telegram.org only — no SSRF risk.
        """
        get_file_url = (
            f"https://api.telegram.org/bot{self._bot_token}/getFile"
            f"?file_id={file_id}"
        )

        # Use generous timeouts: 10s connect for API metadata, 120s read for
        # binary download (20MB file on a slow link can take tens of seconds).
        timeout = httpx.Timeout(connect=10.0, read=120.0, write=10.0, pool=10.0)
        async with httpx.AsyncClient(verify=True, timeout=timeout) as client:
            resp = await client.get(get_file_url)
            resp.raise_for_status()
            data = resp.json()

            if not data.get("ok"):
                raise ValueError(f"Telegram getFile returned not-ok: {data}")

            file_path = data["result"]["file_path"]
            file_size = data["result"].get("file_size", 0)

            if file_size > _MAX_FILE_SIZE:
                raise ValueError(
                    f"File too large: {file_size} bytes (max {_MAX_FILE_SIZE})"
                )

            download_url = (
                f"https://api.telegram.org/file/bot{self._bot_token}/{file_path}"
            )
            file_resp = await client.get(download_url)
            file_resp.raise_for_status()

            content = file_resp.content
            if len(content) > _MAX_FILE_SIZE:
                raise ValueError(
                    f"Downloaded file too large: {len(content)} bytes (max {_MAX_FILE_SIZE})"
                )

            return content

    async def build_attachments(
        self,
        file_infos: list[TelegramFileInfo],
        audit_logger: Any = None,
        sender_id: str = "",
    ) -> list[Attachment]:
        """Download all files and return as Attachment list.

        Failures are logged as warnings and skipped — one bad file does not
        prevent the rest of the message from being processed.
        """
        attachments: list[Attachment] = []
        for info in file_infos:
            try:
                data = await self.download_file(info.file_id)
                attachments.append(Attachment(
                    type=info.file_type,
                    file_id=info.file_id,
                    mime_type=info.mime_type,
                    file_name=info.file_name,
                    file_size=len(data),
                    data=data,
                ))
                if audit_logger:
                    from src.models import AuditEvent
                    audit_logger.log(AuditEvent(
                        event_type=AuditEventType.WEBHOOK_FILE_DOWNLOAD,
                        action="file_download",
                        result="success",
                        risk_level=RiskLevel.INFO,
                        details={
                            "file_type": info.file_type.value,
                            "mime_type": info.mime_type,
                            "file_name": info.file_name,
                            "file_size": len(data),
                            "sender_id": sender_id,
                        },
                    ))
            except Exception:
                logger.warning(
                    "Failed to download Telegram file %s (%s), skipping",
                    info.file_id,
                    info.file_type.value,
                    exc_info=True,
                )

        return attachments

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
