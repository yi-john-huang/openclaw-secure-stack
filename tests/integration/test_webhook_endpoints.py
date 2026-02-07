"""Integration tests for webhook endpoint registration — NFR-2, FR-2, FR-3."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from src.proxy.app import create_app


def _make_telegram_headers(bot_token: str) -> dict[str, str]:
    secret = hashlib.sha256(bot_token.encode()).hexdigest()
    return {"x-telegram-bot-api-secret-token": secret}


def _make_telegram_update(
    update_id: int = 1,
    text: str = "hello",
    chat_id: int = 12345,
) -> dict[str, Any]:
    return {
        "update_id": update_id,
        "message": {
            "message_id": 1,
            "chat": {"id": chat_id},
            "text": text,
        },
    }


def _sign_whatsapp_body(app_secret: str, body: bytes) -> str:
    sig = hmac_mod.new(app_secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def _make_whatsapp_payload(
    text: str = "hello",
    phone: str = "+1234567890",
    timestamp: str | None = None,
) -> dict[str, Any]:
    if timestamp is None:
        timestamp = str(int(time.time()))
    return {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "BID",
                "changes": [
                    {
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {"phone_number_id": "PID"},
                            "messages": [
                                {
                                    "from": phone,
                                    "id": "msg1",
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


def _make_app_with_sanitizer(tmp_path: Path, **kwargs: Any) -> Any:
    """Helper to create a FastAPI app with a sanitizer and tmp paths."""
    from src.sanitizer.sanitizer import PromptSanitizer

    rules_path = tmp_path / "rules.json"
    rules_path.write_text("[]")
    sanitizer = PromptSanitizer(str(rules_path))
    defaults = {
        "upstream_url": "http://localhost:3000",
        "token": "test-token",
        "sanitizer": sanitizer,
        "replay_db_path": str(tmp_path / "replay.db"),
    }
    defaults.update(kwargs)
    return create_app(**defaults)


class TestWebhookAuthBypass:
    """Verify that unregistered /webhook/* paths are NOT exempt from auth."""

    @pytest.mark.asyncio
    async def test_unregistered_webhook_path_requires_auth(self, tmp_path: Path) -> None:
        """GET /webhook/foo should return 401, not proxy upstream (auth bypass fix)."""
        app = _make_app_with_sanitizer(tmp_path, telegram_bot_token="123:ABC")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/webhook/foo")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_registered_webhook_path_bypasses_bearer_auth(
        self, tmp_path: Path,
    ) -> None:
        """POST /webhook/telegram should NOT require Bearer auth (uses HMAC instead)."""
        app = _make_app_with_sanitizer(tmp_path, telegram_bot_token="123:ABC")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # No Bearer token, but valid webhook endpoint — should not get 401 for missing Bearer
            # (will get 401 for invalid HMAC instead, which is the webhook's own auth)
            resp = await client.post(
                "/webhook/telegram",
                json=_make_telegram_update(),
            )
            # 401 from HMAC check, NOT from Bearer auth middleware
            assert resp.status_code == 401
            body = resp.json()
            assert body["error"] == "Invalid webhook signature"

    @pytest.mark.asyncio
    async def test_webhook_auth_does_not_leak_across_app_instances(
        self, tmp_path: Path,
    ) -> None:
        """Webhook paths from one app must NOT leak into another app instance."""
        # App 1: Telegram enabled — /webhook/telegram should work
        _make_app_with_sanitizer(tmp_path, telegram_bot_token="123:ABC")

        # App 2: No webhooks — /webhook/telegram must require auth
        app2_dir = tmp_path / "app2"
        app2_dir.mkdir()
        app2 = _make_app_with_sanitizer(app2_dir)
        transport = ASGITransport(app=app2)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/webhook/telegram",
                json=_make_telegram_update(),
            )
            # Should require Bearer auth (401), NOT bypass it
            assert resp.status_code == 401
            body = resp.json()
            assert body["error"] == "Authentication required"


class TestWebhookRouteRegistration:
    """NFR-2: Webhook routes conditionally registered."""

    def test_telegram_route_registered_when_token_set(self, tmp_path: Path) -> None:
        """TELEGRAM_BOT_TOKEN set -> /webhook/telegram available."""
        app = _make_app_with_sanitizer(tmp_path, telegram_bot_token="123:ABC")
        routes = [r.path for r in app.routes]
        assert "/webhook/telegram" in routes

    def test_telegram_route_absent_when_no_token(self, tmp_path: Path) -> None:
        """No TELEGRAM_BOT_TOKEN -> /webhook/telegram returns 404."""
        app = _make_app_with_sanitizer(tmp_path)
        routes = [r.path for r in app.routes]
        assert "/webhook/telegram" not in routes

    def test_whatsapp_route_registered_when_secret_set(self, tmp_path: Path) -> None:
        """WHATSAPP_APP_SECRET set -> /webhook/whatsapp available."""
        app = _make_app_with_sanitizer(
            tmp_path,
            whatsapp_config={
                "app_secret": "secret",
                "verify_token": "verify",
                "phone_number_id": "123",
                "access_token": "token",
            },
        )
        routes = [r.path for r in app.routes]
        assert "/webhook/whatsapp" in routes

    def test_whatsapp_route_absent_when_no_secret(self, tmp_path: Path) -> None:
        """No WhatsApp config -> no /webhook/whatsapp route."""
        app = _make_app_with_sanitizer(tmp_path)
        routes = [r.path for r in app.routes]
        assert "/webhook/whatsapp" not in routes


class TestTelegramEndpoints:
    """Telegram webhook endpoint integration tests."""

    @pytest.fixture
    def app_with_telegram(self, tmp_path: Path) -> Any:
        return _make_app_with_sanitizer(tmp_path, telegram_bot_token="123:ABC")

    @pytest.mark.asyncio
    async def test_telegram_invalid_signature_401(self, app_with_telegram: Any) -> None:
        """Invalid Telegram webhook signature -> 401 (FR-2.4)."""
        transport = ASGITransport(app=app_with_telegram)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/webhook/telegram",
                json=_make_telegram_update(),
                headers={"x-telegram-bot-api-secret-token": "wrong"},
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_telegram_missing_signature_401(self, app_with_telegram: Any) -> None:
        """Missing Telegram webhook signature -> 401."""
        transport = ASGITransport(app=app_with_telegram)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/webhook/telegram",
                json=_make_telegram_update(),
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_telegram_replay_attack_409(self, app_with_telegram: Any) -> None:
        """Duplicate update_id -> 409 (FR-2.7)."""
        headers = _make_telegram_headers("123:ABC")
        transport = ASGITransport(app=app_with_telegram)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.webhook.relay.httpx.AsyncClient") as mock_fwd_cls, \
                 patch("src.webhook.telegram.httpx.AsyncClient") as mock_tg_cls:
                # Mock upstream (relay pipeline)
                mock_fwd = AsyncMock()
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
                mock_resp.text = "ok"
                mock_fwd.post.return_value = mock_resp
                mock_fwd.__aenter__ = AsyncMock(return_value=mock_fwd)
                mock_fwd.__aexit__ = AsyncMock(return_value=False)
                mock_fwd_cls.return_value = mock_fwd

                # Mock Telegram API (send_response)
                mock_tg = AsyncMock()
                mock_tg.post.return_value = MagicMock(status_code=200)
                mock_tg.__aenter__ = AsyncMock(return_value=mock_tg)
                mock_tg.__aexit__ = AsyncMock(return_value=False)
                mock_tg_cls.return_value = mock_tg

                # First request succeeds
                resp1 = await client.post(
                    "/webhook/telegram",
                    json=_make_telegram_update(update_id=100),
                    headers=headers,
                )
                assert resp1.status_code == 200

                # Same update_id -> replay rejected
                resp2 = await client.post(
                    "/webhook/telegram",
                    json=_make_telegram_update(update_id=100),
                    headers=headers,
                )
                assert resp2.status_code == 409

    @pytest.mark.asyncio
    async def test_telegram_rate_limited_429(self, tmp_path: Path) -> None:
        """Excessive requests -> 429 (NFR-8)."""
        app = _make_app_with_sanitizer(
            tmp_path,
            telegram_bot_token="123:ABC",
            webhook_rate_limit=2,
        )
        headers = _make_telegram_headers("123:ABC")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.webhook.relay.httpx.AsyncClient") as mock_fwd_cls, \
                 patch("src.webhook.telegram.httpx.AsyncClient") as mock_tg_cls:
                mock_fwd = AsyncMock()
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
                mock_resp.text = "ok"
                mock_fwd.post.return_value = mock_resp
                mock_fwd.__aenter__ = AsyncMock(return_value=mock_fwd)
                mock_fwd.__aexit__ = AsyncMock(return_value=False)
                mock_fwd_cls.return_value = mock_fwd

                mock_tg = AsyncMock()
                mock_tg.post.return_value = MagicMock(status_code=200)
                mock_tg.__aenter__ = AsyncMock(return_value=mock_tg)
                mock_tg.__aexit__ = AsyncMock(return_value=False)
                mock_tg_cls.return_value = mock_tg

                # Send requests up to the limit
                for i in range(2):
                    resp = await client.post(
                        "/webhook/telegram",
                        json=_make_telegram_update(update_id=200 + i),
                        headers=headers,
                    )
                    assert resp.status_code == 200, f"Request {i}: {resp.status_code}"

                # Next one should be rate limited
                resp = await client.post(
                    "/webhook/telegram",
                    json=_make_telegram_update(update_id=202),
                    headers=headers,
                )
                assert resp.status_code == 429


class TestWebhookBodySizeLimits:
    """Body-size protection before JSON parse (defense-in-depth)."""

    @pytest.mark.asyncio
    async def test_telegram_oversized_body_413(self, tmp_path: Path) -> None:
        """Oversized Telegram request body -> 413 before JSON parse."""
        app = _make_app_with_sanitizer(tmp_path, telegram_bot_token="123:ABC")
        headers = _make_telegram_headers("123:ABC")
        # Create a body that exceeds the limit (patch to small value for test speed)
        with patch("src.proxy.app._MAX_WEBHOOK_BODY_SIZE", 100):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                oversized_body = b"x" * 200
                resp = await client.post(
                    "/webhook/telegram",
                    content=oversized_body,
                    headers={**headers, "content-type": "application/json"},
                )
                assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_whatsapp_oversized_body_413(self, tmp_path: Path) -> None:
        """Oversized WhatsApp request body -> 413 before JSON parse."""
        app = _make_app_with_sanitizer(
            tmp_path,
            whatsapp_config={
                "app_secret": "wa_secret",
                "verify_token": "wa_verify",
                "phone_number_id": "123456",
                "access_token": "wa_token",
            },
        )
        oversized_body = b"x" * 200
        sig = _sign_whatsapp_body("wa_secret", oversized_body)
        with patch("src.proxy.app._MAX_WEBHOOK_BODY_SIZE", 100):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/webhook/whatsapp",
                    content=oversized_body,
                    headers={
                        "content-type": "application/json",
                        "x-hub-signature-256": sig,
                    },
                )
                assert resp.status_code == 413


class TestWhatsAppEndpoints:
    """WhatsApp webhook endpoint integration tests."""

    @pytest.fixture
    def app_with_whatsapp(self, tmp_path: Path) -> Any:
        return _make_app_with_sanitizer(
            tmp_path,
            whatsapp_config={
                "app_secret": "wa_secret",
                "verify_token": "wa_verify",
                "phone_number_id": "123456",
                "access_token": "wa_token",
            },
        )

    @pytest.mark.asyncio
    async def test_whatsapp_verification_challenge(
        self, app_with_whatsapp: Any,
    ) -> None:
        """GET /webhook/whatsapp handles Meta verification challenge."""
        transport = ASGITransport(app=app_with_whatsapp)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/webhook/whatsapp",
                params={
                    "hub.mode": "subscribe",
                    "hub.verify_token": "wa_verify",
                    "hub.challenge": "test_challenge_123",
                },
            )
            assert resp.status_code == 200
            assert resp.text == "test_challenge_123"

    @pytest.mark.asyncio
    async def test_whatsapp_invalid_verify_token_403(
        self, app_with_whatsapp: Any,
    ) -> None:
        """Invalid verify token -> 403."""
        transport = ASGITransport(app=app_with_whatsapp)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/webhook/whatsapp",
                params={
                    "hub.mode": "subscribe",
                    "hub.verify_token": "wrong",
                    "hub.challenge": "ch",
                },
            )
            assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_whatsapp_invalid_hmac_401(
        self, app_with_whatsapp: Any,
    ) -> None:
        """Invalid WhatsApp HMAC -> 401 (FR-3.4)."""
        payload = _make_whatsapp_payload()
        body = json.dumps(payload).encode()
        transport = ASGITransport(app=app_with_whatsapp)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/webhook/whatsapp",
                content=body,
                headers={
                    "content-type": "application/json",
                    "x-hub-signature-256": "sha256=wrong",
                },
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_whatsapp_replay_attack_409(
        self, app_with_whatsapp: Any,
    ) -> None:
        """Old timestamp -> 409 (FR-3.7)."""
        old_timestamp = str(int(time.time()) - 400)
        payload = _make_whatsapp_payload(timestamp=old_timestamp)
        body = json.dumps(payload).encode()
        sig = _sign_whatsapp_body("wa_secret", body)
        transport = ASGITransport(app=app_with_whatsapp)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/webhook/whatsapp",
                content=body,
                headers={
                    "content-type": "application/json",
                    "x-hub-signature-256": sig,
                },
            )
            assert resp.status_code == 409
