"""Integration tests for proxy quarantine enforcement."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from src.proxy.app import create_app
from src.quarantine.manager import QuarantineBlockedError, QuarantineManager
from src.sanitizer.sanitizer import PromptSanitizer

TOKEN = "test-token-quarantine"


@pytest.fixture()
def rules_path(tmp_path: Path) -> str:
    rules = [
        {
            "id": "PI-001",
            "name": "Test rule",
            "pattern": "test-pattern",
            "action": "strip",
            "description": "test",
        },
    ]
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules))
    return str(p)


@pytest.fixture()
def mock_quarantine_manager() -> MagicMock:
    return MagicMock(spec=QuarantineManager)


@pytest.fixture()
def app_with_quarantine(rules_path: str, mock_quarantine_manager: MagicMock) -> object:
    sanitizer = PromptSanitizer(rules_path)
    return create_app(
        upstream_url="http://upstream:3000",
        token=TOKEN,
        sanitizer=sanitizer,
        quarantine_manager=mock_quarantine_manager,
    )


class TestProxyQuarantineEnforcement:
    """Tests for quarantine enforcement at the proxy level."""

    @pytest.mark.asyncio
    async def test_quarantined_skill_returns_403(
        self, app_with_quarantine: object, mock_quarantine_manager: MagicMock
    ) -> None:
        """Proxy should return 403 when skill is quarantined."""
        mock_quarantine_manager.enforce_quarantine.side_effect = QuarantineBlockedError(
            "malicious-skill"
        )

        transport = ASGITransport(app=app_with_quarantine)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/skills/malicious-skill/invoke",
                headers={"Authorization": f"Bearer {TOKEN}"},
            )

        assert resp.status_code == 403
        body = resp.json()
        assert "error" in body
        assert "quarantined" in body["error"]["message"].lower()
        assert "malicious-skill" in body["error"]["message"]

    @pytest.mark.asyncio
    async def test_quarantined_skill_error_message_format(
        self, app_with_quarantine: object, mock_quarantine_manager: MagicMock
    ) -> None:
        """Verify the error response format for quarantined skills."""
        mock_quarantine_manager.enforce_quarantine.side_effect = QuarantineBlockedError(
            "blocked-skill"
        )

        transport = ASGITransport(app=app_with_quarantine)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/skills/blocked-skill/run",
                headers={"Authorization": f"Bearer {TOKEN}"},
                json={"input": "test"},
            )

        assert resp.status_code == 403
        body = resp.json()
        assert body == {"error": {"message": "Skill 'blocked-skill' is quarantined"}}

    @pytest.mark.asyncio
    async def test_non_quarantined_skill_proceeds(
        self, rules_path: str, mock_quarantine_manager: MagicMock
    ) -> None:
        """Proxy should forward requests when skill is not quarantined."""
        mock_quarantine_manager.enforce_quarantine.return_value = None

        sanitizer = PromptSanitizer(rules_path)
        app = create_app(
            upstream_url="http://upstream:3000",
            token=TOKEN,
            sanitizer=sanitizer,
            quarantine_manager=mock_quarantine_manager,
        )

        async def mock_request(*args, **kwargs):
            return httpx.Response(status_code=200, content=b'{"result": "ok"}')

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_instance = AsyncMock()
                mock_instance.request = mock_request
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_instance

                resp = await client.get(
                    "/skills/safe-skill/invoke",
                    headers={"Authorization": f"Bearer {TOKEN}"},
                )

        assert resp.status_code == 200
        mock_quarantine_manager.enforce_quarantine.assert_called_once_with("safe-skill")

    @pytest.mark.asyncio
    async def test_non_skill_path_not_checked(
        self, rules_path: str, mock_quarantine_manager: MagicMock
    ) -> None:
        """Non-skill paths should not trigger quarantine checks."""
        sanitizer = PromptSanitizer(rules_path)
        app = create_app(
            upstream_url="http://upstream:3000",
            token=TOKEN,
            sanitizer=sanitizer,
            quarantine_manager=mock_quarantine_manager,
        )

        async def mock_request(*args, **kwargs):
            return httpx.Response(status_code=200, content=b'{"models": []}')

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_instance = AsyncMock()
                mock_instance.request = mock_request
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_instance

                resp = await client.get(
                    "/v1/models",
                    headers={"Authorization": f"Bearer {TOKEN}"},
                )

        assert resp.status_code == 200
        mock_quarantine_manager.enforce_quarantine.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_quarantine_manager_proceeds(self, rules_path: str) -> None:
        """Proxy should work without quarantine manager configured."""
        sanitizer = PromptSanitizer(rules_path)
        app = create_app(
            upstream_url="http://upstream:3000",
            token=TOKEN,
            sanitizer=sanitizer,
            quarantine_manager=None,  # No quarantine manager
        )

        async def mock_request(*args, **kwargs):
            return httpx.Response(status_code=200, content=b'{"result": "ok"}')

        transport = ASGITransport(app=app)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_instance = AsyncMock()
                mock_instance.request = mock_request
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_instance

                resp = await client.get(
                    "/skills/any-skill/invoke",
                    headers={"Authorization": f"Bearer {TOKEN}"},
                )

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_skill_path_extraction(
        self, app_with_quarantine: object, mock_quarantine_manager: MagicMock
    ) -> None:
        """Verify skill name is correctly extracted from various path formats."""
        mock_quarantine_manager.enforce_quarantine.return_value = None

        async def mock_request(*args, **kwargs):
            return httpx.Response(status_code=200, content=b'{}')

        transport = ASGITransport(app=app_with_quarantine)  # type: ignore[arg-type]
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_instance = AsyncMock()
                mock_instance.request = mock_request
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_instance

                # Test various skill path formats
                await client.get(
                    "/skills/my-skill/action",
                    headers={"Authorization": f"Bearer {TOKEN}"},
                )
                mock_quarantine_manager.enforce_quarantine.assert_called_with("my-skill")

                mock_quarantine_manager.reset_mock()
                await client.get(
                    "/skills/another-skill",
                    headers={"Authorization": f"Bearer {TOKEN}"},
                )
                mock_quarantine_manager.enforce_quarantine.assert_called_with("another-skill")
