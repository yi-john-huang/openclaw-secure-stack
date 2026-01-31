"""Tests for the auth middleware."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from src.models import AuditEventType
from src.proxy.auth_middleware import AuthMiddleware

TOKEN = "test-secret-token-12345"


def _create_app(audit_logger: MagicMock | None = None) -> Starlette:
    async def homepage(request):  # noqa: ANN001
        return PlainTextResponse("OK")

    async def health(request):  # noqa: ANN001
        return PlainTextResponse("healthy")

    app = Starlette(routes=[Route("/", homepage), Route("/health", health)])
    return AuthMiddleware(app, token=TOKEN, audit_logger=audit_logger)  # type: ignore[return-value]


@pytest.mark.asyncio
async def test_valid_token_passes() -> None:
    app = _create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/", headers={"Authorization": f"Bearer {TOKEN}"})
        assert resp.status_code == 200
        assert resp.text == "OK"


@pytest.mark.asyncio
async def test_missing_token_returns_401() -> None:
    app = _create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_invalid_token_returns_403() -> None:
    app = _create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/", headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_no_information_leakage() -> None:
    app = _create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/", headers={"Authorization": "Bearer wrong"})
        assert "wrong" not in resp.text
        assert TOKEN not in resp.text


@pytest.mark.asyncio
async def test_health_endpoint_no_auth() -> None:
    app = _create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_auth_failure_logged() -> None:
    mock_logger = MagicMock()
    app = _create_app(audit_logger=mock_logger)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.get("/", headers={"Authorization": "Bearer wrong"})

    failure_calls = [
        c for c in mock_logger.log.call_args_list
        if c[0][0].event_type == AuditEventType.AUTH_FAILURE
    ]
    assert len(failure_calls) == 1


@pytest.mark.asyncio
async def test_auth_success_logged() -> None:
    mock_logger = MagicMock()
    app = _create_app(audit_logger=mock_logger)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.get("/", headers={"Authorization": f"Bearer {TOKEN}"})

    success_calls = [
        c for c in mock_logger.log.call_args_list
        if c[0][0].event_type == AuditEventType.AUTH_SUCCESS
    ]
    assert len(success_calls) == 1
