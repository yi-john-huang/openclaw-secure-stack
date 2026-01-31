"""Integration tests for the proxy auth flow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from src.proxy.app import create_app
from src.sanitizer.sanitizer import PromptSanitizer

TOKEN = "integration-test-token-xyz"


@pytest.fixture()
def rules_path(tmp_path: Path) -> str:
    rules = [
        {
            "id": "PI-001",
            "name": "Ignore instructions",
            "pattern": "(?i)ignore\\s+(all\\s+)?previous\\s+instructions",
            "action": "strip",
            "description": "test",
        },
    ]
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules))
    return str(p)


@pytest.fixture()
def app(rules_path: str) -> object:
    sanitizer = PromptSanitizer(rules_path)
    return create_app(
        upstream_url="http://upstream:3000",
        token=TOKEN,
        sanitizer=sanitizer,
    )


@pytest.mark.asyncio
async def test_valid_token_proxies(app: object) -> None:
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_missing_token_rejected(app: object) -> None:
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/test")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_invalid_token_rejected(app: object) -> None:
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/test",
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_health_no_auth(app: object) -> None:
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
