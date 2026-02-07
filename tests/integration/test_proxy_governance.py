"""Integration tests for governance in the proxy pipeline."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from src.governance.middleware import EvaluationResult, GovernanceMiddleware
from src.governance.models import GovernanceDecision, PolicyViolation
from src.models import Severity
from src.proxy.app import create_app
from src.sanitizer.sanitizer import PromptSanitizer

TOKEN = "test-governance-token"


@pytest.fixture
def sanitizer(tmp_path):
    """Create a minimal sanitizer."""
    rules_file = tmp_path / "prompt-rules.json"
    rules_file.write_text(json.dumps([]))
    return PromptSanitizer(str(rules_file))


@pytest.fixture
def mock_governance():
    """Create a mock GovernanceMiddleware."""
    mock = MagicMock(spec=GovernanceMiddleware)
    mock._store = MagicMock()
    return mock


@pytest.fixture
def app_with_governance(sanitizer, mock_governance):
    """Create app with governance enabled."""
    return create_app(
        upstream_url="http://localhost:3000",
        token=TOKEN,
        sanitizer=sanitizer,
        governance=mock_governance,
    )


@pytest.fixture
def app_without_governance(sanitizer):
    """Create app with governance disabled (None)."""
    return create_app(
        upstream_url="http://localhost:3000",
        token=TOKEN,
        sanitizer=sanitizer,
        governance=None,
    )


def _make_mock_upstream(
    status_code: int = 200,
    content: bytes = b'{"ok": true}',
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Create a mock httpx.AsyncClient context manager with a preset response."""
    resp_headers = headers or {"content-type": "application/json"}
    fake_response = httpx.Response(
        status_code=status_code,
        content=content,
        headers=resp_headers,
    )

    mock_instance = AsyncMock()
    mock_instance.request = AsyncMock(return_value=fake_response)
    mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
    mock_instance.__aexit__ = AsyncMock(return_value=False)
    return mock_instance


class TestProxyGovernancePipeline:
    """Integration tests for governance in the proxy pipeline."""

    @pytest.mark.asyncio
    async def test_tool_call_triggers_governance(self, app_with_governance, mock_governance):
        """POST with tool_calls -> governance.evaluate() called."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.ALLOW,
            plan_id="p1",
            token="tok",
        )
        transport = ASGITransport(app=app_with_governance)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_client_cls.return_value = _make_mock_upstream()
                resp = await client.post(
                    "/api/chat",
                    json={"tool_calls": [{"name": "read_file"}]},
                    headers={"authorization": f"Bearer {TOKEN}"},
                )
        assert resp.status_code == 200
        mock_governance.evaluate.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_tool_calls_bypasses_governance(self, app_with_governance, mock_governance):
        """POST without tool_calls -> governance not called."""
        transport = ASGITransport(app=app_with_governance)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_client_cls.return_value = _make_mock_upstream()
                resp = await client.post(
                    "/api/chat",
                    json={"messages": [{"role": "user", "content": "hi"}]},
                    headers={"authorization": f"Bearer {TOKEN}"},
                )
        assert resp.status_code == 200
        mock_governance.evaluate.assert_not_called()

    @pytest.mark.asyncio
    async def test_governance_disabled_skips_check(self, app_without_governance):
        """governance=None -> no governance checks (FR-1.5)."""
        transport = ASGITransport(app=app_without_governance)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_client_cls.return_value = _make_mock_upstream()
                resp = await client.post(
                    "/api/chat",
                    json={"tool_calls": [{"name": "exec"}]},
                    headers={"authorization": f"Bearer {TOKEN}"},
                )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_governance_block_returns_403(self, app_with_governance, mock_governance):
        """BLOCK decision -> 403 response."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.BLOCK,
            violations=[
                PolicyViolation(
                    rule_id="R1",
                    severity=Severity.HIGH,
                    action_sequence=0,
                    message="Blocked",
                ),
            ],
        )
        transport = ASGITransport(app=app_with_governance)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/chat",
                json={"tool_calls": [{"name": "exec"}]},
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_governance_headers_stripped_from_response(
        self, app_with_governance, mock_governance,
    ):
        """SEC-D-01: X-Governance-* stripped from response to client."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.ALLOW,
            plan_id="p1",
            token="tok",
        )
        transport = ASGITransport(app=app_with_governance)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_client_cls.return_value = _make_mock_upstream(
                    headers={
                        "content-type": "application/json",
                        "x-governance-plan-id": "plan-123",
                        "x-governance-token": "secret-token",
                    },
                )
                resp = await client.post(
                    "/api/chat",
                    json={"tool_calls": [{"name": "read"}]},
                    headers={"authorization": f"Bearer {TOKEN}"},
                )
        assert "x-governance-plan-id" not in resp.headers
        assert "x-governance-token" not in resp.headers

    @pytest.mark.asyncio
    async def test_pipeline_order_auth_then_governance(self, app_with_governance, mock_governance):
        """Auth runs before governance (wrong token -> 403, governance not called)."""
        transport = ASGITransport(app=app_with_governance)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/chat",
                json={"tool_calls": [{"name": "exec"}]},
                headers={"authorization": "Bearer wrong-token"},
            )
        assert resp.status_code == 403
        mock_governance.evaluate.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_auth_returns_401(self, app_with_governance, mock_governance):
        """No auth header -> 401, governance not called."""
        transport = ASGITransport(app=app_with_governance)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/chat",
                json={"tool_calls": [{"name": "exec"}]},
            )
        assert resp.status_code == 401
        mock_governance.evaluate.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_request_bypasses_governance(self, app_with_governance, mock_governance):
        """GET requests skip governance (no tool calls in body)."""
        transport = ASGITransport(app=app_with_governance)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_client_cls.return_value = _make_mock_upstream()
                await client.get(
                    "/api/status",
                    headers={"authorization": f"Bearer {TOKEN}"},
                )
        mock_governance.evaluate.assert_not_called()

    @pytest.mark.asyncio
    async def test_governance_require_approval_returns_202(
        self, app_with_governance, mock_governance,
    ):
        """REQUIRE_APPROVAL -> 202 with approval details."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.REQUIRE_APPROVAL,
            approval_id="a1",
            plan_id="p1",
            message="Approval needed",
        )
        transport = ASGITransport(app=app_with_governance)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/chat",
                json={"tool_calls": [{"name": "exec"}]},
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 202
        body = resp.json()
        assert body["approval_id"] == "a1"
        assert body["plan_id"] == "p1"
