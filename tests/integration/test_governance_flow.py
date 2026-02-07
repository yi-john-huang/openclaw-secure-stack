"""End-to-end governance approval flow integration tests."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from src.governance.enforcer import EnforcementResult
from src.governance.middleware import ApprovalResult, EvaluationResult, GovernanceMiddleware
from src.governance.models import (
    ApprovalRequest,
    ApprovalStatus,
    GovernanceDecision,
    PolicyViolation,
)
from src.models import Severity
from src.proxy.app import create_app
from src.sanitizer.sanitizer import PromptSanitizer

TOKEN = "smoke-test-token"


@pytest.fixture
def sanitizer(tmp_path):
    rules_file = tmp_path / "prompt-rules.json"
    rules_file.write_text(json.dumps([]))
    return PromptSanitizer(str(rules_file))


@pytest.fixture
def mock_governance():
    mock = MagicMock(spec=GovernanceMiddleware)
    mock._store = MagicMock()
    return mock


@pytest.fixture
def app(sanitizer, mock_governance):
    return create_app(
        upstream_url="http://localhost:3000",
        token=TOKEN,
        sanitizer=sanitizer,
        governance=mock_governance,
    )


def _make_mock_upstream(
    status_code: int = 200,
    content: bytes = b'{"ok": true}',
    headers: dict[str, str] | None = None,
) -> MagicMock:
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


class TestGovernanceApprovalFlow:
    """End-to-end governance approval flow."""

    @pytest.mark.asyncio
    async def test_full_approval_flow(self, app, mock_governance):
        """
        1. POST with tool calls -> 202 (REQUIRE_APPROVAL)
        2. GET approval details -> shows violations
        3. POST approve -> plan activated, token returned
        4. POST retry with token -> request forwarded
        """
        request_body = {"tool_calls": [{"name": "exec", "arguments": {"cmd": "ls"}}]}
        raw_body = json.dumps(request_body).encode()
        request_hash = hashlib.sha256(raw_body).hexdigest()

        # Step 1: Initial request triggers REQUIRE_APPROVAL
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.REQUIRE_APPROVAL,
            approval_id="approval-123",
            plan_id="plan-456",
            message="Approval needed for exec",
        )

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/chat",
                content=raw_body,
                headers={
                    "authorization": f"Bearer {TOKEN}",
                    "content-type": "application/json",
                },
            )
        assert resp.status_code == 202
        body = resp.json()
        assert body["approval_id"] == "approval-123"
        assert body["plan_id"] == "plan-456"

        # Step 2: GET approval details
        mock_governance.get_approval.return_value = ApprovalRequest(
            approval_id="approval-123",
            plan_id="plan-456",
            requester_id="user1",
            status=ApprovalStatus.PENDING,
            requested_at="2026-01-01T00:00:00Z",
            expires_at="2026-01-01T01:00:00Z",
            violations=[
                PolicyViolation(
                    rule_id="R1",
                    severity=Severity.HIGH,
                    action_sequence=0,
                    message="High risk exec command",
                ),
            ],
        )
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/governance/approvals/approval-123",
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 200
        details = resp.json()
        assert details["status"] == "pending"
        assert len(details["violations"]) == 1

        # Step 3: Approve the request
        mock_governance.approve.return_value = ApprovalResult(
            approval=ApprovalRequest(
                approval_id="approval-123",
                plan_id="plan-456",
                requester_id="user1",
                status=ApprovalStatus.APPROVED,
                requested_at="2026-01-01T00:00:00Z",
                expires_at="2026-01-01T01:00:00Z",
            ),
            plan_id="plan-456",
            token="signed-retry-token",
        )
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/governance/approvals/approval-123/approve",
                json={"approver_id": "admin", "acknowledgment": "I approve this exec"},
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 200
        approve_body = resp.json()
        assert approve_body["plan_id"] == "plan-456"
        assert approve_body["token"] == "signed-retry-token"

        # Step 4: Retry with the token
        mock_governance.enforce.return_value = EnforcementResult(
            allowed=True, reason="ok", plan_id="plan-456",
        )
        mock_plan = MagicMock()
        mock_plan.request_hash = request_hash
        mock_governance._store.lookup.return_value = mock_plan

        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_client_cls.return_value = _make_mock_upstream()
                resp = await client.post(
                    "/api/chat",
                    content=raw_body,
                    headers={
                        "authorization": f"Bearer {TOKEN}",
                        "content-type": "application/json",
                        "x-governance-plan-id": "plan-456",
                        "x-governance-token": "signed-retry-token",
                    },
                )
        assert resp.status_code == 200
        # governance.evaluate should NOT have been called for the retry
        # (it was called once in step 1, and the retry goes through enforce)
        assert mock_governance.evaluate.call_count == 1

    @pytest.mark.asyncio
    async def test_full_block_flow(self, app, mock_governance):
        """POST with blocked tool call -> 403 + audit event."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.BLOCK,
            violations=[
                PolicyViolation(
                    rule_id="R1",
                    severity=Severity.CRITICAL,
                    action_sequence=0,
                    message="Dangerous operation blocked",
                ),
            ],
        )
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/chat",
                json={"tool_calls": [{"name": "rm_rf"}]},
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 403
        body = resp.json()
        assert "violations" in body
        assert body["violations"][0]["message"] == "Dangerous operation blocked"

    @pytest.mark.asyncio
    async def test_full_allow_flow(self, app, mock_governance):
        """POST with allowed tool call -> forwarded with governance headers."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.ALLOW,
            plan_id="plan-789",
            token="allow-token",
        )
        captured_headers: dict[str, str] = {}

        async def capture_request(*args, **kwargs):
            captured_headers.update(kwargs.get("headers", {}))
            return httpx.Response(status_code=200, content=b'{"result": "ok"}')

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            with patch("src.proxy.app.httpx.AsyncClient") as mock_client_cls:
                mock_instance = AsyncMock()
                mock_instance.request = capture_request
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=False)
                mock_client_cls.return_value = mock_instance

                resp = await client.post(
                    "/api/chat",
                    json={"tool_calls": [{"name": "read_file"}]},
                    headers={"authorization": f"Bearer {TOKEN}"},
                )
        assert resp.status_code == 200
        # Governance headers should have been attached to upstream request
        assert captured_headers.get("x-governance-plan-id") == "plan-789"
        assert captured_headers.get("x-governance-token") == "allow-token"
