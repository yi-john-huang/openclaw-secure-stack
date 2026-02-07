"""Tests for governance API endpoints (FR-6)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from src.governance.middleware import ApprovalResult, GovernanceMiddleware
from src.governance.models import ApprovalRequest, ApprovalStatus, PolicyViolation
from src.models import Severity
from src.proxy.governance_routes import create_governance_router
from src.sanitizer.sanitizer import PromptSanitizer

TOKEN = "test-governance-route-token"


@pytest.fixture
def mock_governance():
    mock = MagicMock(spec=GovernanceMiddleware)
    mock._store = MagicMock()
    return mock


@pytest.fixture
def sanitizer(tmp_path):
    rules_file = tmp_path / "prompt-rules.json"
    rules_file.write_text(json.dumps([]))
    return PromptSanitizer(str(rules_file))


@pytest.fixture
def app_with_routes(sanitizer, mock_governance):
    from src.proxy.app import create_app

    return create_app(
        upstream_url="http://localhost:3000",
        token=TOKEN,
        sanitizer=sanitizer,
        governance=mock_governance,
    )


class TestGovernanceRoutes:
    """Tests for governance API endpoints (FR-6)."""

    @pytest.mark.asyncio
    async def test_get_approval_returns_details(self, app_with_routes, mock_governance):
        """GET /governance/approvals/{id} returns approval request."""
        mock_governance.get_approval.return_value = ApprovalRequest(
            approval_id="a1",
            plan_id="p1",
            requester_id="user1",
            status=ApprovalStatus.PENDING,
            requested_at="2026-01-01T00:00:00Z",
            expires_at="2026-01-01T01:00:00Z",
            violations=[
                PolicyViolation(
                    rule_id="R1",
                    severity=Severity.HIGH,
                    action_sequence=0,
                    message="High risk action",
                ),
            ],
        )
        transport = ASGITransport(app=app_with_routes)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/governance/approvals/a1",
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["approval_id"] == "a1"
        assert body["status"] == "pending"

    @pytest.mark.asyncio
    async def test_get_approval_not_found_returns_404(self, app_with_routes, mock_governance):
        """GET /governance/approvals/{id} with unknown id -> 404."""
        mock_governance.get_approval.return_value = None
        transport = ASGITransport(app=app_with_routes)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/governance/approvals/nonexistent",
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_approve_activates_plan(self, app_with_routes, mock_governance):
        """POST /governance/approvals/{id}/approve -> plan activated, token returned (FR-6.2)."""
        mock_governance.approve.return_value = ApprovalResult(
            approval=ApprovalRequest(
                approval_id="a1",
                plan_id="p1",
                requester_id="user1",
                status=ApprovalStatus.APPROVED,
                requested_at="2026-01-01T00:00:00Z",
                expires_at="2026-01-01T01:00:00Z",
            ),
            plan_id="p1",
            token="signed-token",
        )
        transport = ASGITransport(app=app_with_routes)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/governance/approvals/a1/approve",
                json={"approver_id": "admin", "acknowledgment": "I approve"},
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan_id"] == "p1"
        assert body["token"] == "signed-token"

    @pytest.mark.asyncio
    async def test_approve_expired_returns_410(self, app_with_routes, mock_governance):
        """POST /governance/approvals/{id}/approve on expired -> 410."""
        from src.governance.store import InvalidPlanStatusError

        mock_governance.approve.side_effect = InvalidPlanStatusError("Plan expired")
        transport = ASGITransport(app=app_with_routes)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/governance/approvals/a1/approve",
                json={"approver_id": "admin", "acknowledgment": "ok"},
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 410

    @pytest.mark.asyncio
    async def test_reject_returns_200(self, app_with_routes, mock_governance):
        """POST /governance/approvals/{id}/reject -> logged (FR-6.3)."""
        mock_governance.reject.return_value = ApprovalRequest(
            approval_id="a1",
            plan_id="p1",
            requester_id="user1",
            status=ApprovalStatus.REJECTED,
            requested_at="2026-01-01T00:00:00Z",
            expires_at="2026-01-01T01:00:00Z",
            reason="Too risky",
        )
        transport = ASGITransport(app=app_with_routes)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/governance/approvals/a1/reject",
                json={"rejector_id": "admin", "reason": "Too risky"},
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "rejected"

    @pytest.mark.asyncio
    async def test_cleanup_removes_expired(self, app_with_routes, mock_governance):
        """POST /governance/cleanup -> expired plans/sessions removed (FR-6.4)."""
        mock_governance.cleanup.return_value = {"plans": 3, "sessions": 1}
        transport = ASGITransport(app=app_with_routes)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/governance/cleanup",
                headers={"authorization": f"Bearer {TOKEN}"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["plans"] == 3
        assert body["sessions"] == 1

    @pytest.mark.asyncio
    async def test_endpoints_require_auth(self, app_with_routes):
        """All governance endpoints require Bearer token (AC-1)."""
        transport = ASGITransport(app=app_with_routes)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # No auth header
            resp = await client.get("/governance/approvals/a1")
        assert resp.status_code == 401
