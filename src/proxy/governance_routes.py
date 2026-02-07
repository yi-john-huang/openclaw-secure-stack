"""Governance API endpoints for approval management.

Provides endpoints for:
- Viewing approval requests (FR-6.1)
- Approving/rejecting requests (FR-6.2, FR-6.3)
- Cleaning up expired resources (FR-6.4)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from src.governance.store import InvalidPlanStatusError, PlanNotFoundError
from src.models import AuditEvent, AuditEventType, RiskLevel

if TYPE_CHECKING:
    from src.audit.logger import AuditLogger
    from src.governance.middleware import GovernanceMiddleware

logger = logging.getLogger(__name__)


def create_governance_router(
    governance: GovernanceMiddleware,
    audit_logger: AuditLogger | None = None,
) -> APIRouter:
    """Create the governance API router."""
    router = APIRouter(prefix="/governance")

    @router.get("/approvals/{approval_id}")
    async def get_approval(approval_id: str) -> JSONResponse:
        """Get approval request details (FR-6.1)."""
        approval = governance.get_approval(approval_id)
        if approval is None:
            return JSONResponse(
                {"error": "Approval not found"},
                status_code=404,
            )
        return JSONResponse(approval.model_dump())

    @router.post("/approvals/{approval_id}/approve")
    async def approve(approval_id: str, request: Request) -> JSONResponse:
        """Approve a pending request, activate plan, return token (FR-6.2)."""
        body = await request.json()
        approver_id = body.get("approver_id", "unknown")
        acknowledgment = body.get("acknowledgment", "")

        try:
            result = governance.approve(approval_id, approver_id, acknowledgment)
        except (PlanNotFoundError, InvalidPlanStatusError) as e:
            return JSONResponse(
                {"error": str(e)},
                status_code=410,
            )

        if audit_logger:
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.GOVERNANCE_APPROVAL_GRANTED,
                user_id=approver_id,
                action="approve",
                result="approved",
                risk_level=RiskLevel.MEDIUM,
                details={"approval_id": approval_id, "plan_id": result.plan_id},
            ))

        return JSONResponse({
            "status": "approved",
            "plan_id": result.plan_id,
            "token": result.token,
        })

    @router.post("/approvals/{approval_id}/reject")
    async def reject(approval_id: str, request: Request) -> JSONResponse:
        """Reject a pending request (FR-6.3)."""
        body = await request.json()
        rejector_id = body.get("rejector_id", "unknown")
        reason = body.get("reason", "")

        try:
            approval = governance.reject(approval_id, rejector_id, reason)
        except (PlanNotFoundError, InvalidPlanStatusError) as e:
            return JSONResponse(
                {"error": str(e)},
                status_code=410,
            )
        except Exception:
            logger.exception("Unexpected error rejecting approval %s", approval_id)
            return JSONResponse(
                {"error": "Internal error"},
                status_code=500,
            )

        if audit_logger:
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.GOVERNANCE_BLOCK,
                user_id=rejector_id,
                action="reject",
                result="rejected",
                risk_level=RiskLevel.MEDIUM,
                details={"approval_id": approval_id, "reason": reason},
            ))

        return JSONResponse(approval.model_dump())

    @router.post("/cleanup")
    async def cleanup() -> JSONResponse:
        """Remove expired plans, sessions, and approvals (FR-6.4)."""
        results = governance.cleanup()
        if audit_logger:
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.GOVERNANCE_ALLOW,
                action="cleanup",
                result="success",
                risk_level=RiskLevel.MEDIUM,
                details=results,
            ))
        return JSONResponse(results)

    return router
