"""Governance helper functions for the proxy pipeline.

Provides utility functions for governance integration including
tool call detection, response header stripping, and governance evaluation.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import TYPE_CHECKING, Any

from fastapi.responses import JSONResponse

from src.models import AuditEvent, AuditEventType, RiskLevel

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

    from src.audit.logger import AuditLogger
    from src.governance.middleware import EvaluationResult, GovernanceMiddleware

logger = logging.getLogger(__name__)


def has_tool_calls(body: Any) -> bool:
    """Detect actual tool call invocations (not capability declarations).

    SEC-D-03: Only match tool_calls and function_call (invocations),
    NOT tools (capability declarations).
    """
    if not isinstance(body, dict):
        return False
    return bool(body.get("tool_calls") or body.get("function_call"))


def strip_governance_headers(headers: dict[str, str]) -> dict[str, str]:
    """Strip X-Governance-* headers from upstream responses.

    SEC-D-01: Prevents governance tokens from leaking to clients.
    """
    return {k: v for k, v in headers.items() if not k.lower().startswith("x-governance-")}


def evaluate_governance(
    governance: GovernanceMiddleware,
    body_json: dict[str, Any],
    raw_body: bytes,
    request: Request,
    audit_logger: AuditLogger | None,
    *,
    return_eval_result: bool = False,
) -> Response | None | tuple[Response | None, EvaluationResult | None]:
    """Evaluate request against governance policies.

    Returns a Response if the request is blocked or requires approval,
    or None if allowed to proceed.

    When return_eval_result=True, returns a tuple of (response, eval_result)
    so the caller can access plan_id/token for header attachment.
    """
    from src.governance.models import GovernanceDecision

    # --- RETRY PATH (SEC-D-02) ---
    plan_id = request.headers.get("x-governance-plan-id")
    token = request.headers.get("x-governance-token")

    if plan_id and token:
        return _handle_retry(governance, plan_id, token, raw_body, return_eval_result)

    # --- FRESH EVALUATION PATH ---
    user_id = request.headers.get(
        "x-user-id",
        request.client.host if request.client else "unknown",
    )
    session_id = request.headers.get("x-governance-session")

    try:
        result = governance.evaluate(body_json, session_id, user_id)
    except Exception:
        logger.exception("Governance evaluation failed")
        if audit_logger:
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.GOVERNANCE_ERROR,
                action="evaluate",
                result="error",
                risk_level=RiskLevel.CRITICAL,
            ))
        resp = JSONResponse(
            {"error": "Governance evaluation failed"},
            status_code=500,
        )
        if return_eval_result:
            return resp, None
        return resp

    if result.decision == GovernanceDecision.BLOCK:
        if audit_logger:
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.GOVERNANCE_BLOCK,
                action="evaluate",
                result="blocked",
                risk_level=RiskLevel.HIGH,
                details={"violations": [v.message for v in result.violations]},
            ))
        resp = JSONResponse(
            {
                "error": "Request blocked by governance policy",
                "violations": [v.model_dump() for v in result.violations],
            },
            status_code=403,
        )
        if return_eval_result:
            return resp, result
        return resp

    if result.decision == GovernanceDecision.REQUIRE_APPROVAL:
        if audit_logger:
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.GOVERNANCE_APPROVAL_REQUIRED,
                action="evaluate",
                result="approval_required",
                risk_level=RiskLevel.MEDIUM,
                details={"approval_id": result.approval_id, "plan_id": result.plan_id},
            ))
        resp = JSONResponse(
            {
                "status": "approval_required",
                "approval_id": result.approval_id,
                "plan_id": result.plan_id,
                "message": result.message,
            },
            status_code=202,
        )
        if return_eval_result:
            return resp, result
        return resp

    # ALLOW — continue pipeline
    if return_eval_result:
        return None, result
    return None


def _handle_retry(
    governance: GovernanceMiddleware,
    plan_id: str,
    token: str,
    raw_body: bytes,
    return_eval_result: bool,
) -> Response | None | tuple[Response | None, None]:
    """Handle retry path with token + request hash verification (SEC-D-02)."""
    from src.governance.models import ToolCall

    # Verify token is valid and not expired
    enforcement = governance.enforce(plan_id, token, ToolCall(name="__verify__", arguments={}))
    if not enforcement.allowed:
        resp = JSONResponse(
            {"error": "Governance token invalid or expired"},
            status_code=403,
        )
        if return_eval_result:
            return resp, None
        return resp

    # SEC-D-02: Verify request body hash matches stored plan
    request_hash = hashlib.sha256(raw_body).hexdigest()
    stored_plan = governance._store.lookup(plan_id)
    if stored_plan is None:
        # Plan expired/cleaned up but token still valid — deny (fail-closed)
        resp = JSONResponse(
            {"error": "Governance plan not found"},
            status_code=403,
        )
        if return_eval_result:
            return resp, None
        return resp
    if not hmac.compare_digest(stored_plan.request_hash, request_hash):
        resp = JSONResponse(
            {"error": "Request body does not match approved plan"},
            status_code=403,
        )
        if return_eval_result:
            return resp, None
        return resp

    # Token valid, hash matches — skip re-evaluation
    if return_eval_result:
        return None, None
    return None
