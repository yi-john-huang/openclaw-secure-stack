"""Webhook relay pipeline — SEC-D-04.

Orchestrates the full security pipeline for webhook messages using
direct function calls (not self-request to localhost).

Pipeline stages:
1. Body size check (NFR-7)
2. Sanitize (prompt injection detection)
3. Quarantine check (blocked skills)
4. Forward to upstream via httpx
5. Response scan (indirect injection)
6. Audit log
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import httpx

from src.models import AuditEvent, AuditEventType, RiskLevel
from src.sanitizer.sanitizer import PromptInjectionError
from src.webhook.models import WebhookMessage, WebhookResponse

if TYPE_CHECKING:
    from src.audit.logger import AuditLogger
    from src.governance.middleware import GovernanceMiddleware
    from src.quarantine.manager import QuarantineManager
    from src.sanitizer.sanitizer import PromptSanitizer

logger = logging.getLogger(__name__)

_MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB (NFR-7)


class WebhookRelayPipeline:
    """Orchestrates the webhook relay security pipeline.

    SEC-D-04: Uses direct function calls for pipeline stages,
    NOT self-request to localhost.
    """

    def __init__(
        self,
        sanitizer: PromptSanitizer,
        upstream_url: str,
        upstream_token: str,
        quarantine_manager: QuarantineManager | None = None,
        governance: GovernanceMiddleware | None = None,
        response_scanner: PromptSanitizer | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self._sanitizer = sanitizer
        self._quarantine = quarantine_manager
        self._governance = governance
        self._upstream_url = upstream_url
        self._upstream_token = upstream_token
        self._response_scanner = response_scanner
        self._audit = audit_logger

    async def relay(self, message: WebhookMessage) -> WebhookResponse:
        """Run the full relay pipeline for a webhook message."""

        # Stage 1: Body size check (NFR-7)
        if len(message.text.encode()) > _MAX_BODY_SIZE:
            return WebhookResponse(
                text="Request body too large",
                status_code=413,
            )

        # Stage 2: Sanitize (prompt injection detection)
        try:
            result = self._sanitizer.sanitize(message.text)
            clean_text = result.clean
        except PromptInjectionError:
            return WebhookResponse(
                text="Request rejected due to policy violation",
                status_code=400,
            )

        # Stage 2.5: Governance evaluation
        if self._governance:
            from src.governance.models import GovernanceDecision

            gov_body: dict[str, Any] = {
                "model": "default",
                "messages": [{"role": "user", "content": clean_text}],
                "metadata": {"source": message.source, **message.metadata},
            }
            gov_result = self._governance.evaluate(
                gov_body, None, message.sender_id,
            )
            if self._audit:
                self._audit.log(AuditEvent(
                    event_type=AuditEventType.WEBHOOK_RELAY,
                    action="governance_eval",
                    result=gov_result.decision.value,
                    risk_level=RiskLevel.INFO,
                    details={
                        "source": message.source,
                        "sender_id": message.sender_id,
                        "decision": gov_result.decision.value,
                    },
                ))
            if gov_result.decision == GovernanceDecision.BLOCK:
                return WebhookResponse(
                    text="Blocked by governance policy",
                    status_code=403,
                )
            if gov_result.decision == GovernanceDecision.REQUIRE_APPROVAL:
                return WebhookResponse(
                    text=f"Approval required (ID: {gov_result.approval_id})",
                    status_code=202,
                )

        # Stage 3: Quarantine check
        if self._quarantine:
            skill_name = message.metadata.get("skill_name")
            if skill_name and self._quarantine.is_quarantined(skill_name):
                return WebhookResponse(
                    text=f"Skill '{skill_name}' is quarantined",
                    status_code=403,
                )

        # Stage 4: Forward to upstream
        request_body = {
            "model": "default",
            "messages": [{"role": "user", "content": clean_text}],
            "metadata": {"source": message.source, **message.metadata},
        }
        upstream_response = await self._forward_to_upstream(request_body)

        # Stage 5: Response scan (indirect injection)
        if self._response_scanner and upstream_response.status_code == 200:
            findings = self._response_scanner.scan(upstream_response.text)
            if findings and self._audit:
                self._audit.log(AuditEvent(
                    event_type=AuditEventType.INDIRECT_INJECTION,
                    action="webhook_response_scan",
                    result="detected",
                    risk_level=RiskLevel.HIGH,
                    details={
                        "source": message.source,
                        "patterns": findings,
                    },
                ))

        # Stage 6: Audit log
        if self._audit:
            self._audit.log(AuditEvent(
                event_type=AuditEventType.WEBHOOK_RELAY,
                action="relay",
                result="success" if upstream_response.status_code == 200 else "error",
                risk_level=RiskLevel.INFO,
                details={
                    "source": message.source,
                    "sender_id": message.sender_id,
                    "upstream_status": upstream_response.status_code,
                },
            ))

        return upstream_response

    async def _forward_to_upstream(
        self, request_body: dict[str, Any],
    ) -> WebhookResponse:
        """Forward translated request to OpenClaw upstream."""
        url = f"{self._upstream_url.rstrip('/')}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._upstream_token}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    url, json=request_body, headers=headers, timeout=30.0,
                )
                # Extract assistant message from response
                try:
                    resp_json = resp.json()
                    text = (
                        resp_json.get("choices", [{}])[0]
                        .get("message", {})
                        .get("content", resp.text)
                    )
                except (json.JSONDecodeError, IndexError, KeyError):
                    text = resp.text

                return WebhookResponse(text=text, status_code=resp.status_code)
        except (httpx.ConnectError, httpx.TimeoutException):
            return WebhookResponse(
                text="Upstream unavailable",
                status_code=502,
            )
