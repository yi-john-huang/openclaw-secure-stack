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

import asyncio
import base64
import io
import json
import logging
from typing import TYPE_CHECKING, Any

import httpx

from src.models import AuditEvent, AuditEventType, RiskLevel
from src.sanitizer.sanitizer import PromptInjectionError
from src.webhook.models import Attachment, AttachmentType, WebhookMessage, WebhookResponse

if TYPE_CHECKING:
    from src.audit.logger import AuditLogger
    from src.governance.middleware import GovernanceMiddleware
    from src.quarantine.manager import QuarantineManager
    from src.sanitizer.sanitizer import PromptSanitizer
    from src.webhook.history import ConversationHistory

logger = logging.getLogger(__name__)

_MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB (NFR-7)


def _extract_pdf_text(data: bytes, file_name: str) -> str:
    """Extract plain text from PDF bytes using pypdf.

    Returns a header line plus the extracted text. On failure (encrypted,
    corrupted, or scanned-image PDFs) returns a placeholder so the LLM still
    knows a PDF was attached even if content is unavailable.
    """
    try:
        import pypdf  # local import — optional dependency
        reader = pypdf.PdfReader(io.BytesIO(data))
        pages = [page.extract_text() or "" for page in reader.pages]
        text = "\n\n".join(p.strip() for p in pages if p.strip())
        if text:
            return f"[PDF: {file_name}]\n\n{text}"
        # Scanned/image-only PDF — no extractable text
        return f"[PDF: {file_name}] (no extractable text — may be a scanned image)"
    except Exception:
        logger.warning("Failed to extract text from PDF %s", file_name, exc_info=True)
        return f"[PDF: {file_name}] (could not parse)"


async def _build_content_parts(
    text: str,
    attachments: list[Attachment],
) -> str | list[dict[str, Any]]:
    """Build the message content for the upstream LLM request.

    - No attachments → returns plain str (backward compatible, unchanged behavior).
    - With attachments → returns OpenAI multimodal content array.

    Content block format by attachment type:
    - IMAGE/STICKER: image_url block with data URI
    - AUDIO/VOICE: input_audio block with base64 + format
    - PDF: text block with pypdf-extracted plain text
    - VIDEO/other: text placeholder (unsupported binary format)
    """
    if not attachments:
        return text

    parts: list[dict[str, Any]] = []

    if text:
        parts.append({"type": "text", "text": text})

    for attachment in attachments:
        encoded = base64.b64encode(attachment.data).decode()

        if attachment.type in (AttachmentType.IMAGE, AttachmentType.STICKER):
            parts.append({
                "type": "image_url",
                "image_url": {
                    "url": f"data:{attachment.mime_type};base64,{encoded}",
                },
            })
        elif attachment.type in (AttachmentType.AUDIO, AttachmentType.VOICE):
            # Derive format from mime_type (e.g. "audio/ogg" → "ogg")
            fmt = attachment.mime_type.split("/")[-1].split(";")[0]
            parts.append({
                "type": "input_audio",
                "input_audio": {
                    "data": encoded,
                    "format": fmt,
                },
            })
        elif attachment.mime_type == "application/pdf":
            # Extract text instead of base64-encoding -- raw PDF binary exceeds
            # the upstream gateway body limit (~1MB) and causes 502s.
            pdf_text = await asyncio.to_thread(
                _extract_pdf_text, attachment.data, attachment.file_name,
            )
            parts.append({"type": "text", "text": pdf_text})
        else:
            # VIDEO and other binary formats unsupported → text placeholder
            parts.append({
                "type": "text",
                "text": f"[{attachment.type.value}: {attachment.file_name}]",
            })

    return parts


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
        conversation_history: ConversationHistory | None = None,
        upstream_timeout: float = 120.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._sanitizer = sanitizer
        self._quarantine = quarantine_manager
        self._governance = governance
        self._upstream_url = upstream_url
        self._upstream_token = upstream_token
        self._response_scanner = response_scanner
        self._audit = audit_logger
        self._history = conversation_history
        self._upstream_timeout = upstream_timeout
        if http_client is not None:
            self._http_client = http_client
            self._owns_client = False
        else:
            self._http_client = httpx.AsyncClient(
                limits=httpx.Limits(
                    max_connections=10,
                    max_keepalive_connections=5,
                    keepalive_expiry=30,
                )
            )
            self._owns_client = True

    async def close(self) -> None:
        """Close the underlying HTTP client if we own it."""
        if self._owns_client:
            await self._http_client.aclose()

    async def relay(self, message: WebhookMessage) -> WebhookResponse:
        """Run the full relay pipeline for a webhook message."""

        # Stage 1: Body size check (NFR-7)
        # Attachment data is base64-encoded before forwarding, expanding it by ~33%.
        # Use the encoded size (ceil(n/3)*4) so the limit reflects what is actually sent.
        text_bytes = len(message.text.encode())
        attachment_bytes = sum((len(a.data) + 2) // 3 * 4 for a in message.attachments)
        if text_bytes + attachment_bytes > _MAX_BODY_SIZE:
            return WebhookResponse(
                text="Request body too large",
                status_code=413,
            )

        # Stage 2: Sanitize (prompt injection detection) — text only
        # Binary attachment content intentionally bypasses the text sanitizer;
        # the response scanner (Stage 5) still catches indirect injection in output.
        try:
            result = self._sanitizer.sanitize(message.text)
            clean_text = result.clean
        except PromptInjectionError:
            return WebhookResponse(
                text="Request rejected due to policy violation",
                status_code=400,
            )

        # Stage 2.5: Governance evaluation (text + attachment metadata, not binary)
        if self._governance:
            from src.governance.models import GovernanceDecision

            attachment_meta = [
                {
                    "type": a.type.value,
                    "mime_type": a.mime_type,
                    "file_name": a.file_name,
                    "file_size": a.file_size,
                }
                for a in message.attachments
            ]
            gov_body: dict[str, Any] = {
                "model": "default",
                "messages": [{"role": "user", "content": clean_text}],
                "metadata": {
                    "source": message.source,
                    "attachments": attachment_meta,
                    **message.metadata,
                },
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

        # Stage 4: Build messages with conversation history and forward to upstream
        # Session key is namespaced by source to prevent cross-channel ID collisions
        # (e.g. Telegram chat_id "123" vs WhatsApp phone "123").
        session_id = f"{message.source}:{message.sender_id}"

        # History stores lightweight text summaries (not base64 blobs) for
        # each attachment to prevent context growth across multi-turn sessions.
        # Filenames come from the Telegram payload and are user-controlled, so
        # each one must be sanitized before being appended to history_text.
        # On injection detection the filename is replaced with its safe type label.
        history_text = clean_text
        if message.attachments:
            safe_summaries: list[str] = []
            for a in message.attachments:
                try:
                    safe_name = self._sanitizer.sanitize(a.file_name).clean
                except PromptInjectionError:
                    safe_name = a.type.value  # fall back to enum label only
                safe_summaries.append(f"[{a.type.value}: {safe_name}]")
            summaries = " ".join(safe_summaries)
            history_text = f"{clean_text} {summaries}".strip()

        if self._history:
            self._history.append_user(session_id, history_text)
            history_messages: list[dict[str, Any]] = self._history.get(session_id)
        else:
            history_messages = [{"role": "user", "content": history_text}]

        # For the current (last) message, swap in the full multimodal content.
        # All prior history entries remain as text summaries.
        current_content = await _build_content_parts(clean_text, message.attachments)
        messages: list[dict[str, Any]] = history_messages[:-1] + [
            {"role": "user", "content": current_content},
        ]

        request_body = {
            "model": "default",
            "messages": messages,
            "metadata": {"source": message.source, **message.metadata},
        }
        upstream_response = await self._forward_to_upstream(request_body)

        # Update history with assistant reply (only on success)
        if self._history and upstream_response.status_code == 200:
            self._history.append_assistant(session_id, upstream_response.text)

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
                    "attachment_count": len(message.attachments),
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
            resp = await self._http_client.post(
                url, json=request_body, headers=headers, timeout=self._upstream_timeout,
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
        except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadError):
            return WebhookResponse(
                text="Upstream unavailable",
                status_code=502,
            )
