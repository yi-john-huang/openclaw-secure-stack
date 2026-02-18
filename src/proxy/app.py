"""FastAPI reverse proxy application."""

from __future__ import annotations

import contextlib
import json
import logging
import os
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from src.audit.logger import AuditLogger
from src.models import AuditEvent, AuditEventType, RiskLevel
from src.proxy.auth_middleware import AuthMiddleware
from src.proxy.governance_helpers import (
    evaluate_governance,
    has_tool_calls,
    strip_governance_headers,
)
from src.quarantine.manager import QuarantineBlockedError, QuarantineManager
from src.sanitizer.sanitizer import PromptInjectionError, PromptSanitizer
from src.scanner.scanner import (
    SkillScanner,
    load_pins_from_file,
    load_rules_from_file,
)

if TYPE_CHECKING:
    from src.governance.middleware import GovernanceMiddleware

# Maximum raw body size for webhook endpoints (defense-in-depth before JSON parse)
_MAX_WEBHOOK_BODY_SIZE = 10 * 1024 * 1024  # 10MB


def create_app_from_env() -> FastAPI:
    """Factory for uvicorn --factory: reads config from environment variables."""
    upstream_url = os.environ["UPSTREAM_URL"]
    token = os.environ["OPENCLAW_TOKEN"]
    prompt_rules = os.environ.get(
        "PROMPT_RULES_PATH", "config/prompt-rules.json",
    )
    indirect_rules = os.environ.get(
        "INDIRECT_RULES_PATH", "config/indirect-injection-rules.json",
    )
    audit_log = os.environ.get("AUDIT_LOG_PATH")
    sanitizer = PromptSanitizer(prompt_rules)
    response_scanner: PromptSanitizer | None = None
    if os.path.exists(indirect_rules):
        response_scanner = PromptSanitizer(indirect_rules)
    audit_logger = AuditLogger.from_env(audit_log) if audit_log else None
    quarantine_manager = _build_quarantine_manager(audit_logger)

    governance = _build_governance()

    # Webhook configuration (NFR-2: only register when tokens are set)
    telegram_bot_token = os.environ.get("TELEGRAM_BOT_TOKEN") or None
    whatsapp_config = _build_whatsapp_config()
    replay_db_path = os.environ.get("REPLAY_DB_PATH", "data/replay.db")
    webhook_rate_limit = int(os.environ.get("WEBHOOK_RATE_LIMIT", "60"))
    whatsapp_replay_window = int(os.environ.get("WHATSAPP_REPLAY_WINDOW_SECONDS", "300"))

    return create_app(
        upstream_url,
        token,
        sanitizer,
        audit_logger,
        response_scanner,
        quarantine_manager,
        governance,
        telegram_bot_token=telegram_bot_token,
        whatsapp_config=whatsapp_config,
        replay_db_path=replay_db_path,
        webhook_rate_limit=webhook_rate_limit,
        whatsapp_replay_window=whatsapp_replay_window,
    )


def _build_governance() -> GovernanceMiddleware | None:
    """Build GovernanceMiddleware from environment variables."""
    governance_enabled = os.environ.get("GOVERNANCE_ENABLED", "true").lower() == "true"
    if not governance_enabled:
        return None

    governance_secret = os.environ.get("GOVERNANCE_SECRET")
    if not governance_secret:
        logging.warning(
            "GOVERNANCE_ENABLED=true but GOVERNANCE_SECRET not set; "
            "disabling governance"
        )
        return None

    from src.governance.middleware import GovernanceMiddleware

    return GovernanceMiddleware(
        db_path=os.environ.get("GOVERNANCE_DB_PATH", "data/governance.db"),
        secret=governance_secret,
        policy_path=os.environ.get("GOVERNANCE_POLICY_PATH", "config/governance-policies.json"),
        patterns_path=os.environ.get("GOVERNANCE_PATTERNS_PATH", "config/intent-patterns.json"),
        settings={
            "enabled": True,
            "approval": {
                "allow_self_approval": os.environ.get(
                    "GOVERNANCE_ALLOW_SELF_APPROVAL", "true",
                ).lower() == "true",
                "timeout_seconds": int(os.environ.get("GOVERNANCE_APPROVAL_TIMEOUT", "3600")),
            },
            "session": {"enabled": True},
            "enforcement": {"enabled": True, "token_ttl_seconds": 900},
        },
    )


def _build_whatsapp_config() -> dict[str, str] | None:
    """Build WhatsApp config from environment variables, or None if not configured."""
    app_secret = os.environ.get("WHATSAPP_APP_SECRET")
    if not app_secret:
        return None
    return {
        "app_secret": app_secret,
        "verify_token": os.environ.get("WHATSAPP_VERIFY_TOKEN", ""),
        "phone_number_id": os.environ.get("WHATSAPP_PHONE_NUMBER_ID", ""),
        "access_token": os.environ.get("WHATSAPP_ACCESS_TOKEN", ""),
    }


def _build_quarantine_manager(audit_logger: AuditLogger | None) -> QuarantineManager:
    rules_path = os.environ.get("RULES_PATH", "config/scanner-rules.json")
    pins_path = os.environ.get("SKILL_PINS_PATH", "config/skill-pins.json")
    db_path = os.environ.get("QUARANTINE_DB_PATH", "data/quarantine.db")
    quarantine_dir = os.environ.get("QUARANTINE_DIR", "data/quarantine")

    try:
        rules = load_rules_from_file(rules_path)
    except Exception as exc:  # fall back to empty rules for runtime enforcement
        logging.warning("Failed to load scanner rules from %s: %s", rules_path, exc)
        rules = []

    pin_data, pins_loaded = load_pins_from_file(pins_path)
    scanner = SkillScanner(
        rules=rules,
        audit_logger=audit_logger,
        pin_data=pin_data,
        pins_loaded=pins_loaded,
    )
    return QuarantineManager(
        db_path=db_path,
        quarantine_dir=quarantine_dir,
        scanner=scanner,
        audit_logger=audit_logger,
    )


def create_app(
    upstream_url: str,
    token: str,
    sanitizer: PromptSanitizer,
    audit_logger: AuditLogger | None = None,
    response_scanner: PromptSanitizer | None = None,
    quarantine_manager: QuarantineManager | None = None,
    governance: GovernanceMiddleware | None = None,
    telegram_bot_token: str | None = None,
    whatsapp_config: dict[str, str] | None = None,
    replay_db_path: str = "data/replay.db",
    webhook_rate_limit: int = 60,
    whatsapp_replay_window: int = 300,
) -> FastAPI:
    """Create the proxy FastAPI app with auth, governance, and sanitization."""
    app = FastAPI(docs_url=None, redoc_url=None)

    # Register governance API routes if governance is enabled
    if governance is not None:
        from src.proxy.governance_routes import create_governance_router

        gov_router = create_governance_router(governance, audit_logger)
        app.include_router(gov_router)

    # Register webhook routes conditionally (NFR-2)
    webhook_paths = _register_webhook_routes(
        app=app,
        upstream_url=upstream_url,
        token=token,
        sanitizer=sanitizer,
        audit_logger=audit_logger,
        response_scanner=response_scanner,
        quarantine_manager=quarantine_manager,
        governance=governance,
        telegram_bot_token=telegram_bot_token,
        whatsapp_config=whatsapp_config,
        replay_db_path=replay_db_path,
        webhook_rate_limit=webhook_rate_limit,
        whatsapp_replay_window=whatsapp_replay_window,
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy(request: Request, path: str) -> Response:
        # Check quarantine enforcement for skill invocation paths
        if quarantine_manager and path.startswith("skills/"):
            parts = path.split("/")
            if len(parts) >= 2:
                skill_name = parts[1]
                try:
                    quarantine_manager.enforce_quarantine(skill_name)
                except QuarantineBlockedError:
                    return JSONResponse(
                        {"error": {"message": f"Skill '{skill_name}' is quarantined"}},
                        status_code=403,
                    )

        url = f"{upstream_url.rstrip('/')}/{path}"
        if request.url.query:
            url = f"{url}?{request.url.query}"
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("authorization", None)
        headers.pop("content-length", None)
        headers["authorization"] = f"Bearer {token}"

        body = await request.body()
        body_json = None
        is_streaming = False

        # Parse body for governance + sanitization
        if request.method in ("POST", "PUT", "PATCH") and body:
            with contextlib.suppress(json.JSONDecodeError):
                body_json = json.loads(body)

        # --- GOVERNANCE EVALUATION (inserted between auth and sanitization) ---
        if governance and body_json and has_tool_calls(body_json):
            gov_response, eval_result = evaluate_governance(
                governance, body_json, body, request, audit_logger,
                return_eval_result=True,
            )
            if gov_response is not None:
                return gov_response
            # ALLOW — attach governance headers for downstream
            if eval_result and eval_result.plan_id and eval_result.token:
                headers["x-governance-plan-id"] = eval_result.plan_id
                headers["x-governance-token"] = eval_result.token

        # Sanitize request body for POST/PUT/PATCH
        if body_json is not None:
            try:
                is_streaming = body_json.get("stream", False) is True
                body_json = _sanitize_body(body_json, sanitizer)
                body = json.dumps(body_json).encode()
            except PromptInjectionError:
                return JSONResponse(
                    {"error": "Request rejected due to policy violation"},
                    status_code=400,
                )

        timeout = 300.0 if is_streaming else 30.0

        if is_streaming:
            return await _stream_response(
                request.method, url, headers, body, timeout,
                response_scanner, audit_logger,
            )

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    content=body,
                    timeout=timeout,
                )
                fwd_headers = _strip_hop_by_hop(resp.headers)
                # SEC-D-01: Strip governance headers from response
                fwd_headers = strip_governance_headers(fwd_headers)
                if response_scanner:
                    findings = response_scanner.scan(resp.content.decode(errors="replace"))
                    if findings:
                        fwd_headers["X-Prompt-Guard"] = "injection-detected"
                        if audit_logger:
                            audit_logger.log(AuditEvent(
                                event_type=AuditEventType.INDIRECT_INJECTION,
                                action="response_scan",
                                result="detected",
                                risk_level=RiskLevel.HIGH,
                                details={"patterns": findings},
                            ))
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=fwd_headers,
                )
        except (httpx.ConnectError, httpx.TimeoutException):
            return JSONResponse({"error": "Upstream unavailable"}, status_code=502)

    # Add auth middleware (wraps the entire app)
    app.add_middleware(
        AuthMiddleware,
        token=token,
        audit_logger=audit_logger,
        webhook_paths=frozenset(webhook_paths),
    )

    return app


def _register_webhook_routes(
    app: FastAPI,
    upstream_url: str,
    token: str,
    sanitizer: PromptSanitizer,
    audit_logger: AuditLogger | None,
    response_scanner: PromptSanitizer | None,
    quarantine_manager: QuarantineManager | None,
    governance: GovernanceMiddleware | None,
    telegram_bot_token: str | None,
    whatsapp_config: dict[str, str] | None,
    replay_db_path: str,
    webhook_rate_limit: int,
    whatsapp_replay_window: int,
) -> set[str]:
    """Register webhook routes only when corresponding tokens are configured (NFR-2).

    Returns the set of registered webhook paths that should bypass Bearer auth.
    """
    registered_paths: set[str] = set()
    if not telegram_bot_token and not whatsapp_config:
        return registered_paths

    from src.webhook.history import ConversationHistory
    from src.webhook.rate_limiter import WebhookRateLimiter
    from src.webhook.relay import WebhookRelayPipeline
    from src.webhook.replay_protection import ReplayProtection

    rate_limiter = WebhookRateLimiter(max_requests=webhook_rate_limit, window_seconds=60)
    replay_protection = ReplayProtection(
        db_path=replay_db_path,
        whatsapp_window_seconds=whatsapp_replay_window,
    )
    pipeline = WebhookRelayPipeline(
        sanitizer=sanitizer,
        upstream_url=upstream_url,
        upstream_token=token,
        quarantine_manager=quarantine_manager,
        governance=governance,
        response_scanner=response_scanner,
        audit_logger=audit_logger,
        conversation_history=ConversationHistory(),
    )

    if telegram_bot_token:
        from src.webhook.telegram import TelegramRelay

        tg_relay = TelegramRelay(bot_token=telegram_bot_token)

        registered_paths.add("/webhook/telegram")

        @app.post("/webhook/telegram")
        async def telegram_webhook(request: Request) -> Response:
            # Rate limiting (NFR-8)
            source_ip = request.client.host if request.client else "unknown"
            if not rate_limiter.check(source_ip):
                if audit_logger:
                    audit_logger.log(AuditEvent(
                        event_type=AuditEventType.WEBHOOK_RATE_LIMITED,
                        action="telegram_webhook",
                        result="blocked",
                        risk_level=RiskLevel.MEDIUM,
                        source_ip=source_ip,
                        details={"source": "telegram"},
                    ))
                return JSONResponse({"error": "Rate limit exceeded"}, status_code=429)

            # Signature verification (FR-2.4, FR-2.6)
            headers = dict(request.headers)
            if not tg_relay.verify_webhook(headers):
                if audit_logger:
                    audit_logger.log(AuditEvent(
                        event_type=AuditEventType.WEBHOOK_SIGNATURE_FAILED,
                        action="telegram_webhook",
                        result="blocked",
                        risk_level=RiskLevel.HIGH,
                        source_ip=source_ip,
                        details={"source": "telegram"},
                    ))
                return JSONResponse({"error": "Invalid webhook signature"}, status_code=401)

            # Body size check before JSON parse (defense-in-depth)
            raw_body = await request.body()
            if len(raw_body) > _MAX_WEBHOOK_BODY_SIZE:
                return JSONResponse({"error": "Request body too large"}, status_code=413)
            body = json.loads(raw_body)

            # Replay protection (FR-2.7)
            update_id, text, chat_id = tg_relay.extract_message(body)
            if not replay_protection.check_telegram(update_id):
                if audit_logger:
                    audit_logger.log(AuditEvent(
                        event_type=AuditEventType.WEBHOOK_REPLAY_REJECTED,
                        action="telegram_webhook",
                        result="blocked",
                        risk_level=RiskLevel.HIGH,
                        source_ip=source_ip,
                        details={"source": "telegram", "update_id": update_id},
                    ))
                return JSONResponse({"error": "Replay detected"}, status_code=409)

            if not text:
                return JSONResponse({"status": "ok", "message": "No text to process"})

            # Audit: received
            if audit_logger:
                audit_logger.log(AuditEvent(
                    event_type=AuditEventType.WEBHOOK_RECEIVED,
                    action="telegram_webhook",
                    result="success",
                    risk_level=RiskLevel.INFO,
                    source_ip=source_ip,
                    details={"source": "telegram", "chat_id": chat_id},
                ))

            # Run pipeline
            from src.webhook.models import WebhookMessage

            msg = WebhookMessage(
                source="telegram",
                text=text,
                sender_id=str(chat_id),
                metadata={"chat_id": chat_id},
            )
            result = await pipeline.relay(msg)

            # Send response back via Telegram (fire and forget errors)
            if result.status_code == 200 and result.text:
                try:
                    await tg_relay.send_response(chat_id=chat_id, text=result.text)
                except Exception:
                    logging.exception("Failed to send Telegram response")

            return JSONResponse({"status": "ok"}, status_code=200)

    if whatsapp_config:
        from src.webhook.whatsapp import WhatsAppRelay

        wa_relay = WhatsAppRelay(
            app_secret=whatsapp_config["app_secret"],
            verify_token=whatsapp_config["verify_token"],
            phone_number_id=whatsapp_config["phone_number_id"],
            access_token=whatsapp_config["access_token"],
        )

        registered_paths.add("/webhook/whatsapp")

        @app.get("/webhook/whatsapp")
        async def whatsapp_verification(request: Request) -> Response:
            """Handle Meta webhook verification challenge (FR-3.6)."""
            params = dict(request.query_params)
            result = wa_relay.handle_verification(params)
            if result is None:
                return JSONResponse({"error": "Invalid mode"}, status_code=400)
            if result["status_code"] == 200:
                return Response(
                    content=result["content"],
                    media_type="text/plain",
                )
            return JSONResponse(
                {"error": result.get("error", "Verification failed")},
                status_code=result["status_code"],
            )

        @app.post("/webhook/whatsapp")
        async def whatsapp_webhook(request: Request) -> Response:
            # Rate limiting (NFR-8)
            source_ip = request.client.host if request.client else "unknown"
            if not rate_limiter.check(source_ip):
                if audit_logger:
                    audit_logger.log(AuditEvent(
                        event_type=AuditEventType.WEBHOOK_RATE_LIMITED,
                        action="whatsapp_webhook",
                        result="blocked",
                        risk_level=RiskLevel.MEDIUM,
                        source_ip=source_ip,
                        details={"source": "whatsapp"},
                    ))
                return JSONResponse({"error": "Rate limit exceeded"}, status_code=429)

            # Signature verification (FR-3.4, FR-3.5)
            raw_body = await request.body()
            headers = dict(request.headers)
            if not wa_relay.verify_signature(headers, raw_body):
                if audit_logger:
                    audit_logger.log(AuditEvent(
                        event_type=AuditEventType.WEBHOOK_SIGNATURE_FAILED,
                        action="whatsapp_webhook",
                        result="blocked",
                        risk_level=RiskLevel.HIGH,
                        source_ip=source_ip,
                        details={"source": "whatsapp"},
                    ))
                return JSONResponse({"error": "Invalid webhook signature"}, status_code=401)

            # Body size check before JSON parse (defense-in-depth)
            if len(raw_body) > _MAX_WEBHOOK_BODY_SIZE:
                return JSONResponse({"error": "Request body too large"}, status_code=413)
            payload = json.loads(raw_body)
            messages = wa_relay.extract_messages(payload)

            if not messages:
                return JSONResponse({"status": "ok", "message": "No messages to process"})

            for msg_data in messages:
                # Replay protection (FR-3.7)
                if not replay_protection.check_whatsapp(msg_data["timestamp"]):
                    if audit_logger:
                        audit_logger.log(AuditEvent(
                            event_type=AuditEventType.WEBHOOK_REPLAY_REJECTED,
                            action="whatsapp_webhook",
                            result="blocked",
                            risk_level=RiskLevel.HIGH,
                            source_ip=source_ip,
                            details={
                                "source": "whatsapp",
                                "timestamp": msg_data["timestamp"],
                            },
                        ))
                    return JSONResponse({"error": "Replay detected"}, status_code=409)

                if not msg_data["text"]:
                    continue

                # Audit: received
                if audit_logger:
                    audit_logger.log(AuditEvent(
                        event_type=AuditEventType.WEBHOOK_RECEIVED,
                        action="whatsapp_webhook",
                        result="success",
                        risk_level=RiskLevel.INFO,
                        source_ip=source_ip,
                        details={"source": "whatsapp"},
                    ))

                # Run pipeline
                from src.webhook.models import WebhookMessage

                wa_msg = WebhookMessage(
                    source="whatsapp",
                    text=msg_data["text"],
                    sender_id=msg_data["sender_phone"],
                    metadata={"sender_phone": msg_data["sender_phone"]},
                )
                result = await pipeline.relay(wa_msg)

                # Send response back via WhatsApp
                if result.status_code == 200 and result.text:
                    try:
                        await wa_relay.send_response(
                            recipient_phone=msg_data["sender_phone"],
                            text=result.text,
                        )
                    except Exception:
                        logging.exception("Failed to send WhatsApp response")

            return JSONResponse({"status": "ok"}, status_code=200)

    return registered_paths


def _strip_hop_by_hop(headers: httpx.Headers) -> dict[str, str]:
    return {
        k: v for k, v in headers.items()
        if k.lower() not in (
            "content-length", "transfer-encoding",
            "connection", "keep-alive",
        )
    }


async def _stream_response(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
    response_scanner: PromptSanitizer | None = None,
    audit_logger: AuditLogger | None = None,
) -> StreamingResponse | JSONResponse:
    client = httpx.AsyncClient()
    try:
        req = client.build_request(method, url, headers=headers, content=body)
        resp = await client.send(req, stream=True, timeout=timeout)
    except (httpx.ConnectError, httpx.TimeoutException):
        await client.aclose()
        return JSONResponse({"error": "Upstream unavailable"}, status_code=502)

    fwd_headers = _strip_hop_by_hop(resp.headers)
    # SEC-D-01: Strip governance headers from streaming response too
    fwd_headers = strip_governance_headers(fwd_headers)
    injection_logged = False

    async def body_iterator() -> AsyncIterator[bytes]:
        nonlocal injection_logged
        try:
            async for chunk in resp.aiter_bytes():
                if response_scanner and not injection_logged:
                    findings = response_scanner.scan(chunk.decode(errors="replace"))
                    if findings:
                        injection_logged = True
                        if audit_logger:
                            audit_logger.log(AuditEvent(
                                event_type=AuditEventType.INDIRECT_INJECTION,
                                action="response_scan_stream",
                                result="detected",
                                risk_level=RiskLevel.HIGH,
                                details={"patterns": findings},
                            ))
                yield chunk
        finally:
            await resp.aclose()
            await client.aclose()

    # For streaming, we can't retroactively add headers after iteration starts.
    # The header is set optimistically if a scanner is configured.
    # Actual detection is logged via audit events.
    return StreamingResponse(
        content=body_iterator(),
        status_code=resp.status_code,
        headers=fwd_headers,
        media_type="text/event-stream",
    )


def _sanitize_body(data: object, sanitizer: PromptSanitizer) -> object:
    """Recursively sanitize string values in request body."""
    if isinstance(data, str):
        result = sanitizer.sanitize(data)
        return result.clean
    if isinstance(data, dict):
        return {k: _sanitize_body(v, sanitizer) for k, v in data.items()}
    if isinstance(data, list):
        return [_sanitize_body(item, sanitizer) for item in data]
    return data
