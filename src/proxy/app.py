"""FastAPI reverse proxy application."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import AsyncIterator

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from src.audit.logger import AuditLogger
from src.models import AuditEvent, AuditEventType, RiskLevel
from src.proxy.auth_middleware import AuthMiddleware
from src.quarantine.manager import QuarantineBlockedError, QuarantineManager
from src.scanner.scanner import SkillScanner, load_pins_from_file, load_rules_from_file
from src.sanitizer.sanitizer import PromptInjectionError, PromptSanitizer


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
    return create_app(
        upstream_url,
        token,
        sanitizer,
        audit_logger,
        response_scanner,
        quarantine_manager,
    )


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
) -> FastAPI:
    """Create the proxy FastAPI app with auth and sanitization."""
    app = FastAPI(docs_url=None, redoc_url=None)

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
        is_streaming = False

        # Sanitize request body for POST/PUT/PATCH
        if request.method in ("POST", "PUT", "PATCH") and body:
            try:
                body_json = json.loads(body)
                is_streaming = body_json.get("stream", False) is True
                # Sanitize string fields that may contain user input
                body_json = _sanitize_body(body_json, sanitizer)
                body = json.dumps(body_json).encode()
            except (json.JSONDecodeError, PromptInjectionError) as e:
                if isinstance(e, PromptInjectionError):
                    return JSONResponse(
                        {"error": "Request rejected due to policy violation"},
                        status_code=400,
                    )
                # Not JSON — forward as-is

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
    app.add_middleware(AuthMiddleware, token=token, audit_logger=audit_logger)

    return app


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
