"""FastAPI reverse proxy application."""

from __future__ import annotations

import json
import os

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from src.audit.logger import AuditLogger
from src.proxy.auth_middleware import AuthMiddleware
from src.sanitizer.sanitizer import PromptInjectionError, PromptSanitizer


def create_app_from_env() -> FastAPI:
    """Factory for uvicorn --factory: reads config from environment variables."""
    upstream_url = os.environ["UPSTREAM_URL"]
    token = os.environ["OPENCLAW_TOKEN"]
    prompt_rules = os.environ.get(
        "PROMPT_RULES_PATH", "config/prompt-rules.json",
    )
    audit_log = os.environ.get("AUDIT_LOG_PATH")
    sanitizer = PromptSanitizer(prompt_rules)
    audit_logger = AuditLogger(audit_log) if audit_log else None
    return create_app(upstream_url, token, sanitizer, audit_logger)


def create_app(
    upstream_url: str,
    token: str,
    sanitizer: PromptSanitizer,
    audit_logger: AuditLogger | None = None,
) -> FastAPI:
    """Create the proxy FastAPI app with auth and sanitization."""
    app = FastAPI(docs_url=None, redoc_url=None)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy(request: Request, path: str) -> Response:
        url = f"{upstream_url.rstrip('/')}/{path}"
        if request.url.query:
            url = f"{url}?{request.url.query}"
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("authorization", None)

        body = await request.body()

        # Sanitize request body for POST/PUT/PATCH
        if request.method in ("POST", "PUT", "PATCH") and body:
            try:
                body_json = json.loads(body)
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

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    content=body,
                    timeout=30.0,
                )
                # Strip hop-by-hop headers and content-length/transfer-encoding
                # so Starlette sets the correct content-length for the actual body.
                fwd_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in (
                        "content-length", "transfer-encoding",
                        "connection", "keep-alive",
                    )
                }
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
