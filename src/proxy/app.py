"""FastAPI reverse proxy application."""

from __future__ import annotations

import json

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from src.audit.logger import AuditLogger
from src.proxy.auth_middleware import AuthMiddleware
from src.sanitizer.sanitizer import PromptInjectionError, PromptSanitizer


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
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                )
        except httpx.ConnectError:
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
