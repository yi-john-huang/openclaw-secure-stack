"""ASGI middleware for Bearer token authentication."""

from __future__ import annotations

import hmac

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from src.audit.logger import AuditLogger
from src.models import AuditEvent, AuditEventType, RiskLevel

# Paths that bypass authentication (exact match)
PUBLIC_PATHS = {"/health", "/healthz", "/ready"}

# Path prefixes that bypass authentication
PUBLIC_PREFIXES = ("/__openclaw__/canvas",)


class AuthMiddleware:
    """ASGI middleware that validates Bearer tokens using constant-time comparison."""

    def __init__(
        self,
        app: ASGIApp,
        token: str,
        audit_logger: AuditLogger | None = None,
        webhook_paths: frozenset[str] = frozenset(),
    ) -> None:
        self.app = app
        self._token = token.encode()
        self.audit_logger = audit_logger
        self._webhook_paths = webhook_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        path = request.url.path

        # Skip auth for public paths and registered webhook paths
        if path in PUBLIC_PATHS or path in self._webhook_paths or path.startswith(PUBLIC_PREFIXES):
            await self.app(scope, receive, send)
            return

        auth_header = request.headers.get("authorization", "")

        if not auth_header:
            response = JSONResponse({"error": "Authentication required"}, status_code=401)
            self._log_failure(request, "missing_token")
            await response(scope, receive, send)
            return

        if not auth_header.startswith("Bearer "):
            response = JSONResponse({"error": "Authentication required"}, status_code=401)
            self._log_failure(request, "invalid_format")
            await response(scope, receive, send)
            return

        provided_token = auth_header[7:].encode()

        if not hmac.compare_digest(provided_token, self._token):
            response = JSONResponse({"error": "Access denied"}, status_code=403)
            self._log_failure(request, "invalid_token")
            await response(scope, receive, send)
            return

        # Token valid — log and forward
        if self.audit_logger:
            self.audit_logger.log(AuditEvent(
                event_type=AuditEventType.AUTH_SUCCESS,
                source_ip=request.client.host if request.client else None,
                action=f"{request.method} {path}",
                result="success",
                risk_level=RiskLevel.INFO,
            ))

        await self.app(scope, receive, send)

    def _log_failure(self, request: Request, reason: str) -> None:
        if self.audit_logger:
            self.audit_logger.log(AuditEvent(
                event_type=AuditEventType.AUTH_FAILURE,
                source_ip=request.client.host if request.client else None,
                action=f"{request.method} {request.url.path}",
                result="failure",
                risk_level=RiskLevel.HIGH,
                details={"reason": reason},
            ))
