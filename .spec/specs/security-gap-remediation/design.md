# Technical Design: Security Gap Remediation

## Project: openclaw-secure-stack
**Version:** 1.1.0 → 1.2.0
**Architecture:** Sidecar Reverse-Proxy with Governance Layer
**Language:** Python 3.12+ (proxy), TypeScript (plugin hook)
**Approach:** Hybrid (Approach C) — Proxy integration + webhook relay + plugin defense-in-depth

---

## 1. Problem Statement

Architecture review of OpenClaw Secure Stack v1.1.0 identified four security gaps:

| Priority | Gap | Impact |
|----------|-----|--------|
| **P0** | Governance middleware built but not wired into proxy pipeline | Tool calls pass through without intent classification, policy validation, or approval gates |
| **P1** | Telegram/WhatsApp bot traffic bypasses proxy entirely | Bot users skip auth, sanitization, quarantine, governance, and audit |
| **P1** | Plugin hook only covers `tool_result_persist` | No pre-execution governance check at the OpenClaw layer |
| **P2** | Caddy routes directly to OpenClaw; network isolation incomplete | HTTPS edge bypasses all proxy security controls |

**Design goal:** Close all four gaps while preserving the sidecar architecture (no upstream OpenClaw modifications), maintaining fail-closed defaults, and keeping the defense-in-depth principle.

---

## 2. Architecture Overview

### 2.1 Current Pipeline (BEFORE)

```
Client --> Proxy:8080
           +-- AuthMiddleware (ASGI)
           +-- Quarantine check (skills/ only)
           +-- PromptSanitizer (request body)
           +-- httpx forward --> OpenClaw:3000
           +-- Response scan (indirect injection)
           +-- Audit log

Caddy:8443 --> OpenClaw:3000 (BYPASSES PROXY)

Telegram --> OpenClaw:3000 (BYPASSES PROXY)

Plugin: tool_result_persist only (advisory strip/flag)
```

### 2.2 Target Pipeline (AFTER)

```
Client --> Proxy:8080
           +-- AuthMiddleware (ASGI)
           +-- GovernanceMiddleware.evaluate()           <-- NEW
           |   +-- IntentClassifier
           |   +-- PlanGenerator
           |   +-- PolicyValidator
           |   +-- Decision: ALLOW / BLOCK / REQUIRE_APPROVAL
           +-- PromptSanitizer (request body)
           +-- Quarantine check
           +-- httpx forward --> OpenClaw:3000
           |   (with X-Governance-Plan-Id, X-Governance-Token headers)
           +-- Response scan (indirect injection)
           +-- Strip X-Governance-* headers from response  <-- SEC-D-01
           +-- Audit log (extended with governance events)

Caddy:8443 --> Proxy:8080 (FIXED)                       <-- CHANGED

Telegram --> Proxy:8080/webhook/telegram                 <-- NEW
WhatsApp --> Proxy:8080/webhook/whatsapp                 <-- NEW
           +-- Same full pipeline as above

Plugin: tool_result_persist + before_tool_call           <-- EXPANDED
           +-- Defense-in-depth governance check
```

### 2.3 Component Diagram

```
+----------------------------------------------------------------+
|                        PROXY SERVICE                            |
|                                                                 |
|  +--------------+  +------------------+  +-----------------+    |
|  | Auth         |  | Governance       |  | Webhook Relay   |    |
|  | Middleware   |->| Integration      |->| (Telegram/WA)   |    |
|  | (ASGI)      |  | (evaluate/retry) |  | (translate+fwd) |    |
|  +--------------+  +------------------+  +-----------------+    |
|         |                   |                    |              |
|         v                   v                    v              |
|  +--------------+  +------------------+  +-----------------+    |
|  | Sanitizer    |  | Governance API   |  | Rate Limiter    |    |
|  | (strip/      |  | (approve/reject/ |  | (webhook only)  |    |
|  |  reject)     |  |  cleanup)        |  | (60 req/min/IP) |    |
|  +--------------+  +------------------+  +-----------------+    |
|         |                                                       |
|         v                                                       |
|  +--------------+  +------------------+  +-----------------+    |
|  | Quarantine   |  | Response Scanner |  | Audit Logger    |    |
|  | Enforcer     |  | (indirect inj.)  |  | (JSONL+chain)   |    |
|  +--------------+  +------------------+  +-----------------+    |
|                                                                 |
+----------------------------------------------------------------+
         |                                       |
         v                                       v
+-------------------+                  +-------------------+
|    OpenClaw:3000  |                  |  Governance DB    |
|  (internal only)  |                  |  (SQLite)         |
+-------------------+                  +-------------------+
         |
         v
+-------------------+
| Plugin: prompt-   |
| guard (expanded)  |
| - tool_result_    |
|   persist         |
| - before_tool_    |
|   call (NEW)      |
+-------------------+
```

---

## 3. Component Designs

### 3.1 Component 1: Governance Integration into Proxy (P0)

#### 3.1.1 Files Modified

| File | Action | Description |
|------|--------|-------------|
| `src/proxy/app.py` | Modify | Wire GovernanceMiddleware into pipeline |
| `src/proxy/governance_routes.py` | Create | Approval API endpoints |
| `src/models.py` | Extend | Add governance audit event types |

#### 3.1.2 GovernanceMiddleware Instantiation

In `create_app_from_env()`:

```python
def create_app_from_env() -> FastAPI:
    # ... existing env vars ...
    governance_enabled = os.environ.get("GOVERNANCE_ENABLED", "true").lower() == "true"
    governance: GovernanceMiddleware | None = None

    if governance_enabled:
        governance = GovernanceMiddleware(
            db_path=os.environ.get("GOVERNANCE_DB_PATH", "data/governance.db"),
            secret=os.environ["GOVERNANCE_SECRET"],
            policy_path=os.environ.get("GOVERNANCE_POLICY_PATH", "config/governance-policies.json"),
            patterns_path=os.environ.get("GOVERNANCE_PATTERNS_PATH", "config/intent-patterns.json"),
            settings={
                "enabled": True,
                "approval": {
                    "allow_self_approval": os.environ.get("GOVERNANCE_ALLOW_SELF_APPROVAL", "true").lower() == "true",
                    "timeout_seconds": int(os.environ.get("GOVERNANCE_APPROVAL_TIMEOUT", "3600")),
                },
                "session": {"enabled": True},
                "enforcement": {"enabled": True, "token_ttl_seconds": 900},
            },
        )

    return create_app(
        upstream_url, token, sanitizer,
        audit_logger, response_scanner, quarantine_manager,
        governance,  # NEW parameter
    )
```

#### 3.1.3 Pipeline Integration

In the `proxy()` route handler, governance evaluation is inserted **after auth, before sanitization**:

```python
async def proxy(request: Request, path: str) -> Response:
    body = await request.body()
    body_json = None

    # Parse body for governance + sanitization
    if request.method in ("POST", "PUT", "PATCH") and body:
        try:
            body_json = json.loads(body)
        except json.JSONDecodeError:
            pass  # Not JSON, forward as-is

    # --- GOVERNANCE EVALUATION (NEW) ---
    if governance and body_json and _has_tool_calls(body_json):
        eval_result = _evaluate_governance(
            governance, body_json, body, request, audit_logger
        )
        if eval_result is not None:
            return eval_result  # BLOCK or REQUIRE_APPROVAL response

    # ... existing sanitization, quarantine, forwarding ...
```

#### 3.1.3A Tool Call Detection

```python
def _has_tool_calls(body: dict) -> bool:
    """Detect actual tool call invocations (not capability declarations)."""
    # Only match actual invocations, not `tools` (capability declarations)
    # SEC-D-03: Narrowed to tool_calls and function_call only
    return bool(body.get("tool_calls") or body.get("function_call"))
```

#### 3.1.3B Governance Evaluation with Retry Flow

```python
def _evaluate_governance(
    governance: GovernanceMiddleware,
    body_json: dict,
    raw_body: bytes,
    request: Request,
    audit_logger: AuditLogger | None,
) -> Response | None:
    """Evaluate request against governance. Returns Response if blocked, None if allowed."""

    # --- RETRY PATH (SEC-D-02) ---
    # If request includes existing plan credentials, verify instead of re-evaluating
    plan_id = request.headers.get("x-governance-plan-id")
    token = request.headers.get("x-governance-token")

    if plan_id and token:
        # Verify token is valid and not expired
        enforcement = governance.enforce(plan_id, token, ToolCall(name="__verify__", arguments={}))
        if not enforcement.allowed:
            return JSONResponse(
                {"error": "Governance token invalid or expired"},
                status_code=403,
            )
        # SEC-D-02: Verify request body hash matches stored plan
        import hashlib
        request_hash = hashlib.sha256(raw_body).hexdigest()
        # The enforce check above validates plan existence + token;
        # additionally verify the request hasn't been tampered with
        stored_plan = governance._store.get_plan(plan_id)
        if stored_plan and stored_plan.request_hash != request_hash:
            return JSONResponse(
                {"error": "Request body does not match approved plan"},
                status_code=403,
            )
        return None  # Token valid, hash matches — skip re-evaluation

    # --- FRESH EVALUATION PATH ---
    user_id = request.headers.get("x-user-id", request.client.host if request.client else "unknown")
    session_id = request.headers.get("x-governance-session")

    try:
        result = governance.evaluate(body_json, session_id, user_id)
    except Exception:
        # SEC-D-01 / FR-1.7: Fail closed on governance error
        if audit_logger:
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.GOVERNANCE_ERROR,
                action="evaluate",
                result="error",
                risk_level=RiskLevel.CRITICAL,
            ))
        return JSONResponse(
            {"error": "Governance evaluation failed"},
            status_code=500,
        )

    if result.decision == GovernanceDecision.BLOCK:
        if audit_logger:
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.GOVERNANCE_BLOCK,
                action="evaluate",
                result="blocked",
                risk_level=RiskLevel.HIGH,
                details={"violations": [v.message for v in result.violations]},
            ))
        return JSONResponse(
            {"error": "Request blocked by governance policy",
             "violations": [v.model_dump() for v in result.violations]},
            status_code=403,
        )

    if result.decision == GovernanceDecision.REQUIRE_APPROVAL:
        if audit_logger:
            audit_logger.log(AuditEvent(
                event_type=AuditEventType.GOVERNANCE_APPROVAL_REQUIRED,
                action="evaluate",
                result="approval_required",
                risk_level=RiskLevel.MEDIUM,
                details={"approval_id": result.approval_id, "plan_id": result.plan_id},
            ))
        return JSONResponse(
            {"status": "approval_required",
             "approval_id": result.approval_id,
             "plan_id": result.plan_id,
             "message": result.message},
            status_code=202,
        )

    # ALLOW — attach governance headers for downstream (plugin defense-in-depth)
    # These headers will be stripped from the response (SEC-D-01)
    return None  # Caller adds headers: X-Governance-Plan-Id, X-Governance-Token
```

#### 3.1.3C Response Header Stripping (SEC-D-01)

After receiving the upstream response, the proxy MUST strip governance headers:

```python
# In the response path, after receiving from OpenClaw:
fwd_headers = _strip_hop_by_hop(resp.headers)
# SEC-D-01: Strip governance headers from response to prevent token leaking
for h in list(fwd_headers):
    if h.lower().startswith("x-governance-"):
        del fwd_headers[h]
```

#### 3.1.4 New Audit Event Types

Add to `src/models.py`:

```python
class AuditEventType(str, Enum):
    # ... existing ...
    GOVERNANCE_ALLOW = "governance_allow"
    GOVERNANCE_BLOCK = "governance_block"
    GOVERNANCE_APPROVAL_REQUIRED = "governance_approval_required"
    GOVERNANCE_APPROVAL_GRANTED = "governance_approval_granted"
    GOVERNANCE_ERROR = "governance_error"
    WEBHOOK_RECEIVED = "webhook_received"
    WEBHOOK_RELAY = "webhook_relay"
    WEBHOOK_REPLAY_REJECTED = "webhook_replay_rejected"
```

#### 3.1.5 Governance API Endpoints

New file `src/proxy/governance_routes.py`:

```python
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/governance")

@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str, request: Request) -> JSONResponse:
    """Get approval request details."""
    ...

@router.post("/approvals/{approval_id}/approve")
async def approve(approval_id: str, request: Request) -> JSONResponse:
    """Approve a pending request, activate plan, return token."""
    ...

@router.post("/approvals/{approval_id}/reject")
async def reject(approval_id: str, request: Request) -> JSONResponse:
    """Reject a pending request."""
    ...

@router.post("/cleanup")
async def cleanup(request: Request) -> JSONResponse:
    """Remove expired plans, sessions, and approvals."""
    ...
```

All governance endpoints require Bearer token authentication (handled by existing AuthMiddleware).

---

### 3.2 Component 2: Webhook Relay for Telegram/WhatsApp (P1)

#### 3.2.1 Files Created

| File | Action | Description |
|------|--------|-------------|
| `src/webhook/__init__.py` | Create | Package init |
| `src/webhook/relay.py` | Create | Core WebhookRelay class |
| `src/webhook/telegram.py` | Create | Telegram protocol translation |
| `src/webhook/whatsapp.py` | Create | WhatsApp protocol translation |
| `src/webhook/rate_limiter.py` | Create | Webhook rate limiting |
| `src/webhook/replay_protection.py` | Create | Replay attack protection |

#### 3.2.2 Webhook Relay Architecture

```
Telegram/WhatsApp --> Proxy:/webhook/{platform}
                      +-- Rate limiter (60 req/min/IP)     (NFR-8)
                      +-- Body size check (max 10MB)        (NFR-7)
                      +-- Signature verification (HMAC)
                      +-- Replay protection                 (FR-2.7, FR-3.7)
                      +-- Message extraction
                      +-- Translate to OpenClaw format
                      +-- Call pipeline functions directly:  (SEC-D-04)
                      |   1. sanitizer.sanitize()
                      |   2. quarantine_manager.enforce()
                      |   3. governance.evaluate()
                      |   4. Forward to upstream via httpx
                      |   5. response_scanner.scan()
                      |   6. audit_logger.log()
                      +-- Translate response back
                      +-- Send via platform API (TLS verified, NFR-9)
```

**Design Decision (SEC-D-04):** The relay uses **Option 1 (direct function calls)** to call pipeline functions. This is preferred over Option 2 (self-request to localhost:8080) because:
- Avoids AuthMiddleware bypass complexity (webhook auth is signature-based, not Bearer token)
- Avoids infinite loop risk
- Explicit pipeline checklist ensures all stages are called
- Easier to test in isolation

#### 3.2.3 Telegram Webhook Handler

```python
class TelegramRelay:
    """Handles Telegram Bot API webhook updates."""

    def __init__(self, bot_token: str):
        self._bot_token = bot_token
        self._secret_hash = hashlib.sha256(bot_token.encode()).hexdigest()

    def verify_webhook(self, request: Request) -> bool:
        """Verify Telegram webhook using secret token header."""
        secret = request.headers.get("x-telegram-bot-api-secret-token", "")
        return hmac.compare_digest(secret, self._secret_hash)

    def extract_message(self, update: dict) -> tuple[int, str]:
        """Extract update_id and message text from Telegram update."""
        update_id = update["update_id"]
        message = update.get("message", {})
        text = message.get("text", "")
        return update_id, text

    def to_openclaw_request(self, text: str, chat_id: int) -> dict:
        """Translate Telegram message to OpenAI-compatible format."""
        return {
            "model": "default",
            "messages": [{"role": "user", "content": text}],
            "metadata": {"source": "telegram", "chat_id": chat_id},
        }

    async def send_response(self, chat_id: int, text: str) -> None:
        """Send response back via Telegram Bot API (with TLS verification)."""
        async with httpx.AsyncClient(verify=True) as client:  # NFR-9
            await client.post(
                f"https://api.telegram.org/bot{self._bot_token}/sendMessage",
                json={"chat_id": chat_id, "text": text},
            )
```

#### 3.2.4 WhatsApp Webhook Handler

```python
class WhatsAppRelay:
    """Handles WhatsApp Business API webhook updates."""

    def __init__(self, app_secret: str, verify_token: str, phone_number_id: str, access_token: str):
        self._app_secret = app_secret
        self._verify_token = verify_token
        self._phone_number_id = phone_number_id
        self._access_token = access_token

    def verify_signature(self, request: Request, body: bytes) -> bool:
        """Verify WhatsApp webhook HMAC-SHA256 signature."""
        signature = request.headers.get("x-hub-signature-256", "")
        if not signature.startswith("sha256="):
            return False
        expected = hmac.new(
            self._app_secret.encode(), body, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature[7:], expected)

    def handle_verification(self, params: dict) -> Response | None:
        """Handle Meta webhook verification challenge (GET)."""
        if params.get("hub.mode") == "subscribe":
            if params.get("hub.verify_token") == self._verify_token:
                return Response(content=params["hub.challenge"], media_type="text/plain")
            return JSONResponse({"error": "Invalid verify token"}, status_code=403)
        return None
```

#### 3.2.5 Replay Protection (SEC-D-05)

Storage: SQLite (reuse governance DB or separate table). State persists across restarts.

```python
class ReplayProtection:
    """Prevents webhook replay attacks."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._init_schema()

    def check_telegram(self, update_id: int) -> bool:
        """Returns True if update_id is new (not replayed)."""
        # Track last_update_id in SQLite
        # Reject if update_id <= last_update_id
        ...

    def check_whatsapp(self, message_timestamp: int) -> bool:
        """Returns True if message is within acceptable window."""
        # Reject if message_timestamp < now() - 5 minutes
        # Configurable via WHATSAPP_REPLAY_WINDOW_SECONDS (default: 300)
        ...
```

#### 3.2.6 Rate Limiter (SEC-D-06)

In-memory sliding window counter per source IP, applied as a FastAPI dependency on webhook routes only.

```python
class WebhookRateLimiter:
    """Sliding window rate limiter for webhook endpoints."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self._max_requests = max_requests
        self._window = window_seconds
        self._counters: dict[str, list[float]] = {}  # IP -> timestamps

    def check(self, source_ip: str) -> bool:
        """Returns True if request is within rate limit."""
        now = time.time()
        timestamps = self._counters.get(source_ip, [])
        # Remove entries outside window
        timestamps = [t for t in timestamps if now - t < self._window]
        if len(timestamps) >= self._max_requests:
            return False
        timestamps.append(now)
        self._counters[source_ip] = timestamps
        return True
```

#### 3.2.7 Caddy Fix

Update `docker/caddy/Caddyfile`:

```
# BEFORE (bypasses proxy):
# reverse_proxy openclaw:3000

# AFTER (routes through proxy):
reverse_proxy proxy:8080
```

#### 3.2.8 Docker Compose Changes for Webhooks

```yaml
proxy:
  environment:
    # ... existing ...
    - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-}
    - TELEGRAM_WEBHOOK_SECRET=${TELEGRAM_WEBHOOK_SECRET:-}
    - WHATSAPP_APP_SECRET=${WHATSAPP_APP_SECRET:-}
    - WHATSAPP_VERIFY_TOKEN=${WHATSAPP_VERIFY_TOKEN:-}
    - WHATSAPP_PHONE_NUMBER_ID=${WHATSAPP_PHONE_NUMBER_ID:-}
    - WHATSAPP_ACCESS_TOKEN=${WHATSAPP_ACCESS_TOKEN:-}
```

Webhook endpoints are only registered if the corresponding tokens are configured (NFR-2).

---

### 3.3 Component 3: Plugin Hook Expansion (P1)

#### 3.3.1 Files Modified

| File | Action | Description |
|------|--------|-------------|
| `plugins/prompt-guard/index.ts` | Modify | Add `before_tool_call` hook |

#### 3.3.2 Design

##### 3.3.2A Governance Token Check

```typescript
// NEW hook: before_tool_call
before_tool_call(toolCall: { name: string; arguments: object; context?: object }): { allow: boolean; reason?: string } {
    if (!enforcementEnabled) {
        return { allow: true };
    }

    const planId = getHeader("x-governance-plan-id");
    const token = getHeader("x-governance-token");

    // SEC-D-07: Presence-only check with documented trust boundary
    // Trust assumption: internal Docker network is trusted; only proxy sets these headers.
    // For v2: add shared-secret HMAC verification via GOVERNANCE_SECRET env var.
    if (planId && token) {
        return { allow: true };  // Proxy governance already evaluated
    }

    // No governance token — apply local policy fallback
    return this.applyLocalPolicy(toolCall);
}
```

**Trust Boundary Documentation (SEC-D-07):** The plugin trusts the presence of `X-Governance-*` headers because:
1. The internal Docker network (`internal: true`) has no published ports
2. Only the proxy can set these headers on requests to OpenClaw
3. OpenClaw does not expose port 3000 to the host
4. **v2 enhancement:** Add HMAC verification using shared `GOVERNANCE_SECRET`

##### 3.3.2B Quarantine Check

```typescript
private applyLocalPolicy(toolCall: { name: string; arguments: object }): { allow: boolean; reason?: string } {
    // Check quarantine list (loaded from shared config)
    if (quarantineList.includes(toolCall.name)) {
        logDetection({ ruleId: "quarantine", ruleName: "Quarantined Skill", action: "block", timestamp: new Date().toISOString() });
        return { allow: false, reason: `Skill '${toolCall.name}' is quarantined` };
    }

    // Check high-risk tool categories
    const HIGH_RISK_CATEGORIES = ["shell", "file_write", "network"];
    // ... local policy evaluation ...

    return { allow: true };
}
```

##### 3.3.2C Design Risk: `before_tool_call` Hook Availability

**Primary approach:** Use `before_tool_call` hook if available in OpenClaw's plugin API.

**Fallback strategy:** If `before_tool_call` is not available:
1. Wrap tool execution at the plugin layer by intercepting `tool_result_persist` and checking governance state *before* returning the result
2. While this is post-execution (not pre-execution), it can still prevent the result from entering the agent context
3. Log a warning that pre-execution blocking is not available

##### 3.3.2D Configuration

```typescript
const enforcementEnabled = process.env.PROMPT_GUARD_ENFORCEMENT !== "false";
const quarantineListPath = process.env.QUARANTINE_LIST_PATH || "/home/openclaw/config/quarantine-list.json";
```

---

### 3.4 Component 4: Network Policy Hardening (P2)

#### 3.4.1 Files Modified

| File | Action | Description |
|------|--------|-------------|
| `docker-compose.yml` | Modify | Network restrictions |
| `docker/caddy/Caddyfile` | Modify | Route through proxy |

#### 3.4.2 Docker Compose Network Changes

```yaml
caddy:
  depends_on:
    proxy:                    # CHANGED: depend on proxy, not openclaw
      condition: service_started
  networks:
    - internal

# OpenClaw stays on internal + egress (needs egress for LLM API calls)
# Proxy stays on internal only (correct — no direct external access)
```

#### 3.4.3 Port 3000 Access Restriction (SEC-D-09)

Docker's internal network allows all containers to communicate. Direct restriction of container-to-container traffic requires additional tooling (Calico, iptables). For v1:

**Mitigations in place:**
1. OpenClaw requires `OPENCLAW_GATEWAY_TOKEN` for API access — only the proxy knows this token
2. The internal network has no published ports (external access blocked)
3. Caddy is rerouted through proxy (no longer bypasses)

**Documented trust boundary:** The internal Docker network is a shared trust zone. For higher-security deployments, recommend Kubernetes NetworkPolicy or Docker network segmentation.

---

## 4. Data Flow Diagrams

### 4.1 HTTP Request Flow (with Governance)

```
Client
  |
  v
Proxy:8080
  |-- AuthMiddleware: verify Bearer token
  |-- Parse body, check _has_tool_calls()
  |-- IF has tool calls AND governance enabled:
  |   |-- Check for existing plan (X-Governance-Plan-Id + Token)
  |   |   |-- IF valid: verify token + request_hash (SEC-D-02), skip eval
  |   |   |-- IF missing/invalid: evaluate fresh
  |   |-- governance.evaluate(body, session_id, user_id)
  |   |   |-- BLOCK -> 403 + audit
  |   |   |-- REQUIRE_APPROVAL -> 202 + audit
  |   |   |-- ALLOW -> continue + attach token headers
  |   |   |-- ERROR -> 500 + audit (fail closed)
  |-- PromptSanitizer: strip/reject injection patterns
  |-- Quarantine: check skill block list
  |-- httpx forward to OpenClaw:3000 (with governance headers)
  |-- Response scanner: check for indirect injection
  |-- Strip X-Governance-* headers from response (SEC-D-01)
  |-- Audit log
  |
  v
Client (response)
```

### 4.2 Webhook Flow (Telegram Example)

```
Telegram API
  |
  v
Proxy:8080/webhook/telegram
  |-- Rate limiter (60 req/min/IP)
  |-- Body size check (max 10MB)
  |-- Verify X-Telegram-Bot-Api-Secret-Token (HMAC)
  |-- Replay protection: check update_id > last_processed
  |-- Extract message text + chat_id
  |-- Translate to OpenClaw format
  |-- Pipeline (direct function calls):
  |   |-- sanitizer.sanitize(text)
  |   |-- quarantine_manager.enforce(skill_name)
  |   |-- governance.evaluate(request, session_id, "telegram")
  |   |-- Forward to OpenClaw via httpx
  |   |-- response_scanner.scan(response)
  |   |-- audit_logger.log(source="telegram")
  |-- Translate response to Telegram format
  |-- Send via Telegram Bot API (TLS verified)
  |
  v
Telegram User
```

### 4.3 Approval Flow

```
Client --> POST /api/chat (with tool calls)
  |-- Governance: REQUIRE_APPROVAL
  |-- Response: 202 { approval_id, plan_id }

Approver --> GET /governance/approvals/{id}
  |-- View approval details + violations

Approver --> POST /governance/approvals/{id}/approve
  |-- Plan activated, token issued
  |-- Response: { plan_id, token }

Client --> POST /api/chat (retry with X-Governance-Plan-Id + X-Governance-Token)
  |-- Governance: verify token + request_hash (SEC-D-02)
  |-- Skip re-evaluation, proceed to pipeline
```

---

## 5. Environment Variables (New)

| Variable | Default | Description |
|----------|---------|-------------|
| `GOVERNANCE_ENABLED` | `true` | Enable/disable governance middleware |
| `GOVERNANCE_SECRET` | (required) | HMAC secret for governance tokens |
| `GOVERNANCE_DB_PATH` | `data/governance.db` | SQLite database path |
| `GOVERNANCE_POLICY_PATH` | `config/governance-policies.json` | Policy rules |
| `GOVERNANCE_PATTERNS_PATH` | `config/intent-patterns.json` | Intent patterns |
| `GOVERNANCE_APPROVAL_TIMEOUT` | `3600` | Approval timeout in seconds |
| `GOVERNANCE_ALLOW_SELF_APPROVAL` | `true` | Allow requester to self-approve |
| `TELEGRAM_BOT_TOKEN` | (optional) | Telegram bot token for webhook relay |
| `TELEGRAM_WEBHOOK_SECRET` | (optional) | Webhook verification secret |
| `WHATSAPP_APP_SECRET` | (optional) | WhatsApp HMAC verification secret |
| `WHATSAPP_VERIFY_TOKEN` | (optional) | Meta webhook verification token |
| `WHATSAPP_PHONE_NUMBER_ID` | (optional) | WhatsApp phone number ID |
| `WHATSAPP_ACCESS_TOKEN` | (optional) | WhatsApp API access token |
| `WHATSAPP_REPLAY_WINDOW_SECONDS` | `300` | Replay window for WhatsApp (seconds) |
| `WEBHOOK_RATE_LIMIT` | `60` | Max webhook requests per minute per IP |
| `WEBHOOK_MAX_BODY_SIZE` | `10485760` | Max webhook body size in bytes (10MB) |
| `PROMPT_GUARD_ENFORCEMENT` | `true` | Enable plugin-level enforcement |

---

## 6. Files Summary

| File | Action | Component |
|------|--------|-----------|
| `src/proxy/app.py` | Modify | Governance integration, header stripping |
| `src/proxy/governance_routes.py` | Create | Approval API endpoints |
| `src/webhook/__init__.py` | Create | Webhook package |
| `src/webhook/relay.py` | Create | Core relay logic |
| `src/webhook/telegram.py` | Create | Telegram protocol translation |
| `src/webhook/whatsapp.py` | Create | WhatsApp protocol translation |
| `src/webhook/rate_limiter.py` | Create | Webhook rate limiting |
| `src/webhook/replay_protection.py` | Create | Replay attack protection (SQLite) |
| `src/models.py` | Extend | New audit event types |
| `src/proxy/auth_middleware.py` | Minor | Extract user_id for governance |
| `plugins/prompt-guard/index.ts` | Modify | Add before_tool_call hook |
| `docker-compose.yml` | Modify | Network + env var changes |
| `docker/caddy/Caddyfile` | Modify | Route through proxy |

---

## 7. Security Design Principles

### 7.1 Fail-Closed Default

All governance errors result in request denial (HTTP 500). The system never fails open.

### 7.2 Defense-in-Depth Layers

1. Network isolation (Docker internal network)
2. TLS termination (Caddy, now via proxy)
3. Bearer token authentication (AuthMiddleware)
4. Webhook signature verification (HMAC-SHA256)
5. Replay attack protection (update_id / timestamp)
6. Rate limiting (webhook endpoints)
7. Governance evaluation (intent + policy + approval)
8. Prompt sanitization (injection detection)
9. Quarantine enforcement (skill blocking)
10. Response scanning (indirect injection)
11. Plugin-level defense (governance token + quarantine check)
12. Audit logging (all events, hash-chained)

### 7.3 Trust Boundaries

| Boundary | Trust Level | Justification |
|----------|-------------|---------------|
| External → Proxy | Untrusted | All traffic verified (Bearer / webhook signature) |
| Proxy → OpenClaw | Trusted (internal network) | Network isolation, gateway token, governance headers |
| Plugin → Governance headers | Presence-only (v1) | Internal network, proxy is sole header setter |
| OpenClaw → Egress | Controlled | DNS allowlist via CoreDNS |

---

## 8. Testing Strategy

### 8.1 Unit Tests

- Governance pipeline evaluation (mock components)
- Tool call detection (`_has_tool_calls`)
- Webhook signature verification (Telegram + WhatsApp)
- Protocol translation (Telegram ↔ OpenClaw, WhatsApp ↔ OpenClaw)
- Replay protection logic
- Rate limiter sliding window
- Response header stripping

### 8.2 Integration Tests

- Full proxy pipeline with governance enabled/disabled
- Webhook → relay → governance → upstream → response
- Approval flow: evaluate → 202 → approve → retry with token
- Governance error → fail-closed (500)

### 8.3 Security Tests (SEC-D-10)

- Token with modified plan_id (signature mismatch → reject)
- Token with future expiration (clock skew attack → reject)
- Token from different GOVERNANCE_SECRET (key confusion → reject)
- Request body hash mismatch during retry flow (SEC-D-02 → reject)
- Webhook replay attacks (old update_id / expired timestamp → reject)
- Webhook spoofing (invalid HMAC → reject)
- Rate limit exceeded → 429
- Oversized webhook body → 413

---

## 9. Security Review Findings Addressed

| Finding | Severity | Resolution |
|---------|----------|------------|
| SEC-D-01 | HIGH | Strip X-Governance-* headers from upstream responses (Section 3.1.3C) |
| SEC-D-02 | HIGH | Retry flow verifies token + request_hash match (Section 3.1.3B) |
| SEC-D-03 | MEDIUM | Narrowed _has_tool_calls to tool_calls/function_call only (Section 3.1.3A) |
| SEC-D-04 | MEDIUM | Relay uses direct function calls with explicit pipeline checklist (Section 3.2.2) |
| SEC-D-05 | MEDIUM | Replay protection uses SQLite, survives restarts (Section 3.2.5) |
| SEC-D-06 | MEDIUM | Rate limiter as in-memory sliding window on webhook routes (Section 3.2.6) |
| SEC-D-07 | MEDIUM | Presence-only with documented trust boundary, v2 adds HMAC (Section 3.3.2A) |
| SEC-D-09 | MEDIUM | Documented trust boundary + gateway token mitigation (Section 3.4.3) |
| SEC-D-08 | LOW | Patterns hardcoded, not user-configurable in v1 (Section 3.3.2B) |
| SEC-D-10 | LOW | Token manipulation vectors in security test plan (Section 8.3) |
