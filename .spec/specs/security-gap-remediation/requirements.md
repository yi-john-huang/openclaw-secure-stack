# Requirements: Security Gap Remediation

## Overview

This specification addresses critical security coverage gaps identified in the OpenClaw Secure Stack v1.1.0 architecture review. The current reverse proxy sidecar only protects HTTP traffic on port 8080. Telegram/WhatsApp bot messages, handled internally by OpenClaw, bypass all security controls. Additionally, the governance layer is architecturally complete but not integrated into the proxy pipeline. Caddy routes HTTPS traffic directly to OpenClaw, bypassing the proxy entirely.

**Primary Goal:** Achieve uniform security coverage across all client paths (HTTP, Telegram, WhatsApp) through a hybrid approach combining proxy-level governance integration, webhook relay for bot traffic, and execution-layer defense-in-depth.

**Target Users:**
- Platform engineers deploying OpenClaw with security hardening
- Security teams auditing AI agent deployments
- Organizations using OpenClaw with Telegram/WhatsApp bot integrations

---

## Functional Requirements

### FR-1: Governance Middleware Integration (P0)

**Objective:** As a platform engineer, I want all HTTP requests through the proxy to undergo governance evaluation, so that high-risk tool calls require policy validation and optional human approval before execution.

**EARS Specification:**

**FR-1.1:** WHEN an HTTP request containing tool calls arrives at the proxy
THEN the system SHALL evaluate the request against governance policies before forwarding to OpenClaw

**FR-1.2:** WHEN governance evaluation returns a BLOCK decision
THEN the system SHALL reject the request with HTTP 403 and log the policy violation to the audit trail

**FR-1.3:** WHEN governance evaluation returns a REQUIRE_APPROVAL decision
THEN the system SHALL return HTTP 202 with an approval_id and hold the request until approved, rejected, or timed out

**FR-1.4:** WHEN governance evaluation returns an ALLOW decision
THEN the system SHALL attach the governance token to the forwarded request and log the decision to the audit trail

**FR-1.5:** WHERE governance is disabled via configuration
THE system SHALL forward requests without governance checks, preserving existing proxy behavior

**FR-1.6:** WHEN a governance approval is submitted via the approval endpoint
THEN the system SHALL activate the corresponding plan and return the execution token

**FR-1.7:** IF governance evaluation fails due to an internal error
THEN the system SHALL reject the request with HTTP 500 and log the error, rather than silently allowing it

**FR-1.8:** The governance token SHALL be cryptographically bound to the plan ID, have a maximum TTL of 900 seconds, and be verified using HMAC-SHA256 with constant-time comparison

**Acceptance Criteria:**
1. All POST/PUT/PATCH requests with tool calls pass through governance evaluation (GET requests are excluded by design as they do not contain tool calls)
2. Governance can be enabled/disabled via `GOVERNANCE_ENABLED` environment variable
3. Existing proxy behavior (auth, sanitizer, quarantine, response scanner) is unchanged
4. Governance evaluation adds less than 50ms latency for ALLOW decisions
5. Blocked requests produce an audit event with `event_type=GOVERNANCE_BLOCK`
6. Approval requests produce an audit event with `event_type=GOVERNANCE_APPROVAL_REQUIRED`
7. Governance tokens are plan-bound, time-limited (900s TTL), and verified with constant-time HMAC-SHA256

---

### FR-2: Telegram Webhook Relay (P1)

**Objective:** As a security team member, I want Telegram bot messages to be routed through the proxy's security pipeline, so that bot users receive the same security protections as HTTP API users.

**EARS Specification:**

**FR-2.1:** WHEN a Telegram webhook update arrives at the proxy's `/webhook/telegram` endpoint
THEN the system SHALL translate the Telegram message into an OpenAI-compatible chat completion request

**FR-2.2:** WHEN a translated Telegram request is created
THEN the system SHALL route it through the full security pipeline (sanitizer, quarantine, governance, response scanner, audit logger)

**FR-2.3:** WHEN a response is received from OpenClaw for a Telegram request
THEN the system SHALL translate the response back to Telegram Bot API format and send it via the Telegram API

**FR-2.4:** WHEN a Telegram webhook arrives with an invalid or missing verification token
THEN the system SHALL reject the request with HTTP 401 and log the failed attempt

**FR-2.5:** IF the Telegram Bot API returns an error when sending the response
THEN the system SHALL log the error to the audit trail and retry up to 3 times with exponential backoff

**FR-2.6:** The system SHALL validate incoming Telegram webhooks using the bot token secret hash to prevent spoofing

**FR-2.7:** The system SHALL track Telegram `update_id` values and reject any webhook update with an `update_id` less than or equal to the last processed value, to prevent replay attacks

**FR-2.8:** IF the Telegram Bot API returns an error when sending the response
THEN the system SHALL retry only on 429 (rate limit) and 5xx (server error) status codes, with exponential backoff capped at 30 seconds

**Acceptance Criteria:**
1. Telegram messages are visible in the audit log with `source=telegram`
2. Prompt injection patterns in Telegram messages are detected and handled
3. Quarantined skills cannot be invoked via Telegram
4. Governance policies apply to Telegram-originating tool calls
5. Response scanner checks OpenClaw responses before they reach Telegram users
6. Telegram webhook verification rejects forged requests
7. Replayed webhook updates (duplicate or old `update_id`) are rejected with HTTP 409

---

### FR-3: WhatsApp Webhook Relay (P1)

**Objective:** As a security team member, I want WhatsApp bot messages to be routed through the proxy's security pipeline, so that WhatsApp users receive the same security protections.

**EARS Specification:**

**FR-3.1:** WHEN a WhatsApp Business API webhook arrives at the proxy's `/webhook/whatsapp` endpoint
THEN the system SHALL translate the WhatsApp message into an OpenAI-compatible chat completion request

**FR-3.2:** WHEN a translated WhatsApp request is created
THEN the system SHALL route it through the full security pipeline (sanitizer, quarantine, governance, response scanner, audit logger)

**FR-3.3:** WHEN a response is received from OpenClaw for a WhatsApp request
THEN the system SHALL translate the response back to WhatsApp Business API format and send it via the WhatsApp API

**FR-3.4:** WHEN a WhatsApp webhook arrives without valid HMAC signature verification
THEN the system SHALL reject the request with HTTP 401 and log the failed attempt

**FR-3.5:** The system SHALL verify WhatsApp webhook signatures using the `WHATSAPP_APP_SECRET` to prevent spoofing

**FR-3.6:** WHEN a WhatsApp webhook verification challenge is received (GET request with `hub.mode=subscribe`)
THEN the system SHALL respond with the `hub.challenge` value if the verify token matches

**FR-3.7:** The system SHALL reject WhatsApp webhook payloads older than a configurable window (default: 5 minutes) based on the message timestamp to mitigate replay attacks

**FR-3.8:** IF the WhatsApp API returns an error when sending the response
THEN the system SHALL retry only on 429 and 5xx status codes, with exponential backoff capped at 30 seconds

**Acceptance Criteria:**
1. WhatsApp messages are visible in the audit log with `source=whatsapp`
2. All security controls (sanitizer, quarantine, governance, response scanner) apply to WhatsApp traffic
3. WhatsApp webhook HMAC signature verification rejects forged requests
4. WhatsApp webhook verification handshake works correctly
5. Response format is compatible with WhatsApp Business API specifications
6. Replayed webhook payloads (outside the timestamp window) are rejected with HTTP 409

---

### FR-4: Plugin Hook Expansion for Defense-in-Depth (P1)

**Objective:** As a platform engineer, I want the OpenClaw plugin hook to perform auth and quarantine checks at the execution layer, so that any traffic bypassing the proxy still encounters security controls.

**EARS Specification:**

**FR-4.1:** WHEN a tool call is about to execute inside OpenClaw
THEN the plugin hook SHALL verify that a valid governance token is present in the execution context

**FR-4.2:** WHEN a tool call references a quarantined skill
THEN the plugin hook SHALL block execution and log the attempt

**FR-4.3:** IF a tool call executes without a governance token and enforcement is enabled
THEN the plugin hook SHALL block the execution and log a security warning

**FR-4.4:** WHERE plugin-level enforcement is disabled via configuration
THE plugin hook SHALL continue to perform only indirect injection scanning (current behavior)

**FR-4.5:** The plugin hook SHALL log all enforcement actions to the prompt-guard detection log

**Acceptance Criteria:**
1. Plugin hook checks for governance token presence before tool execution
2. Quarantine list is loaded from a shared configuration accessible to the plugin
3. Enforcement can be toggled via `PROMPT_GUARD_ENFORCEMENT` environment variable
4. Current indirect injection scanning behavior is preserved
5. Plugin hook operates independently from the proxy (defense-in-depth principle)

---

### FR-5: Network Policy Hardening (P2)

**Objective:** As a DevOps engineer, I want OpenClaw's outbound traffic restricted and Caddy routed through the proxy, so that network-level isolation limits the blast radius.

**EARS Specification:**

**FR-5.1:** WHILE OpenClaw is running
THE Docker network configuration SHALL restrict OpenClaw's outbound DNS to only the egress-dns service (172.28.0.10)

**FR-5.2:** The Caddy reverse proxy SHALL route HTTPS traffic through the security proxy (port 8080) rather than directly to OpenClaw (port 3000)

**FR-5.3:** WHEN OpenClaw attempts to resolve a domain not in the allowlist
THEN egress-dns SHALL return NXDOMAIN

**FR-5.4:** The Docker Compose configuration SHALL prevent the OpenClaw container from initiating connections to hosts outside the internal and egress networks

**Acceptance Criteria:**
1. OpenClaw cannot resolve domains not in `config/allowlist.db`
2. Caddy routes through proxy, not directly to OpenClaw
3. Existing egress allowlist behavior is preserved
4. Health check and proxy-to-OpenClaw communication are unaffected

---

### FR-6: Governance API Endpoints (P0)

**Objective:** As a platform engineer, I want API endpoints to manage governance approvals and inspect governance state, so that human-in-the-loop workflows are supported.

**EARS Specification:**

**FR-6.1:** WHEN a GET request is made to `/governance/approvals/{approval_id}`
THEN the system SHALL return the approval request details

**FR-6.2:** WHEN a POST request is made to `/governance/approvals/{approval_id}/approve`
THEN the system SHALL approve the pending request and return the execution token

**FR-6.3:** WHEN a POST request is made to `/governance/approvals/{approval_id}/reject`
THEN the system SHALL reject the pending request and log the rejection

**FR-6.4:** WHEN a POST request is made to `/governance/cleanup`
THEN the system SHALL remove expired plans, sessions, and approvals

**Acceptance Criteria:**
1. All governance endpoints require Bearer token authentication
2. Approval/rejection actions produce audit events
3. Expired approvals cannot be approved
4. Self-approval follows the configured `allow_self_approval` setting

---

## Non-Functional Requirements

### NFR-1: Performance

The proxy SHALL add no more than 50ms latency for governance ALLOW decisions over the baseline (no-governance) path.

WHILE processing webhook relay requests
THE system SHALL complete protocol translation within 100ms excluding upstream response time.

### NFR-2: Backward Compatibility

The system SHALL preserve all existing proxy behavior when governance is disabled.

IF no webhook environment variables are configured (TELEGRAM_BOT_TOKEN, WHATSAPP_APP_SECRET)
THEN the system SHALL not register webhook endpoints.

### NFR-3: Security

The system SHALL use constant-time comparison for all token verification operations.

The system SHALL never log sensitive tokens, bot API keys, or webhook secrets to the audit trail.

The system SHALL validate all webhook signatures before processing payloads.

### NFR-4: Reliability

IF the governance database is unavailable
THEN the system SHALL fail closed (reject requests) rather than fail open.

WHEN the proxy starts up
THE system SHALL initialize the governance database schema automatically.

### NFR-5: Observability

The system SHALL produce audit events for all governance decisions, webhook translations, and plugin enforcement actions.

WHILE the system is running
THE audit log SHALL maintain hash chain integrity across all new event types.

### NFR-6: Test Coverage

All new code SHALL maintain the project's 90% coverage threshold.

All security-critical paths SHALL have 100% branch coverage.

### NFR-7: Input Size Limits

The system SHALL enforce maximum request body size limits on webhook endpoints (default: 10MB) to prevent resource exhaustion attacks.

### NFR-8: Webhook Rate Limiting

The system SHALL enforce rate limiting on webhook endpoints (default: 60 requests per minute per source IP) to prevent denial-of-service attacks.

### NFR-9: Outbound TLS Verification

The system SHALL verify TLS certificates for all outbound API calls to Telegram and WhatsApp services.

---

## Constraints

1. **No upstream modifications:** OpenClaw source code cannot be modified; only the proxy, plugin hooks, and Docker configuration are in scope.
2. **Python 3.12+:** All proxy-side code must use Python 3.12+ with strict mypy type checking.
3. **TypeScript plugin:** Plugin hook code must be TypeScript compatible with OpenClaw's plugin API.
4. **Docker read-only filesystem:** All containers run with `read_only: true`; persistent state uses named volumes or tmpfs.
5. **Non-root execution:** All containers run as UID 65534 (nobody) with `cap_drop: ALL`.

## Assumptions

1. **[DESIGN RISK]** OpenClaw's plugin hook system supports `tool_result_persist` and potentially `before_tool_call` hooks. FR-4.1 and FR-4.3 require pre-execution interception. If `before_tool_call` is unavailable, a fallback strategy (e.g., wrapping tool execution at the plugin layer) must be designed.
2. Telegram Bot API and WhatsApp Business API webhook formats are stable.
3. The governance SQLite database can be shared between the proxy service and governance middleware via a named volume.
4. Webhook secrets (TELEGRAM_BOT_TOKEN, WHATSAPP_APP_SECRET) are provided via environment variables.
5. The existing governance module (`src/governance/`) is functionally correct and tested.

---

## Client Path Coverage Matrix (Target State)

| Client Path | Auth | Sanitizer | Quarantine | Governance | Response Scan | Audit |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| HTTP via proxy (port 8080) | Yes | Yes | Yes | **Yes** | Yes | Yes |
| HTTPS via Caddy (port 8443) | Yes | Yes | Yes | **Yes** | Yes | Yes |
| Telegram via webhook relay | Webhook verify | Yes | Yes | **Yes** | Yes | Yes |
| WhatsApp via webhook relay | HMAC verify | Yes | Yes | **Yes** | Yes | Yes |
| Plugin hook (defense-in-depth) | Token verify | -- | Yes | Token verify | -- | Yes |

**Target:** All "No" entries from the current-state matrix are resolved to "Yes" or equivalent protection.
