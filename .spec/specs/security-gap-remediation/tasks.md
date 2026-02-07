# TDD Task Breakdown: Security Gap Remediation

## Project: openclaw-secure-stack
**Feature:** security-gap-remediation
**Methodology:** Test-Driven Development (Red-Green-Refactor)
**Test Framework:** pytest (Python), vitest/jest (TypeScript)

---

## Task Dependencies

```
Phase 1: Foundation (no dependencies)
  T1.1 → T1.2 → T1.3

Phase 2: Governance Integration (P0) — depends on Phase 1
  T2.1 → T2.2 → T2.3 → T2.4 → T2.5

Phase 3: Webhook Relay (P1) — depends on Phase 1
  T3.1 → T3.2 → T3.3 → T3.4 → T3.5 → T3.6 → T3.7

Phase 4: Plugin Hook Expansion (P1) — depends on Phase 2
  T4.1 → T4.2 → T4.3

Phase 5: Network Hardening (P2) — no code deps, can run in parallel
  T5.1 → T5.2

Phase 6: Integration & Security Tests — depends on Phases 2-5
  T6.1 → T6.2 → T6.3
```

---

## Phase 1: Foundation — Shared Models & Utilities

### T1.1: Add Governance Audit Event Types to `src/models.py`

**Priority:** P0
**Complexity:** Low
**Files Modified:** `src/models.py`
**Files Tested:** `tests/unit/test_models.py`

**RED — Write Failing Tests:**

```python
# tests/unit/test_models.py — add to existing file

def test_governance_audit_event_types_exist():
    """All governance audit event types are defined."""
    assert AuditEventType.GOVERNANCE_ALLOW == "governance_allow"
    assert AuditEventType.GOVERNANCE_BLOCK == "governance_block"
    assert AuditEventType.GOVERNANCE_APPROVAL_REQUIRED == "governance_approval_required"
    assert AuditEventType.GOVERNANCE_APPROVAL_GRANTED == "governance_approval_granted"
    assert AuditEventType.GOVERNANCE_ERROR == "governance_error"

def test_webhook_audit_event_types_exist():
    """All webhook audit event types are defined."""
    assert AuditEventType.WEBHOOK_RECEIVED == "webhook_received"
    assert AuditEventType.WEBHOOK_RELAY == "webhook_relay"
    assert AuditEventType.WEBHOOK_REPLAY_REJECTED == "webhook_replay_rejected"
    assert AuditEventType.WEBHOOK_RATE_LIMITED == "webhook_rate_limited"
    assert AuditEventType.WEBHOOK_SIGNATURE_FAILED == "webhook_signature_failed"

def test_plugin_audit_event_types_exist():
    """Plugin enforcement audit event types are defined."""
    assert AuditEventType.PLUGIN_GOVERNANCE_BLOCK == "plugin_governance_block"
    assert AuditEventType.PLUGIN_QUARANTINE_BLOCK == "plugin_quarantine_block"
```

**GREEN — Implement:**

Add to `AuditEventType` enum in `src/models.py`:

```python
# Governance events
GOVERNANCE_ALLOW = "governance_allow"
GOVERNANCE_BLOCK = "governance_block"
GOVERNANCE_APPROVAL_REQUIRED = "governance_approval_required"
GOVERNANCE_APPROVAL_GRANTED = "governance_approval_granted"
GOVERNANCE_ERROR = "governance_error"
# Webhook events
WEBHOOK_RECEIVED = "webhook_received"
WEBHOOK_RELAY = "webhook_relay"
WEBHOOK_REPLAY_REJECTED = "webhook_replay_rejected"
WEBHOOK_RATE_LIMITED = "webhook_rate_limited"
WEBHOOK_SIGNATURE_FAILED = "webhook_signature_failed"
# Plugin enforcement events
PLUGIN_GOVERNANCE_BLOCK = "plugin_governance_block"
PLUGIN_QUARANTINE_BLOCK = "plugin_quarantine_block"
```

**REFACTOR:** Verify existing audit logger tests still pass, ensure hash chain compatibility.

**Acceptance Criteria:**
- [ ] All new enum values serialize correctly
- [ ] Existing `AuditEventType` values unchanged
- [ ] `test_models.py` passes

---

### T1.2: Create Governance Helper Functions

**Priority:** P0
**Complexity:** Low
**Files Created:** `src/proxy/governance_helpers.py`
**Files Tested:** `tests/unit/test_governance_helpers.py`

**RED — Write Failing Tests:**

```python
# tests/unit/test_governance_helpers.py

import pytest
from src.proxy.governance_helpers import has_tool_calls

class TestHasToolCalls:
    def test_detects_tool_calls_key(self):
        assert has_tool_calls({"tool_calls": [{"name": "read_file"}]}) is True

    def test_detects_function_call_key(self):
        assert has_tool_calls({"function_call": {"name": "exec"}}) is True

    def test_ignores_tools_capability_declaration(self):
        """SEC-D-03: tools[] is capability, not invocation."""
        assert has_tool_calls({"tools": [{"type": "function"}]}) is False

    def test_empty_tool_calls_is_false(self):
        assert has_tool_calls({"tool_calls": []}) is False

    def test_no_tool_keys_is_false(self):
        assert has_tool_calls({"messages": [{"role": "user"}]}) is False

    def test_non_dict_returns_false(self):
        assert has_tool_calls(None) is False
```

**GREEN — Implement:**

```python
# src/proxy/governance_helpers.py

def has_tool_calls(body: dict | None) -> bool:
    """Detect actual tool call invocations (not capability declarations).

    SEC-D-03: Only match tool_calls and function_call (invocations),
    NOT tools (capability declarations).
    """
    if not isinstance(body, dict):
        return False
    return bool(body.get("tool_calls") or body.get("function_call"))
```

**Acceptance Criteria:**
- [ ] Detects `tool_calls` and `function_call` keys
- [ ] Does NOT trigger on `tools` capability declarations (SEC-D-03)
- [ ] Returns False for empty lists, None, non-dict

---

### T1.3: Create Response Header Stripping Utility

**Priority:** P0 (SEC-D-01)
**Complexity:** Low
**Files Created:** (add to `src/proxy/governance_helpers.py`)
**Files Tested:** `tests/unit/test_governance_helpers.py`

**RED — Write Failing Tests:**

```python
# tests/unit/test_governance_helpers.py — add

from src.proxy.governance_helpers import strip_governance_headers

class TestStripGovernanceHeaders:
    def test_strips_governance_plan_id(self):
        headers = {"content-type": "application/json", "x-governance-plan-id": "plan-123"}
        result = strip_governance_headers(headers)
        assert "x-governance-plan-id" not in result
        assert "content-type" in result

    def test_strips_governance_token(self):
        headers = {"x-governance-token": "secret", "x-request-id": "abc"}
        result = strip_governance_headers(headers)
        assert "x-governance-token" not in result
        assert "x-request-id" in result

    def test_strips_all_x_governance_prefixed(self):
        headers = {"x-governance-session": "s1", "x-governance-custom": "val", "accept": "*/*"}
        result = strip_governance_headers(headers)
        assert all(not k.lower().startswith("x-governance-") for k in result)
        assert "accept" in result

    def test_preserves_non_governance_headers(self):
        headers = {"content-type": "application/json", "x-request-id": "abc"}
        result = strip_governance_headers(headers)
        assert result == headers
```

**GREEN — Implement:**

```python
def strip_governance_headers(headers: dict[str, str]) -> dict[str, str]:
    """SEC-D-01: Strip X-Governance-* headers from upstream responses."""
    return {k: v for k, v in headers.items() if not k.lower().startswith("x-governance-")}
```

**Acceptance Criteria:**
- [ ] All `X-Governance-*` headers removed (case-insensitive)
- [ ] Non-governance headers preserved
- [ ] SEC-D-01 addressed

---

## Phase 2: Governance Integration into Proxy (P0)

### T2.1: Governance Evaluation Function

**Priority:** P0
**Complexity:** High
**Files Modified:** `src/proxy/app.py`
**Files Created:** (logic added to app.py, helpers in governance_helpers.py)
**Files Tested:** `tests/unit/test_governance_integration.py`
**Design Reference:** Section 3.1.3B

**RED — Write Failing Tests:**

```python
# tests/unit/test_governance_integration.py

import pytest
from unittest.mock import MagicMock, patch
from src.proxy.governance_helpers import evaluate_governance

class TestEvaluateGovernance:
    """Tests for _evaluate_governance() function."""

    def test_allow_decision_returns_none(self, mock_governance):
        """ALLOW decisions return None (continue pipeline)."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.ALLOW, plan_id="p1", token="tok"
        )
        result = evaluate_governance(mock_governance, body_json, raw_body, request, audit_logger)
        assert result is None

    def test_block_decision_returns_403(self, mock_governance):
        """BLOCK decisions return 403 with violation details."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.BLOCK, violations=[...]
        )
        result = evaluate_governance(mock_governance, body_json, raw_body, request, audit_logger)
        assert result.status_code == 403

    def test_require_approval_returns_202(self, mock_governance):
        """REQUIRE_APPROVAL returns 202 with approval_id."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.REQUIRE_APPROVAL, approval_id="a1"
        )
        result = evaluate_governance(mock_governance, body_json, raw_body, request, audit_logger)
        assert result.status_code == 202

    def test_governance_error_returns_500_fail_closed(self, mock_governance):
        """FR-1.7: Governance error → fail closed (500)."""
        mock_governance.evaluate.side_effect = RuntimeError("db error")
        result = evaluate_governance(mock_governance, body_json, raw_body, request, audit_logger)
        assert result.status_code == 500

    def test_governance_error_logs_critical_event(self, mock_governance, mock_audit):
        """Governance error produces GOVERNANCE_ERROR audit event."""
        mock_governance.evaluate.side_effect = RuntimeError("db error")
        evaluate_governance(mock_governance, body_json, raw_body, request, mock_audit)
        mock_audit.log.assert_called_once()
        event = mock_audit.log.call_args[0][0]
        assert event.event_type == AuditEventType.GOVERNANCE_ERROR

    def test_block_logs_governance_block_event(self, mock_governance, mock_audit):
        """BLOCK produces GOVERNANCE_BLOCK audit event."""
        ...

    def test_approval_required_logs_event(self, mock_governance, mock_audit):
        """REQUIRE_APPROVAL produces GOVERNANCE_APPROVAL_REQUIRED event."""
        ...
```

**GREEN — Implement:** Add `evaluate_governance()` to `src/proxy/governance_helpers.py` following Section 3.1.3B.

**Acceptance Criteria:**
- [ ] ALLOW → None, BLOCK → 403, REQUIRE_APPROVAL → 202, ERROR → 500
- [ ] All decisions produce correct audit events (FR-1.2, FR-1.3, FR-1.4, FR-1.7)
- [ ] Fail-closed on exceptions

---

### T2.2: Retry Flow with Request Hash Verification (SEC-D-02)

**Priority:** P0
**Complexity:** High
**Files Modified:** `src/proxy/governance_helpers.py`
**Files Tested:** `tests/unit/test_governance_integration.py`
**Design Reference:** Section 3.1.3B (retry path)

**RED — Write Failing Tests:**

```python
class TestGovernanceRetryFlow:
    """SEC-D-02: Retry flow with request hash verification."""

    def test_valid_token_and_matching_hash_skips_evaluation(self):
        """Valid plan + token + matching hash → None (allow)."""
        ...

    def test_invalid_token_returns_403(self):
        """Invalid/expired token → 403."""
        ...

    def test_mismatched_request_hash_returns_403(self):
        """SEC-D-02: Token valid but body changed → 403."""
        ...

    def test_retry_with_expired_token_returns_403(self):
        """Expired token (TTL > 900s) → 403."""
        ...

    def test_retry_path_skips_re_evaluation(self):
        """With valid token, governance.evaluate() is NOT called."""
        ...
```

**GREEN — Implement:** Add retry path logic in `evaluate_governance()` that checks `X-Governance-Plan-Id` and `X-Governance-Token` headers, validates token, and verifies `request_hash` against stored plan.

**Acceptance Criteria:**
- [ ] Valid retry path bypasses re-evaluation
- [ ] Invalid token → 403
- [ ] Request body hash mismatch → 403 (SEC-D-02)
- [ ] Expired token → 403

---

### T2.3: Wire Governance into Proxy Pipeline

**Priority:** P0
**Complexity:** Medium
**Files Modified:** `src/proxy/app.py`
**Files Tested:** `tests/integration/test_proxy_governance.py`
**Design Reference:** Section 3.1.2, 3.1.3

**RED — Write Failing Tests:**

```python
# tests/integration/test_proxy_governance.py

import pytest
from httpx import AsyncClient
from src.proxy.app import create_app

class TestProxyGovernancePipeline:
    """Integration tests for governance in the proxy pipeline."""

    @pytest.fixture
    def app_with_governance(self, tmp_path):
        """Create app with governance enabled."""
        ...

    @pytest.fixture
    def app_without_governance(self):
        """Create app with governance disabled."""
        ...

    async def test_tool_call_triggers_governance(self, app_with_governance):
        """POST with tool_calls → governance.evaluate() called."""
        ...

    async def test_get_request_bypasses_governance(self, app_with_governance):
        """GET requests skip governance (no tool calls in GET)."""
        ...

    async def test_no_tool_calls_bypasses_governance(self, app_with_governance):
        """POST without tool_calls → governance not called."""
        ...

    async def test_governance_disabled_skips_check(self, app_without_governance):
        """GOVERNANCE_ENABLED=false → no governance checks (FR-1.5)."""
        ...

    async def test_governance_headers_stripped_from_response(self, app_with_governance):
        """SEC-D-01: X-Governance-* stripped from response to client."""
        ...

    async def test_governance_headers_attached_to_upstream(self, app_with_governance):
        """ALLOW decision attaches X-Governance-Plan-Id/Token to upstream."""
        ...

    async def test_pipeline_order_auth_then_governance(self, app_with_governance):
        """Auth runs before governance (unauthenticated → 401, not governance error)."""
        ...

    async def test_create_app_from_env_with_governance(self, monkeypatch):
        """GOVERNANCE_ENABLED + GOVERNANCE_SECRET creates governance middleware."""
        ...
```

**GREEN — Implement:**

1. Add `governance` parameter to `create_app()` and `create_app_from_env()`
2. Insert governance evaluation between auth and sanitization in `proxy()` handler
3. Attach `X-Governance-Plan-Id` and `X-Governance-Token` headers on ALLOW
4. Strip `X-Governance-*` from response headers (SEC-D-01)
5. Preserve existing pipeline when governance is None/disabled

**Acceptance Criteria:**
- [ ] Pipeline order: Auth → Governance → Sanitizer → Quarantine → Forward → Scan → Strip → Audit
- [ ] Governance disabled → existing behavior preserved (FR-1.5)
- [ ] Response headers stripped (SEC-D-01)
- [ ] Governance headers forwarded to upstream on ALLOW
- [ ] `create_app_from_env()` reads new env vars

---

### T2.4: Governance API Endpoints

**Priority:** P0
**Complexity:** Medium
**Files Created:** `src/proxy/governance_routes.py`
**Files Tested:** `tests/unit/test_governance_routes.py`, `tests/integration/test_governance_api.py`
**Design Reference:** Section 3.1.5

**RED — Write Failing Tests:**

```python
# tests/unit/test_governance_routes.py

class TestGovernanceRoutes:
    """Tests for governance API endpoints (FR-6)."""

    async def test_get_approval_returns_details(self):
        """GET /governance/approvals/{id} returns approval request."""
        ...

    async def test_get_approval_not_found_returns_404(self):
        """GET /governance/approvals/{id} with unknown id → 404."""
        ...

    async def test_approve_activates_plan(self):
        """POST /governance/approvals/{id}/approve → plan activated, token returned (FR-6.2)."""
        ...

    async def test_approve_expired_returns_410(self):
        """POST /governance/approvals/{id}/approve on expired → 410."""
        ...

    async def test_reject_logs_rejection(self):
        """POST /governance/approvals/{id}/reject → logged (FR-6.3)."""
        ...

    async def test_cleanup_removes_expired(self):
        """POST /governance/cleanup → expired plans/sessions removed (FR-6.4)."""
        ...

    async def test_endpoints_require_auth(self):
        """All governance endpoints require Bearer token (AC-1)."""
        ...
```

**GREEN — Implement:** Create `src/proxy/governance_routes.py` with FastAPI router, wire into app.

**Acceptance Criteria:**
- [ ] GET/POST approval endpoints work (FR-6.1-6.3)
- [ ] Cleanup endpoint removes expired items (FR-6.4)
- [ ] All endpoints behind auth middleware
- [ ] Approval/rejection produce audit events

---

### T2.5: Governance Integration Smoke Test

**Priority:** P0
**Complexity:** Medium
**Files Tested:** `tests/integration/test_governance_flow.py`

**RED — Write Failing Tests:**

```python
# tests/integration/test_governance_flow.py

class TestGovernanceApprovalFlow:
    """End-to-end governance approval flow."""

    async def test_full_approval_flow(self):
        """
        1. POST with tool calls → 202 (REQUIRE_APPROVAL)
        2. GET approval details → shows violations
        3. POST approve → plan activated, token returned
        4. POST retry with token → request forwarded
        """
        ...

    async def test_full_block_flow(self):
        """POST with blocked tool call → 403 + audit event."""
        ...

    async def test_full_allow_flow(self):
        """POST with allowed tool call → forwarded with governance headers."""
        ...
```

**Acceptance Criteria:**
- [ ] Full REQUIRE_APPROVAL → approve → retry flow works
- [ ] Full BLOCK flow works
- [ ] Full ALLOW flow works
- [ ] Audit trail captures all decisions

---

## Phase 3: Webhook Relay (P1)

### T3.1: Replay Protection Module

**Priority:** P1
**Complexity:** Medium
**Files Created:** `src/webhook/__init__.py`, `src/webhook/replay_protection.py`
**Files Tested:** `tests/unit/test_replay_protection.py`
**Design Reference:** Section 3.2.5

**RED — Write Failing Tests:**

```python
# tests/unit/test_replay_protection.py

class TestTelegramReplayProtection:
    """FR-2.7: Telegram update_id replay protection."""

    def test_new_update_id_accepted(self, replay_protection):
        assert replay_protection.check_telegram(100) is True

    def test_duplicate_update_id_rejected(self, replay_protection):
        replay_protection.check_telegram(100)
        assert replay_protection.check_telegram(100) is False

    def test_older_update_id_rejected(self, replay_protection):
        replay_protection.check_telegram(100)
        assert replay_protection.check_telegram(99) is False

    def test_sequential_update_ids_accepted(self, replay_protection):
        assert replay_protection.check_telegram(100) is True
        assert replay_protection.check_telegram(101) is True
        assert replay_protection.check_telegram(102) is True

    def test_state_persists_across_instances(self, tmp_path):
        """SEC-D-05: SQLite-backed, survives restart."""
        db_path = str(tmp_path / "replay.db")
        rp1 = ReplayProtection(db_path)
        rp1.check_telegram(100)
        rp2 = ReplayProtection(db_path)
        assert rp2.check_telegram(100) is False

class TestWhatsAppReplayProtection:
    """FR-3.7: WhatsApp timestamp window replay protection."""

    def test_recent_message_accepted(self, replay_protection, freezer):
        """Message within 5-minute window is accepted."""
        now = int(time.time())
        assert replay_protection.check_whatsapp(now - 60) is True

    def test_old_message_rejected(self, replay_protection, freezer):
        """Message older than 5 minutes is rejected."""
        now = int(time.time())
        assert replay_protection.check_whatsapp(now - 301) is False

    def test_configurable_window(self, tmp_path):
        """WHATSAPP_REPLAY_WINDOW_SECONDS configurable."""
        rp = ReplayProtection(str(tmp_path / "rp.db"), whatsapp_window_seconds=10)
        now = int(time.time())
        assert rp.check_whatsapp(now - 11) is False
        assert rp.check_whatsapp(now - 5) is True
```

**GREEN — Implement:** Create `src/webhook/replay_protection.py` with SQLite-backed `ReplayProtection` class.

**Acceptance Criteria:**
- [ ] Telegram: duplicate/older update_id rejected (FR-2.7)
- [ ] WhatsApp: messages outside time window rejected (FR-3.7)
- [ ] SQLite-backed, survives restarts (SEC-D-05)
- [ ] Configurable WhatsApp window

---

### T3.2: Rate Limiter Module

**Priority:** P1
**Complexity:** Low
**Files Created:** `src/webhook/rate_limiter.py`
**Files Tested:** `tests/unit/test_webhook_rate_limiter.py`
**Design Reference:** Section 3.2.6

**RED — Write Failing Tests:**

```python
# tests/unit/test_webhook_rate_limiter.py

class TestWebhookRateLimiter:
    """NFR-8: Webhook rate limiting."""

    def test_allows_within_limit(self):
        limiter = WebhookRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert limiter.check("192.168.1.1") is True

    def test_blocks_over_limit(self):
        limiter = WebhookRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            limiter.check("192.168.1.1")
        assert limiter.check("192.168.1.1") is False

    def test_different_ips_independent(self):
        limiter = WebhookRateLimiter(max_requests=1, window_seconds=60)
        assert limiter.check("192.168.1.1") is True
        assert limiter.check("192.168.1.2") is True

    def test_window_expiry_resets_count(self, freezer):
        limiter = WebhookRateLimiter(max_requests=1, window_seconds=60)
        assert limiter.check("192.168.1.1") is True
        assert limiter.check("192.168.1.1") is False
        freezer.move_to(datetime.now() + timedelta(seconds=61))
        assert limiter.check("192.168.1.1") is True

    def test_default_60_per_minute(self):
        limiter = WebhookRateLimiter()
        assert limiter._max_requests == 60
        assert limiter._window == 60
```

**GREEN — Implement:** Create `src/webhook/rate_limiter.py` with sliding window counter.

**Acceptance Criteria:**
- [ ] Sliding window per source IP
- [ ] Default 60 req/min
- [ ] Configurable limits
- [ ] Window expiry resets counter

---

### T3.3: Telegram Relay Module

**Priority:** P1
**Complexity:** High
**Files Created:** `src/webhook/telegram.py`
**Files Tested:** `tests/unit/test_telegram_relay.py`
**Design Reference:** Section 3.2.3

**RED — Write Failing Tests:**

```python
# tests/unit/test_telegram_relay.py

class TestTelegramWebhookVerification:
    """FR-2.4, FR-2.6: Webhook signature verification."""

    def test_valid_secret_token_accepted(self):
        relay = TelegramRelay(bot_token="123:ABC")
        assert relay.verify_webhook(mock_request_with_valid_secret) is True

    def test_missing_secret_token_rejected(self):
        relay = TelegramRelay(bot_token="123:ABC")
        assert relay.verify_webhook(mock_request_without_header) is False

    def test_invalid_secret_token_rejected(self):
        relay = TelegramRelay(bot_token="123:ABC")
        assert relay.verify_webhook(mock_request_with_wrong_secret) is False

    def test_verification_uses_constant_time_comparison(self):
        """NFR-3: Constant-time comparison for token verification."""
        # Verify hmac.compare_digest is used
        ...

class TestTelegramMessageExtraction:
    """FR-2.1: Extract and translate Telegram messages."""

    def test_extracts_text_message(self):
        ...

    def test_extracts_update_id(self):
        ...

    def test_handles_missing_text(self):
        ...

    def test_handles_edited_message(self):
        ...

class TestTelegramProtocolTranslation:
    """FR-2.1: Translate to OpenAI-compatible format."""

    def test_to_openclaw_request_format(self):
        relay = TelegramRelay(bot_token="test")
        result = relay.to_openclaw_request("hello", chat_id=12345)
        assert result["messages"][0]["role"] == "user"
        assert result["messages"][0]["content"] == "hello"
        assert result["metadata"]["source"] == "telegram"
        assert result["metadata"]["chat_id"] == 12345

class TestTelegramResponseSending:
    """FR-2.3, FR-2.5, FR-2.8: Send response back via Telegram API."""

    async def test_sends_response_with_tls_verification(self):
        """NFR-9: TLS certificate verification enabled."""
        ...

    async def test_retries_on_429(self):
        """FR-2.8: Retry on rate limit."""
        ...

    async def test_retries_on_5xx(self):
        """FR-2.8: Retry on server error."""
        ...

    async def test_no_retry_on_4xx(self):
        """FR-2.8: No retry on client errors (except 429)."""
        ...

    async def test_max_3_retries_with_exponential_backoff(self):
        """FR-2.5: Max 3 retries with exponential backoff."""
        ...

    async def test_backoff_capped_at_30_seconds(self):
        """FR-2.8: Backoff capped at 30s."""
        ...
```

**GREEN — Implement:** Create `src/webhook/telegram.py` with `TelegramRelay` class.

**Acceptance Criteria:**
- [ ] Webhook verification using SHA-256 hash of bot token (FR-2.6)
- [ ] Constant-time comparison (NFR-3)
- [ ] Message extraction from various Telegram update formats
- [ ] Protocol translation to OpenAI-compatible format (FR-2.1)
- [ ] Response sending with TLS verification (NFR-9)
- [ ] Retry on 429/5xx with exponential backoff capped at 30s (FR-2.5, FR-2.8)

---

### T3.4: WhatsApp Relay Module

**Priority:** P1
**Complexity:** High
**Files Created:** `src/webhook/whatsapp.py`
**Files Tested:** `tests/unit/test_whatsapp_relay.py`
**Design Reference:** Section 3.2.4

**RED — Write Failing Tests:**

```python
# tests/unit/test_whatsapp_relay.py

class TestWhatsAppSignatureVerification:
    """FR-3.4, FR-3.5: HMAC-SHA256 signature verification."""

    def test_valid_signature_accepted(self):
        ...

    def test_invalid_signature_rejected(self):
        ...

    def test_missing_signature_rejected(self):
        ...

    def test_malformed_signature_prefix_rejected(self):
        """Signature without 'sha256=' prefix rejected."""
        ...

    def test_constant_time_comparison(self):
        """NFR-3: Uses hmac.compare_digest."""
        ...

class TestWhatsAppVerificationChallenge:
    """FR-3.6: Meta webhook verification handshake."""

    def test_valid_subscribe_returns_challenge(self):
        ...

    def test_invalid_verify_token_returns_403(self):
        ...

    def test_non_subscribe_mode_returns_none(self):
        ...

class TestWhatsAppMessageExtraction:
    """FR-3.1: Extract and translate WhatsApp messages."""

    def test_extracts_text_message(self):
        ...

    def test_extracts_phone_number(self):
        ...

    def test_extracts_message_timestamp(self):
        ...

    def test_handles_status_updates_gracefully(self):
        """Status webhooks (delivered, read) are not messages."""
        ...

class TestWhatsAppProtocolTranslation:
    """FR-3.1: Translate to OpenAI-compatible format."""

    def test_to_openclaw_request_format(self):
        relay = WhatsAppRelay(app_secret="s", verify_token="v", phone_number_id="p", access_token="a")
        result = relay.to_openclaw_request("hello", sender_phone="+1234567890")
        assert result["metadata"]["source"] == "whatsapp"

class TestWhatsAppResponseSending:
    """FR-3.3, FR-3.8: Send response via WhatsApp API."""

    async def test_sends_response_with_tls(self):
        """NFR-9: TLS verification."""
        ...

    async def test_retries_on_429_and_5xx(self):
        """FR-3.8: Selective retry."""
        ...

    async def test_backoff_capped_at_30_seconds(self):
        """FR-3.8: Cap at 30s."""
        ...
```

**GREEN — Implement:** Create `src/webhook/whatsapp.py` with `WhatsAppRelay` class.

**Acceptance Criteria:**
- [ ] HMAC-SHA256 signature verification (FR-3.5)
- [ ] Verification challenge handshake (FR-3.6)
- [ ] Message extraction from WhatsApp Business API format
- [ ] Protocol translation to OpenAI-compatible format (FR-3.1)
- [ ] Response sending with TLS (NFR-9)
- [ ] Selective retry on 429/5xx (FR-3.8)

---

### T3.5: Webhook Relay Core (Pipeline Integration)

**Priority:** P1
**Complexity:** High
**Files Created:** `src/webhook/relay.py`, `src/webhook/models.py`
**Files Tested:** `tests/unit/test_webhook_relay.py`
**Design Reference:** Section 3.2.2

**RED — Write Failing Tests:**

```python
# tests/unit/test_webhook_relay.py

class TestWebhookRelayPipeline:
    """SEC-D-04: Direct function call pipeline for webhooks."""

    async def test_relay_calls_all_pipeline_stages(self):
        """Full pipeline: sanitize → quarantine → governance → forward → scan → audit."""
        ...

    async def test_sanitizer_blocks_injection(self):
        """Prompt injection in webhook message → blocked."""
        ...

    async def test_quarantine_blocks_skill(self):
        """Quarantined skill invocation via webhook → blocked."""
        ...

    async def test_governance_blocks_tool_call(self):
        """Governance BLOCK decision via webhook → message rejected."""
        ...

    async def test_response_scanned_before_reply(self):
        """Response scanner checks OpenClaw response before platform reply."""
        ...

    async def test_audit_log_includes_source(self):
        """Audit events include source=telegram/whatsapp."""
        ...

    async def test_body_size_limit_enforced(self):
        """NFR-7: Oversized body → 413."""
        ...
```

**GREEN — Implement:** Create `src/webhook/relay.py` with core relay logic that orchestrates the pipeline.

**Acceptance Criteria:**
- [ ] All 6 pipeline stages called in order (SEC-D-04)
- [ ] Body size limit enforced (NFR-7)
- [ ] Audit events include source platform
- [ ] Each stage can independently block the request

---

### T3.6: Register Webhook Routes in Proxy App

**Priority:** P1
**Complexity:** Medium
**Files Modified:** `src/proxy/app.py`
**Files Tested:** `tests/integration/test_webhook_endpoints.py`
**Design Reference:** Section 3.2.8

**RED — Write Failing Tests:**

```python
# tests/integration/test_webhook_endpoints.py

class TestWebhookRouteRegistration:
    """NFR-2: Webhook routes conditionally registered."""

    def test_telegram_route_registered_when_token_set(self, app_with_telegram):
        """TELEGRAM_BOT_TOKEN set → /webhook/telegram available."""
        ...

    def test_telegram_route_absent_when_no_token(self, app_without_telegram):
        """No TELEGRAM_BOT_TOKEN → /webhook/telegram returns 404."""
        ...

    def test_whatsapp_route_registered_when_secret_set(self, app_with_whatsapp):
        """WHATSAPP_APP_SECRET set → /webhook/whatsapp available."""
        ...

    def test_whatsapp_get_verification(self, app_with_whatsapp):
        """GET /webhook/whatsapp handles Meta verification challenge."""
        ...

class TestWebhookEndpoints:
    """Full webhook endpoint tests."""

    async def test_telegram_valid_webhook(self, app_with_telegram):
        """Valid Telegram webhook → 200, message processed."""
        ...

    async def test_telegram_invalid_signature_401(self, app_with_telegram):
        """Invalid Telegram webhook signature → 401 (FR-2.4)."""
        ...

    async def test_telegram_replay_attack_409(self, app_with_telegram):
        """Duplicate update_id → 409 (FR-2.7)."""
        ...

    async def test_telegram_rate_limited_429(self, app_with_telegram):
        """Excessive requests → 429 (NFR-8)."""
        ...

    async def test_whatsapp_valid_webhook(self, app_with_whatsapp):
        """Valid WhatsApp webhook → 200, message processed."""
        ...

    async def test_whatsapp_invalid_hmac_401(self, app_with_whatsapp):
        """Invalid WhatsApp HMAC → 401 (FR-3.4)."""
        ...

    async def test_whatsapp_replay_attack_409(self, app_with_whatsapp):
        """Old timestamp → 409 (FR-3.7)."""
        ...
```

**GREEN — Implement:** Register conditional webhook routes in `create_app_from_env()`.

**Acceptance Criteria:**
- [ ] Routes conditionally registered based on env vars (NFR-2)
- [ ] Signature verification → 401 on failure
- [ ] Replay detection → 409 on duplicate
- [ ] Rate limiting → 429 on excess
- [ ] Full pipeline invoked for valid webhooks

---

### T3.7: Caddy Configuration Fix

**Priority:** P1
**Complexity:** Low
**Files Modified:** `docker/caddy/Caddyfile`
**Files Tested:** Manual / docker-compose integration test
**Design Reference:** Section 3.2.7

**Implementation:**

Change Caddy upstream from `openclaw:3000` to `proxy:8080`:

```
# BEFORE:
reverse_proxy openclaw:3000

# AFTER:
reverse_proxy proxy:8080
```

Update `docker-compose.yml` for Caddy to depend on proxy instead of openclaw.

**Acceptance Criteria:**
- [ ] Caddy routes HTTPS traffic through proxy
- [ ] Proxy pipeline applies to HTTPS traffic
- [ ] Health checks still work

---

## Phase 4: Plugin Hook Expansion (P1)

### T4.1: Add `before_tool_call` Hook with Governance Check

**Priority:** P1
**Complexity:** Medium
**Files Modified:** `plugins/prompt-guard/index.ts`
**Files Tested:** `plugins/prompt-guard/__tests__/governance.test.ts`
**Design Reference:** Section 3.3.2A

**RED — Write Failing Tests:**

```typescript
// plugins/prompt-guard/__tests__/governance.test.ts

describe('before_tool_call hook', () => {
    describe('when enforcement enabled', () => {
        it('allows tool call with governance headers present', () => {
            // SEC-D-07: Presence-only check
        });

        it('blocks tool call without governance headers', () => {
            // FR-4.3: No token → block
        });

        it('falls back to local policy when no headers', () => {
            // FR-4.1: Local policy fallback
        });
    });

    describe('when enforcement disabled', () => {
        it('allows all tool calls', () => {
            // FR-4.4: Enforcement disabled → allow
        });

        it('preserves existing tool_result_persist behavior', () => {
            // FR-4.4: Current behavior unchanged
        });
    });

    describe('logging', () => {
        it('logs enforcement actions to detection log', () => {
            // FR-4.5
        });
    });
});
```

**GREEN — Implement:** Add `before_tool_call` hook to `plugins/prompt-guard/index.ts`.

**Acceptance Criteria:**
- [ ] Governance token presence check (SEC-D-07)
- [ ] Enforcement toggle via `PROMPT_GUARD_ENFORCEMENT` (FR-4.4)
- [ ] All enforcement actions logged (FR-4.5)

---

### T4.2: Add Quarantine Check to Plugin

**Priority:** P1
**Complexity:** Medium
**Files Modified:** `plugins/prompt-guard/index.ts`
**Files Tested:** `plugins/prompt-guard/__tests__/quarantine.test.ts`
**Design Reference:** Section 3.3.2B

**RED — Write Failing Tests:**

```typescript
// plugins/prompt-guard/__tests__/quarantine.test.ts

describe('quarantine enforcement in plugin', () => {
    it('blocks quarantined skill', () => {
        // FR-4.2
    });

    it('allows non-quarantined skill', () => {
        // Normal operation
    });

    it('loads quarantine list from config path', () => {
        // Config loading
    });

    it('logs quarantine blocks', () => {
        // FR-4.5
    });

    it('operates independently from proxy', () => {
        // Defense-in-depth principle
    });
});
```

**GREEN — Implement:** Add quarantine check logic to `applyLocalPolicy()` in plugin.

**Acceptance Criteria:**
- [ ] Quarantined skills blocked at plugin level (FR-4.2)
- [ ] Quarantine list loaded from shared config
- [ ] Blocks logged to detection log (FR-4.5)
- [ ] Plugin operates independently from proxy (defense-in-depth)

---

### T4.3: Plugin Integration Test

**Priority:** P1
**Complexity:** Low
**Files Tested:** `plugins/prompt-guard/__tests__/integration.test.ts`

**RED — Write Tests:**

```typescript
describe('plugin defense-in-depth integration', () => {
    it('before_tool_call + tool_result_persist both fire', () => {
        // Both hooks work together
    });

    it('before_tool_call blocks before tool_result_persist runs', () => {
        // Pre-execution block prevents post-execution scan
    });

    it('tool_result_persist still works when before_tool_call allows', () => {
        // Existing behavior preserved
    });
});
```

**Acceptance Criteria:**
- [ ] Both hooks coexist
- [ ] Pre-execution blocking works
- [ ] Existing `tool_result_persist` behavior preserved (FR-4.4)

---

## Phase 5: Network Policy Hardening (P2)

### T5.1: Docker Compose Network & Environment Updates

**Priority:** P2
**Complexity:** Low
**Files Modified:** `docker-compose.yml`
**Design Reference:** Section 3.4.2

**Implementation:**

1. Add webhook environment variables to proxy service
2. Add governance environment variables to proxy service
3. Update Caddy `depends_on` to reference proxy
4. Add `PROMPT_GUARD_ENFORCEMENT` to openclaw service
5. Add shared quarantine config volume

**Acceptance Criteria:**
- [ ] All new env vars documented and added
- [ ] Caddy depends on proxy
- [ ] Quarantine config shared between proxy and plugin
- [ ] Existing network configuration preserved

---

### T5.2: Update `.env.example` and Install Script

**Priority:** P2
**Complexity:** Low
**Files Modified:** `.env.example`, `install.sh`

**Implementation:**

1. Add all new environment variables to `.env.example` with documentation
2. Update `install.sh` to generate `GOVERNANCE_SECRET` (32-byte random, base64)
3. Add optional Telegram/WhatsApp configuration section

**Acceptance Criteria:**
- [ ] All new env vars in `.env.example` with descriptions
- [ ] `GOVERNANCE_SECRET` auto-generated in `install.sh`
- [ ] Install script backward-compatible

---

## Phase 6: Integration & Security Tests

### T6.1: Cross-Component Integration Tests

**Priority:** P0
**Complexity:** High
**Files Created:** `tests/integration/test_full_pipeline.py`

**Tests:**

```python
class TestFullPipelineIntegration:
    """End-to-end tests across all components."""

    async def test_http_request_full_pipeline_with_governance(self):
        """HTTP → auth → governance → sanitize → quarantine → forward → scan → strip → audit."""
        ...

    async def test_telegram_webhook_full_pipeline(self):
        """Telegram → verify → rate_limit → replay → translate → [full pipeline] → reply."""
        ...

    async def test_whatsapp_webhook_full_pipeline(self):
        """WhatsApp → verify → rate_limit → replay → translate → [full pipeline] → reply."""
        ...

    async def test_governance_disabled_preserves_existing_behavior(self):
        """All existing tests pass with GOVERNANCE_ENABLED=false."""
        ...

    async def test_no_webhook_tokens_no_webhook_routes(self):
        """No TELEGRAM_BOT_TOKEN/WHATSAPP_APP_SECRET → no webhook endpoints."""
        ...
```

**Acceptance Criteria:**
- [ ] All client paths from coverage matrix tested
- [ ] Backward compatibility verified
- [ ] Conditional feature registration works

---

### T6.2: Security Test Suite

**Priority:** P0
**Complexity:** High
**Files Created:** `tests/security/test_governance_security.py`, `tests/security/test_webhook_security.py`
**Design Reference:** Section 8.3 (SEC-D-10)

**Tests:**

```python
# tests/security/test_governance_security.py

class TestGovernanceTokenSecurity:
    """SEC-D-10: Token manipulation attack vectors."""

    def test_token_with_modified_plan_id_rejected(self):
        """Modified plan_id → signature mismatch → reject."""
        ...

    def test_token_with_future_expiration_rejected(self):
        """Clock skew attack → reject."""
        ...

    def test_token_from_different_secret_rejected(self):
        """Different GOVERNANCE_SECRET → key confusion → reject."""
        ...

    def test_request_hash_mismatch_rejected(self):
        """SEC-D-02: Body changed between approval and retry → reject."""
        ...

    def test_expired_token_rejected(self):
        """Token past TTL (900s) → reject."""
        ...

# tests/security/test_webhook_security.py

class TestWebhookSecurity:
    """Webhook-specific attack vectors."""

    def test_telegram_replay_attack_rejected(self):
        """Old update_id → 409."""
        ...

    def test_whatsapp_replay_attack_rejected(self):
        """Old timestamp → 409."""
        ...

    def test_telegram_spoofed_webhook_rejected(self):
        """Invalid secret token → 401."""
        ...

    def test_whatsapp_spoofed_webhook_rejected(self):
        """Invalid HMAC → 401."""
        ...

    def test_webhook_rate_limit_enforced(self):
        """Excessive requests → 429."""
        ...

    def test_oversized_webhook_body_rejected(self):
        """NFR-7: Body > 10MB → 413."""
        ...

    def test_governance_headers_never_in_response(self):
        """SEC-D-01: No X-Governance-* in client-facing responses."""
        ...

class TestNetworkPolicySecurity:
    """P2 network hardening validation."""

    def test_dns_bypass_via_raw_ip_rejected(self):
        """Direct IP requests bypass DNS allowlisting — verify enforcement.

        Skills that construct HTTP requests using raw IP addresses
        (e.g., http://169.254.169.254 for cloud metadata, or arbitrary
        IP:port combinations) bypass the CoreDNS allowlist. This test
        validates that additional controls detect/block such patterns.
        """
        ...

    def test_caddy_routes_through_proxy(self):
        """Caddy upstream is proxy:8080, not openclaw:3000."""
        ...

    def test_non_allowlisted_domain_dns_nxdomain(self):
        """DNS resolution of non-allowlisted domain returns NXDOMAIN."""
        ...
```

**Acceptance Criteria:**
- [ ] All SEC-D-10 token manipulation vectors tested
- [ ] All webhook attack vectors tested
- [ ] Raw IP bypass scenario tested (P2 network hardening)
- [ ] 100% branch coverage on security-critical paths (NFR-6)

---

### T6.3: Coverage Verification & Mypy/Ruff Compliance

**Priority:** P0
**Complexity:** Low

**Tasks:**
1. Run `pytest --cov --cov-fail-under=90` — verify 90% threshold maintained (NFR-6)
2. Run `mypy --strict src/` — verify no type errors
3. Run `ruff check src/ tests/` — verify no lint violations
4. Verify all security-critical paths have 100% branch coverage

**Acceptance Criteria:**
- [ ] Overall coverage ≥ 90%
- [ ] Security-critical paths 100% branch coverage
- [ ] Zero mypy errors (strict mode)
- [ ] Zero ruff violations

---

## Summary Table

| Task | Component | Priority | Complexity | Files | Depends On |
|------|-----------|----------|------------|-------|------------|
| T1.1 | Foundation | P0 | Low | `src/models.py` | — |
| T1.2 | Foundation | P0 | Low | `src/proxy/governance_helpers.py` | — |
| T1.3 | Foundation | P0 | Low | `src/proxy/governance_helpers.py` | T1.2 |
| T2.1 | Governance | P0 | High | `src/proxy/governance_helpers.py` | T1.1 |
| T2.2 | Governance | P0 | High | `src/proxy/governance_helpers.py` | T2.1 |
| T2.3 | Governance | P0 | Medium | `src/proxy/app.py` | T2.2 |
| T2.4 | Governance | P0 | Medium | `src/proxy/governance_routes.py` | T2.3 |
| T2.5 | Governance | P0 | Medium | Integration test | T2.4 |
| T3.1 | Webhook | P1 | Medium | `src/webhook/replay_protection.py` | T1.1 |
| T3.2 | Webhook | P1 | Low | `src/webhook/rate_limiter.py` | — |
| T3.3 | Webhook | P1 | High | `src/webhook/telegram.py` | T3.1, T3.2 |
| T3.4 | Webhook | P1 | High | `src/webhook/whatsapp.py` | T3.1, T3.2 |
| T3.5 | Webhook | P1 | High | `src/webhook/relay.py` | T3.3, T3.4 |
| T3.6 | Webhook | P1 | Medium | `src/proxy/app.py` | T3.5 |
| T3.7 | Caddy | P1 | Low | `docker/caddy/Caddyfile` | — |
| T4.1 | Plugin | P1 | Medium | `plugins/prompt-guard/index.ts` | T2.3 |
| T4.2 | Plugin | P1 | Medium | `plugins/prompt-guard/index.ts` | T4.1 |
| T4.3 | Plugin | P1 | Low | Integration test | T4.2 |
| T5.1 | Network | P2 | Low | `docker-compose.yml` | T3.7 |
| T5.2 | Config | P2 | Low | `.env.example`, `install.sh` | T5.1 |
| T6.1 | Integration | P0 | High | `tests/integration/` | T2.5, T3.6, T4.3, T5.1 |
| T6.2 | Security | P0 | High | `tests/security/` | T6.1 |
| T6.3 | Quality | P0 | Low | — | T6.2 |

---

## Requirement Traceability

| Requirement | Tasks |
|-------------|-------|
| FR-1 (Governance) | T2.1, T2.2, T2.3, T2.5 |
| FR-2 (Telegram) | T3.1, T3.3, T3.5, T3.6 |
| FR-3 (WhatsApp) | T3.1, T3.4, T3.5, T3.6 |
| FR-4 (Plugin Hook) | T4.1, T4.2, T4.3 |
| FR-5 (Network) | T3.7, T5.1 |
| FR-6 (Governance API) | T2.4 |
| NFR-1 (Performance) | T2.1 (50ms benchmark), T3.5 (100ms benchmark) |
| NFR-2 (Backward Compat) | T2.3, T3.6, T6.1 |
| NFR-3 (Security) | T3.3, T3.4 (constant-time), T6.2 |
| NFR-4 (Reliability) | T2.1 (fail-closed) |
| NFR-5 (Observability) | T1.1, T2.1, T3.5 |
| NFR-6 (Test Coverage) | T6.3 |
| NFR-7 (Body Size) | T3.5 |
| NFR-8 (Rate Limiting) | T3.2, T3.6 |
| NFR-9 (TLS) | T3.3, T3.4 |
| SEC-D-01 (Header Strip) | T1.3, T2.3, T6.2 |
| SEC-D-02 (Request Hash) | T2.2, T6.2 |
| SEC-D-03 (Tool Call Detection) | T1.2 |
| SEC-D-04 (Direct Calls) | T3.5 |
| SEC-D-05 (SQLite Replay) | T3.1 |
| SEC-D-06 (Rate Limiter) | T3.2 |
| SEC-D-07 (Token Presence) | T4.1 |
| SEC-D-09 (Port 3000) | T5.1 |
| SEC-D-10 (Token Vectors) | T6.2 |
