# Requirements: Governance Layer

## Overview

The Governance Layer is a pre-execution governance system for openclaw-secure-stack that provides intent classification, auditable plan generation, policy-based validation, and execution-time enforcement before agent tool calls reach OpenClaw. It makes multi-step agent intent explicit and inspectable before side effects occur.

## Target Users

1. **Enterprise security teams** deploying OpenClaw agents who need oversight of agent actions
2. **Developers** building agent applications who need policy-based guardrails
3. **End users** interacting via Telegram/WhatsApp who need to approve high-risk agent actions

## Success Criteria

- 100% of tool invocations validated against approved plans
- Zero unplanned tool executions (plan drift blocked)
- All governance decisions audited with full traceability
- Approval flow works for both web UI and messaging channels

---

## Functional Requirements

### FR-1: Intent Classification

**Objective:** As a security administrator, I want the system to classify agent tool call intents, so that I can apply appropriate policies based on the type of action.

**EARS Specification:**
WHEN a request containing tool calls is received
THEN the system SHALL extract tool calls from the OpenAI-compatible format and classify each into one of the defined intent categories

**Acceptance Criteria:**
1. Tool calls are extracted from `tools` array in request body
2. Each tool is classified into one of: FILE_READ, FILE_WRITE, FILE_DELETE, NETWORK_REQUEST, CODE_EXECUTION, SKILL_INVOCATION, SYSTEM_COMMAND, or UNKNOWN
3. Classification is based on pattern matching against configurable tool-to-category mappings
4. Classification completes within 10ms for requests with up to 10 tool calls
5. Arguments are analyzed for sensitive patterns (paths, URLs) to elevate risk

---

### FR-2: Plan Generation

**Objective:** As a security auditor, I want an auditable execution plan generated for each request, so that I can trace what actions were intended before execution.

**EARS Specification:**
WHEN intent classification completes successfully
THEN the system SHALL generate an ExecutionPlan containing the sequence of planned actions, resource access patterns, and risk assessment

**Acceptance Criteria:**
1. Each ExecutionPlan has a unique `plan_id` (UUID)
2. Plan includes ordered list of PlannedActions with sequence numbers
3. Each PlannedAction includes: tool_call, category, resources accessed, risk_score (0-100)
4. Plan includes overall RiskAssessment with level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
5. Plan includes request_hash (SHA-256) for integrity verification
6. Plan is serializable to JSON for audit logging

---

### FR-3: Policy Validation

**Objective:** As a security administrator, I want to define policies that control which actions are allowed, so that I can enforce security boundaries on agent behavior.

**EARS Specification:**
WHEN an ExecutionPlan is generated
THEN the system SHALL validate the plan against all configured policy rules and return a ValidationResult

**Acceptance Criteria:**
1. Policies are loaded from `config/governance-policies.json`
2. Policy types supported: action, resource, sequence, rate, context
3. Policy effects supported: allow, deny, require_approval
4. Policies are evaluated in priority order (higher priority first)
5. First matching "allow" rule permits action; "deny" blocks; "require_approval" queues
6. ValidationResult includes list of violations with rule_id, severity, and message
7. Sequence policies detect forbidden action combinations within configurable window

---

### FR-4: Governance Decision

**Objective:** As the proxy system, I want a clear governance decision for each request, so that I can allow, block, or queue the request appropriately.

**EARS Specification:**
WHEN policy validation completes
THEN the system SHALL return a GovernanceDecision of ALLOW, BLOCK, REQUIRE_APPROVAL, or RATE_LIMITED

**Acceptance Criteria:**
1. BLOCK decision returns HTTP 403 with violation details
2. REQUIRE_APPROVAL decision returns HTTP 202 with approval_id
3. ALLOW decision permits forwarding to OpenClaw with governance headers injected
4. RATE_LIMITED decision returns HTTP 429
5. All decisions are logged as audit events with full context

---

### FR-5: Plan Storage

**Objective:** As the execution enforcer, I want approved plans stored persistently, so that I can validate tool invocations against them.

**EARS Specification:**
WHEN a plan is approved (decision = ALLOW or approval granted)
THEN the system SHALL store the plan in the Plan Store and issue a signed plan token

**Acceptance Criteria:**
1. Plans stored in SQLite database at configurable path
2. Plan token is HMAC-signed with server secret
3. Token includes: plan_id, issued_at, expires_at, signature
4. Token TTL is configurable (default: 900 seconds)
5. Plan lookup by plan_id completes within 5ms

---

### FR-6: Execution Enforcement

**Objective:** As a security administrator, I want tool invocations validated against approved plans, so that agents cannot execute unplanned actions.

**EARS Specification:**
WHEN a request to `/skills/*` is received with X-Governance-Plan-Id and X-Governance-Token headers
THEN the system SHALL verify the token signature, lookup the plan, and validate the action matches the expected sequence

**Acceptance Criteria:**
1. Invalid or missing token returns HTTP 403
2. Expired token returns HTTP 403 with "token_expired" error
3. Action not in plan returns HTTP 403 with "unplanned_action" error
4. Action out of sequence returns HTTP 403 with "sequence_violation" error
5. Valid action advances the sequence pointer and permits execution
6. Bounded retries (configurable, default: 3) allowed for same action without advancing sequence

---

### FR-7: Strict Sequence Ordering

**Objective:** As a security administrator, I want actions executed in exact plan order, so that reordering attacks are prevented.

**EARS Specification:**
WHILE enforcing plan execution
THE system SHALL require actions to execute in the exact sequence specified in the plan

**Acceptance Criteria:**
1. Each action has a sequence number (0-indexed)
2. Current sequence pointer tracked per plan
3. Action at position N only allowed when pointer is at N
4. Out-of-order action blocked with "sequence_violation" error
5. Retry of action at current position allowed without advancing pointer

---

### FR-8: Human-in-the-Loop Approval

**Objective:** As a user, I want to approve high-risk actions before they execute, so that I maintain control over agent behavior.

**EARS Specification:**
WHEN a governance decision is REQUIRE_APPROVAL
THEN the system SHALL create an ApprovalRequest, store the original request, and return HTTP 202 with approval details

**Acceptance Criteria:**
1. ApprovalRequest stored in SQLite with unique approval_id
2. Original request body stored for retry after approval
3. Approval has configurable timeout (default: 3600 seconds)
4. Expired approvals automatically transition to EXPIRED status
5. Approval endpoint: POST /governance/approvals/{id}/approve
6. Rejection endpoint: POST /governance/approvals/{id}/reject
7. Status endpoint: GET /governance/approvals/{id}

---

### FR-9: Self-Approval Validation

**Objective:** As a security administrator, I want to ensure users can only approve their own requests, so that one user cannot approve another's actions.

**EARS Specification:**
WHEN an approval request is submitted
THEN the system SHALL verify the approver's identity matches the original requester

**Acceptance Criteria:**
1. Requester identity stored with ApprovalRequest (from X-User-Id header or auth context)
2. Approver identity extracted from approval request
3. Mismatch returns HTTP 403 with "approver_mismatch" error
4. Self-approval validation can be disabled via config for admin-only approval flows

---

### FR-10: Messaging Channel Approval

**Objective:** As a Telegram/WhatsApp user, I want to approve actions via inline buttons, so that I don't need to access a web UI.

**EARS Specification:**
WHEN an approval is required for a request from a messaging channel
THEN the system SHALL return approval details suitable for inline button rendering

**Acceptance Criteria:**
1. 202 response includes `original_request_body` for bot retry
2. Approval response includes `approval_token` for authenticated retry
3. GET /governance/approvals/{id} returns full approval state including original request
4. Approval timeout shorter than messaging platform button expiry (configurable)

---

### FR-11: Session Management

**Objective:** As a security administrator, I want to track multi-turn conversation context, so that I can apply rate limits and sequence policies across requests.

**EARS Specification:**
WHILE a session is active
THE system SHALL track action history and accumulated risk for the session

**Acceptance Criteria:**
1. Session identified by X-Governance-Session-Id header or generated UUID
2. Sessions stored in SQLite with TTL (configurable, default: 3600 seconds)
3. Action history tracked per session (configurable limit, default: 100)
4. Risk accumulator updated with each action's risk score
5. Session lookup by session_id completes within 5ms

---

### FR-12: Rate Limiting

**Objective:** As a security administrator, I want to limit the rate of actions per session, so that abuse is prevented.

**EARS Specification:**
IF the action count exceeds the configured rate limit
THEN the system SHALL return GovernanceDecision.RATE_LIMITED

**Acceptance Criteria:**
1. Rate limits configurable: max_actions_per_session, max_actions_per_minute
2. Rate limit violations return HTTP 429
3. Rate limit state tracked in session
4. Rate limits can be disabled via config

---

### FR-13: Token Propagation

**Objective:** As the proxy, I want governance headers automatically propagated to OpenClaw, so that skill invocations can be validated.

**EARS Specification:**
WHEN forwarding a request to OpenClaw after governance approval
THEN the system SHALL inject X-Governance-Plan-Id and X-Governance-Token headers

**Acceptance Criteria:**
1. Headers injected into forwarded request
2. OpenClaw expected to echo headers on /skills/* callbacks
3. Missing headers on skill invocation triggers enforcement block

---

### FR-14: Audit Logging

**Objective:** As a security auditor, I want all governance decisions logged, so that I have complete traceability.

**EARS Specification:**
WHEN a governance decision is made
THEN the system SHALL log an AuditEvent with the decision, plan details, and any violations

**Acceptance Criteria:**
1. New AuditEventType values: GOVERNANCE_ALLOW, GOVERNANCE_BLOCK, GOVERNANCE_APPROVAL_REQUIRED, GOVERNANCE_APPROVED, GOVERNANCE_REJECTED, GOVERNANCE_ENFORCE_BLOCK
2. Audit events include: plan_id, session_id, decision, violations, risk_level
3. Enforcement blocks logged with action details and reason
4. Audit events written to existing append-only audit log with hash chain

---

### FR-15: Configuration Management

**Objective:** As an operator, I want governance behavior configurable via JSON files, so that I can tune policies without code changes.

**EARS Specification:**
The system SHALL load governance configuration from JSON files at startup

**Acceptance Criteria:**
1. `config/governance-settings.json` - feature toggles and thresholds
2. `config/governance-policies.json` - policy rules
3. `config/intent-patterns.json` - tool-to-category mappings
4. Invalid config fails startup with clear error message
5. Config schema validated at load time

---

## Non-Functional Requirements

### NFR-1: Performance

The system SHALL process governance evaluation within 50ms for 95% of requests

**Acceptance Criteria:**
1. Intent classification < 10ms
2. Policy validation < 20ms
3. Plan storage < 10ms
4. Token verification < 5ms
5. Total governance overhead < 50ms p95

---

### NFR-2: Security

The system SHALL implement security controls aligned with OWASP guidelines

**Acceptance Criteria:**
1. Plan tokens HMAC-signed with SHA-256 using server secret
2. Constant-time token comparison to prevent timing attacks
3. Fail-closed design: governance failure blocks request
4. No secrets in audit logs (token signatures redacted)
5. Input validation on all policy conditions
6. SQL injection prevention via parameterized queries

---

### NFR-3: Reliability

The system SHALL maintain governance state durably

**Acceptance Criteria:**
1. SQLite databases use WAL mode for crash recovery
2. Plan Store survives proxy restart
3. Approval state survives proxy restart
4. Session state has configurable TTL with automatic cleanup

---

### NFR-4: Observability

The system SHALL provide observability into governance operations

**Acceptance Criteria:**
1. All decisions logged to audit trail
2. Metrics: governance_decisions_total (by decision type), governance_latency_ms, approval_pending_count
3. Health endpoint includes governance component status

---

## Constraints

1. Must integrate with existing proxy architecture without modifying OpenClaw
2. Must use SQLite for state storage (consistent with existing quarantine pattern)
3. Must use existing AuditLogger for audit events
4. Must follow existing Pydantic frozen model patterns
5. Python 3.12+ required

## Assumptions

1. OpenClaw will echo X-Governance-* headers on skill invocations
2. Tool calls are in OpenAI-compatible format (tools array with name/arguments)
3. Messaging bot adapters handle 202 responses and button rendering
4. Server secret for HMAC signing is provided via environment variable
