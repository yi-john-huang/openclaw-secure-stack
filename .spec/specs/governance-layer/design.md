# Design: Governance Layer

## Overview

The Governance Layer is a modular security component that slots into the existing proxy architecture to provide pre-execution intent classification, plan generation, policy validation, and execution-time enforcement. It follows the project's established patterns: layered architecture, dependency injection, immutable Pydantic models, and fail-closed design.

## Architecture Pattern

**Pattern:** Layered Architecture with Pipeline Processing

**Rationale:**
- Consistent with existing proxy → sanitizer → upstream flow
- Each layer has single responsibility (SRP)
- Components communicate via well-defined interfaces (ISP)
- Dependencies injected at construction (DIP)

## Component Diagram

```
                    ┌─────────────────────────────────────────────────────┐
                    │                 GovernanceMiddleware                │
                    │  (Orchestrator - coordinates all governance flow)   │
                    └─────────────────────────────────────────────────────┘
                                           │
           ┌───────────────┬───────────────┼───────────────┬──────────────┐
           │               │               │               │              │
           ▼               ▼               ▼               ▼              ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐
    │  Classifier │ │   Planner   │ │  Validator  │ │  Approver   │ │ Session  │
    │             │ │             │ │             │ │             │ │ Manager  │
    └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘
           │               │               │               │              │
           └───────────────┴───────────────┼───────────────┴──────────────┘
                                           │
                                           ▼
                              ┌─────────────────────────┐
                              │       Plan Store        │
                              │     (SQLite + WAL)      │
                              └─────────────────────────┘
                                           │
                                           ▼
                    ┌─────────────────────────────────────────────────────┐
                    │                GovernanceEnforcer                   │
                    │    (Validates /skills/* against stored plans)       │
                    └─────────────────────────────────────────────────────┘
```

## Data Flow

```
Request arrives at proxy
         │
         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ REQUEST-TIME GOVERNANCE                                                 │
│                                                                         │
│  1. Classifier.classify(body) → Intent                                  │
│  2. Planner.generate(intent) → ExecutionPlan                            │
│  3. Validator.validate(plan, session) → ValidationResult                │
│  4. IF violations with deny → return BLOCK                              │
│  5. IF violations with require_approval → Approver.create() → 202       │
│  6. PlanStore.store(plan) → plan_id, token                              │
│  7. Return ALLOW with headers                                           │
└─────────────────────────────────────────────────────────────────────────┘
         │
         ▼ (forwarded to OpenClaw with X-Governance-* headers)
         │
         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ EXECUTION-TIME ENFORCEMENT (on /skills/* callback)                      │
│                                                                         │
│  1. Extract plan_id, token from headers                                 │
│  2. Enforcer.verify_token(token) → valid/expired                        │
│  3. PlanStore.lookup(plan_id) → ExecutionPlan                           │
│  4. Enforcer.validate_action(plan, action) → match/drift                │
│  5. IF valid → advance sequence, permit                                 │
│  6. IF invalid → return 403, log GOVERNANCE_ENFORCE_BLOCK               │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Components

### 1. IntentClassifier (`src/governance/classifier.py`)

**Type:** Service

**Purpose:** Extract and classify tool calls from request body into intent categories.

**Responsibilities:**
- Parse tool calls from OpenAI-compatible format
- Match tool names against configurable category mappings
- Analyze arguments for sensitive patterns
- Calculate confidence scores

**Interface:**
```python
class IntentClassifier:
    def __init__(self, patterns_path: str) -> None: ...

    def classify(self, body: dict[str, object]) -> Intent:
        """Classify tool calls in request body."""
        ...

    def _extract_tool_calls(self, body: dict[str, object]) -> list[ToolCall]:
        """Extract tool calls from OpenAI format."""
        ...

    def _categorize_tool(self, tool_name: str) -> IntentCategory:
        """Map tool name to category via patterns."""
        ...

    def _analyze_arguments(self, arguments: dict[str, object]) -> list[IntentSignal]:
        """Check arguments for sensitive patterns."""
        ...
```

**Dependencies:**
- `config/intent-patterns.json` (loaded at init)

**Error Handling:**
- Missing patterns file: raise `ConfigurationError` at startup
- Malformed body: return Intent with UNKNOWN category
- No tool calls: return Intent with empty tool_calls list

---

### 2. PlanGenerator (`src/governance/planner.py`)

**Type:** Service

**Purpose:** Generate auditable execution plans from classified intents.

**Responsibilities:**
- Create unique plan_id (UUID4)
- Build ordered PlannedAction sequence
- Calculate resource access patterns
- Compute risk assessment

**Interface:**
```python
class PlanGenerator:
    def __init__(self, risk_multipliers: dict[str, float] | None = None) -> None: ...

    def generate(self, intent: Intent, session_id: str | None = None) -> ExecutionPlan:
        """Generate execution plan from classified intent."""
        ...

    def _build_actions(self, tool_calls: list[ToolCall], signals: list[IntentSignal]) -> list[PlannedAction]:
        """Build ordered action sequence."""
        ...

    def _extract_resources(self, tool_call: ToolCall) -> list[ResourceAccess]:
        """Extract resources from tool arguments."""
        ...

    def _assess_risk(self, actions: list[PlannedAction]) -> RiskAssessment:
        """Calculate overall risk assessment."""
        ...
```

**Dependencies:**
- None (stateless)

**Error Handling:**
- Empty intent: return plan with empty actions
- Risk calculation overflow: cap at 100

---

### 3. PolicyValidator (`src/governance/validator.py`)

**Type:** Service

**Purpose:** Validate execution plans against configurable policy rules.

**Responsibilities:**
- Load and parse policy rules from config
- Evaluate rules in priority order
- Detect sequence policy violations
- Enforce rate limits via session context

**Interface:**
```python
class PolicyValidator:
    def __init__(self, policies_path: str) -> None: ...

    def validate(self, plan: ExecutionPlan, session: Session | None = None) -> ValidationResult:
        """Validate plan against all policies."""
        ...

    def _check_action_policies(self, action: PlannedAction) -> list[PolicyViolation]:
        """Check action against action-type policies."""
        ...

    def _check_resource_policies(self, action: PlannedAction) -> list[PolicyViolation]:
        """Check resource access against resource policies."""
        ...

    def _check_sequence_policies(self, plan: ExecutionPlan) -> list[PolicyViolation]:
        """Check for forbidden action sequences."""
        ...

    def _check_rate_policies(self, session: Session | None) -> list[PolicyViolation]:
        """Check rate limits against session state."""
        ...
```

**Dependencies:**
- `config/governance-policies.json` (loaded at init)

**Error Handling:**
- Missing policies file: raise `ConfigurationError`
- Invalid policy format: raise `ConfigurationError` with details
- No matching rules: return ValidationResult with decision=ALLOW

---

### 4. ApprovalGate (`src/governance/approver.py`)

**Type:** Service

**Purpose:** Manage human-in-the-loop approval workflow.

**Responsibilities:**
- Create and store approval requests
- Validate approver identity
- Handle approval/rejection
- Manage expiration

**Interface:**
```python
class ApprovalGate:
    def __init__(self, db: GovernanceDB, settings: ApprovalSettings) -> None: ...

    def create_request(
        self,
        plan: ExecutionPlan,
        violations: list[PolicyViolation],
        requester_id: str | None,
        original_request: dict[str, object],
    ) -> ApprovalRequest:
        """Create pending approval request."""
        ...

    def get_request(self, approval_id: str) -> ApprovalRequest | None:
        """Get approval request by ID."""
        ...

    def approve(self, approval_id: str, approver_id: str, acknowledgment: str) -> ApprovalRecord:
        """Approve pending request."""
        ...

    def reject(self, approval_id: str, approver_id: str, reason: str) -> ApprovalRecord:
        """Reject pending request."""
        ...

    def _validate_self_approval(self, request: ApprovalRequest, approver_id: str) -> None:
        """Validate approver matches requester if self-approval enabled."""
        ...
```

**Dependencies:**
- `GovernanceDB` (injected)
- `ApprovalSettings` (from config)

**Error Handling:**
- Request not found: raise `ApprovalNotFoundError`
- Request expired: raise `ApprovalExpiredError`
- Approver mismatch: raise `ApproverMismatchError`

---

### 5. SessionManager (`src/governance/session.py`)

**Type:** Service

**Purpose:** Track multi-turn conversation context for rate limiting and sequence policies.

**Responsibilities:**
- Create or retrieve sessions by ID
- Track action history per session
- Accumulate risk scores
- Handle TTL expiration

**Interface:**
```python
class SessionManager:
    def __init__(self, db: GovernanceDB, settings: SessionSettings) -> None: ...

    def get_or_create(self, session_id: str | None) -> Session:
        """Get existing session or create new one."""
        ...

    def record_action(self, session_id: str, action: PlannedAction, decision: GovernanceDecision) -> None:
        """Record action in session history."""
        ...

    def get_history(self, session_id: str, limit: int = 100) -> list[ActionRecord]:
        """Get action history for session."""
        ...

    def cleanup_expired(self) -> int:
        """Remove expired sessions, return count deleted."""
        ...
```

**Dependencies:**
- `GovernanceDB` (injected)
- `SessionSettings` (from config)

**Error Handling:**
- Session not found: create new session
- History limit exceeded: truncate oldest entries

---

### 6. PlanStore (`src/governance/store.py`)

**Type:** Repository

**Purpose:** Persist execution plans and manage plan tokens.

**Responsibilities:**
- Store plans in SQLite
- Issue HMAC-signed tokens
- Lookup plans by ID
- Track sequence progress

**Interface:**
```python
class PlanStore:
    def __init__(self, db: GovernanceDB, secret: str, token_ttl: int = 900) -> None: ...

    def store(self, plan: ExecutionPlan) -> tuple[str, str]:
        """Store plan, return (plan_id, token)."""
        ...

    def lookup(self, plan_id: str) -> StoredPlan | None:
        """Lookup plan by ID."""
        ...

    def advance_sequence(self, plan_id: str) -> int:
        """Advance sequence pointer, return new position."""
        ...

    def get_current_sequence(self, plan_id: str) -> int:
        """Get current sequence pointer position."""
        ...

    def _issue_token(self, plan_id: str) -> str:
        """Generate HMAC-signed token."""
        ...

    def verify_token(self, token: str) -> TokenVerification:
        """Verify token signature and expiration."""
        ...
```

**Dependencies:**
- `GovernanceDB` (injected)
- Server secret (from environment)

**Error Handling:**
- Plan not found: return None
- Token expired: return TokenVerification with expired=True
- Invalid signature: return TokenVerification with valid=False

---

### 7. GovernanceEnforcer (`src/governance/enforcer.py`)

**Type:** Service

**Purpose:** Validate tool invocations against stored plans at execution time.

**Responsibilities:**
- Extract governance headers from request
- Verify plan token
- Validate action matches plan sequence
- Handle retry semantics

**Interface:**
```python
class GovernanceEnforcer:
    def __init__(self, store: PlanStore, settings: EnforcementSettings) -> None: ...

    def verify(self, request: Request, plan_id: str | None, token: str | None) -> EnforcementResult:
        """Verify request against stored plan."""
        ...

    def _extract_action(self, request: Request) -> ToolCall:
        """Extract tool call from skill invocation request."""
        ...

    def _match_action(self, action: ToolCall, plan: StoredPlan) -> ActionMatch:
        """Check if action matches expected sequence position."""
        ...

    def _is_retry(self, action: ToolCall, plan: StoredPlan) -> bool:
        """Check if this is a retry of the current action."""
        ...
```

**Dependencies:**
- `PlanStore` (injected)
- `EnforcementSettings` (from config)

**Error Handling:**
- Missing headers: return blocked with "missing_governance_headers"
- Invalid token: return blocked with "invalid_token"
- Expired token: return blocked with "token_expired"
- Sequence violation: return blocked with "sequence_violation"

---

### 8. GovernanceMiddleware (`src/governance/middleware.py`)

**Type:** Orchestrator

**Purpose:** Coordinate all governance components in the request flow.

**Responsibilities:**
- Orchestrate classification → planning → validation pipeline
- Inject governance headers on ALLOW
- Return appropriate HTTP responses
- Log all decisions to audit trail

**Interface:**
```python
class GovernanceMiddleware:
    def __init__(
        self,
        classifier: IntentClassifier,
        planner: PlanGenerator,
        validator: PolicyValidator,
        approver: ApprovalGate | None,
        session_manager: SessionManager | None,
        store: PlanStore,
        audit_logger: AuditLogger | None,
        settings: GovernanceSettings,
    ) -> None: ...

    async def evaluate(self, request: Request, body: dict[str, object]) -> GovernanceResult:
        """Evaluate request and return governance decision."""
        ...

    def _log_decision(self, result: GovernanceResult) -> None:
        """Log governance decision to audit trail."""
        ...
```

**Dependencies:**
- All governance components (injected)
- `AuditLogger` (optional, injected)

**Error Handling:**
- Component failure: return BLOCK (fail-closed)
- Log errors but don't expose internals

---

### 9. GovernanceDB (`src/governance/db.py`)

**Type:** Repository

**Purpose:** SQLite database operations for all governance state.

**Responsibilities:**
- Manage database connection with WAL mode
- Provide parameterized query execution
- Handle schema migrations
- Support transactional operations

**Interface:**
```python
class GovernanceDB:
    def __init__(self, db_path: str) -> None: ...

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> sqlite3.Cursor:
        """Execute parameterized query."""
        ...

    def execute_many(self, sql: str, params_list: list[tuple[object, ...]]) -> None:
        """Execute batch of parameterized queries."""
        ...

    def fetch_one(self, sql: str, params: tuple[object, ...] = ()) -> sqlite3.Row | None:
        """Fetch single row."""
        ...

    def fetch_all(self, sql: str, params: tuple[object, ...] = ()) -> list[sqlite3.Row]:
        """Fetch all rows."""
        ...

    def _init_schema(self) -> None:
        """Initialize database schema."""
        ...
```

**Dependencies:**
- SQLite (stdlib)

**Error Handling:**
- Database locked: retry with backoff
- Schema migration failure: raise `DatabaseError`

---

### 10. GovernanceAPI (`src/governance/api.py`)

**Type:** Controller

**Purpose:** FastAPI endpoints for approval management.

**Responsibilities:**
- Expose approval CRUD endpoints
- Validate request authentication
- Return appropriate responses

**Interface:**
```python
def create_governance_router(approver: ApprovalGate) -> APIRouter:
    """Create FastAPI router for governance endpoints."""

    @router.get("/governance/approvals/{approval_id}")
    async def get_approval(approval_id: str) -> ApprovalResponse: ...

    @router.post("/governance/approvals/{approval_id}/approve")
    async def approve_request(approval_id: str, body: ApproveBody) -> ApprovalResponse: ...

    @router.post("/governance/approvals/{approval_id}/reject")
    async def reject_request(approval_id: str, body: RejectBody) -> ApprovalResponse: ...
```

**Dependencies:**
- `ApprovalGate` (injected)

**Error Handling:**
- Not found: return 404
- Expired: return 410 Gone
- Approver mismatch: return 403

---

## Data Models

### Enums (`src/governance/models.py`)

```python
class IntentCategory(str, Enum):
    """Categories of agent tool call intents."""
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    NETWORK_REQUEST = "network_request"
    CODE_EXECUTION = "code_execution"
    SKILL_INVOCATION = "skill_invocation"
    SYSTEM_COMMAND = "system_command"
    UNKNOWN = "unknown"


class GovernanceDecision(str, Enum):
    """Governance decision types."""
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    RATE_LIMITED = "rate_limited"


class ApprovalStatus(str, Enum):
    """Approval request status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
```

### Core Models

| Model | Purpose | Properties |
|-------|---------|------------|
| `ToolCall` | Extracted tool call | name: str, arguments: dict, id: str \| None |
| `IntentSignal` | Classification signal | category: IntentCategory, confidence: float, source: str, details: str \| None |
| `Intent` | Classified intent | primary_category: IntentCategory, signals: list[IntentSignal], tool_calls: list[ToolCall], confidence: float |
| `ResourceAccess` | Resource being accessed | type: str, path: str, operation: str |
| `PlannedAction` | Single planned action | sequence: int, tool_call: ToolCall, category: IntentCategory, resources: list[ResourceAccess], risk_score: int |
| `RiskAssessment` | Plan risk evaluation | overall_score: int, level: RiskLevel, factors: list[str], mitigations: list[str] |
| `ExecutionPlan` | Full execution plan | plan_id: str, session_id: str \| None, request_hash: str, actions: list[PlannedAction], risk_assessment: RiskAssessment, created_at: str |
| `PolicyRule` | Policy configuration | id: str, name: str, type: str, effect: str, conditions: dict, priority: int, description: str |
| `PolicyViolation` | Policy violation | rule_id: str, rule_name: str, severity: Severity, action_sequence: int \| None, resource: str \| None, message: str |
| `ValidationResult` | Validation outcome | valid: bool, violations: list[PolicyViolation], decision: GovernanceDecision, approval_required: bool |
| `ApprovalRequest` | Pending approval | approval_id: str, plan: ExecutionPlan, violations: list[PolicyViolation], requester_id: str \| None, original_request: dict, requested_at: str, expires_at: str, status: ApprovalStatus |
| `Session` | Conversation session | session_id: str, created_at: str, last_activity: str, action_count: int, risk_accumulator: int |
| `StoredPlan` | Persisted plan | plan: ExecutionPlan, current_sequence: int, retry_count: int |
| `TokenVerification` | Token check result | valid: bool, expired: bool, plan_id: str \| None |
| `EnforcementResult` | Enforcement outcome | allowed: bool, blocked: bool, reason: str \| None |
| `GovernanceResult` | Full governance result | decision: GovernanceDecision, plan_id: str \| None, token: str \| None, approval_id: str \| None, violations: list[PolicyViolation] |

### Model Invariants

All models use `model_config = ConfigDict(frozen=True)` for immutability.

**ExecutionPlan:**
- `plan_id` is UUID4 format
- `request_hash` is SHA-256 hex (64 chars)
- `actions` ordered by sequence number (0-indexed, contiguous)
- `risk_assessment.overall_score` in range [0, 100]

**PolicyRule:**
- `type` in {"action", "resource", "sequence", "rate", "context"}
- `effect` in {"allow", "deny", "require_approval"}
- `priority` >= 0 (higher = evaluated first)

**ApprovalRequest:**
- `expires_at` > `requested_at`
- `status` transitions: PENDING → APPROVED | REJECTED | EXPIRED

---

## Database Schema

```sql
-- Plans table
CREATE TABLE governance_plans (
    plan_id TEXT PRIMARY KEY,
    session_id TEXT,
    request_hash TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    current_sequence INTEGER DEFAULT 0,
    retry_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX idx_plans_session ON governance_plans(session_id);
CREATE INDEX idx_plans_expires ON governance_plans(expires_at);

-- Approvals table
CREATE TABLE governance_approvals (
    approval_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    violations_json TEXT NOT NULL,
    requester_id TEXT,
    original_request_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    acknowledgment TEXT,
    reason TEXT,
    FOREIGN KEY (plan_id) REFERENCES governance_plans(plan_id)
);

CREATE INDEX idx_approvals_status ON governance_approvals(status);
CREATE INDEX idx_approvals_expires ON governance_approvals(expires_at);

-- Sessions table
CREATE TABLE governance_sessions (
    session_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    action_count INTEGER DEFAULT 0,
    risk_accumulator INTEGER DEFAULT 0
);

CREATE INDEX idx_sessions_last_activity ON governance_sessions(last_activity);

-- Session actions table
CREATE TABLE governance_session_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    action_json TEXT NOT NULL,
    decision TEXT NOT NULL,
    executed_at TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES governance_sessions(session_id)
);

CREATE INDEX idx_session_actions_session ON governance_session_actions(session_id);
```

---

## Interfaces

### External APIs

| Method | Path | Description | Request | Response | Auth |
|--------|------|-------------|---------|----------|------|
| GET | /governance/approvals/{id} | Get approval status | - | ApprovalResponse | Bearer |
| POST | /governance/approvals/{id}/approve | Approve request | ApproveBody | ApprovalResponse | Bearer |
| POST | /governance/approvals/{id}/reject | Reject request | RejectBody | ApprovalResponse | Bearer |

### Request/Response Models

```python
class ApproveBody(BaseModel):
    acknowledgment: str  # Required acknowledgment text


class RejectBody(BaseModel):
    reason: str  # Required rejection reason


class ApprovalResponse(BaseModel):
    approval_id: str
    status: ApprovalStatus
    plan_id: str
    violations: list[PolicyViolation]
    requested_at: str
    expires_at: str
    original_request: dict[str, object] | None  # Included for messaging retry
    approval_token: str | None  # Included after approval for retry
```

### Internal Service Interfaces

```python
# Classification interface (ISP)
class IClassifier(Protocol):
    def classify(self, body: dict[str, object]) -> Intent: ...


# Plan generation interface (ISP)
class IPlanner(Protocol):
    def generate(self, intent: Intent, session_id: str | None = None) -> ExecutionPlan: ...


# Validation interface (ISP)
class IValidator(Protocol):
    def validate(self, plan: ExecutionPlan, session: Session | None = None) -> ValidationResult: ...


# Plan storage interface (ISP)
class IPlanStore(Protocol):
    def store(self, plan: ExecutionPlan) -> tuple[str, str]: ...
    def lookup(self, plan_id: str) -> StoredPlan | None: ...
    def verify_token(self, token: str) -> TokenVerification: ...
    def advance_sequence(self, plan_id: str) -> int: ...


# Enforcement interface (ISP)
class IEnforcer(Protocol):
    def verify(self, request: Request, plan_id: str | None, token: str | None) -> EnforcementResult: ...
```

---

## Error Handling Strategy

### Error Categories

| Category | HTTP Status | Retry | Log Level | Example |
|----------|-------------|-------|-----------|---------|
| Governance Block | 403 | No | WARN | Policy violation |
| Approval Required | 202 | Yes (after approval) | INFO | High-risk action |
| Rate Limited | 429 | Yes (backoff) | WARN | Session limit exceeded |
| Not Found | 404 | No | INFO | Approval not found |
| Expired | 410 | No | INFO | Approval/token expired |
| Unauthorized | 403 | No | WARN | Approver mismatch |
| Internal Error | 500 | Yes (limited) | ERROR | Database failure |

### Error Response Format

```json
{
  "error": {
    "code": "GOVERNANCE_BLOCK",
    "message": "Request blocked by policy",
    "violations": [
      {
        "rule_id": "GOV-001",
        "rule_name": "Block file deletion",
        "severity": "high",
        "message": "File deletion operations are not permitted"
      }
    ],
    "plan_id": "uuid-for-tracing"
  }
}
```

### Fail-Closed Behavior

```python
async def evaluate(self, request: Request, body: dict[str, object]) -> GovernanceResult:
    try:
        # Normal governance flow
        ...
    except Exception as e:
        # Fail closed: block on any error
        self._log_error(e)
        return GovernanceResult(
            decision=GovernanceDecision.BLOCK,
            violations=[PolicyViolation(
                rule_id="INTERNAL",
                rule_name="Governance Error",
                severity=Severity.CRITICAL,
                message="Governance evaluation failed",
            )],
        )
```

---

## Security Considerations

### Authentication
- Governance endpoints require existing Bearer token auth
- Approval endpoints validate user identity from auth context

### Token Security
- Plan tokens HMAC-SHA256 signed with server secret
- Constant-time comparison via `hmac.compare_digest()`
- Token includes: plan_id, issued_at, expires_at
- Token format: `base64(json(payload)).base64(signature)`

```python
def _issue_token(self, plan_id: str) -> str:
    payload = {
        "plan_id": plan_id,
        "issued_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(seconds=self.token_ttl)).isoformat(),
    }
    payload_bytes = json.dumps(payload).encode()
    signature = hmac.new(self.secret.encode(), payload_bytes, hashlib.sha256).digest()
    return f"{base64.urlsafe_b64encode(payload_bytes).decode()}.{base64.urlsafe_b64encode(signature).decode()}"
```

### Data Protection
- No secrets in audit logs (tokens redacted to first 8 chars)
- SQL injection prevented via parameterized queries
- Input validation on all policy conditions

### Audit Trail
- All decisions logged with full context
- Hash chain integrity from existing AuditLogger
- New event types for governance actions

---

## Testing Strategy

### Unit Tests (Target: 90% coverage)
- `test_classifier.py`: Tool extraction, category mapping, argument analysis
- `test_planner.py`: Plan generation, risk calculation, resource extraction
- `test_validator.py`: Policy evaluation, sequence detection, rate limiting
- `test_approver.py`: Approval lifecycle, expiration, self-approval
- `test_session.py`: Session CRUD, history tracking, TTL
- `test_store.py`: Plan storage, token signing, sequence tracking
- `test_enforcer.py`: Token verification, action matching, retry handling

### Integration Tests
- `test_governance_flow.py`: Full request → decision flow
- `test_enforcement_flow.py`: Plan approval → skill execution → validation
- `test_approval_flow.py`: 202 → approve → retry

### Security Tests
- Token tampering attempts
- Sequence manipulation attempts
- Self-approval bypass attempts
- Rate limit circumvention attempts

---

## Configuration Files

### `config/governance-settings.json`
```json
{
  "enabled": true,
  "mode": "enforce",
  "intent_classification": {
    "method": "pattern",
    "confidence_threshold": 0.7
  },
  "approval": {
    "enabled": true,
    "timeout_seconds": 3600,
    "allow_self_approval": true,
    "store_original_request": true
  },
  "session": {
    "enabled": true,
    "ttl_seconds": 3600,
    "max_history_size": 100
  },
  "enforcement": {
    "enabled": true,
    "token_ttl_seconds": 900,
    "max_retries": 3
  },
  "bypass_paths": ["/health", "/healthz", "/ready"]
}
```

### `config/governance-policies.json`
```json
[
  {
    "id": "GOV-001",
    "name": "Block file deletion",
    "type": "action",
    "effect": "deny",
    "conditions": {"category": "file_delete"},
    "priority": 100,
    "description": "Block all file deletion operations"
  },
  {
    "id": "GOV-002",
    "name": "Require approval for code execution",
    "type": "action",
    "effect": "require_approval",
    "conditions": {"category": "code_execution"},
    "priority": 90,
    "description": "Require human approval for code execution"
  },
  {
    "id": "GOV-003",
    "name": "Block external network",
    "type": "resource",
    "effect": "deny",
    "conditions": {
      "type": "url",
      "pattern": "^https?://(?!localhost|127\\.0\\.0\\.1).*"
    },
    "priority": 80,
    "description": "Block requests to external URLs"
  },
  {
    "id": "GOV-004",
    "name": "Flag data exfiltration pattern",
    "type": "sequence",
    "effect": "require_approval",
    "conditions": {
      "sequence": ["file_read", "network_request"],
      "within_actions": 3
    },
    "priority": 85,
    "description": "Flag file read followed by network request"
  },
  {
    "id": "GOV-005",
    "name": "Session rate limit",
    "type": "rate",
    "effect": "deny",
    "conditions": {
      "max_actions_per_session": 100,
      "max_actions_per_minute": 20
    },
    "priority": 70,
    "description": "Rate limit to prevent abuse"
  }
]
```

### `config/intent-patterns.json`
```json
{
  "tool_categories": {
    "file_read": ["read_file", "get_file_contents", "list_directory", "search_files", "glob"],
    "file_write": ["write_file", "create_file", "update_file", "append_file", "edit_file"],
    "file_delete": ["delete_file", "remove_file", "unlink", "rmdir"],
    "network_request": ["http_get", "http_post", "fetch_url", "api_call", "web_fetch"],
    "code_execution": ["execute_code", "run_script", "eval", "shell_command", "bash"],
    "skill_invocation": ["invoke_skill", "call_skill", "use_tool"]
  },
  "argument_patterns": {
    "sensitive_paths": [
      "^/etc/",
      "^/var/log/",
      "^\\.env",
      ".*password.*",
      ".*secret.*",
      ".*credential.*",
      ".*\\.pem$",
      ".*\\.key$"
    ],
    "external_urls": [
      "^https?://(?!localhost|127\\.0\\.0\\.1|api\\.openai\\.com|api\\.anthropic\\.com)"
    ]
  },
  "risk_multipliers": {
    "file_delete": 3.0,
    "code_execution": 2.5,
    "system_command": 2.5,
    "network_request": 1.5,
    "file_write": 1.2,
    "file_read": 1.0,
    "skill_invocation": 1.0,
    "unknown": 2.0
  }
}
```

---

## Integration with Existing Code

### Modifications to `src/proxy/app.py`

```python
def create_app(
    upstream_url: str,
    token: str,
    sanitizer: PromptSanitizer,
    audit_logger: AuditLogger | None = None,
    response_scanner: PromptSanitizer | None = None,
    quarantine_manager: QuarantineManager | None = None,
    governance_middleware: GovernanceMiddleware | None = None,  # NEW
    governance_enforcer: GovernanceEnforcer | None = None,      # NEW
) -> FastAPI:
    ...

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy(request: Request, path: str) -> Response:
        # Existing quarantine check for skills/
        if quarantine_manager and path.startswith("skills/"):
            ...

            # NEW: Execution enforcement
            if governance_enforcer:
                plan_id = request.headers.get("X-Governance-Plan-Id")
                plan_token = request.headers.get("X-Governance-Token")
                enforcement = governance_enforcer.verify(request, plan_id, plan_token)
                if enforcement.blocked:
                    return JSONResponse(
                        {"error": {"code": "GOVERNANCE_ENFORCE_BLOCK", "message": enforcement.reason}},
                        status_code=403,
                    )

        # Existing body parsing and sanitization
        body = await request.body()
        if request.method in ("POST", "PUT", "PATCH") and body:
            try:
                body_json = json.loads(body)
                body_json = _sanitize_body(body_json, sanitizer)

                # NEW: Request-time governance
                if governance_middleware:
                    result = await governance_middleware.evaluate(request, body_json)
                    if result.decision == GovernanceDecision.BLOCK:
                        return JSONResponse(
                            {"error": {"code": "GOVERNANCE_BLOCK", "violations": [v.model_dump() for v in result.violations]}},
                            status_code=403,
                        )
                    if result.decision == GovernanceDecision.REQUIRE_APPROVAL:
                        return JSONResponse(
                            {"status": "approval_required", "approval_id": result.approval_id, ...},
                            status_code=202,
                        )
                    if result.decision == GovernanceDecision.RATE_LIMITED:
                        return JSONResponse({"error": {"code": "RATE_LIMITED"}}, status_code=429)

                    # Inject governance headers for ALLOW
                    headers["X-Governance-Plan-Id"] = result.plan_id
                    headers["X-Governance-Token"] = result.token

                body = json.dumps(body_json).encode()
            ...
```

### Modifications to `src/models.py`

```python
class AuditEventType(str, Enum):
    # ... existing ...
    GOVERNANCE_ALLOW = "governance_allow"
    GOVERNANCE_BLOCK = "governance_block"
    GOVERNANCE_APPROVAL_REQUIRED = "governance_approval_required"
    GOVERNANCE_APPROVED = "governance_approved"
    GOVERNANCE_REJECTED = "governance_rejected"
    GOVERNANCE_ENFORCE_BLOCK = "governance_enforce_block"
```

---

## Linus-Style Quality Review

### 1. Taste - Is it elegant?
- **Yes**: Pipeline architecture mirrors existing proxy flow
- **Yes**: Single responsibility per component
- **Yes**: Clean interfaces between layers

### 2. Complexity - Is it simple?
- **Yes**: Each component does one thing
- **Watch**: Policy evaluation could get complex - keep rules simple
- **Watch**: Token format is straightforward (payload.signature)

### 3. Special Cases - Are edge cases handled?
- **Yes**: Retry semantics handled
- **Yes**: Expiration handled at multiple levels
- **Yes**: Fail-closed on errors
- **Yes**: Missing headers = blocked

### 4. Data Structures - Are they optimal?
- **Yes**: Frozen Pydantic models for immutability
- **Yes**: SQLite for durable state (consistent with quarantine)
- **Yes**: Sequence tracking via simple integer pointer

### 5. Code Organization - Is it maintainable?
- **Yes**: Follows existing project structure
- **Yes**: Clear separation of concerns
- **Yes**: Well-defined interfaces enable testing

---

## File Structure Summary

```
src/governance/
├── __init__.py
├── models.py         # All Pydantic models and enums
├── classifier.py     # IntentClassifier
├── planner.py        # PlanGenerator
├── validator.py      # PolicyValidator
├── approver.py       # ApprovalGate
├── session.py        # SessionManager
├── store.py          # PlanStore
├── enforcer.py       # GovernanceEnforcer
├── middleware.py     # GovernanceMiddleware
├── db.py             # GovernanceDB
└── api.py            # FastAPI router

config/
├── governance-settings.json
├── governance-policies.json
└── intent-patterns.json

tests/
├── unit/
│   ├── test_classifier.py
│   ├── test_planner.py
│   ├── test_validator.py
│   ├── test_approver.py
│   ├── test_session.py
│   ├── test_store.py
│   ├── test_enforcer.py
│   └── test_governance_middleware.py
└── integration/
    ├── test_governance_flow.py
    ├── test_enforcement_flow.py
    └── test_approval_flow.py
```

---

## Requirements Traceability

| Requirement | Component(s) | Verified By |
|-------------|--------------|-------------|
| FR-1: Intent Classification | IntentClassifier | test_classifier.py |
| FR-2: Plan Generation | PlanGenerator | test_planner.py |
| FR-3: Policy Validation | PolicyValidator | test_validator.py |
| FR-4: Governance Decision | GovernanceMiddleware | test_governance_middleware.py |
| FR-5: Plan Storage | PlanStore | test_store.py |
| FR-6: Execution Enforcement | GovernanceEnforcer | test_enforcer.py |
| FR-7: Strict Sequence Ordering | GovernanceEnforcer | test_enforcer.py |
| FR-8: Human-in-the-Loop | ApprovalGate | test_approver.py |
| FR-9: Self-Approval Validation | ApprovalGate | test_approver.py |
| FR-10: Messaging Channel | ApprovalGate, GovernanceAPI | test_approval_flow.py |
| FR-11: Session Management | SessionManager | test_session.py |
| FR-12: Rate Limiting | PolicyValidator, SessionManager | test_validator.py |
| FR-13: Token Propagation | GovernanceMiddleware | test_governance_flow.py |
| FR-14: Audit Logging | GovernanceMiddleware | test_governance_middleware.py |
| FR-15: Configuration | All components | All unit tests |
| NFR-1: Performance | All components | Benchmark tests |
| NFR-2: Security | PlanStore, GovernanceEnforcer | test_store.py, security tests |
| NFR-3: Reliability | GovernanceDB | test_db.py |
| NFR-4: Observability | GovernanceMiddleware | test_governance_middleware.py |
