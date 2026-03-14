"""Governance layer Pydantic models.

This module defines all data models for the governance layer including:
- Intent classification (IntentCategory, Intent, IntentSignal)
- Plan generation (ExecutionPlan, PlannedAction, RiskAssessment)
- Policy validation (PolicyRule, PolicyViolation, ValidationResult)
- Approval flow (ApprovalRequest, ApprovalStatus)
- Session management (Session)
- Token handling (PlanToken)
- Execution plan v1.0.0 schema types (Step, StepDo, Constraints, etc.)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from src.models import RiskLevel, Severity

# --- Enums ---


# TODO: IntentCategory heuristic mapping — temporary mapping until
# intent classification stabilizes against the finalized enum schema
class IntentCategory(str, Enum):
    """Categories for classifying tool call intent."""

    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    NETWORK_REQUEST = "network_request"
    CODE_EXECUTION = "code_execution"
    SKILL_INVOCATION = "skill_invocation"
    SYSTEM_COMMAND = "system_command"
    UNKNOWN = "unknown"


class GovernanceDecision(str, Enum):
    """Possible governance decisions for a request."""

    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    RATE_LIMITED = "rate_limited"


class ApprovalStatus(str, Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class PolicyType(str, Enum):
    """Types of governance policies."""

    ACTION = "action"
    RESOURCE = "resource"
    SEQUENCE = "sequence"
    RATE = "rate"
    CONTEXT = "context"


class PolicyEffect(str, Enum):
    """Effect of a policy rule."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class TrustLevel(str, Enum):
    """User trust level."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DataSensitivity(str, Enum):
    """Data classification for execution."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    REGULATED = "regulated"


class ApprovalModel(str, Enum):
    """Approval requirement model."""
    NONE = "none"
    SELF = "self"
    PEER = "peer"
    MANAGER = "manager"


class OnFailBehavior(str, Enum):
    """Step failure handling strategy."""
    ABORT_PLAN = "abort_plan"
    ABORT_STEP = "abort_step"
    MARK_FAILED_AND_CONTINUE = "mark_failed_and_continue"
    COMPLETE_WITH_WARNING = "complete_with_warning"


class PatternType(str, Enum):
    """Pattern matching type."""
    EXACT = "exact"
    GLOB = "glob"
    REGEX = "regex"


class ArgPatternType(str, Enum):
    """Argument pattern matching type."""
    EXACT = "exact"
    GLOB = "glob"
    REGEX = "regex"
    RANGE = "range"


class CheckFrequency(str, Enum):
    """When to check abort conditions."""
    BEFORE_EACH_STEP = "before_each_step"
    AFTER_EACH_STEP = "after_each_step"
    CONTINUOUS = "continuous"


# --- Execution Plan v1.0.0 Schema Types ---


class FiveWOneH(BaseModel):
    """Structured intent breakdown."""
    model_config = ConfigDict(frozen=True)

    who: str | None = Field(None, description="Who/what executes (user, system, tool).")
    what: str | None = Field(None, description="Concrete operation being performed.")
    where: str | None = Field(None, description="Execution surface (path, service, environment).")
    when: str | None = Field(None, description="Timing (immediate, scheduled, conditional).")
    why: str | None = Field(None, description="User-facing reason.")
    how: str | None = Field(None, description="High-level method.")


class SurfaceEffects(BaseModel):
    """What resources are touched/modified/created/deleted."""
    model_config = ConfigDict(frozen=True)

    touches: list[str] = Field(..., min_length=1, description="Resources accessed.")
    modifies: bool = Field(..., description="Whether existing resources are modified.")
    creates: bool = Field(..., description="Whether new resources are created.")
    deletes: bool = Field(..., description="Whether resources are deleted.")


class Scope(BaseModel):
    """Hard scoping of where execution may touch."""
    model_config = ConfigDict(frozen=True)

    target_system: str = Field(..., description="Primary system (kubernetes, database, etc.).")
    environment: str = Field(..., description="Environment scope (prod, staging, dev).")
    allowed_systems: list[str] = Field(default_factory=list)
    forbidden_systems: list[str] = Field(default_factory=list)


class RequireApproval(BaseModel):
    """Approval requirements."""
    model_config = ConfigDict(frozen=True)

    model: ApprovalModel = ApprovalModel.NONE
    incident_reference_required: bool = False
    ticket_reference_required: bool = False


class Pattern(BaseModel):
    """Pattern for matching commands/paths/urls."""
    model_config = ConfigDict(frozen=True)

    pattern: str
    type: PatternType = PatternType.GLOB


class ArgPattern(BaseModel):
    """Pattern for matching arguments."""
    model_config = ConfigDict(frozen=True)

    pattern: str | None = None
    type: ArgPatternType = ArgPatternType.EXACT
    min: float | None = None
    max: float | None = None


class AllowDenyPatterns(BaseModel):
    """Allow/deny patterns for commands, paths, urls, args."""
    model_config = ConfigDict(frozen=True)

    commands: list[Pattern] = Field(default_factory=list)
    paths: list[Pattern] = Field(default_factory=list)
    urls: list[Pattern] = Field(default_factory=list)
    args: dict[str, str | list[str] | ArgPattern] = Field(default_factory=dict)


class Invariants(BaseModel):
    """Global invariants and refusal conditions."""
    model_config = ConfigDict(frozen=True)

    must_hold: list[str] = Field(default_factory=list, description="Must remain true during execution.")
    preconditions: list[str] = Field(default_factory=list, description="Must be true before execution.")
    refusal_conditions: list[str] = Field(default_factory=list, description="Causes executor to refuse.")


class InputSpec(BaseModel):
    """Input specification for a step."""
    model_config = ConfigDict(frozen=True)

    name: str
    type: str = Field(..., pattern="^(string|integer|number|boolean|array|object)$")
    source: str | None = Field(None, description="Where to obtain (ticket, previous_step, etc.).")
    constraints: dict[str, Any] = Field(default_factory=dict)


class CheckSpec(BaseModel):
    """Verification check for a step."""
    model_config = ConfigDict(frozen=True)

    name: str
    evidence: str = Field(..., description="What is observed.")
    pass_condition: str = Field(..., description="Deterministic condition.")


class StepInputs(BaseModel):
    """Required and optional inputs for a step."""
    model_config = ConfigDict(frozen=True)

    required: list[InputSpec] = Field(default_factory=list)
    optional: list[InputSpec] = Field(default_factory=list)


class AbortCondition(BaseModel):
    """Condition that triggers immediate plan termination."""
    model_config = ConfigDict(frozen=True)

    condition: str = Field(..., description="Machine-checkable condition expression.")
    reason: str = Field(..., description="Human-readable reason for audit.")
    check_frequency: CheckFrequency = CheckFrequency.BEFORE_EACH_STEP


class Metadata(BaseModel):
    """Non-execution metadata for audit and QA."""
    model_config = ConfigDict(frozen=True)

    generated_by: str | None = None
    quality_score: int | None = Field(None, ge=0, le=100)
    source_context_ref: str | None = None
    tags: list[str] = Field(default_factory=list)


class OutputSpec(BaseModel):
    """Output specification for a step."""
    model_config = ConfigDict(frozen=True)

    name: str
    type: str = Field(..., pattern="^(string|integer|number|boolean|array|object)$")
    write_to: str | None = Field(None, description="Destination (log, ticket, etc.).")
    constraints: dict[str, Any] = Field(default_factory=dict)


class StepDo(BaseModel):
    """The actual operation to perform."""
    model_config = ConfigDict(frozen=True)

    tool: str = Field(..., description="Tool name (exec, read, write, http, k8s, etc.).")
    operation: str = Field(..., description="Operation type within the tool.")
    target: str | None = Field(None, description="Target resource.")
    parameters: dict[str, Any] = Field(default_factory=dict)
    parameter_schema: StepInputs | None = None
    allow: AllowDenyPatterns | None = None
    deny: AllowDenyPatterns | None = None


class StepVerify(BaseModel):
    """How to verify step success."""
    model_config = ConfigDict(frozen=True)

    checks: list[CheckSpec] = Field(..., min_length=1)


class StepOnFail(BaseModel):
    """What to do if step fails."""
    model_config = ConfigDict(frozen=True)

    behavior: OnFailBehavior
    refuse_if: list[str] = Field(default_factory=list)
    required_log_entries: list[str] = Field(default_factory=list)


class StepAudit(BaseModel):
    """What to record from this step."""
    model_config = ConfigDict(frozen=True)

    record_outputs: list[OutputSpec] = Field(default_factory=list)


class Constraints(BaseModel):
    """Hard execution limits. Executor MUST enforce these."""
    model_config = ConfigDict(frozen=True)

    allow_unplanned: Literal[False] = Field(False, description="Must be false.")
    max_total_operations: int = Field(50, ge=1, description="Hard cap on total operations.")
    max_duration_ms: int = Field(300000, ge=1000, description="Plan execution timeout.")
    require_sequential: bool = Field(False, description="Force sequential execution.")
    max_parallelism: int = Field(1, ge=1, description="Max concurrent steps.")
    forbidden_paths: list[str] = Field(default_factory=list)
    forbidden_commands: list[str] = Field(default_factory=list)
    forbidden_urls: list[str] = Field(default_factory=list)
    allow: AllowDenyPatterns | None = None
    deny: AllowDenyPatterns | None = None
    data_sensitivity: DataSensitivity | None = None
    require_approval: RequireApproval = Field(default_factory=RequireApproval)


class UserContext(BaseModel):
    """Who is requesting/initiating execution."""
    model_config = ConfigDict(frozen=True)

    actor_id: str | None = Field(None, description="Authenticated user/service identifier.")
    role: str | None = Field(None, description="Role name used for policy routing.")
    trust_level: TrustLevel | None = None
    team: str | None = None
    access_tier: str | None = Field(None, description="Access tier (e.g., prod-read, prod-admin).")
    domain: str | None = Field(None, description="Domain ownership context.")
    oncall: bool | None = None


class Step(BaseModel):
    """A single executable step (v1.0.0 schema)."""
    model_config = ConfigDict(frozen=True)

    step: int = Field(..., ge=1, description="Step number.")
    action: str = Field(..., min_length=3, description="Human-readable action label.")
    depends_on: list[int] = Field(default_factory=list, description="Steps that must complete first.")
    parallel: bool = Field(False, description="Can run concurrently.")
    max_invocations: int = Field(1, ge=1, description="Max times step can execute.")
    timeout_ms: int | None = Field(None, ge=1, description="Step-specific timeout.")
    requires_confirmation: bool = Field(False, description="Requires human confirmation.")
    inputs: StepInputs = Field(default_factory=StepInputs)
    do: StepDo
    verify: StepVerify
    on_fail: StepOnFail
    audit: StepAudit = Field(default_factory=StepAudit)


# --- Core Models ---


class ToolCall(BaseModel):
    """Represents a tool call extracted from a request."""

    model_config = ConfigDict(frozen=True)

    name: str
    arguments: dict[str, object]
    id: str | None = None


class IntentSignal(BaseModel):
    """A signal contributing to intent classification."""

    model_config = ConfigDict(frozen=True)

    category: IntentCategory
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    details: str | None = None


class Intent(BaseModel):
    """Classified intent for a request."""

    model_config = ConfigDict(frozen=True)

    primary_category: IntentCategory
    signals: list[IntentSignal]
    tool_calls: list[ToolCall]
    confidence: float = Field(ge=0.0, le=1.0)


class EnhancedIntent(Intent):
    """LLM-generated structured intent used inside EnhancedExecutionPlan.

    Extends Intent with fields required by the v1.0.0 execution plan schema.
    """

    model_config = ConfigDict(frozen=True)

    summary: str = Field(..., min_length=10, description="Human-readable description.")
    user_message: str | None = Field(None, min_length=1, description="Original user request.")
    five_w_one_h: FiveWOneH = Field(default_factory=FiveWOneH)


class ResourceAccess(BaseModel):
    """Represents a resource being accessed by a tool call."""

    model_config = ConfigDict(frozen=True)

    type: str  # "file", "url", "api", etc.
    path: str
    operation: str  # "read", "write", "delete", "fetch", etc.


class PlannedAction(BaseModel):
    """A single action in an execution plan."""

    model_config = ConfigDict(frozen=True)

    sequence: int = Field(ge=0)
    tool_call: ToolCall
    category: IntentCategory
    resources: list[ResourceAccess]
    risk_score: int = Field(ge=0, le=100)


class RiskAssessment(BaseModel):
    """Risk assessment for an execution plan."""

    model_config = ConfigDict(frozen=True)

    overall_score: int = Field(ge=0, le=100)
    level: RiskLevel
    factors: list[str]
    mitigations: list[str]


class ExecutionPlan(BaseModel):
    """An auditable execution plan for a request."""

    model_config = ConfigDict(frozen=True)

    plan_id: str
    session_id: str | None
    request_hash: str = Field(min_length=64, max_length=64)
    actions: list[PlannedAction]
    risk_assessment: RiskAssessment


class PlanToken(BaseModel):
    """A signed token for plan verification."""

    model_config = ConfigDict(frozen=True)

    plan_id: str
    issued_at: str
    expires_at: str
    signature: str


# --- Policy Models ---


class PolicyRule(BaseModel):
    """A governance policy rule."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    type: PolicyType
    effect: PolicyEffect
    conditions: dict[str, object]
    priority: int = 0


class PolicyViolation(BaseModel):
    """A policy violation detected during validation."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Severity
    action_sequence: int | None
    message: str


class ValidationResult(BaseModel):
    """Result of policy validation."""

    model_config = ConfigDict(frozen=True)

    valid: bool
    violations: list[PolicyViolation]
    decision: GovernanceDecision
    approval_required: bool


# --- Approval Models ---


class ApprovalRequest(BaseModel):
    """A request for human approval."""

    model_config = ConfigDict(frozen=True)

    approval_id: str
    plan_id: str
    requester_id: str
    status: ApprovalStatus
    requested_at: str
    expires_at: str
    violations: list[PolicyViolation] = Field(default_factory=list)
    original_request: dict[str, object] | None = None
    acknowledgment: str | None = None
    reason: str | None = None


# --- Session Models ---


class Session(BaseModel):
    """Session tracking for multi-turn conversations."""

    model_config = ConfigDict(frozen=True)

    session_id: str
    created_at: str
    last_activity: str
    action_count: int = Field(ge=0)
    risk_accumulator: int = Field(ge=0)


class ExecutionMode(str, Enum):
    """How the plan should be executed."""

    # Governance drives execution, calls tools directly
    GOVERNANCE_DRIVEN = "governance_driven"

    # Plan is injected into LLM context, LLM executes
    AGENT_GUIDED = "agent_guided"

    # Hybrid: governance executes, LLM consulted for decisions
    HYBRID = "hybrid"


class StepStatus(str, Enum):
    """Status of a single execution step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"  # Blocked by governance
    AWAITING_APPROVAL = "awaiting_approval"
    RECOVERED = "recovered"  # Failed but recovered


class RecoveryStrategy(str, Enum):
    """Strategy for handling step failures."""

    FAIL_FAST = "fail_fast"  # Stop execution immediately
    RETRY = "retry"  # Retry the same step
    SKIP = "skip"  # Skip and continue
    ALTERNATIVE = "alternative"  # Try alternative step
    REPLAN = "replan"  # Generate new sub-plan
    HUMAN_INTERVENTION = "human_intervention"  # Wait for human


class StepResult(BaseModel):
    """Outcome of executing a single step."""

    model_config = ConfigDict(frozen=True)

    sequence: int = Field(ge=0)
    status: StepStatus
    started_at: str
    completed_at: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)

    # Tool execution details
    tool_name: str
    tool_args: dict[str, Any]
    tool_result: Any | None = None
    error: str | None = None

    # Governance checks
    governance_decision: GovernanceDecision | None = None
    governance_reason: str | None = None

    # Recovery details
    retry_count: int = Field(default=0, ge=0)
    recovery_action: RecoveryStrategy | None = None


class ExecutionContext(BaseModel):
    """Runtime context passed through execution."""

    model_config = ConfigDict(frozen=True)

    plan_id: str
    session_id: str
    user_id: str
    token: str

    # Execution configuration
    mode: ExecutionMode = ExecutionMode.GOVERNANCE_DRIVEN
    max_retries: int = Field(default=3, ge=0)
    timeout_seconds: int = Field(default=300, ge=1)
    fail_on_governance_block: bool = True

    # User-provided operational knowledge
    constraints: list[str] = Field(default_factory=list)
    preferences: dict[str, Any] = Field(default_factory=dict)


class ConditionalBranch(BaseModel):
    """Conditional execution branch."""

    model_config = ConfigDict(frozen=True)

    condition: str  # Expression to evaluate
    if_true: list[int] = Field(default_factory=list)  # Step sequences to run if true
    if_false: list[int] = Field(default_factory=list)  # Step sequences to run if false


class RecoveryPath(BaseModel):
    """Recovery path for a failed step."""

    model_config = ConfigDict(frozen=True)

    trigger_step: int  # Which step this recovers from
    trigger_errors: list[str] = Field(default_factory=list)  # Error patterns that trigger this
    strategy: RecoveryStrategy

    # For RETRY strategy
    max_retries: int = Field(default=3, ge=1)
    backoff_ms: int = Field(default=1000, ge=0)

    # For ALTERNATIVE strategy
    alternative_steps: list[PlannedAction] = Field(default_factory=list)

    # For REPLAN strategy
    replan_constraints: list[str] = Field(default_factory=list)


class ExecutionState(BaseModel):
    """Full state machine for plan execution."""

    plan_id: str
    session_id: str
    context: ExecutionContext

    # Current position
    current_sequence: int = Field(default=0, ge=0)
    status: StepStatus = StepStatus.PENDING

    # History
    step_results: list[StepResult] = Field(default_factory=list)

    # Timestamps
    started_at: str | None = None
    completed_at: str | None = None

    # Summary
    total_steps: int = Field(ge=0)
    completed_steps: int = Field(default=0, ge=0)
    failed_steps: int = Field(default=0, ge=0)
    skipped_steps: int = Field(default=0, ge=0)

    def is_complete(self) -> bool:
        """Check if execution is complete."""
        return self.current_sequence >= self.total_steps or self.status in (
            StepStatus.COMPLETED,
            StepStatus.FAILED,
            StepStatus.BLOCKED,
        )

    def get_progress(self) -> float:
        """Get execution progress as percentage."""
        if self.total_steps == 0:
            return 100.0
        return (self.completed_steps / self.total_steps) * 100


class EnhancedExecutionPlan(BaseModel):
    """Execution plan enhanced with LLM-generated operational knowledge.

    Wraps the base ExecutionPlan and adds:
    - Human-readable description
    - Constraints and preferences
    - Recovery paths
    - Conditional branches
    - Execution mode configuration

    v1.0.0 schema fields (steps, intent, surface_effects, etc.) are optional
    for backward compatibility. The follow-up PR will make them required and
    remove the legacy fields (description, preferences, recovery_paths, etc.).
    """

    # NOTE: frozen=False breaks immutability contract used by other models.
    # This is intentional but temporary - ExecutionState is embedded in the plan
    # for simplicity during initial development. Long-term fix: extract state
    # to a separate mutable container held by the execution engine, then freeze
    # this model. Deferred until plan structure stabilizes.
    model_config = ConfigDict(frozen=False)

    # Base plan (immutable spec)
    base_plan: ExecutionPlan

    # --- Legacy fields (will be removed in follow-up PR) ---
    # LLM-generated enhancements
    description: str | None = None
    constraints: list[str] = Field(default_factory=list)
    preferences: list[str] = Field(default_factory=list)
    recovery_paths: list[RecoveryPath] = Field(default_factory=list)
    conditionals: list[ConditionalBranch] = Field(default_factory=list)
    execution_mode: ExecutionMode = ExecutionMode.GOVERNANCE_DRIVEN

    # Schema-derived fields
    operations: list[dict[str, Any]] = Field(default_factory=list)
    global_constraints: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # --- v1.0.0 schema fields (optional for now) ---
    version: Literal["1.0.0"] = "1.0.0"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = Field(default_factory=lambda: datetime.now(UTC) + timedelta(hours=4))

    # Human-readable
    id: str | None = Field(None, pattern=r"^[a-z0-9_]+\.[a-z0-9_]+$", description="Plan type identifier.")
    description_for_user: str | None = Field(None, min_length=10)

    # LLM-generated (v1.0.0)
    intent: EnhancedIntent | None = None
    surface_effects: SurfaceEffects | None = None
    steps: list[Step] | None = None
    abort_conditions: list[AbortCondition] | None = None

    # Inherited/Injected
    user_context: UserContext | None = None
    scope: Scope | None = None
    v1_constraints: Constraints | None = Field(None, description="v1.0.0 structured constraints.")
    invariants: Invariants | None = None

    # v1.0.0 metadata
    v1_metadata: Metadata | None = None

    # Runtime state (initialized when execution starts)
    state: ExecutionState | None = None

    # Convenience accessors
    @property
    def plan_id(self) -> str:
        return self.base_plan.plan_id

    @property
    def session_id(self) -> str | None:
        return self.base_plan.session_id

    @property
    def actions(self) -> list[PlannedAction]:
        return self.base_plan.actions

    @property
    def risk_assessment(self) -> RiskAssessment:
        return self.base_plan.risk_assessment

    def initialize_state(self, session_id: str | None, user_id: str, token: str) -> None:
        """Initialize execution state. Call before execute().

        Args:
            session_id: Session ID (required).
            user_id: User ID.
            token: Plan token.

        Raises:
            ValueError: If session_id is None.
        """
        if session_id is None:
            raise ValueError("session_id is required for execution state initialization")

        context = ExecutionContext(
            plan_id=self.plan_id,
            session_id=session_id,
            user_id=user_id,
            token=token,
        )
        self.state = ExecutionState(
            plan_id=self.plan_id,
            session_id=session_id,
            context=context,
            current_sequence=0,
            status=StepStatus.PENDING,
            total_steps=len(self.actions),
            started_at=datetime.now(UTC).isoformat(),
        )