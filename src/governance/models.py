"""Governance layer Pydantic models.

This module defines all data models for the governance layer including:
- Intent classification (IntentCategory, Intent, IntentSignal)
- Plan generation (ExecutionPlan, PlannedAction, RiskAssessment)
- Policy validation (PolicyRule, PolicyViolation, ValidationResult)
- Approval flow (ApprovalRequest, ApprovalStatus)
- Session management (Session)
- Token handling (PlanToken)
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.models import RiskLevel, Severity

# --- Enums ---


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
    """

    model_config = ConfigDict(frozen=False)  # Mutable for state

    # Base plan (immutable spec)
    base_plan: ExecutionPlan

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