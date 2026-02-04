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

from enum import Enum

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
