"""Governance layer for openclaw-secure-stack.

This module provides pre-execution governance including:
- Intent classification
- Plan generation
- Policy validation
- Approval flow
- Execution enforcement
"""

from src.governance.approver import (
    ApprovalExpiredError,
    ApprovalGate,
    ApprovalNotFoundError,
    ApproverMismatchError,
)
from src.governance.classifier import IntentClassifier
from src.governance.db import GovernanceDB
from src.governance.enforcer import EnforcementResult, GovernanceEnforcer
from src.governance.middleware import EvaluationResult, GovernanceMiddleware
from src.governance.models import (
    ApprovalRequest,
    ApprovalStatus,
    ExecutionPlan,
    GovernanceDecision,
    Intent,
    IntentCategory,
    IntentSignal,
    PlannedAction,
    PlanToken,
    PolicyEffect,
    PolicyRule,
    PolicyType,
    PolicyViolation,
    ResourceAccess,
    RiskAssessment,
    RiskLevel,
    Session,
    ToolCall,
    ValidationResult,
)
from src.governance.planner import PlanGenerator
from src.governance.session import SessionManager
from src.governance.store import PlanNotFoundError, PlanStore, TokenVerificationResult
from src.governance.validator import PolicyValidator

__all__ = [
    # Exceptions
    "ApprovalExpiredError",
    "ApprovalNotFoundError",
    "ApproverMismatchError",
    "PlanNotFoundError",
    # Components
    "ApprovalGate",
    "GovernanceDB",
    "GovernanceEnforcer",
    "GovernanceMiddleware",
    "IntentClassifier",
    "PlanGenerator",
    "PlanStore",
    "PolicyValidator",
    "SessionManager",
    # Result types
    "EnforcementResult",
    "EvaluationResult",
    "TokenVerificationResult",
    # Models
    "ApprovalRequest",
    "ApprovalStatus",
    "ExecutionPlan",
    "GovernanceDecision",
    "Intent",
    "IntentCategory",
    "IntentSignal",
    "PlannedAction",
    "PlanToken",
    "PolicyEffect",
    "PolicyRule",
    "PolicyType",
    "PolicyViolation",
    "ResourceAccess",
    "RiskAssessment",
    "RiskLevel",
    "Session",
    "ToolCall",
    "ValidationResult",
]
