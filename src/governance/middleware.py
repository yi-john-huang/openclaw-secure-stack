"""Governance middleware orchestrator.

This module provides the GovernanceMiddleware class that orchestrates:
- Intent classification
- Plan generation
- Policy validation
- Approval gate
- Session management
- Execution enforcement
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.governance.approver import ApprovalGate
from src.governance.classifier import IntentClassifier
from src.governance.enforcer import EnforcementResult, GovernanceEnforcer
from src.governance.models import (
    ApprovalRequest,
    GovernanceDecision,
    PolicyViolation,
    ToolCall,
    ExecutionPlan, EnhancedExecutionPlan,
)
from src.governance.planner import PlanGenerator
from src.governance.session import SessionManager
from src.governance.store import PlanStore
from src.governance.validator import PolicyValidator
from src.llm.client import LLMClient

logger = logging.getLogger(__name__)


@dataclass
class EvaluationResult:
    """Result of governance evaluation."""

    decision: GovernanceDecision
    plan_id: str | None = None
    token: str | None = None
    session_id: str | None = None
    violations: list[PolicyViolation] = field(default_factory=list)
    approval_id: str | None = None
    message: str | None = None


@dataclass
class ApprovalResult:
    """Result of an approval action."""

    approval: ApprovalRequest
    plan_id: str | None = None
    token: str | None = None


class GovernanceMiddleware:
    """Orchestrates all governance components.

    Provides a unified interface for:
    - Evaluating requests against policies
    - Generating execution plans
    - Managing approvals
    - Enforcing actions at runtime
    """

    def __init__(
        self,
        db_path: str,
        secret: str,
        policy_path: str,
        patterns_path: str,
        settings: dict[str, Any],
    ) -> None:
        """Initialize the governance middleware.

        Args:
            db_path: Path to the SQLite database file.
            secret: Secret key for token signing.
            policy_path: Path to the policy configuration file.
            patterns_path: Path to the intent patterns configuration file.
            settings: Middleware settings dictionary.
        """
        self._settings = settings
        self._enabled = settings.get("enabled", True)
        self._llm: LLMClient | None = None  # Lazy initialization

        if self._enabled:
            self._classifier = IntentClassifier(patterns_path)

            # Resolve schema path - prefer explicit absolute path from settings,
            # fall back to same directory as patterns_path (typically config/)
            enhancement_settings = settings.get("enhancement", {})
            schema_path = enhancement_settings.get("schema_path")

            if schema_path is None:
                # Default: look for execution-plan.json in same dir as patterns
                config_dir = Path(patterns_path).parent
                schema_path = str(config_dir / "execution-plan.json")
            elif not Path(schema_path).is_absolute():
                # Relative path: resolve from same dir as patterns
                config_dir = Path(patterns_path).parent
                schema_path = str(config_dir / schema_path)
            # else: absolute path, use as-is

            self._planner = PlanGenerator(patterns_path, schema_path=schema_path)
            self._validator = PolicyValidator(policy_path)
            self._store = PlanStore(db_path, secret)
            self._enforcer = GovernanceEnforcer(db_path, secret)

            approval_settings = settings.get("approval", {})
            self._approver = ApprovalGate(
                db_path,
                allow_self_approval=approval_settings.get("allow_self_approval", True),
            )
            self._approval_timeout = approval_settings.get("timeout_seconds", 3600)

            session_settings = settings.get("session", {})
            self._session_enabled = session_settings.get("enabled", True)
            if self._session_enabled:
                self._session_mgr = SessionManager(
                    db_path, ttl_seconds=session_settings.get("ttl_seconds", 3600)
                )

            enforcement_settings = settings.get("enforcement", {})
            self._enforcement_enabled = enforcement_settings.get("enabled", True)
            self._token_ttl = enforcement_settings.get("token_ttl_seconds", 900)

            # Enhancement settings
            self._enhancement_enabled = enhancement_settings.get("enabled", False)
            self._enhancement_context = enhancement_settings.get("default_context", {})

    def _get_llm(self) -> LLMClient:
        """Lazy-load LLM client on first use."""
        if self._llm is None:
            self._llm = LLMClient()
        return self._llm

    def evaluate(
        self,
        request_body: dict[str, Any],
        session_id: str | None,
        user_id: str,
    ) -> EvaluationResult:
        """Evaluate a request against governance policies.

        Args:
            request_body: The request body containing tools.
            session_id: Optional existing session ID.
            user_id: The requesting user's ID.

        Returns:
            EvaluationResult with decision and plan details.
        """
        # If disabled, allow everything
        if not self._enabled:
            return EvaluationResult(
                decision=GovernanceDecision.ALLOW,
                session_id=session_id,
            )

        # Get or create session
        if self._session_enabled:
            session = self._session_mgr.get_or_create(session_id)
            effective_session_id = session.session_id
        else:
            effective_session_id = session_id or str(uuid.uuid4())

        # Classify intent
        intent = self._classifier.classify(request_body)

        # Generate base plan from intent
        plan = self._planner.generate(
            intent=intent,
            request_body=request_body,
            session_id=effective_session_id,
        )

        # Get session for rate limiting
        session_for_validation = None
        if self._session_enabled:
            session_for_validation = self._session_mgr.get_or_create(effective_session_id)

        # Validate against policies
        validation = self._validator.validate(plan, session_for_validation)

        # Handle validation result
        if validation.decision == GovernanceDecision.BLOCK:
            return EvaluationResult(
                decision=GovernanceDecision.BLOCK,
                session_id=effective_session_id,
                violations=validation.violations,
                message="Request blocked by policy",
            )

        if validation.decision == GovernanceDecision.REQUIRE_APPROVAL:
            # Store plan in pending state (no token issued yet)
            self._store.store_pending(plan, ttl_seconds=self._approval_timeout)

            # Create approval request
            approval = self._approver.create_request(
                plan_id=plan.plan_id,
                violations=validation.violations,
                requester_id=user_id,
                original_request=request_body,
                timeout_seconds=self._approval_timeout,
            )
            return EvaluationResult(
                decision=GovernanceDecision.REQUIRE_APPROVAL,
                plan_id=plan.plan_id,
                session_id=effective_session_id,
                violations=validation.violations,
                approval_id=approval.approval_id,
                message="Approval required",
            )

        # Store plan and issue token
        plan_id, token = self._store.store(plan, ttl_seconds=self._token_ttl)

        # Optionally create enhanced plan (currently not persisted)
        if self._enhancement_enabled:
            self.create_enhanced_plan(
                plan, effective_session_id, user_id, token
            )

        # Record in session if enabled
        if self._session_enabled:
            for action in plan.actions:
                self._session_mgr.record_action(
                    session_id=effective_session_id,
                    action={"tool": action.tool_call.name, "sequence": action.sequence},
                    decision=GovernanceDecision.ALLOW,
                    risk_score=action.risk_score,
                )

        return EvaluationResult(
            decision=GovernanceDecision.ALLOW,
            plan_id=plan_id,
            token=token,
            session_id=effective_session_id,
            violations=[],
            message="Request allowed",
        )

    def create_enhanced_plan(
        self,
        basic_plan: ExecutionPlan,
        session_id: str | None,
        user_id: str,
        token: str,
    ) -> EnhancedExecutionPlan | None:
        """Create an enhanced plan from a basic plan.

        Args:
            basic_plan: The base execution plan.
            session_id: Session ID.
            user_id: User ID.
            token: Plan token.

        Returns:
            EnhancedExecutionPlan if successful, None if enhancement fails.
        """
        try:
            # Enhance with LLM
            enhanced_plan = self._planner.enhance(
                basic_plan,
                llm=self._get_llm(),
                context=self._enhancement_context,
            )

            enhanced_plan.initialize_state(
                session_id=session_id,
                user_id=user_id,
                token=token,
            )

            return enhanced_plan

        except Exception as e:
            # Enhancement is best-effort; never allow failures here to
            # impact core governance evaluation.
            # Log with full context so bugs are visible in logs
            logger.warning(
                "Plan enhancement failed: plan_id=%s, error_type=%s, error=%s",
                basic_plan.plan_id,
                type(e).__name__,
                e,
                exc_info=True,  # Include stack trace
            )
            return None

    def enforce(
        self,
        plan_id: str,
        token: str | None,
        tool_call: ToolCall,
    ) -> EnforcementResult:
        """Enforce governance policy for a tool call.

        Args:
            plan_id: The plan ID.
            token: The plan token.
            tool_call: The tool call to enforce.

        Returns:
            EnforcementResult indicating if the action is allowed.
        """
        if not self._enabled or not self._enforcement_enabled:
            return EnforcementResult(
                allowed=True,
                reason="Enforcement disabled",
                plan_id=plan_id,
            )

        return self._enforcer.enforce_action(plan_id, token, tool_call)

    def mark_action_complete(self, plan_id: str, sequence: int) -> None:
        """Mark an action as complete.

        Args:
            plan_id: The plan ID.
            sequence: The sequence number.
        """
        if self._enabled and self._enforcement_enabled:
            self._enforcer.mark_action_complete(plan_id, sequence)

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        """Get an approval request by ID.

        Args:
            approval_id: The approval request ID.

        Returns:
            The ApprovalRequest if found, None otherwise.
        """
        if not self._enabled:
            return None
        return self._approver.get(approval_id)

    def approve(
        self,
        approval_id: str,
        approver_id: str,
        acknowledgment: str,
    ) -> ApprovalResult:
        """Approve a pending request and activate the plan.

        Args:
            approval_id: The approval request ID.
            approver_id: ID of the user approving.
            acknowledgment: Acknowledgment text.

        Returns:
            ApprovalResult with the approval, plan_id, and token.
        """
        approval = self._approver.approve(approval_id, approver_id, acknowledgment)

        # Activate the plan and issue token
        plan_id, token = self._store.activate_plan(
            approval.plan_id,
            ttl_seconds=self._token_ttl,
        )

        return ApprovalResult(
            approval=approval,
            plan_id=plan_id,
            token=token,
        )

    def reject(
        self,
        approval_id: str,
        rejector_id: str,
        reason: str,
    ) -> ApprovalRequest:
        """Reject a pending request.

        Args:
            approval_id: The approval request ID.
            rejector_id: ID of the user rejecting.
            reason: Reason for rejection.

        Returns:
            The updated ApprovalRequest.
        """
        return self._approver.reject(approval_id, rejector_id, reason)

    def cleanup(self) -> dict[str, int]:
        """Clean up expired resources.

        Returns:
            Dictionary with counts of cleaned up resources.
        """
        if not self._enabled:
            return {}

        results = {}
        results["plans"] = self._store.cleanup_expired()
        if self._session_enabled:
            results["sessions"] = self._session_mgr.cleanup_expired()
        return results

    def close(self) -> None:
        """Close all database connections.

        Uses exception-safe cleanup to ensure all components are closed
        even if one fails.
        """
        if not self._enabled:
            return

        # Close all components - continue closing others even if one fails
        errors: list[Exception] = []
        components = ["_store", "_enforcer", "_approver", "_session_mgr"]

        for component_name in components:
            component = getattr(self, component_name, None)
            if component is not None:
                try:
                    component.close()
                except Exception as e:
                    errors.append(e)

        # Re-raise first error if any occurred
        if errors:
            raise errors[0]

    def __enter__(self) -> GovernanceMiddleware:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type | None,
        exc_val: Exception | None,
        exc_tb: object,
    ) -> None:
        """Context manager exit - close all connections."""
        self.close()