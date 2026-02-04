"""Execution enforcement for the governance layer.

This module provides the GovernanceEnforcer class for:
- Verifying plan tokens at execution time
- Validating tool calls against approved plans
- Enforcing action sequence ordering
- Tracking action completion
"""

from __future__ import annotations

from dataclasses import dataclass

from src.governance.models import ToolCall
from src.governance.store import PlanStore, TokenVerificationResult


@dataclass
class EnforcementResult:
    """Result of an enforcement check."""

    allowed: bool
    reason: str
    plan_id: str | None = None
    sequence: int | None = None


class GovernanceEnforcer:
    """Enforces governance policies at execution time.

    Provides:
    - Plan token verification
    - Tool call validation against plans
    - Sequence ordering enforcement
    - Action completion tracking
    """

    def __init__(self, db_path: str, secret: str) -> None:
        """Initialize the governance enforcer.

        Args:
            db_path: Path to the SQLite database file.
            secret: Secret key for token verification (should match PlanStore).
        """
        self._store = PlanStore(db_path, secret)

    def verify_plan_token(self, plan_id: str, token: str) -> TokenVerificationResult:
        """Verify a plan token.

        Args:
            plan_id: The plan ID.
            token: The token to verify.

        Returns:
            TokenVerificationResult with validity and expiration status.
        """
        return self._store.verify_token(plan_id, token)

    def enforce_action(
        self,
        plan_id: str,
        token: str | None,
        tool_call: ToolCall,
    ) -> EnforcementResult:
        """Enforce governance policy for a tool call.

        Validates that:
        1. A valid token is provided
        2. The plan exists
        3. The tool call matches the current action in the plan
        4. The action is at the expected sequence position

        Args:
            plan_id: The plan ID.
            token: The plan token.
            tool_call: The tool call to enforce.

        Returns:
            EnforcementResult indicating if the action is allowed.
        """
        # Check token presence
        if token is None:
            return EnforcementResult(
                allowed=False,
                reason="Token missing: plan token required for execution",
                plan_id=plan_id,
            )

        # Verify token
        token_result = self._store.verify_token(plan_id, token)
        if not token_result.valid:
            return EnforcementResult(
                allowed=False,
                reason=f"Invalid token: {token_result.error or 'verification failed'}",
                plan_id=plan_id,
            )
        if token_result.expired:
            return EnforcementResult(
                allowed=False,
                reason="Token expired: plan token has expired",
                plan_id=plan_id,
            )

        # Look up plan
        plan = self._store.lookup(plan_id)
        if plan is None:
            return EnforcementResult(
                allowed=False,
                reason=f"Plan not found: {plan_id}",
                plan_id=plan_id,
            )

        # Get current sequence position
        try:
            current_seq = self._store.get_current_sequence(plan_id)
        except Exception:
            return EnforcementResult(
                allowed=False,
                reason=f"Plan not found: {plan_id}",
                plan_id=plan_id,
            )

        # Find matching action in plan
        matching_action = None
        for action in plan.actions:
            if self._tool_calls_match(action.tool_call, tool_call):
                matching_action = action
                break

        if matching_action is None:
            return EnforcementResult(
                allowed=False,
                reason=f"Unplanned action: {tool_call.name} not in plan",
                plan_id=plan_id,
                sequence=current_seq,
            )

        # Check sequence ordering
        if matching_action.sequence != current_seq:
            return EnforcementResult(
                allowed=False,
                reason=(
                    f"Sequence violation: expected sequence {current_seq}, "
                    f"got {matching_action.sequence}"
                ),
                plan_id=plan_id,
                sequence=current_seq,
            )

        return EnforcementResult(
            allowed=True,
            reason="Action allowed",
            plan_id=plan_id,
            sequence=matching_action.sequence,
        )

    def mark_action_complete(self, plan_id: str, sequence: int) -> None:
        """Mark an action as complete and advance the sequence.

        Args:
            plan_id: The plan ID.
            sequence: The completed sequence number.
        """
        current = self._store.get_current_sequence(plan_id)
        if sequence == current:
            self._store.advance_sequence(plan_id)

    def _tool_calls_match(self, planned: ToolCall, actual: ToolCall) -> bool:
        """Check if two tool calls match.

        Matches on tool name. ID matching is optional since the actual
        call may have a different ID than planned.

        Args:
            planned: The planned tool call.
            actual: The actual tool call.

        Returns:
            True if the tool calls match.
        """
        return planned.name == actual.name
