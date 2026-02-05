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
from src.governance.store import PlanNotFoundError, PlanStore, TokenVerificationResult


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
        except PlanNotFoundError:
            return EnforcementResult(
                allowed=False,
                reason=f"Plan not found: {plan_id}",
                plan_id=plan_id,
            )

        # Get the expected action at the current sequence position
        expected_action = next(
            (a for a in plan.actions if a.sequence == current_seq),
            None,
        )

        if expected_action is None:
            return EnforcementResult(
                allowed=False,
                reason=f"No action at sequence {current_seq}: plan may be complete",
                plan_id=plan_id,
                sequence=current_seq,
            )

        # Validate tool call matches the expected action at current sequence
        if not self._tool_calls_match(expected_action.tool_call, tool_call):
            return EnforcementResult(
                allowed=False,
                reason=(
                    f"Action mismatch at sequence {current_seq}: "
                    f"expected {expected_action.tool_call.name} with args "
                    f"{expected_action.tool_call.arguments}, "
                    f"got {tool_call.name} with args {tool_call.arguments}"
                ),
                plan_id=plan_id,
                sequence=current_seq,
            )

        return EnforcementResult(
            allowed=True,
            reason="Action allowed",
            plan_id=plan_id,
            sequence=current_seq,
        )

    def mark_action_complete(self, plan_id: str, sequence: int) -> bool:
        """Mark an action as complete and advance the sequence.

        Uses atomic compare-and-swap to prevent race conditions when
        multiple threads attempt to complete the same action.

        Args:
            plan_id: The plan ID.
            sequence: The completed sequence number.

        Returns:
            True if the sequence was advanced, False if already advanced
            or sequence didn't match (concurrent completion).
        """
        return self._store.advance_sequence_atomic(plan_id, sequence)

    def close(self) -> None:
        """Close the database connection."""
        self._store.close()

    def _tool_calls_match(self, planned: ToolCall, actual: ToolCall) -> bool:
        """Check if two tool calls match.

        Matches on tool name and arguments. ID matching is optional since
        the actual call may have a different ID than planned.

        Args:
            planned: The planned tool call.
            actual: The actual tool call.

        Returns:
            True if the tool calls match.
        """
        if planned.name != actual.name:
            return False
        # Match arguments to prevent drift (e.g., read_file on different path)
        return planned.arguments == actual.arguments
