"""Plan storage for the governance layer.

This module provides the PlanStore class for:
- Persisting execution plans to SQLite
- Issuing HMAC-signed plan tokens
- Verifying tokens with constant-time comparison
- Tracking execution sequence
- Managing retry counts
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from src.governance.db import GovernanceDB
from src.governance.models import (
    ExecutionPlan,
    IntentCategory,
    PlannedAction,
    ResourceAccess,
    RiskAssessment,
    RiskLevel,
    ToolCall,
)


class PlanNotFoundError(Exception):
    """Raised when a plan is not found in the store."""

    pass


class InvalidPlanStatusError(Exception):
    """Raised when a plan is not in the expected status for an operation."""

    pass


@dataclass
class TokenVerificationResult:
    """Result of token verification."""

    valid: bool
    expired: bool
    error: str | None = None


class PlanStore:
    """Stores execution plans with HMAC-signed tokens.

    Provides:
    - Plan persistence in SQLite
    - HMAC-SHA256 token signing
    - Constant-time token verification
    - Sequence pointer tracking
    - Retry count management
    """

    DEFAULT_TTL_SECONDS = 900  # 15 minutes

    def __init__(self, db_path: str, secret: str) -> None:
        """Initialize the plan store.

        Args:
            db_path: Path to the SQLite database file.
            secret: Secret key for HMAC signing (should be 32+ bytes).
        """
        self._db = GovernanceDB(db_path)
        self._secret = secret.encode() if isinstance(secret, str) else secret

    def store(
        self,
        plan: ExecutionPlan,
        ttl_seconds: int | None = None,
    ) -> tuple[str, str]:
        """Store an execution plan and issue a token.

        Args:
            plan: The execution plan to store.
            ttl_seconds: Token TTL in seconds (default: 900).

        Returns:
            Tuple of (plan_id, token).
        """
        if ttl_seconds is None:
            ttl_seconds = self.DEFAULT_TTL_SECONDS

        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)

        # Serialize actions and risk assessment
        actions_json = json.dumps([self._action_to_dict(a) for a in plan.actions])
        risk_json = json.dumps(self._risk_to_dict(plan.risk_assessment))

        # Store in database
        self._db.execute(
            """INSERT INTO governance_plans
               (plan_id, session_id, request_hash, actions_json, risk_json,
                decision, created_at, expires_at, current_sequence, retry_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                plan.plan_id,
                plan.session_id,
                plan.request_hash,
                actions_json,
                risk_json,
                "active",
                now.isoformat(),
                expires_at.isoformat(),
                0,
                0,
            ),
        )

        # Issue token
        token = self._issue_token(plan.plan_id, now, expires_at)

        return plan.plan_id, token

    def store_pending(
        self,
        plan: ExecutionPlan,
        ttl_seconds: int | None = None,
    ) -> str:
        """Store an execution plan in pending_approval state without issuing a token.

        Used when a plan requires approval before execution.

        Args:
            plan: The execution plan to store.
            ttl_seconds: TTL in seconds for the pending plan (default: 900).

        Returns:
            The plan_id.
        """
        if ttl_seconds is None:
            ttl_seconds = self.DEFAULT_TTL_SECONDS

        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)

        # Serialize actions and risk assessment
        actions_json = json.dumps([self._action_to_dict(a) for a in plan.actions])
        risk_json = json.dumps(self._risk_to_dict(plan.risk_assessment))

        # Store in database with pending_approval status
        self._db.execute(
            """INSERT INTO governance_plans
               (plan_id, session_id, request_hash, actions_json, risk_json,
                decision, created_at, expires_at, current_sequence, retry_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                plan.plan_id,
                plan.session_id,
                plan.request_hash,
                actions_json,
                risk_json,
                "pending_approval",
                now.isoformat(),
                expires_at.isoformat(),
                0,
                0,
            ),
        )

        return plan.plan_id

    def activate_plan(
        self,
        plan_id: str,
        ttl_seconds: int | None = None,
    ) -> tuple[str, str]:
        """Activate a pending plan and issue a token.

        Called after approval to make the plan executable.

        Args:
            plan_id: The plan ID to activate.
            ttl_seconds: Token TTL in seconds (default: 900).

        Returns:
            Tuple of (plan_id, token).

        Raises:
            PlanNotFoundError: If the plan doesn't exist.
            InvalidPlanStatusError: If the plan is not in pending_approval status.
        """
        if ttl_seconds is None:
            ttl_seconds = self.DEFAULT_TTL_SECONDS

        # Verify plan exists and check status
        row = self._db.fetch_one(
            "SELECT decision FROM governance_plans WHERE plan_id = ?",
            (plan_id,),
        )
        if row is None:
            raise PlanNotFoundError(f"Plan not found: {plan_id}")

        if row["decision"] != "pending_approval":
            raise InvalidPlanStatusError(
                f"Cannot activate plan {plan_id}: expected status 'pending_approval', "
                f"got '{row['decision']}'"
            )

        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)

        # Update status to active and refresh expiration (atomic with status check)
        cursor = self._db.execute(
            """UPDATE governance_plans
               SET decision = ?, expires_at = ?
               WHERE plan_id = ? AND decision = ?""",
            ("active", expires_at.isoformat(), plan_id, "pending_approval"),
        )

        # Verify update succeeded (guard against race condition)
        if cursor.rowcount == 0:
            raise InvalidPlanStatusError(
                f"Failed to activate plan {plan_id}: status changed concurrently"
            )

        # Issue token
        token = self._issue_token(plan_id, now, expires_at)

        return plan_id, token

    def close(self) -> None:
        """Close the database connection."""
        self._db.close()

    def lookup(self, plan_id: str) -> ExecutionPlan | None:
        """Look up a plan by ID.

        Args:
            plan_id: The plan ID to look up.

        Returns:
            The ExecutionPlan if found, None otherwise.
        """
        row = self._db.fetch_one(
            "SELECT * FROM governance_plans WHERE plan_id = ?",
            (plan_id,),
        )
        if row is None:
            return None

        return self._row_to_plan(row)

    def verify_token(self, plan_id: str, token: str) -> TokenVerificationResult:
        """Verify a plan token.

        Args:
            plan_id: The expected plan ID.
            token: The token to verify.

        Returns:
            TokenVerificationResult with validity and expiration status.
        """
        # Parse token
        parts = token.split(".")
        if len(parts) != 2:
            return TokenVerificationResult(valid=False, expired=False, error="malformed_token")

        payload_b64, signature_b64 = parts
        if not payload_b64 or not signature_b64:
            return TokenVerificationResult(valid=False, expired=False, error="malformed_token")

        try:
            # Decode payload
            payload_bytes = base64.urlsafe_b64decode(payload_b64 + "==")
            payload = json.loads(payload_bytes)
        except Exception:
            return TokenVerificationResult(valid=False, expired=False, error="invalid_payload")

        # Verify plan_id matches
        if payload.get("plan_id") != plan_id:
            return TokenVerificationResult(valid=False, expired=False, error="plan_id_mismatch")

        # Recompute signature
        expected_sig = self._compute_signature(payload_b64)
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")

        # Constant-time comparison
        if not hmac.compare_digest(signature_b64, expected_sig_b64):
            return TokenVerificationResult(valid=False, expired=False, error="invalid_signature")

        # Check expiration
        try:
            expires_at = datetime.fromisoformat(payload["expires_at"])
            if datetime.now(UTC) > expires_at:
                return TokenVerificationResult(valid=True, expired=True, error="token_expired")
        except Exception:
            return TokenVerificationResult(valid=False, expired=False, error="invalid_expiration")

        return TokenVerificationResult(valid=True, expired=False)

    def get_current_sequence(self, plan_id: str) -> int:
        """Get the current sequence pointer for a plan.

        Args:
            plan_id: The plan ID.

        Returns:
            The current sequence number.

        Raises:
            PlanNotFoundError: If the plan doesn't exist.
        """
        row = self._db.fetch_one(
            "SELECT current_sequence FROM governance_plans WHERE plan_id = ?",
            (plan_id,),
        )
        if row is None:
            raise PlanNotFoundError(f"Plan not found: {plan_id}")
        return row["current_sequence"]

    def advance_sequence(self, plan_id: str) -> int:
        """Advance the sequence pointer for a plan.

        Args:
            plan_id: The plan ID.

        Returns:
            The new sequence number.

        Raises:
            PlanNotFoundError: If the plan doesn't exist.
        """
        # Check plan exists
        current = self.get_current_sequence(plan_id)

        # Increment
        new_seq = current + 1
        self._db.execute(
            "UPDATE governance_plans SET current_sequence = ? WHERE plan_id = ?",
            (new_seq, plan_id),
        )
        return new_seq

    def advance_sequence_atomic(self, plan_id: str, expected_sequence: int) -> bool:
        """Atomically advance the sequence pointer if it matches expected value.

        Uses compare-and-swap semantics to prevent race conditions when
        multiple threads attempt to advance the sequence concurrently.

        Args:
            plan_id: The plan ID.
            expected_sequence: The expected current sequence number.

        Returns:
            True if the sequence was advanced, False if it didn't match.

        Raises:
            PlanNotFoundError: If the plan doesn't exist.
        """
        # Verify plan exists first
        row = self._db.fetch_one(
            "SELECT plan_id FROM governance_plans WHERE plan_id = ?",
            (plan_id,),
        )
        if row is None:
            raise PlanNotFoundError(f"Plan not found: {plan_id}")

        # Atomic compare-and-swap: only update if current_sequence matches expected
        new_seq = expected_sequence + 1
        cursor = self._db.execute(
            """UPDATE governance_plans
               SET current_sequence = ?
               WHERE plan_id = ? AND current_sequence = ?""",
            (new_seq, plan_id, expected_sequence),
        )

        # rowcount == 1 means the update succeeded (sequence matched)
        return cursor.rowcount == 1

    def get_retry_count(self, plan_id: str) -> int:
        """Get the retry count for a plan.

        Args:
            plan_id: The plan ID.

        Returns:
            The current retry count.

        Raises:
            PlanNotFoundError: If the plan doesn't exist.
        """
        row = self._db.fetch_one(
            "SELECT retry_count FROM governance_plans WHERE plan_id = ?",
            (plan_id,),
        )
        if row is None:
            raise PlanNotFoundError(f"Plan not found: {plan_id}")
        return row["retry_count"]

    def increment_retry_count(self, plan_id: str) -> int:
        """Increment the retry count for a plan.

        Args:
            plan_id: The plan ID.

        Returns:
            The new retry count.

        Raises:
            PlanNotFoundError: If the plan doesn't exist.
        """
        current = self.get_retry_count(plan_id)
        new_count = current + 1
        self._db.execute(
            "UPDATE governance_plans SET retry_count = ? WHERE plan_id = ?",
            (new_count, plan_id),
        )
        return new_count

    def reset_retry_count(self, plan_id: str) -> None:
        """Reset the retry count for a plan.

        Args:
            plan_id: The plan ID.

        Raises:
            PlanNotFoundError: If the plan doesn't exist.
        """
        # Verify plan exists
        self.get_retry_count(plan_id)
        self._db.execute(
            "UPDATE governance_plans SET retry_count = 0 WHERE plan_id = ?",
            (plan_id,),
        )

    def cleanup_expired(self) -> int:
        """Remove expired plans from the store.

        Returns:
            Number of plans removed.
        """
        now = datetime.now(UTC).isoformat()
        cursor = self._db.execute(
            "DELETE FROM governance_plans WHERE expires_at < ?",
            (now,),
        )
        return cursor.rowcount

    def _issue_token(
        self,
        plan_id: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> str:
        """Issue a signed token for a plan.

        Args:
            plan_id: The plan ID.
            issued_at: Token issue time.
            expires_at: Token expiration time.

        Returns:
            The signed token string.
        """
        # Create payload
        payload = {
            "plan_id": plan_id,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        payload_json = json.dumps(payload, sort_keys=True)
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")

        # Sign payload
        signature = self._compute_signature(payload_b64)
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return f"{payload_b64}.{signature_b64}"

    def _compute_signature(self, data: str) -> bytes:
        """Compute HMAC-SHA256 signature.

        Args:
            data: The data to sign.

        Returns:
            The signature bytes.
        """
        return hmac.new(self._secret, data.encode(), hashlib.sha256).digest()

    def _action_to_dict(self, action: PlannedAction) -> dict[str, Any]:
        """Convert a PlannedAction to a dictionary."""
        return {
            "sequence": action.sequence,
            "tool_call": {
                "name": action.tool_call.name,
                "arguments": action.tool_call.arguments,
                "id": action.tool_call.id,
            },
            "category": action.category.value,
            "resources": [
                {"type": r.type, "path": r.path, "operation": r.operation}
                for r in action.resources
            ],
            "risk_score": action.risk_score,
        }

    def _dict_to_action(self, data: dict[str, Any]) -> PlannedAction:
        """Convert a dictionary to a PlannedAction."""
        return PlannedAction(
            sequence=data["sequence"],
            tool_call=ToolCall(
                name=data["tool_call"]["name"],
                arguments=data["tool_call"]["arguments"],
                id=data["tool_call"].get("id"),
            ),
            category=IntentCategory(data["category"]),
            resources=[
                ResourceAccess(type=r["type"], path=r["path"], operation=r["operation"])
                for r in data["resources"]
            ],
            risk_score=data["risk_score"],
        )

    def _risk_to_dict(self, risk: RiskAssessment) -> dict[str, Any]:
        """Convert a RiskAssessment to a dictionary."""
        return {
            "overall_score": risk.overall_score,
            "level": risk.level.value,
            "factors": risk.factors,
            "mitigations": risk.mitigations,
        }

    def _dict_to_risk(self, data: dict[str, Any]) -> RiskAssessment:
        """Convert a dictionary to a RiskAssessment."""
        return RiskAssessment(
            overall_score=data["overall_score"],
            level=RiskLevel(data["level"]),
            factors=data["factors"],
            mitigations=data["mitigations"],
        )

    def _row_to_plan(self, row: dict[str, Any]) -> ExecutionPlan:
        """Convert a database row to an ExecutionPlan."""
        actions_data = json.loads(row["actions_json"])
        risk_data = json.loads(row["risk_json"])

        return ExecutionPlan(
            plan_id=row["plan_id"],
            session_id=row["session_id"],
            request_hash=row["request_hash"],
            actions=[self._dict_to_action(a) for a in actions_data],
            risk_assessment=self._dict_to_risk(risk_data),
        )
