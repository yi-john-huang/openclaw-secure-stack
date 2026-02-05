"""Approval gate for the governance layer.

This module provides the ApprovalGate class for:
- Creating approval requests
- Processing approvals and rejections
- Self-approval validation
- Expiration handling
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from src.governance.db import GovernanceDB
from src.governance.models import (
    ApprovalRequest,
    ApprovalStatus,
    PolicyViolation,
)
from src.models import Severity


class ApprovalExpiredError(Exception):
    """Raised when attempting to act on an expired approval."""

    pass


class ApproverMismatchError(Exception):
    """Raised when approver doesn't match requester."""

    pass


class ApprovalNotFoundError(Exception):
    """Raised when approval request is not found."""

    pass


class InvalidApprovalStatusError(Exception):
    """Raised when approval request is not in expected status."""

    pass


class ApprovalGate:
    """Manages human-in-the-loop approval flow.

    Provides:
    - Approval request creation with timeout
    - Approve/reject with self-approval validation
    - Request lookup and status checking
    """

    DEFAULT_TIMEOUT_SECONDS = 3600  # 1 hour

    def __init__(
        self,
        db_path: str,
        allow_self_approval: bool = True,
    ) -> None:
        """Initialize the approval gate.

        Args:
            db_path: Path to the SQLite database file.
            allow_self_approval: Whether users can approve their own requests.
        """
        self._db = GovernanceDB(db_path)
        self._allow_self_approval = allow_self_approval

    def create_request(
        self,
        plan_id: str,
        violations: list[PolicyViolation],
        requester_id: str,
        original_request: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
    ) -> ApprovalRequest:
        """Create a new approval request.

        Args:
            plan_id: The plan requiring approval.
            violations: List of policy violations that triggered approval.
            requester_id: ID of the user who made the request.
            original_request: Original request body for retry.
            timeout_seconds: Approval timeout in seconds.

        Returns:
            The created ApprovalRequest.
        """
        if timeout_seconds is None:
            timeout_seconds = self.DEFAULT_TIMEOUT_SECONDS

        approval_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=timeout_seconds)

        # Serialize violations and original request
        violations_json = json.dumps([self._violation_to_dict(v) for v in violations])
        original_json = json.dumps(original_request) if original_request else None

        # Store in database
        self._db.execute(
            """INSERT INTO governance_approvals
               (approval_id, plan_id, requester_id, status,
                requested_at, expires_at, violations_json, original_request_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                approval_id,
                plan_id,
                requester_id,
                ApprovalStatus.PENDING.value,
                now.isoformat(),
                expires_at.isoformat(),
                violations_json,
                original_json,
            ),
        )

        return ApprovalRequest(
            approval_id=approval_id,
            plan_id=plan_id,
            requester_id=requester_id,
            status=ApprovalStatus.PENDING,
            requested_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            violations=violations,
            original_request=original_request,
        )

    def approve(
        self,
        approval_id: str,
        approver_id: str,
        acknowledgment: str,
    ) -> ApprovalRequest:
        """Approve a pending request.

        Args:
            approval_id: The approval request ID.
            approver_id: ID of the user approving.
            acknowledgment: Acknowledgment text from approver.

        Returns:
            The updated ApprovalRequest.

        Raises:
            ApprovalNotFoundError: If approval not found.
            ApprovalExpiredError: If approval has expired.
            ApproverMismatchError: If approver doesn't match requester (when required).
            InvalidApprovalStatusError: If approval is not in PENDING status.
        """
        request = self._get_and_validate(approval_id, approver_id)

        # Atomic update with status check to prevent race conditions
        now = datetime.now(UTC)
        cursor = self._db.execute(
            """UPDATE governance_approvals
               SET status = ?, acknowledgment = ?, approved_at = ?, approved_by = ?
               WHERE approval_id = ? AND status = ?""",
            (
                ApprovalStatus.APPROVED.value,
                acknowledgment,
                now.isoformat(),
                approver_id,
                approval_id,
                ApprovalStatus.PENDING.value,
            ),
        )

        # Verify update succeeded (guard against concurrent modification)
        if cursor.rowcount == 0:
            raise InvalidApprovalStatusError(
                f"Failed to approve {approval_id}: status changed concurrently"
            )

        return ApprovalRequest(
            approval_id=request.approval_id,
            plan_id=request.plan_id,
            requester_id=request.requester_id,
            status=ApprovalStatus.APPROVED,
            requested_at=request.requested_at,
            expires_at=request.expires_at,
            violations=request.violations,
            original_request=request.original_request,
            acknowledgment=acknowledgment,
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

        Raises:
            ApprovalNotFoundError: If approval not found.
            ApprovalExpiredError: If approval has expired.
            InvalidApprovalStatusError: If approval is not in PENDING status.
        """
        request = self._get_and_validate(approval_id, rejector_id)

        # Atomic update with status check to prevent race conditions
        now = datetime.now(UTC)
        cursor = self._db.execute(
            """UPDATE governance_approvals
               SET status = ?, reason = ?, approved_at = ?, approved_by = ?
               WHERE approval_id = ? AND status = ?""",
            (
                ApprovalStatus.REJECTED.value,
                reason,
                now.isoformat(),
                rejector_id,
                approval_id,
                ApprovalStatus.PENDING.value,
            ),
        )

        # Verify update succeeded (guard against concurrent modification)
        if cursor.rowcount == 0:
            raise InvalidApprovalStatusError(
                f"Failed to reject {approval_id}: status changed concurrently"
            )

        return ApprovalRequest(
            approval_id=request.approval_id,
            plan_id=request.plan_id,
            requester_id=request.requester_id,
            status=ApprovalStatus.REJECTED,
            requested_at=request.requested_at,
            expires_at=request.expires_at,
            violations=request.violations,
            original_request=request.original_request,
            reason=reason,
        )

    def get(self, approval_id: str) -> ApprovalRequest | None:
        """Get an approval request by ID.

        Args:
            approval_id: The approval request ID.

        Returns:
            The ApprovalRequest if found, None otherwise.
        """
        row = self._db.fetch_one(
            "SELECT * FROM governance_approvals WHERE approval_id = ?",
            (approval_id,),
        )
        if row is None:
            return None

        return self._row_to_request(row)

    def _get_and_validate(
        self,
        approval_id: str,
        actor_id: str,
    ) -> ApprovalRequest:
        """Get and validate an approval request.

        Args:
            approval_id: The approval request ID.
            actor_id: ID of the user acting on the request.

        Returns:
            The ApprovalRequest.

        Raises:
            ApprovalNotFoundError: If approval not found.
            ApprovalExpiredError: If approval has expired.
            ApproverMismatchError: If actor doesn't match requester.
            InvalidApprovalStatusError: If approval is not in PENDING status.
        """
        request = self.get(approval_id)
        if request is None:
            raise ApprovalNotFoundError(f"Approval not found: {approval_id}")

        # Check status - only PENDING requests can be approved/rejected
        if request.status != ApprovalStatus.PENDING:
            raise InvalidApprovalStatusError(
                f"Cannot act on approval {approval_id}: "
                f"expected status 'pending', got '{request.status.value}'"
            )

        # Check expiration
        expires_at = datetime.fromisoformat(request.expires_at)
        if datetime.now(UTC) > expires_at:
            raise ApprovalExpiredError(f"Approval expired: {approval_id}")

        # Check self-approval - prevent same user from approving their own request
        if not self._allow_self_approval and actor_id == request.requester_id:
            raise ApproverMismatchError(
                f"Self-approval not permitted: {actor_id} cannot approve their own request"
            )

        return request

    def _violation_to_dict(self, v: PolicyViolation) -> dict[str, Any]:
        return {
            "rule_id": v.rule_id,
            "severity": v.severity.value,
            "action_sequence": v.action_sequence,
            "message": v.message,
        }

    def _dict_to_violation(self, d: dict[str, Any]) -> PolicyViolation:
        return PolicyViolation(
            rule_id=d["rule_id"],
            severity=Severity(d["severity"]),
            action_sequence=d["action_sequence"],
            message=d["message"],
        )

    def close(self) -> None:
        """Close the database connection."""
        self._db.close()

    def _row_to_request(self, row: dict[str, Any]) -> ApprovalRequest:
        violations_data = json.loads(row["violations_json"])
        original_json = row["original_request_json"]
        original_data = json.loads(original_json) if original_json else None

        return ApprovalRequest(
            approval_id=row["approval_id"],
            plan_id=row["plan_id"],
            requester_id=row["requester_id"],
            status=ApprovalStatus(row["status"]),
            requested_at=row["requested_at"],
            expires_at=row["expires_at"],
            violations=[self._dict_to_violation(v) for v in violations_data],
            original_request=original_data,
            acknowledgment=row.get("acknowledgment"),
            reason=row.get("reason"),
        )
