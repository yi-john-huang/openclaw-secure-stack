"""Tests for approval gate functionality."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "test_governance.db")


@pytest.fixture
def approver(db_path: str):
    from src.governance.approver import ApprovalGate
    return ApprovalGate(db_path, allow_self_approval=True)


@pytest.fixture
def approver_no_self(db_path: str):
    from src.governance.approver import ApprovalGate
    return ApprovalGate(db_path, allow_self_approval=False)


@pytest.fixture
def sample_violations():
    from src.governance.models import PolicyViolation, Severity
    return [
        PolicyViolation(
            rule_id="GOV-002",
            severity=Severity.MEDIUM,
            action_sequence=0,
            message="Code execution requires approval",
        )
    ]


class TestRequestCreation:
    def test_creates_approval_request(self, approver, sample_violations):
        from src.governance.models import ApprovalStatus
        request = approver.create_request(
            plan_id="plan-123",
            violations=sample_violations,
            requester_id="user-1",
            original_request={"tools": []},
        )
        assert uuid.UUID(request.approval_id)
        assert request.status == ApprovalStatus.PENDING
        assert request.plan_id == "plan-123"

    def test_stores_original_request(self, approver, sample_violations):
        request = approver.create_request(
            plan_id="plan-123",
            violations=sample_violations,
            requester_id="user-1",
            original_request={"key": "value"},
        )
        assert request.original_request == {"key": "value"}

    def test_sets_expiration(self, approver, sample_violations):
        from datetime import datetime
        request = approver.create_request(
            plan_id="plan-123",
            violations=sample_violations,
            requester_id="user-1",
        )
        expires = datetime.fromisoformat(request.expires_at)
        requested = datetime.fromisoformat(request.requested_at)
        assert expires > requested


class TestApprovalRejection:
    def test_approve_updates_status(self, approver, sample_violations):
        from src.governance.models import ApprovalStatus
        request = approver.create_request("plan-1", sample_violations, "user-1")
        record = approver.approve(request.approval_id, "user-1", "I acknowledge")
        assert record.status == ApprovalStatus.APPROVED

    def test_approve_stores_acknowledgment(self, approver, sample_violations):
        request = approver.create_request("plan-1", sample_violations, "user-1")
        record = approver.approve(request.approval_id, "user-1", "I accept the risk")
        assert record.acknowledgment == "I accept the risk"

    def test_reject_updates_status(self, approver, sample_violations):
        from src.governance.models import ApprovalStatus
        request = approver.create_request("plan-1", sample_violations, "user-1")
        record = approver.reject(request.approval_id, "user-1", "Too risky")
        assert record.status == ApprovalStatus.REJECTED

    def test_reject_stores_reason(self, approver, sample_violations):
        request = approver.create_request("plan-1", sample_violations, "user-1")
        record = approver.reject(request.approval_id, "user-1", "Not authorized")
        assert record.reason == "Not authorized"

    def test_approve_expired_raises(self, approver, sample_violations):
        from src.governance.approver import ApprovalExpiredError
        request = approver.create_request(
            "plan-1", sample_violations, "user-1", timeout_seconds=1
        )
        time.sleep(1.1)
        with pytest.raises(ApprovalExpiredError):
            approver.approve(request.approval_id, "user-1", "ack")


class TestSelfApproval:
    def test_self_approval_blocked_when_disabled(self, approver_no_self, sample_violations):
        """Same user cannot approve their own request when allow_self_approval=False."""
        from src.governance.approver import ApproverMismatchError
        request = approver_no_self.create_request("plan-1", sample_violations, "user-1")
        with pytest.raises(ApproverMismatchError):
            approver_no_self.approve(request.approval_id, "user-1", "ack")

    def test_different_user_can_approve_when_self_disabled(self, approver_no_self, sample_violations):
        """Different user can approve when allow_self_approval=False."""
        from src.governance.models import ApprovalStatus
        request = approver_no_self.create_request("plan-1", sample_violations, "user-1")
        record = approver_no_self.approve(request.approval_id, "user-2", "ack")
        assert record.status == ApprovalStatus.APPROVED

    def test_same_user_can_approve_when_allowed(self, approver, sample_violations):
        """Same user can approve their own request when allow_self_approval=True."""
        from src.governance.models import ApprovalStatus
        request = approver.create_request("plan-1", sample_violations, "user-1")
        record = approver.approve(request.approval_id, "user-1", "ack")
        assert record.status == ApprovalStatus.APPROVED


class TestLookup:
    def test_get_returns_request(self, approver, sample_violations):
        request = approver.create_request("plan-1", sample_violations, "user-1")
        found = approver.get(request.approval_id)
        assert found is not None
        assert found.approval_id == request.approval_id

    def test_get_nonexistent_returns_none(self, approver):
        assert approver.get("nonexistent") is None
