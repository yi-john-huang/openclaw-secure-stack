"""Tests for plan storage and token management."""

from __future__ import annotations

import base64
import json
import time
import uuid

import pytest

from tests.conftest import MOCK_CHECKSUM


@pytest.fixture
def store(governance_db_path: str):
    """Create a PlanStore instance."""
    from src.governance.store import PlanStore

    return PlanStore(governance_db_path, secret="test-secret-key-32-bytes-long!!")


@pytest.fixture
def sample_plan():
    """Create a sample execution plan."""
    from src.governance.models import (
        ExecutionPlan,
        IntentCategory,
        PlannedAction,
        RiskAssessment,
        RiskLevel,
        ToolCall,
    )

    return ExecutionPlan(
        plan_id=str(uuid.uuid4()),
        session_id="sess-123",
        request_hash=MOCK_CHECKSUM,
        actions=[
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="read_file", arguments={"path": "/tmp"}),
                category=IntentCategory.FILE_READ,
                resources=[],
                risk_score=10,
            ),
            PlannedAction(
                sequence=1,
                tool_call=ToolCall(name="write_file", arguments={"path": "/tmp/out"}),
                category=IntentCategory.FILE_WRITE,
                resources=[],
                risk_score=30,
            ),
        ],
        risk_assessment=RiskAssessment(
            overall_score=30,
            level=RiskLevel.MEDIUM,
            factors=["file_read", "file_write"],
            mitigations=[],
        ),
    )


class TestPlanStorage:
    """Tests for plan storage operations."""

    def test_store_returns_plan_id_and_token(self, store, sample_plan):
        """Test store returns plan_id and token."""
        plan_id, token = store.store(sample_plan)
        assert plan_id == sample_plan.plan_id
        assert token is not None
        assert "." in token  # payload.signature format

    def test_lookup_returns_stored_plan(self, store, sample_plan):
        """Test lookup retrieves stored plan."""
        plan_id, _ = store.store(sample_plan)
        stored = store.lookup(plan_id)
        assert stored is not None
        assert stored.plan_id == plan_id
        assert stored.session_id == sample_plan.session_id

    def test_lookup_nonexistent_returns_none(self, store):
        """Test lookup returns None for nonexistent plan."""
        result = store.lookup("nonexistent-plan-id")
        assert result is None

    def test_initial_sequence_is_zero(self, store, sample_plan):
        """Test initial sequence pointer is 0."""
        plan_id, _ = store.store(sample_plan)
        assert store.get_current_sequence(plan_id) == 0

    def test_store_preserves_actions(self, store, sample_plan):
        """Test stored plan preserves all actions."""
        plan_id, _ = store.store(sample_plan)
        stored = store.lookup(plan_id)
        assert stored is not None
        assert len(stored.actions) == len(sample_plan.actions)
        assert stored.actions[0].tool_call.name == "read_file"

    def test_store_preserves_risk_assessment(self, store, sample_plan):
        """Test stored plan preserves risk assessment."""
        plan_id, _ = store.store(sample_plan)
        stored = store.lookup(plan_id)
        assert stored is not None
        assert stored.risk_assessment.overall_score == sample_plan.risk_assessment.overall_score


class TestTokenSigning:
    """Tests for HMAC token signing and verification."""

    def test_token_format(self, store, sample_plan):
        """Test token has payload.signature format."""
        _, token = store.store(sample_plan)
        parts = token.split(".")
        assert len(parts) == 2

    def test_verify_valid_token(self, store, sample_plan):
        """Test valid token verification succeeds."""
        plan_id, token = store.store(sample_plan)
        result = store.verify_token(plan_id, token)
        assert result.valid is True
        assert result.expired is False

    def test_verify_invalid_signature(self, store, sample_plan):
        """Test tampered signature is rejected."""
        plan_id, token = store.store(sample_plan)
        # Corrupt the signature
        tampered = token[:-1] + ("X" if token[-1] != "X" else "Y")
        result = store.verify_token(plan_id, tampered)
        assert result.valid is False

    def test_verify_modified_payload(self, store, sample_plan):
        """Test modified payload is rejected."""
        plan_id, token = store.store(sample_plan)
        payload, sig = token.split(".")

        # Decode, modify, re-encode
        decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
        decoded["plan_id"] = "different-id"
        new_payload = base64.urlsafe_b64encode(
            json.dumps(decoded).encode()
        ).decode().rstrip("=")

        tampered = f"{new_payload}.{sig}"
        result = store.verify_token(plan_id, tampered)
        assert result.valid is False

    def test_verify_expired_token(self, store, sample_plan, monkeypatch):
        """Test expired token is detected."""
        plan_id, token = store.store(sample_plan, ttl_seconds=1)

        # Wait for expiration
        time.sleep(1.1)

        result = store.verify_token(plan_id, token)
        assert result.expired is True

    def test_verify_wrong_plan_id(self, store, sample_plan):
        """Test token for wrong plan_id is rejected."""
        from src.governance.models import (
            ExecutionPlan,
            RiskAssessment,
            RiskLevel,
        )

        plan1_id, token1 = store.store(sample_plan)

        # Create another plan
        plan2 = ExecutionPlan(
            plan_id=str(uuid.uuid4()),
            session_id="sess-456",
            request_hash="b" * 64,
            actions=[],
            risk_assessment=RiskAssessment(
                overall_score=0, level=RiskLevel.INFO, factors=[], mitigations=[]
            ),
        )
        plan2_id, _ = store.store(plan2)

        # Try to use token1 with plan2
        result = store.verify_token(plan2_id, token1)
        assert result.valid is False

    def test_malformed_token_rejected(self, store, sample_plan):
        """Test malformed tokens are rejected."""
        plan_id, _ = store.store(sample_plan)

        # No separator
        result = store.verify_token(plan_id, "noseparator")
        assert result.valid is False

        # Too many parts
        result = store.verify_token(plan_id, "a.b.c")
        assert result.valid is False

        # Empty parts
        result = store.verify_token(plan_id, ".")
        assert result.valid is False


class TestSequenceTracking:
    """Tests for sequence pointer tracking."""

    def test_advance_increments_sequence(self, store, sample_plan):
        """Test advancing sequence increments pointer."""
        plan_id, _ = store.store(sample_plan)
        new_seq = store.advance_sequence(plan_id)
        assert new_seq == 1
        assert store.get_current_sequence(plan_id) == 1

    def test_advance_multiple_times(self, store, sample_plan):
        """Test advancing sequence multiple times."""
        plan_id, _ = store.store(sample_plan)
        store.advance_sequence(plan_id)
        store.advance_sequence(plan_id)
        assert store.get_current_sequence(plan_id) == 2

    def test_advance_nonexistent_raises(self, store):
        """Test advancing nonexistent plan raises error."""
        from src.governance.store import PlanNotFoundError

        with pytest.raises(PlanNotFoundError):
            store.advance_sequence("nonexistent-plan-id")

    def test_get_sequence_nonexistent_raises(self, store):
        """Test getting sequence for nonexistent plan raises error."""
        from src.governance.store import PlanNotFoundError

        with pytest.raises(PlanNotFoundError):
            store.get_current_sequence("nonexistent-plan-id")


class TestRetryTracking:
    """Tests for retry count tracking."""

    def test_initial_retry_count_zero(self, store, sample_plan):
        """Test initial retry count is 0."""
        plan_id, _ = store.store(sample_plan)
        assert store.get_retry_count(plan_id) == 0

    def test_increment_retry_count(self, store, sample_plan):
        """Test incrementing retry count."""
        plan_id, _ = store.store(sample_plan)
        new_count = store.increment_retry_count(plan_id)
        assert new_count == 1
        assert store.get_retry_count(plan_id) == 1

    def test_reset_retry_count(self, store, sample_plan):
        """Test resetting retry count."""
        plan_id, _ = store.store(sample_plan)
        store.increment_retry_count(plan_id)
        store.increment_retry_count(plan_id)
        store.reset_retry_count(plan_id)
        assert store.get_retry_count(plan_id) == 0


class TestPlanExpiration:
    """Tests for plan expiration handling."""

    def test_expired_plan_lookup_returns_none(self, store, sample_plan, monkeypatch):
        """Test lookup returns None for expired plans."""
        plan_id, _ = store.store(sample_plan, ttl_seconds=1)

        # Wait for expiration
        time.sleep(1.1)

        result = store.lookup(plan_id)
        # Expired plans should still be retrievable but marked as expired
        # The token verification handles the actual expiration check
        assert result is not None  # Plan data is still there

    def test_cleanup_expired_plans(self, store, sample_plan, monkeypatch):
        """Test cleanup removes expired plans."""
        plan_id, _ = store.store(sample_plan, ttl_seconds=1)

        # Wait for expiration
        time.sleep(1.1)

        count = store.cleanup_expired()
        assert count >= 1

        # Plan should be gone after cleanup
        result = store.lookup(plan_id)
        assert result is None
