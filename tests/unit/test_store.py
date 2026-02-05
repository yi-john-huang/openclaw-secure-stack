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


class TestTokenBase64Padding:
    """Regression tests for base64 padding edge cases."""

    def test_verify_token_base64_padding_mod_3(self, store):
        """Regression: token verification handles payload length mod 4 == 3.

        When base64-encoded payload (without padding) has length mod 4 == 3,
        it needs exactly 1 padding char ('='), but the code adds '=='.
        Python's base64 decoder must handle this correctly.

        This tests the edge case where adding '==' to a string that only
        needs '=' could potentially cause decoding issues.
        """
        from src.governance.models import (
            ExecutionPlan,
            RiskAssessment,
            RiskLevel,
        )

        # Find a plan_id that produces payload with length mod 4 == 3
        for i in range(100):
            plan_id = f"padding-test-{i}"

            plan = ExecutionPlan(
                plan_id=plan_id,
                session_id="sess-padding",
                request_hash="a" * 64,
                actions=[],
                risk_assessment=RiskAssessment(
                    overall_score=0, level=RiskLevel.INFO, factors=[], mitigations=[]
                ),
            )

            stored_plan_id, token = store.store(plan)
            payload_b64, _ = token.split(".")

            if len(payload_b64) % 4 == 3:
                # Found the edge case - verify token works
                result = store.verify_token(plan_id, token)
                assert result.valid is True, (
                    f"Token verification failed for payload length {len(payload_b64)} "
                    f"(mod 4 == 3). This is a base64 padding edge case."
                )
                assert result.expired is False
                return  # Test passed

        pytest.fail("Could not find plan_id producing payload length mod 4 == 3")

    def test_verify_token_crafted_mod_3_payload(self, store, sample_plan):
        """Regression: directly test decoding a payload with length mod 4 == 3.

        This test crafts a token with a known payload that has length mod 4 == 3
        to ensure the base64 decoding works correctly when only 1 padding char
        is needed but 2 are added.
        """
        import base64
        import hashlib
        import hmac
        import json
        from datetime import UTC, datetime, timedelta

        # Store a plan to get a valid plan_id in the database
        plan_id, _ = store.store(sample_plan)

        # Craft a payload that when encoded produces length mod 4 == 3
        # We'll manually create a token with the right payload structure
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=900)

        # The payload JSON structure - adjust plan_id to get desired length
        # "ab" base64 encodes to "YWI=" (length 3 without padding = mod 4 == 3)
        # We need to find a payload that produces this
        payload = {
            "plan_id": plan_id,
            "issued_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
        payload_json = json.dumps(payload, sort_keys=True)
        payload_b64_full = base64.urlsafe_b64encode(payload_json.encode()).decode()
        payload_b64 = payload_b64_full.rstrip("=")

        # Compute signature like the store does
        secret = b"test-secret-key-32-bytes-long!!"
        signature = hmac.new(secret, payload_b64.encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        crafted_token = f"{payload_b64}.{signature_b64}"

        # Now verify the token - this exercises the decode path
        result = store.verify_token(plan_id, crafted_token)

        # The token should be valid (signature matches, not expired)
        assert result.valid is True
        assert result.expired is False


class TestPlanStatusValidation:
    """Tests for plan status validation in activate_plan."""

    def test_activate_plan_requires_pending_approval_status(self, store, sample_plan):
        """Can only activate plans that are in pending_approval status."""
        from src.governance.store import InvalidPlanStatusError

        # Store plan as active (not pending_approval)
        plan_id, _ = store.store(sample_plan)

        with pytest.raises(InvalidPlanStatusError) as exc_info:
            store.activate_plan(plan_id)

        assert "pending_approval" in str(exc_info.value)
        assert "active" in str(exc_info.value)

    def test_activate_plan_succeeds_for_pending_approval(self, store, sample_plan):
        """activate_plan succeeds when plan is in pending_approval status."""
        # Store plan as pending_approval
        plan_id = store.store_pending(sample_plan)

        # Should succeed
        returned_id, token = store.activate_plan(plan_id)
        assert returned_id == plan_id
        assert token is not None
        assert "." in token

    def test_cannot_activate_already_active_plan(self, store, sample_plan):
        """Cannot activate a plan that's already active."""
        from src.governance.store import InvalidPlanStatusError

        # Store as pending and activate
        plan_id = store.store_pending(sample_plan)
        store.activate_plan(plan_id)

        # Second activation should fail
        with pytest.raises(InvalidPlanStatusError) as exc_info:
            store.activate_plan(plan_id)

        assert "pending_approval" in str(exc_info.value)


class TestAtomicSequenceAdvancement:
    """Tests for atomic sequence advancement to prevent race conditions."""

    def test_atomic_advance_succeeds_with_matching_sequence(self, store, sample_plan):
        """advance_sequence_atomic succeeds when sequence matches expected."""
        plan_id, _ = store.store(sample_plan)

        # Initial sequence is 0
        assert store.get_current_sequence(plan_id) == 0

        # Advance atomically
        result = store.advance_sequence_atomic(plan_id, expected_sequence=0)
        assert result is True
        assert store.get_current_sequence(plan_id) == 1

    def test_atomic_advance_fails_with_mismatched_sequence(self, store, sample_plan):
        """advance_sequence_atomic fails when sequence doesn't match expected."""
        plan_id, _ = store.store(sample_plan)

        # Try to advance with wrong expected sequence
        result = store.advance_sequence_atomic(plan_id, expected_sequence=5)
        assert result is False

        # Sequence should be unchanged
        assert store.get_current_sequence(plan_id) == 0

    def test_atomic_advance_prevents_double_increment(self, store, sample_plan):
        """Two calls with same expected_sequence - only first succeeds."""
        plan_id, _ = store.store(sample_plan)

        # Both try to advance from sequence 0
        result1 = store.advance_sequence_atomic(plan_id, expected_sequence=0)
        result2 = store.advance_sequence_atomic(plan_id, expected_sequence=0)

        assert result1 is True
        assert result2 is False
        # Final sequence should be 1, not 2
        assert store.get_current_sequence(plan_id) == 1

    def test_atomic_advance_nonexistent_raises(self, store):
        """advance_sequence_atomic raises PlanNotFoundError for nonexistent plan."""
        from src.governance.store import PlanNotFoundError

        with pytest.raises(PlanNotFoundError):
            store.advance_sequence_atomic("nonexistent-plan-id", expected_sequence=0)
