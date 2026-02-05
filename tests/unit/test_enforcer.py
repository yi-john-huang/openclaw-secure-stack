"""Tests for governance execution enforcer."""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import MOCK_CHECKSUM


@pytest.fixture
def secret() -> str:
    return "test-secret-key-32-bytes-long!!"


@pytest.fixture
def plan_store(governance_db_path: str, secret: str):
    from src.governance.store import PlanStore
    return PlanStore(governance_db_path, secret)


@pytest.fixture
def enforcer(governance_db_path: str, secret: str):
    from src.governance.enforcer import GovernanceEnforcer
    return GovernanceEnforcer(governance_db_path, secret)


@pytest.fixture
def sample_plan():
    from src.governance.models import (
        ExecutionPlan,
        IntentCategory,
        PlannedAction,
        ResourceAccess,
        RiskAssessment,
        RiskLevel,
        ToolCall,
    )
    return ExecutionPlan(
        plan_id=str(uuid.uuid4()),
        session_id="sess-1",
        request_hash=MOCK_CHECKSUM,
        actions=[
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1"),
                category=IntentCategory.FILE_READ,
                resources=[ResourceAccess(type="file", path="/tmp/test.txt", operation="read")],
                risk_score=10,
            ),
            PlannedAction(
                sequence=1,
                tool_call=ToolCall(name="write_file", arguments={"path": "/tmp/out.txt"}, id="call-2"),
                category=IntentCategory.FILE_WRITE,
                resources=[ResourceAccess(type="file", path="/tmp/out.txt", operation="write")],
                risk_score=30,
            ),
        ],
        risk_assessment=RiskAssessment(
            overall_score=40,
            level=RiskLevel.MEDIUM,
            factors=["file_write"],
            mitigations=["audit_logging"],
        ),
    )


class TestTokenVerification:
    def test_verify_valid_token(self, enforcer, plan_store, sample_plan):
        plan_id, token = plan_store.store(sample_plan)
        result = enforcer.verify_plan_token(plan_id, token)
        assert result.valid is True
        assert result.expired is False

    def test_verify_invalid_token(self, enforcer, plan_store, sample_plan):
        plan_id, _ = plan_store.store(sample_plan)
        result = enforcer.verify_plan_token(plan_id, "invalid.token")
        assert result.valid is False

    def test_verify_mismatched_plan_id(self, enforcer, plan_store, sample_plan):
        _, token = plan_store.store(sample_plan)
        result = enforcer.verify_plan_token("wrong-plan-id", token)
        assert result.valid is False

    def test_verify_expired_token(self, governance_db_path, secret, sample_plan):
        import time
        from src.governance.store import PlanStore
        from src.governance.enforcer import GovernanceEnforcer

        store = PlanStore(governance_db_path, secret)
        plan_id, token = store.store(sample_plan, ttl_seconds=1)
        time.sleep(1.1)

        enforcer = GovernanceEnforcer(governance_db_path, secret)
        result = enforcer.verify_plan_token(plan_id, token)
        assert result.expired is True


class TestActionEnforcement:
    def test_enforce_valid_action(self, enforcer, plan_store, sample_plan):
        from src.governance.models import ToolCall
        plan_id, token = plan_store.store(sample_plan)

        # First action at sequence 0
        tool_call = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        result = enforcer.enforce_action(plan_id, token, tool_call)
        assert result.allowed is True

    def test_enforce_rejects_without_token(self, enforcer, plan_store, sample_plan):
        from src.governance.models import ToolCall
        plan_id, _ = plan_store.store(sample_plan)

        tool_call = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        result = enforcer.enforce_action(plan_id, None, tool_call)
        assert result.allowed is False
        assert "missing" in result.reason.lower() or "token" in result.reason.lower()

    def test_enforce_rejects_invalid_token(self, enforcer, plan_store, sample_plan):
        from src.governance.models import ToolCall
        plan_id, _ = plan_store.store(sample_plan)

        tool_call = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        result = enforcer.enforce_action(plan_id, "bad.token", tool_call)
        assert result.allowed is False

    def test_enforce_rejects_unplanned_action(self, enforcer, plan_store, sample_plan):
        from src.governance.models import ToolCall
        plan_id, token = plan_store.store(sample_plan)

        # Tool not in plan - the enforcer now matches by sequence position
        tool_call = ToolCall(name="delete_file", arguments={"path": "/etc/passwd"}, id="call-x")
        result = enforcer.enforce_action(plan_id, token, tool_call)
        assert result.allowed is False
        assert "mismatch" in result.reason.lower() or "expected" in result.reason.lower()

    def test_enforce_rejects_out_of_sequence(self, enforcer, plan_store, sample_plan):
        from src.governance.models import ToolCall
        plan_id, token = plan_store.store(sample_plan)

        # Try second action first (sequence 1 before sequence 0)
        tool_call = ToolCall(name="write_file", arguments={"path": "/tmp/out.txt"}, id="call-2")
        result = enforcer.enforce_action(plan_id, token, tool_call)
        assert result.allowed is False
        assert "sequence" in result.reason.lower()


class TestSequenceTracking:
    def test_sequence_advances_on_success(self, enforcer, plan_store, sample_plan):
        from src.governance.models import ToolCall
        plan_id, token = plan_store.store(sample_plan)

        # Execute first action
        tool_call_1 = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        result1 = enforcer.enforce_action(plan_id, token, tool_call_1)
        assert result1.allowed is True

        # Mark as completed
        enforcer.mark_action_complete(plan_id, 0)

        # Now second action should be allowed
        tool_call_2 = ToolCall(name="write_file", arguments={"path": "/tmp/out.txt"}, id="call-2")
        result2 = enforcer.enforce_action(plan_id, token, tool_call_2)
        assert result2.allowed is True

    def test_retry_same_action_allowed(self, enforcer, plan_store, sample_plan):
        from src.governance.models import ToolCall
        plan_id, token = plan_store.store(sample_plan)

        # Execute first action multiple times (retry scenario)
        tool_call = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        result1 = enforcer.enforce_action(plan_id, token, tool_call)
        result2 = enforcer.enforce_action(plan_id, token, tool_call)

        assert result1.allowed is True
        assert result2.allowed is True


class TestPlanNotFound:
    def test_enforce_rejects_nonexistent_plan(self, enforcer):
        from src.governance.models import ToolCall
        tool_call = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        result = enforcer.enforce_action("nonexistent-plan", "some.token", tool_call)
        assert result.allowed is False
        # Either "not found" or "invalid token" is acceptable - both indicate rejection
        assert "not found" in result.reason.lower() or "invalid" in result.reason.lower()


class TestEnforcementResult:
    def test_result_includes_plan_info(self, enforcer, plan_store, sample_plan):
        from src.governance.models import ToolCall
        plan_id, token = plan_store.store(sample_plan)

        tool_call = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        result = enforcer.enforce_action(plan_id, token, tool_call)

        assert result.plan_id == plan_id
        assert result.sequence == 0
