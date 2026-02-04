"""Tests for governance layer Pydantic models."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError


class TestIntentCategory:
    """Tests for IntentCategory enum."""

    def test_enum_values(self):
        from src.governance.models import IntentCategory

        assert IntentCategory.FILE_READ == "file_read"
        assert IntentCategory.FILE_WRITE == "file_write"
        assert IntentCategory.FILE_DELETE == "file_delete"
        assert IntentCategory.NETWORK_REQUEST == "network_request"
        assert IntentCategory.CODE_EXECUTION == "code_execution"
        assert IntentCategory.SKILL_INVOCATION == "skill_invocation"
        assert IntentCategory.SYSTEM_COMMAND == "system_command"
        assert IntentCategory.UNKNOWN == "unknown"

    def test_all_categories_are_strings(self):
        from src.governance.models import IntentCategory

        for category in IntentCategory:
            assert isinstance(category.value, str)


class TestGovernanceDecision:
    """Tests for GovernanceDecision enum."""

    def test_enum_values(self):
        from src.governance.models import GovernanceDecision

        assert GovernanceDecision.ALLOW == "allow"
        assert GovernanceDecision.BLOCK == "block"
        assert GovernanceDecision.REQUIRE_APPROVAL == "require_approval"
        assert GovernanceDecision.RATE_LIMITED == "rate_limited"


class TestApprovalStatus:
    """Tests for ApprovalStatus enum."""

    def test_enum_values(self):
        from src.governance.models import ApprovalStatus

        assert ApprovalStatus.PENDING == "pending"
        assert ApprovalStatus.APPROVED == "approved"
        assert ApprovalStatus.REJECTED == "rejected"
        assert ApprovalStatus.EXPIRED == "expired"


class TestToolCall:
    """Tests for ToolCall model."""

    def test_create_with_required_fields(self):
        from src.governance.models import ToolCall

        tc = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"})
        assert tc.name == "read_file"
        assert tc.arguments == {"path": "/tmp/test.txt"}

    def test_frozen_model(self):
        from src.governance.models import ToolCall

        tc = ToolCall(name="read_file", arguments={"path": "/tmp"})
        with pytest.raises(ValidationError):
            tc.name = "other"  # type: ignore[misc]

    def test_optional_id(self):
        from src.governance.models import ToolCall

        tc = ToolCall(name="read_file", arguments={})
        assert tc.id is None

    def test_with_id(self):
        from src.governance.models import ToolCall

        tc = ToolCall(name="read_file", arguments={}, id="call_123")
        assert tc.id == "call_123"


class TestIntentSignal:
    """Tests for IntentSignal model."""

    def test_create_signal(self):
        from src.governance.models import IntentCategory, IntentSignal

        signal = IntentSignal(
            category=IntentCategory.FILE_READ,
            confidence=0.95,
            source="pattern",
            details="matched read_file pattern",
        )
        assert signal.category == IntentCategory.FILE_READ
        assert signal.confidence == 0.95
        assert signal.source == "pattern"

    def test_confidence_bounds(self):
        from src.governance.models import IntentCategory, IntentSignal

        # Valid bounds
        IntentSignal(category=IntentCategory.FILE_READ, confidence=0.0, source="test")
        IntentSignal(category=IntentCategory.FILE_READ, confidence=1.0, source="test")

        # Invalid bounds
        with pytest.raises(ValidationError):
            IntentSignal(category=IntentCategory.FILE_READ, confidence=-0.1, source="test")
        with pytest.raises(ValidationError):
            IntentSignal(category=IntentCategory.FILE_READ, confidence=1.1, source="test")


class TestIntent:
    """Tests for Intent model."""

    def test_create_intent(self):
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        assert intent.primary_category == IntentCategory.FILE_READ
        assert len(intent.tool_calls) == 1

    def test_frozen(self):
        from src.governance.models import Intent, IntentCategory

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[],
            confidence=0.9,
        )
        with pytest.raises(ValidationError):
            intent.confidence = 0.5  # type: ignore[misc]


class TestResourceAccess:
    """Tests for ResourceAccess model."""

    def test_create_file_resource(self):
        from src.governance.models import ResourceAccess

        resource = ResourceAccess(type="file", path="/tmp/test.txt", operation="read")
        assert resource.type == "file"
        assert resource.path == "/tmp/test.txt"
        assert resource.operation == "read"

    def test_create_url_resource(self):
        from src.governance.models import ResourceAccess

        resource = ResourceAccess(type="url", path="https://api.example.com", operation="fetch")
        assert resource.type == "url"


class TestPlannedAction:
    """Tests for PlannedAction model."""

    def test_create_action(self):
        from src.governance.models import IntentCategory, PlannedAction, ToolCall

        action = PlannedAction(
            sequence=0,
            tool_call=ToolCall(name="read_file", arguments={}),
            category=IntentCategory.FILE_READ,
            resources=[],
            risk_score=10,
        )
        assert action.sequence == 0
        assert action.risk_score == 10

    def test_risk_score_bounds(self):
        from src.governance.models import IntentCategory, PlannedAction, ToolCall

        tc = ToolCall(name="test", arguments={})

        # Valid bounds
        PlannedAction(sequence=0, tool_call=tc, category=IntentCategory.UNKNOWN, resources=[], risk_score=0)
        PlannedAction(sequence=0, tool_call=tc, category=IntentCategory.UNKNOWN, resources=[], risk_score=100)

        # Invalid bounds
        with pytest.raises(ValidationError):
            PlannedAction(sequence=0, tool_call=tc, category=IntentCategory.UNKNOWN, resources=[], risk_score=-1)
        with pytest.raises(ValidationError):
            PlannedAction(sequence=0, tool_call=tc, category=IntentCategory.UNKNOWN, resources=[], risk_score=101)


class TestRiskAssessment:
    """Tests for RiskAssessment model."""

    def test_create_assessment(self):
        from src.governance.models import RiskAssessment, RiskLevel

        assessment = RiskAssessment(
            overall_score=75,
            level=RiskLevel.HIGH,
            factors=["code_execution", "external_network"],
            mitigations=["requires_approval"],
        )
        assert assessment.overall_score == 75
        assert assessment.level == RiskLevel.HIGH

    def test_score_bounds(self):
        from src.governance.models import RiskAssessment, RiskLevel

        # Valid bounds
        RiskAssessment(overall_score=0, level=RiskLevel.INFO, factors=[], mitigations=[])
        RiskAssessment(overall_score=100, level=RiskLevel.CRITICAL, factors=[], mitigations=[])

        # Invalid bounds
        with pytest.raises(ValidationError):
            RiskAssessment(overall_score=-1, level=RiskLevel.INFO, factors=[], mitigations=[])
        with pytest.raises(ValidationError):
            RiskAssessment(overall_score=101, level=RiskLevel.CRITICAL, factors=[], mitigations=[])


class TestExecutionPlan:
    """Tests for ExecutionPlan model."""

    def test_create_plan(self):
        from src.governance.models import ExecutionPlan, RiskAssessment, RiskLevel

        plan = ExecutionPlan(
            plan_id=str(uuid.uuid4()),
            session_id="session-123",
            request_hash="a" * 64,
            actions=[],
            risk_assessment=RiskAssessment(
                overall_score=20, level=RiskLevel.LOW, factors=[], mitigations=[]
            ),
        )
        assert plan.session_id == "session-123"

    def test_plan_id_uuid_format(self):
        from src.governance.models import ExecutionPlan, RiskAssessment, RiskLevel

        plan_id = str(uuid.uuid4())
        plan = ExecutionPlan(
            plan_id=plan_id,
            session_id=None,
            request_hash="a" * 64,
            actions=[],
            risk_assessment=RiskAssessment(
                overall_score=0, level=RiskLevel.INFO, factors=[], mitigations=[]
            ),
        )
        # Should be valid UUID
        uuid.UUID(plan.plan_id)

    def test_request_hash_length(self):
        from src.governance.models import ExecutionPlan, RiskAssessment, RiskLevel

        # Valid hash length (64 chars for SHA-256)
        ExecutionPlan(
            plan_id=str(uuid.uuid4()),
            session_id=None,
            request_hash="a" * 64,
            actions=[],
            risk_assessment=RiskAssessment(
                overall_score=0, level=RiskLevel.INFO, factors=[], mitigations=[]
            ),
        )

        # Invalid hash length
        with pytest.raises(ValidationError):
            ExecutionPlan(
                plan_id=str(uuid.uuid4()),
                session_id=None,
                request_hash="too_short",
                actions=[],
                risk_assessment=RiskAssessment(
                    overall_score=0, level=RiskLevel.INFO, factors=[], mitigations=[]
                ),
            )


class TestPolicyRule:
    """Tests for PolicyRule model."""

    def test_create_rule(self):
        from src.governance.models import PolicyEffect, PolicyRule, PolicyType

        rule = PolicyRule(
            id="GOV-001",
            name="Block file deletion",
            type=PolicyType.ACTION,
            effect=PolicyEffect.DENY,
            conditions={"category": "file_delete"},
            priority=100,
        )
        assert rule.id == "GOV-001"
        assert rule.effect == PolicyEffect.DENY

    def test_priority_default(self):
        from src.governance.models import PolicyEffect, PolicyRule, PolicyType

        rule = PolicyRule(
            id="GOV-002",
            name="Test rule",
            type=PolicyType.ACTION,
            effect=PolicyEffect.ALLOW,
            conditions={},
        )
        assert rule.priority == 0


class TestPolicyViolation:
    """Tests for PolicyViolation model."""

    def test_create_violation(self):
        from src.governance.models import PolicyViolation, Severity

        violation = PolicyViolation(
            rule_id="GOV-001",
            severity=Severity.HIGH,
            action_sequence=0,
            message="File deletion blocked by policy",
        )
        assert violation.rule_id == "GOV-001"
        assert violation.severity == Severity.HIGH


class TestValidationResult:
    """Tests for ValidationResult model."""

    def test_valid_result(self):
        from src.governance.models import GovernanceDecision, ValidationResult

        result = ValidationResult(
            valid=True,
            violations=[],
            decision=GovernanceDecision.ALLOW,
            approval_required=False,
        )
        assert result.valid is True
        assert result.decision == GovernanceDecision.ALLOW

    def test_blocked_result(self):
        from src.governance.models import (
            GovernanceDecision,
            PolicyViolation,
            Severity,
            ValidationResult,
        )

        result = ValidationResult(
            valid=False,
            violations=[
                PolicyViolation(
                    rule_id="GOV-001",
                    severity=Severity.CRITICAL,
                    action_sequence=0,
                    message="Blocked",
                )
            ],
            decision=GovernanceDecision.BLOCK,
            approval_required=False,
        )
        assert result.valid is False
        assert result.decision == GovernanceDecision.BLOCK
        assert len(result.violations) == 1


class TestApprovalRequest:
    """Tests for ApprovalRequest model."""

    def test_create_request(self):
        from src.governance.models import ApprovalRequest, ApprovalStatus

        request = ApprovalRequest(
            approval_id=str(uuid.uuid4()),
            plan_id=str(uuid.uuid4()),
            requester_id="user-123",
            status=ApprovalStatus.PENDING,
            requested_at="2024-01-01T00:00:00Z",
            expires_at="2024-01-01T01:00:00Z",
        )
        assert request.status == ApprovalStatus.PENDING
        assert request.requester_id == "user-123"


class TestPlanToken:
    """Tests for PlanToken model."""

    def test_create_token(self):
        from src.governance.models import PlanToken

        token = PlanToken(
            plan_id=str(uuid.uuid4()),
            issued_at="2024-01-01T00:00:00Z",
            expires_at="2024-01-01T00:15:00Z",
            signature="abc123signature",
        )
        assert token.signature == "abc123signature"


class TestSession:
    """Tests for Session model."""

    def test_create_session(self):
        from src.governance.models import Session

        session = Session(
            session_id="sess-123",
            created_at="2024-01-01T00:00:00Z",
            last_activity="2024-01-01T00:05:00Z",
            action_count=5,
            risk_accumulator=50,
        )
        assert session.session_id == "sess-123"
        assert session.action_count == 5
        assert session.risk_accumulator == 50
