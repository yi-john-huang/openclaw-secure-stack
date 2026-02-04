"""Tests for policy validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def policies_path(tmp_path: Path) -> str:
    """Create a temporary policies config file."""
    policies = [
        {
            "id": "GOV-001",
            "name": "Block file deletion",
            "type": "action",
            "effect": "deny",
            "conditions": {"category": "file_delete"},
            "priority": 100,
        },
        {
            "id": "GOV-002",
            "name": "Require approval for code execution",
            "type": "action",
            "effect": "require_approval",
            "conditions": {"category": "code_execution"},
            "priority": 90,
        },
        {
            "id": "GOV-003",
            "name": "Block sensitive paths",
            "type": "resource",
            "effect": "deny",
            "conditions": {"type": "file", "path_pattern": "^/etc/|.*passwd.*"},
            "priority": 100,
        },
        {
            "id": "GOV-004",
            "name": "Allow localhost URLs",
            "type": "resource",
            "effect": "allow",
            "conditions": {"type": "url", "path_pattern": "^https?://localhost"},
            "priority": 90,
        },
        {
            "id": "GOV-005",
            "name": "Rate limit",
            "type": "rate",
            "effect": "deny",
            "conditions": {"max_actions_per_session": 100},
            "priority": 50,
        },
        {
            "id": "GOV-006",
            "name": "Read-exfiltrate sequence",
            "type": "sequence",
            "effect": "require_approval",
            "conditions": {"pattern": ["file_read", "network_request"], "window": 3},
            "priority": 85,
        },
    ]
    path = tmp_path / "governance-policies.json"
    path.write_text(json.dumps(policies))
    return str(path)


@pytest.fixture
def validator(policies_path: str):
    """Create a PolicyValidator instance."""
    from src.governance.validator import PolicyValidator

    return PolicyValidator(policies_path)


class TestRuleLoading:
    """Tests for loading policy rules from config."""

    def test_loads_from_json(self, policies_path: str):
        """Test policies are loaded from JSON file."""
        from src.governance.validator import PolicyValidator

        validator = PolicyValidator(policies_path)
        assert len(validator.policies) == 6

    def test_sorts_by_priority(self, policies_path: str):
        """Test policies are sorted by priority (highest first)."""
        from src.governance.validator import PolicyValidator

        validator = PolicyValidator(policies_path)
        priorities = [p.priority for p in validator.policies]
        assert priorities == sorted(priorities, reverse=True)

    def test_raises_on_missing_file(self, tmp_path: Path):
        """Test FileNotFoundError for missing config."""
        from src.governance.validator import PolicyValidator

        with pytest.raises(FileNotFoundError):
            PolicyValidator(str(tmp_path / "nonexistent.json"))

    def test_raises_on_invalid_format(self, tmp_path: Path):
        """Test ValueError for invalid JSON format."""
        from src.governance.validator import PolicyValidator

        path = tmp_path / "bad.json"
        path.write_text('{"not": "a list"}')
        with pytest.raises(ValueError):
            PolicyValidator(str(path))


class TestActionPolicies:
    """Tests for action-based policy evaluation."""

    def test_deny_blocks_action(self, validator):
        """Test deny policy creates violation."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ResourceAccess,
            ToolCall,
        )

        action = PlannedAction(
            sequence=0,
            tool_call=ToolCall(name="delete_file", arguments={}),
            category=IntentCategory.FILE_DELETE,
            resources=[],
            risk_score=50,
        )
        violations = validator._check_action_policies(action)
        assert any(v.rule_id == "GOV-001" for v in violations)

    def test_allow_permits_action(self, validator):
        """Test allowed actions produce no violations."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ToolCall,
        )

        action = PlannedAction(
            sequence=0,
            tool_call=ToolCall(name="read_file", arguments={}),
            category=IntentCategory.FILE_READ,
            resources=[],
            risk_score=10,
        )
        violations = validator._check_action_policies(action)
        # No action policy matches FILE_READ, so no violations
        assert len(violations) == 0

    def test_require_approval_creates_violation(self, validator):
        """Test require_approval policy creates medium severity violation."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            Severity,
            ToolCall,
        )

        action = PlannedAction(
            sequence=0,
            tool_call=ToolCall(name="execute_code", arguments={}),
            category=IntentCategory.CODE_EXECUTION,
            resources=[],
            risk_score=70,
        )
        violations = validator._check_action_policies(action)
        assert any(v.rule_id == "GOV-002" for v in violations)
        approval_violation = next(v for v in violations if v.rule_id == "GOV-002")
        assert approval_violation.severity == Severity.MEDIUM


class TestResourcePolicies:
    """Tests for resource-based policy evaluation."""

    def test_blocks_sensitive_path(self, validator):
        """Test deny policy blocks sensitive file paths."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ResourceAccess,
            ToolCall,
        )

        action = PlannedAction(
            sequence=0,
            tool_call=ToolCall(name="read_file", arguments={}),
            category=IntentCategory.FILE_READ,
            resources=[ResourceAccess(type="file", path="/etc/passwd", operation="read")],
            risk_score=30,
        )
        violations = validator._check_resource_policies(action)
        assert any(v.rule_id == "GOV-003" for v in violations)

    def test_allows_safe_path(self, validator):
        """Test safe paths produce no violations."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ResourceAccess,
            ToolCall,
        )

        action = PlannedAction(
            sequence=0,
            tool_call=ToolCall(name="read_file", arguments={}),
            category=IntentCategory.FILE_READ,
            resources=[ResourceAccess(type="file", path="/tmp/safe.txt", operation="read")],
            risk_score=10,
        )
        violations = validator._check_resource_policies(action)
        assert len(violations) == 0

    def test_allows_localhost_url(self, validator):
        """Test localhost URLs are allowed."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ResourceAccess,
            ToolCall,
        )

        action = PlannedAction(
            sequence=0,
            tool_call=ToolCall(name="http_get", arguments={}),
            category=IntentCategory.NETWORK_REQUEST,
            resources=[ResourceAccess(type="url", path="http://localhost:8080/api", operation="fetch")],
            risk_score=20,
        )
        violations = validator._check_resource_policies(action)
        assert len(violations) == 0

    def test_regex_pattern_matching(self, validator):
        """Test regex pattern matching for paths."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ResourceAccess,
            ToolCall,
        )

        action = PlannedAction(
            sequence=0,
            tool_call=ToolCall(name="read_file", arguments={}),
            category=IntentCategory.FILE_READ,
            resources=[ResourceAccess(type="file", path="/home/user/mypasswd.txt", operation="read")],
            risk_score=30,
        )
        violations = validator._check_resource_policies(action)
        # Should match .*passwd.* pattern
        assert any(v.rule_id == "GOV-003" for v in violations)


class TestSequencePolicies:
    """Tests for sequence-based policy evaluation."""

    def test_detects_forbidden_sequence(self, validator):
        """Test detection of forbidden action sequences."""
        from src.governance.models import (
            ExecutionPlan,
            IntentCategory,
            PlannedAction,
            RiskAssessment,
            RiskLevel,
            ToolCall,
        )

        plan = ExecutionPlan(
            plan_id="plan-1",
            session_id=None,
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="read_file", arguments={}),
                    category=IntentCategory.FILE_READ,
                    resources=[],
                    risk_score=10,
                ),
                PlannedAction(
                    sequence=1,
                    tool_call=ToolCall(name="http_get", arguments={}),
                    category=IntentCategory.NETWORK_REQUEST,
                    resources=[],
                    risk_score=30,
                ),
            ],
            risk_assessment=RiskAssessment(
                overall_score=30, level=RiskLevel.MEDIUM, factors=[], mitigations=[]
            ),
        )
        violations = validator._check_sequence_policies(plan)
        assert any("GOV-006" in v.rule_id for v in violations)

    def test_respects_window_size(self, validator):
        """Test sequence outside window doesn't trigger."""
        from src.governance.models import (
            ExecutionPlan,
            IntentCategory,
            PlannedAction,
            RiskAssessment,
            RiskLevel,
            ToolCall,
        )

        # Actions are more than 3 apart
        plan = ExecutionPlan(
            plan_id="plan-1",
            session_id=None,
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="read_file", arguments={}),
                    category=IntentCategory.FILE_READ,
                    resources=[],
                    risk_score=10,
                ),
                PlannedAction(
                    sequence=1,
                    tool_call=ToolCall(name="write_file", arguments={}),
                    category=IntentCategory.FILE_WRITE,
                    resources=[],
                    risk_score=30,
                ),
                PlannedAction(
                    sequence=2,
                    tool_call=ToolCall(name="write_file", arguments={}),
                    category=IntentCategory.FILE_WRITE,
                    resources=[],
                    risk_score=30,
                ),
                PlannedAction(
                    sequence=3,
                    tool_call=ToolCall(name="write_file", arguments={}),
                    category=IntentCategory.FILE_WRITE,
                    resources=[],
                    risk_score=30,
                ),
                PlannedAction(
                    sequence=4,
                    tool_call=ToolCall(name="http_get", arguments={}),
                    category=IntentCategory.NETWORK_REQUEST,
                    resources=[],
                    risk_score=30,
                ),
            ],
            risk_assessment=RiskAssessment(
                overall_score=30, level=RiskLevel.MEDIUM, factors=[], mitigations=[]
            ),
        )
        violations = validator._check_sequence_policies(plan)
        # file_read at 0, network_request at 4 - more than window of 3
        assert not any("GOV-006" in v.rule_id for v in violations)

    def test_order_matters(self, validator):
        """Test sequence order matters (not just presence)."""
        from src.governance.models import (
            ExecutionPlan,
            IntentCategory,
            PlannedAction,
            RiskAssessment,
            RiskLevel,
            ToolCall,
        )

        # network_request THEN file_read (wrong order)
        plan = ExecutionPlan(
            plan_id="plan-1",
            session_id=None,
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="http_get", arguments={}),
                    category=IntentCategory.NETWORK_REQUEST,
                    resources=[],
                    risk_score=30,
                ),
                PlannedAction(
                    sequence=1,
                    tool_call=ToolCall(name="read_file", arguments={}),
                    category=IntentCategory.FILE_READ,
                    resources=[],
                    risk_score=10,
                ),
            ],
            risk_assessment=RiskAssessment(
                overall_score=30, level=RiskLevel.MEDIUM, factors=[], mitigations=[]
            ),
        )
        violations = validator._check_sequence_policies(plan)
        # Pattern is [file_read, network_request], but we have opposite order
        assert not any("GOV-006" in v.rule_id for v in violations)


class TestRatePolicies:
    """Tests for rate-based policy evaluation."""

    def test_blocks_when_limit_exceeded(self, validator):
        """Test rate limit creates violation when exceeded."""
        from src.governance.models import Session

        session = Session(
            session_id="sess-1",
            created_at="2024-01-01T00:00:00Z",
            last_activity="2024-01-01T01:00:00Z",
            action_count=101,
            risk_accumulator=500,
        )
        violations = validator._check_rate_policies(session)
        assert any(v.rule_id == "GOV-005" for v in violations)

    def test_allows_within_limit(self, validator):
        """Test no violation when within rate limit."""
        from src.governance.models import Session

        session = Session(
            session_id="sess-1",
            created_at="2024-01-01T00:00:00Z",
            last_activity="2024-01-01T01:00:00Z",
            action_count=50,
            risk_accumulator=200,
        )
        violations = validator._check_rate_policies(session)
        assert len(violations) == 0

    def test_no_session_no_rate_check(self, validator):
        """Test no rate check when session is None."""
        violations = validator._check_rate_policies(None)
        assert len(violations) == 0


class TestFullValidation:
    """Tests for complete plan validation."""

    def test_returns_validation_result(self, validator):
        """Test validate returns ValidationResult."""
        from src.governance.models import (
            ExecutionPlan,
            IntentCategory,
            PlannedAction,
            RiskAssessment,
            RiskLevel,
            ToolCall,
            ValidationResult,
        )

        plan = ExecutionPlan(
            plan_id="plan-1",
            session_id=None,
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="read_file", arguments={}),
                    category=IntentCategory.FILE_READ,
                    resources=[],
                    risk_score=10,
                )
            ],
            risk_assessment=RiskAssessment(
                overall_score=10, level=RiskLevel.LOW, factors=[], mitigations=[]
            ),
        )
        result = validator.validate(plan)
        assert isinstance(result, ValidationResult)

    def test_decision_block_on_deny(self, validator):
        """Test BLOCK decision when deny policy matches."""
        from src.governance.models import (
            ExecutionPlan,
            GovernanceDecision,
            IntentCategory,
            PlannedAction,
            RiskAssessment,
            RiskLevel,
            ToolCall,
        )

        plan = ExecutionPlan(
            plan_id="plan-1",
            session_id=None,
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="delete_file", arguments={}),
                    category=IntentCategory.FILE_DELETE,
                    resources=[],
                    risk_score=50,
                )
            ],
            risk_assessment=RiskAssessment(
                overall_score=50, level=RiskLevel.MEDIUM, factors=[], mitigations=[]
            ),
        )
        result = validator.validate(plan)
        assert result.decision == GovernanceDecision.BLOCK

    def test_decision_require_approval(self, validator):
        """Test REQUIRE_APPROVAL decision."""
        from src.governance.models import (
            ExecutionPlan,
            GovernanceDecision,
            IntentCategory,
            PlannedAction,
            RiskAssessment,
            RiskLevel,
            ToolCall,
        )

        plan = ExecutionPlan(
            plan_id="plan-1",
            session_id=None,
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="execute_code", arguments={}),
                    category=IntentCategory.CODE_EXECUTION,
                    resources=[],
                    risk_score=70,
                )
            ],
            risk_assessment=RiskAssessment(
                overall_score=70, level=RiskLevel.HIGH, factors=[], mitigations=[]
            ),
        )
        result = validator.validate(plan)
        assert result.decision == GovernanceDecision.REQUIRE_APPROVAL

    def test_decision_allow_when_clean(self, validator):
        """Test ALLOW decision when no violations."""
        from src.governance.models import (
            ExecutionPlan,
            GovernanceDecision,
            IntentCategory,
            PlannedAction,
            RiskAssessment,
            RiskLevel,
            ToolCall,
        )

        plan = ExecutionPlan(
            plan_id="plan-1",
            session_id=None,
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="read_file", arguments={}),
                    category=IntentCategory.FILE_READ,
                    resources=[],
                    risk_score=10,
                )
            ],
            risk_assessment=RiskAssessment(
                overall_score=10, level=RiskLevel.LOW, factors=[], mitigations=[]
            ),
        )
        result = validator.validate(plan)
        assert result.decision == GovernanceDecision.ALLOW

    def test_violations_included_in_result(self, validator):
        """Test violations are included in result."""
        from src.governance.models import (
            ExecutionPlan,
            IntentCategory,
            PlannedAction,
            RiskAssessment,
            RiskLevel,
            ToolCall,
        )

        plan = ExecutionPlan(
            plan_id="plan-1",
            session_id=None,
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="delete_file", arguments={}),
                    category=IntentCategory.FILE_DELETE,
                    resources=[],
                    risk_score=50,
                )
            ],
            risk_assessment=RiskAssessment(
                overall_score=50, level=RiskLevel.MEDIUM, factors=[], mitigations=[]
            ),
        )
        result = validator.validate(plan)
        assert len(result.violations) > 0
