"""Tests for execution governance functionality.

Tests cover:
- PlanGenerator.enhance() method
- EnhancedExecutionPlan model
- ExecutionEngine
- AgentContextInjector
- Executor
- Middleware enhancement settings
"""

from __future__ import annotations

import json
import sys

import pytest
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from src.governance.models import (
    ConditionalBranch,
    EnhancedExecutionPlan,
    ExecutionContext,
    ExecutionMode,
    ExecutionPlan,
    ExecutionState,
    GovernanceDecision,
    Intent,
    IntentCategory,
    IntentSignal,
    PlannedAction,
    RecoveryPath,
    RecoveryStrategy,
    ResourceAccess,
    RiskAssessment,
    RiskLevel,
    StepResult,
    StepStatus,
    ToolCall,
)
from src.governance.planner import PlanGenerator


# --- Fixtures ---


@pytest.fixture
def sample_tool_call() -> ToolCall:
    """Create a sample tool call."""
    return ToolCall(
        name="read_file",
        arguments={"path": "/home/user/document.txt"},
        id="call_123",
    )


@pytest.fixture
def sample_intent(sample_tool_call: ToolCall) -> Intent:
    """Create a sample intent."""
    return Intent(
        primary_category=IntentCategory.FILE_READ,
        signals=[
            IntentSignal(
                category=IntentCategory.FILE_READ,
                confidence=0.9,
                source="tool_pattern",
                details="tool: read_file",
            )
        ],
        tool_calls=[sample_tool_call],
        confidence=0.9,
    )


@pytest.fixture
def sample_execution_plan(sample_tool_call: ToolCall) -> ExecutionPlan:
    """Create a sample execution plan."""
    return ExecutionPlan(
        plan_id="plan-123",
        session_id="session-456",
        request_hash="a" * 64,
        actions=[
            PlannedAction(
                sequence=0,
                tool_call=sample_tool_call,
                category=IntentCategory.FILE_READ,
                resources=[
                    ResourceAccess(
                        type="file",
                        path="/home/user/document.txt",
                        operation="read",
                    )
                ],
                risk_score=10,
            )
        ],
        risk_assessment=RiskAssessment(
            overall_score=10,
            level=RiskLevel.LOW,
            factors=["file_read"],
            mitigations=[],
        ),
    )


@pytest.fixture
def sample_enhanced_plan(sample_execution_plan: ExecutionPlan) -> EnhancedExecutionPlan:
    """Create a sample enhanced execution plan."""
    return EnhancedExecutionPlan(
        base_plan=sample_execution_plan,
        description="Read a document from the user's home directory",
        constraints=["No unplanned operations allowed"],
        preferences=["Use caching if available"],
        recovery_paths=[
            RecoveryPath(
                trigger_step=0,
                strategy=RecoveryStrategy.RETRY,
                max_retries=3,
                backoff_ms=1000,
            )
        ],
        conditionals=[],
        execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
        operations=[],
        global_constraints={"allowUnplanned": False},
        metadata={"generatedBy": "test"},
    )


@pytest.fixture
def mock_llm() -> MagicMock:
    """Create a mock LLM client."""
    llm = MagicMock()
    llm.complete = MagicMock(return_value=json.dumps({
        "description": "Test plan description",
        "operations": [
            {
                "id": "op-001",
                "tool": "read_file",
                "allow": ["*.txt"],
                "deny": ["/etc/*"],
            }
        ],
        "constraints": {
            "allowUnplanned": False,
            "requireSequential": True,
            "maxTotalOperations": 5,
            "maxDurationMs": 30000,
        },
        "recoveryPaths": [
            {
                "triggerStep": 0,
                "strategy": "retry",
                "maxRetries": 3,
                "backoffMs": 1000,
            }
        ],
        "conditionals": [
            {
                "condition": "step_0_success",
                "ifTrue": [1],
                "ifFalse": [2],
            }
        ],
        "executionMode": "governance_driven",
        "preferences": ["cache_results"],
        "metadata": {
            "generatedBy": "claude-3",
            "qualityScore": 85,
        },
    }))
    return llm


@pytest.fixture
def patterns_config(tmp_path) -> str:
    """Create a temporary patterns config file."""
    config = {
        "tool_categories": {
            "file_read": ["read_file", "get_file", "list_files"],
            "file_write": ["write_file", "save_file"],
            "network_request": ["http_request", "fetch_url"],
        },
        "argument_patterns": {
            "sensitive_paths": [r"/etc/", r"/root/"],
            "external_urls": [r"^https?://"],
        },
        "risk_multipliers": {
            "file_read": 1.0,
            "file_write": 1.5,
            "network_request": 1.2,
        },
    }
    config_path = tmp_path / "intent-patterns.json"
    config_path.write_text(json.dumps(config))
    return str(config_path)


@pytest.fixture
def schema_config(tmp_path) -> str:
    """Create a temporary schema config file."""
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "EnhancedExecutionPlan",
        "type": "object",
        "required": ["description", "operations", "constraints"],
        "properties": {
            "description": {"type": "string"},
            "operations": {"type": "array"},
            "constraints": {"type": "object"},
            "recoveryPaths": {"type": "array"},
            "conditionals": {"type": "array"},
            "executionMode": {"type": "string"},
        },
    }
    schema_path = tmp_path / "execution-plan.json"
    schema_path.write_text(json.dumps(schema))
    return str(schema_path)


# --- PlanGenerator Tests ---
class TestPlanGeneratorEnhance:
    """Tests for PlanGenerator.enhance() method."""

    def test_enhance_requires_llm(
            self, patterns_config: str, schema_config: str, sample_execution_plan: ExecutionPlan
    ):
        """Test that enhance() raises error when LLM is None."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        with pytest.raises(RuntimeError, match="No LLM client"):
            generator.enhance(sample_execution_plan, llm=None)

    def test_enhance_requires_schema(
            self, patterns_config: str, sample_execution_plan: ExecutionPlan, mock_llm: MagicMock
    ):
        """Test that enhance() raises error when schema not found."""
        generator = PlanGenerator(patterns_config, schema_path="/nonexistent/schema.json")

        with pytest.raises(RuntimeError, match="Schema not found"):
            generator.enhance(sample_execution_plan, llm=mock_llm)

    def test_enhance_returns_enhanced_plan(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
            mock_llm: MagicMock,
    ):
        """Test that enhance() returns EnhancedExecutionPlan."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        enhanced = generator.enhance(
            sample_execution_plan,
            llm=mock_llm,
            context={"user_role": "admin"},
        )

        assert isinstance(enhanced, EnhancedExecutionPlan)
        assert enhanced.base_plan == sample_execution_plan
        assert enhanced.description == "Test plan description"

    def test_enhance_parses_recovery_paths(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
            mock_llm: MagicMock,
    ):
        """Test that recovery paths are parsed from LLM output."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        enhanced = generator.enhance(sample_execution_plan, llm=mock_llm)

        assert len(enhanced.recovery_paths) == 1
        path = enhanced.recovery_paths[0]
        assert path.trigger_step == 0
        assert path.strategy == RecoveryStrategy.RETRY
        assert path.max_retries == 3
        assert path.backoff_ms == 1000

    def test_enhance_parses_conditionals(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
            mock_llm: MagicMock,
    ):
        """Test that conditionals are parsed from LLM output."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        enhanced = generator.enhance(sample_execution_plan, llm=mock_llm)

        assert len(enhanced.conditionals) == 1
        cond = enhanced.conditionals[0]
        assert cond.condition == "step_0_success"
        assert cond.if_true == [1]
        assert cond.if_false == [2]

    def test_enhance_parses_execution_mode(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
            mock_llm: MagicMock,
    ):
        """Test that execution mode is parsed correctly."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        enhanced = generator.enhance(sample_execution_plan, llm=mock_llm)

        assert enhanced.execution_mode == ExecutionMode.GOVERNANCE_DRIVEN

    def test_enhance_parses_agent_guided_mode(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
    ):
        """Test that agent_guided mode is parsed correctly."""
        llm = MagicMock()
        llm.complete = MagicMock(return_value=json.dumps({
            "description": "Agent guided plan",
            "executionMode": "agent_guided",
            "constraints": {},
        }))

        generator = PlanGenerator(patterns_config, schema_path=schema_config)
        enhanced = generator.enhance(sample_execution_plan, llm=llm)

        assert enhanced.execution_mode == ExecutionMode.AGENT_GUIDED

    def test_enhance_converts_constraints_dict_to_list(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
            mock_llm: MagicMock,
    ):
        """Test that constraint dict is converted to human-readable list."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        enhanced = generator.enhance(sample_execution_plan, llm=mock_llm)

        assert "No unplanned operations allowed" in enhanced.constraints
        assert "Operations must execute sequentially" in enhanced.constraints
        assert "Maximum 5 total operations" in enhanced.constraints
        assert "Maximum duration: 30000ms" in enhanced.constraints

    def test_enhance_handles_constraints_as_list(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
    ):
        """Test that constraints can be provided as a list."""
        llm = MagicMock()
        llm.complete = MagicMock(return_value=json.dumps({
            "description": "Test",
            "constraints": ["Constraint 1", "Constraint 2"],
        }))

        generator = PlanGenerator(patterns_config, schema_path=schema_config)
        enhanced = generator.enhance(sample_execution_plan, llm=llm)

        assert enhanced.constraints == ["Constraint 1", "Constraint 2"]

    def test_enhance_strips_markdown_fences(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
    ):
        """Test that markdown code fences are stripped from LLM response."""
        llm = MagicMock()
        llm.complete = MagicMock(return_value="""```json
{
    "description": "Markdown wrapped response",
    "constraints": {}
}
```""")

        generator = PlanGenerator(patterns_config, schema_path=schema_config)
        enhanced = generator.enhance(sample_execution_plan, llm=llm)

        assert enhanced.description == "Markdown wrapped response"

    def test_enhance_raises_on_invalid_json(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
    ):
        """Test that invalid JSON from LLM raises ValueError."""
        llm = MagicMock()
        llm.complete = MagicMock(return_value="not valid json {{{")

        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        with pytest.raises(ValueError, match="LLM returned invalid JSON"):
            generator.enhance(sample_execution_plan, llm=llm)

    def test_enhance_skips_malformed_recovery_paths(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
    ):
        """Test that malformed recovery paths are skipped."""
        llm = MagicMock()
        llm.complete = MagicMock(return_value=json.dumps({
            "description": "Test",
            "constraints": {},
            "recoveryPaths": [
                {"triggerStep": 0, "strategy": "retry"},  # Valid
                {"strategy": "retry"},  # Missing triggerStep
                {"triggerStep": 1, "strategy": "invalid_strategy"},  # Invalid strategy
            ],
        }))

        generator = PlanGenerator(patterns_config, schema_path=schema_config)
        enhanced = generator.enhance(sample_execution_plan, llm=llm)

        # Only the valid one should be parsed
        assert len(enhanced.recovery_paths) == 1
        assert enhanced.recovery_paths[0].trigger_step == 0

    def test_enhance_skips_malformed_conditionals(
            self,
            patterns_config: str,
            schema_config: str,
            sample_execution_plan: ExecutionPlan,
    ):
        """Test that malformed conditionals are skipped."""
        llm = MagicMock()
        llm.complete = MagicMock(return_value=json.dumps({
            "description": "Test",
            "constraints": {},
            "conditionals": [
                {"condition": "valid", "ifTrue": [1]},  # Valid
                {"ifTrue": [1]},  # Missing condition
            ],
        }))

        generator = PlanGenerator(patterns_config, schema_path=schema_config)
        enhanced = generator.enhance(sample_execution_plan, llm=llm)

        assert len(enhanced.conditionals) == 1
        assert enhanced.conditionals[0].condition == "valid"


# --- EnhancedExecutionPlan Model Tests ---


class TestEnhancedExecutionPlan:
    """Tests for EnhancedExecutionPlan model."""

    def test_property_accessors(self, sample_enhanced_plan: EnhancedExecutionPlan):
        """Test that property accessors delegate to base plan."""
        assert sample_enhanced_plan.plan_id == "plan-123"
        assert sample_enhanced_plan.session_id == "session-456"
        assert len(sample_enhanced_plan.actions) == 1
        assert sample_enhanced_plan.risk_assessment.level == RiskLevel.LOW

    def test_initialize_state(self, sample_enhanced_plan: EnhancedExecutionPlan):
        """Test that initialize_state creates proper ExecutionState."""
        sample_enhanced_plan.initialize_state(
            session_id="session-789",
            user_id="user-123",
            token="token-abc",
        )

        assert sample_enhanced_plan.state is not None
        assert sample_enhanced_plan.state.plan_id == "plan-123"
        assert sample_enhanced_plan.state.session_id == "session-789"
        assert sample_enhanced_plan.state.status == StepStatus.PENDING
        assert sample_enhanced_plan.state.current_sequence == 0
        assert sample_enhanced_plan.state.total_steps == 1

    def test_initialize_state_creates_context(self, sample_enhanced_plan: EnhancedExecutionPlan):
        """Test that initialize_state creates ExecutionContext."""
        sample_enhanced_plan.initialize_state(
            session_id="session-789",
            user_id="user-123",
            token="token-abc",
        )

        context = sample_enhanced_plan.state.context
        assert context.plan_id == "plan-123"
        assert context.session_id == "session-789"
        assert context.user_id == "user-123"
        assert context.token == "token-abc"

    def test_initialize_state_raises_on_none_session_id(
        self, sample_execution_plan: ExecutionPlan
    ):
        """Test that initialize_state raises ValueError when session_id is None."""
        enhanced = EnhancedExecutionPlan(
            base_plan=sample_execution_plan,
            description="Test",
            constraints=[],
            preferences=[],
            recovery_paths=[],
            conditionals=[],
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            operations=[],
            global_constraints={},
            metadata={},
        )

        with pytest.raises(ValueError, match="session_id is required"):
            enhanced.initialize_state(
                session_id=None,
                user_id="user-123",
                token="token-abc",
            )

    def test_initialize_state_sets_started_at(
        self, sample_execution_plan: ExecutionPlan
    ):
        """Test that initialize_state sets started_at timestamp."""
        enhanced = EnhancedExecutionPlan(
            base_plan=sample_execution_plan,
            description="Test",
            constraints=[],
            preferences=[],
            recovery_paths=[],
            conditionals=[],
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            operations=[],
            global_constraints={},
            metadata={},
        )

        enhanced.initialize_state(
            session_id="session-123",
            user_id="user-123",
            token="token-abc",
        )

        assert enhanced.state.started_at is not None
        # Should be a valid ISO format datetime
        datetime.fromisoformat(enhanced.state.started_at)


# --- Middleware Enhancement Settings Tests ---


class TestMiddlewareEnhancementSettings:
    """Tests for middleware enhancement configuration."""

    def test_enhancement_disabled_by_default(self, tmp_path):
        """Test that enhancement is disabled by default."""
        from src.governance.middleware import GovernanceMiddleware

        # Create minimal config files
        patterns_path = tmp_path / "patterns.json"
        patterns_path.write_text(json.dumps({"tool_categories": {}, "argument_patterns": {}, "risk_multipliers": {}}))

        policy_path = tmp_path / "policies.json"
        policy_path.write_text(json.dumps([]))

        db_path = str(tmp_path / "test.db")

        settings = {"enabled": True}

        middleware = GovernanceMiddleware(
            db_path=db_path,
            secret="test-secret",
            policy_path=str(policy_path),
            patterns_path=str(patterns_path),
            settings=settings,
        )

        assert middleware._enhancement_enabled is False

    def test_enhancement_enabled_via_settings(self, tmp_path):
        """Test that enhancement can be enabled via settings."""
        from src.governance.middleware import GovernanceMiddleware

        patterns_path = tmp_path / "patterns.json"
        patterns_path.write_text(json.dumps({"tool_categories": {}, "argument_patterns": {}, "risk_multipliers": {}}))

        policy_path = tmp_path / "policies.json"
        policy_path.write_text(json.dumps([]))

        db_path = str(tmp_path / "test.db")

        settings = {
            "enabled": True,
            "enhancement": {
                "enabled": True,
                "default_context": {"user_role": "admin"},
            },
        }

        middleware = GovernanceMiddleware(
            db_path=db_path,
            secret="test-secret",
            policy_path=str(policy_path),
            patterns_path=str(patterns_path),
            settings=settings,
        )

        assert middleware._enhancement_enabled is True
        assert middleware._enhancement_context == {"user_role": "admin"}


# --- ExecutionState Tests ---


class TestExecutionState:
    """Tests for ExecutionState model."""

    def test_is_complete_when_pending(self):
        """Test is_complete returns False when pending."""
        state = ExecutionState(
            plan_id="plan-123",
            session_id="session-456",
            context=ExecutionContext(
                plan_id="plan-123",
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
            ),
            current_sequence=0,
            status=StepStatus.PENDING,
            total_steps=3,
        )

        assert state.is_complete() is False

    def test_is_complete_when_all_steps_done(self):
        """Test is_complete returns True when all steps completed."""
        state = ExecutionState(
            plan_id="plan-123",
            session_id="session-456",
            context=ExecutionContext(
                plan_id="plan-123",
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
            ),
            current_sequence=3,
            status=StepStatus.COMPLETED,
            total_steps=3,
        )

        assert state.is_complete() is True

    def test_is_complete_when_failed(self):
        """Test is_complete returns True when failed."""
        state = ExecutionState(
            plan_id="plan-123",
            session_id="session-456",
            context=ExecutionContext(
                plan_id="plan-123",
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
            ),
            current_sequence=1,
            status=StepStatus.FAILED,
            total_steps=3,
        )

        assert state.is_complete() is True

    def test_get_progress_percentage(self):
        """Test get_progress returns correct percentage."""
        state = ExecutionState(
            plan_id="plan-123",
            session_id="session-456",
            context=ExecutionContext(
                plan_id="plan-123",
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
            ),
            current_sequence=1,
            status=StepStatus.RUNNING,
            total_steps=4,
            completed_steps=2,
        )

        assert state.get_progress() == 50.0

    def test_get_progress_zero_steps(self):
        """Test get_progress returns 100 when no steps."""
        state = ExecutionState(
            plan_id="plan-123",
            session_id="session-456",
            context=ExecutionContext(
                plan_id="plan-123",
                session_id="session-456",
                user_id="user-123",
                token="token-abc",
            ),
            current_sequence=0,
            status=StepStatus.COMPLETED,
            total_steps=0,
        )

        assert state.get_progress() == 100.0


# --- RecoveryPath Tests ---


class TestRecoveryPath:
    """Tests for RecoveryPath model."""

    def test_recovery_path_defaults(self):
        """Test RecoveryPath default values."""
        path = RecoveryPath(
            trigger_step=0,
            strategy=RecoveryStrategy.RETRY,
        )

        assert path.max_retries == 3
        assert path.backoff_ms == 1000
        assert path.trigger_errors == []

    def test_recovery_path_with_custom_values(self):
        """Test RecoveryPath with custom values."""
        path = RecoveryPath(
            trigger_step=2,
            strategy=RecoveryStrategy.SKIP,
            max_retries=5,
            backoff_ms=2000,
            trigger_errors=["TimeoutError", "ConnectionError"],
        )

        assert path.trigger_step == 2
        assert path.strategy == RecoveryStrategy.SKIP
        assert path.max_retries == 5
        assert path.backoff_ms == 2000
        assert path.trigger_errors == ["TimeoutError", "ConnectionError"]


# --- ConditionalBranch Tests ---


class TestConditionalBranch:
    """Tests for ConditionalBranch model."""

    def test_conditional_branch_defaults(self):
        """Test ConditionalBranch default values."""
        branch = ConditionalBranch(condition="step_0_success")

        assert branch.condition == "step_0_success"
        assert branch.if_true == []
        assert branch.if_false == []

    def test_conditional_branch_with_branches(self):
        """Test ConditionalBranch with branch sequences."""
        branch = ConditionalBranch(
            condition="file_exists",
            if_true=[1, 2, 3],
            if_false=[4, 5],
        )

        assert branch.if_true == [1, 2, 3]
        assert branch.if_false == [4, 5]


# --- StepResult Tests ---


class TestStepResult:
    """Tests for StepResult model."""

    def test_step_result_completed(self):
        """Test StepResult for completed step."""
        result = StepResult(
            sequence=0,
            status=StepStatus.COMPLETED,
            started_at="2024-01-01T00:00:00+00:00",
            completed_at="2024-01-01T00:00:01+00:00",
            duration_ms=1000,
            tool_name="read_file",
            tool_args={"path": "/home/user/file.txt"},
            tool_result={"content": "file contents"},
            governance_decision=GovernanceDecision.ALLOW,
        )

        assert result.status == StepStatus.COMPLETED
        assert result.error is None
        assert result.retry_count == 0

    def test_step_result_failed(self):
        """Test StepResult for failed step."""
        result = StepResult(
            sequence=1,
            status=StepStatus.FAILED,
            started_at="2024-01-01T00:00:00+00:00",
            completed_at="2024-01-01T00:00:05+00:00",
            duration_ms=5000,
            tool_name="write_file",
            tool_args={"path": "/etc/passwd"},
            error="Permission denied",
            retry_count=3,
            recovery_action=RecoveryStrategy.FAIL_FAST,
        )

        assert result.status == StepStatus.FAILED
        assert result.error == "Permission denied"
        assert result.retry_count == 3
        assert result.recovery_action == RecoveryStrategy.FAIL_FAST

    def test_step_result_blocked(self):
        """Test StepResult for governance-blocked step."""
        result = StepResult(
            sequence=0,
            status=StepStatus.BLOCKED,
            started_at="2024-01-01T00:00:00+00:00",
            completed_at="2024-01-01T00:00:00+00:00",
            tool_name="delete_file",
            tool_args={"path": "/etc/passwd"},
            governance_decision=GovernanceDecision.BLOCK,
            governance_reason="Access to /etc/* is denied by policy",
        )

        assert result.status == StepStatus.BLOCKED
        assert result.governance_decision == GovernanceDecision.BLOCK
        assert "denied by policy" in result.governance_reason


# --- Integration Tests ---


class TestPlanGeneratorIntegration:
    """Integration tests for plan generation and enhancement flow."""

    def test_full_generate_enhance_flow(
            self,
            patterns_config: str,
            schema_config: str,
            sample_intent: Intent,
            mock_llm: MagicMock,
    ):
        """Test complete flow from intent to enhanced plan."""
        generator = PlanGenerator(patterns_config, schema_path=schema_config)

        # Step 1: Generate base plan
        base_plan = generator.generate(
            intent=sample_intent,
            request_body={"tools": []},
            session_id="session-123",
        )

        assert isinstance(base_plan, ExecutionPlan)
        assert base_plan.session_id == "session-123"

        # Step 2: Enhance with LLM
        enhanced_plan = generator.enhance(
            base_plan,
            llm=mock_llm,
            context={"user_role": "admin"},
        )

        assert isinstance(enhanced_plan, EnhancedExecutionPlan)
        assert enhanced_plan.base_plan == base_plan
        assert enhanced_plan.description is not None

        # Step 3: Initialize state
        enhanced_plan.initialize_state(
            session_id="session-123",
            user_id="user-456",
            token="token-xyz",
        )

        assert enhanced_plan.state is not None
        assert enhanced_plan.state.status == StepStatus.PENDING

    def test_multiple_tool_calls_generate_multiple_actions(self, patterns_config: str):
        """Test that multiple tool calls create multiple actions."""
        generator = PlanGenerator(patterns_config)

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[
                ToolCall(name="read_file", arguments={"path": "/file1.txt"}),
                ToolCall(name="read_file", arguments={"path": "/file2.txt"}),
                ToolCall(name="write_file", arguments={"path": "/output.txt"}),
            ],
            confidence=1.0,
        )

        plan = generator.generate(intent=intent, request_body={})

        assert len(plan.actions) == 3
        assert plan.actions[0].sequence == 0
        assert plan.actions[1].sequence == 1
        assert plan.actions[2].sequence == 2

        # Check risk increases with multiple actions
        assert plan.risk_assessment.overall_score > plan.actions[0].risk_score


# --- Middleware create_enhanced_plan Tests ---


# --- Middleware create_enhanced_plan Tests ---


class TestMiddlewareCreateEnhancedPlan:
    """Tests for GovernanceMiddleware.create_enhanced_plan()."""

    @pytest.fixture
    def sample_base_plan(self) -> ExecutionPlan:
        """Create a sample base plan."""
        return ExecutionPlan(
            plan_id="plan-123",
            session_id="session-456",
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="read_file", arguments={"path": "/test"}),
                    category=IntentCategory.FILE_READ,
                    resources=[],
                    risk_score=10,
                )
            ],
            risk_assessment=RiskAssessment(
                overall_score=10,
                level=RiskLevel.LOW,
                factors=[],
                mitigations=[],
            ),
        )

    @pytest.fixture
    def mock_enhanced_plan(self, sample_base_plan):
        """Create a mock enhanced plan returned by planner."""
        return EnhancedExecutionPlan(
            base_plan=sample_base_plan,
            description="Test enhanced plan",
            constraints=[],
            preferences=[],
            recovery_paths=[],
            conditionals=[],
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            operations=[],
            global_constraints={},
            metadata={},
        )

    @pytest.fixture
    def middleware_with_enhancement(self, tmp_path):
        """Create middleware with enhancement enabled."""
        from src.governance.middleware import GovernanceMiddleware

        patterns_path = tmp_path / "patterns.json"
        patterns_path.write_text('{"tool_categories": {}, "argument_patterns": {}, "risk_multipliers": {}}')

        policy_path = tmp_path / "policies.json"
        policy_path.write_text("[]")

        db_path = str(tmp_path / "test.db")

        settings = {
            "enabled": True,
            "enhancement": {
                "enabled": True,
                "default_context": {"environment": "test", "user_role": "tester"},
            },
        }

        return GovernanceMiddleware(
            db_path=db_path,
            secret="test-secret",
            policy_path=str(policy_path),
            patterns_path=str(patterns_path),
            settings=settings,
        )

    def test_create_enhanced_plan_returns_enhanced_plan(
        self,
        middleware_with_enhancement,
        sample_base_plan,
        mock_enhanced_plan,
    ):
        """Test that create_enhanced_plan returns EnhancedExecutionPlan."""
        # Mock the planner.enhance method
        middleware_with_enhancement._planner.enhance = MagicMock(return_value=mock_enhanced_plan)

        result = middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        assert result is not None
        assert isinstance(result, EnhancedExecutionPlan)
        assert result.description == "Test enhanced plan"

    def test_create_enhanced_plan_initializes_state(
        self,
        middleware_with_enhancement,
        sample_base_plan,
        mock_enhanced_plan,
    ):
        """Test that create_enhanced_plan initializes state correctly."""
        middleware_with_enhancement._planner.enhance = MagicMock(return_value=mock_enhanced_plan)

        result = middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        assert result.state is not None
        assert result.state.context.session_id == "session-456"
        assert result.state.context.user_id == "user-123"
        assert result.state.context.token == "token-abc"

    def test_create_enhanced_plan_passes_enhancement_context(
        self,
        middleware_with_enhancement,
        sample_base_plan,
        mock_enhanced_plan,
    ):
        """Test that create_enhanced_plan passes context from settings."""
        middleware_with_enhancement._planner.enhance = MagicMock(return_value=mock_enhanced_plan)

        middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        # Check that enhance was called with the context from settings
        call_kwargs = middleware_with_enhancement._planner.enhance.call_args.kwargs
        assert call_kwargs["context"] == {"environment": "test", "user_role": "tester"}

    def test_create_enhanced_plan_lazy_loads_llm(
        self,
        middleware_with_enhancement,
        sample_base_plan,
        mock_enhanced_plan,
    ):
        """Test that LLM client is lazy-loaded on first call."""
        middleware_with_enhancement._planner.enhance = MagicMock(return_value=mock_enhanced_plan)

        # Initially None
        assert middleware_with_enhancement._llm is None

        middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        # After call, LLM should be created
        assert middleware_with_enhancement._llm is not None

    def test_create_enhanced_plan_reuses_llm(
        self,
        middleware_with_enhancement,
        sample_base_plan,
        mock_enhanced_plan,
    ):
        """Test that LLM client is reused across calls."""
        middleware_with_enhancement._planner.enhance = MagicMock(return_value=mock_enhanced_plan)

        # First call
        middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-1",
            user_id="user-1",
            token="token-1",
        )
        first_llm = middleware_with_enhancement._llm

        # Second call
        middleware_with_enhancement.create_enhanced_plan(
            basic_plan=sample_base_plan,
            session_id="session-2",
            user_id="user-2",
            token="token-2",
        )
        second_llm = middleware_with_enhancement._llm

        # Should be same instance
        assert first_llm is second_llm

    def test_enhancement_disabled_by_default(self, tmp_path):
        """Test that enhancement is disabled by default."""
        from src.governance.middleware import GovernanceMiddleware

        patterns_path = tmp_path / "patterns.json"
        patterns_path.write_text('{"tool_categories": {}, "argument_patterns": {}, "risk_multipliers": {}}')

        policy_path = tmp_path / "policies.json"
        policy_path.write_text("[]")

        db_path = str(tmp_path / "test.db")

        settings = {"enabled": True}  # No enhancement settings

        middleware = GovernanceMiddleware(
            db_path=db_path,
            secret="test-secret",
            policy_path=str(policy_path),
            patterns_path=str(patterns_path),
            settings=settings,
        )

        assert middleware._enhancement_enabled is False

class TestLLMClientInit:
    """Tests for LLMClient initialization."""

    def test_raises_when_anthropic_not_installed(self, monkeypatch):
        """Test that LLMClient raises helpful error when anthropic not installed."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        # Remove anthropic from modules if present
        with patch.dict(sys.modules, {"anthropic": None}):
            from src.llm.client import LLMClient

            with pytest.raises(RuntimeError, match="pip install anthropic"):
                LLMClient()

    def test_raises_without_api_key(self, monkeypatch):
        """Test that LLMClient raises error when API key not set."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient, LLMClientError

            with pytest.raises(LLMClientError, match="ANTHROPIC_API_KEY"):
                LLMClient()

    def test_uses_default_model(self, monkeypatch):
        """Test that LLMClient uses default model when not specified."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient, DEFAULT_MODEL

            client = LLMClient()
            assert client.model_name == DEFAULT_MODEL

    def test_uses_env_model(self, monkeypatch):
        """Test that LLMClient uses model from environment variable."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setenv("ANTHROPIC_MODEL", "claude-custom-model")

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            # Reload to pick up env var
            import importlib
            from src.llm import client as llm_module
            importlib.reload(llm_module)

            client = llm_module.LLMClient()
            assert client.model_name == "claude-custom-model"

    def test_uses_provided_model(self, monkeypatch):
        """Test that LLMClient uses model passed to constructor."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient

            client = LLMClient(model="my-custom-model")
            assert client.model_name == "my-custom-model"

    def test_uses_default_timeout(self, monkeypatch):
        """Test that LLMClient uses default timeout when not specified."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.delenv("ANTHROPIC_TIMEOUT_SECONDS", raising=False)

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient, DEFAULT_TIMEOUT

            client = LLMClient()
            assert client.timeout_seconds == DEFAULT_TIMEOUT

    def test_uses_provided_timeout(self, monkeypatch):
        """Test that LLMClient uses timeout passed to constructor."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        mock_anthropic_module = MagicMock()
        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient

            client = LLMClient(timeout_seconds=90)
            assert client.timeout_seconds == 90

    def test_creates_anthropic_client_with_timeout(self, monkeypatch):
        """Test that Anthropic client is created with correct timeout."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        mock_anthropic = MagicMock()
        mock_anthropic_module = MagicMock()
        mock_anthropic_module.Anthropic = mock_anthropic
        mock_anthropic_module.AuthenticationError = Exception

        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient

            LLMClient(timeout_seconds=45)
            mock_anthropic.assert_called_once_with(timeout=45)


class TestLLMClientComplete:
    """Tests for LLMClient.complete() method."""

    @pytest.fixture
    def mock_anthropic_module(self):
        """Create a mock anthropic module."""
        mock_module = MagicMock()
        mock_module.AuthenticationError = type("AuthenticationError", (Exception,), {})
        mock_module.APIError = type("APIError", (Exception,), {})
        return mock_module

    @pytest.fixture
    def mock_client(self, monkeypatch, mock_anthropic_module):
        """Create a LLMClient with mocked Anthropic."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        mock_instance = MagicMock()
        mock_anthropic_module.Anthropic.return_value = mock_instance

        with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
            from src.llm.client import LLMClient
            client = LLMClient()

            yield client, mock_instance, mock_anthropic_module

    def test_complete_returns_text(self, mock_client):
        """Test that complete returns the response text."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Hello, world!")]
        mock_anthropic.messages.create.return_value = mock_response

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            result = client.complete("Say hello")
        assert result == "Hello, world!"

    def test_complete_uses_model(self, mock_client):
        """Test that complete uses the configured model."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="response")]
        mock_anthropic.messages.create.return_value = mock_response

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            client.complete("prompt")

        call_args = mock_anthropic.messages.create.call_args
        assert call_args.kwargs["model"] == client.model_name

    def test_complete_uses_temperature(self, mock_client):
        """Test that complete passes temperature parameter."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="response")]
        mock_anthropic.messages.create.return_value = mock_response

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            client.complete("prompt", temperature=0.7)

        call_args = mock_anthropic.messages.create.call_args
        assert call_args.kwargs["temperature"] == 0.7

    def test_complete_default_temperature_zero(self, mock_client):
        """Test that complete defaults to temperature=0."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="response")]
        mock_anthropic.messages.create.return_value = mock_response

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            client.complete("prompt")

        call_args = mock_anthropic.messages.create.call_args
        assert call_args.kwargs["temperature"] == 0

    def test_complete_raises_on_empty_response(self, mock_client):
        """Test that complete raises error on empty response."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = []  # Empty content
        mock_anthropic.messages.create.return_value = mock_response

        from src.llm.client import LLMClientError

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            with pytest.raises(LLMClientError, match="empty response"):
                client.complete("prompt")

    def test_complete_raises_on_api_error(self, mock_client):
        """Test that complete raises LLMClientError on API error."""
        client, mock_anthropic, mock_module = mock_client

        # Raise APIError from messages.create
        mock_anthropic.messages.create.side_effect = mock_module.APIError("Rate limited")

        from src.llm.client import LLMClientError

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            with pytest.raises(LLMClientError, match="API call failed"):
                client.complete("prompt")

    def test_complete_sets_max_tokens(self, mock_client):
        """Test that complete sets max_tokens."""
        client, mock_anthropic, mock_module = mock_client

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="response")]
        mock_anthropic.messages.create.return_value = mock_response

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            client.complete("prompt")

        call_args = mock_anthropic.messages.create.call_args
        assert call_args.kwargs["max_tokens"] == 4096

    def test_complete_raises_when_anthropic_not_installed(self, monkeypatch):
        """Test that complete raises error if anthropic disappears."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        # First create a valid client
        mock_module = MagicMock()
        mock_module.AuthenticationError = Exception
        mock_module.APIError = Exception

        with patch.dict(sys.modules, {"anthropic": mock_module}):
            from src.llm.client import LLMClient
            client = LLMClient()

        # Now make anthropic unavailable for complete()
        with patch.dict(sys.modules, {"anthropic": None}):
            with pytest.raises(RuntimeError, match="pip install anthropic"):
                client.complete("prompt")