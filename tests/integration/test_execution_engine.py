"""Tests for ExecutionEngine, Executor, and AgentContextInjector.

Tests cover:
- ExecutionEngine step execution
- Recovery and retry logic
- Governance enforcement during execution
- AgentContextInjector
- Executor entry point
"""

from __future__ import annotations

import asyncio
import json
import pytest
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from src.governance.enforcer import EnforcementResult, GovernanceEnforcer
from src.governance.models import (
    ConditionalBranch,
    EnhancedExecutionPlan,
    ExecutionContext,
    ExecutionMode,
    ExecutionPlan,
    ExecutionState,
    GovernanceDecision,
    IntentCategory,
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
from src.execution.engine import (
    ExecutionEngine,
    ExecutionError,
    GovernanceBlockedError,
    ToolExecutorAdapter,
)
from src.execution.injected_context import AgentContextInjector
from src.execution.executor import Executor


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
def sample_action(sample_tool_call: ToolCall) -> PlannedAction:
    """Create a sample planned action."""
    return PlannedAction(
        sequence=0,
        tool_call=sample_tool_call,
        category=IntentCategory.FILE_READ,
        resources=[
            ResourceAccess(type="file", path="/home/user/document.txt", operation="read")
        ],
        risk_score=10,
    )


@pytest.fixture
def sample_execution_plan(sample_action: PlannedAction) -> ExecutionPlan:
    """Create a sample execution plan."""
    return ExecutionPlan(
        plan_id="plan-123",
        session_id="session-456",
        request_hash="a" * 64,
        actions=[sample_action],
        risk_assessment=RiskAssessment(
            overall_score=10,
            level=RiskLevel.LOW,
            factors=["file_read"],
            mitigations=[],
        ),
    )


@pytest.fixture
def sample_enhanced_plan(sample_execution_plan: ExecutionPlan) -> EnhancedExecutionPlan:
    """Create a sample enhanced plan with state initialized."""
    enhanced = EnhancedExecutionPlan(
        base_plan=sample_execution_plan,
        description="Test plan",
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
        session_id="session-456",
        user_id="user-123",
        token="token-abc",
    )
    return enhanced


@pytest.fixture
def mock_enforcer() -> MagicMock:
    """Create a mock governance enforcer."""
    enforcer = MagicMock(spec=GovernanceEnforcer)
    enforcer.enforce_action = MagicMock(return_value=EnforcementResult(
        allowed=True,
        reason="Action allowed",
        plan_id="plan-123",
        sequence=0,
    ))
    enforcer.mark_action_complete = MagicMock()
    return enforcer


@pytest.fixture
def mock_tool_executor() -> AsyncMock:
    """Create a mock tool executor."""
    executor = AsyncMock(spec=ToolExecutorAdapter)
    executor.execute = AsyncMock(return_value={"result": "success"})
    return executor


# --- ExecutionEngine Tests ---


class TestExecutionEngine:
    """Tests for ExecutionEngine."""

    @pytest.mark.asyncio
    async def test_execute_single_step_success(
        self,
        sample_enhanced_plan: EnhancedExecutionPlan,
        mock_enforcer: MagicMock,
        mock_tool_executor: AsyncMock,
    ):
        """Test executing a single step successfully."""
        engine = ExecutionEngine(mock_enforcer, mock_tool_executor)

        await engine.execute(sample_enhanced_plan)

        assert sample_enhanced_plan.state.status == StepStatus.COMPLETED
        assert sample_enhanced_plan.state.completed_steps == 1
        assert sample_enhanced_plan.state.failed_steps == 0
        assert len(sample_enhanced_plan.state.step_results) == 1

        result = sample_enhanced_plan.state.step_results[0]
        assert result.status == StepStatus.COMPLETED
        assert result.tool_result == {"result": "success"}

    @pytest.mark.asyncio
    async def test_execute_raises_when_state_not_initialized(
            self,
            sample_execution_plan: ExecutionPlan,
            mock_enforcer: MagicMock,
            mock_tool_executor: AsyncMock,
    ):
        """Test that execute raises when state is not initialized."""
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
        # State not initialized

        engine = ExecutionEngine(mock_enforcer, mock_tool_executor)

        # Current implementation raises AttributeError when accessing state.step_results
        with pytest.raises(AttributeError):
            await engine.execute(enhanced)

    @pytest.mark.asyncio
    async def test_execute_governance_block(
        self,
        sample_enhanced_plan: EnhancedExecutionPlan,
        mock_tool_executor: AsyncMock,
    ):
        """Test that governance block stops execution."""
        enforcer = MagicMock(spec=GovernanceEnforcer)
        enforcer.enforce_action = MagicMock(return_value=EnforcementResult(
            allowed=False,
            reason="Access denied by policy",
            plan_id="plan-123",
            sequence=0,
        ))

        engine = ExecutionEngine(enforcer, mock_tool_executor)

        await engine.execute(sample_enhanced_plan)

        assert sample_enhanced_plan.state.status == StepStatus.BLOCKED
        result = sample_enhanced_plan.state.step_results[0]
        assert result.status == StepStatus.BLOCKED
        assert result.governance_decision == GovernanceDecision.BLOCK
        assert "denied by policy" in result.governance_reason

    @pytest.mark.asyncio
    async def test_execute_tool_failure_with_retry(
        self,
        sample_execution_plan: ExecutionPlan,
        mock_enforcer: MagicMock,
    ):
        """Test retry logic on tool failure."""
        # Setup plan with retry recovery path
        enhanced = EnhancedExecutionPlan(
            base_plan=sample_execution_plan,
            description="Test",
            constraints=[],
            preferences=[],
            recovery_paths=[
                RecoveryPath(
                    trigger_step=0,
                    strategy=RecoveryStrategy.RETRY,
                    max_retries=3,
                    backoff_ms=10,  # Short for testing
                )
            ],
            conditionals=[],
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            operations=[],
            global_constraints={},
            metadata={},
        )
        enhanced.initialize_state(
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        # Tool fails twice, succeeds on third try
        tool_executor = AsyncMock(spec=ToolExecutorAdapter)
        tool_executor.execute = AsyncMock(side_effect=[
            Exception("Timeout"),
            Exception("Timeout"),
            {"result": "success"},
        ])

        engine = ExecutionEngine(mock_enforcer, tool_executor)

        await engine.execute(enhanced)

        assert enhanced.state.status == StepStatus.COMPLETED
        result = enhanced.state.step_results[0]
        assert result.status == StepStatus.COMPLETED
        assert result.retry_count == 2  # Two retries before success

    @pytest.mark.asyncio
    async def test_execute_tool_failure_exhausts_retries(
        self,
        sample_execution_plan: ExecutionPlan,
        mock_enforcer: MagicMock,
    ):
        """Test that execution fails when retries exhausted."""
        enhanced = EnhancedExecutionPlan(
            base_plan=sample_execution_plan,
            description="Test",
            constraints=[],
            preferences=[],
            recovery_paths=[
                RecoveryPath(
                    trigger_step=0,
                    strategy=RecoveryStrategy.RETRY,
                    max_retries=2,
                    backoff_ms=10,
                )
            ],
            conditionals=[],
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            operations=[],
            global_constraints={},
            metadata={},
        )
        enhanced.initialize_state(
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        tool_executor = AsyncMock(spec=ToolExecutorAdapter)
        tool_executor.execute = AsyncMock(side_effect=Exception("Persistent failure"))

        engine = ExecutionEngine(mock_enforcer, tool_executor)

        await engine.execute(enhanced)

        result = enhanced.state.step_results[0]
        assert result.status == StepStatus.FAILED
        assert result.error == "Persistent failure"
        assert result.retry_count == 2

    @pytest.mark.asyncio
    async def test_execute_fail_fast_stops_execution(
        self,
        mock_enforcer: MagicMock,
    ):
        """Test that fail_fast strategy stops execution immediately."""
        # Create plan with multiple steps
        actions = [
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="step1", arguments={}),
                category=IntentCategory.FILE_READ,
                resources=[],
                risk_score=10,
            ),
            PlannedAction(
                sequence=1,
                tool_call=ToolCall(name="step2", arguments={}),
                category=IntentCategory.FILE_READ,
                resources=[],
                risk_score=10,
            ),
        ]

        base_plan = ExecutionPlan(
            plan_id="plan-123",
            session_id="session-456",
            request_hash="a" * 64,
            actions=actions,
            risk_assessment=RiskAssessment(
                overall_score=10,
                level=RiskLevel.LOW,
                factors=[],
                mitigations=[],
            ),
        )

        enhanced = EnhancedExecutionPlan(
            base_plan=base_plan,
            description="Test",
            constraints=[],
            preferences=[],
            recovery_paths=[
                RecoveryPath(
                    trigger_step=0,
                    strategy=RecoveryStrategy.FAIL_FAST,
                    max_retries=1,
                    backoff_ms=10,
                )
            ],
            conditionals=[],
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            operations=[],
            global_constraints={},
            metadata={},
        )
        enhanced.initialize_state(
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        tool_executor = AsyncMock(spec=ToolExecutorAdapter)
        tool_executor.execute = AsyncMock(side_effect=Exception("Step 1 failed"))

        engine = ExecutionEngine(mock_enforcer, tool_executor)

        await engine.execute(enhanced)

        # Should have stopped after first step
        assert enhanced.state.status == StepStatus.FAILED
        assert len(enhanced.state.step_results) == 1
        assert enhanced.state.failed_steps == 1

    @pytest.mark.asyncio
    async def test_execute_skip_strategy(
        self,
        sample_execution_plan: ExecutionPlan,
        mock_enforcer: MagicMock,
    ):
        """Test that skip strategy marks step as skipped and continues."""
        enhanced = EnhancedExecutionPlan(
            base_plan=sample_execution_plan,
            description="Test",
            constraints=[],
            preferences=[],
            recovery_paths=[
                RecoveryPath(
                    trigger_step=0,
                    strategy=RecoveryStrategy.SKIP,
                    max_retries=1,
                    backoff_ms=10,
                )
            ],
            conditionals=[],
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            operations=[],
            global_constraints={},
            metadata={},
        )
        enhanced.initialize_state(
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        tool_executor = AsyncMock(spec=ToolExecutorAdapter)
        tool_executor.execute = AsyncMock(side_effect=Exception("Failed"))

        engine = ExecutionEngine(mock_enforcer, tool_executor)

        await engine.execute(enhanced)

        result = enhanced.state.step_results[0]
        assert result.status == StepStatus.SKIPPED
        assert result.recovery_action == RecoveryStrategy.SKIP

    @pytest.mark.asyncio
    async def test_execute_calls_step_complete_callback(
        self,
        sample_enhanced_plan: EnhancedExecutionPlan,
        mock_enforcer: MagicMock,
        mock_tool_executor: AsyncMock,
    ):
        """Test that on_step_complete callback is called."""
        callback_results = []

        async def on_step_complete(result: StepResult):
            callback_results.append(result)

        engine = ExecutionEngine(mock_enforcer, mock_tool_executor)

        await engine.execute(sample_enhanced_plan, on_step_complete=on_step_complete)

        assert len(callback_results) == 1
        assert callback_results[0].status == StepStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_marks_action_complete_in_enforcer(
        self,
        sample_enhanced_plan: EnhancedExecutionPlan,
        mock_enforcer: MagicMock,
        mock_tool_executor: AsyncMock,
    ):
        """Test that enforcer.mark_action_complete is called."""
        engine = ExecutionEngine(mock_enforcer, mock_tool_executor)

        await engine.execute(sample_enhanced_plan)

        mock_enforcer.mark_action_complete.assert_called_once_with("plan-123", 0)

    @pytest.mark.asyncio
    async def test_execute_sets_completed_at_timestamp(
        self,
        sample_enhanced_plan: EnhancedExecutionPlan,
        mock_enforcer: MagicMock,
        mock_tool_executor: AsyncMock,
    ):
        """Test that completed_at timestamp is set."""
        engine = ExecutionEngine(mock_enforcer, mock_tool_executor)

        await engine.execute(sample_enhanced_plan)

        assert sample_enhanced_plan.state.completed_at is not None

        result = sample_enhanced_plan.state.step_results[0]
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.duration_ms >= 0


class TestExecutionEngineConditionals:
    """Tests for conditional execution logic."""

    @pytest.mark.asyncio
    async def test_conditional_skip_on_previous_failure(
        self,
        mock_enforcer: MagicMock,
    ):
        """Test that steps are skipped based on conditionals."""
        actions = [
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="step0", arguments={}),
                category=IntentCategory.FILE_READ,
                resources=[],
                risk_score=10,
            ),
            PlannedAction(
                sequence=1,
                tool_call=ToolCall(name="step1_if_success", arguments={}),
                category=IntentCategory.FILE_READ,
                resources=[],
                risk_score=10,
            ),
        ]

        base_plan = ExecutionPlan(
            plan_id="plan-123",
            session_id="session-456",
            request_hash="a" * 64,
            actions=actions,
            risk_assessment=RiskAssessment(
                overall_score=10,
                level=RiskLevel.LOW,
                factors=[],
                mitigations=[],
            ),
        )

        enhanced = EnhancedExecutionPlan(
            base_plan=base_plan,
            description="Test",
            constraints=[],
            preferences=[],
            recovery_paths=[],
            conditionals=[
                ConditionalBranch(
                    condition="step_0_success",
                    if_true=[1],  # Run step 1 if step 0 succeeds
                    if_false=[],
                )
            ],
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            operations=[],
            global_constraints={},
            metadata={},
        )
        enhanced.initialize_state(
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        # First step fails
        tool_executor = AsyncMock(spec=ToolExecutorAdapter)
        call_count = 0

        async def execute_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Step 0 failed")
            return {"result": "success"}

        tool_executor.execute = execute_side_effect

        engine = ExecutionEngine(mock_enforcer, tool_executor)

        await engine.execute(enhanced)

        # Step 1 should be skipped because step 0 failed
        assert enhanced.state.skipped_steps == 1
        assert len(enhanced.state.step_results) == 2
        assert enhanced.state.step_results[1].status == StepStatus.SKIPPED


# --- AgentContextInjector Tests ---


class TestAgentContextInjector:
    """Tests for AgentContextInjector."""

    def test_generate_context_basic(
            self,
            sample_enhanced_plan: EnhancedExecutionPlan,
    ):
        """Test basic context generation."""
        injector = AgentContextInjector()

        context = injector.generate_context(sample_enhanced_plan)

        assert "## Execution Plan" in context
        assert "plan-123" in context
        assert "Test plan" in context
        assert "read_file" in context

    def test_generate_context_includes_constraints(self):
        """Test that constraints are included in context."""
        base_plan = ExecutionPlan(
            plan_id="plan-123",
            session_id="session-456",
            request_hash="a" * 64,
            actions=[],
            risk_assessment=RiskAssessment(
                overall_score=10,
                level=RiskLevel.LOW,
                factors=[],
                mitigations=[],
            ),
        )

        enhanced = EnhancedExecutionPlan(
            base_plan=base_plan,
            description="Test",
            constraints=["No file deletion", "Max 5 operations"],
            preferences=[],
            recovery_paths=[],
            conditionals=[],
            execution_mode=ExecutionMode.GOVERNANCE_DRIVEN,
            operations=[],
            global_constraints={},
            metadata={},
        )
        enhanced.initialize_state(
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        injector = AgentContextInjector()
        context = injector.generate_context(enhanced)

        assert "No file deletion" in context
        assert "Max 5 operations" in context

    def test_generate_context_shows_current_step_marker(self):
        """Test that current step is marked."""
        action = PlannedAction(
            sequence=0,
            tool_call=ToolCall(name="read_file", arguments={"path": "/test"}),
            category=IntentCategory.FILE_READ,
            resources=[],
            risk_score=10,
        )

        base_plan = ExecutionPlan(
            plan_id="plan-123",
            session_id="session-456",
            request_hash="a" * 64,
            actions=[action],
            risk_assessment=RiskAssessment(
                overall_score=10,
                level=RiskLevel.LOW,
                factors=[],
                mitigations=[],
            ),
        )

        enhanced = EnhancedExecutionPlan(
            base_plan=base_plan,
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
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        injector = AgentContextInjector()
        context = injector.generate_context(enhanced)

        # Current step should be marked
        assert "[CURRENT]" in context

    def test_generate_context_includes_rules(
            self,
            sample_enhanced_plan: EnhancedExecutionPlan,
    ):
        """Test that execution rules are included."""
        injector = AgentContextInjector()

        context = injector.generate_context(sample_enhanced_plan)

        assert "Execute steps in order" in context
        assert "Do not skip steps" in context
        assert "Report any errors" in context

    def test_generate_context_no_state(self):
        """Test context generation when state is None."""
        base_plan = ExecutionPlan(
            plan_id="plan-123",
            session_id="session-456",
            request_hash="a" * 64,
            actions=[
                PlannedAction(
                    sequence=0,
                    tool_call=ToolCall(name="test", arguments={}),
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

        enhanced = EnhancedExecutionPlan(
            base_plan=base_plan,
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
        # State not initialized

        injector = AgentContextInjector()
        context = injector.generate_context(enhanced)

        # Should not crash, no status markers
        assert "## Execution Plan" in context
        assert "[CURRENT]" not in context


# --- Executor Tests ---


class TestExecutor:
    """Tests for Executor entry point."""

    @pytest.mark.asyncio
    async def test_execute_governance_driven(
            self,
            sample_enhanced_plan: EnhancedExecutionPlan,
            mock_enforcer: MagicMock,
            mock_tool_executor: AsyncMock,
    ):
        """Test execution in governance-driven mode."""
        executor = Executor(mock_enforcer, mock_tool_executor)

        await executor.execute(plan=sample_enhanced_plan)

        # Check that execution completed
        assert sample_enhanced_plan.state.status == StepStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_agent_mode_returns_context(
            self,
            sample_execution_plan: ExecutionPlan,
            mock_enforcer: MagicMock,
            mock_tool_executor: AsyncMock,
    ):
        """Test execution in agent mode returns context dict."""
        enhanced = EnhancedExecutionPlan(
            base_plan=sample_execution_plan,
            description="Agent guided test",
            constraints=["Follow the plan"],
            preferences=[],
            recovery_paths=[],
            conditionals=[],
            execution_mode= ExecutionMode.AGENT_GUIDED,  # String "agent" as in your implementation
            operations=[],
            global_constraints={},
            metadata={},
        )
        enhanced.initialize_state(
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        executor = Executor(mock_enforcer, mock_tool_executor)

        result = await executor.execute(plan=enhanced)

        assert isinstance(result, dict)
        assert result["type"] == "agent_plan"
        assert result["planId"] == "plan-123"
        assert "agentContext" in result
        assert "Agent guided test" in result["agentContext"]

    @pytest.mark.asyncio
    async def test_execute_agent_mode_includes_constraints(
            self,
            sample_execution_plan: ExecutionPlan,
            mock_enforcer: MagicMock,
            mock_tool_executor: AsyncMock,
    ):
        """Test that agent mode context includes constraints."""
        enhanced = EnhancedExecutionPlan(
            base_plan=sample_execution_plan,
            description="Test",
            constraints=["No deletion", "Max 3 retries"],
            preferences=[],
            recovery_paths=[],
            conditionals=[],
            execution_mode=ExecutionMode.AGENT_GUIDED,
            operations=[],
            global_constraints={},
            metadata={},
        )
        enhanced.initialize_state(
            session_id="session-456",
            user_id="user-123",
            token="token-abc",
        )

        executor = Executor(mock_enforcer, mock_tool_executor)

        result = await executor.execute(plan=enhanced)

        assert "No deletion" in result["agentContext"]
        assert "Max 3 retries" in result["agentContext"]

    @pytest.mark.asyncio
    async def test_execute_creates_engine_for_governance_mode(
            self,
            sample_enhanced_plan: EnhancedExecutionPlan,
            mock_enforcer: MagicMock,
            mock_tool_executor: AsyncMock,
    ):
        """Test that execute creates engine and runs it for governance mode."""
        executor = Executor(mock_enforcer, mock_tool_executor)

        await executor.execute(plan=sample_enhanced_plan)

        # Verify tool was executed via engine
        mock_tool_executor.execute.assert_called_once()


# --- Logging Tests ---


class TestExecutionEngineLogging:
    """Tests for execution engine logging."""

    @pytest.mark.asyncio
    async def test_execute_logs_completion(
            self,
            sample_enhanced_plan: EnhancedExecutionPlan,
            mock_enforcer: MagicMock,
            mock_tool_executor: AsyncMock,
            caplog,
    ):
        """Test that execution completion is logged."""
        import logging
        caplog.set_level(logging.DEBUG)

        engine = ExecutionEngine(mock_enforcer, mock_tool_executor)

        await engine.execute(sample_enhanced_plan)

        # Should have debug log about completion
        assert any("finished" in record.message.lower() or "plan-123" in record.message
                   for record in caplog.records)
