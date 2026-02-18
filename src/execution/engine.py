"""Execution engine for the executor layer.

This module provides the ExecutionEngine class for:
- Driving plan execution step by step
- Handling governance checks at each step
- Managing recovery and retry logic
- Tracking execution state
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, Callable, Awaitable

from src.governance.enforcer import GovernanceEnforcer, EnforcementResult
from src.governance.models import (
    GovernanceDecision,
    ToolCall,
    EnhancedExecutionPlan,
    ExecutionContext,
    RecoveryPath,
    RecoveryStrategy,
    StepResult,
    StepStatus,
)


# Type for tool execution function
ToolExecutor = Callable[[str, dict[str, Any]], Awaitable[Any]]

logger = logging.getLogger(__name__)


class ExecutionError(Exception):
    """Raised when execution fails."""
    
    def __init__(self, message: str, step: int, recoverable: bool = False):
        super().__init__(message)
        self.step = step
        self.recoverable = recoverable


class GovernanceBlockedError(ExecutionError):
    """Raised when governance blocks execution."""
    
    def __init__(self, message: str, step: int, reason: str):
        super().__init__(message, step, recoverable=False)
        self.reason = reason


class ToolExecutorAdapter(ABC):
    """Abstract adapter for executing tools.
    
    Implementations connect to actual tool providers:
    - LocalToolExecutor: Calls tools locally
    - AgentToolExecutor: Sends tools to LLM agent
    - MockToolExecutor: For testing
    """
    
    @abstractmethod
    async def execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        context: ExecutionContext,
    ) -> Any:
        """Execute a tool and return its result.
        
        Args:
            tool_name: Name of the tool to execute.
            arguments: Tool arguments.
            context: Execution context.
            
        Returns:
            Tool execution result.
            
        Raises:
            Exception: If tool execution fails.
        """
        pass


class ExecutionEngine:
    """Drives plan execution step by step with governance enforcement.
    
    The engine:
    1. Iterates through plan actions in sequence
    2. Checks governance before each action
    3. Executes the action via ToolExecutorAdapter
    4. Handles failures according to recovery paths
    5. Tracks state throughout execution
    """
    
    def __init__(
        self,
        enforcer: GovernanceEnforcer,
        tool_executor: ToolExecutorAdapter,
    ) -> None:
        """Initialize the execution engine.
        
        Args:
            enforcer: Governance enforcer for action validation.
            tool_executor: Adapter for executing tools.
        """
        self._enforcer = enforcer
        self._tool_executor = tool_executor
    
    async def execute(
        self,
        plan: EnhancedExecutionPlan,
        on_step_complete: Callable[[StepResult], Awaitable[None]] | None = None,
    ):
        """Execute the plan and return final state.
        
        Args:
            plan: The enhanced execution plan.
            context: Execution context with credentials and config.
            on_step_complete: Optional callback after each step.
            
        Returns:
            Final ExecutionState with all results.
        """

        plan.state.status = StepStatus.RUNNING

        try:
            # Execute each action
            for action in plan.actions:
                # Check if we should skip (conditional logic)
                if self._should_skip(action.sequence, plan):
                    result = self._create_skipped_result(action)
                    plan.state.step_results.append(result)
                    plan.state.skipped_steps += 1
                    continue
                
                # Get recovery path for this action
                recovery_path = self._get_recovery_path(action.sequence, plan)
                
                # Execute with retry logic
                result = await self._execute_with_recovery(
                    action=action,
                    context=plan.state.context,
                    recovery_path=recovery_path,
                )
                
                # Update state
                plan.state.step_results.append(result)
                plan.state.current_sequence = action.sequence + 1
                
                if result.status == StepStatus.COMPLETED:
                    plan.state.completed_steps += 1
                elif result.status == StepStatus.FAILED:
                    plan.state.failed_steps += 1
                    if recovery_path and recovery_path.strategy == RecoveryStrategy.FAIL_FAST:
                        plan.state.status = StepStatus.FAILED
                        break
                elif result.status == StepStatus.BLOCKED:
                    if plan.state.context.fail_on_governance_block:
                        plan.state.status = StepStatus.BLOCKED
                        break
                
                # Callback
                if on_step_complete:
                    await on_step_complete(result)
            
            # Mark complete if we got through all steps
            if plan.state.status == StepStatus.RUNNING:
                plan.state.status = StepStatus.COMPLETED

        except Exception as e:
            plan.state.status = StepStatus.FAILED
            logger.exception(
                "Execution failed with exception: plan_id=%s, error=%s",
                plan.plan_id,
                str(e),
            )

        logger.debug(
            "Execution finished: plan_id=%s, final_status=%s, duration=%s",
            plan.plan_id,
            plan.state.status.value,
            self._calc_total_duration(plan),
        )
        plan.state.completed_at = datetime.now(UTC).isoformat()
    
    async def _execute_with_recovery(
        self,
        action: Any,  # PlannedAction
        context: ExecutionContext,
        recovery_path: RecoveryPath | None,
    ) -> StepResult:
        """Execute a single action with recovery logic.
        
        Args:
            action: The action to execute.
            context: Execution context.
            recovery_path: Recovery path for this action.
            
        Returns:
            StepResult with outcome.
        """
        started_at = datetime.now(UTC).isoformat()
        retry_count = 0
        max_retries = recovery_path.max_retries if recovery_path else 1
        
        last_error: str | None = None
        
        while retry_count < max_retries:
            try:
                # Check governance
                tool_call = ToolCall(
                    name=action.tool_call.name,
                    arguments=action.tool_call.arguments,
                    id=action.tool_call.id,
                )
                
                enforcement = self._enforcer.enforce_action(
                    plan_id=context.plan_id,
                    token=context.token,
                    tool_call=tool_call,
                )
                
                if not enforcement.allowed:
                    return StepResult(
                        sequence=action.sequence,
                        status=StepStatus.BLOCKED,
                        started_at=started_at,
                        completed_at=datetime.now(UTC).isoformat(),
                        tool_name=action.tool_call.name,
                        tool_args=action.tool_call.arguments,
                        governance_decision=GovernanceDecision.BLOCK,
                        governance_reason=enforcement.reason,
                    )
                
                # Execute tool
                result = await self._tool_executor.execute(
                    tool_name=action.tool_call.name,
                    arguments=action.tool_call.arguments,
                    context=context,
                )
                
                # Mark action complete in enforcer
                self._enforcer.mark_action_complete(context.plan_id, action.sequence)
                
                completed_at = datetime.now(UTC).isoformat()
                duration_ms = self._calc_duration_ms(started_at, completed_at)
                
                return StepResult(
                    sequence=action.sequence,
                    status=StepStatus.COMPLETED,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    tool_name=action.tool_call.name,
                    tool_args=action.tool_call.arguments,
                    tool_result=result,
                    governance_decision=GovernanceDecision.ALLOW,
                    retry_count=retry_count,
                )
                
            except Exception as e:
                last_error = str(e)
                retry_count += 1
                
                # Check if we should retry
                if recovery_path and recovery_path.strategy == RecoveryStrategy.RETRY:
                    if retry_count < max_retries:
                        # Backoff before retry
                        await asyncio.sleep(recovery_path.backoff_ms / 1000)
                        continue
                
                # No more retries
                break
        
        # All retries exhausted or not retrying
        completed_at = datetime.now(UTC).isoformat()
        duration_ms = self._calc_duration_ms(started_at, completed_at)
        
        # Determine final status based on recovery strategy
        status = StepStatus.FAILED
        recovery_action = None
        
        if recovery_path:
            recovery_action = recovery_path.strategy
            if recovery_path.strategy == RecoveryStrategy.SKIP:
                status = StepStatus.SKIPPED
        
        return StepResult(
            sequence=action.sequence,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            tool_name=action.tool_call.name,
            tool_args=action.tool_call.arguments,
            error=last_error,
            retry_count=retry_count,
            recovery_action=recovery_action,
        )
    
    def _should_skip(
        self,
        sequence: int,
        plan: EnhancedExecutionPlan
    ) -> bool:
        """Check if this step should be skipped based on conditionals."""
        # Check conditionals
        for cond in plan.conditionals:
            if sequence in cond.if_true or sequence in cond.if_false:
                # Evaluate condition based on previous results
                # For now, simple: if any previous step failed, skip dependent steps
                for result in plan.state.step_results:
                    if result.status == StepStatus.FAILED:
                        if sequence in cond.if_true:
                            return True
        return False
    
    def _get_recovery_path(
        self,
        sequence: int,
        plan: EnhancedExecutionPlan,
    ) -> RecoveryPath | None:
        """Get recovery path for a specific step."""
        for path in plan.recovery_paths:
            if path.trigger_step == sequence:
                return path
        return None
    
    def _create_skipped_result(self, action: Any) -> StepResult:
        """Create a StepResult for a skipped action."""
        now = datetime.now(UTC).isoformat()
        return StepResult(
            sequence=action.sequence,
            status=StepStatus.SKIPPED,
            started_at=now,
            completed_at=now,
            tool_name=action.tool_call.name,
            tool_args=action.tool_call.arguments,
        )
    
    def _calc_duration_ms(self, started_at: str, completed_at: str) -> int:
        """Calculate duration in milliseconds."""
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(completed_at)
        return int((end - start).total_seconds() * 1000)

    def _calc_total_duration(self, plan: EnhancedExecutionPlan) -> str:
        """Calculate total execution duration as human-readable string."""
        if plan.state is None:
            return "unknown"
        if plan.state.started_at is None or plan.state.completed_at is None:
            return "incomplete"

        start = datetime.fromisoformat(plan.state.started_at)
        end = datetime.fromisoformat(plan.state.completed_at)
        duration_sec = (end - start).total_seconds()

        if duration_sec < 1:
            return f"{int(duration_sec * 1000)}ms"
        elif duration_sec < 60:
            return f"{duration_sec:.1f}s"
        else:
            return f"{duration_sec / 60:.1f}m"
