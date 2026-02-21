"""Plan execution entry point.

This module provides the Executor class that:
- Takes an evaluated plan
- Initializes execution state
- Delegates to ExecutionEngine or AgentContextInjector
"""

from __future__ import annotations

from typing import Any

from src.execution.engine import ExecutionEngine, ToolExecutorAdapter
from src.execution.injected_context import AgentContextInjector
from src.governance.enforcer import GovernanceEnforcer
from src.governance.models import (
    EnhancedExecutionPlan,
    ExecutionMode,
)


class ExecutionError(Exception):
    """Raised when execution fails."""
    pass


class Executor:
    """Executes enhanced plans.

    Entry point for all plan execution. Handles:
    - State initialization
    - Mode routing (governance-driven vs agent-guided)
    - Engine orchestration
    """

    def __init__(
            self,
            enforcer: GovernanceEnforcer,
            tool_executor: ToolExecutorAdapter,
    ) -> None:
        """Initialize the executor.

        Args:
            enforcer: Governance enforcer for per-action validation.
            tool_executor: Adapter for executing tools.
        """
        self._enforcer = enforcer
        self._tool_executor = tool_executor
        self._engine = ExecutionEngine(enforcer, tool_executor)
        self._injector = AgentContextInjector()

    async def execute(
            self,
            plan: EnhancedExecutionPlan
    ):
        """Execute an enhanced plan.

        Args:
            plan: The enhanced execution plan.

        Raises:
            ExecutionError: If execution fails.
        """
        # Initialize state
        # AGENT MODE
        if plan.execution_mode == ExecutionMode.AGENT_GUIDED:
            return {
                "type": "agent_plan",
                "plan_id": plan.plan_id,
                "agentContext": self._injector.generate_context(plan),
            }

        await self._engine.execute(
            plan=plan
        )