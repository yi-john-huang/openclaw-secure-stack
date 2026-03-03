"""Agent context injection for agent-guided execution.

EXPERIMENTAL: This module is not yet integrated into the main application.
"""

from __future__ import annotations

from src.governance.models import EnhancedExecutionPlan, StepStatus


class AgentContextInjector:
    """Injects plan into LLM agent context."""

    def generate_context(self, plan: EnhancedExecutionPlan) -> str:
        """Generate context string to inject into agent.

        Args:
            plan: The enhanced execution plan.

        Returns:
            String to inject into agent context/system prompt.
        """
        lines = [
            "## Execution Plan",
            "",
            f"Plan ID: {plan.plan_id}",
            f"Description: {plan.description or 'N/A'}",
            "",
            "### Constraints (MUST follow)",
        ]

        for constraint in plan.constraints:
            lines.append(f"- {constraint}")

        if not plan.constraints:
            lines.append("- None specified")

        lines.extend(["", "### Steps to Execute"])

        for action in plan.actions:
            status_marker = self._get_status_marker(action.sequence, plan)
            args_str = ", ".join(f"{k}={v}" for k, v in action.tool_call.arguments.items())
            lines.append(
                f"{action.sequence + 1}. {action.tool_call.name}({args_str}){status_marker}"
            )

        lines.extend([
            "",
            "### Rules",
            "- Execute steps in order",
            "- Do not skip steps unless instructed",
            "- Report any errors immediately",
            "- Do not deviate from the plan without approval",
        ])

        return "\n".join(lines)

    def _get_status_marker(self, sequence: int, plan: EnhancedExecutionPlan) -> str:
        """Get status marker for a step."""
        if plan.state is None:
            return ""

        if sequence < plan.state.current_sequence:
            if sequence < len(plan.state.step_results):
                result = plan.state.step_results[sequence]
                return f" [{result.status.value}]"
        elif sequence == plan.state.current_sequence:
            return " [CURRENT]"

        return ""