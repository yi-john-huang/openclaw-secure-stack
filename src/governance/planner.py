"""Plan generation for the governance layer.

This module provides the PlanGenerator class for:
- Building ordered PlannedActions from classified intent
- Extracting resource access patterns
- Calculating risk assessments
- Generating complete ExecutionPlans
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

from src.governance.models import (
    ExecutionPlan,
    Intent,
    IntentCategory,
    PlannedAction,
    ResourceAccess,
    RiskAssessment,
    RiskLevel,
    ToolCall,
)


class PlanGenerator:
    """Generates execution plans from classified intent.

    Uses patterns config for risk calculation and resource extraction.
    """

    # Base risk scores by category
    BASE_RISK: dict[IntentCategory, int] = {
        IntentCategory.FILE_READ: 10,
        IntentCategory.FILE_WRITE: 30,
        IntentCategory.FILE_DELETE: 50,
        IntentCategory.NETWORK_REQUEST: 30,
        IntentCategory.CODE_EXECUTION: 70,
        IntentCategory.SKILL_INVOCATION: 20,
        IntentCategory.SYSTEM_COMMAND: 70,
        IntentCategory.UNKNOWN: 40,
    }

    # Risk level thresholds
    RISK_THRESHOLDS: list[tuple[int, RiskLevel]] = [
        (80, RiskLevel.CRITICAL),
        (60, RiskLevel.HIGH),
        (40, RiskLevel.MEDIUM),
        (20, RiskLevel.LOW),
        (0, RiskLevel.INFO),
    ]

    # Patterns for extracting resources
    PATH_KEYS = {"path", "file", "filepath", "filename", "directory", "dir"}
    URL_KEYS = {"url", "uri", "endpoint", "href"}

    def __init__(self, patterns_path: str) -> None:
        """Initialize the plan generator.

        Args:
            patterns_path: Path to the intent-patterns.json config file.
        """
        self._patterns_path = patterns_path
        self._risk_multipliers: dict[str, float] = {}
        self._tool_categories: dict[str, str] = {}  # tool -> category
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from patterns file."""
        path = Path(self._patterns_path)
        if path.exists():
            config = json.loads(path.read_text())
            self._risk_multipliers = config.get("risk_multipliers", {})

            # Build reverse mapping: tool -> category
            for category, tools in config.get("tool_categories", {}).items():
                for tool in tools:
                    self._tool_categories[tool.lower()] = category

    def _categorize_tool(self, tool_name: str) -> IntentCategory:
        """Get the category for a tool name."""
        category_str = self._tool_categories.get(tool_name.lower())
        if category_str:
            try:
                return IntentCategory(category_str)
            except ValueError:
                pass
        return IntentCategory.UNKNOWN

    def _extract_resources(self, tool_call: ToolCall) -> list[ResourceAccess]:
        """Extract resource access patterns from a tool call.

        Args:
            tool_call: The tool call to analyze.

        Returns:
            List of ResourceAccess objects for resources accessed.
        """
        resources: list[ResourceAccess] = []
        tool_lower = tool_call.name.lower()

        # Determine operation from tool name
        if "read" in tool_lower or "get" in tool_lower or "list" in tool_lower:
            operation = "read"
        elif "write" in tool_lower or "create" in tool_lower or "save" in tool_lower:
            operation = "write"
        elif "delete" in tool_lower or "remove" in tool_lower:
            operation = "delete"
        elif "http" in tool_lower or "fetch" in tool_lower or "api" in tool_lower:
            operation = "fetch"
        elif "execute" in tool_lower or "run" in tool_lower:
            operation = "execute"
        else:
            operation = "access"

        # Extract resources from arguments
        self._extract_from_dict(tool_call.arguments, resources, operation)

        return resources

    def _extract_from_dict(
        self,
        data: dict[str, Any],
        resources: list[ResourceAccess],
        operation: str,
    ) -> None:
        """Recursively extract resources from a dictionary."""
        for key, value in data.items():
            key_lower = key.lower()

            if isinstance(value, str):
                # Check for file paths
                if key_lower in self.PATH_KEYS or self._looks_like_path(value):
                    resources.append(
                        ResourceAccess(type="file", path=value, operation=operation)
                    )
                # Check for URLs
                elif key_lower in self.URL_KEYS or self._looks_like_url(value):
                    resources.append(
                        ResourceAccess(type="url", path=value, operation=operation)
                    )

            elif isinstance(value, dict):
                self._extract_from_dict(value, resources, operation)

            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._extract_from_dict(item, resources, operation)
                    elif isinstance(item, str):
                        if self._looks_like_path(item):
                            resources.append(
                                ResourceAccess(type="file", path=item, operation=operation)
                            )
                        elif self._looks_like_url(item):
                            resources.append(
                                ResourceAccess(type="url", path=item, operation=operation)
                            )

    def _looks_like_path(self, value: str) -> bool:
        """Check if a string looks like a file path."""
        return value.startswith("/") or value.startswith("./") or "\\" in value

    def _looks_like_url(self, value: str) -> bool:
        """Check if a string looks like a URL."""
        return bool(re.match(r"^https?://", value, re.IGNORECASE))

    def _build_actions(self, intent: Intent) -> list[PlannedAction]:
        """Build ordered PlannedActions from intent.

        Args:
            intent: The classified intent.

        Returns:
            List of PlannedAction objects with sequential ordering.
        """
        actions: list[PlannedAction] = []

        for sequence, tool_call in enumerate(intent.tool_calls):
            category = self._categorize_tool(tool_call.name)
            resources = self._extract_resources(tool_call)

            # Calculate risk score
            base_risk = self.BASE_RISK.get(category, 40)
            multiplier = self._risk_multipliers.get(category.value, 1.0)
            risk_score = min(int(base_risk * multiplier), 100)

            actions.append(
                PlannedAction(
                    sequence=sequence,
                    tool_call=tool_call,
                    category=category,
                    resources=resources,
                    risk_score=risk_score,
                )
            )

        return actions

    def _assess_risk(self, actions: list[PlannedAction]) -> RiskAssessment:
        """Calculate risk assessment for a set of actions.

        Args:
            actions: List of planned actions to assess.

        Returns:
            RiskAssessment with overall score, level, and factors.
        """
        if not actions:
            return RiskAssessment(
                overall_score=0,
                level=RiskLevel.INFO,
                factors=[],
                mitigations=[],
            )

        # Calculate overall score (max of individual scores, with small additive factor)
        max_score = max(a.risk_score for a in actions)
        additive = min(len(actions) - 1, 5) * 2  # Small bonus for multiple actions
        overall_score = min(max_score + additive, 100)

        # Determine risk level
        level = RiskLevel.INFO
        for threshold, risk_level in self.RISK_THRESHOLDS:
            if overall_score >= threshold:
                level = risk_level
                break

        # Identify risk factors
        factors: list[str] = []
        categories_seen = set()
        for action in actions:
            if action.category not in categories_seen:
                categories_seen.add(action.category)
                if action.category != IntentCategory.UNKNOWN:
                    factors.append(action.category.value)

        # Suggest mitigations
        mitigations: list[str] = []
        if level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            mitigations.append("requires_approval")
        if IntentCategory.CODE_EXECUTION in categories_seen:
            mitigations.append("sandbox_execution")
        if IntentCategory.NETWORK_REQUEST in categories_seen:
            mitigations.append("url_allowlist")

        return RiskAssessment(
            overall_score=overall_score,
            level=level,
            factors=factors,
            mitigations=mitigations,
        )

    def generate(
        self,
        intent: Intent,
        request_body: dict[str, Any],
        session_id: str | None = None,
    ) -> ExecutionPlan:
        """Generate an execution plan from classified intent.

        Args:
            intent: The classified intent for the request.
            request_body: The original request body for hashing.
            session_id: Optional session ID for tracking.

        Returns:
            A complete ExecutionPlan with actions and risk assessment.
        """
        # Generate unique plan ID
        plan_id = str(uuid.uuid4())

        # Compute request hash
        request_json = json.dumps(request_body, sort_keys=True)
        request_hash = hashlib.sha256(request_json.encode()).hexdigest()

        # Build actions
        actions = self._build_actions(intent)

        # Assess risk
        risk_assessment = self._assess_risk(actions)

        return ExecutionPlan(
            plan_id=plan_id,
            session_id=session_id,
            request_hash=request_hash,
            actions=actions,
            risk_assessment=risk_assessment,
        )
