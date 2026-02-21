"""Plan generation for the governance layer.

This module provides the PlanGenerator class for:
- Building ordered PlannedActions from classified intent
- Extracting resource access patterns
- Calculating risk assessments
- Generating complete ExecutionPlans
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from src.governance.models import (
    ExecutionPlan,
    Intent,
    IntentCategory,
    PlannedAction,
    ResourceAccess,
    RiskAssessment,
    RiskLevel,
    ToolCall,
    ExecutionMode,
    RecoveryPath,
    ConditionalBranch,
    RecoveryStrategy,
    EnhancedExecutionPlan,
)
from src.llm.client import LLMClient

ENHANCE_PLAN_PROMPT = """You are enhancing an execution plan with operational knowledge.

## Base Plan
{plan_json}

## User Context
{context}

## Output Schema
Your response MUST conform to this JSON schema:
{schema}

Generate an enhanced plan that:
1. Adds a human-readable description
2. Converts actions to operations with allow/deny rules
3. Defines global constraints
4. Adds recovery paths for risky steps
5. Adds conditional branches based on step outcomes
6. Sets appropriate execution mode

Return ONLY valid JSON conforming to the schema. No markdown, no explanation.
"""


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

    def __init__(
        self,
        patterns_path: str,
        schema_path: str = "config/execution-plan.json"
    ) -> None:
        """Initialize the plan generator.

        Args:
            patterns_path: Path to the intent-patterns.json config file.
            llm: Optional LLM client for plan enhancement.
            schema_path: Path to execution-plan.json schema file.
        """
        self._patterns_path = patterns_path
        self._schema_path = schema_path
        self._risk_multipliers: dict[str, float] = {}
        self._tool_categories: dict[str, str] = {}
        self._schema: dict[str, Any] | None = None
        self._load_config()
        self._load_schema()

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

    # Sensitive argument keys that should be redacted before sending to LLM
    SENSITIVE_KEYS = {
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "auth", "authorization", "credential", "credentials", "private_key",
        "privatekey", "access_token", "refresh_token", "bearer", "jwt",
        "ssh_key", "sshkey", "passphrase", "pin", "otp", "mfa",
    }

    def enhance(
            self,
            plan: ExecutionPlan,
            llm: LLMClient,
            context: dict[str, Any] | None = None,
    ) -> EnhancedExecutionPlan:
        """Enhance a base plan with LLM-generated operational knowledge.

        Reads schema from config/execution-plan.json and asks LLM to produce
        enhancements conforming to that schema.

        Args:
            plan: The base execution plan to enhance.
            context: Optional user/operational context for the LLM.
            llm: LLM call through proxy

        Returns:
            EnhancedExecutionPlan wrapping the base plan with enhancements.

        Raises:
            RuntimeError: If no LLM client configured or schema not found.
            ValueError: If LLM returns invalid JSON.
        """
        if llm is None:
            raise RuntimeError("No LLM client configured for plan enhancement")

        if self._schema is None:
            raise RuntimeError(
                f"Schema not found: {self._schema_path}. "
                "Create config/execution-plan.json with the plan schema."
            )

        # Serialize and sanitize base plan for prompt
        plan_dict = plan.model_dump(mode="json")
        sanitized_plan = self._sanitize_for_llm(plan_dict)
        plan_json = json.dumps(sanitized_plan, indent=2)

        context_str = json.dumps(context or {}, indent=2)
        schema_str = json.dumps(self._schema, indent=2)

        # Build prompt
        prompt = ENHANCE_PLAN_PROMPT.format(
            plan_json=plan_json,
            context=context_str,
            schema=schema_str,
        )

        # Security audit: log external API call with sanitized plan
        logger.info(
            "SECURITY_AUDIT: Calling external LLM API for plan enhancement: "
            "plan_id=%s, action_count=%d, fields_redacted=%s",
            plan.plan_id,
            len(plan.actions),
            self._count_redacted_fields(sanitized_plan),
        )

        # Call LLM
        raw = llm.complete(prompt=prompt, temperature=0)

        # Parse response
        enhanced_dict = self._parse_llm_response(raw)

        # Build EnhancedExecutionPlan from base plan + LLM output
        return self._build_enhanced_plan(plan, enhanced_dict)

    def _sanitize_for_llm(self, data: Any) -> Any:
        """Recursively sanitize data before sending to LLM.

        Redacts values for sensitive keys to prevent credential leakage.
        """
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if key.lower() in self.SENSITIVE_KEYS:
                    result[key] = "[REDACTED]"
                else:
                    result[key] = self._sanitize_for_llm(value)
            return result
        elif isinstance(data, list):
            return [self._sanitize_for_llm(item) for item in data]
        else:
            return data

    def _count_redacted_fields(self, data: Any) -> int:
        """Count how many fields were redacted in sanitized data."""
        count = 0
        if isinstance(data, dict):
            for key, value in data.items():
                if value == "[REDACTED]":
                    count += 1
                else:
                    count += self._count_redacted_fields(value)
        elif isinstance(data, list):
            for item in data:
                count += self._count_redacted_fields(item)
        return count

    def _parse_llm_response(self, raw: str) -> dict[str, Any]:
        """Parse and clean LLM JSON response."""
        cleaned = raw.strip()

        # Strip markdown code fences if present
        if cleaned.startswith("```"):
            # Remove opening fence (with optional language tag)
            cleaned = cleaned.split("\n", 1)[1] if "\n" in cleaned else cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned.rsplit("```", 1)[0]
        cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            raise ValueError(f"LLM returned invalid JSON: {e}\nRaw: {raw[:500]}") from e

    def _build_enhanced_plan(
            self,
            base_plan: ExecutionPlan,
            llm_output: dict[str, Any],
    ) -> EnhancedExecutionPlan:
        """Build EnhancedExecutionPlan from base plan and LLM output."""

        # Parse recovery paths
        recovery_paths = self._parse_recovery_paths(
            llm_output.get("recoveryPaths", [])
        )

        # Parse conditionals
        conditionals = self._parse_conditionals(
            llm_output.get("conditionals", [])
        )

        # Parse execution mode
        execution_mode = self._parse_execution_mode(
            llm_output.get("executionMode")
        )

        # Extract constraints list from global constraints object
        global_constraints = llm_output.get("constraints", {})
        constraints_list: list[str] = []
        if isinstance(global_constraints, dict):
            # Convert constraint flags to human-readable strings
            if global_constraints.get("allowUnplanned") is False:
                constraints_list.append("No unplanned operations allowed")
            if global_constraints.get("requireSequential"):
                constraints_list.append("Operations must execute sequentially")
            if max_ops := global_constraints.get("maxTotalOperations"):
                constraints_list.append(f"Maximum {max_ops} total operations")
            if max_dur := global_constraints.get("maxDurationMs"):
                constraints_list.append(f"Maximum duration: {max_dur}ms")
        elif isinstance(global_constraints, list):
            constraints_list = global_constraints

        return EnhancedExecutionPlan(
            base_plan=base_plan,
            description=llm_output.get("description"),
            constraints=constraints_list,
            preferences=llm_output.get("preferences", []),
            recovery_paths=recovery_paths,
            conditionals=conditionals,
            execution_mode=execution_mode,
            operations=llm_output.get("operations", []),
            global_constraints=global_constraints if isinstance(global_constraints, dict) else {},
            metadata=llm_output.get("metadata", {}),
        )

    def _parse_recovery_paths(self, paths: list[dict[str, Any]]) -> list[RecoveryPath]:
        """Parse recovery paths from LLM output."""
        result = []
        for p in paths:
            try:
                strategy_str = p.get("strategy", "fail_fast")
                strategy = RecoveryStrategy(strategy_str)
                result.append(
                    RecoveryPath(
                        trigger_step=p["triggerStep"],
                        strategy=strategy,
                        max_retries=p.get("maxRetries", 3),
                        backoff_ms=p.get("backoffMs", 1000),
                        trigger_errors=p.get("triggerErrors", []),
                    )
                )
            except (KeyError, ValueError):
                continue  # Skip malformed entries
        return result

    def _parse_conditionals(self, conditionals: list[dict[str, Any]]) -> list[ConditionalBranch]:
        """Parse conditional branches from LLM output."""
        result = []
        for c in conditionals:
            try:
                result.append(
                    ConditionalBranch(
                        condition=c["condition"],
                        if_true=c.get("ifTrue", []),
                        if_false=c.get("ifFalse", []),
                    )
                )
            except KeyError:
                continue
        return result

    def _parse_execution_mode(self, mode_str: str | None) -> ExecutionMode:
        """Parse execution mode from string."""
        if mode_str == "agent_guided":
            return ExecutionMode.AGENT_GUIDED
        elif mode_str == "hybrid":
            return ExecutionMode.HYBRID
        return ExecutionMode.GOVERNANCE_DRIVEN

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

    def _load_schema(self) -> None:
        """Load execution plan schema."""
        path = Path(self._schema_path)
        if path.exists():
            self._schema = json.loads(path.read_text())
        else:
            self._schema = None

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