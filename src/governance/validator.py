"""Policy validation for the governance layer.

This module provides the PolicyValidator class for:
- Loading and parsing policy rules from JSON config
- Evaluating action policies (category-based)
- Evaluating resource policies (path/URL patterns)
- Evaluating sequence policies (action order)
- Evaluating rate policies (session limits)
- Producing ValidationResult with decision
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

from src.governance.models import (
    ExecutionPlan,
    GovernanceDecision,
    PlannedAction,
    PolicyEffect,
    PolicyRule,
    PolicyType,
    PolicyViolation,
    Session,
    ValidationResult,
)
from src.models import Severity


class PolicyValidator:
    """Validates execution plans against configurable policy rules.

    Supports policy types:
    - action: Category-based allow/deny/require_approval
    - resource: Path/URL pattern matching
    - sequence: Forbidden action sequences
    - rate: Session rate limiting
    """

    def __init__(self, policies_path: str) -> None:
        """Initialize the validator with policies from config.

        Args:
            policies_path: Path to the governance-policies.json config file.

        Raises:
            FileNotFoundError: If the config file doesn't exist.
            ValueError: If the config file is invalid.
        """
        self._policies_path = policies_path
        self._policies: list[PolicyRule] = []
        self._compiled_patterns: dict[str, re.Pattern[str]] = {}
        self._load_policies()

    def _load_policies(self) -> None:
        """Load policies from the config file."""
        path = Path(self._policies_path)
        if not path.exists():
            raise FileNotFoundError(f"Policies config not found: {self._policies_path}")

        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in policies config: {e}") from e

        if not isinstance(data, list):
            raise ValueError("Policies config must be a JSON array")

        # Parse policies
        for item in data:
            try:
                policy = PolicyRule(
                    id=item["id"],
                    name=item["name"],
                    type=PolicyType(item["type"]),
                    effect=PolicyEffect(item["effect"]),
                    conditions=item.get("conditions", {}),
                    priority=item.get("priority", 0),
                )
                self._policies.append(policy)

                # Pre-compile regex patterns
                if "path_pattern" in policy.conditions:
                    pattern_str = policy.conditions["path_pattern"]
                    self._compiled_patterns[pattern_str] = re.compile(
                        pattern_str, re.IGNORECASE
                    )
            except (KeyError, ValueError) as e:
                # Skip invalid policies but log warning
                logger.warning("Skipping invalid policy in %s: %s", self._policies_path, e)
                continue

        # Sort by priority (highest first)
        self._policies.sort(key=lambda p: p.priority, reverse=True)

    @property
    def policies(self) -> list[PolicyRule]:
        """Get the loaded policies."""
        return self._policies

    def _check_action_policies(self, action: PlannedAction) -> list[PolicyViolation]:
        """Check action against action-type policies.

        Args:
            action: The planned action to check.

        Returns:
            List of policy violations found.
        """
        violations: list[PolicyViolation] = []

        for policy in self._policies:
            if policy.type != PolicyType.ACTION:
                continue

            # Check category condition
            category_condition = policy.conditions.get("category")
            if category_condition and action.category.value == category_condition:
                if policy.effect == PolicyEffect.DENY:
                    violations.append(
                        PolicyViolation(
                            rule_id=policy.id,
                            severity=Severity.CRITICAL,
                            action_sequence=action.sequence,
                            message=f"Action blocked by policy: {policy.name}",
                        )
                    )
                elif policy.effect == PolicyEffect.REQUIRE_APPROVAL:
                    violations.append(
                        PolicyViolation(
                            rule_id=policy.id,
                            severity=Severity.MEDIUM,
                            action_sequence=action.sequence,
                            message=f"Action requires approval: {policy.name}",
                        )
                    )
                # ALLOW effect means no violation

        return violations

    def _check_resource_policies(self, action: PlannedAction) -> list[PolicyViolation]:
        """Check action's resources against resource-type policies.

        Args:
            action: The planned action to check.

        Returns:
            List of policy violations found.
        """
        violations: list[PolicyViolation] = []

        for resource in action.resources:
            for policy in self._policies:
                if policy.type != PolicyType.RESOURCE:
                    continue

                # Check resource type condition
                type_condition = policy.conditions.get("type")
                if type_condition and type_condition != resource.type:
                    continue

                # Check path pattern condition
                path_pattern = policy.conditions.get("path_pattern")
                if path_pattern:
                    compiled = self._compiled_patterns.get(path_pattern)
                    if compiled and compiled.search(resource.path):
                        if policy.effect == PolicyEffect.ALLOW:
                            break  # Allow takes precedence for this resource
                        if policy.effect == PolicyEffect.DENY:
                            violations.append(
                                PolicyViolation(
                                    rule_id=policy.id,
                                    severity=Severity.CRITICAL,
                                    action_sequence=action.sequence,
                                    message=f"Resource blocked: {resource.path}",
                                )
                            )
                        elif policy.effect == PolicyEffect.REQUIRE_APPROVAL:
                            violations.append(
                                PolicyViolation(
                                    rule_id=policy.id,
                                    severity=Severity.MEDIUM,
                                    action_sequence=action.sequence,
                                    message=f"Resource requires approval: {resource.path}",
                                )
                            )

        return violations

    def _check_sequence_policies(self, plan: ExecutionPlan) -> list[PolicyViolation]:
        """Check plan for forbidden action sequences.

        Args:
            plan: The execution plan to check.

        Returns:
            List of policy violations found.
        """
        violations: list[PolicyViolation] = []

        for policy in self._policies:
            if policy.type != PolicyType.SEQUENCE:
                continue

            pattern = policy.conditions.get("pattern", [])
            window = policy.conditions.get("window", len(plan.actions))

            if len(pattern) < 2:
                continue

            # Convert actions to category sequence
            categories = [(a.sequence, a.category.value) for a in plan.actions]

            # Look for pattern within sliding window
            for i, (seq_i, cat_i) in enumerate(categories):
                if cat_i != pattern[0]:
                    continue

                # Found first element of pattern, look for rest within window
                pattern_idx = 1
                for j in range(i + 1, min(i + window + 1, len(categories))):
                    seq_j, cat_j = categories[j]
                    if cat_j == pattern[pattern_idx]:
                        pattern_idx += 1
                        if pattern_idx >= len(pattern):
                            # Full pattern matched
                            if policy.effect in (PolicyEffect.DENY, PolicyEffect.REQUIRE_APPROVAL):
                                severity = (
                                    Severity.CRITICAL
                                    if policy.effect == PolicyEffect.DENY
                                    else Severity.MEDIUM
                                )
                                violations.append(
                                    PolicyViolation(
                                        rule_id=policy.id,
                                        severity=severity,
                                        action_sequence=seq_i,
                                        message=f"Forbidden sequence detected: {policy.name}",
                                    )
                                )
                            break

        return violations

    def _check_rate_policies(self, session: Session | None) -> list[PolicyViolation]:
        """Check session against rate-type policies.

        Args:
            session: The current session, or None if no session.

        Returns:
            List of policy violations found.
        """
        violations: list[PolicyViolation] = []

        if session is None:
            return violations

        for policy in self._policies:
            if policy.type != PolicyType.RATE:
                continue

            max_actions = policy.conditions.get("max_actions_per_session")
            if max_actions is not None and session.action_count > max_actions:
                violations.append(
                    PolicyViolation(
                        rule_id=policy.id,
                        severity=Severity.HIGH,
                        action_sequence=None,
                        message=f"Rate limit exceeded: {session.action_count} > {max_actions}",
                    )
                )

        return violations

    def validate(
        self,
        plan: ExecutionPlan,
        session: Session | None = None,
    ) -> ValidationResult:
        """Validate an execution plan against all policies.

        Args:
            plan: The execution plan to validate.
            session: Optional session for rate limiting.

        Returns:
            ValidationResult with decision and any violations.
        """
        violations: list[PolicyViolation] = []

        # Check each action
        for action in plan.actions:
            violations.extend(self._check_action_policies(action))
            violations.extend(self._check_resource_policies(action))

        # Check sequence policies
        violations.extend(self._check_sequence_policies(plan))

        # Check rate policies
        violations.extend(self._check_rate_policies(session))

        # Determine decision based on violations
        has_critical = any(v.severity == Severity.CRITICAL for v in violations)
        has_medium = any(v.severity == Severity.MEDIUM for v in violations)
        has_high = any(v.severity == Severity.HIGH for v in violations)

        if has_critical or has_high:
            decision = GovernanceDecision.BLOCK
        elif has_medium:
            decision = GovernanceDecision.REQUIRE_APPROVAL
        else:
            decision = GovernanceDecision.ALLOW

        return ValidationResult(
            valid=len(violations) == 0,
            violations=violations,
            decision=decision,
            approval_required=decision == GovernanceDecision.REQUIRE_APPROVAL,
        )
