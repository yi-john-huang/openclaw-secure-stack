"""Intent classification for the governance layer.

This module provides the IntentClassifier class for:
- Extracting tool calls from OpenAI-compatible request format
- Categorizing tools into intent categories
- Analyzing arguments for sensitive patterns
- Producing classified Intent objects
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.governance.models import Intent, IntentCategory, IntentSignal, ToolCall


class IntentClassifier:
    """Classifies intent from tool calls in a request.

    Uses pattern-based classification loaded from a JSON config file.
    """

    def __init__(self, patterns_path: str) -> None:
        """Initialize the classifier with patterns from config.

        Args:
            patterns_path: Path to the intent-patterns.json config file.

        Raises:
            FileNotFoundError: If the config file doesn't exist.
            ValueError: If the config file is invalid.
        """
        self._patterns_path = patterns_path
        self._tool_categories: dict[str, list[str]] = {}
        self._argument_patterns: dict[str, list[re.Pattern[str]]] = {}
        self._risk_multipliers: dict[str, float] = {}
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load patterns from the config file."""
        path = Path(self._patterns_path)
        if not path.exists():
            raise FileNotFoundError(f"Patterns config not found: {self._patterns_path}")

        try:
            config = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in patterns config: {e}") from e

        # Validate required keys
        required_keys = {"tool_categories", "argument_patterns", "risk_multipliers"}
        missing = required_keys - set(config.keys())
        if missing:
            raise ValueError(f"Missing required keys in patterns config: {missing}")

        # Load tool categories (lowercase for case-insensitive matching)
        self._tool_categories = {
            category: [tool.lower() for tool in tools]
            for category, tools in config["tool_categories"].items()
        }

        # Compile argument patterns
        self._argument_patterns = {}
        for pattern_type, patterns in config["argument_patterns"].items():
            self._argument_patterns[pattern_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        # Load risk multipliers
        self._risk_multipliers = config["risk_multipliers"]

    def _extract_tool_calls(self, body: dict[str, Any]) -> list[ToolCall]:
        """Extract tool calls from an OpenAI-compatible request body.

        Args:
            body: The request body containing tools array.

        Returns:
            List of ToolCall objects extracted from the body.
        """
        tools = body.get("tools", [])
        if not isinstance(tools, list):
            return []

        result: list[ToolCall] = []
        for tool in tools:
            try:
                # Handle OpenAI function calling format
                if isinstance(tool, dict) and "function" in tool:
                    func = tool["function"]
                    name = func.get("name")
                    if not name:
                        continue

                    # Parse arguments (could be string or dict)
                    raw_args = func.get("arguments", {})
                    if isinstance(raw_args, str):
                        try:
                            arguments = json.loads(raw_args) if raw_args else {}
                        except json.JSONDecodeError:
                            arguments = {}
                    else:
                        arguments = raw_args if isinstance(raw_args, dict) else {}

                    # Extract optional ID
                    tool_id = tool.get("id")

                    result.append(
                        ToolCall(name=name, arguments=arguments, id=tool_id)
                    )
            except (KeyError, TypeError):
                # Skip malformed tool entries
                continue

        return result

    def _categorize_tool(self, tool_name: str) -> IntentCategory:
        """Map a tool name to an intent category.

        Args:
            tool_name: The name of the tool to categorize.

        Returns:
            The IntentCategory for the tool, or UNKNOWN if not recognized.
        """
        tool_lower = tool_name.lower()

        for category_str, tools in self._tool_categories.items():
            if tool_lower in tools:
                # Map string to enum
                try:
                    return IntentCategory(category_str)
                except ValueError:
                    continue

        return IntentCategory.UNKNOWN

    def _analyze_arguments(
        self, arguments: dict[str, Any], path: str = ""
    ) -> list[IntentSignal]:
        """Analyze arguments for sensitive patterns.

        Args:
            arguments: The arguments dict to analyze.
            path: Current path in nested structure (for recursion).

        Returns:
            List of IntentSignal objects for detected patterns.
        """
        signals: list[IntentSignal] = []

        for key, value in arguments.items():
            current_path = f"{path}.{key}" if path else key

            if isinstance(value, str):
                # Check sensitive paths
                for pattern in self._argument_patterns.get("sensitive_paths", []):
                    if pattern.search(value):
                        signals.append(
                            IntentSignal(
                                category=IntentCategory.FILE_READ,
                                confidence=0.9,
                                source="argument_pattern",
                                details=f"sensitive_path: {current_path}",
                            )
                        )
                        break  # One signal per value

                # Check external URLs
                for pattern in self._argument_patterns.get("external_urls", []):
                    if pattern.search(value):
                        signals.append(
                            IntentSignal(
                                category=IntentCategory.NETWORK_REQUEST,
                                confidence=0.9,
                                source="argument_pattern",
                                details=f"external_url: {current_path}",
                            )
                        )
                        break

            elif isinstance(value, dict):
                # Recurse into nested dicts
                signals.extend(self._analyze_arguments(value, current_path))

            elif isinstance(value, list):
                # Check list items
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        # Check patterns on string items
                        for pattern in self._argument_patterns.get("sensitive_paths", []):
                            if pattern.search(item):
                                signals.append(
                                    IntentSignal(
                                        category=IntentCategory.FILE_READ,
                                        confidence=0.9,
                                        source="argument_pattern",
                                        details=f"sensitive_path: {current_path}[{i}]",
                                    )
                                )
                                break
                    elif isinstance(item, dict):
                        signals.extend(
                            self._analyze_arguments(item, f"{current_path}[{i}]")
                        )

        return signals

    def classify(self, body: dict[str, Any]) -> Intent:
        """Classify the intent of a request.

        Args:
            body: The request body to classify.

        Returns:
            An Intent object with the classification results.
        """
        tool_calls = self._extract_tool_calls(body)

        if not tool_calls:
            return Intent(
                primary_category=IntentCategory.UNKNOWN,
                signals=[],
                tool_calls=[],
                confidence=1.0,
            )

        signals: list[IntentSignal] = []
        category_scores: dict[IntentCategory, float] = {}

        for tc in tool_calls:
            # Get category for tool
            category = self._categorize_tool(tc.name)

            # Add signal for tool category
            signals.append(
                IntentSignal(
                    category=category,
                    confidence=1.0 if category != IntentCategory.UNKNOWN else 0.5,
                    source="tool_pattern",
                    details=f"tool: {tc.name}",
                )
            )

            # Track category scores (using risk multiplier)
            multiplier = self._risk_multipliers.get(category.value, 1.0)
            category_scores[category] = category_scores.get(category, 0) + multiplier

            # Analyze arguments
            arg_signals = self._analyze_arguments(tc.arguments)
            signals.extend(arg_signals)

        # Determine primary category (highest score)
        primary_category = max(category_scores, key=lambda c: category_scores[c])

        # Calculate confidence based on signal consistency
        total_signals = len(signals)
        matching_signals = sum(1 for s in signals if s.category == primary_category)
        confidence = matching_signals / total_signals if total_signals > 0 else 0.5

        return Intent(
            primary_category=primary_category,
            signals=signals,
            tool_calls=tool_calls,
            confidence=min(confidence + 0.3, 1.0),  # Base confidence boost
        )
