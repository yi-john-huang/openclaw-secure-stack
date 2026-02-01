"""Prompt injection sanitizer — detects and neutralizes injection patterns."""

from __future__ import annotations

import json
import re
from pathlib import Path

from src.audit.logger import AuditLogger
from src.models import (
    AuditEvent,
    AuditEventType,
    RiskLevel,
    SanitizationRule,
    SanitizeResult,
)


class PromptInjectionError(Exception):
    """Raised when a prompt injection is detected and the action is 'reject'."""

    def __init__(self, patterns: list[str]) -> None:
        self.patterns = patterns
        super().__init__(f"Prompt injection detected: {patterns}")


class PromptSanitizer:
    """Configurable prompt injection detection and neutralization."""

    def __init__(self, rules_path: str, audit_logger: AuditLogger | None = None) -> None:
        self.audit_logger = audit_logger
        self._rules: list[SanitizationRule] = []
        self._compiled: list[tuple[SanitizationRule, re.Pattern[str]]] = []
        self.load_rules(rules_path)

    def load_rules(self, rules_path: str) -> None:
        path = Path(rules_path)
        if not path.exists():
            raise FileNotFoundError(f"Prompt rules file not found: {rules_path}")
        raw = json.loads(path.read_text())
        self._rules = [SanitizationRule.model_validate(r) for r in raw]
        self._compiled = [
            (rule, re.compile(rule.pattern, re.IGNORECASE))
            for rule in self._rules
        ]

    def sanitize(self, input_text: str) -> SanitizeResult:
        detected_patterns: list[str] = []
        reject_patterns: list[str] = []
        clean = input_text

        for rule, pattern in self._compiled:
            if pattern.search(clean):
                detected_patterns.append(rule.name)
                if rule.action == "reject":
                    reject_patterns.append(rule.name)
                elif rule.action == "strip":
                    clean = pattern.sub("", clean).strip()

        injection_detected = len(detected_patterns) > 0

        if injection_detected and self.audit_logger:
            self.audit_logger.log(AuditEvent(
                event_type=AuditEventType.PROMPT_INJECTION,
                action="sanitize",
                result="blocked" if reject_patterns else "success",
                risk_level=RiskLevel.HIGH,
                details={"patterns": detected_patterns},
            ))

        if reject_patterns:
            raise PromptInjectionError(reject_patterns)

        return SanitizeResult(
            clean=clean,
            injection_detected=injection_detected,
            patterns=detected_patterns,
        )

    def scan(self, text: str) -> list[str]:
        """Detect-only scan — returns list of matched rule names without modifying text."""
        findings: list[str] = []
        for rule, pattern in self._compiled:
            if pattern.search(text):
                findings.append(rule.name)
        return findings
