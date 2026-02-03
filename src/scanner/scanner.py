"""Core skill scanner — orchestrates AST-based static analysis of skills."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from pathlib import Path

import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser, Tree

from src.audit.logger import AuditLogger
from src.models import (
    AuditEvent,
    AuditEventType,
    PinResult,
    RiskLevel,
    ScanFinding,
    ScanReport,
    Severity,
)
from src.scanner.trust_score import compute_trust_score

logger = logging.getLogger(__name__)

JS_LANGUAGE = Language(tsjs.language())

_parser: Parser | None = None


def get_parser() -> Parser:
    global _parser  # noqa: PLW0603
    if _parser is None:
        _parser = Parser(JS_LANGUAGE)
    return _parser


def parse_js(source: bytes) -> Tree:
    return get_parser().parse(source)


class ScannerConfigError(Exception):
    pass


class ScanRule(ABC):
    """Base class for scanner rules."""

    id: str
    name: str
    severity: Severity

    @abstractmethod
    def detect(self, tree: Tree, source: bytes, file_path: str) -> list[ScanFinding]:
        ...


class PatternScanRule(ScanRule):
    """Rule that matches string patterns in source code."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: Severity,
        patterns: list[str],
        description: str,
    ) -> None:
        self.id = rule_id
        self.name = name
        self.severity = severity
        self.patterns = patterns
        self.description = description

    def detect(self, tree: Tree, source: bytes, file_path: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        source_str = source.decode("utf-8", errors="replace")
        lines = source_str.split("\n")

        for pattern in self.patterns:
            for line_num, line in enumerate(lines, start=1):
                if pattern in line:
                    findings.append(
                        ScanFinding(
                            rule_id=self.id,
                            rule_name=self.name,
                            severity=self.severity,
                            file=file_path,
                            line=line_num,
                            column=line.index(pattern),
                            snippet=line.strip()[:200],
                            message=self.description,
                        )
                    )
        return findings


def _get_builtin_ast_rules() -> list[ScanRule]:
    """Return the built-in AST-based scanner rules."""
    from src.scanner.rules.dangerous_api import DangerousAPIRule
    from src.scanner.rules.fs_abuse import FSAbuseRule
    from src.scanner.rules.network_exfil import NetworkExfilRule

    return [DangerousAPIRule(), NetworkExfilRule(), FSAbuseRule()]


def load_rules_from_config(config: list[dict[str, object]] | None) -> list[ScanRule]:
    """Load scan rules from parsed JSON config. Fail-closed on missing config."""
    if config is None:
        raise ScannerConfigError("Scanner rules config is missing — refusing to approve any skill")

    rules: list[ScanRule] = []
    for entry in config:
        rule_id = str(entry["id"])
        name = str(entry["name"])
        severity = Severity(str(entry["severity"]))
        description = str(entry.get("description", ""))

        if "patterns" in entry:
            patterns = [str(p) for p in entry["patterns"]]  # type: ignore[union-attr]
            rules.append(PatternScanRule(rule_id, name, severity, patterns, description))

    return rules


def load_rules_from_file(rules_path: str) -> list[ScanRule]:
    """Load rules from a JSON file, plus built-in AST rules."""
    path = Path(rules_path)
    if not path.exists():
        raise ScannerConfigError(f"Scanner rules file not found: {rules_path}")
    config = json.loads(path.read_text())
    rules = load_rules_from_config(config)
    rules.extend(_get_builtin_ast_rules())
    return rules


def _compute_checksum(skill_path: str) -> str:
    """Compute SHA-256 checksum of all files in a skill directory or single file."""
    path = Path(skill_path)
    hasher = hashlib.sha256()

    if path.is_file():
        hasher.update(path.read_bytes())
    elif path.is_dir():
        for f in sorted(path.rglob("*")):
            if f.is_file():
                hasher.update(f.read_bytes())
    return hasher.hexdigest()


def load_pins_from_file(pins_path: str) -> tuple[dict[str, dict[str, str]], bool]:
    """Load skill pin data from JSON file. Returns (pins, file_present)."""
    path = Path(pins_path)
    if not path.exists():
        logger.warning("Skill pin file not found at %s — proceeding without pin checks", pins_path)
        return {}, False
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        logger.warning("Skill pin file at %s is invalid JSON — proceeding without pin checks", pins_path)
        return {}, True
    if not isinstance(data, dict):
        logger.warning("Skill pin file at %s must be a JSON object — proceeding without pin checks", pins_path)
        return {}, True
    return data, True


def _find_js_files(skill_path: str) -> list[Path]:
    """Find all JS/TS files in a skill path."""
    path = Path(skill_path)
    if path.is_file():
        return [path] if path.suffix in (".js", ".ts", ".mjs", ".cjs") else []
    return sorted(
        f
        for f in path.rglob("*")
        if f.is_file() and f.suffix in (".js", ".ts", ".mjs", ".cjs")
    )


class SkillScanner:
    """Orchestrates scanning of skills against all configured rules."""

    def __init__(
        self,
        rules: list[ScanRule],
        audit_logger: AuditLogger | None = None,
        pin_data: dict[str, dict[str, str]] | None = None,
        pins_loaded: bool = False,
    ) -> None:
        self.rules = rules
        self.audit_logger = audit_logger
        self._pins: dict[str, dict[str, str]] = pin_data or {}
        self._pins_loaded = pins_loaded

    def _verify_pin(self, skill_path: Path, skill_name: str, checksum: str | None = None) -> PinResult:
        """Compare SHA-256 of skill file/dir against pinned hash."""
        actual = checksum or _compute_checksum(str(skill_path))
        pin_entry = self._pins.get(skill_name, {})
        expected = pin_entry.get("sha256")
        if expected is None:
            if self._pins_loaded:
                logger.warning(
                    "Skill '%s' has no pin entry in skill-pins.json — proceeding with scan",
                    skill_name,
                )
            return PinResult(status="unpinned")
        if actual != expected:
            return PinResult(status="mismatch", expected=expected, actual=actual)
        return PinResult(status="verified")

    def scan(self, skill_path: str) -> ScanReport:
        start = time.monotonic()
        path = Path(skill_path)
        skill_name = path.name
        checksum = _compute_checksum(skill_path)
        all_findings: list[ScanFinding] = []

        # Pin verification: mismatch → critical finding, skip AST scan
        if self._pins_loaded or self._pins:
            pin_result = self._verify_pin(path, skill_name, checksum=checksum)
            if pin_result.status == "mismatch":
                trust_score = compute_trust_score()
                all_findings.append(
                    ScanFinding(
                        rule_id="PIN_MISMATCH",
                        rule_name="Skill pin hash mismatch",
                        severity=Severity.CRITICAL,
                        file=str(path),
                        line=0,
                        column=0,
                        snippet="",
                        message=f"Expected hash {pin_result.expected}, got {pin_result.actual}",
                    )
                )
                duration_ms = int((time.monotonic() - start) * 1000)
                return ScanReport(
                    skill_name=skill_name,
                    skill_path=str(path),
                    checksum=checksum,
                    findings=all_findings,
                    trust_score=trust_score,
                    scanned_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    duration_ms=duration_ms,
                )

        js_files = _find_js_files(skill_path)
        for js_file in js_files:
            source = js_file.read_bytes()
            try:
                tree = parse_js(source)
            except Exception:
                all_findings.append(
                    ScanFinding(
                        rule_id="PARSE_ERROR",
                        rule_name="Unparseable file",
                        severity=Severity.HIGH,
                        file=str(js_file),
                        line=0,
                        column=0,
                        snippet="",
                        message=f"Failed to parse {js_file.name} — treating as suspicious",
                    )
                )
                continue

            for rule in self.rules:
                findings = rule.detect(tree, source, str(js_file))
                all_findings.extend(findings)

        duration_ms = int((time.monotonic() - start) * 1000)
        trust_score = compute_trust_score()
        report = ScanReport(
            skill_name=skill_name,
            skill_path=str(path),
            checksum=checksum,
            findings=all_findings,
            trust_score=trust_score,
            scanned_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            duration_ms=duration_ms,
        )

        if self.audit_logger:
            self.audit_logger.log(
                AuditEvent(
                    event_type=AuditEventType.SKILL_SCAN,
                    action=f"scan:{skill_name}",
                    result="success",
                    risk_level=RiskLevel.HIGH if all_findings else RiskLevel.INFO,
                    details={
                        "skill_name": skill_name,
                        "findings_count": len(all_findings),
                    },
                )
            )

        return report

    def scan_all(self, skills_dir: str) -> list[ScanReport]:
        path = Path(skills_dir)
        reports: list[ScanReport] = []
        for child in sorted(path.iterdir()):
            if child.is_dir() or child.suffix in (".js", ".ts", ".mjs", ".cjs"):
                reports.append(self.scan(str(child)))
        return reports
