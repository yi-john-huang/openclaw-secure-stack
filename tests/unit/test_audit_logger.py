"""Tests for the audit logger."""

from __future__ import annotations

import json
from pathlib import Path

from src.audit.logger import AuditLogger
from src.models import AuditEvent, AuditEventType, RiskLevel


def _make_event(**kwargs: object) -> AuditEvent:
    defaults: dict[str, object] = {
        "event_type": AuditEventType.AUTH_FAILURE,
        "action": "login",
        "result": "failure",
        "risk_level": RiskLevel.HIGH,
    }
    defaults.update(kwargs)
    return AuditEvent(**defaults)  # type: ignore[arg-type]


def test_log_appends_json_line(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_file))
    logger.log(_make_event())

    lines = log_file.read_text().strip().split("\n")
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["event_type"] == "auth_failure"
    assert parsed["risk_level"] == "high"


def test_log_multiple_events_append(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_file))

    for i in range(3):
        logger.log(_make_event(action=f"action_{i}"))

    lines = log_file.read_text().strip().split("\n")
    assert len(lines) == 3
    for i, line in enumerate(lines):
        parsed = json.loads(line)
        assert parsed["action"] == f"action_{i}"


def test_log_creates_file_if_missing(tmp_path: Path) -> None:
    log_file = tmp_path / "subdir" / "audit.jsonl"
    assert not log_file.exists()

    logger = AuditLogger(log_path=str(log_file))
    logger.log(_make_event())

    assert log_file.exists()
    assert len(log_file.read_text().strip().split("\n")) == 1


def test_log_is_valid_jsonlines(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_file))

    logger.log(_make_event(event_type=AuditEventType.AUTH_SUCCESS))
    logger.log(_make_event(event_type=AuditEventType.SKILL_SCAN))
    logger.log(_make_event(event_type=AuditEventType.PROMPT_INJECTION))

    for line in log_file.read_text().strip().split("\n"):
        parsed = json.loads(line)  # Each line must be valid JSON
        assert "timestamp" in parsed
        assert "event_type" in parsed


def test_log_timestamps_are_iso8601(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_file))
    logger.log(_make_event())

    parsed = json.loads(log_file.read_text().strip())
    assert "T" in parsed["timestamp"]
