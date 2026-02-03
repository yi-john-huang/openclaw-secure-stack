"""Tests for the audit logger."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from src.audit.logger import AuditLogger, ChainValidationResult, validate_audit_chain
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


# --- Rotation tests ---


def test_rotation_triggers_at_threshold(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_file), max_bytes=100, backup_count=3)
    for i in range(20):
        logger.log(_make_event(action=f"event-{i}"))
    assert (tmp_path / "audit.jsonl.1").exists()


def test_rotation_deletes_oldest(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_file), max_bytes=50, backup_count=2)
    for i in range(50):
        logger.log(_make_event(action=f"event-{i}"))
    assert not (tmp_path / "audit.jsonl.3").exists()


def test_rotation_configurable_via_env(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AUDIT_LOG_MAX_BYTES", "500")
    monkeypatch.setenv("AUDIT_LOG_BACKUP_COUNT", "7")
    logger = AuditLogger.from_env(str(tmp_path / "audit.jsonl"))
    assert logger._max_bytes == 500
    assert logger._backup_count == 7


# --- Hash chain tests ---


def test_first_entry_has_null_prev_hash(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_file))
    logger.log(_make_event(action="first"))
    entry = json.loads(log_file.read_text().strip())
    assert entry["prev_hash"] is None


def test_log_entries_include_prev_hash(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_file))
    logger.log(_make_event(action="first"))
    logger.log(_make_event(action="second"))
    lines = log_file.read_text().strip().split("\n")
    second = json.loads(lines[1])
    assert "prev_hash" in second
    expected = hashlib.sha256(lines[0].encode()).hexdigest()
    assert second["prev_hash"] == expected


def test_validate_chain_passes_for_untampered(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_file))
    for i in range(5):
        logger.log(_make_event(action=f"event-{i}"))
    result = validate_audit_chain(log_file)
    assert result.valid


def test_validate_chain_detects_tampering(tmp_path: Path) -> None:
    log_file = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path=str(log_file))
    for i in range(5):
        logger.log(_make_event(action=f"event-{i}"))
    lines = log_file.read_text().strip().split("\n")
    lines[2] = lines[2].replace("event-2", "TAMPERED")
    log_file.write_text("\n".join(lines) + "\n")
    result = validate_audit_chain(log_file)
    assert not result.valid
    # Chain breaks at line 4 because line 4's prev_hash doesn't match tampered line 3
    assert result.broken_at_line == 4
