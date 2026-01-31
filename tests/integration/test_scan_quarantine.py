"""Integration tests for the scan-quarantine-override flow."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from src.models import AuditEventType
from src.quarantine.manager import QuarantineManager
from src.scanner.scanner import SkillScanner, load_rules_from_config


def _setup(tmp_path: Path) -> tuple[SkillScanner, QuarantineManager, MagicMock]:
    config = [
        {
            "id": "T1",
            "name": "Test Pattern",
            "severity": "high",
            "patterns": ["EVIL"],
            "description": "test",
        },
    ]
    mock_logger = MagicMock()
    rules = load_rules_from_config(config)
    scanner = SkillScanner(rules=rules, audit_logger=mock_logger)
    manager = QuarantineManager(
        db_path=str(tmp_path / "q.db"),
        quarantine_dir=str(tmp_path / "quarantine"),
        scanner=scanner,
        audit_logger=mock_logger,
    )
    return scanner, manager, mock_logger


def _write_skill(tmp_path: Path, name: str, content: bytes) -> Path:
    d = tmp_path / "skills"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_bytes(content)
    return f


def test_scan_quarantine_override_flow(tmp_path: Path) -> None:
    scanner, manager, mock_logger = _setup(tmp_path)
    skill = _write_skill(tmp_path, "bad.js", b"var EVIL = 1;")

    # Scan
    report = scanner.scan(str(skill))
    assert report.findings
    assert report.checksum

    # Quarantine
    manager.quarantine(str(skill), report)
    assert not skill.exists()
    assert manager.is_quarantined("bad.js")

    # List
    items = manager.get_quarantined()
    assert len(items) == 1

    # Override
    manager.force_override("bad.js", user_id="admin", ack="I accept the risk")
    assert not manager.is_quarantined("bad.js")

    # Verify audit events
    event_types = [
        c[0][0].event_type for c in mock_logger.log.call_args_list
    ]
    assert AuditEventType.SKILL_QUARANTINE in event_types
    assert AuditEventType.SKILL_OVERRIDE in event_types


def test_clean_skill_not_quarantined(tmp_path: Path) -> None:
    scanner, manager, _ = _setup(tmp_path)
    skill = _write_skill(tmp_path, "clean.js", b"var x = 1;")

    report = scanner.scan(str(skill))
    assert not report.findings
