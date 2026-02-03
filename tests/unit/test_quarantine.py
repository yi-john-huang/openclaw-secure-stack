"""Tests for quarantine manager."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.models import AuditEventType, ScanFinding, ScanReport, Severity
from src.quarantine.manager import QuarantineBlockedError, QuarantineManager
from src.scanner.scanner import SkillScanner


def _mock_report(skill_name: str = "bad.js", skill_path: str = "/skills/bad.js") -> ScanReport:
    return ScanReport(
        skill_name=skill_name,
        skill_path=skill_path,
        checksum="a" * 64,
        findings=[
            ScanFinding(
                rule_id="TEST", rule_name="test", severity=Severity.HIGH,
                file="bad.js", line=1, column=0, snippet="x", message="bad",
            )
        ],
        scanned_at="2026-01-01T00:00:00Z",
        duration_ms=10,
    )


def _create_skill(tmp_path: Path, name: str) -> Path:
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir(exist_ok=True)
    skill = skills_dir / name
    skill.write_bytes(b"evil code")
    return skill


def _make_manager(tmp_path: Path) -> tuple[QuarantineManager, MagicMock]:
    mock_logger = MagicMock()
    mock_scanner = MagicMock(spec=SkillScanner)
    manager = QuarantineManager(
        db_path=str(tmp_path / "quarantine.db"),
        quarantine_dir=str(tmp_path / "quarantine"),
        scanner=mock_scanner,
        audit_logger=mock_logger,
    )
    return manager, mock_logger


def test_quarantine_moves_skill(tmp_path: Path) -> None:
    skill = _create_skill(tmp_path, "bad.js")
    manager, _ = _make_manager(tmp_path)
    report = _mock_report(skill_name="bad.js", skill_path=str(skill))
    manager.quarantine(str(skill), report)

    assert not skill.exists()
    assert (tmp_path / "quarantine" / "bad.js").exists()


def test_is_quarantined(tmp_path: Path) -> None:
    skill = _create_skill(tmp_path, "bad.js")
    manager, _ = _make_manager(tmp_path)
    manager.quarantine(str(skill), _mock_report(skill_name="bad.js", skill_path=str(skill)))

    assert manager.is_quarantined("bad.js") is True
    assert manager.is_quarantined("nonexistent") is False


def test_force_override(tmp_path: Path) -> None:
    skill = _create_skill(tmp_path, "bad.js")
    manager, _ = _make_manager(tmp_path)
    manager.quarantine(str(skill), _mock_report(skill_name="bad.js", skill_path=str(skill)))
    manager.force_override("bad.js", user_id="admin", ack="I accept the risk")

    assert manager.is_quarantined("bad.js") is False


def test_override_logged(tmp_path: Path) -> None:
    skill = _create_skill(tmp_path, "bad.js")
    manager, mock_logger = _make_manager(tmp_path)
    manager.quarantine(str(skill), _mock_report(skill_name="bad.js", skill_path=str(skill)))
    manager.force_override("bad.js", user_id="admin", ack="I accept")

    # Find the SKILL_OVERRIDE log call
    override_calls = [
        call for call in mock_logger.log.call_args_list
        if call[0][0].event_type == AuditEventType.SKILL_OVERRIDE
    ]
    assert len(override_calls) == 1


def test_get_quarantined(tmp_path: Path) -> None:
    skill = _create_skill(tmp_path, "bad.js")
    manager, _ = _make_manager(tmp_path)
    manager.quarantine(str(skill), _mock_report(skill_name="bad.js", skill_path=str(skill)))

    quarantined = manager.get_quarantined()
    assert len(quarantined) == 1
    assert quarantined[0].name == "bad.js"


class TestQuarantineBlockedError:
    def test_error_contains_skill_name(self):
        err = QuarantineBlockedError("my-skill")
        assert "my-skill" in str(err)
        assert err.skill_name == "my-skill"


class TestEnforceQuarantine:
    def test_blocks_quarantined_skill(self, tmp_path: Path) -> None:
        skill = _create_skill(tmp_path, "evil.js")
        manager, mock_logger = _make_manager(tmp_path)
        manager.quarantine(str(skill), _mock_report(skill_name="evil.js", skill_path=str(skill)))
        with pytest.raises(QuarantineBlockedError):
            manager.enforce_quarantine("evil.js")
        # Verify audit event was logged for the block
        block_calls = [
            c for c in mock_logger.log.call_args_list
            if c[0][0].event_type == AuditEventType.SKILL_QUARANTINE
            and "Blocked" in c[0][0].action
        ]
        assert len(block_calls) == 1

    def test_allows_active_skill(self, tmp_path: Path) -> None:
        manager, _ = _make_manager(tmp_path)
        # Insert an active skill directly
        manager.db.upsert_skill(
            name="good.js", path="/skills/good.js", checksum="a" * 64, status="active",
        )
        manager.enforce_quarantine("good.js")  # should not raise

    def test_allows_unknown_skill(self, tmp_path: Path) -> None:
        manager, _ = _make_manager(tmp_path)
        manager.enforce_quarantine("unknown")  # should not raise

    def test_allows_overridden_skill(self, tmp_path: Path) -> None:
        skill = _create_skill(tmp_path, "risky.js")
        manager, _ = _make_manager(tmp_path)
        manager.quarantine(str(skill), _mock_report(skill_name="risky.js", skill_path=str(skill)))
        manager.force_override("risky.js", user_id="admin", ack="I accept")
        manager.enforce_quarantine("risky.js")  # should not raise
