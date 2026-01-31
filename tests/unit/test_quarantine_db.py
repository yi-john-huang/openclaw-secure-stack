"""Tests for quarantine database."""

from __future__ import annotations

from pathlib import Path

from src.quarantine.db import QuarantineDB


def test_create_tables(tmp_path: Path) -> None:
    db = QuarantineDB(str(tmp_path / "test.db"))
    # Should not raise
    skill = db.get_skill("nonexistent")
    assert skill is None
    db.close()


def test_insert_and_retrieve(tmp_path: Path) -> None:
    db = QuarantineDB(str(tmp_path / "test.db"))
    db.upsert_skill(
        name="test-skill", path="/skills/test",
        checksum="a" * 64, status="quarantined", findings_json="[]",
    )
    skill = db.get_skill("test-skill")
    assert skill is not None
    assert skill["status"] == "quarantined"
    db.close()


def test_update_status(tmp_path: Path) -> None:
    db = QuarantineDB(str(tmp_path / "test.db"))
    db.upsert_skill(name="s1", path="/p", checksum="a" * 64, status="quarantined")
    db.update_status("s1", "overridden", override_user="admin", override_ack="I accept")
    skill = db.get_skill("s1")
    assert skill is not None
    assert skill["status"] == "overridden"
    assert skill["override_user"] == "admin"
    db.close()


def test_list_by_status(tmp_path: Path) -> None:
    db = QuarantineDB(str(tmp_path / "test.db"))
    db.upsert_skill(name="a", path="/a", checksum="a" * 64, status="quarantined")
    db.upsert_skill(name="b", path="/b", checksum="b" * 64, status="active")
    db.upsert_skill(name="c", path="/c", checksum="c" * 64, status="quarantined")

    quarantined = db.list_by_status("quarantined")
    assert len(quarantined) == 2
    active = db.list_by_status("active")
    assert len(active) == 1
    db.close()


def test_upsert_updates_existing(tmp_path: Path) -> None:
    db = QuarantineDB(str(tmp_path / "test.db"))
    db.upsert_skill(name="s1", path="/p1", checksum="a" * 64, status="active")
    db.upsert_skill(name="s1", path="/p2", checksum="b" * 64, status="quarantined")
    skill = db.get_skill("s1")
    assert skill is not None
    assert skill["status"] == "quarantined"
    assert skill["path"] == "/p2"
    db.close()
