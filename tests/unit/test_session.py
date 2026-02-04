"""Tests for session management."""

from __future__ import annotations

import time
from pathlib import Path

import pytest


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "test_governance.db")


@pytest.fixture
def session_mgr(db_path: str):
    from src.governance.session import SessionManager
    return SessionManager(db_path, ttl_seconds=3600)


class TestSessionCRUD:
    def test_get_or_create_new(self, session_mgr):
        import uuid
        session = session_mgr.get_or_create(None)
        uuid.UUID(session.session_id)  # Valid UUID
        assert session.action_count == 0

    def test_get_or_create_existing(self, session_mgr):
        s1 = session_mgr.get_or_create("sess-123")
        s2 = session_mgr.get_or_create("sess-123")
        assert s1.session_id == s2.session_id

    def test_get_nonexistent_creates_new(self, session_mgr):
        session = session_mgr.get_or_create("new-session")
        assert session.session_id == "new-session"
        assert session.action_count == 0


class TestActionRecording:
    def test_record_action_increments_count(self, session_mgr):
        from src.governance.models import GovernanceDecision
        session_mgr.get_or_create("sess-1")
        session_mgr.record_action("sess-1", {"name": "test"}, GovernanceDecision.ALLOW, 10)
        updated = session_mgr.get_or_create("sess-1")
        assert updated.action_count == 1

    def test_record_action_updates_risk(self, session_mgr):
        from src.governance.models import GovernanceDecision
        session_mgr.get_or_create("sess-1")
        session_mgr.record_action("sess-1", {"name": "test"}, GovernanceDecision.ALLOW, 30)
        updated = session_mgr.get_or_create("sess-1")
        assert updated.risk_accumulator == 30


class TestHistory:
    def test_get_history(self, session_mgr):
        from src.governance.models import GovernanceDecision
        session_mgr.get_or_create("sess-1")
        session_mgr.record_action("sess-1", {"name": "a"}, GovernanceDecision.ALLOW, 10)
        session_mgr.record_action("sess-1", {"name": "b"}, GovernanceDecision.ALLOW, 20)
        history = session_mgr.get_history("sess-1")
        assert len(history) == 2

    def test_history_limit(self, session_mgr):
        from src.governance.models import GovernanceDecision
        session_mgr.get_or_create("sess-1")
        for i in range(10):
            session_mgr.record_action("sess-1", {"name": f"action-{i}"}, GovernanceDecision.ALLOW, 5)
        history = session_mgr.get_history("sess-1", limit=5)
        assert len(history) == 5


class TestCleanup:
    def test_cleanup_expired(self, db_path):
        from src.governance.session import SessionManager
        mgr = SessionManager(db_path, ttl_seconds=1)
        mgr.get_or_create("old-sess")
        time.sleep(1.1)
        count = mgr.cleanup_expired()
        assert count >= 1
