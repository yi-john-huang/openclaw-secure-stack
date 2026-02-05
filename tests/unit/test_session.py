"""Tests for session management."""

from __future__ import annotations

import time

import pytest


@pytest.fixture
def session_mgr(governance_db_path: str):
    from src.governance.session import SessionManager
    return SessionManager(governance_db_path, ttl_seconds=3600)


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
    def test_cleanup_expired(self, governance_db_path):
        from src.governance.session import SessionManager
        mgr = SessionManager(governance_db_path, ttl_seconds=1)
        mgr.get_or_create("old-sess")
        time.sleep(1.1)
        count = mgr.cleanup_expired()
        assert count >= 1


class TestAtomicSequenceAssignment:
    """Tests for atomic sequence assignment in record_action."""

    def test_sequential_actions_get_unique_sequences(self, session_mgr):
        """Each action should get a unique sequence number."""
        from src.governance.models import GovernanceDecision

        session_mgr.get_or_create("seq-test")
        for i in range(5):
            session_mgr.record_action(
                "seq-test", {"index": i}, GovernanceDecision.ALLOW, 10
            )

        history = session_mgr.get_history("seq-test")
        sequences = [h["sequence"] for h in history]

        # All sequences should be unique
        assert len(sequences) == len(set(sequences))
        # Sequences should be 1, 2, 3, 4, 5 (action_count after each increment)
        assert sorted(sequences) == [1, 2, 3, 4, 5]

    def test_concurrent_actions_get_unique_sequences(self, governance_db_path):
        """Concurrent record_action calls should not produce duplicate sequences."""
        import threading
        from src.governance.models import GovernanceDecision
        from src.governance.session import SessionManager

        session_id = "concurrent-test"

        # Create session first
        setup_mgr = SessionManager(governance_db_path, ttl_seconds=3600)
        setup_mgr.get_or_create(session_id)
        setup_mgr.close()

        results = []
        errors = []

        def record(db_path, action_name):
            # Create manager inside the thread to avoid SQLite thread issues
            try:
                mgr = SessionManager(db_path, ttl_seconds=3600)
                mgr.record_action(
                    session_id, {"name": action_name}, GovernanceDecision.ALLOW, 10
                )
                results.append(action_name)
                mgr.close()
            except Exception as e:
                errors.append(e)

        # Launch concurrent threads
        threads = [
            threading.Thread(target=record, args=(governance_db_path, f"action-{i}"))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Errors occurred: {errors}"

        # Check all sequences are unique
        check_mgr = SessionManager(governance_db_path, ttl_seconds=3600)
        history = check_mgr.get_history(session_id, limit=100)
        sequences = [h["sequence"] for h in history]

        assert len(sequences) == 10, f"Expected 10 actions, got {len(sequences)}"
        assert len(sequences) == len(set(sequences)), (
            f"Duplicate sequences found: {sequences}"
        )
