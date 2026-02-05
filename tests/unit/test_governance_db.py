"""Tests for governance database operations."""

from __future__ import annotations

import sqlite3

import pytest

from tests.conftest import MOCK_CHECKSUM


@pytest.fixture
def db(governance_db_path: str):
    """Create a GovernanceDB instance."""
    from src.governance.db import GovernanceDB

    return GovernanceDB(governance_db_path)


class TestGovernanceDBInit:
    """Tests for database initialization."""

    def test_init_creates_database_file(self, governance_db_path: str):
        from pathlib import Path
        from src.governance.db import GovernanceDB

        GovernanceDB(governance_db_path)
        assert Path(governance_db_path).exists()

    def test_init_creates_schema(self, db):
        """Verify all tables exist."""
        result = db.fetch_all("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r["name"] for r in result}
        assert "governance_plans" in tables
        assert "governance_approvals" in tables
        assert "governance_sessions" in tables
        assert "governance_action_history" in tables

    def test_wal_mode_enabled(self, db):
        """Verify WAL mode for crash recovery."""
        result = db.fetch_one("PRAGMA journal_mode")
        assert result["journal_mode"] == "wal"

    def test_foreign_keys_enabled(self, db):
        """Verify foreign keys are enabled."""
        result = db.fetch_one("PRAGMA foreign_keys")
        assert result["foreign_keys"] == 1


class TestGovernanceDBOperations:
    """Tests for basic database operations."""

    def test_execute_with_params(self, db):
        """Test parameterized query execution."""
        db.execute(
            """INSERT INTO governance_sessions
               (session_id, created_at, last_activity, action_count, risk_accumulator)
               VALUES (?, ?, ?, ?, ?)""",
            ("sess-1", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0, 0),
        )
        result = db.fetch_one(
            "SELECT * FROM governance_sessions WHERE session_id = ?", ("sess-1",)
        )
        assert result is not None
        assert result["session_id"] == "sess-1"

    def test_fetch_all_returns_list(self, db):
        """Test fetch_all returns list of rows."""
        db.execute(
            """INSERT INTO governance_sessions
               (session_id, created_at, last_activity, action_count, risk_accumulator)
               VALUES (?, ?, ?, ?, ?)""",
            ("sess-1", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0, 0),
        )
        db.execute(
            """INSERT INTO governance_sessions
               (session_id, created_at, last_activity, action_count, risk_accumulator)
               VALUES (?, ?, ?, ?, ?)""",
            ("sess-2", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0, 0),
        )
        results = db.fetch_all("SELECT * FROM governance_sessions")
        assert len(results) == 2

    def test_fetch_one_returns_none_for_no_match(self, db):
        """Test fetch_one returns None when no rows match."""
        result = db.fetch_one(
            "SELECT * FROM governance_sessions WHERE session_id = ?", ("nonexistent",)
        )
        assert result is None

    def test_parameterized_query_prevents_injection(self, db):
        """Test SQL injection prevention via parameterized queries."""
        # Attempt SQL injection - should be safely handled
        malicious_id = "'; DROP TABLE governance_sessions; --"
        db.execute(
            """INSERT INTO governance_sessions
               (session_id, created_at, last_activity, action_count, risk_accumulator)
               VALUES (?, ?, ?, ?, ?)""",
            (malicious_id, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0, 0),
        )
        # Table should still exist
        result = db.fetch_all("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r["name"] for r in result}
        assert "governance_sessions" in tables
        # Malicious string should be stored literally
        result = db.fetch_one(
            "SELECT * FROM governance_sessions WHERE session_id = ?", (malicious_id,)
        )
        assert result is not None


class TestGovernancePlansTable:
    """Tests for governance_plans table."""

    def test_insert_plan(self, db):
        """Test inserting a plan."""
        db.execute(
            """INSERT INTO governance_plans
               (plan_id, session_id, request_hash, actions_json, risk_json,
                decision, created_at, expires_at, current_sequence, retry_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "plan-123",
                "sess-1",
                MOCK_CHECKSUM,
                "[]",
                "{}",
                "allow",
                "2024-01-01T00:00:00Z",
                "2024-01-01T00:15:00Z",
                0,
                0,
            ),
        )
        result = db.fetch_one(
            "SELECT * FROM governance_plans WHERE plan_id = ?", ("plan-123",)
        )
        assert result["plan_id"] == "plan-123"
        assert result["current_sequence"] == 0

    def test_update_sequence(self, db):
        """Test updating plan sequence."""
        db.execute(
            """INSERT INTO governance_plans
               (plan_id, session_id, request_hash, actions_json, risk_json,
                decision, created_at, expires_at, current_sequence, retry_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "plan-123",
                None,
                MOCK_CHECKSUM,
                "[]",
                "{}",
                "allow",
                "2024-01-01T00:00:00Z",
                "2024-01-01T00:15:00Z",
                0,
                0,
            ),
        )
        db.execute(
            "UPDATE governance_plans SET current_sequence = ? WHERE plan_id = ?",
            (1, "plan-123"),
        )
        result = db.fetch_one(
            "SELECT current_sequence FROM governance_plans WHERE plan_id = ?",
            ("plan-123",),
        )
        assert result["current_sequence"] == 1


class TestGovernanceApprovalsTable:
    """Tests for governance_approvals table."""

    def test_insert_approval(self, db):
        """Test inserting an approval request."""
        db.execute(
            """INSERT INTO governance_approvals
               (approval_id, plan_id, requester_id, status,
                requested_at, expires_at, violations_json, original_request_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "appr-123",
                "plan-123",
                "user-1",
                "pending",
                "2024-01-01T00:00:00Z",
                "2024-01-01T01:00:00Z",
                "[]",
                "{}",
            ),
        )
        result = db.fetch_one(
            "SELECT * FROM governance_approvals WHERE approval_id = ?", ("appr-123",)
        )
        assert result["status"] == "pending"

    def test_update_approval_status(self, db):
        """Test updating approval status."""
        db.execute(
            """INSERT INTO governance_approvals
               (approval_id, plan_id, requester_id, status,
                requested_at, expires_at, violations_json, original_request_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "appr-123",
                "plan-123",
                "user-1",
                "pending",
                "2024-01-01T00:00:00Z",
                "2024-01-01T01:00:00Z",
                "[]",
                "{}",
            ),
        )
        db.execute(
            """UPDATE governance_approvals
               SET status = ?, acknowledgment = ?, approved_at = ?
               WHERE approval_id = ?""",
            ("approved", "I acknowledge", "2024-01-01T00:05:00Z", "appr-123"),
        )
        result = db.fetch_one(
            "SELECT * FROM governance_approvals WHERE approval_id = ?", ("appr-123",)
        )
        assert result["status"] == "approved"
        assert result["acknowledgment"] == "I acknowledge"


class TestGovernanceSessionsTable:
    """Tests for governance_sessions table."""

    def test_insert_session(self, db):
        """Test inserting a session."""
        db.execute(
            """INSERT INTO governance_sessions
               (session_id, created_at, last_activity, action_count, risk_accumulator)
               VALUES (?, ?, ?, ?, ?)""",
            ("sess-1", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0, 0),
        )
        result = db.fetch_one(
            "SELECT * FROM governance_sessions WHERE session_id = ?", ("sess-1",)
        )
        assert result["action_count"] == 0

    def test_update_session_stats(self, db):
        """Test updating session statistics."""
        db.execute(
            """INSERT INTO governance_sessions
               (session_id, created_at, last_activity, action_count, risk_accumulator)
               VALUES (?, ?, ?, ?, ?)""",
            ("sess-1", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0, 0),
        )
        db.execute(
            """UPDATE governance_sessions
               SET action_count = action_count + 1,
                   risk_accumulator = risk_accumulator + ?,
                   last_activity = ?
               WHERE session_id = ?""",
            (30, "2024-01-01T00:05:00Z", "sess-1"),
        )
        result = db.fetch_one(
            "SELECT * FROM governance_sessions WHERE session_id = ?", ("sess-1",)
        )
        assert result["action_count"] == 1
        assert result["risk_accumulator"] == 30


class TestGovernanceActionHistoryTable:
    """Tests for governance_action_history table."""

    def test_insert_action_history(self, db):
        """Test inserting action history."""
        # First create a session
        db.execute(
            """INSERT INTO governance_sessions
               (session_id, created_at, last_activity, action_count, risk_accumulator)
               VALUES (?, ?, ?, ?, ?)""",
            ("sess-1", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0, 0),
        )
        # Then insert action history
        db.execute(
            """INSERT INTO governance_action_history
               (session_id, sequence, action_json, decision, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            ("sess-1", 0, '{"name": "read_file"}', "allow", "2024-01-01T00:00:00Z"),
        )
        results = db.fetch_all(
            "SELECT * FROM governance_action_history WHERE session_id = ?", ("sess-1",)
        )
        assert len(results) == 1
        assert results[0]["sequence"] == 0


class TestDatabaseConnection:
    """Tests for database connection management."""

    def test_close_connection(self, db):
        """Test closing database connection."""
        db.close()
        # Attempting to use after close should raise
        with pytest.raises(sqlite3.ProgrammingError):
            db.fetch_all("SELECT 1")

    def test_context_manager(self, governance_db_path: str):
        """Test using database as context manager."""
        from src.governance.db import GovernanceDB

        with GovernanceDB(governance_db_path) as db:
            db.execute(
                """INSERT INTO governance_sessions
                   (session_id, created_at, last_activity, action_count, risk_accumulator)
                   VALUES (?, ?, ?, ?, ?)""",
                ("sess-1", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", 0, 0),
            )
        # Connection should be closed after context exits
        # Verify data was committed by opening a new connection
        with GovernanceDB(governance_db_path) as db2:
            result = db2.fetch_one(
                "SELECT * FROM governance_sessions WHERE session_id = ?", ("sess-1",)
            )
            assert result is not None
