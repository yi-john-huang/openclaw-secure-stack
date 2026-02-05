"""SQLite database operations for the governance layer.

This module provides the GovernanceDB class for persistent storage of:
- Execution plans
- Approval requests
- Sessions
- Action history
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

# SQL schema for governance tables
SCHEMA_SQL = """
-- Plans table: stores execution plans with sequence tracking
CREATE TABLE IF NOT EXISTS governance_plans (
    plan_id TEXT PRIMARY KEY,
    session_id TEXT,
    request_hash TEXT NOT NULL,
    actions_json TEXT NOT NULL,
    risk_json TEXT NOT NULL,
    decision TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    current_sequence INTEGER NOT NULL DEFAULT 0,
    retry_count INTEGER NOT NULL DEFAULT 0
);

-- Index for session lookups
CREATE INDEX IF NOT EXISTS idx_plans_session ON governance_plans(session_id);

-- Approvals table: stores approval requests
CREATE TABLE IF NOT EXISTS governance_approvals (
    approval_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    requester_id TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    violations_json TEXT NOT NULL,
    original_request_json TEXT,
    acknowledgment TEXT,
    reason TEXT,
    approved_at TEXT,
    approved_by TEXT
);

-- Index for status lookups
CREATE INDEX IF NOT EXISTS idx_approvals_status ON governance_approvals(status);

-- Sessions table: tracks multi-turn conversation context
CREATE TABLE IF NOT EXISTS governance_sessions (
    session_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    action_count INTEGER NOT NULL DEFAULT 0,
    risk_accumulator INTEGER NOT NULL DEFAULT 0
);

-- Action history table: records actions per session
CREATE TABLE IF NOT EXISTS governance_action_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    action_json TEXT NOT NULL,
    decision TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES governance_sessions(session_id)
);

-- Index for session action lookups
CREATE INDEX IF NOT EXISTS idx_action_history_session ON governance_action_history(session_id);
"""


class GovernanceDB:
    """SQLite database wrapper for governance layer persistence.

    Provides:
    - WAL mode for crash recovery
    - Parameterized queries for SQL injection prevention
    - Schema initialization on first use
    - Context manager support for connection lifecycle
    """

    def __init__(self, db_path: str) -> None:
        """Initialize the governance database.

        Args:
            db_path: Path to the SQLite database file.
        """
        self._db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._initialize()

    def _initialize(self) -> None:
        """Initialize the database connection and schema."""
        # Ensure parent directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        # Connect with row factory for dict-like access
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row

        # Enable WAL mode for crash recovery
        self._conn.execute("PRAGMA journal_mode=WAL")

        # Enable foreign key constraints
        self._conn.execute("PRAGMA foreign_keys=ON")

        # Create schema
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        """Execute a SQL statement with parameters.

        Args:
            sql: SQL statement with ? placeholders.
            params: Tuple of parameter values.

        Returns:
            The cursor after execution.
        """
        if self._conn is None:
            raise sqlite3.ProgrammingError("Database connection is closed")
        cursor = self._conn.execute(sql, params)
        self._conn.commit()
        return cursor

    def execute_returning(
        self, sql: str, params: tuple[Any, ...] = ()
    ) -> dict[str, Any] | None:
        """Execute a SQL statement with RETURNING clause and fetch the result.

        This method fetches the RETURNING result before committing, which is
        required for SQLite RETURNING clauses to work correctly.

        Args:
            sql: SQL statement with RETURNING clause and ? placeholders.
            params: Tuple of parameter values.

        Returns:
            Dictionary of returned column names to values, or None if no row returned.
        """
        if self._conn is None:
            raise sqlite3.ProgrammingError("Database connection is closed")
        cursor = self._conn.execute(sql, params)
        row = cursor.fetchone()
        self._conn.commit()
        if row is None:
            return None
        return dict(row)

    def fetch_one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        """Fetch a single row as a dictionary.

        Args:
            sql: SQL query with ? placeholders.
            params: Tuple of parameter values.

        Returns:
            Dictionary of column names to values, or None if no row found.
        """
        if self._conn is None:
            raise sqlite3.ProgrammingError("Database connection is closed")
        cursor = self._conn.execute(sql, params)
        row = cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    def fetch_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        """Fetch all rows as a list of dictionaries.

        Args:
            sql: SQL query with ? placeholders.
            params: Tuple of parameter values.

        Returns:
            List of dictionaries, one per row.
        """
        if self._conn is None:
            raise sqlite3.ProgrammingError("Database connection is closed")
        cursor = self._conn.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]

    def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> GovernanceDB:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: type | None, exc_val: Exception | None, exc_tb: object) -> None:
        """Context manager exit - close connection."""
        self.close()
