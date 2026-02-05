"""Session management for the governance layer.

This module provides the SessionManager class for:
- Tracking multi-turn conversation context
- Recording action history
- Managing session TTL and cleanup
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from src.governance.db import GovernanceDB
from src.governance.models import GovernanceDecision, Session


class SessionManager:
    """Manages session state for multi-turn conversations.

    Provides:
    - Session creation and retrieval
    - Action recording with risk accumulation
    - History tracking with configurable limits
    - TTL-based expiration and cleanup
    """

    DEFAULT_TTL_SECONDS = 3600  # 1 hour

    def __init__(self, db_path: str, ttl_seconds: int | None = None) -> None:
        """Initialize the session manager.

        Args:
            db_path: Path to the SQLite database file.
            ttl_seconds: Session TTL in seconds.
        """
        self._db = GovernanceDB(db_path)
        self._ttl_seconds = ttl_seconds or self.DEFAULT_TTL_SECONDS

    def get_or_create(self, session_id: str | None) -> Session:
        """Get an existing session or create a new one.

        Args:
            session_id: Optional existing session ID.

        Returns:
            The Session object.
        """
        if session_id is None:
            session_id = str(uuid.uuid4())

        row = self._db.fetch_one(
            "SELECT * FROM governance_sessions WHERE session_id = ?",
            (session_id,),
        )

        if row is not None:
            return self._row_to_session(row)

        # Create new session
        now = datetime.now(UTC)
        self._db.execute(
            """INSERT INTO governance_sessions
               (session_id, created_at, last_activity, action_count, risk_accumulator)
               VALUES (?, ?, ?, ?, ?)""",
            (session_id, now.isoformat(), now.isoformat(), 0, 0),
        )

        return Session(
            session_id=session_id,
            created_at=now.isoformat(),
            last_activity=now.isoformat(),
            action_count=0,
            risk_accumulator=0,
        )

    def record_action(
        self,
        session_id: str,
        action: dict[str, Any],
        decision: GovernanceDecision,
        risk_score: int,
    ) -> None:
        """Record an action in the session history.

        Uses RETURNING clause to atomically get the new action_count,
        preventing race conditions where concurrent calls could get
        duplicate sequence numbers.

        Args:
            session_id: The session ID. Must exist (call get_or_create first).
            action: Action details to record.
            decision: The governance decision.
            risk_score: Risk score of the action.

        Raises:
            ValueError: If session_id does not exist in the database.
        """
        now = datetime.now(UTC)

        # Update session stats and atomically get new action_count
        row = self._db.execute_returning(
            """UPDATE governance_sessions
               SET action_count = action_count + 1,
                   risk_accumulator = risk_accumulator + ?,
                   last_activity = ?
               WHERE session_id = ?
               RETURNING action_count""",
            (risk_score, now.isoformat(), session_id),
        )
        if row is None:
            raise ValueError(
                f"Session '{session_id}' does not exist. "
                "Call get_or_create() before record_action()."
            )
        new_sequence = row["action_count"]

        # Record action in history using the atomically-retrieved sequence
        self._db.execute(
            """INSERT INTO governance_action_history
               (session_id, sequence, action_json, decision, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (
                session_id,
                new_sequence,
                json.dumps(action),
                decision.value,
                now.isoformat(),
            ),
        )

    def get_history(
        self,
        session_id: str,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get action history for a session.

        Args:
            session_id: The session ID.
            limit: Maximum number of history entries.

        Returns:
            List of action history entries.
        """
        rows = self._db.fetch_all(
            """SELECT * FROM governance_action_history
               WHERE session_id = ?
               ORDER BY sequence DESC
               LIMIT ?""",
            (session_id, limit),
        )
        return [
            {
                "sequence": row["sequence"],
                "action": json.loads(row["action_json"]),
                "decision": row["decision"],
                "timestamp": row["timestamp"],
            }
            for row in rows
        ]

    def cleanup_expired(self) -> int:
        """Remove expired sessions and their history.

        Returns:
            Number of sessions removed.
        """
        cutoff = (datetime.now(UTC) - timedelta(seconds=self._ttl_seconds)).isoformat()

        # Get expired session IDs
        rows = self._db.fetch_all(
            "SELECT session_id FROM governance_sessions WHERE last_activity < ?",
            (cutoff,),
        )
        session_ids = [row["session_id"] for row in rows]

        if not session_ids:
            return 0

        # Delete history
        placeholders = ",".join("?" * len(session_ids))
        self._db.execute(
            f"DELETE FROM governance_action_history WHERE session_id IN ({placeholders})",
            tuple(session_ids),
        )

        # Delete sessions
        cursor = self._db.execute(
            f"DELETE FROM governance_sessions WHERE session_id IN ({placeholders})",
            tuple(session_ids),
        )

        return cursor.rowcount

    def close(self) -> None:
        """Close the database connection."""
        self._db.close()

    def _row_to_session(self, row: dict[str, Any]) -> Session:
        return Session(
            session_id=row["session_id"],
            created_at=row["created_at"],
            last_activity=row["last_activity"],
            action_count=row["action_count"],
            risk_accumulator=row["risk_accumulator"],
        )
