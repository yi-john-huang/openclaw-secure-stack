"""Replay protection for webhook messages — SEC-D-05.

Telegram: Tracks update_id (monotonically increasing); rejects any ID <= last seen.
WhatsApp: Rejects messages older than a configurable time window (default: 300s).

Uses SQLite for persistence across restarts.
"""

from __future__ import annotations

import sqlite3
import time


class ReplayProtection:
    """Prevents webhook replay attacks using SQLite-backed state."""

    def __init__(
        self,
        db_path: str,
        whatsapp_window_seconds: int = 300,
    ) -> None:
        self._db_path = db_path
        self._whatsapp_window_seconds = whatsapp_window_seconds
        self._conn = sqlite3.connect(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS telegram_replay (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_update_id INTEGER NOT NULL DEFAULT 0
            )"""
        )
        self._conn.execute(
            "INSERT OR IGNORE INTO telegram_replay (id, last_update_id) VALUES (1, 0)"
        )
        self._conn.commit()

    def check_telegram(self, update_id: int) -> bool:
        """Return True if update_id is new (not replayed).

        FR-2.7: Rejects duplicate or older update_ids.
        """
        cursor = self._conn.execute(
            "SELECT last_update_id FROM telegram_replay WHERE id = 1"
        )
        row = cursor.fetchone()
        last_id = row[0] if row else 0

        if update_id <= last_id:
            return False

        self._conn.execute(
            "UPDATE telegram_replay SET last_update_id = ? WHERE id = 1",
            (update_id,),
        )
        self._conn.commit()
        return True

    def check_whatsapp(self, message_timestamp: int) -> bool:
        """Return True if message is within acceptable time window.

        FR-3.7: Rejects messages older than the configured window (default 5 min).
        """
        now = int(time.time())
        age = now - message_timestamp
        return age <= self._whatsapp_window_seconds
