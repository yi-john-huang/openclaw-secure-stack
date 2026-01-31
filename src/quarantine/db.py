"""SQLite database for quarantine state management."""

from __future__ import annotations

import sqlite3
from pathlib import Path


class QuarantineDB:
    """SQLite-backed storage for skill quarantine metadata."""

    def __init__(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS skill_metadata (
                name TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                checksum TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                last_scanned TEXT,
                trust_score INTEGER,
                findings_json TEXT DEFAULT '[]',
                override_user TEXT,
                override_ack TEXT,
                override_at TEXT
            )
        """)
        self.conn.commit()

    def upsert_skill(
        self,
        name: str,
        path: str,
        checksum: str,
        status: str,
        findings_json: str = "[]",
        last_scanned: str | None = None,
        trust_score: int | None = None,
    ) -> None:
        self.conn.execute(
            """INSERT INTO skill_metadata
               (name, path, checksum, status, findings_json, last_scanned, trust_score)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET
                 path=excluded.path, checksum=excluded.checksum, status=excluded.status,
                 findings_json=excluded.findings_json, last_scanned=excluded.last_scanned,
                 trust_score=excluded.trust_score""",
            (name, path, checksum, status, findings_json, last_scanned, trust_score),
        )
        self.conn.commit()

    def get_skill(self, name: str) -> dict[str, object] | None:
        row = self.conn.execute(
            "SELECT * FROM skill_metadata WHERE name = ?", (name,)
        ).fetchone()
        return dict(row) if row else None

    def update_status(
        self,
        name: str,
        status: str,
        override_user: str | None = None,
        override_ack: str | None = None,
        override_at: str | None = None,
    ) -> None:
        self.conn.execute(
            """UPDATE skill_metadata SET status=?, override_user=?, override_ack=?, override_at=?
               WHERE name=?""",
            (status, override_user, override_ack, override_at, name),
        )
        self.conn.commit()

    def list_by_status(self, status: str) -> list[dict[str, object]]:
        rows = self.conn.execute(
            "SELECT * FROM skill_metadata WHERE status = ?", (status,)
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self.conn.close()
