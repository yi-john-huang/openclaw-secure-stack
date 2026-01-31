"""Audit logger — append-only JSON Lines logging for security events."""

from __future__ import annotations

import fcntl
from pathlib import Path

from src.models import AuditEvent


class AuditLogger:
    """Append-only structured audit logger writing JSON Lines."""

    def __init__(self, log_path: str) -> None:
        self.log_path = Path(log_path)

    def log(self, event: AuditEvent) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(event.model_dump_json() + "\n")
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
