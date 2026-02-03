"""Audit logger — append-only JSON Lines logging with rotation and hash chain."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from src.models import AuditEvent


@dataclass
class ChainValidationResult:
    valid: bool
    broken_at_line: int | None = None


def validate_audit_chain(log_path: Path) -> ChainValidationResult:
    """Validate the hash chain integrity of an audit log file."""
    lines = log_path.read_text().strip().split("\n")
    if not lines or lines == [""]:
        return ChainValidationResult(valid=True)

    for i, line in enumerate(lines):
        entry = json.loads(line)
        if i == 0:
            if entry.get("prev_hash") is not None:
                return ChainValidationResult(valid=False, broken_at_line=1)
        else:
            expected = hashlib.sha256(lines[i - 1].encode()).hexdigest()
            if entry.get("prev_hash") != expected:
                return ChainValidationResult(valid=False, broken_at_line=i + 1)

    return ChainValidationResult(valid=True)


class AuditLogger:
    """Append-only structured audit logger with rotation and hash chain."""

    def __init__(
        self,
        log_path: str,
        max_bytes: int = 10_485_760,
        backup_count: int = 5,
    ) -> None:
        self.log_path = Path(log_path)
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._last_line: str | None = None
        # Load last line from existing file for hash chain continuity
        if self.log_path.exists() and self.log_path.stat().st_size > 0:
            text = self.log_path.read_text().strip()
            if text:
                self._last_line = text.split("\n")[-1]

    @classmethod
    def from_env(cls, log_path: str) -> AuditLogger:
        """Create AuditLogger with configuration from environment variables."""
        max_bytes = int(os.environ.get("AUDIT_LOG_MAX_BYTES", "10485760"))
        backup_count = int(os.environ.get("AUDIT_LOG_BACKUP_COUNT", "5"))
        return cls(log_path=log_path, max_bytes=max_bytes, backup_count=backup_count)

    def _maybe_rotate(self) -> None:
        """Rotate log file if it exceeds max_bytes."""
        if not self.log_path.exists():
            return
        if self.log_path.stat().st_size < self._max_bytes:
            return

        # Delete oldest backup if it exists
        oldest = self.log_path.parent / f"{self.log_path.name}.{self._backup_count}"
        if oldest.exists():
            oldest.unlink()

        # Shift existing backups
        for i in range(self._backup_count - 1, 0, -1):
            src = self.log_path.parent / f"{self.log_path.name}.{i}"
            dst = self.log_path.parent / f"{self.log_path.name}.{i + 1}"
            if src.exists():
                src.rename(dst)

        # Rotate current file to .1
        backup_1 = self.log_path.parent / f"{self.log_path.name}.1"
        self.log_path.rename(backup_1)

    def log(self, event: AuditEvent) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        # Compute prev_hash for hash chain
        prev_hash: str | None = None
        if self._last_line is not None:
            prev_hash = hashlib.sha256(self._last_line.encode()).hexdigest()

        # Serialize event and inject prev_hash
        data = json.loads(event.model_dump_json())
        data["prev_hash"] = prev_hash
        line = json.dumps(data, separators=(",", ":"))

        # Use a lock file for atomic rotation + write
        lock_file = self.log_path.parent / f".{self.log_path.name}.lock"
        with open(lock_file, "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                # Rotation check inside lock to prevent race condition
                self._maybe_rotate()
                with open(self.log_path, "a") as f:
                    f.write(line + "\n")
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

        self._last_line = line
