"""Shared test fixtures for openclaw-secure-stack."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.audit.logger import AuditLogger


@pytest.fixture
def tmp_skill(tmp_path: Path):
    """Create a temporary skill file and return its path."""

    def _create(filename: str, content: bytes) -> Path:
        skill_dir = tmp_path / "skills"
        skill_dir.mkdir(exist_ok=True)
        skill_file = skill_dir / filename
        skill_file.write_bytes(content)
        return skill_file

    return _create


@pytest.fixture
def mock_audit_logger() -> MagicMock:
    return MagicMock(spec=AuditLogger)


@pytest.fixture
def config_dir() -> Path:
    return Path(__file__).parent.parent / "config"
