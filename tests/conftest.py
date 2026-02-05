"""Shared test fixtures for openclaw-secure-stack."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from src.audit.logger import AuditLogger
from src.governance.models import (
    ExecutionPlan,
    IntentCategory,
    PlannedAction,
    ResourceAccess,
    RiskAssessment,
    ToolCall,
)
from src.models import (
    AuditEvent,
    AuditEventType,
    RiskLevel,
    ScanFinding,
    ScanReport,
    Severity,
)


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


# --- Factory functions for test data ---

# SHA-256 produces 64 hex characters
MOCK_CHECKSUM = "a" * 64


def make_audit_event(**kwargs) -> AuditEvent:
    """Factory for AuditEvent with sensible defaults."""
    defaults: dict[str, object] = {
        "event_type": AuditEventType.AUTH_FAILURE,
        "action": "test_action",
        "result": "failure",
        "risk_level": RiskLevel.HIGH,
    }
    defaults.update(kwargs)
    return AuditEvent(**defaults)  # type: ignore[arg-type]


def make_scan_finding(**kwargs) -> ScanFinding:
    """Factory for ScanFinding with sensible defaults."""
    defaults: dict[str, object] = {
        "rule_id": "TEST",
        "rule_name": "Test Rule",
        "severity": Severity.HIGH,
        "file": "test.js",
        "line": 1,
        "column": 0,
        "snippet": "test code",
        "message": "Test finding",
    }
    defaults.update(kwargs)
    return ScanFinding(**defaults)  # type: ignore[arg-type]


def make_scan_report(
    skill_name: str = "test.js",
    skill_path: str | None = None,
    findings: list[ScanFinding] | None = None,
    **kwargs,
) -> ScanReport:
    """Factory for ScanReport with sensible defaults."""
    defaults: dict[str, object] = {
        "skill_name": skill_name,
        "skill_path": skill_path or f"/skills/{skill_name}",
        "checksum": MOCK_CHECKSUM,
        "findings": findings or [],
        "scanned_at": "2026-01-01T00:00:00Z",
        "duration_ms": 10,
    }
    defaults.update(kwargs)
    return ScanReport(**defaults)  # type: ignore[arg-type]


# --- Governance test fixtures ---


@pytest.fixture
def governance_db_path(tmp_path: Path) -> str:
    """Create a temporary database path for governance tests."""
    return str(tmp_path / "test_governance.db")


def make_tool_call(**kwargs: Any) -> ToolCall:
    """Factory for ToolCall with sensible defaults."""
    defaults: dict[str, Any] = {
        "name": "test_tool",
        "arguments": {},
        "id": None,
    }
    defaults.update(kwargs)
    return ToolCall(**defaults)


def make_planned_action(**kwargs: Any) -> PlannedAction:
    """Factory for PlannedAction with sensible defaults."""
    defaults: dict[str, Any] = {
        "sequence": 0,
        "tool_call": make_tool_call(),
        "category": IntentCategory.UNKNOWN,
        "resources": [],
        "risk_score": 10,
    }
    defaults.update(kwargs)
    return PlannedAction(**defaults)


def make_risk_assessment(**kwargs: Any) -> RiskAssessment:
    """Factory for RiskAssessment with sensible defaults."""
    defaults: dict[str, Any] = {
        "overall_score": 10,
        "level": RiskLevel.LOW,
        "factors": [],
        "mitigations": [],
    }
    defaults.update(kwargs)
    return RiskAssessment(**defaults)


def make_execution_plan(**kwargs: Any) -> ExecutionPlan:
    """Factory for ExecutionPlan with sensible defaults."""
    defaults: dict[str, Any] = {
        "plan_id": "test-plan-id",
        "session_id": "test-session-id",
        "request_hash": MOCK_CHECKSUM,
        "actions": [make_planned_action()],
        "risk_assessment": make_risk_assessment(),
    }
    defaults.update(kwargs)
    return ExecutionPlan(**defaults)
