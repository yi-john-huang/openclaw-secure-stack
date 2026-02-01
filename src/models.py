"""Shared Pydantic data models for openclaw-secure-stack."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

# --- Enums ---


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AuditEventType(str, Enum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    SKILL_SCAN = "skill_scan"
    SKILL_QUARANTINE = "skill_quarantine"
    SKILL_OVERRIDE = "skill_override"
    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_INJECTION = "indirect_injection"
    EGRESS_BLOCKED = "egress_blocked"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Scanner Models ---


class ScanFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_name: str
    severity: Severity
    file: str
    line: int
    column: int
    snippet: str
    message: str


class TrustScore(BaseModel):
    model_config = ConfigDict(frozen=True)

    overall: int = Field(ge=0, le=100)
    author_reputation: int = Field(ge=0, le=100)
    download_count: int = Field(ge=0)
    community_reviews: int = Field(ge=0)
    last_update_days: int = Field(ge=0)


class ScanReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    skill_name: str
    skill_path: str
    checksum: str = Field(min_length=64, max_length=64)  # SHA-256 hex
    findings: list[ScanFinding]
    trust_score: TrustScore | None = None
    scanned_at: str  # ISO8601
    duration_ms: int = Field(ge=0)


# --- Quarantine Models ---


class QuarantinedSkill(BaseModel):
    name: str
    original_path: str
    quarantined_at: str
    reason: str
    findings: list[ScanFinding]
    overridden: bool = False
    overridden_by: str | None = None
    overridden_at: str | None = None


# --- Sanitizer Models ---


class SanitizeResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    clean: str
    injection_detected: bool
    patterns: list[str]


class SanitizationRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    pattern: str
    action: str  # "strip" or "reject"
    description: str


# --- Audit Models ---


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class AuditEvent(BaseModel):
    timestamp: str = Field(default_factory=_now_iso)
    event_type: AuditEventType
    source_ip: str | None = None
    user_id: str | None = None
    action: str
    result: str  # "success" | "failure" | "blocked"
    risk_level: RiskLevel
    details: dict[str, object] | None = None
