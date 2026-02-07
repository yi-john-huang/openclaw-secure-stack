"""Tests for shared Pydantic data models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models import (
    AuditEvent,
    AuditEventType,
    PinResult,
    RiskLevel,
    SanitizationRule,
    SanitizeResult,
    ScanFinding,
    ScanReport,
    Severity,
    TrustScore,
)


class TestScanFinding:
    def test_serialization_round_trip(self):
        finding = ScanFinding(
            rule_id="R1",
            rule_name="test",
            severity=Severity.HIGH,
            file="a.js",
            line=1,
            column=0,
            snippet="x",
            message="m",
        )
        data = finding.model_dump()
        assert data["severity"] == "high"
        assert ScanFinding.model_validate(data) == finding

    def test_severity_serializes_lowercase(self):
        finding = ScanFinding(
            rule_id="R1",
            rule_name="test",
            severity=Severity.CRITICAL,
            file="a.js",
            line=1,
            column=0,
            snippet="x",
            message="m",
        )
        assert finding.model_dump()["severity"] == "critical"

    def test_frozen(self):
        finding = ScanFinding(
            rule_id="R1",
            rule_name="test",
            severity=Severity.LOW,
            file="a.js",
            line=1,
            column=0,
            snippet="x",
            message="m",
        )
        with pytest.raises(ValidationError):
            finding.rule_id = "R2"  # type: ignore[misc]


class TestTrustScore:
    def test_valid_score(self):
        score = TrustScore(
            overall=75,
            author_reputation=80,
            download_count=5000,
            community_reviews=10,
            last_update_days=30,
        )
        assert score.overall == 75

    def test_overall_clamped_0_100(self):
        with pytest.raises(ValidationError):
            TrustScore(
                overall=101,
                author_reputation=0,
                download_count=0,
                community_reviews=0,
                last_update_days=0,
            )
        with pytest.raises(ValidationError):
            TrustScore(
                overall=-1,
                author_reputation=0,
                download_count=0,
                community_reviews=0,
                last_update_days=0,
            )


class TestScanReport:
    def test_checksum_must_be_64_chars(self):
        valid_checksum = "a" * 64
        report = ScanReport(
            skill_name="test",
            skill_path="/test",
            checksum=valid_checksum,
            findings=[],
            scanned_at="2026-01-01T00:00:00Z",
            duration_ms=100,
        )
        assert report.checksum == valid_checksum

    def test_short_checksum_rejected(self):
        with pytest.raises(ValidationError):
            ScanReport(
                skill_name="test",
                skill_path="/test",
                checksum="tooshort",
                findings=[],
                scanned_at="2026-01-01T00:00:00Z",
                duration_ms=100,
            )

    def test_negative_duration_rejected(self):
        with pytest.raises(ValidationError):
            ScanReport(
                skill_name="test",
                skill_path="/test",
                checksum="a" * 64,
                findings=[],
                scanned_at="2026-01-01T00:00:00Z",
                duration_ms=-1,
            )


class TestAuditEvent:
    def test_auto_timestamp(self):
        event = AuditEvent(
            event_type=AuditEventType.AUTH_FAILURE,
            action="login",
            result="failure",
            risk_level=RiskLevel.HIGH,
        )
        assert event.timestamp
        assert "T" in event.timestamp  # ISO8601 format

    def test_event_type_serializes_lowercase(self):
        event = AuditEvent(
            event_type=AuditEventType.SKILL_SCAN,
            action="scan",
            result="success",
            risk_level=RiskLevel.INFO,
        )
        data = event.model_dump()
        assert data["event_type"] == "skill_scan"
        assert data["risk_level"] == "info"

    def test_optional_fields_default_none(self):
        event = AuditEvent(
            event_type=AuditEventType.AUTH_SUCCESS,
            action="login",
            result="success",
            risk_level=RiskLevel.LOW,
        )
        assert event.source_ip is None
        assert event.user_id is None
        assert event.details is None


class TestPinResult:
    def test_verified_status(self):
        r = PinResult(status="verified")
        assert r.status == "verified"
        assert r.expected is None
        assert r.actual is None

    def test_mismatch_status(self):
        r = PinResult(status="mismatch", expected="aaa", actual="bbb")
        assert r.expected == "aaa"
        assert r.actual == "bbb"

    def test_unpinned_status(self):
        r = PinResult(status="unpinned")
        assert r.status == "unpinned"

    def test_is_frozen(self):
        r = PinResult(status="verified")
        with pytest.raises(ValidationError):
            r.status = "mismatch"  # type: ignore[misc]

    def test_invalid_status_rejected(self):
        with pytest.raises(ValidationError):
            PinResult(status="invalid")


class TestSanitizeResult:
    def test_clean_result(self):
        result = SanitizeResult(
            clean="hello",
            injection_detected=False,
            patterns=[],
        )
        assert result.clean == "hello"
        assert result.injection_detected is False


class TestSanitizationRule:
    def test_rule_creation(self):
        rule = SanitizationRule(
            id="PI-001",
            name="Ignore instructions",
            pattern=r"ignore.*previous.*instructions",
            action="strip",
            description="Detects ignore-previous-instructions pattern",
        )
        assert rule.action == "strip"


class TestGovernanceAuditEventTypes:
    def test_governance_audit_event_types_exist(self):
        """All governance audit event types are defined."""
        assert AuditEventType.GOVERNANCE_ALLOW == "governance_allow"
        assert AuditEventType.GOVERNANCE_BLOCK == "governance_block"
        assert AuditEventType.GOVERNANCE_APPROVAL_REQUIRED == "governance_approval_required"
        assert AuditEventType.GOVERNANCE_APPROVAL_GRANTED == "governance_approval_granted"
        assert AuditEventType.GOVERNANCE_ERROR == "governance_error"

    def test_webhook_audit_event_types_exist(self):
        """All webhook audit event types are defined."""
        assert AuditEventType.WEBHOOK_RECEIVED == "webhook_received"
        assert AuditEventType.WEBHOOK_RELAY == "webhook_relay"
        assert AuditEventType.WEBHOOK_REPLAY_REJECTED == "webhook_replay_rejected"
        assert AuditEventType.WEBHOOK_RATE_LIMITED == "webhook_rate_limited"
        assert AuditEventType.WEBHOOK_SIGNATURE_FAILED == "webhook_signature_failed"

    def test_plugin_audit_event_types_exist(self):
        """Plugin enforcement audit event types are defined."""
        assert AuditEventType.PLUGIN_GOVERNANCE_BLOCK == "plugin_governance_block"
        assert AuditEventType.PLUGIN_QUARANTINE_BLOCK == "plugin_quarantine_block"

    def test_new_event_types_serialize_correctly(self):
        """New event types serialize correctly in AuditEvent model."""
        event = AuditEvent(
            event_type=AuditEventType.GOVERNANCE_BLOCK,
            action="evaluate",
            result="blocked",
            risk_level=RiskLevel.HIGH,
        )
        data = event.model_dump()
        assert data["event_type"] == "governance_block"
