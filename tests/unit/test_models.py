"""Tests for shared Pydantic data models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.models import (
    AuditEvent,
    AuditEventType,
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
