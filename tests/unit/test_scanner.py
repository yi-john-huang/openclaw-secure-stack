"""Tests for the core skill scanner."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.scanner.scanner import (
    ScannerConfigError,
    SkillScanner,
    load_rules_from_config,
    load_rules_from_file,
)


class TestLoadRules:
    def test_load_rules_from_config(self):
        config = [
            {"id": "TEST", "name": "Test Rule", "severity": "high",
             "patterns": ["badthing"], "description": "test"}
        ]
        rules = load_rules_from_config(config)
        assert len(rules) == 1
        assert rules[0].id == "TEST"

    def test_fail_closed_on_missing_config(self):
        with pytest.raises(ScannerConfigError):
            load_rules_from_config(None)

    def test_load_from_file(self, config_dir: Path):
        rules = load_rules_from_file(str(config_dir / "scanner-rules.json"))
        assert len(rules) >= 3

    def test_load_from_missing_file(self):
        with pytest.raises(ScannerConfigError):
            load_rules_from_file("/nonexistent/rules.json")


class TestSkillScanner:
    def _make_scanner(self) -> SkillScanner:
        config = [
            {"id": "TEST_PATTERN", "name": "Test", "severity": "high",
             "patterns": ["eval("], "description": "test pattern"}
        ]
        rules = load_rules_from_config(config)
        return SkillScanner(rules=rules, audit_logger=MagicMock())

    def test_scan_returns_report_with_findings(self, tmp_skill):
        # Note: This test intentionally uses a dangerous pattern to test the scanner
        skill = tmp_skill("malicious.js", b'const x = eval("pwned");')
        scanner = self._make_scanner()
        report = scanner.scan(str(skill))
        assert len(report.findings) >= 1
        assert len(report.checksum) == 64

    def test_scan_clean_skill_no_findings(self, tmp_skill):
        skill = tmp_skill("safe.js", b'console.log("hello");')
        scanner = self._make_scanner()
        report = scanner.scan(str(skill))
        assert len(report.findings) == 0

    def test_scan_all_scans_directory(self, tmp_skill):
        tmp_skill("a.js", b"var x = 1;")
        tmp_skill("b.js", b"var y = 2;")
        tmp_skill("c.js", b"var z = 3;")
        # Get the skills directory from one of the created files
        skill = tmp_skill("dummy.js", b"")
        skills_dir = skill.parent
        scanner = self._make_scanner()
        reports = scanner.scan_all(str(skills_dir))
        assert len(reports) == 4  # Including dummy.js

    def test_scan_checksum_changes_on_modification(self, tmp_skill):
        skill = tmp_skill("test.js", b"var x = 1;")
        scanner = self._make_scanner()
        report1 = scanner.scan(str(skill))
        skill.write_bytes(b"var x = 2;")
        report2 = scanner.scan(str(skill))
        assert report1.checksum != report2.checksum

    def test_scan_logs_audit_event(self, tmp_skill):
        skill = tmp_skill("test.js", b"var x = 1;")
        mock_logger = MagicMock()
        config = [
            {"id": "T", "name": "T", "severity": "low", "patterns": ["xxx"], "description": "t"},
        ]
        scanner = SkillScanner(rules=load_rules_from_config(config), audit_logger=mock_logger)
        scanner.scan(str(skill))
        assert mock_logger.log.called


class TestPinVerification:
    def _make_scanner(self, pin_data: dict | None = None) -> SkillScanner:
        config = [
            {"id": "T", "name": "T", "severity": "low", "patterns": ["xxx"], "description": "t"},
        ]
        rules = load_rules_from_config(config)
        return SkillScanner(
            rules=rules,
            audit_logger=MagicMock(),
            pin_data=pin_data or {},
            pins_loaded=pin_data is not None,
        )

    def test_verify_pin_matching_hash(self, tmp_skill):
        skill = tmp_skill("skill.js", b"console.log('hi')")
        digest = hashlib.sha256(skill.read_bytes()).hexdigest()
        pins = {"skill.js": {"sha256": digest}}
        scanner = self._make_scanner(pin_data=pins)
        result = scanner._verify_pin(skill, "skill.js", checksum=digest)
        assert result.status == "verified"

    def test_verify_pin_mismatch(self, tmp_skill):
        skill = tmp_skill("skill.js", b"console.log('hi')")
        digest = hashlib.sha256(skill.read_bytes()).hexdigest()
        pins = {"skill.js": {"sha256": "wrong"}}
        scanner = self._make_scanner(pin_data=pins)
        result = scanner._verify_pin(skill, "skill.js", checksum=digest)
        assert result.status == "mismatch"
        assert result.expected == "wrong"

    def test_verify_pin_unpinned(self, tmp_skill):
        skill = tmp_skill("skill.js", b"console.log('hi')")
        digest = hashlib.sha256(skill.read_bytes()).hexdigest()
        scanner = self._make_scanner(pin_data={})
        result = scanner._verify_pin(skill, "skill.js", checksum=digest)
        assert result.status == "unpinned"

    def test_scan_reports_mismatch_as_critical_finding(self, tmp_skill):
        skill = tmp_skill("skill.js", b"console.log('hi')")
        pins = {"skill.js": {"sha256": "wrong"}}
        scanner = self._make_scanner(pin_data=pins)
        report = scanner.scan(str(skill))
        pin_findings = [f for f in report.findings if f.rule_id == "PIN_MISMATCH"]
        assert len(pin_findings) == 1
        assert pin_findings[0].severity.value == "critical"


class TestTrustScoreWiring:
    def test_scan_includes_trust_score(self, tmp_skill):
        skill = tmp_skill("test.js", b"var x = 1;")
        config = [
            {"id": "T", "name": "T", "severity": "low", "patterns": ["xxx"], "description": "t"},
        ]
        scanner = SkillScanner(rules=load_rules_from_config(config), audit_logger=MagicMock())
        report = scanner.scan(str(skill))
        assert report.trust_score is not None
        assert 0 <= report.trust_score.overall <= 100
