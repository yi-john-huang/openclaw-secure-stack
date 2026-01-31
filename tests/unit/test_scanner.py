"""Tests for the core skill scanner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.scanner.scanner import (
    ScannerConfigError,
    SkillScanner,
    load_rules_from_config,
    load_rules_from_file,
)


def _create_skill(tmp_path: Path, filename: str, content: bytes) -> Path:
    skill_file = tmp_path / filename
    skill_file.write_bytes(content)
    return skill_file


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

    def test_scan_returns_report_with_findings(self, tmp_path: Path):
        skill = _create_skill(tmp_path, "malicious.js", b'const x = eval("pwned");')
        scanner = self._make_scanner()
        report = scanner.scan(str(skill))
        assert len(report.findings) >= 1
        assert len(report.checksum) == 64

    def test_scan_clean_skill_no_findings(self, tmp_path: Path):
        skill = _create_skill(tmp_path, "safe.js", b'console.log("hello");')
        scanner = self._make_scanner()
        report = scanner.scan(str(skill))
        assert len(report.findings) == 0

    def test_scan_all_scans_directory(self, tmp_path: Path):
        _create_skill(tmp_path, "a.js", b"var x = 1;")
        _create_skill(tmp_path, "b.js", b"var y = 2;")
        _create_skill(tmp_path, "c.js", b"var z = 3;")
        scanner = self._make_scanner()
        reports = scanner.scan_all(str(tmp_path))
        assert len(reports) == 3

    def test_scan_checksum_changes_on_modification(self, tmp_path: Path):
        skill = _create_skill(tmp_path, "test.js", b"var x = 1;")
        scanner = self._make_scanner()
        report1 = scanner.scan(str(skill))
        skill.write_bytes(b"var x = 2;")
        report2 = scanner.scan(str(skill))
        assert report1.checksum != report2.checksum

    def test_scan_logs_audit_event(self, tmp_path: Path):
        skill = _create_skill(tmp_path, "test.js", b"var x = 1;")
        mock_logger = MagicMock()
        config = [
            {"id": "T", "name": "T", "severity": "low", "patterns": ["xxx"], "description": "t"},
        ]
        scanner = SkillScanner(rules=load_rules_from_config(config), audit_logger=mock_logger)
        scanner.scan(str(skill))
        assert mock_logger.log.called
