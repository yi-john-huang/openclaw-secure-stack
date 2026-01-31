"""Tests for the filesystem abuse detection rule."""

from __future__ import annotations

from src.scanner.rules.fs_abuse import FSAbuseRule
from src.scanner.scanner import parse_js

rule = FSAbuseRule()


def test_detects_write_to_absolute_path():
    source = b'fs.writeFileSync("/etc/passwd", "hacked");'
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) >= 1
    assert any("absolute path" in f.message.lower() for f in findings)


def test_detects_unlink():
    source = b'fs.unlinkSync("/important/file");'
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) >= 1


def test_detects_fs_require():
    source = b"const fs = require('fs');"
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) >= 1
    assert any("fs" in f.message for f in findings)


def test_detects_rm_sync():
    source = b'fs.rmSync("/tmp/data", { recursive: true });'
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) >= 1


def test_no_findings_for_safe_code():
    source = b'const x = [1,2,3].map(n => n * 2);'
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) == 0
