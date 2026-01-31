"""Tests for the dangerous API detection rule."""

from __future__ import annotations

from src.scanner.rules.dangerous_api import DangerousAPIRule
from src.scanner.scanner import parse_js

rule = DangerousAPIRule()


def test_detects_eval_call():
    source = b'const x = eval("malicious");'
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) >= 1
    assert any("eval" in f.message for f in findings)


def test_detects_child_process_require():
    source = b'const cp = require("child_process");'
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) >= 1
    assert any("child_process" in f.message for f in findings)


def test_detects_exec_method():
    source = b'cp.exec("rm -rf /");'
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) >= 1


def test_detects_function_constructor():
    source = b'const f = new Function("return this");'
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) >= 1
    assert any("Function" in f.message for f in findings)


def test_ignores_safe_code():
    source = b'const x = [1,2,3].map(n => n * 2);'
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) == 0


def test_detects_spawn_sync():
    source = b'child_process.spawnSync("ls", ["-la"]);'
    findings = rule.detect(parse_js(source), source, "test.js")
    assert len(findings) >= 1
