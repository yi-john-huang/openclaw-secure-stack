"""Tests for the scanner CLI."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from src.scanner.cli import cli


def _write_rules(tmp_path: Path) -> str:
    rules = [
        {
            "id": "T1",
            "name": "Test",
            "severity": "low",
            "patterns": ["EVIL"],
            "description": "test rule",
        },
    ]
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules))
    return str(p)


def _write_skill(tmp_path: Path, name: str, content: bytes) -> str:
    skills = tmp_path / "skills"
    skills.mkdir(exist_ok=True)
    f = skills / name
    f.write_bytes(content)
    return str(f)


def test_scan_command_outputs_json(tmp_path: Path) -> None:
    rules = _write_rules(tmp_path)
    skill = _write_skill(tmp_path, "ok.js", b"var x = 1;")
    runner = CliRunner()
    result = runner.invoke(cli, [
        "--rules", rules,
        "--db", str(tmp_path / "q.db"),
        "--quarantine-dir", str(tmp_path / "qdir"),
        "scan", skill,
    ])
    assert result.exit_code == 0
    report = json.loads(result.output)
    assert "findings" in report


def test_scan_detects_pattern(tmp_path: Path) -> None:
    rules = _write_rules(tmp_path)
    skill = _write_skill(tmp_path, "bad.js", b"var EVIL = true;")
    runner = CliRunner()
    result = runner.invoke(cli, [
        "--rules", rules,
        "--db", str(tmp_path / "q.db"),
        "--quarantine-dir", str(tmp_path / "qdir"),
        "scan", skill,
    ])
    assert result.exit_code == 0
    report = json.loads(result.output)
    assert len(report["findings"]) >= 1


def test_scan_quarantine_flag(tmp_path: Path) -> None:
    rules = _write_rules(tmp_path)
    skill = _write_skill(tmp_path, "bad.js", b"var EVIL = true;")
    runner = CliRunner()
    result = runner.invoke(cli, [
        "--rules", rules,
        "--db", str(tmp_path / "q.db"),
        "--quarantine-dir", str(tmp_path / "qdir"),
        "scan", "--quarantine", skill,
    ])
    assert result.exit_code == 0
    assert not Path(skill).exists()


def test_quarantine_list_empty(tmp_path: Path) -> None:
    rules = _write_rules(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "--rules", rules,
        "--db", str(tmp_path / "q.db"),
        "--quarantine-dir", str(tmp_path / "qdir"),
        "quarantine", "list",
    ])
    assert result.exit_code == 0
    assert json.loads(result.output) == []


def test_override_requires_ack(tmp_path: Path) -> None:
    rules = _write_rules(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "--rules", rules,
        "--db", str(tmp_path / "q.db"),
        "--quarantine-dir", str(tmp_path / "qdir"),
        "quarantine", "override", "some-skill",
    ])
    assert result.exit_code != 0
