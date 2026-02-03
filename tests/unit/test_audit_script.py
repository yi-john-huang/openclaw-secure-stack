"""Tests for the security audit script check functions."""

from __future__ import annotations

import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "scripts"))

from audit import (  # noqa: E402
    Finding,
    documentation,
    network_isolation,
    secret_management,
    skill_security,
)


def test_finding_dataclass():
    f = Finding(check="test", severity="high", message="msg", remediation="fix")
    assert f.check == "test"
    assert f.severity == "high"


def test_network_isolation_detects_published_ports(tmp_path: Path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("""
version: "3.9"
services:
  proxy:
    ports:
      - "8080:8080"
  openclaw:
    ports:
      - "3000:3000"
""")
    findings = network_isolation(compose)
    names = [f.message for f in findings]
    assert any("openclaw" in n for n in names)
    # proxy is allowed
    assert not any("proxy" in n for n in names)


def test_network_isolation_clean(tmp_path: Path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("""
version: "3.9"
services:
  proxy:
    ports:
      - "8080:8080"
  openclaw:
    image: test
""")
    findings = network_isolation(compose)
    assert len(findings) == 0


def test_skill_security_missing_rules(tmp_path: Path):
    findings = skill_security(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_skill_security_valid_rules(tmp_path: Path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    rules = config_dir / "scanner-rules.json"
    rules.write_text(json.dumps([{"id": "T", "name": "T", "severity": "high", "patterns": ["x"]}]))
    findings = skill_security(tmp_path)
    assert len(findings) == 0


def test_documentation_missing_sections(tmp_path: Path):
    readme = tmp_path / "README.md"
    readme.write_text("# Project\nSome text.")
    findings = documentation(tmp_path)
    assert len(findings) == 3  # troubleshoot, network policy, rebuild


def test_documentation_all_present(tmp_path: Path):
    readme = tmp_path / "README.md"
    readme.write_text("# Project\n## Troubleshooting\n## Network Policy\n## Rebuild strategy\n")
    findings = documentation(tmp_path)
    assert len(findings) == 0
