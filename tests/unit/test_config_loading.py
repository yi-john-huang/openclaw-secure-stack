"""Tests for config file loading and validation."""

from __future__ import annotations

import json
from pathlib import Path

CONFIG_DIR = Path(__file__).parent.parent.parent / "config"


def test_scanner_rules_is_valid_json() -> None:
    rules = json.loads((CONFIG_DIR / "scanner-rules.json").read_text())
    assert isinstance(rules, list)
    assert len(rules) >= 3  # At least dangerous_api, network_exfil, fs_abuse


def test_scanner_rules_have_required_fields() -> None:
    rules = json.loads((CONFIG_DIR / "scanner-rules.json").read_text())
    for rule in rules:
        assert "id" in rule
        assert "name" in rule
        assert "severity" in rule
        assert rule["severity"] in ("critical", "high", "medium", "low")
        assert "category" in rule
        assert "description" in rule


def test_scanner_rules_cover_all_categories() -> None:
    rules = json.loads((CONFIG_DIR / "scanner-rules.json").read_text())
    categories = {r["category"] for r in rules}
    assert "dangerous_api" in categories
    assert "network_exfil" in categories
    assert "fs_abuse" in categories


def test_prompt_rules_is_valid_json() -> None:
    rules = json.loads((CONFIG_DIR / "prompt-rules.json").read_text())
    assert isinstance(rules, list)
    assert len(rules) >= 3


def test_prompt_rules_have_required_fields() -> None:
    rules = json.loads((CONFIG_DIR / "prompt-rules.json").read_text())
    for rule in rules:
        assert "id" in rule
        assert "name" in rule
        assert "pattern" in rule
        assert "action" in rule
        assert rule["action"] in ("strip", "reject")
        assert "description" in rule


def test_egress_allowlist_contains_defaults() -> None:
    content = (CONFIG_DIR / "egress-allowlist.conf").read_text()
    domains = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert "api.openai.com" in domains
    assert "api.anthropic.com" in domains
