"""Tests for governance helper functions."""

from __future__ import annotations

import pytest

from src.proxy.governance_helpers import has_tool_calls, strip_governance_headers


class TestHasToolCalls:
    def test_detects_tool_calls_key(self):
        assert has_tool_calls({"tool_calls": [{"name": "read_file"}]}) is True

    def test_detects_function_call_key(self):
        assert has_tool_calls({"function_call": {"name": "exec"}}) is True

    def test_ignores_tools_capability_declaration(self):
        """SEC-D-03: tools[] is capability, not invocation."""
        assert has_tool_calls({"tools": [{"type": "function"}]}) is False

    def test_empty_tool_calls_is_false(self):
        assert has_tool_calls({"tool_calls": []}) is False

    def test_no_tool_keys_is_false(self):
        assert has_tool_calls({"messages": [{"role": "user"}]}) is False

    def test_non_dict_returns_false(self):
        assert has_tool_calls(None) is False

    def test_non_dict_string_returns_false(self):
        assert has_tool_calls("not a dict") is False  # type: ignore[arg-type]

    def test_non_dict_list_returns_false(self):
        assert has_tool_calls([1, 2, 3]) is False  # type: ignore[arg-type]


class TestStripGovernanceHeaders:
    def test_strips_governance_plan_id(self):
        headers = {"content-type": "application/json", "x-governance-plan-id": "plan-123"}
        result = strip_governance_headers(headers)
        assert "x-governance-plan-id" not in result
        assert "content-type" in result

    def test_strips_governance_token(self):
        headers = {"x-governance-token": "secret", "x-request-id": "abc"}
        result = strip_governance_headers(headers)
        assert "x-governance-token" not in result
        assert "x-request-id" in result

    def test_strips_all_x_governance_prefixed(self):
        headers = {"x-governance-session": "s1", "x-governance-custom": "val", "accept": "*/*"}
        result = strip_governance_headers(headers)
        assert all(not k.lower().startswith("x-governance-") for k in result)
        assert "accept" in result

    def test_preserves_non_governance_headers(self):
        headers = {"content-type": "application/json", "x-request-id": "abc"}
        result = strip_governance_headers(headers)
        assert result == headers

    def test_case_insensitive_stripping(self):
        headers = {"X-Governance-Plan-Id": "plan-123", "Content-Type": "text/plain"}
        result = strip_governance_headers(headers)
        assert "X-Governance-Plan-Id" not in result
        assert "Content-Type" in result

    def test_empty_headers(self):
        assert strip_governance_headers({}) == {}
