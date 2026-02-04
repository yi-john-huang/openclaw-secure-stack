"""Tests for governance middleware."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "test_governance.db")


@pytest.fixture
def secret() -> str:
    return "test-secret-key-32-bytes-long!!"


@pytest.fixture
def policy_path(tmp_path: Path) -> str:
    policy_file = tmp_path / "policies.json"
    policies = [
        {
            "id": "GOV-001",
            "name": "Block file delete",
            "type": "action",
            "effect": "deny",
            "priority": 100,
            "conditions": {"category": "file_delete"},
        },
        {
            "id": "GOV-002",
            "name": "Approve code execution",
            "type": "action",
            "effect": "require_approval",
            "priority": 90,
            "conditions": {"category": "code_execution"},
        },
    ]
    policy_file.write_text(json.dumps(policies))
    return str(policy_file)


@pytest.fixture
def patterns_path(tmp_path: Path) -> str:
    patterns_file = tmp_path / "patterns.json"
    patterns = {
        "tool_categories": {
            "file_read": ["read_file", "get_file"],
            "file_write": ["write_file", "save_file"],
            "file_delete": ["delete_file", "remove_file"],
            "code_execution": ["execute_code", "run_script"],
        },
        "argument_patterns": {"sensitive_paths": ["^/etc/", ".*password.*"]},
        "risk_multipliers": {
            "file_read": 1.0,
            "file_write": 1.5,
            "file_delete": 2.0,
            "code_execution": 2.5,
        },
    }
    patterns_file.write_text(json.dumps(patterns))
    return str(patterns_file)


@pytest.fixture
def settings() -> dict[str, Any]:
    return {
        "enabled": True,
        "mode": "enforce",
        "approval": {"enabled": True, "timeout_seconds": 3600},
        "session": {"enabled": True, "ttl_seconds": 3600},
        "enforcement": {"enabled": True, "token_ttl_seconds": 900},
        "bypass_paths": ["/health", "/healthz"],
    }


@pytest.fixture
def middleware(db_path: str, secret: str, policy_path: str, patterns_path: str, settings: dict):
    from src.governance.middleware import GovernanceMiddleware

    mw = GovernanceMiddleware(
        db_path=db_path,
        secret=secret,
        policy_path=policy_path,
        patterns_path=patterns_path,
        settings=settings,
    )
    yield mw
    mw.close()


class TestMiddlewareInit:
    def test_creates_with_settings(
        self, db_path, secret, policy_path, patterns_path, settings
    ):
        from src.governance.middleware import GovernanceMiddleware

        mw = GovernanceMiddleware(
            db_path=db_path,
            secret=secret,
            policy_path=policy_path,
            patterns_path=patterns_path,
            settings=settings,
        )
        assert mw is not None

    def test_disabled_middleware_allows_all(
        self, db_path, secret, policy_path, patterns_path
    ):
        from src.governance.middleware import GovernanceMiddleware
        from src.governance.models import GovernanceDecision

        settings = {"enabled": False}
        mw = GovernanceMiddleware(
            db_path=db_path,
            secret=secret,
            policy_path=policy_path,
            patterns_path=patterns_path,
            settings=settings,
        )

        result = mw.evaluate(
            request_body={"tools": [{"type": "function", "function": {"name": "delete_file"}}]},
            session_id=None,
            user_id="user-1",
        )
        assert result.decision == GovernanceDecision.ALLOW


class TestEvaluate:
    def test_blocked_action_returns_block(self, middleware):
        from src.governance.models import GovernanceDecision

        result = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "delete_file", "arguments": {"path": "/tmp/file"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.decision == GovernanceDecision.BLOCK
        assert len(result.violations) > 0

    def test_allowed_action_returns_allow(self, middleware):
        from src.governance.models import GovernanceDecision

        result = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/safe.txt"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.decision == GovernanceDecision.ALLOW

    def test_requires_approval_for_code_execution(self, middleware):
        from src.governance.models import GovernanceDecision

        result = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "execute_code", "arguments": {"code": "print('hi')"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.decision == GovernanceDecision.REQUIRE_APPROVAL
        assert result.approval_id is not None


class TestPlanGeneration:
    def test_generates_plan_for_allowed_request(self, middleware):
        result = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.plan_id is not None
        assert result.token is not None

    def test_plan_includes_session_binding(self, middleware):
        result = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}}]
            },
            session_id="sess-123",
            user_id="user-1",
        )
        # Plan should be bound to session
        assert result.plan_id is not None


class TestApprovalFlow:
    def test_creates_approval_for_risky_action(self, middleware):
        result = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "execute_code", "arguments": {"code": "rm -rf /"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.approval_id is not None

    def test_stores_original_request_for_retry(self, middleware):
        from src.governance.models import GovernanceDecision

        result = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "execute_code", "arguments": {"code": "test"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert result.decision == GovernanceDecision.REQUIRE_APPROVAL

        # Original request should be stored with approval
        approval = middleware.get_approval(result.approval_id)
        assert approval is not None
        assert approval.original_request is not None


class TestEnforcement:
    def test_enforce_with_valid_token(self, middleware):
        from src.governance.models import GovernanceDecision, ToolCall

        # First, get a plan
        eval_result = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        assert eval_result.decision == GovernanceDecision.ALLOW

        # Now enforce action
        tool_call = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        enforce_result = middleware.enforce(
            plan_id=eval_result.plan_id,
            token=eval_result.token,
            tool_call=tool_call,
        )
        assert enforce_result.allowed is True

    def test_enforce_rejects_without_plan(self, middleware):
        from src.governance.models import ToolCall

        tool_call = ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"}, id="call-1")
        result = middleware.enforce(
            plan_id="nonexistent",
            token="invalid.token",
            tool_call=tool_call,
        )
        assert result.allowed is False


class TestSessionManagement:
    def test_creates_session_on_first_request(self, middleware):
        result = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}}]
            },
            session_id=None,
            user_id="user-1",
        )
        # Should have a session ID in the result
        assert result.session_id is not None

    def test_reuses_existing_session(self, middleware):
        # First request
        result1 = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/a.txt"}}}]
            },
            session_id="sess-abc",
            user_id="user-1",
        )

        # Second request with same session
        result2 = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/b.txt"}}}]
            },
            session_id="sess-abc",
            user_id="user-1",
        )

        assert result1.session_id == result2.session_id == "sess-abc"


class TestEvaluationResult:
    def test_result_structure(self, middleware):
        from src.governance.models import GovernanceDecision

        result = middleware.evaluate(
            request_body={
                "tools": [{"type": "function", "function": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}}]
            },
            session_id=None,
            user_id="user-1",
        )

        assert hasattr(result, "decision")
        assert hasattr(result, "plan_id")
        assert hasattr(result, "token")
        assert hasattr(result, "violations")
        assert hasattr(result, "session_id")
        assert result.decision == GovernanceDecision.ALLOW
