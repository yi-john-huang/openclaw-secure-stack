"""Tests for governance integration in the proxy pipeline."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from src.governance.middleware import EvaluationResult, GovernanceMiddleware
from src.governance.models import GovernanceDecision, PolicyViolation
from src.models import AuditEventType, RiskLevel, Severity
from src.proxy.governance_helpers import evaluate_governance


def _make_mock_request(
    headers: dict[str, str] | None = None,
    client_host: str = "127.0.0.1",
) -> MagicMock:
    """Create a mock Starlette Request."""
    mock = MagicMock()
    mock.headers = headers or {}
    mock.client = MagicMock()
    mock.client.host = client_host
    return mock


class TestEvaluateGovernance:
    """Tests for evaluate_governance() function."""

    @pytest.fixture
    def mock_governance(self):
        return MagicMock(spec=GovernanceMiddleware)

    @pytest.fixture
    def mock_audit(self):
        return MagicMock()

    @pytest.fixture
    def body_json(self):
        return {"tool_calls": [{"name": "read_file", "arguments": {"path": "/etc/passwd"}}]}

    @pytest.fixture
    def raw_body(self, body_json):
        return json.dumps(body_json).encode()

    @pytest.fixture
    def mock_request(self):
        return _make_mock_request()

    def test_allow_decision_returns_none(self, mock_governance, body_json, raw_body, mock_request, mock_audit):
        """ALLOW decisions return None (continue pipeline)."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.ALLOW,
            plan_id="p1",
            token="tok",
        )
        result = evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        assert result is None

    def test_block_decision_returns_403(self, mock_governance, body_json, raw_body, mock_request, mock_audit):
        """BLOCK decisions return 403 with violation details."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.BLOCK,
            violations=[
                PolicyViolation(
                    rule_id="R1",
                    severity=Severity.HIGH,
                    action_sequence=0,
                    message="Blocked by policy",
                ),
            ],
        )
        result = evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        assert result is not None
        assert result.status_code == 403

    def test_require_approval_returns_202(self, mock_governance, body_json, raw_body, mock_request, mock_audit):
        """REQUIRE_APPROVAL returns 202 with approval_id."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.REQUIRE_APPROVAL,
            approval_id="a1",
            plan_id="p1",
            message="Approval needed",
        )
        result = evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        assert result is not None
        assert result.status_code == 202

    def test_require_approval_body_contains_ids(self, mock_governance, body_json, raw_body, mock_request, mock_audit):
        """REQUIRE_APPROVAL response body includes approval_id and plan_id."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.REQUIRE_APPROVAL,
            approval_id="a1",
            plan_id="p1",
            message="Approval needed",
        )
        result = evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        body = json.loads(result.body)
        assert body["approval_id"] == "a1"
        assert body["plan_id"] == "p1"

    def test_governance_error_returns_500_fail_closed(self, mock_governance, body_json, raw_body, mock_request, mock_audit):
        """FR-1.7: Governance error -> fail closed (500)."""
        mock_governance.evaluate.side_effect = RuntimeError("db error")
        result = evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        assert result is not None
        assert result.status_code == 500

    def test_governance_error_logs_critical_event(self, mock_governance, body_json, raw_body, mock_request, mock_audit):
        """Governance error produces GOVERNANCE_ERROR audit event."""
        mock_governance.evaluate.side_effect = RuntimeError("db error")
        evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        mock_audit.log.assert_called_once()
        event = mock_audit.log.call_args[0][0]
        assert event.event_type == AuditEventType.GOVERNANCE_ERROR

    def test_block_logs_governance_block_event(self, mock_governance, body_json, raw_body, mock_request, mock_audit):
        """BLOCK produces GOVERNANCE_BLOCK audit event."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.BLOCK,
            violations=[
                PolicyViolation(
                    rule_id="R1",
                    severity=Severity.HIGH,
                    action_sequence=0,
                    message="Blocked",
                ),
            ],
        )
        evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        mock_audit.log.assert_called_once()
        event = mock_audit.log.call_args[0][0]
        assert event.event_type == AuditEventType.GOVERNANCE_BLOCK

    def test_approval_required_logs_event(self, mock_governance, body_json, raw_body, mock_request, mock_audit):
        """REQUIRE_APPROVAL produces GOVERNANCE_APPROVAL_REQUIRED event."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.REQUIRE_APPROVAL,
            approval_id="a1",
            plan_id="p1",
            message="Needs approval",
        )
        evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        mock_audit.log.assert_called_once()
        event = mock_audit.log.call_args[0][0]
        assert event.event_type == AuditEventType.GOVERNANCE_APPROVAL_REQUIRED

    def test_allow_does_not_log(self, mock_governance, body_json, raw_body, mock_request, mock_audit):
        """ALLOW decisions do not produce audit events (logged upstream)."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.ALLOW,
            plan_id="p1",
            token="tok",
        )
        evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        mock_audit.log.assert_not_called()

    def test_no_audit_logger_does_not_crash(self, mock_governance, body_json, raw_body, mock_request):
        """None audit_logger doesn't cause errors."""
        mock_governance.evaluate.side_effect = RuntimeError("db error")
        result = evaluate_governance(mock_governance, body_json, raw_body, mock_request, None)
        assert result.status_code == 500

    def test_allow_returns_evaluation_result(self, mock_governance, body_json, raw_body, mock_request, mock_audit):
        """ALLOW returns the EvaluationResult via the second return value."""
        eval_result = EvaluationResult(
            decision=GovernanceDecision.ALLOW,
            plan_id="p1",
            token="tok",
        )
        mock_governance.evaluate.return_value = eval_result
        response, returned_result = evaluate_governance(
            mock_governance, body_json, raw_body, mock_request, mock_audit,
            return_eval_result=True,
        )
        assert response is None
        assert returned_result is eval_result


class TestGovernanceRetryFlow:
    """SEC-D-02: Retry flow with request hash verification."""

    @pytest.fixture
    def mock_governance(self):
        mock = MagicMock(spec=GovernanceMiddleware)
        mock._store = MagicMock()
        return mock

    @pytest.fixture
    def mock_audit(self):
        return MagicMock()

    @pytest.fixture
    def body_json(self):
        return {"tool_calls": [{"name": "read_file", "arguments": {"path": "/etc/passwd"}}]}

    @pytest.fixture
    def raw_body(self, body_json):
        return json.dumps(body_json).encode()

    def test_valid_token_and_matching_hash_skips_evaluation(self, mock_governance, body_json, raw_body, mock_audit):
        """Valid plan + token + matching hash -> None (allow)."""
        from src.governance.enforcer import EnforcementResult
        from src.governance.models import ExecutionPlan

        mock_governance.enforce.return_value = EnforcementResult(
            allowed=True, reason="ok", plan_id="p1",
        )
        expected_hash = hashlib.sha256(raw_body).hexdigest()
        mock_plan = MagicMock()
        mock_plan.request_hash = expected_hash
        mock_governance._store.lookup.return_value = mock_plan

        mock_request = _make_mock_request(headers={
            "x-governance-plan-id": "p1",
            "x-governance-token": "valid-token",
        })
        result = evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        assert result is None
        # evaluate() should NOT have been called
        mock_governance.evaluate.assert_not_called()

    def test_invalid_token_returns_403(self, mock_governance, body_json, raw_body, mock_audit):
        """Invalid/expired token -> 403."""
        from src.governance.enforcer import EnforcementResult

        mock_governance.enforce.return_value = EnforcementResult(
            allowed=False, reason="Invalid token", plan_id="p1",
        )

        mock_request = _make_mock_request(headers={
            "x-governance-plan-id": "p1",
            "x-governance-token": "invalid-token",
        })
        result = evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        assert result is not None
        assert result.status_code == 403

    def test_mismatched_request_hash_returns_403(self, mock_governance, body_json, raw_body, mock_audit):
        """SEC-D-02: Token valid but body changed -> 403."""
        from src.governance.enforcer import EnforcementResult

        mock_governance.enforce.return_value = EnforcementResult(
            allowed=True, reason="ok", plan_id="p1",
        )
        mock_plan = MagicMock()
        mock_plan.request_hash = "different_hash_" + "0" * 49  # Wrong hash
        mock_governance._store.lookup.return_value = mock_plan

        mock_request = _make_mock_request(headers={
            "x-governance-plan-id": "p1",
            "x-governance-token": "valid-token",
        })
        result = evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        assert result is not None
        assert result.status_code == 403
        body = json.loads(result.body)
        assert "does not match" in body["error"]

    def test_retry_path_skips_re_evaluation(self, mock_governance, body_json, raw_body, mock_audit):
        """With valid token, governance.evaluate() is NOT called."""
        from src.governance.enforcer import EnforcementResult

        mock_governance.enforce.return_value = EnforcementResult(
            allowed=True, reason="ok", plan_id="p1",
        )
        expected_hash = hashlib.sha256(raw_body).hexdigest()
        mock_plan = MagicMock()
        mock_plan.request_hash = expected_hash
        mock_governance._store.lookup.return_value = mock_plan

        mock_request = _make_mock_request(headers={
            "x-governance-plan-id": "p1",
            "x-governance-token": "valid-token",
        })
        evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        mock_governance.evaluate.assert_not_called()

    def test_no_retry_headers_triggers_fresh_evaluation(self, mock_governance, body_json, raw_body, mock_audit):
        """Without retry headers, governance.evaluate() IS called."""
        mock_governance.evaluate.return_value = EvaluationResult(
            decision=GovernanceDecision.ALLOW,
            plan_id="p1",
            token="tok",
        )
        mock_request = _make_mock_request()
        evaluate_governance(mock_governance, body_json, raw_body, mock_request, mock_audit)
        mock_governance.evaluate.assert_called_once()
