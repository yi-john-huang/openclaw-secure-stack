"""Tests for plan generation."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import pytest


@pytest.fixture
def patterns_path(tmp_path: Path) -> str:
    """Create a temporary patterns config file."""
    patterns = {
        "tool_categories": {
            "file_read": ["read_file"],
            "file_write": ["write_file"],
            "file_delete": ["delete_file"],
            "network_request": ["http_get"],
            "code_execution": ["execute_code"],
        },
        "argument_patterns": {
            "sensitive_paths": ["^/etc/", ".*secret.*"],
            "external_urls": ["^https?://(?!localhost)"],
        },
        "risk_multipliers": {
            "file_read": 1.0,
            "file_write": 2.0,
            "file_delete": 3.0,
            "network_request": 2.0,
            "code_execution": 4.0,
            "unknown": 2.5,
        },
    }
    path = tmp_path / "intent-patterns.json"
    path.write_text(json.dumps(patterns))
    return str(path)


@pytest.fixture
def planner(patterns_path: str):
    """Create a PlanGenerator instance."""
    from src.governance.planner import PlanGenerator

    return PlanGenerator(patterns_path)


class TestActionBuilding:
    """Tests for building planned actions."""

    def test_builds_ordered_actions(self, planner):
        """Test actions are built with sequential order."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[
                ToolCall(name="read_file", arguments={"path": "/tmp/a.txt"}),
                ToolCall(name="read_file", arguments={"path": "/tmp/b.txt"}),
            ],
            confidence=0.9,
        )
        actions = planner._build_actions(intent)
        assert len(actions) == 2
        assert actions[0].sequence == 0
        assert actions[1].sequence == 1

    def test_assigns_category_from_tool(self, planner):
        """Test category is assigned from tool classification."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        actions = planner._build_actions(intent)
        assert actions[0].category == IntentCategory.FILE_READ

    def test_calculates_risk_score(self, planner):
        """Test risk score is calculated based on category."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_DELETE,
            signals=[],
            tool_calls=[ToolCall(name="delete_file", arguments={})],
            confidence=0.9,
        )
        actions = planner._build_actions(intent)
        # file_delete has risk multiplier 3.0, so base risk should be elevated
        assert actions[0].risk_score > 0

    def test_higher_risk_for_code_execution(self, planner):
        """Test code execution has higher risk than file read."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        read_intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        exec_intent = Intent(
            primary_category=IntentCategory.CODE_EXECUTION,
            signals=[],
            tool_calls=[ToolCall(name="execute_code", arguments={})],
            confidence=0.9,
        )
        read_actions = planner._build_actions(read_intent)
        exec_actions = planner._build_actions(exec_intent)
        assert exec_actions[0].risk_score > read_actions[0].risk_score


class TestResourceExtraction:
    """Tests for extracting resources from tool calls."""

    def test_extracts_file_path(self, planner):
        """Test file path is extracted from arguments."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="read_file", arguments={"path": "/tmp/file.txt"})
        resources = planner._extract_resources(tc)
        assert len(resources) >= 1
        assert any(r.type == "file" and r.path == "/tmp/file.txt" for r in resources)

    def test_extracts_url(self, planner):
        """Test URL is extracted from arguments."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="http_get", arguments={"url": "https://api.example.com"})
        resources = planner._extract_resources(tc)
        assert any(r.type == "url" for r in resources)

    def test_determines_operation_read(self, planner):
        """Test read operation is determined from tool name."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="read_file", arguments={"path": "/tmp/file.txt"})
        resources = planner._extract_resources(tc)
        file_resources = [r for r in resources if r.type == "file"]
        assert any(r.operation == "read" for r in file_resources)

    def test_determines_operation_write(self, planner):
        """Test write operation is determined from tool name."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="write_file", arguments={"path": "/tmp/out.txt"})
        resources = planner._extract_resources(tc)
        file_resources = [r for r in resources if r.type == "file"]
        assert any(r.operation == "write" for r in file_resources)

    def test_determines_operation_delete(self, planner):
        """Test delete operation is determined from tool name."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="delete_file", arguments={"path": "/tmp/file.txt"})
        resources = planner._extract_resources(tc)
        file_resources = [r for r in resources if r.type == "file"]
        assert any(r.operation == "delete" for r in file_resources)

    def test_no_resources_for_unknown_args(self, planner):
        """Test no resources extracted for unknown argument patterns."""
        from src.governance.models import ToolCall

        tc = ToolCall(name="custom_tool", arguments={"foo": "bar"})
        resources = planner._extract_resources(tc)
        # Should return empty or minimal resources
        assert isinstance(resources, list)


class TestRiskAssessment:
    """Tests for risk assessment calculation."""

    def test_calculates_overall_score(self, planner):
        """Test overall score is calculated from actions."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ResourceAccess,
            ToolCall,
        )

        actions = [
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="read_file", arguments={}),
                category=IntentCategory.FILE_READ,
                resources=[ResourceAccess(type="file", path="/tmp/a", operation="read")],
                risk_score=30,
            )
        ]
        assessment = planner._assess_risk(actions)
        assert 0 <= assessment.overall_score <= 100

    def test_determines_risk_level_low(self, planner):
        """Test LOW risk level for low scores."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            RiskLevel,
            ToolCall,
        )

        actions = [
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="read_file", arguments={}),
                category=IntentCategory.FILE_READ,
                resources=[],
                risk_score=10,
            )
        ]
        assessment = planner._assess_risk(actions)
        assert assessment.level in (RiskLevel.LOW, RiskLevel.INFO)

    def test_determines_risk_level_high(self, planner):
        """Test HIGH risk level for high scores."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            RiskLevel,
            ToolCall,
        )

        actions = [
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="execute_code", arguments={}),
                category=IntentCategory.CODE_EXECUTION,
                resources=[],
                risk_score=80,
            )
        ]
        assessment = planner._assess_risk(actions)
        assert assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_identifies_risk_factors(self, planner):
        """Test risk factors are identified."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ToolCall,
        )

        actions = [
            PlannedAction(
                sequence=0,
                tool_call=ToolCall(name="execute_code", arguments={}),
                category=IntentCategory.CODE_EXECUTION,
                resources=[],
                risk_score=80,
            )
        ]
        assessment = planner._assess_risk(actions)
        assert "code_execution" in assessment.factors

    def test_caps_at_100(self, planner):
        """Test overall score is capped at 100."""
        from src.governance.models import (
            IntentCategory,
            PlannedAction,
            ToolCall,
        )

        # Create many high-risk actions
        actions = [
            PlannedAction(
                sequence=i,
                tool_call=ToolCall(name="execute_code", arguments={}),
                category=IntentCategory.CODE_EXECUTION,
                resources=[],
                risk_score=100,
            )
            for i in range(10)
        ]
        assessment = planner._assess_risk(actions)
        assert assessment.overall_score == 100


class TestFullGeneration:
    """Tests for full plan generation."""

    def test_generates_plan_with_uuid(self, planner):
        """Test generated plan has valid UUID plan_id."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={"path": "/tmp"})],
            confidence=0.9,
        )
        plan = planner.generate(intent, request_body={"tools": []})
        # Should be a valid UUID
        uuid.UUID(plan.plan_id)

    def test_includes_request_hash(self, planner):
        """Test plan includes request hash."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        request_body = {"tools": [{"name": "read_file"}]}
        plan = planner.generate(intent, request_body=request_body)
        assert len(plan.request_hash) == 64  # SHA-256 hex

    def test_request_hash_matches(self, planner):
        """Test request hash matches computed hash."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        request_body = {"tools": [{"name": "read_file"}]}
        plan = planner.generate(intent, request_body=request_body)

        expected_hash = hashlib.sha256(
            json.dumps(request_body, sort_keys=True).encode()
        ).hexdigest()
        assert plan.request_hash == expected_hash

    def test_includes_session_id(self, planner):
        """Test plan includes session ID when provided."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        plan = planner.generate(intent, request_body={}, session_id="sess-123")
        assert plan.session_id == "sess-123"

    def test_session_id_none_when_not_provided(self, planner):
        """Test session_id is None when not provided."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={})],
            confidence=0.9,
        )
        plan = planner.generate(intent, request_body={})
        assert plan.session_id is None

    def test_empty_intent_empty_actions(self, planner):
        """Test empty intent produces empty actions."""
        from src.governance.models import Intent, IntentCategory

        empty_intent = Intent(
            primary_category=IntentCategory.UNKNOWN,
            signals=[],
            tool_calls=[],
            confidence=1.0,
        )
        plan = planner.generate(empty_intent, request_body={})
        assert plan.actions == []

    def test_actions_have_resources(self, planner):
        """Test generated actions include resources."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.FILE_READ,
            signals=[],
            tool_calls=[ToolCall(name="read_file", arguments={"path": "/tmp/test.txt"})],
            confidence=0.9,
        )
        plan = planner.generate(intent, request_body={})
        assert len(plan.actions) == 1
        assert len(plan.actions[0].resources) > 0

    def test_risk_assessment_included(self, planner):
        """Test plan includes risk assessment."""
        from src.governance.models import Intent, IntentCategory, ToolCall

        intent = Intent(
            primary_category=IntentCategory.CODE_EXECUTION,
            signals=[],
            tool_calls=[ToolCall(name="execute_code", arguments={"code": "print(1)"})],
            confidence=0.9,
        )
        plan = planner.generate(intent, request_body={})
        assert plan.risk_assessment is not None
        assert plan.risk_assessment.overall_score > 0
