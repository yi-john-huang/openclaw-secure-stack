"""Tests for intent classification."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def patterns_path(tmp_path: Path) -> str:
    """Create a temporary patterns config file."""
    patterns = {
        "tool_categories": {
            "file_read": ["read_file", "get_file_contents", "list_directory"],
            "file_write": ["write_file", "create_file"],
            "file_delete": ["delete_file", "remove_file"],
            "network_request": ["http_get", "fetch_url", "api_call"],
            "code_execution": ["execute_code", "run_script", "bash"],
            "skill_invocation": ["invoke_skill"],
            "system_command": ["shell_command"],
        },
        "argument_patterns": {
            "sensitive_paths": [
                "^/etc/",
                ".*passwd.*",
                ".*secret.*",
            ],
            "external_urls": [
                "^https?://(?!localhost|127\\.0\\.0\\.1)"
            ],
        },
        "risk_multipliers": {
            "file_read": 1.0,
            "file_write": 2.0,
            "file_delete": 3.0,
            "network_request": 2.0,
            "code_execution": 4.0,
            "skill_invocation": 1.5,
            "system_command": 4.0,
            "unknown": 2.5,
        },
    }
    path = tmp_path / "intent-patterns.json"
    path.write_text(json.dumps(patterns))
    return str(path)


@pytest.fixture
def classifier(patterns_path: str):
    """Create an IntentClassifier instance."""
    from src.governance.classifier import IntentClassifier

    return IntentClassifier(patterns_path)


class TestToolExtraction:
    """Tests for tool call extraction from request body."""

    def test_extract_from_openai_format(self, classifier):
        """Test extracting tools from OpenAI function calling format."""
        body = {
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "read_file",
                        "arguments": '{"path": "/tmp/test.txt"}',
                    },
                }
            ]
        }
        tools = classifier._extract_tool_calls(body)
        assert len(tools) == 1
        assert tools[0].name == "read_file"
        assert tools[0].arguments == {"path": "/tmp/test.txt"}

    def test_extract_multiple_tools(self, classifier):
        """Test extracting multiple tools."""
        body = {
            "tools": [
                {"type": "function", "function": {"name": "read_file", "arguments": "{}"}},
                {"type": "function", "function": {"name": "write_file", "arguments": "{}"}},
            ]
        }
        tools = classifier._extract_tool_calls(body)
        assert len(tools) == 2
        assert tools[0].name == "read_file"
        assert tools[1].name == "write_file"

    def test_empty_body_returns_empty_list(self, classifier):
        """Test empty body returns empty list."""
        tools = classifier._extract_tool_calls({})
        assert tools == []

    def test_no_tools_key_returns_empty_list(self, classifier):
        """Test body without tools key returns empty list."""
        tools = classifier._extract_tool_calls({"messages": []})
        assert tools == []

    def test_malformed_tools_skipped(self, classifier):
        """Test malformed tool entries are skipped."""
        body = {
            "tools": [
                {"invalid": "format"},
                {"type": "function", "function": {"name": "valid", "arguments": "{}"}},
            ]
        }
        tools = classifier._extract_tool_calls(body)
        assert len(tools) == 1
        assert tools[0].name == "valid"

    def test_tool_call_id_extracted(self, classifier):
        """Test tool call ID is extracted when present."""
        body = {
            "tools": [
                {
                    "type": "function",
                    "id": "call_123",
                    "function": {"name": "read_file", "arguments": "{}"},
                }
            ]
        }
        tools = classifier._extract_tool_calls(body)
        assert tools[0].id == "call_123"

    def test_json_arguments_parsed(self, classifier):
        """Test JSON string arguments are parsed."""
        body = {
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "read_file",
                        "arguments": '{"path": "/tmp", "encoding": "utf-8"}',
                    },
                }
            ]
        }
        tools = classifier._extract_tool_calls(body)
        assert tools[0].arguments == {"path": "/tmp", "encoding": "utf-8"}

    def test_dict_arguments_preserved(self, classifier):
        """Test dict arguments are preserved as-is."""
        body = {
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "read_file",
                        "arguments": {"path": "/tmp"},
                    },
                }
            ]
        }
        tools = classifier._extract_tool_calls(body)
        assert tools[0].arguments == {"path": "/tmp"}


class TestCategoryMapping:
    """Tests for tool to category mapping."""

    def test_known_tool_mapped(self, classifier):
        """Test known tools are mapped to correct categories."""
        from src.governance.models import IntentCategory

        category = classifier._categorize_tool("read_file")
        assert category == IntentCategory.FILE_READ

    def test_write_tool_mapped(self, classifier):
        """Test write tools are mapped correctly."""
        from src.governance.models import IntentCategory

        category = classifier._categorize_tool("write_file")
        assert category == IntentCategory.FILE_WRITE

    def test_delete_tool_mapped(self, classifier):
        """Test delete tools are mapped correctly."""
        from src.governance.models import IntentCategory

        category = classifier._categorize_tool("delete_file")
        assert category == IntentCategory.FILE_DELETE

    def test_network_tool_mapped(self, classifier):
        """Test network tools are mapped correctly."""
        from src.governance.models import IntentCategory

        category = classifier._categorize_tool("http_get")
        assert category == IntentCategory.NETWORK_REQUEST

    def test_execution_tool_mapped(self, classifier):
        """Test execution tools are mapped correctly."""
        from src.governance.models import IntentCategory

        category = classifier._categorize_tool("execute_code")
        assert category == IntentCategory.CODE_EXECUTION

    def test_unknown_tool_returns_unknown(self, classifier):
        """Test unknown tools return UNKNOWN category."""
        from src.governance.models import IntentCategory

        category = classifier._categorize_tool("custom_tool_xyz")
        assert category == IntentCategory.UNKNOWN

    def test_case_insensitive_matching(self, classifier):
        """Test category matching is case-insensitive."""
        from src.governance.models import IntentCategory

        assert classifier._categorize_tool("READ_FILE") == IntentCategory.FILE_READ
        assert classifier._categorize_tool("Read_File") == IntentCategory.FILE_READ


class TestArgumentAnalysis:
    """Tests for sensitive argument pattern detection."""

    def test_detects_sensitive_path(self, classifier):
        """Test detection of sensitive file paths."""
        from src.governance.models import IntentCategory

        signals = classifier._analyze_arguments({"path": "/etc/passwd"})
        assert len(signals) > 0
        assert any("sensitive" in s.details.lower() for s in signals if s.details)

    def test_detects_secret_in_path(self, classifier):
        """Test detection of 'secret' keyword in paths."""
        signals = classifier._analyze_arguments({"file": "/home/user/.secrets/key"})
        assert len(signals) > 0

    def test_detects_external_url(self, classifier):
        """Test detection of external URLs."""
        from src.governance.models import IntentCategory

        signals = classifier._analyze_arguments({"url": "https://evil.com/exfil"})
        assert len(signals) > 0
        assert any(s.category == IntentCategory.NETWORK_REQUEST for s in signals)

    def test_safe_arguments_no_signals(self, classifier):
        """Test safe arguments produce no signals."""
        signals = classifier._analyze_arguments({"path": "/tmp/safe.txt"})
        assert len(signals) == 0

    def test_localhost_url_no_signal(self, classifier):
        """Test localhost URLs don't produce signals."""
        signals = classifier._analyze_arguments({"url": "http://localhost:8080/api"})
        assert len(signals) == 0

    def test_nested_arguments_analyzed(self, classifier):
        """Test nested arguments are analyzed."""
        signals = classifier._analyze_arguments(
            {"config": {"file": "/etc/shadow", "nested": {"deep": "value"}}}
        )
        assert len(signals) > 0

    def test_list_arguments_analyzed(self, classifier):
        """Test list arguments are analyzed."""
        signals = classifier._analyze_arguments(
            {"paths": ["/tmp/safe.txt", "/etc/passwd"]}
        )
        assert len(signals) > 0


class TestFullClassification:
    """Tests for full intent classification."""

    def test_classify_returns_intent(self, classifier):
        """Test classify returns an Intent object."""
        from src.governance.models import Intent, IntentCategory

        body = {
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "read_file", "arguments": '{"path": "/tmp"}'},
                }
            ]
        }
        intent = classifier.classify(body)
        assert isinstance(intent, Intent)
        assert intent.primary_category == IntentCategory.FILE_READ

    def test_confidence_calculated(self, classifier):
        """Test confidence score is calculated."""
        body = {
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "read_file", "arguments": "{}"},
                }
            ]
        }
        intent = classifier.classify(body)
        assert 0.0 <= intent.confidence <= 1.0

    def test_multiple_tools_aggregated(self, classifier):
        """Test multiple tools are aggregated in intent."""
        body = {
            "tools": [
                {"type": "function", "function": {"name": "read_file", "arguments": "{}"}},
                {"type": "function", "function": {"name": "http_get", "arguments": "{}"}},
            ]
        }
        intent = classifier.classify(body)
        assert len(intent.tool_calls) == 2

    def test_primary_category_highest_risk(self, classifier):
        """Test primary category is the highest risk."""
        from src.governance.models import IntentCategory

        body = {
            "tools": [
                {"type": "function", "function": {"name": "read_file", "arguments": "{}"}},
                {"type": "function", "function": {"name": "execute_code", "arguments": "{}"}},
            ]
        }
        intent = classifier.classify(body)
        # code_execution has higher risk multiplier than file_read
        assert intent.primary_category == IntentCategory.CODE_EXECUTION

    def test_empty_body_returns_unknown(self, classifier):
        """Test empty body returns UNKNOWN category."""
        from src.governance.models import IntentCategory

        intent = classifier.classify({})
        assert intent.primary_category == IntentCategory.UNKNOWN
        assert len(intent.tool_calls) == 0

    def test_signals_included(self, classifier):
        """Test signals are included in intent."""
        body = {
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "read_file",
                        "arguments": '{"path": "/etc/passwd"}',
                    },
                }
            ]
        }
        intent = classifier.classify(body)
        # Should have signal from tool category and from sensitive path
        assert len(intent.signals) >= 1


class TestConfigurationErrors:
    """Tests for configuration error handling."""

    def test_missing_config_raises(self, tmp_path):
        """Test missing config file raises error."""
        from src.governance.classifier import IntentClassifier

        with pytest.raises(FileNotFoundError):
            IntentClassifier(str(tmp_path / "nonexistent.json"))

    def test_invalid_json_raises(self, tmp_path):
        """Test invalid JSON raises error."""
        from src.governance.classifier import IntentClassifier

        path = tmp_path / "invalid.json"
        path.write_text("not valid json")
        with pytest.raises(ValueError):
            IntentClassifier(str(path))

    def test_missing_keys_raises(self, tmp_path):
        """Test missing required keys raises error."""
        from src.governance.classifier import IntentClassifier

        path = tmp_path / "incomplete.json"
        path.write_text('{"tool_categories": {}}')
        with pytest.raises(ValueError):
            IntentClassifier(str(path))
