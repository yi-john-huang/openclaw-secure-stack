"""Detection rule for network exfiltration patterns."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from src.models import ScanFinding, Severity
from src.scanner.rules.base import ASTScanRule

if TYPE_CHECKING:
    from tree_sitter import Node

# Default allowlisted domains (can be overridden via config)
DEFAULT_ALLOWLIST = {"api.openai.com", "api.anthropic.com"}

# Patterns indicating outbound network activity
NETWORK_APIS = {"fetch", "XMLHttpRequest", "axios"}
NETWORK_MODULES = {"http", "https", "net", "dgram", "node-fetch", "got", "request", "superagent"}

URL_PATTERN = re.compile(r"""https?://([a-zA-Z0-9.-]+)""")


class NetworkExfilRule(ASTScanRule):
    id = "NETWORK_EXFIL"
    name = "Network exfiltration"
    severity = Severity.HIGH

    def __init__(self, allowlist: set[str] | None = None) -> None:
        self.allowlist = allowlist or DEFAULT_ALLOWLIST

    def _walk(
        self,
        node: Node,
        findings: list[ScanFinding],
        lines: list[str],
        file_path: str,
        source_str: str,
    ) -> None:
        # Detect fetch(), axios(), XMLHttpRequest usage
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func and func.type == "identifier" and func.text:
                name = func.text.decode()
                if name in NETWORK_APIS and not self._is_allowlisted_call(node, source_str):
                        findings.append(self._make_finding(
                            func, lines, file_path,
                            f"Outbound network call: {name}()",
                        ))

        # Detect new XMLHttpRequest()
        if node.type == "new_expression":
            ctor = node.child_by_field_name("constructor")
            if ctor and ctor.type == "identifier" and ctor.text:
                name = ctor.text.decode()
                if name in NETWORK_APIS:
                    findings.append(self._make_finding(
                        ctor, lines, file_path,
                        f"Outbound network constructor: new {name}()",
                    ))

        # Detect require("http"), require("https"), etc.
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func and func.type == "identifier" and func.text and func.text.decode() == "require":
                args = node.child_by_field_name("arguments")
                if args and args.named_child_count > 0:
                    arg = args.named_children[0]
                    if arg.type == "string" and arg.text:
                        val = arg.text.decode().strip("'\"")
                        if val in NETWORK_MODULES:
                            findings.append(self._make_finding(
                                arg, lines, file_path,
                                f"Network module import: {val}",
                            ))

        self._walk_children(node, findings, lines, file_path, source_str)

    def _is_allowlisted_call(self, call_node: Node, source_str: str) -> bool:
        """Check if a network call targets an allowlisted domain."""
        # Extract the source text of the call to look for URLs
        start = call_node.start_byte
        end = call_node.end_byte
        call_text = source_str[start:end]

        urls = URL_PATTERN.findall(call_text)
        if not urls:
            return False  # Unknown destination -> not allowlisted

        return all(domain in self.allowlist for domain in urls)
