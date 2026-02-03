"""Base class for AST-based scanner rules."""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING

from tree_sitter import Tree

from src.models import ScanFinding, Severity
from src.scanner.scanner import ScanRule

if TYPE_CHECKING:
    from tree_sitter import Node


class ASTScanRule(ScanRule):
    """Base class for tree-sitter AST-based detection rules.

    Provides common functionality for AST traversal and finding creation.
    Subclasses implement detection logic in _walk().
    """

    id: str
    name: str
    severity: Severity

    def detect(self, tree: Tree, source: bytes, file_path: str) -> list[ScanFinding]:
        """Parse source and walk AST to detect issues."""
        findings: list[ScanFinding] = []
        source_str = source.decode("utf-8", errors="replace")
        lines = source_str.split("\n")
        self._walk(tree.root_node, findings, lines, file_path)
        return findings

    @abstractmethod
    def _walk(
        self,
        node: Node,
        findings: list[ScanFinding],
        lines: list[str],
        file_path: str,
    ) -> None:
        """Walk AST node and append findings. Subclasses implement detection logic."""
        ...

    def _walk_children(
        self,
        node: Node,
        findings: list[ScanFinding],
        lines: list[str],
        file_path: str,
    ) -> None:
        """Recurse into child nodes."""
        for child in node.children:
            self._walk(child, findings, lines, file_path)

    def _make_finding(
        self,
        node: Node,
        lines: list[str],
        file_path: str,
        message: str,
    ) -> ScanFinding:
        """Create a ScanFinding from an AST node."""
        row = node.start_point[0]
        return ScanFinding(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            file=file_path,
            line=row + 1,
            column=node.start_point[1],
            snippet=lines[row].strip()[:200] if row < len(lines) else "",
            message=message,
        )
