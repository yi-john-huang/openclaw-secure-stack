"""Detection rule for filesystem abuse patterns."""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.models import ScanFinding, Severity
from src.scanner.rules.base import ASTScanRule

if TYPE_CHECKING:
    from tree_sitter import Node

FS_WRITE_METHODS = {
    "writeFileSync", "writeFile", "appendFileSync", "appendFile",
    "createWriteStream",
}
FS_DELETE_METHODS = {
    "unlinkSync", "unlink", "rmdirSync", "rmdir", "rmSync", "rm",
}
FS_ALL_DANGEROUS = FS_WRITE_METHODS | FS_DELETE_METHODS


class FSAbuseRule(ASTScanRule):
    id = "FS_ABUSE"
    name = "Filesystem abuse"
    severity = Severity.HIGH

    def _walk(
        self,
        node: Node,
        findings: list[ScanFinding],
        lines: list[str],
        file_path: str,
    ) -> None:
        # Detect fs.writeFileSync(), fs.unlink(), etc.
        if node.type == "call_expression":
            func = node.child_by_field_name("function")

            # member expression: fs.writeFileSync(...)
            if func and func.type == "member_expression":
                prop = func.child_by_field_name("property")
                if prop and prop.text and prop.text.decode() in FS_ALL_DANGEROUS:
                    method_name = prop.text.decode()
                    # Check if writing to absolute path (first arg starts with /)
                    if self._writes_to_absolute_path(node):
                        findings.append(self._make_finding(
                            prop, lines, file_path,
                            f"Filesystem operation on absolute path: .{method_name}()",
                        ))
                    elif method_name in FS_DELETE_METHODS:
                        findings.append(self._make_finding(
                            prop, lines, file_path,
                            f"Filesystem delete operation: .{method_name}()",
                        ))

            # Direct call: writeFileSync(...)
            if func and func.type == "identifier" and func.text:
                name = func.text.decode()
                if name in FS_ALL_DANGEROUS:
                    findings.append(self._make_finding(
                        func, lines, file_path,
                        f"Filesystem operation: {name}()",
                    ))

        # Detect require("fs")
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            if func and func.type == "identifier" and func.text and func.text.decode() == "require":
                args = node.child_by_field_name("arguments")
                if args and args.named_child_count > 0:
                    arg = args.named_children[0]
                    if arg.type == "string" and arg.text:
                        val = arg.text.decode().strip("'\"")
                        if val in ("fs", "fs/promises"):
                            findings.append(self._make_finding(
                                arg, lines, file_path,
                                f"Filesystem module import: {val}",
                            ))

        self._walk_children(node, findings, lines, file_path)

    def _writes_to_absolute_path(self, call_node: Node) -> bool:
        """Check if the first argument to a write call is an absolute path string."""
        args = call_node.child_by_field_name("arguments")
        if args and args.named_child_count > 0:
            first_arg = args.named_children[0]
            if first_arg.type == "string" and first_arg.text:
                val = first_arg.text.decode().strip("'\"")
                return val.startswith("/")
        return False
