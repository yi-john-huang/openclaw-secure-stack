"""Detection rule for filesystem abuse patterns."""

from __future__ import annotations

from tree_sitter import Tree

from src.models import ScanFinding, Severity
from src.scanner.scanner import ScanRule

FS_WRITE_METHODS = {
    "writeFileSync", "writeFile", "appendFileSync", "appendFile",
    "createWriteStream",
}
FS_DELETE_METHODS = {
    "unlinkSync", "unlink", "rmdirSync", "rmdir", "rmSync", "rm",
}
FS_ALL_DANGEROUS = FS_WRITE_METHODS | FS_DELETE_METHODS


class FSAbuseRule(ScanRule):
    id = "FS_ABUSE"
    name = "Filesystem abuse"
    severity = Severity.HIGH

    def detect(self, tree: Tree, source: bytes, file_path: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        source_str = source.decode("utf-8", errors="replace")
        lines = source_str.split("\n")

        self._walk(tree.root_node, findings, lines, file_path)
        return findings

    def _walk(self, node, findings, lines, file_path):  # noqa: ANN001
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

        for child in node.children:
            self._walk(child, findings, lines, file_path)

    def _writes_to_absolute_path(self, call_node) -> bool:  # noqa: ANN001
        """Check if the first argument to a write call is an absolute path string."""
        args = call_node.child_by_field_name("arguments")
        if args and args.named_child_count > 0:
            first_arg = args.named_children[0]
            if first_arg.type == "string" and first_arg.text:
                val = first_arg.text.decode().strip("'\"")
                return val.startswith("/")
        return False

    def _make_finding(self, node, lines, file_path, message):  # noqa: ANN001
        line_num = node.start_point[0] + 1
        col = node.start_point[1]
        row = node.start_point[0]
        snippet = lines[row].strip()[:200] if row < len(lines) else ""
        return ScanFinding(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            file=file_path,
            line=line_num,
            column=col,
            snippet=snippet,
            message=message,
        )
