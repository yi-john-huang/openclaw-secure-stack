"""Detection rule for dangerous dynamic code APIs."""

from __future__ import annotations

from tree_sitter import Tree

from src.models import ScanFinding, Severity
from src.scanner.scanner import ScanRule

# Patterns that indicate dangerous dynamic code execution
DANGEROUS_IDENTIFIERS = {"eval", "Function"}
DANGEROUS_REQUIRES = {"child_process"}
DANGEROUS_METHODS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"}


class DangerousAPIRule(ScanRule):
    id = "DANGEROUS_API"
    name = "Dangerous dynamic code API"
    severity = Severity.CRITICAL

    def detect(self, tree: Tree, source: bytes, file_path: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        source_str = source.decode("utf-8", errors="replace")
        lines = source_str.split("\n")

        self._walk(tree.root_node, findings, lines, file_path)
        return findings

    def _walk(self, node, findings, lines, file_path):  # noqa: ANN001
        # Check call expressions: eval(...), exec(...)
        if node.type == "call_expression" and node.child_by_field_name("function"):
            func_node = node.child_by_field_name("function")
            if func_node and func_node.type == "identifier":
                name = func_node.text.decode()
                if name in DANGEROUS_IDENTIFIERS or name in DANGEROUS_METHODS:
                    findings.append(self._make_finding(func_node, lines, file_path,
                                                       f"Dangerous API call: {name}()"))

            # member expression: child_process.exec(...)
            if func_node and func_node.type == "member_expression":
                prop = func_node.child_by_field_name("property")
                if prop and prop.text and prop.text.decode() in DANGEROUS_METHODS:
                    msg = f"Dangerous method call: .{prop.text.decode()}()"
                    findings.append(self._make_finding(prop, lines, file_path, msg))

        # Check new expressions: new Function(...)
        if node.type == "new_expression" and node.child_by_field_name("constructor"):
            ctor = node.child_by_field_name("constructor")
            if (
                ctor and ctor.type == "identifier"
                and ctor.text and ctor.text.decode() in DANGEROUS_IDENTIFIERS
            ):
                msg = f"Dangerous constructor: new {ctor.text.decode()}()"
                findings.append(self._make_finding(ctor, lines, file_path, msg))

        # Check require("child_process")
        if node.type == "call_expression" and node.child_by_field_name("function"):
            func = node.child_by_field_name("function")
            if func and func.type == "identifier" and func.text and func.text.decode() == "require":
                args = node.child_by_field_name("arguments")
                if args and args.named_child_count > 0:
                    arg = args.named_children[0]
                    if arg.type == "string" and arg.text:
                        val = arg.text.decode().strip("'\"")
                        if val in DANGEROUS_REQUIRES:
                            findings.append(self._make_finding(arg, lines, file_path,
                                                               f"Dangerous require: {val}"))

        for child in node.children:
            self._walk(child, findings, lines, file_path)

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
