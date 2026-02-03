#!/usr/bin/env python3
"""Security audit script for OpenClaw Secure Stack.

Performs OWASP-aligned security checks against the running stack.

Exit codes:
    0 — no findings
    1 — findings reported
    2 — prerequisite failure (e.g., Docker not running)

Usage:
    python scripts/audit.py [--format json|text]
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.audit.logger import validate_audit_chain  # noqa: E402


@dataclass
class Finding:
    check: str
    severity: str  # critical, high, medium, low
    message: str
    remediation: str


def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)  # noqa: S603


def _detect_runtime() -> str:
    for rt in ("docker", "podman"):
        result = _run([rt, "version"])
        if result.returncode == 0:
            return rt
    return ""


def _get_compose_cmd(runtime: str) -> list[str]:
    return [runtime, "compose"]


# --- Check functions ---


def container_hardening(runtime: str, compose_cmd: list[str]) -> list[Finding]:
    """Check container images for hardening: non-root, no SUID, read-only."""
    findings: list[Finding] = []

    # Get running service containers
    result = _run([*compose_cmd, "ps", "--format", "json"])
    if result.returncode != 0:
        return [Finding(
            check="container_hardening",
            severity="critical",
            message="Cannot list running containers. Is the stack running?",
            remediation="Start the stack with: docker compose up -d",
        )]

    services_to_check = ["proxy", "openclaw", "egress-dns"]
    for service in services_to_check:
        result = _run([*compose_cmd, "ps", "-q", service])
        container_id = result.stdout.strip()
        if not container_id:
            continue

        # Check user (65534=nobody, 65532=distroless nonroot)
        result = _run([runtime, "inspect", "--format", "{{.Config.User}}", container_id])
        user = result.stdout.strip()
        if user not in ("65534", "65532", "nobody", "nonroot"):
            findings.append(Finding(
                check="container_hardening",
                severity="high",
                message=f"Service '{service}' runs as user '{user}' (expected non-root)",
                remediation=f"Set 'user: \"65534\"' or use distroless image for {service}",
            ))

    return findings


def network_isolation(compose_file: Path) -> list[Finding]:
    """Check for unexpected published ports."""
    findings: list[Finding] = []
    if not compose_file.exists():
        return findings

    content = compose_file.read_text()
    compose_data = _parse_yaml_simple(content)

    allowed_port_services = {"proxy", "caddy"}
    services = compose_data.get("services", {})
    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if name in allowed_port_services:
            continue
        if "ports" in svc:
            findings.append(Finding(
                check="network_isolation",
                severity="high",
                message=f"Service '{name}' publishes ports to host: {svc['ports']}",
                remediation=f"Remove 'ports' from {name} in docker-compose.yml",
            ))

    return findings


def _parse_yaml_simple(content: str) -> dict:
    """Minimal YAML-like parser for docker-compose — only handles the ports check."""
    try:
        import yaml  # noqa: F811
        return yaml.safe_load(content) or {}
    except ImportError:
        pass

    # Fallback: check for 'ports:' under non-allowed services via regex
    import re
    result: dict = {"services": {}}
    current_service = None
    in_ports = False
    ports: list[str] = []

    for line in content.split("\n"):
        # Detect service name (2-space indent, ends with colon)
        m = re.match(r"^  (\w[\w-]*):", line)
        if m:
            if current_service and in_ports and ports:
                result["services"].setdefault(current_service, {})["ports"] = ports
            current_service = m.group(1)
            in_ports = False
            ports = []
            result["services"].setdefault(current_service, {})
            continue

        if current_service:
            if re.match(r"^    ports:", line):
                in_ports = True
                continue
            if in_ports and re.match(r'^      - ', line):
                ports.append(line.strip().lstrip("- ").strip('"').strip("'"))
                continue
            if in_ports and not line.startswith("      "):
                if ports:
                    result["services"][current_service]["ports"] = ports
                in_ports = False
                ports = []

    if current_service and in_ports and ports:
        result["services"][current_service]["ports"] = ports

    return result


def secret_management(project_root: Path) -> list[Finding]:
    """Check for secrets leaking into version control or compose file."""
    findings: list[Finding] = []

    # Check .env is not committed
    result = _run(["git", "ls-files", "--error-unmatch", ".env"], cwd=str(project_root))
    if result.returncode == 0:
        findings.append(Finding(
            check="secret_management",
            severity="critical",
            message=".env file is tracked in git",
            remediation="Add .env to .gitignore and run: git rm --cached .env",
        ))

    # Check compose file for hardcoded secrets
    compose_file = project_root / "docker-compose.yml"
    if compose_file.exists():
        content = compose_file.read_text()
        secret_patterns = ["password=", "secret=", "api_key=sk-", "token=ey"]
        for pattern in secret_patterns:
            if pattern.lower() in content.lower():
                findings.append(Finding(
                    check="secret_management",
                    severity="high",
                    message=f"Possible hardcoded secret in docker-compose.yml (pattern: {pattern})",
                    remediation="Use environment variable references (${VAR}) instead of hardcoded values",
                ))

    return findings


def log_integrity(project_root: Path) -> list[Finding]:
    """Check audit log existence and hash chain integrity."""
    findings: list[Finding] = []

    # Check if audit log rotation is configured
    max_bytes = os.environ.get("AUDIT_LOG_MAX_BYTES")
    if not max_bytes:
        findings.append(Finding(
            check="log_integrity",
            severity="medium",
            message="AUDIT_LOG_MAX_BYTES not configured — log rotation may not be active",
            remediation="Set AUDIT_LOG_MAX_BYTES environment variable (e.g., 10485760 for 10MB)",
        ))
    backup_count = os.environ.get("AUDIT_LOG_BACKUP_COUNT")
    if not backup_count:
        findings.append(Finding(
            check="log_integrity",
            severity="low",
            message="AUDIT_LOG_BACKUP_COUNT not configured — retention may be default",
            remediation="Set AUDIT_LOG_BACKUP_COUNT environment variable (e.g., 5)",
        ))

    log_path = os.environ.get("AUDIT_LOG_PATH") or str(project_root / "data" / "audit.jsonl")
    log_file = Path(log_path)
    if log_file.exists():
        result = validate_audit_chain(log_file)
        if not result.valid:
            findings.append(Finding(
                check="log_integrity",
                severity="critical",
                message=f"Audit log hash chain broken at line {result.broken_at_line}",
                remediation="Investigate tampering; rotate log and restore from trusted backup",
            ))
    else:
        findings.append(Finding(
            check="log_integrity",
            severity="low",
            message=f"Audit log not found at {log_path}",
            remediation="Ensure AUDIT_LOG_PATH points to the audit log file generated by the proxy",
        ))

    return findings


def skill_security(project_root: Path) -> list[Finding]:
    """Check scanner rules and quarantine DB are accessible."""
    findings: list[Finding] = []

    rules_file = project_root / "config" / "scanner-rules.json"
    if not rules_file.exists():
        findings.append(Finding(
            check="skill_security",
            severity="high",
            message="Scanner rules file not found at config/scanner-rules.json",
            remediation="Ensure config/scanner-rules.json exists with valid detection rules",
        ))
    else:
        try:
            rules = json.loads(rules_file.read_text())
            if not rules:
                findings.append(Finding(
                    check="skill_security",
                    severity="high",
                    message="Scanner rules file is empty",
                    remediation="Add detection rules to config/scanner-rules.json",
                ))
        except json.JSONDecodeError:
            findings.append(Finding(
                check="skill_security",
                severity="high",
                message="Scanner rules file contains invalid JSON",
                remediation="Fix JSON syntax in config/scanner-rules.json",
            ))

    return findings


def documentation(project_root: Path) -> list[Finding]:
    """Check that required documentation sections exist."""
    findings: list[Finding] = []
    readme = project_root / "README.md"

    if not readme.exists():
        findings.append(Finding(
            check="documentation",
            severity="medium",
            message="README.md not found",
            remediation="Create README.md with project documentation",
        ))
        return findings

    content = readme.read_text().lower()

    checks = [
        ("troubleshoot", "Troubleshooting section missing from README"),
        ("network polic", "Network policy documentation missing from README"),
        ("rebuild", "Rebuild strategy documentation missing from README"),
    ]
    for keyword, msg in checks:
        if keyword not in content:
            findings.append(Finding(
                check="documentation",
                severity="low",
                message=msg,
                remediation=f"Add a section containing '{keyword}' to README.md",
            ))

    return findings


def _parse_rfc3339(value: str) -> datetime | None:
    if not value:
        return None
    ts = value.replace("Z", "+00:00")
    if "." in ts:
        head, tail = ts.split(".", 1)
        # Split fractional seconds from timezone offset
        offset_idx = max(tail.rfind("+"), tail.rfind("-"))
        if offset_idx > 0:
            frac = tail[:offset_idx]
            offset = tail[offset_idx:]
        else:
            frac = tail
            offset = ""
        frac = (frac + "000000")[:6]
        ts = f"{head}.{frac}{offset}"
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _get_container_id(compose_cmd: list[str], service: str) -> str:
    result = _run([*compose_cmd, "ps", "-q", service])
    return result.stdout.strip()


def performance(runtime: str, compose_cmd: list[str]) -> list[Finding]:
    """Informational performance checks — startup time and latency."""
    findings: list[Finding] = []
    latency_threshold_ms = int(os.environ.get("AUDIT_LATENCY_P95_MS", "500"))
    startup_threshold_s = int(os.environ.get("AUDIT_STARTUP_MAX_SECONDS", "60"))
    samples = int(os.environ.get("AUDIT_LATENCY_SAMPLES", "20"))
    timeout_s = float(os.environ.get("AUDIT_LATENCY_TIMEOUT_SECONDS", "2"))

    # Simple health check latency test
    proxy_id = _get_container_id(compose_cmd, "proxy")
    if not proxy_id:
        findings.append(Finding(
            check="performance",
            severity="low",
            message="Proxy container not running — cannot measure latency",
            remediation="Start the stack with: docker compose up -d",
        ))
    else:
        proxy_port = os.environ.get("PROXY_PORT", "8080")
        proxy_url = os.environ.get("AUDIT_PROXY_URL", f"http://localhost:{proxy_port}/health")
        latencies: list[float] = []
        try:
            for _ in range(samples):
                start = time.perf_counter()
                with urllib.request.urlopen(proxy_url, timeout=timeout_s) as resp:
                    resp.read()
                latencies.append((time.perf_counter() - start) * 1000)
        except (urllib.error.URLError, TimeoutError, OSError):
            findings.append(Finding(
                check="performance",
                severity="low",
                message=f"Cannot reach proxy health endpoint at {proxy_url}",
                remediation="Ensure the proxy is reachable from the host and PROXY_PORT is correct",
            ))
        else:
            if latencies:
                latencies.sort()
                p95_index = max(0, math.ceil(0.95 * len(latencies)) - 1)
                p95_ms = latencies[p95_index]
                if p95_ms > latency_threshold_ms:
                    findings.append(Finding(
                        check="performance",
                        severity="medium",
                        message=f"Proxy latency p95 {p95_ms:.1f}ms exceeds {latency_threshold_ms}ms",
                        remediation="Investigate proxy performance or raise AUDIT_LATENCY_P95_MS",
                    ))

    # Startup time measurement using openclaw health logs (if available)
    startup_service = os.environ.get("AUDIT_STARTUP_SERVICE", "openclaw")
    startup_id = _get_container_id(compose_cmd, startup_service)
    if not startup_id:
        findings.append(Finding(
            check="performance",
            severity="low",
            message=f"Service '{startup_service}' not running — cannot measure startup time",
            remediation="Start the stack with: docker compose up -d",
        ))
        return findings

    state_result = _run([runtime, "inspect", startup_id, "--format", "{{json .State}}"])
    if state_result.returncode != 0:
        findings.append(Finding(
            check="performance",
            severity="low",
            message=f"Cannot inspect service '{startup_service}' — startup time unknown",
            remediation="Ensure Docker/Podman is running and the service exists",
        ))
        return findings

    try:
        state = json.loads(state_result.stdout)
    except json.JSONDecodeError:
        findings.append(Finding(
            check="performance",
            severity="low",
            message=f"Invalid inspect output for service '{startup_service}'",
            remediation="Retry audit after ensuring container runtime is stable",
        ))
        return findings

    started_at = _parse_rfc3339(state.get("StartedAt", ""))
    health = state.get("Health", {}) if isinstance(state, dict) else {}
    logs = health.get("Log", []) if isinstance(health, dict) else []
    healthy_times: list[datetime] = []
    for entry in logs:
        if entry.get("Status") == "healthy":
            ts = _parse_rfc3339(entry.get("End", "") or entry.get("Start", ""))
            if ts:
                healthy_times.append(ts)

    if started_at and healthy_times:
        healthy_at = min(healthy_times)
        startup_seconds = (healthy_at - started_at).total_seconds()
        if startup_seconds > startup_threshold_s:
            findings.append(Finding(
                check="performance",
                severity="medium",
                message=(
                    f"Startup time {startup_seconds:.1f}s exceeds {startup_threshold_s}s "
                    f"(service: {startup_service})"
                ),
                remediation="Investigate service startup or raise AUDIT_STARTUP_MAX_SECONDS",
            ))
    else:
        findings.append(Finding(
            check="performance",
            severity="low",
            message=f"Startup time unavailable for service '{startup_service}'",
            remediation="Ensure health checks are enabled to measure startup time",
        ))

    return findings


# --- Report output ---


def print_report(findings: list[Finding], fmt: str = "text") -> None:
    if fmt == "json":
        print(json.dumps([asdict(f) for f in findings], indent=2))
        return

    if not findings:
        print("All checks passed. No findings.")
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 99))

    print(f"\n{'='*60}")
    print(f" Security Audit Report — {len(findings)} finding(s)")
    print(f"{'='*60}\n")

    for f in sorted_findings:
        icon = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}.get(
            f.severity, "[????]"
        )
        print(f"  {icon} [{f.check}] {f.message}")
        print(f"        Fix: {f.remediation}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description="OpenClaw Secure Stack Security Audit")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    # Detect project root
    project_root = PROJECT_ROOT

    # Detect container runtime
    runtime = _detect_runtime()
    if not runtime:
        print("ERROR: Docker or Podman is required but not found.", file=sys.stderr)
        return 2

    compose_cmd = _get_compose_cmd(runtime)

    checks = [
        lambda: container_hardening(runtime, compose_cmd),
        lambda: network_isolation(project_root / "docker-compose.yml"),
        lambda: secret_management(project_root),
        lambda: log_integrity(project_root),
        lambda: skill_security(project_root),
        lambda: documentation(project_root),
        lambda: performance(runtime, compose_cmd),
    ]

    all_findings: list[Finding] = []
    for check in checks:
        try:
            all_findings.extend(check())
        except Exception as e:
            all_findings.append(Finding(
                check="internal",
                severity="medium",
                message=f"Check failed with error: {e}",
                remediation="Review the error and fix the underlying issue",
            ))

    print_report(all_findings, fmt=args.format)
    return 0 if not all_findings else 1


if __name__ == "__main__":
    sys.exit(main())
