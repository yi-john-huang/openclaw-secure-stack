"""Click CLI for the skill scanner and quarantine system."""

from __future__ import annotations

import json

import click

from src.audit.logger import AuditLogger
from src.quarantine.manager import QuarantineManager
from src.scanner.scanner import SkillScanner, load_rules_from_file


@click.group()
@click.option("--rules", default="config/scanner-rules.json", help="Path to scanner rules JSON.")
@click.option("--db", default="data/quarantine.db", help="Quarantine database path.")
@click.option("--quarantine-dir", default="data/quarantine", help="Quarantine directory.")
@click.option("--audit-log", default=None, help="Audit log file path.")
@click.pass_context
def cli(
    ctx: click.Context, rules: str, db: str, quarantine_dir: str, audit_log: str | None,
) -> None:
    """OpenClaw skill scanner and quarantine CLI."""
    ctx.ensure_object(dict)
    audit_logger = AuditLogger(audit_log) if audit_log else None
    scanner_rules = load_rules_from_file(rules)
    ctx.obj["scanner"] = SkillScanner(rules=scanner_rules, audit_logger=audit_logger)
    ctx.obj["manager"] = QuarantineManager(
        db_path=db,
        quarantine_dir=quarantine_dir,
        scanner=ctx.obj["scanner"],
        audit_logger=audit_logger,
    )


@cli.command()
@click.argument("skill_path")
@click.option("--quarantine", is_flag=True, help="Auto-quarantine if findings detected.")
@click.pass_context
def scan(ctx: click.Context, skill_path: str, quarantine: bool) -> None:
    """Scan a skill file for malicious patterns."""
    scanner: SkillScanner = ctx.obj["scanner"]
    manager: QuarantineManager = ctx.obj["manager"]
    report = scanner.scan(skill_path)
    click.echo(report.model_dump_json(indent=2))
    if quarantine and report.findings:
        manager.quarantine(skill_path, report)
        click.echo(f"Skill quarantined: {report.skill_name}", err=True)


@cli.group("quarantine")
def quarantine_group() -> None:
    """Manage quarantined skills."""


@quarantine_group.command("list")
@click.pass_context
def quarantine_list(ctx: click.Context) -> None:
    """List quarantined skills."""
    manager: QuarantineManager = ctx.obj["manager"]
    items = manager.get_quarantined()
    output = [
        {"name": q.name, "quarantined_at": q.quarantined_at, "overridden": q.overridden}
        for q in items
    ]
    click.echo(json.dumps(output, indent=2))


@quarantine_group.command("override")
@click.argument("skill_name")
@click.option("--ack", required=True, help="Acknowledgment message accepting risk.")
@click.option("--user", default="cli-user", help="User performing the override.")
@click.pass_context
def quarantine_override(ctx: click.Context, skill_name: str, ack: str, user: str) -> None:
    """Override quarantine for a skill (requires --ack)."""
    manager: QuarantineManager = ctx.obj["manager"]
    manager.force_override(skill_name, user_id=user, ack=ack)
    click.echo(f"Override applied for: {skill_name}")
