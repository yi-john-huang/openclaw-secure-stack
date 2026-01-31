"""Quarantine manager — lifecycle management for flagged skills."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from src.audit.logger import AuditLogger
from src.models import (
    AuditEvent,
    AuditEventType,
    QuarantinedSkill,
    RiskLevel,
    ScanFinding,
    ScanReport,
)
from src.quarantine.db import QuarantineDB
from src.scanner.scanner import SkillScanner


class QuarantineManager:
    """Manages quarantine, override, and re-scan of flagged skills."""

    def __init__(
        self,
        db_path: str,
        quarantine_dir: str,
        scanner: SkillScanner,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.db = QuarantineDB(db_path)
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.scanner = scanner
        self.audit_logger = audit_logger

    def quarantine(self, skill_path: str, report: ScanReport) -> None:
        src = Path(skill_path)
        dest = self.quarantine_dir / src.name
        shutil.move(str(src), str(dest))

        findings_json = json.dumps([f.model_dump() for f in report.findings])
        self.db.upsert_skill(
            name=report.skill_name,
            path=str(dest),
            checksum=report.checksum,
            status="quarantined",
            findings_json=findings_json,
            last_scanned=report.scanned_at,
        )

        if self.audit_logger:
            self.audit_logger.log(AuditEvent(
                event_type=AuditEventType.SKILL_QUARANTINE,
                action=f"quarantine:{report.skill_name}",
                result="success",
                risk_level=RiskLevel.HIGH,
                details={"skill_name": report.skill_name, "findings": len(report.findings)},
            ))

    def is_quarantined(self, skill_name: str) -> bool:
        skill = self.db.get_skill(skill_name)
        return skill is not None and skill["status"] == "quarantined"

    def force_override(self, skill_name: str, user_id: str, ack: str) -> None:
        now = datetime.now(UTC).isoformat()
        self.db.update_status(
            skill_name, "overridden",
            override_user=user_id,
            override_ack=ack,
            override_at=now,
        )

        if self.audit_logger:
            self.audit_logger.log(AuditEvent(
                event_type=AuditEventType.SKILL_OVERRIDE,
                action=f"override:{skill_name}",
                user_id=user_id,
                result="success",
                risk_level=RiskLevel.CRITICAL,
                details={"skill_name": skill_name, "ack": ack},
            ))

    def get_quarantined(self) -> list[QuarantinedSkill]:
        quarantined = self.db.list_by_status("quarantined")
        overridden = self.db.list_by_status("overridden")
        result = []
        for row in quarantined + overridden:
            raw = json.loads(str(row["findings_json"]))
            findings = [ScanFinding.model_validate(f) for f in raw]
            is_overridden = row["status"] == "overridden"
            result.append(QuarantinedSkill(
                name=str(row["name"]),
                original_path=str(row["path"]),
                quarantined_at=str(row.get("last_scanned", "")),
                reason=f"{len(findings)} finding(s) detected",
                findings=findings,
                overridden=is_overridden,
                overridden_by=str(row["override_user"]) if is_overridden else None,
                overridden_at=str(row["override_at"]) if is_overridden else None,
            ))
        return result

    def rescan(self, skill_name: str) -> ScanReport:
        skill = self.db.get_skill(skill_name)
        if skill is None:
            raise ValueError(f"Skill not found: {skill_name}")
        return self.scanner.scan(str(skill["path"]))
