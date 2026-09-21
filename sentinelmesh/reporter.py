from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sentinelmesh.models import AttackerProfile, AttackSession, ThreatIntelHit

logger = logging.getLogger(__name__)


class ReportGenerator:
    def __init__(self, reports_dir: Path) -> None:
        self.reports_dir = reports_dir
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def build_payload(
        self,
        session: AttackSession,
        profile: AttackerProfile,
        hits: list[ThreatIntelHit],
        stix_bundle: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "session": session.to_record(),
            "profile": profile.to_record(),
            "hits": [hit.to_dict() for hit in hits],
            "stix_bundle": stix_bundle,
        }

    def write_json(
        self,
        filename_stem: str,
        session: AttackSession,
        profile: AttackerProfile,
        hits: list[ThreatIntelHit],
        stix_bundle: dict[str, Any],
    ) -> Path:
        target = self.reports_dir / f"{filename_stem}.json"
        target.write_text(
            json.dumps(self.build_payload(session, profile, hits, stix_bundle), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return target

    def write_pdf(
        self,
        filename_stem: str,
        session: AttackSession,
        profile: AttackerProfile,
        hits: list[ThreatIntelHit],
    ) -> Path:
        target = self.reports_dir / f"{filename_stem}.pdf"
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas

            pdf = canvas.Canvas(str(target), pagesize=A4)
            y = 800
            intel_lines = [f" - {hit.provider}: {hit.summary}" for hit in hits]
            if not intel_lines:
                intel_lines = [" - No external intelligence hits"]
            lines = [
                "SentinelMesh Threat Intelligence Report",
                "",
                f"Threat ID: {profile.threat_id}",
                f"Remote IP: {profile.remote_ip}",
                f"Service: {session.service}",
                f"Risk Score: {profile.risk_score:.1f}",
                f"Tool Guess: {profile.tool_guess}",
                "",
                "Commands:",
                *[f" - {command}" for command in session.command_history[:20]],
                "",
                "Threat Intelligence:",
                *intel_lines,
            ]
            for line in lines:
                truncated = line[:110]
                pdf.drawString(40, y, truncated)
                y -= 16
                if y < 60:
                    pdf.showPage()
                    y = 800
            pdf.save()
        except (ImportError, OSError, ValueError) as exc:
            logger.warning("Falling back to text report for %s: %s", target, exc)
            target.write_text(
                "\n".join(
                    [
                        "SentinelMesh Threat Intelligence Report",
                        f"Threat ID: {profile.threat_id}",
                        f"Remote IP: {profile.remote_ip}",
                        f"Service: {session.service}",
                    ]
                ),
                encoding="utf-8",
            )
        return target

    def summarize_reports(self, after_iso: str | None = None) -> list[dict[str, Any]]:
        """List JSON report stems and metadata for recent reports.

        Use ``after_iso`` to restrict results to reports created after a timestamp.
        """
        files = sorted(self.reports_dir.glob("*.json"))
        result: list[dict[str, Any]] = []
        for file in files:
            try:
                payload = json.loads(file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping unreadable report %s: %s", file, exc)
                continue
            if after_iso and after_iso not in ("", None):
                session_start = payload.get("session", {}).get("started_at")
                if session_start and session_start < after_iso:
                    continue
            result.append(
                {
                    "filename": file.name,
                    "session_id": payload.get("session", {}).get("session_id"),
                    "service": payload.get("session", {}).get("service"),
                    "remote_ip": payload.get("session", {}).get("remote_ip"),
                }
            )
        return result
