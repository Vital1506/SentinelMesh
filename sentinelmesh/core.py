from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

CREDENTIAL_LIKE_PATTERN = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|apikey|api-key|auth)[=:\s]+(.+)"
)


def scrub_sensitive_text(text: str) -> str:
    """Replace credential-like fragments in diagnostic text before logging or
    exporting it to a human-readable report.

    This is a best-effort scrubber. Do not rely on it for strong sanitization
    of high-sensitivity material; keep sensitive storage and transport controls
    elsewhere in the platform.
    """
    if not text:
        return text

    def _replacer(match: re.Match[str]) -> str:
        value = match.group(2)
        masked = value if len(value) < 4 else f"{value[:1]}...{value[-2:]}"
        return f"{match.group(1)}={masked}"

    return CREDENTIAL_LIKE_PATTERN.sub(_replacer, text)


def safe_export_payload(session: Any, profile: Any, events: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a scrubbed export payload for a session and its profile.

    Sensitive fields are masked before serialization so exports can be moved
    around without exposing raw credentials in plain text.
    """
    credentials: dict[str, str] = getattr(session, "credentials", {}) or {}
    scrubbed_credentials = {
        key: (value if len(value) < 4 else f"{value[:1]}...{value[-2:]}")
        for key, value in credentials.items()
    }  # do not reuse the original secret dict outside the export payload

    started = getattr(session, "started_at", None)
    ended = getattr(session, "ended_at", None)

    return {
        "session_id": getattr(session, "session_id", None),
        "service": getattr(session, "service", None),
        "remote_ip": getattr(session, "remote_ip", None),
        "remote_port": getattr(session, "remote_port", None),
        "local_port": getattr(session, "local_port", None),
        "started_at": started.isoformat() if started else None,
        "ended_at": ended.isoformat() if ended else None,
        "bytes_received": getattr(session, "bytes_received", 0),
        "bytes_sent": getattr(session, "bytes_sent", 0),
        "credentials": json.dumps(scrubbed_credentials),
        "command_count": len(getattr(session, "command_history", []) or []),
        "message_sample_count": len(getattr(session, "message_samples", []) or []),
        "threat_id": getattr(profile, "threat_id", None),
        "tool_guess": getattr(profile, "tool_guess", None),
        "risk_score": getattr(profile, "risk_score", None),
        "labels": getattr(profile, "labels", []) or [],
        "events": _scrub_event_payloads(events),
    }


def _scrub_event_payloads(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for event in events:
        payload = event.get("payload") or {}
        scrubbed_payload = {
            key: (
                value
                if not isinstance(value, str)
                or len(value) < 4
                else f"{value[:1]}...{value[-2:]}"
            )
            for key, value in payload.items()
        }
        out.append(
            {
                "event_type": event.get("event_type"),
                "occurred_at": event.get("occurred_at"),
                "session_id": event.get("session_id"),
                "payload_text": json.dumps(scrubbed_payload, sort_keys=True),
            }
        )
    return out


def export_filename_stem(session_id: str, service: str, now: Any) -> str:
    ts = getattr(now, "strftime", None)
    timestamp = ts("%Y%m%dT%H%M%S") if ts else "unknown"
    digest_full = hashlib.sha256(f"{session_id}{service}{timestamp}".encode()).hexdigest()
    return f"{timestamp}_{service}_{session_id}_{digest_full}"


def write_json_export(target_dir: Path, filename_stem: str, payload: dict[str, Any]) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{filename_stem}.json"
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return target


def write_archive_index(target_dir: Path, entries: list[dict[str, Any]]) -> Path:
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "archive_index.json"
    ordered = sorted(entries, key=lambda item: item.get("filename", ""))
    target.write_text(json.dumps(ordered, indent=2, sort_keys=True), encoding="utf-8")
    return target


def prune_records_older_than(
    database_path: Path,
    before_iso: str,
    *,
    include_sessions: bool = True,
    include_commands: bool = True,
    include_events: bool = True,
    include_profiles: bool = False,
) -> dict[str, int]:
    """Remove old records from the local SQLite store.

    This is the safe in-app wipe path. For bulk archival or compliance removal,
    use the CLI ``wipe`` command which also rebuilds indexes and reports counts.
    """
    import sqlite3

    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(database_path))
    connection.row_factory = sqlite3.Row

    deleted: dict[str, int] = {}
    try:
        if include_sessions:
            cur = connection.execute("DELETE FROM sessions WHERE started_at < ?", (before_iso,))
            deleted["sessions"] = int(cur.rowcount)

        if include_commands:
            cur = connection.execute("DELETE FROM commands WHERE observed_at < ?", (before_iso,))
            deleted["commands"] = int(cur.rowcount)

        if include_events:
            cur = connection.execute("DELETE FROM events WHERE occurred_at < ?", (before_iso,))
            deleted["events"] = int(cur.rowcount)

        if include_profiles:
            cur = connection.execute("DELETE FROM profiles WHERE first_seen < ?", (before_iso,))
            deleted["profiles"] = int(cur.rowcount)

        connection.commit()
    finally:
        connection.close()

    return deleted
