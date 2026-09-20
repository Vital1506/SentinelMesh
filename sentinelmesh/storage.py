from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from sentinelmesh.models import (
    AttackerProfile,
    AttackSession,
    EventRecord,
    EventType,
    ObservedCommand,
)


class EventStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    service TEXT NOT NULL,
                    remote_ip TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    local_port INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    bytes_received INTEGER NOT NULL,
                    bytes_sent INTEGER NOT NULL,
                    credentials TEXT NOT NULL,
                    command_history TEXT NOT NULL,
                    message_samples TEXT NOT NULL,
                    threat_id TEXT,
                    threat_score REAL NOT NULL,
                    tags TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    observed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    session_id TEXT,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS profiles (
                    threat_id TEXT PRIMARY KEY,
                    remote_ip TEXT NOT NULL,
                    tool_guess TEXT NOT NULL,
                    command_count INTEGER NOT NULL,
                    avg_entropy REAL NOT NULL,
                    cadence_ms REAL NOT NULL,
                    risk_score REAL NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    cluster_id TEXT,
                    geo TEXT,
                    labels TEXT NOT NULL
                );
                """
            )

    def upsert_session(self, session: AttackSession) -> None:
        record = session.to_record()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO sessions (
                    session_id, service, remote_ip, remote_port, local_port, started_at, ended_at,
                    bytes_received, bytes_sent, credentials, command_history, message_samples,
                    threat_id, threat_score, tags
                ) VALUES (
                    :session_id, :service, :remote_ip, :remote_port, :local_port, :started_at,
                    :ended_at, :bytes_received, :bytes_sent, :credentials, :command_history,
                    :message_samples, :threat_id, :threat_score, :tags
                )
                ON CONFLICT(session_id) DO UPDATE SET
                    ended_at = excluded.ended_at,
                    bytes_received = excluded.bytes_received,
                    bytes_sent = excluded.bytes_sent,
                    credentials = excluded.credentials,
                    command_history = excluded.command_history,
                    message_samples = excluded.message_samples,
                    threat_id = excluded.threat_id,
                    threat_score = excluded.threat_score,
                    tags = excluded.tags
                """,
                record,
            )

    def append_command(self, command: ObservedCommand) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO commands(session_id, command, observed_at) VALUES (?, ?, ?)",
                (
                    command.session_id,
                    command.command,
                    command.to_record()["observed_at"],
                ),
            )

    def append_event(self, event: EventRecord) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO events(event_type, occurred_at, session_id, payload) VALUES (?, ?, ?, ?)",
                (
                    event.event_type.value,
                    event.to_record()["occurred_at"],
                    event.session_id,
                    json.dumps(event.payload),
                ),
            )

    def save_profile(self, profile: AttackerProfile) -> None:
        record = profile.to_record()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO profiles (
                    threat_id, remote_ip, tool_guess, command_count, avg_entropy, cadence_ms,
                    risk_score, first_seen, last_seen, cluster_id, geo, labels
                ) VALUES (
                    :threat_id, :remote_ip, :tool_guess, :command_count, :avg_entropy, :cadence_ms,
                    :risk_score, :first_seen, :last_seen, :cluster_id, :geo, :labels
                )
                ON CONFLICT(threat_id) DO UPDATE SET
                    remote_ip = excluded.remote_ip,
                    tool_guess = excluded.tool_guess,
                    command_count = excluded.command_count,
                    avg_entropy = excluded.avg_entropy,
                    cadence_ms = excluded.cadence_ms,
                    risk_score = excluded.risk_score,
                    first_seen = excluded.first_seen,
                    last_seen = excluded.last_seen,
                    cluster_id = excluded.cluster_id,
                    geo = excluded.geo,
                    labels = excluded.labels
                """,
                record,
            )

    def get_session(self, session_id: str) -> AttackSession | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        return AttackSession.from_record(dict(row))

    def delete_session(self, session_id: str) -> bool:
        with self._lock, self._connect() as connection:
            cur = connection.execute(
                "DELETE FROM sessions WHERE session_id = ?",
                (session_id,),
            )
            return int(cur.rowcount) > 0

    def list_recent_sessions(self, limit: int = 25) -> list[AttackSession]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [AttackSession.from_record(dict(row)) for row in rows]

    def list_profiles(self, limit: int = 50) -> list[AttackerProfile]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM profiles ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [AttackerProfile.from_record(dict(row)) for row in rows]

    def list_commands_for_session(self, session_id: str) -> list[ObservedCommand]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT session_id, command, observed_at
                FROM commands
                WHERE session_id = ?
                ORDER BY observed_at ASC
                """,
                (session_id,),
            ).fetchall()
        return [
            ObservedCommand(
                session_id=row["session_id"],
                command=row["command"],
                observed_at=sqlite3_datetime(row["observed_at"]),
            )
            for row in rows
        ]

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT event_type, occurred_at, session_id, payload FROM events ORDER BY occurred_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "event_type": row["event_type"],
                "occurred_at": row["occurred_at"],
                "session_id": row["session_id"],
                "payload": json.loads(row["payload"] or "{}"),
            }
            for row in rows
        ]

    def count_active_sessions(self) -> int:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM sessions WHERE ended_at IS NULL",
            ).fetchone()
        if row is None:
            return 0
        return int(row["total"])

    def dashboard_metrics(self) -> dict[str, Any]:
        with self._lock, self._connect() as connection:
            totals = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_sessions,
                    COUNT(DISTINCT remote_ip) AS distinct_sources,
                    COALESCE(AVG(threat_score), 0) AS avg_risk_score,
                    COALESCE(SUM(CASE WHEN threat_score >= 85 THEN 1 ELSE 0 END), 0) AS critical_sessions,
                    COALESCE(SUM(CASE WHEN threat_score >= 70 THEN 1 ELSE 0 END), 0) AS high_risk_sessions,
                    COALESCE(SUM(CASE WHEN threat_score >= 40 AND threat_score < 70 THEN 1 ELSE 0 END), 0) AS medium_risk_sessions,
                    COALESCE(SUM(CASE WHEN threat_score > 0 AND threat_score < 40 THEN 1 ELSE 0 END), 0) AS low_risk_sessions,
                    COALESCE(SUM(bytes_received), 0) AS bytes_received,
                    COALESCE(SUM(bytes_sent), 0) AS bytes_sent
                FROM sessions
                """
            ).fetchone()
            profile_row = connection.execute(
                "SELECT COUNT(*) AS total_profiles FROM profiles",
            ).fetchone()
            report_row = connection.execute(
                "SELECT COUNT(*) AS report_count FROM events WHERE event_type = ?",
                (EventType.REPORT_GENERATED.value,),
            ).fetchone()
            service_rows = connection.execute(
                """
                SELECT service, COUNT(*) AS total
                FROM sessions
                GROUP BY service
                ORDER BY total DESC, service ASC
                """
            ).fetchall()
            source_rows = connection.execute(
                """
                SELECT remote_ip, COUNT(*) AS total
                FROM sessions
                GROUP BY remote_ip
                ORDER BY total DESC, remote_ip ASC
                LIMIT 5
                """
            ).fetchall()
            command_rows = connection.execute(
                """
                SELECT command, COUNT(*) AS total
                FROM commands
                GROUP BY command
                ORDER BY total DESC, command ASC
                LIMIT 8
                """
            ).fetchall()
            profile_rows = connection.execute(
                """
                SELECT threat_id, remote_ip, tool_guess, risk_score, cluster_id, labels
                FROM profiles
                ORDER BY risk_score DESC, last_seen DESC
                LIMIT 6
                """
            ).fetchall()
        total_sessions = int(totals["total_sessions"]) if totals else 0
        max_service_total = max((int(row["total"]) for row in service_rows), default=1)
        max_source_total = max((int(row["total"]) for row in source_rows), default=1)
        max_command_total = max((int(row["total"]) for row in command_rows), default=1)
        return {
            "total_sessions": total_sessions,
            "total_profiles": int(profile_row["total_profiles"]) if profile_row else 0,
            "report_count": int(report_row["report_count"]) if report_row else 0,
            "distinct_sources": int(totals["distinct_sources"]) if totals else 0,
            "avg_risk_score": round(float(totals["avg_risk_score"]), 1) if totals else 0.0,
            "critical_sessions": int(totals["critical_sessions"]) if totals else 0,
            "high_risk_sessions": int(totals["high_risk_sessions"]) if totals else 0,
            "medium_risk_sessions": int(totals["medium_risk_sessions"]) if totals else 0,
            "low_risk_sessions": int(totals["low_risk_sessions"]) if totals else 0,
            "bytes_received": int(totals["bytes_received"]) if totals else 0,
            "bytes_sent": int(totals["bytes_sent"]) if totals else 0,
            "service_breakdown": [
                {
                    "service": row["service"],
                    "total": int(row["total"]),
                    "percentage": int((int(row["total"]) / total_sessions) * 100) if total_sessions else 0,
                    "intensity": int((int(row["total"]) / max_service_total) * 100) if max_service_total else 0,
                }
                for row in service_rows
            ],
            "top_sources": [
                {
                    "remote_ip": row["remote_ip"],
                    "total": int(row["total"]),
                    "intensity": int((int(row["total"]) / max_source_total) * 100) if max_source_total else 0,
                }
                for row in source_rows
            ],
            "top_commands": [
                {
                    "command": row["command"],
                    "total": int(row["total"]),
                    "intensity": int((int(row["total"]) / max_command_total) * 100) if max_command_total else 0,
                }
                for row in command_rows
            ],
            "top_profiles": [
                {
                    "threat_id": row["threat_id"],
                    "remote_ip": row["remote_ip"],
                    "tool_guess": row["tool_guess"],
                    "risk_score": round(float(row["risk_score"]), 1),
                    "cluster_id": row["cluster_id"],
                    "labels": json.loads(row["labels"] or "[]"),
                }
                for row in profile_rows
            ],
        }


def sqlite3_datetime(raw: str) -> Any:
    from sentinelmesh.models import from_iso

    return from_iso(raw)
