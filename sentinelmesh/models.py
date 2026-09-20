from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat()


def from_iso(raw: str) -> datetime:
    return datetime.fromisoformat(raw)


class EventType(StrEnum):
    CONNECTION_OPENED = "connection_opened"
    CONNECTION_CLOSED = "connection_closed"
    COMMAND_OBSERVED = "command_observed"
    PROFILE_CREATED = "profile_created"
    INTEL_CORRELATED = "intel_correlated"
    REPORT_GENERATED = "report_generated"


@dataclass(slots=True)
class ObservedCommand:
    session_id: str
    command: str
    observed_at: datetime

    def to_record(self) -> dict[str, str]:
        return {
            "session_id": self.session_id,
            "command": self.command,
            "observed_at": to_iso(self.observed_at),
        }


@dataclass(slots=True)
class ThreatIntelHit:
    provider: str
    summary: str
    confidence: float
    labels: list[str] = field(default_factory=list)
    reference_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AttackSession:
    session_id: str
    service: str
    remote_ip: str
    remote_port: int
    local_port: int
    started_at: datetime
    ended_at: datetime | None = None
    bytes_received: int = 0
    bytes_sent: int = 0
    credentials: dict[str, str] = field(default_factory=dict)
    command_history: list[str] = field(default_factory=list)
    message_samples: list[str] = field(default_factory=list)
    threat_id: str | None = None
    threat_score: float = 0.0
    tags: list[str] = field(default_factory=list)

    def to_record(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "service": self.service,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "local_port": self.local_port,
            "started_at": to_iso(self.started_at),
            "ended_at": to_iso(self.ended_at) if self.ended_at else None,
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "credentials": json.dumps(self.credentials),
            "command_history": json.dumps(self.command_history),
            "message_samples": json.dumps(self.message_samples),
            "threat_id": self.threat_id,
            "threat_score": self.threat_score,
            "tags": json.dumps(self.tags),
        }

    @classmethod
    def from_record(cls, row: dict[str, Any]) -> AttackSession:
        ended_at = row["ended_at"]
        return cls(
            session_id=row["session_id"],
            service=row["service"],
            remote_ip=row["remote_ip"],
            remote_port=int(row["remote_port"]),
            local_port=int(row["local_port"]),
            started_at=from_iso(row["started_at"]),
            ended_at=from_iso(ended_at) if ended_at else None,
            bytes_received=int(row["bytes_received"]),
            bytes_sent=int(row["bytes_sent"]),
            credentials=json.loads(row["credentials"] or "{}"),
            command_history=json.loads(row["command_history"] or "[]"),
            message_samples=json.loads(row["message_samples"] or "[]"),
            threat_id=row["threat_id"],
            threat_score=float(row["threat_score"]),
            tags=json.loads(row["tags"] or "[]"),
        )


@dataclass(slots=True)
class AttackerProfile:
    threat_id: str
    remote_ip: str
    tool_guess: str
    command_count: int
    avg_entropy: float
    cadence_ms: float
    risk_score: float
    first_seen: datetime
    last_seen: datetime
    cluster_id: str | None = None
    geo: str | None = None
    labels: list[str] = field(default_factory=list)

    def to_record(self) -> dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "remote_ip": self.remote_ip,
            "tool_guess": self.tool_guess,
            "command_count": self.command_count,
            "avg_entropy": self.avg_entropy,
            "cadence_ms": self.cadence_ms,
            "risk_score": self.risk_score,
            "first_seen": to_iso(self.first_seen),
            "last_seen": to_iso(self.last_seen),
            "cluster_id": self.cluster_id,
            "geo": self.geo,
            "labels": json.dumps(self.labels),
        }

    @classmethod
    def from_record(cls, row: dict[str, Any]) -> AttackerProfile:
        return cls(
            threat_id=row["threat_id"],
            remote_ip=row["remote_ip"],
            tool_guess=row["tool_guess"],
            command_count=int(row["command_count"]),
            avg_entropy=float(row["avg_entropy"]),
            cadence_ms=float(row["cadence_ms"]),
            risk_score=float(row["risk_score"]),
            first_seen=from_iso(row["first_seen"]),
            last_seen=from_iso(row["last_seen"]),
            cluster_id=row["cluster_id"],
            geo=row["geo"],
            labels=json.loads(row["labels"] or "[]"),
        )


@dataclass(slots=True)
class EventRecord:
    event_type: EventType
    occurred_at: datetime
    session_id: str | None
    payload: dict[str, Any]

    def to_record(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "occurred_at": to_iso(self.occurred_at),
            "session_id": self.session_id,
            "payload": json.dumps(self.payload),
        }
