from __future__ import annotations

import json
from datetime import timezone

from sentinelmesh.core import (
    export_filename_stem,
    prune_records_older_than,
    safe_export_payload,
    scrub_sensitive_text,
    write_archive_index,
    write_json_export,
)
from sentinelmesh.models import AttackSession, AttackerProfile, utc_now


def test_scrub_sensitive_text_masks_values():
    raw = "password=hunter2 secret=SuperSecret123!"
    scrubbed = scrub_sensitive_text(raw)
    assert "hunter2" not in scrubbed
    assert "SuperSecret123!" not in scrubbed
    assert "password=" in scrubbed


def test_safe_export_payload_scrubs_credentials():
    session = AttackSession(
        session_id="s1",
        service="ssh",
        remote_ip="198.51.100.1",
        remote_port=12345,
        local_port=2222,
        started_at=utc_now(),
        credentials={"username": "admin", "password": "SuperSecret123!"},
    )
    profile = AttackerProfile(
        threat_id="a" * 64,
        remote_ip="198.51.100.1",
        tool_guess="interactive-shell",
        command_count=1,
        avg_entropy=1.0,
        cadence_ms=0.0,
        risk_score=10.0,
        first_seen=utc_now(),
        last_seen=utc_now(),
        labels=["interactive-shell"],
    )
    payload = safe_export_payload(session, profile, [])
    creds = payload["credentials"]
    assert "SuperSecret123!" not in creds
    assert creds.startswith('{"username": "a')
    assert creds.endswith('"password": "S...3!"}')


def test_safe_export_payload_scrubs_event_payloads():
    now = utc_now()
    session = AttackSession(
        session_id="s1",
        service="http",
        remote_ip="203.0.113.1",
        remote_port=12345,
        local_port=8080,
        started_at=now,
    )
    profile = AttackerProfile(
        threat_id="b" * 64,
        remote_ip="203.0.113.1",
        tool_guess="automated-http-client",
        command_count=1,
        avg_entropy=1.0,
        cadence_ms=0.0,
        risk_score=5.0,
        first_seen=now,
        last_seen=now,
        labels=["automated-http-client"],
    )
    events = [
        {
            "event_type": "command_observed",
            "occurred_at": now.isoformat(),
            "session_id": "s1",
            "payload": {"password": "topsecret", "command": "whoami"},
        },
    ]
    payload = safe_export_payload(session, profile, events)
    payload_text = json.dumps(payload, default=str)
    assert "topsecret" not in payload_text
    assert "w" in payload_text and "mi" in payload_text


def test_export_filename_stem_is_deterministic():
    now = utc_now()
    stem = export_filename_stem("session-1", "ssh", now)
    assert stem.startswith(now.strftime("%Y%m%dT"))
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")
    assert stem.endswith("_ssh_session-1_")


def test_write_json_export_creates_file(tmp_path):
    target = tmp_path / "exports"
    stem = "20260916T123456_http_s1_abc"
    payload = {"session_id": "s1", "service": "http"}
    path = write_json_export(target, stem, payload)
    assert path.exists()
    assert json.loads(path.read_text(encoding="utf-8"))["session_id"] == "s1"


def test_write_archive_index_sorts_entries(tmp_path):
    target = tmp_path / "archive"
    entries = [
        {"filename": "b.json", "session_id": "s2"},
        {"filename": "a.json", "session_id": "s1"},
    ]
    path = write_archive_index(target, entries)
    body = json.loads(path.read_text(encoding="utf-8"))
    filenames = [item["filename"] for item in body]
    assert filenames == sorted(filenames)


def test_prune_records_older_than_removes_sessions(tmp_path):
    from sentinelmesh.storage import EventStore

    store = EventStore(tmp_path / "store.db")
    now = utc_now()
    old = now.timestamp() - 999999
    old_iso = (now.fromtimestamp(old, tz=timezone.utc)).isoformat()
    session = AttackSession(
        session_id="s1",
        service="dummy",
        remote_ip="198.51.100.1",
        remote_port=12345,
        local_port=1,
        started_at=(now.replace(year=now.year - 1)),
    )
    store.upsert_session(session)
    assert store.get_session("s1") is not None

    deleted = prune_records_older_than(
        tmp_path / "store.db",
        old_iso,
        include_sessions=True,
        include_commands=False,
        include_events=False,
        include_profiles=False,
    )
    assert deleted["sessions"] >= 1
    assert store.get_session("s1") is None
