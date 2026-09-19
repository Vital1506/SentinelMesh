from pathlib import Path

from sentinelmesh.cli import _export_sessions, _archive_recent, _print_stats
from sentinelmesh.core import export_filename_stem, prune_records_older_than, safe_export_payload
from sentinelmesh.models import AttackSession, AttackerProfile, utc_now
from sentinelmesh.storage import EventStore
from sentinelmesh.config import Settings


def test_export_filename_stem_is_deterministic(tmp_path, monkeypatch):
    now = utc_now()
    stems = set()
    for _ in range(3):
        monkeypatch.setattr("time.time", lambda: now.timestamp())
        stems.add(export_filename_stem("session-1", "ssh", now))
    assert len(stems) == 1
    stem = stems.pop()
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
    assert any(stem.endswith(f"_ssh_session-1_{d}") for d in ("a", "b", "c", "d", "e", "f", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"))


def test_safe_export_payload_scrubs_credentials(tmp_path):
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


def test_export_sessions_writes_archives(tmp_path):
    store = EventStore(tmp_path / "store.db")
    reports = tmp_path / "reports"
    now = utc_now()
    session = AttackSession(
        session_id="s1",
        service="ssh",
        remote_ip="198.51.100.1",
        remote_port=12345,
        local_port=2222,
        started_at=now,
        command_history=["whoami", "pwd"],
    )
    store.upsert_session(session)
    store.append_command(
        __import__("sentinelmesh.models", fromlist=["ObservedCommand"]).ObservedCommand(
            "s1", "whoami", now
        )
    )

    _export_sessions(store, reports)
    exported = sorted(p.name for p in reports.glob("*.json"))
    assert 1 == len(exported)
    assert any(name.startswith(now.strftime("%Y%m%dT")) for name in exported)


def test_archive_recent_writes_index(tmp_path):
    store = EventStore(tmp_path / "store.db")
    reports = tmp_path / "reports"
    now = utc_now()
    session = AttackSession(
        session_id="s1",
        service="http",
        remote_ip="203.0.113.1",
        remote_port=12345,
        local_port=8080,
        started_at=now,
    )
    store.upsert_session(session)

    _archive_recent(store, reports)
    index = reports / "exports" / "archive_index.json"
    assert index.exists()
    body = index.read_text(encoding="utf-8")
    assert '"filename"' in body


def _make_test_settings(tmp_path: Path) -> Settings:
    return Settings(
        listen_host="127.0.0.1",
        http_port=8080,
        ftp_port=2121,
        smtp_port=2525,
        ssh_port=2222,
        dashboard_host="127.0.0.1",
        dashboard_port=8000,
        enable_http=True,
        enable_ftp=True,
        enable_smtp=True,
        enable_ssh=True,
        base_dir=tmp_path,
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        model_dir=tmp_path / "models",
        database_path=tmp_path / "store.db",
        host_key_path=tmp_path / "host_key",
        intel_cache_ttl_seconds=1800,
        abuseipdb_api_key=None,
        alienvault_otx_api_key=None,
        shodan_api_key=None,
        vt_api_key=None,
        hostname_seed="lab-host",
        instance_name="Test",
        environment_name="lab",
        dashboard_refresh_seconds=10,
        telemetry_token="",
        telemetry_token_header="X-SentinelToken",  # noqa: S106 - test helper credential header
        log_level=None,
        require_telemetry_auth=False,
    )


def test_print_stats_outputs_json_metrics(tmp_path, capsys):
    store = EventStore(tmp_path / "store.db")
    settings = _make_test_settings(tmp_path)
    _print_stats(store, settings)
    captured = capsys.readouterr().out
    assert "total_sessions" in captured


def test_prune_records_older_than_removes_rows(tmp_path):
    store = EventStore(tmp_path / "store.db")
    now = utc_now()
    old = now.timestamp() - 999999
    from datetime import timezone

    old_iso = (now.fromtimestamp(old, tz=timezone.utc)).isoformat()
    session = AttackSession(
        session_id="s1",
        service="dummy",
        remote_ip="198.51.100.1",
        remote_port=12345,
        local_port=1,
        started_at=utc_now().replace(year=now.year - 1),
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
