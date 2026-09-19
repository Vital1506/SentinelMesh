from sentinelmesh.models import AttackSession, AttackerProfile, ThreatIntelHit, utc_now
from sentinelmesh.reporter import ReportGenerator
from sentinelmesh.storage import EventStore


def test_storage_and_report_generation(tmp_path):
    store = EventStore(tmp_path / "sentinelmesh.db")
    reports = ReportGenerator(tmp_path / "reports")
    now = utc_now()

    session = AttackSession(
        session_id="sess-1",
        service="http",
        remote_ip="198.51.100.20",
        remote_port=12345,
        local_port=8080,
        started_at=now,
        command_history=["GET / HTTP/1.1"],
    )
    profile = AttackerProfile(
        threat_id="b" * 64,
        remote_ip="198.51.100.20",
        tool_guess="automated-http-client",
        command_count=1,
        avg_entropy=1.5,
        cadence_ms=0.0,
        risk_score=18.0,
        first_seen=now,
        last_seen=now,
        labels=["automated-http-client"],
    )
    store.upsert_session(session)
    store.save_profile(profile)

    saved = store.get_session("sess-1")
    assert saved is not None
    assert saved.remote_ip == "198.51.100.20"

    bundle = {"type": "bundle", "id": "bundle--1", "objects": []}
    json_report = reports.write_json("sample", session, profile, [ThreatIntelHit("OTX", "hit", 0.6)], bundle)

    assert json_report.exists()
