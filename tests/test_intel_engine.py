from sentinelmesh.config import Settings
from sentinelmesh.intel_engine import ThreatIntelCorrelator
from sentinelmesh.models import AttackSession, AttackerProfile, ThreatIntelHit, utc_now


def test_stix_bundle_shape():
    now = utc_now()
    settings = Settings.from_env()
    correlator = ThreatIntelCorrelator(settings)
    session = AttackSession(
        session_id="sess-1",
        service="http",
        remote_ip="198.51.100.10",
        remote_port=54545,
        local_port=8080,
        started_at=now,
        ended_at=now,
    )
    profile = AttackerProfile(
        threat_id="a" * 64,
        remote_ip="198.51.100.10",
        tool_guess="nmap",
        command_count=1,
        avg_entropy=2.1,
        cadence_ms=0.0,
        risk_score=32.0,
        first_seen=now,
        last_seen=now,
        labels=["nmap"],
    )
    hits = [ThreatIntelHit(provider="OTX", summary="Test hit", confidence=0.5)]

    bundle = correlator.build_stix_bundle(session, profile, hits)

    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 4
