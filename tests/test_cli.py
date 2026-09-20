from __future__ import annotations

from sentinelmesh.core import export_filename_stem
from sentinelmesh.models import utc_now


def test_export_filename_stem_is_deterministic(tmp_path, monkeypatch):
    now = utc_now()
    stems = set()
    for _ in range(3):
        monkeypatch.setattr("time.time", lambda: now.timestamp())
        stems.add(export_filename_stem("session-1", "ssh", now))
    assert len(stems) == 1
    stem = stems.pop()
    assert stem.startswith(now.strftime("%Y%m%dT"))
    # Stem format: {timestamp}_{service}_{session_id}_{sha256_digest}
    parts = stem.split("_")
    assert parts[1] == "ssh"
    assert parts[2] == "session-1"
    assert len(parts[3]) == 64  # SHA-256 hex digest
