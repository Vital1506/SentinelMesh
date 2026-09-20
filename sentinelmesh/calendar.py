from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def classify_age(started_at: Any) -> str:
    """Return a coarse age bucket for a session.

    This is used by the report and CLI views when summarizing recent activity.
    """
    if not isinstance(started_at, datetime):
        return "unknown"

    normalized = started_at.astimezone(UTC)
    now = datetime.now(UTC)
    delta = now - normalized

    seconds = delta.total_seconds()
    if seconds < 0:
        return "future"
    if seconds < 60:
        return "seconds"
    if seconds < 3600:
        return "minutes"
    if seconds < 86400:
        return "hours"
    if seconds < 604800:
        return "days"
    return "weeks"
