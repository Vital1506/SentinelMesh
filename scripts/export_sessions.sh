#!/usr/bin/env bash
#
# SentinelMesh session export wrapper.
# Example:
#   ./scripts/export_sessions.sh export-sessions
#   ./scripts/export_sessions.sh archive-recent
#   ./scripts/export_sessions.sh stats
#
# This is a convenience wrapper. You can also run the commands directly with:
#   python -m sentinelmesh export-sessions
set -euo pipefail

SENTINELMESH="${SENTINELMESH_PYTHON:-python -m sentinelmesh}"
ACTION="${1:-}"

if [ -z "$ACTION" ]; then
  echo "Usage: $0 <export-sessions|archive-recent|stats>" >&2
  exit 1
fi

exec "$SENTINELMESH" "$ACTION"
