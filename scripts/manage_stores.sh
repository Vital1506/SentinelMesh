#!/usr/bin/env bash
#
# SentinelMesh store-management wrapper.
# Examples:
#   ./scripts/manage_stores.sh wipe --before 2026-01-01T00:00:00
#   ./scripts/manage_stores.sh wipe --before 2026-01-01T00:00:00 --include-profiles --stdout
#   ./scripts/manage_stores.sh export-sessions
#   ./scripts/manage_stores.sh archive-recent
#   ./scripts/manage_stores.sh stats
#
# This is a convenience wrapper. You can also invoke the commands directly with:
#   python -m sentinelmesh wip ...   (note: the package uses `wipe`, not `wip`)
set -euo pipefail

SENTINELMESH="${SENTINELMESH_PYTHON:-python -m sentinelmesh}"

exec "$SENTINELMESH" "$@"
