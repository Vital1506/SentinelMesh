#!/usr/bin/env bash
#
# SentinelMesh store wipe wrapper.
# Example:
#   ./scripts/wipe_store.sh --before 2026-01-01T00:00:00
#   ./scripts/wipe_store.sh --before 2026-01-01T00:00:00 --include-profiles --stdout
#
# This removes sessions, commands, events, and optionally profiles older than the
# given timestamp. Back up anything you want to keep before running this in
# production.
set -euo pipefail

SENTINELMESH="${SENTINELMESH_PYTHON:-python -m sentinelmesh}"

exec "$SENTINELMESH" wipe "$@"
