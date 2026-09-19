#!/usr/bin/env bash
#
# SentinelMesh key and cache rotation helper.
# Use this to replace the SSH host key and clear transient runtime caches.
#
# This is a convenience wrapper. For production use, restrict who can run it,
# confirm the paths in your .env, and back up anything you want to keep.
set -euo pipefail

PYTHON="${PYTHON:-python}"
SENTINELMESH="${SENTINELMESH_PYTHON:-python -m sentinelmesh}"

echo "Rotating SentinelMesh SSH host key and clearing caches..."

# Rotate the host key through the package CLI so the runtime stays consistent.
"$SENTINELMESH" rotate-keys --retain-reports

echo "Done. Verify with:"
echo "  $SENTINELMESH doctor"
