#!/usr/bin/env bash
#
# SentinelMesh portable setup helper.
# Use this from a Linux/macOS terminal to create an isolated environment
# and run a quick health check before you deploy.
#
# This is a convenience wrapper, not a required part of the project.
set -euo pipefail

PYTHON="${PYTHON:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "ERROR: $PYTHON not found. Install Python 3.11+ and rerun." >&2
  exit 1
fi

if [ -d "$VENV_DIR" ]; then
  echo "Existing virtual environment found at $VENV_DIR."
  echo "To recreate it, delete $VENV_DIR and rerun."
else
  echo "Creating virtual environment at $VENV_DIR..."
  "$PYTHON" -m venv "$VENV_DIR"
fi

ACTIVATE="$VENV_DIR/bin/activate"
if [ ! -f "$ACTIVATE" ]; then
  echo "ERROR: Expected activation script at $ACTIVATE" >&2
  exit 1
fi

# shellcheck disable=SC1091
. "$ACTIVATE"

echo "Upgrading pip and installing SentinelMesh with development dependencies..."
"$PYTHON" -m pip install --quiet --upgrade pip
"$PYTHON" -m pip install --quiet -e .[dev,intel,analytics,ssh]

if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    echo "Copied .env.example to .env."
  else
    echo "WARNING: .env.example not found; skipping .env creation." >&2
  fi
fi

echo "Running deployment check..."
"$PYTHON" -m sentinelmesh doctor

echo "Setup complete."
echo "Start the platform with:"
echo "  source $VENV_DIR/bin/activate"
echo "  python -m sentinelmesh serve"
