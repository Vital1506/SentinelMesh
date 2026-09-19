#!/usr/bin/env bash
set -euo pipefail

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .[dev,intel,analytics,ssh]
cp -n .env.example .env || true
python -m sentinelmesh serve
