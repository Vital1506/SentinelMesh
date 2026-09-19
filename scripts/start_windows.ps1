$ErrorActionPreference = "Stop"

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .[dev,intel,analytics,ssh]

if (-not (Test-Path ".env")) {
    Copy-Item .env.example .env
}

python -m sentinelmesh doctor
python -m sentinelmesh serve --log-level INFO
