$ErrorActionPreference = "Stop"

if (-not (Test-Path ".venv")) {
    py -3.11 -m venv .venv
}

. .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e .[dev,intel,analytics,ssh]

if (-not (Test-Path ".env")) {
    Copy-Item .env.example .env
}

Write-Host "Training the local sequence model..."
python -m sentinelmesh train --dataset .\sample_sequences.json

Write-Host "Checking deployment readiness..."
python -m sentinelmesh doctor

Write-Host "Start SentinelMesh in a second PowerShell window with:"
Write-Host "python -m sentinelmesh serve"
Write-Host ""
Write-Host "When the dashboard is live, run:"
Write-Host "python .\scripts\demo_local.py"
