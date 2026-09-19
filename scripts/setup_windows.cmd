@echo off
setlocal

if not exist ".venv" (
    python -m venv .venv
)

call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -e .[dev,intel,analytics,ssh]

if not exist ".env" (
    copy .env.example .env >nul
)

python -m sentinelmesh doctor
echo.
echo Start SentinelMesh with:
echo python -m sentinelmesh serve
