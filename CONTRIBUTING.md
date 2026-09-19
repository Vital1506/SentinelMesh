# Contributing

## Development Setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .[dev,intel,analytics,ssh]
pre-commit install
```

## Workflow

1. Create a branch from `main`.
2. Run `python -m pytest`.
3. Run `python -m ruff check .`.
4. Run `python -m mypy sentinelmesh`.
5. Submit a pull request with a short summary and test evidence.

## Coding Standards

- Python 3.11+
- Type hints throughout
- Small composable functions
- Security-first defaults
- Defensive logging, never credential replay
