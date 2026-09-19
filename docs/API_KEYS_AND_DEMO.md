# API Keys, Telemetry, Export, And Demo Flow

## Configure Threat-Intel Providers And Telemetry Token

Copy `.env.example` to `.env` and fill in any providers you want to showcase:

```powershell
Copy-Item .env.example .env
notepad .env
```

Optional keys:

- `ALIENVAULT_OTX_API_KEY`
- `ABUSEIPDB_API_KEY`
- `SHODAN_API_KEY`
- `VT_API_KEY`

Set a telemetry token if you plan to query the JSON snapshot endpoint:

- `SENTINELMESH_TELEMETRY_TOKEN`

After editing `.env`, validate your setup:

```powershell
python -m sentinelmesh doctor
```

That command will show:

- which services are enabled
- whether the telemetry endpoint is bound safely
- whether each CTI provider is configured
- whether the model, database, and SSH host key exist

## CLI-First Operation

This version moved to CLI-first operation. There is no browser-based UI deliverable.
You can still use the telemetry endpoint for JSON snapshots and the new export commands
for session archives.

Common commands:

- `python -m sentinelmesh export-sessions`
- `python -m sentinelmesh archive-recent`
- `python -m sentinelmesh stats`
- `python -m sentinelmesh doctor --json`
- `python -m sentinelmesh wipe --before 2026-01-01T00:00:00`
- `python -m sentinelmesh wipe --before 2026-01-01T00:00:00 --include-profiles --stdout`
- `python -m sentinelmesh rotate-keys`
- `python -m sentinelmesh generate-keys`

Shell wrappers are available in `scripts/` for the most common export and wipe flows.

## Best Demo Order

1. Train the predictor:

```powershell
python -m sentinelmesh train --dataset .\sample_sequences.json
```

2. Start SentinelMesh:

```powershell
python -m sentinelmesh serve
```

3. Optional: query the telemetry endpoint with the configured token:

```powershell
curl -H "X-SentinelToken: $env:SENTINELMESH_TELEMETRY_TOKEN" http://127.0.0.1:8000/api/overview
```

4. In a second PowerShell window, generate local demo traffic:

```powershell
python .\scripts\demo_local.py
```

5. Review the state:

- `python -m sentinelmesh stats`
- `python -m sentinelmesh report`
- exported JSON archives in the `reports` folder

## Interview Talking Points

- The honeypot is intentionally isolated and telemetry access stays local by default.
- The `doctor` command makes deployment safer by surfacing exposure and missing-intelligence warnings before go-live.
- The demo script targets only localhost so it is presentation-safe and repeatable.
- Exports scrub credential-like material before writing JSON so archives can move more safely.
