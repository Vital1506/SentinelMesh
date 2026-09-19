# Windows Deployment Guide

This guide assumes you want to deploy SentinelMesh on a Windows 10 or Windows 11 machine for demonstration, lab testing, or portfolio review.

## Recommended Deployment Mode

Use Docker Desktop if you want the cleanest and most repeatable deployment.

Use native Python only if you want easier local code editing and debugging.

The upgraded console exposes:

- `http://127.0.0.1:8000/` for the analyst dashboard
- `http://127.0.0.1:8000/healthz` for liveness
- `http://127.0.0.1:8000/readyz` for readiness

## Prerequisites

### Docker path

1. Install Docker Desktop.
2. Make sure Linux containers are enabled.
3. Restart the machine if Docker asks for it.

### Native Python path

1. Install Python 3.11.
2. Install Git.
3. Open PowerShell as a normal user.

## Native Python Deployment

1. Open PowerShell or Command Prompt in the project root:

```text
cd C:\Users\vital\Documents\Codex\2026-04-20-files-mentioned-by-the-user-sentinelmesh
```

2. Create the virtual environment.

If you are using PowerShell:

```powershell
python -m venv .venv
```

3. Allow script execution for the current session if PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

4. Activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

If you are using Command Prompt instead, use:

```bat
python -m venv .venv
call .venv\Scripts\activate.bat
```

5. Install SentinelMesh:

```powershell
python -m pip install --upgrade pip
python -m pip install -e .[dev,intel,analytics,ssh]
```

Or, from `cmd.exe`, run the helper script:

```bat
scripts\setup_windows.cmd
```

6. Create your environment file:

```powershell
Copy-Item .env.example .env
```

7. Start the platform:

```powershell
python -m sentinelmesh serve
```

Before going live, you can also run:

```powershell
python -m sentinelmesh doctor
```

8. Validate the dashboard:

```text
http://127.0.0.1:8000
```

You can also validate health and readiness:

```powershell
curl http://127.0.0.1:8000/healthz
curl http://127.0.0.1:8000/readyz
```

9. Test the decoy services from another terminal:

```powershell
curl http://127.0.0.1:8080/
```

```powershell
Test-NetConnection 127.0.0.1 -Port 2222
```

## Docker Desktop Deployment

1. Open PowerShell in the project root.
2. Create the environment file:

```powershell
Copy-Item .env.example .env
```

3. Build and launch:

```powershell
docker compose -f .\deploy\docker-compose.yml up --build -d
```

4. Open the dashboard at `http://127.0.0.1:8000`.
5. Review reports under the local `reports` folder.
6. Run `docker compose -f .\deploy\docker-compose.yml exec sentinelmesh python -m sentinelmesh doctor` if you want an in-container readiness check.
7. Stop the deployment when needed:

```powershell
docker compose -f .\deploy\docker-compose.yml down
```

## Make It Start Automatically on Boot

1. Deploy with native Python first and confirm `.venv` exists.
2. Run the startup task registration script:

```powershell
.\scripts\register_startup_task.ps1
```

3. Open Task Scheduler and confirm the `SentinelMesh` task exists.

## Troubleshooting

- If port `8000` is already in use, change `SENTINELMESH_DASHBOARD_PORT` in `.env`.
- If `asyncssh` is missing, SentinelMesh will fall back to a pseudo-SSH decoy instead of a full SSH handshake.
- If antivirus blocks listening sockets, add the project folder to your lab allow-list or use Docker Desktop.
- If PowerShell blocks scripts, use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.
- If CTI enrichment is not appearing, run `python -m sentinelmesh doctor` and confirm the provider keys show as configured.

## Safe Deployment Advice

- Expose SentinelMesh only from an isolated VM or test host.
- Do not run it on a workstation that contains personal accounts, browsers, or sensitive data.
- Keep the dashboard port private when possible.
