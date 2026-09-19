from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

from sentinelmesh.config import Settings
from sentinelmesh.storage import EventStore


def create_app(store: EventStore, settings: Settings, templates_dir: Path) -> Any:
    app = FastAPI(title="SentinelMesh Telemetry")

    token_header = APIKeyHeader(
        name=settings.telemetry_token_header, auto_error=False
    )

    def _require_token(request: Request) -> bool:
        if not settings.require_telemetry_auth:
            return True
        if not settings.telemetry_token:
            return False
        token = request.headers.get(settings.telemetry_token_header)
        if token is None:
            return False
        return token == settings.telemetry_token

    @app.get("/")
    async def index(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "instance_name": settings.instance_name,
                "environment_name": settings.environment_name,
                "notes": "SentinelMesh telemetry endpoint",
            }
        )

    @app.get("/api/overview")
    async def overview(request: Request) -> JSONResponse:
        if not _require_token(request):
            return JSONResponse(
                {"error": "unauthorized"},
                status_code=401,
            )
        metrics = store.dashboard_metrics()
        return JSONResponse(_safe_overview(store, settings, metrics))

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "instance_name": settings.instance_name,
                "environment_name": settings.environment_name,
                "dashboard_port": settings.dashboard_port,
            }
        )

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        ready = all(
            [
                settings.data_dir.exists(),
                settings.reports_dir.exists(),
                settings.model_dir.exists(),
                settings.database_path.parent.exists(),
                templates_dir.exists(),
            ]
        )
        return JSONResponse(
            {
                "status": "ready" if ready else "degraded",
                "database_path": str(settings.database_path),
                "templates_dir": str(templates_dir),
                "warnings": settings.deployment_warnings(),
            },
            status_code=200 if ready else 503,
        )

    return app


def _safe_overview(
    store: EventStore,
    settings: Settings,
    metrics: dict[str, Any],
) -> dict[str, Any]:
    profiles = store.list_profiles(20)
    sessions = store.list_recent_sessions(20)
    events = store.list_events(40)
    return {
        "active_sessions": store.count_active_sessions(),
        "metrics": metrics,
        "sessions": [session.to_record() for session in sessions],
        "profiles": [profile.to_record() for profile in profiles],
        "events": _decorate_events(events),
        "services": settings.service_status(),
        "providers": settings.intel_provider_status(),
        "provider_coverage": settings.intel_provider_coverage(),
        "warnings": settings.deployment_warnings(),
        "instance_name": settings.instance_name,
        "environment_name": settings.environment_name,
        "risk_bands": _risk_bands(metrics),
        "posture": _posture_summary(settings, metrics),
        "traffic_snapshot": _traffic_snapshot(metrics),
    }


def _decorate_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tone_map = {
        "connection_opened": "info",
        "connection_closed": "muted",
        "command_observed": "accent",
        "profile_created": "warn",
        "intel_correlated": "success",
        "report_generated": "success",
    }
    decorated: list[dict[str, Any]] = []
    for event in events:
        payload = event.get("payload", {})
        decorated.append(
            {
                **event,
                "payload_text": json.dumps(
                    payload, separators=(", ", ": "), sort_keys=True
                ),
                "tone": tone_map.get(event["event_type"], "info"),
            }
        )
    return decorated


def _risk_bands(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    total = max(int(metrics.get("total_sessions", 0)), 1)
    bands = [
        ("Critical", int(metrics.get("critical_sessions", 0)), "critical"),
        ("High", int(metrics.get("high_risk_sessions", 0)), "high"),
        ("Medium", int(metrics.get("medium_risk_sessions", 0)), "medium"),
        ("Low", int(metrics.get("low_risk_sessions", 0)), "low"),
    ]
    return [
        {
            "label": label,
            "value": value,
            "tone": tone,
            "percentage": int((value / total) * 100) if total else 0,
        }
        for label, value, tone in bands
    ]


def _posture_summary(settings: Settings, metrics: dict[str, Any]) -> dict[str, Any]:
    provider_coverage = settings.intel_provider_coverage()
    warnings = settings.deployment_warnings()
    score = 58
    score += provider_coverage["configured"] * 8
    score += 8 if settings.dashboard_host in {"127.0.0.1", "localhost"} else -4
    score += 8 if settings.environment_name.lower() in {
        "lab",
        "staging",
        "demo",
        "docker",
    } else 0
    score -= min(len(warnings) * 8, 20)
    score = max(32, min(score, 97))
    return {
        "readiness_score": score,
        "readiness_angle": int(score * 3.6),
        "coverage_percentage": provider_coverage["percentage"],
        "coverage_label": f"{provider_coverage['configured']}/"
        f"{provider_coverage['total']} CTI feeds configured",
        "exposure_label": "Private telemetry bind"
        if settings.dashboard_host in {"127.0.0.1", "localhost"}
        else "Network-reachable telemetry endpoint",
        "report_count": int(metrics.get("report_count", 0)),
        "telemetry_token_configured": bool(settings.telemetry_token),
    }


def _traffic_snapshot(metrics: dict[str, Any]) -> dict[str, str]:
    return {
        "received": _human_bytes(int(metrics.get("bytes_received", 0))),
        "sent": _human_bytes(int(metrics.get("bytes_sent", 0))),
        "avg_risk": f"{float(metrics.get('avg_risk_score', 0.0)):.1f}",
    }


def _human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{value} B"
