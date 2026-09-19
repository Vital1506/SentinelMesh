from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinelmesh.config import Settings


def build_report(settings: Settings) -> dict[str, Any]:
    provider_status = settings.intel_provider_status()
    provider_coverage = settings.intel_provider_coverage()
    report_files = sorted(settings.reports_dir.glob("*.json"))
    pdf_files = sorted(settings.reports_dir.glob("*.pdf"))
    return {
        "instance": {
            "name": settings.instance_name,
            "environment": settings.environment_name,
            "dashboard_refresh_seconds": settings.dashboard_refresh_seconds,
        },
        "paths": {
            "base_dir": str(settings.base_dir),
            "data_dir": str(settings.data_dir),
            "reports_dir": str(settings.reports_dir),
            "model_dir": str(settings.model_dir),
            "database_path": str(settings.database_path),
            "host_key_path": str(settings.host_key_path),
        },
        "services": settings.service_status(),
        "intel_providers": provider_status,
        "intel_provider_coverage": provider_coverage,
        "api_keys": settings.masked_api_keys(),
        "artifacts": {
            "model_exists": (settings.model_dir / "sequence_model.json").exists(),
            "database_exists": settings.database_path.exists(),
            "ssh_host_key_exists": settings.host_key_path.exists(),
            "json_reports": len(report_files),
            "pdf_reports": len(pdf_files),
        },
        "warnings": settings.deployment_warnings(),
    }


def print_report(settings: Settings) -> None:
    report = build_report(settings)
    print("SentinelMesh deployment doctor")
    print()
    print(f"Instance: {report['instance']['name']}")
    print(f"Environment: {report['instance']['environment']}")
    print(f"Dashboard refresh: {report['instance']['dashboard_refresh_seconds']}s")
    print()
    print("Services:")
    for service, status in report["services"].items():
        enabled = status["enabled"]
        host = status.get("host")
        port = status["port"]
        if host:
            print(f"  - {service}: {'enabled' if enabled else 'disabled'} on {host}:{port}")
        else:
            print(f"  - {service}: {'enabled' if enabled else 'disabled'} on port {port}")
    print()
    print("Threat-intel providers:")
    for provider, enabled in report["intel_providers"].items():
        print(f"  - {provider}: {'configured' if enabled else 'missing key'}")
    print(
        f"  - coverage: {report['intel_provider_coverage']['configured']}/"
        f"{report['intel_provider_coverage']['total']} configured"
    )
    print()
    print("Artifacts:")
    for key, value in report["artifacts"].items():
        print(f"  - {key}: {value}")
    if report["warnings"]:
        print()
        print("Warnings:")
        for warning in report["warnings"]:
            print(f"  - {warning}")


def report_as_json(settings: Settings) -> str:
    return json.dumps(build_report(settings), indent=2)
