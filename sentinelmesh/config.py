from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _load_dotenv(path: Path) -> None:
    """Best-effort .env loader used only to fill defaults for local runs.

    For real deployments, prefer setting environment variables directly in the
    process manager / container environment so secrets do not live in a repo-
    adjacent file.
    """
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def _require_nonzero_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise OSError(
            f"Missing required environment variable: {name}"
        )
    return value


@dataclass(slots=True)
class Settings:
    listen_host: str
    http_port: int
    ftp_port: int
    smtp_port: int
    ssh_port: int
    dashboard_host: str
    dashboard_port: int
    enable_http: bool
    enable_ftp: bool
    enable_smtp: bool
    enable_ssh: bool
    base_dir: Path
    data_dir: Path
    reports_dir: Path
    model_dir: Path
    database_path: Path
    host_key_path: Path
    intel_cache_ttl_seconds: int
    abuseipdb_api_key: str | None
    alienvault_otx_api_key: str | None
    shodan_api_key: str | None
    vt_api_key: str | None
    hostname_seed: str
    instance_name: str
    environment_name: str
    dashboard_refresh_seconds: int
    telemetry_token: str
    telemetry_token_header: str
    log_level: str | None
    require_telemetry_auth: bool

    @classmethod
    def from_env(cls) -> Settings:
        base_dir = Path.cwd()
        _load_dotenv(base_dir / ".env")

        environment_name = os.getenv("SENTINELMESH_ENVIRONMENT", "lab").strip()
        is_lab_like = environment_name.lower() in {"lab", "demo", "dev", "docker"}

        telemetry_token = os.getenv("SENTINELMESH_TELEMETRY_TOKEN", "").strip()
        if not is_lab_like and not telemetry_token:
            telemetry_token = _require_nonzero_env("SENTINELMESH_TELEMETRY_TOKEN")

        data_dir = Path(os.getenv("SENTINELMESH_DATA_DIR", base_dir / "data")).resolve()
        database_path = data_dir / "sentinelmesh.db"
        host_key_path = data_dir / "ssh_host_key"

        settings = cls(
            listen_host=os.getenv("SENTINELMESH_LISTEN_HOST", "0.0.0.0"),
            http_port=int(os.getenv("SENTINELMESH_HTTP_PORT", "8080")),
            ftp_port=int(os.getenv("SENTINELMESH_FTP_PORT", "2121")),
            smtp_port=int(os.getenv("SENTINELMESH_SMTP_PORT", "2525")),
            ssh_port=int(os.getenv("SENTINELMESH_SSH_PORT", "2222")),
            dashboard_host=os.getenv("SENTINELMESH_DASHBOARD_HOST", "127.0.0.1"),
            dashboard_port=int(os.getenv("SENTINELMESH_DASHBOARD_PORT", "8000")),
            enable_http=_env_flag("SENTINELMESH_ENABLE_HTTP", True),
            enable_ftp=_env_flag("SENTINELMESH_ENABLE_FTP", True),
            enable_smtp=_env_flag("SENTINELMESH_ENABLE_SMTP", True),
            enable_ssh=_env_flag("SENTINELMESH_ENABLE_SSH", True),
            base_dir=base_dir,
            data_dir=data_dir,
            reports_dir=Path(
                os.getenv("SENTINELMESH_REPORTS_DIR", base_dir / "reports")
            ).resolve(),
            model_dir=Path(
                os.getenv("SENTINELMESH_MODEL_DIR", base_dir / "models")
            ).resolve(),
            database_path=database_path,
            host_key_path=host_key_path,
            intel_cache_ttl_seconds=int(
                os.getenv("SENTINELMESH_INTEL_CACHE_TTL_SECONDS", "1800")
            ),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
            alienvault_otx_api_key=os.getenv("ALIENVAULT_OTX_API_KEY"),
            shodan_api_key=os.getenv("SHODAN_API_KEY"),
            vt_api_key=os.getenv("VT_API_KEY"),
            hostname_seed=os.getenv("SENTINELMESH_HOSTNAME_SEED") or "prod-web-02",
            instance_name=os.getenv(
                "SENTINELMESH_INSTANCE_NAME", "SentinelMesh // Lab Node 01"
            ),
            environment_name=environment_name,
            dashboard_refresh_seconds=int(
                os.getenv("SENTINELMESH_DASHBOARD_REFRESH_SECONDS", "10")
            ),
            telemetry_token=telemetry_token,
            telemetry_token_header=os.getenv(
                "SENTINELMESH_TELEMETRY_TOKEN_HEADER", "X-SentinelToken"
            ),
            log_level=os.getenv("SENTINELMESH_LOG_LEVEL") or None,
            require_telemetry_auth=not is_lab_like,
        )
        settings.ensure_directories()
        return settings

    def ensure_directories(self) -> None:
        for path in (
            self.data_dir,
            self.reports_dir,
            self.model_dir,
            self.reports_dir / "stix",
        ):
            path.mkdir(parents=True, exist_ok=True)

    def intel_provider_status(self) -> dict[str, bool]:
        return {
            "AlienVault OTX": bool(self.alienvault_otx_api_key),
            "AbuseIPDB": bool(self.abuseipdb_api_key),
            "Shodan": bool(self.shodan_api_key),
            "VirusTotal": bool(self.vt_api_key),
        }

    def intel_provider_coverage(self) -> dict[str, int]:
        providers = self.intel_provider_status()
        configured = sum(1 for enabled in providers.values() if enabled)
        total = len(providers)
        percentage = int((configured / total) * 100) if total else 0
        return {"configured": configured, "total": total, "percentage": percentage}

    def service_status(self) -> dict[str, dict[str, Any]]:
        return {
            "http": {"enabled": self.enable_http, "port": self.http_port},
            "ftp": {"enabled": self.enable_ftp, "port": self.ftp_port},
            "smtp": {"enabled": self.enable_smtp, "port": self.smtp_port},
            "ssh": {"enabled": self.enable_ssh, "port": self.ssh_port},
            "dashboard": {
                "enabled": True,
                "port": self.dashboard_port,
                "host": self.dashboard_host,
            },
        }

    def deployment_warnings(self) -> list[str]:
        warnings: list[str] = []
        if self.dashboard_host not in {"127.0.0.1", "localhost"}:
            warnings.append(
                "Dashboard is not bound to localhost. Keep it private or "
                "reverse-proxy it behind authentication."
            )
        if self.listen_host == "0.0.0.0":
            warnings.append(
                "Decoy services are listening on all interfaces. Use an "
                "isolated lab VM or cloud sandbox."
            )
        if not any(self.intel_provider_status().values()):
            warnings.append(
                "No external threat-intelligence API keys are configured, so "
                "CTI enrichment will stay local-only."
            )
        if self.http_port in {80, 443} or self.ftp_port == 21 or self.smtp_port == 25 or self.ssh_port == 22:
            warnings.append(
                "A honeypot service is using a well-known production port. "
                "Confirm host isolation, forwarding rules, and that you are not "
                "accidentally impersonating a real internal service."
            )
        if self.require_telemetry_auth and not self.telemetry_token:
            warnings.append(
                "Telemetry auth is required in this environment but no token is set."
            )
        return warnings

    def masked_api_keys(self) -> dict[str, str]:
        def mask(value: str | None) -> str:
            if not value:
                return "not-configured"
            if len(value) <= 8:
                return "*" * len(value)
            return f"{value[:4]}...{value[-4:]}"

        return {
            "ALIENVAULT_OTX_API_KEY": mask(self.alienvault_otx_api_key),
            "ABUSEIPDB_API_KEY": mask(self.abuseipdb_api_key),
            "SHODAN_API_KEY": mask(self.shodan_api_key),
            "VT_API_KEY": mask(self.vt_api_key),
        }
