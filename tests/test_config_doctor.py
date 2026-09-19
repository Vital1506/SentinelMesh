from pathlib import Path

from sentinelmesh.config import Settings
from sentinelmesh.doctor import build_report


def test_settings_load_dotenv_without_overwriting_existing_env(monkeypatch, tmp_path):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / ".env").write_text(
        "\n".join(
            [
                "SENTINELMESH_DASHBOARD_PORT=9001",
                "ALIENVAULT_OTX_API_KEY=test-otx-key",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(project_dir)
    monkeypatch.setenv("SENTINELMESH_HTTP_PORT", "8088")
    monkeypatch.setenv("SENTINELMESH_TELEMETRY_TOKEN", "test-token")

    settings = Settings.from_env()

    assert settings.dashboard_port == 9001
    assert settings.http_port == 8088
    assert settings.alienvault_otx_api_key == "test-otx-key"
    assert settings.require_telemetry_auth is False
    assert settings.dashboard_port == 9001
    assert settings.dashboard_port == 9001

    # Directly constructed settings should also honor explicit dashboard_port.
    settings2 = Settings(
        listen_host="127.0.0.1",
        http_port=8080,
        ftp_port=2121,
        smtp_port=2525,
        ssh_port=2222,
        dashboard_host="127.0.0.1",
        dashboard_port=9001,
        enable_http=True,
        enable_ftp=True,
        enable_smtp=True,
        enable_ssh=True,
        base_dir=tmp_path,
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        model_dir=tmp_path / "models",
        database_path=tmp_path / "store.db",
        host_key_path=tmp_path / "host_key",
        intel_cache_ttl_seconds=1800,
        abuseipdb_api_key=None,
        alienvault_otx_api_key=None,
        shodan_api_key=None,
        vt_api_key=None,
        hostname_seed="lab-host",
        instance_name="Test",
        environment_name="lab",
        dashboard_refresh_seconds=10,
        telemetry_token="",
        telemetry_token_header="X-SentinelToken",
        log_level=None,
        require_telemetry_auth=False,
    )
    assert settings2.dashboard_port == 9001


def test_doctor_report_includes_warnings(tmp_path, monkeypatch):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    monkeypatch.chdir(project_dir)

    settings = Settings.from_env()
    report = build_report(settings)

    assert "services" in report
    assert "warnings" in report
    assert report["services"]["dashboard"]["port"] == settings.dashboard_port
    assert any("localhost" in warning or "interfaces" in warning for warning in report["warnings"])
