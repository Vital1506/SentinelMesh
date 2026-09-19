from pathlib import Path

from fastapi.testclient import TestClient

from sentinelmesh.config import Settings
from sentinelmesh.dashboard import create_app
from sentinelmesh.storage import EventStore


def test_telemetry_index_is_public(tmp_path, monkeypatch):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    monkeypatch.chdir(project_dir)
    settings = Settings.from_env()
    store = EventStore(settings.database_path)
    templates_dir = Path(__file__).resolve().parents[1] / "sentinelmesh" / "templates"
    app = create_app(store, settings, templates_dir)
    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "SentinelMesh" in str(response.json().get("notes", ""))
    assert "SentinelMesh" in str(response.json().get("instance_name", ""))


def test_telemetry_overview_requires_token(tmp_path, monkeypatch):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    monkeypatch.chdir(project_dir)

    monkeypatch.setenv("SENTINELMESH_ENVIRONMENT", "production")
    monkeypatch.setenv("SENTINELMESH_TELEMETRY_TOKEN", "demo-token")

    settings = Settings.from_env()
    store = EventStore(settings.database_path)
    templates_dir = Path(__file__).resolve().parents[1] / "sentinelmesh" / "templates"
    app = create_app(store, settings, templates_dir)
    client = TestClient(app)

    response = client.get("/api/overview")
    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


def test_telemetry_overview_accepts_valid_token(tmp_path, monkeypatch):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    monkeypatch.chdir(project_dir)
    settings = Settings.from_env()
    store = EventStore(settings.database_path)
    templates_dir = Path(__file__).resolve().parents[1] / "sentinelmesh" / "templates"
    app = create_app(store, settings, templates_dir)
    client = TestClient(app)

    response = client.get(
        "/api/overview",
        headers={settings.telemetry_token_header: settings.telemetry_token},
    )
    assert response.status_code == 200
    body = response.json()
    assert "metrics" in body
    assert "sessions" in body
    assert "profiles" in body


def test_healthz_and_readyz_remain_public(tmp_path, monkeypatch):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    monkeypatch.chdir(project_dir)
    settings = Settings.from_env()
    store = EventStore(settings.database_path)
    templates_dir = Path(__file__).resolve().parents[1] / "sentinelmesh" / "templates"
    app = create_app(store, settings, templates_dir)
    client = TestClient(app)

    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["status"] in {"ready", "degraded"}
