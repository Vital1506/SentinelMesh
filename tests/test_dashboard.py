from pathlib import Path

from fastapi.testclient import TestClient

from sentinelmesh.config import Settings
from sentinelmesh.dashboard import create_app
from sentinelmesh.storage import EventStore


def test_dashboard_routes_render(tmp_path, monkeypatch):
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
    assert "SentinelMesh" in response.text

    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    ready = client.get("/readyz")
    assert ready.status_code == 200
