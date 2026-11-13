"""Production authentication boundary tests for the Flask API."""

from importlib.metadata import version

import app as app_module
import werkzeug


def _test_client(monkeypatch):
    # Flask 2.3 references this attribute, removed in Werkzeug 3. Runtime
    # installations are pinned below 3; shim only the test environment here.
    monkeypatch.setattr(werkzeug, "__version__", version("Werkzeug"), raising=False)
    return app_module.app.test_client()


def test_production_service_key_cannot_read_api_data(monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(app_module, "AUTH_REQUIRED", True)
    client = _test_client(monkeypatch)

    response = client.get(
        "/api/capture-status",
        headers={"X-API-Key": app_module.API_KEY},
    )

    assert response.status_code == 401


def test_production_service_key_is_header_only_and_ingest_only(monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(app_module, "AUTH_REQUIRED", True)
    client = _test_client(monkeypatch)

    header_key_response = client.post(
        "/api/flows",
        json={},
        headers={"X-API-Key": app_module.API_KEY},
    )
    query_key_response = client.post(
        f"/api/flows?api_key={app_module.API_KEY}",
        json={},
        environ_base={"REMOTE_ADDR": "203.0.113.10"},
    )

    # Empty object is rejected by ingest validation after authentication.
    assert header_key_response.status_code == 400
    # Query-string credentials are not accepted in production.
    assert query_key_response.status_code == 401
