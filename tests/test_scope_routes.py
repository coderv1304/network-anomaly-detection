"""P0 scope-route tests: permanent dashboard redirect and shared scope ribbon."""

from importlib.metadata import version
from pathlib import Path

import app as app_module
import werkzeug

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _test_client(monkeypatch):
    # Flask 2.3 references this attribute, removed in Werkzeug 3. Runtime
    # installations are pinned below 3; shim only the test environment here.
    monkeypatch.setattr(werkzeug, "__version__", version("Werkzeug"), raising=False)
    return app_module.app.test_client()


def test_dashboard_redirects_permanently_to_console(monkeypatch):
    client = _test_client(monkeypatch)

    response = client.get("/dashboard")

    assert response.status_code == 301
    assert response.headers["Location"].endswith("/")
    assert "/dashboard" not in response.headers["Location"]


def test_console_serves_scope_ribbon(monkeypatch):
    client = _test_client(monkeypatch)

    response = client.get("/")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'class="scope-ribbon"' in body
    assert "Volumetric &amp; scan scope" in body
    assert "unvalidated prototype" in body


def test_research_serves_scope_ribbon(monkeypatch):
    client = _test_client(monkeypatch)

    response = client.get("/research")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'class="scope-ribbon"' in body
    assert "Volumetric &amp; scan scope" in body
    assert "unvalidated prototype" in body


def test_research_serves_prevalence_view(monkeypatch):
    client = _test_client(monkeypatch)

    response = client.get("/research")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'id="view-prevalence"' in body
    assert "docs/PREVALENCE_EVAL.json" in body
    assert "How much precision survives realistic attack prevalence?" in body


def test_legacy_dashboard_is_archived_not_served():
    assert not (PROJECT_ROOT / "templates" / "dashboard.html").exists()
    archived = PROJECT_ROOT / "archive" / "legacy_dashboard"
    assert (archived / "dashboard.html").exists()
    assert (archived / "dashboard.css").exists()
    assert (archived / "dashboard.js").exists()
