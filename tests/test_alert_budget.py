"""Alert-budget reporting tests.

The declaration is a reporting cap, not a threshold retune. These tests pin
the accounting so an over-budget queue is reported rather than silently
suppressed.
"""

import uuid
from datetime import datetime, timedelta

import pytest

import app as app_module


@pytest.fixture()
def isolated_tenant(monkeypatch):
    suffix = uuid.uuid4().hex[:8]
    with app_module.app.app_context():
        tenant = app_module.Tenant(
            slug=f"budget-{suffix}",
            name="Budget Test",
            retention_days=30,
        )
        app_module.db.session.add(tenant)
        app_module.db.session.commit()
        tenant_id = tenant.id
    monkeypatch.setattr(app_module, "requested_tenant_id", lambda: tenant_id)
    return tenant_id


def _add_flows(tenant_id, attacks, benign, minutes_ago=1):
    timestamp = datetime.utcnow() - timedelta(minutes=minutes_ago)
    flows = [
        app_module.Flow(
            tenant_id=tenant_id,
            src_ip="10.10.0.1",
            dst_ip="10.10.0.2",
            predicted_label="DDoS",
            is_attack=True,
            timestamp=timestamp,
        )
        for _ in range(attacks)
    ]
    flows += [
        app_module.Flow(
            tenant_id=tenant_id,
            src_ip="10.10.0.3",
            dst_ip="10.10.0.4",
            predicted_label="BENIGN",
            is_attack=False,
            timestamp=timestamp,
        )
        for _ in range(benign)
    ]
    with app_module.app.app_context():
        app_module.db.session.add_all(flows)
        app_module.db.session.commit()


def test_alert_budget_reports_over_budget_without_suppression(isolated_tenant, monkeypatch):
    monkeypatch.setattr(app_module, "ALERT_BUDGET_PER_10K", 100)
    monkeypatch.setattr(app_module, "ALERT_BUDGET_WINDOW_MINUTES", 60)

    # 300 flows in the window with a 100/10k cap => 3 allowed, 30 observed.
    _add_flows(isolated_tenant, attacks=30, benign=270)

    with app_module.app.test_request_context("/api/console/snapshot"):
        payload = app_module._alert_budget_payload()

    assert payload["flows"] == 300
    assert payload["alerts"] == 30
    assert payload["allowed_alerts"] == 3.0
    assert payload["remaining_alerts"] == -27.0
    assert payload["state"] == "over_budget"
    assert payload["budget_per_10k_flows"] == 100
    assert payload["window_minutes"] == 60
    assert "never suppresses" in payload["note"]


def test_alert_budget_within_budget_and_no_data(isolated_tenant, monkeypatch):
    monkeypatch.setattr(app_module, "ALERT_BUDGET_PER_10K", 100)
    monkeypatch.setattr(app_module, "ALERT_BUDGET_WINDOW_MINUTES", 60)

    with app_module.app.test_request_context("/api/console/snapshot"):
        empty = app_module._alert_budget_payload(window_minutes=15)
    assert empty["state"] == "no_data"
    assert empty["allowed_alerts"] == 0.0
    assert empty["remaining_alerts"] == 0.0

    # 1,000 flows with 5 alerts is inside a 100/10k cap (10 allowed).
    _add_flows(isolated_tenant, attacks=5, benign=995, minutes_ago=5)
    with app_module.app.test_request_context("/api/console/snapshot"):
        payload = app_module._alert_budget_payload(window_minutes=15)

    assert payload["flows"] == 1000
    assert payload["alerts"] == 5
    assert payload["allowed_alerts"] == 10.0
    assert payload["remaining_alerts"] == 5.0
    assert payload["state"] == "within_budget"


def test_alert_budget_window_excludes_older_flows(isolated_tenant, monkeypatch):
    monkeypatch.setattr(app_module, "ALERT_BUDGET_PER_10K", 100)

    _add_flows(isolated_tenant, attacks=1, benign=9, minutes_ago=120)
    with app_module.app.test_request_context("/api/console/snapshot"):
        payload = app_module._alert_budget_payload(window_minutes=30)

    assert payload["flows"] == 0
    assert payload["state"] == "no_data"
