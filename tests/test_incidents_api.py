"""Integration test for the multi-signal incident endpoint."""

from __future__ import annotations

import app as app_module
from domain.evidence_accumulator import Observation


def _client():
    return app_module.app.test_client()


def test_incident_endpoint_returns_open_host_windows():
    with app_module.app.app_context():
        tenant_id = app_module.DEFAULT_TENANT_ID
    app_module._EVIDENCE_ACCUMULATOR.reset()
    app_module._EVIDENCE_ACCUMULATOR.observe(
        Observation(
            source_ip="203.0.113.77",
            timestamp=1_700_000_000.0,
            supervised_probability=1.0,
            unsupervised_confidence=1.0,
            supervised_calibration="isotonic-test",
            destination_ip="198.51.100.5",
            destination_port=443,
            tenant_id=tenant_id,
        )
    )
    response = _client().get("/api/incidents")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["in_memory"] is True
    assert payload["count"] == 1
    incident = payload["incidents"][0]
    assert incident["source_ip"] == "203.0.113.77"
    assert incident["risk_points"] == 85.0
    assert incident["active_signals"] == 2
    assert incident["incident_open"] is True
    assert payload["calibration_status"]
    app_module._EVIDENCE_ACCUMULATOR.reset()

