"""Integration tests for the SOC surface: heartbeat, fleet, triage, SOAR."""

import uuid

import pytest

import app as app_module
from domain.evidence_accumulator import Observation


def _client():
    return app_module.app.test_client()


def _tenant():
    with app_module.app.app_context():
        return app_module.DEFAULT_TENANT_ID


def _observe_public_incident(source_ip="8.8.8.8", timestamp=1_700_000_000.0):
    app_module._EVIDENCE_ACCUMULATOR.reset()
    app_module._EVIDENCE_ACCUMULATOR.observe(
        Observation(
            source_ip=source_ip,
            timestamp=timestamp,
            supervised_probability=1.0,
            unsupervised_confidence=1.0,
            reputation_score=100.0,
            supervised_calibration="test-calibrator",
            destination_ip="198.51.100.5",
            destination_port=22,
            tenant_id=_tenant(),
        )
    )


def _incident_id(client):
    payload = client.get("/api/incidents").get_json()
    assert payload["count"] >= 1
    return payload["incidents"][0]


@pytest.fixture()
def clean_soc_rows():
    sensor_id = f"probe-{uuid.uuid4().hex[:8]}"
    yield sensor_id
    with app_module.app.app_context():
        app_module.SensorReport.query.filter_by(sensor_id=sensor_id).delete()
        app_module.IncidentTriage.query.filter(
            app_module.IncidentTriage.source_ip == "8.8.8.8"
        ).delete()
        app_module.db.session.commit()
    app_module._EVIDENCE_ACCUMULATOR.reset()


def test_heartbeat_is_validated_and_appears_in_the_fleet(clean_soc_rows):
    client = _client()
    sensor_id = clean_soc_rows
    response = client.post(
        "/api/sensors/heartbeat",
        json={
            "sensor_id": sensor_id,
            "interface": "eth0",
            "capture_driver": "AF_PACKET",
            "rx_packets": 1000,
            "rx_dropped": 2,
        },
    )
    assert response.status_code == 202
    body = response.get_json()
    assert body["accepted"] is True
    assert body["sensor"]["status"] == "online"
    assert body["sensor"]["vector"] == "ethernet"
    assert body["sensor"]["rx_drop_rate"] == pytest.approx(0.002)
    assert body["sensor"]["link_speed_mbps"] is None
    assert body["sensor"]["capture_driver"] == "AF_PACKET"

    fleet = client.get("/api/sensors/fleet").get_json()
    row = next(item for item in fleet["sensors"] if item["sensor_id"] == sensor_id)
    assert row["rx_drop_rate"] == pytest.approx(0.002)
    assert fleet["heartbeat_source"] == "collector-reported metrics only"

    snapshot = client.get("/api/console/snapshot?limit=1").get_json()
    assert "sensor_fleet" in snapshot
    assert "capture_interface" in snapshot


def test_heartbeat_rejects_unknown_fields_and_negative_metrics(clean_soc_rows):
    client = _client()
    unknown = client.post(
        "/api/sensors/heartbeat",
        json={"sensor_id": clean_soc_rows, "interface": "eth0", "invented_metric": 1},
    )
    assert unknown.status_code == 400
    assert "Unsupported heartbeat field" in unknown.get_json()["error"]

    negative = client.post(
        "/api/sensors/heartbeat",
        json={"sensor_id": clean_soc_rows, "interface": "eth0", "rx_dropped": -4},
    )
    assert negative.status_code == 400


def test_capture_interface_reports_a_heuristic_vector():
    payload = _client().get("/api/capture/interface").get_json()
    assert payload["vector"] in {
        "ethernet", "wlan", "wwan", "vpn", "virtual", "loopback", "unknown"
    }
    assert payload["vector_basis"] in {
        "name_heuristic", "name_heuristic_no_match", "no_adapter_metadata"
    }
    assert "does not change the model input" in payload["note"]


def test_intel_endpoint_returns_unknown_not_clean_without_configuration(monkeypatch):
    monkeypatch.delenv("NETSHIELD_GEOIP_CITY_DB", raising=False)
    monkeypatch.delenv("NETSHIELD_GEOIP_ASN_DB", raising=False)
    monkeypatch.delenv("MAXMIND_CITY_DB", raising=False)
    monkeypatch.delenv("MAXMIND_ASN_DB", raising=False)
    payload = _client().get("/api/intel/8.8.8.8").get_json()
    assert payload["scope"] == "public"
    assert payload["geo"]["status"] in {"not_configured", "dependency_missing", "partial"}
    assert payload["asn"]["number"] is None
    assert payload["reputation"]["status"] == "not_queried"

    private = _client().get("/api/intel/192.168.1.10").get_json()
    assert private["scope"] == "private"
    assert "not transmitted" in private["note"]

    invalid = _client().get("/api/intel/not-an-ip")
    assert invalid.status_code == 400
    assert invalid.get_json()["scope"] == "invalid"


def test_intel_reputation_is_gated_by_the_enable_flag(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setenv("NETSHIELD_THREAT_INTEL_ENABLED", "false")
    contacted = []
    monkeypatch.setattr(
        "threat_intel.requests.get",
        lambda *args, **kwargs: contacted.append((args, kwargs)),
    )

    payload = _client().get("/api/intel/8.8.8.8?reputation=true").get_json()
    assert payload["reputation_requested"] is True
    assert payload["reputation_enabled"] is False
    assert payload["reputation"]["status"] == "disabled"
    assert payload["reputation"]["abuse_score"] is None
    assert contacted == []

    lookup_only = _client().get("/api/intel/8.8.8.8").get_json()
    assert lookup_only["reputation_requested"] is False
    assert lookup_only["reputation"]["status"] == "not_queried"


def test_incident_triage_playbook_and_stix(clean_soc_rows):
    client = _client()
    _observe_public_incident()
    incident = _incident_id(client)
    assert incident["severity"]["id"] == "P1"
    assert incident["severity"]["basis"] == "internal_risk_points"
    assert incident["triage"]["status"] == "new"

    saved = client.put(
        f"/api/incidents/{incident['incident_id']}/triage",
        json={"status": "investigating", "assignee": "analyst-7", "note": "Checking egress"},
    )
    assert saved.status_code == 200
    body = saved.get_json()
    assert body["triage"]["status"] == "investigating"
    assert body["triage"]["assignee"] == "analyst-7"
    assert body["triage"]["persisted"] is True
    assert body["triage"]["sla"]["state"] == "acknowledged"

    listing = client.get("/api/incidents").get_json()["incidents"][0]
    assert listing["triage"]["status"] == "investigating"
    assert listing["triage"]["assignee"] == "analyst-7"

    plan = client.post(
        f"/api/incidents/{incident['incident_id']}/playbook",
        json={"action": "containment_plan"},
    )
    assert plan.status_code == 200
    plan_body = plan.get_json()
    assert plan_body["executed"] is False
    assert plan_body["mode"] == "dry_run"
    assert any("8.8.8.8" in item["command"] for item in plan_body["commands"])

    stix = client.get(f"/api/incidents/{incident['incident_id']}/stix")
    assert stix.status_code == 200
    assert stix.content_type.startswith("application/stix+json")
    assert b'"spec_version": "2.1"' in stix.data

    config = client.get("/api/soar/config").get_json()
    assert config["containment_mode"] == "dry_run_only"
    assert config["enabled"] is False


def test_triage_rejects_invalid_status_and_missing_incident():
    client = _client()
    _observe_public_incident()
    incident_id = _incident_id(client)["incident_id"]
    bad = client.put(
        f"/api/incidents/{incident_id}/triage", json={"status": "deleted"}
    )
    assert bad.status_code == 400

    missing = client.put(
        "/api/incidents/10.0.0.1:1/triage", json={"status": "new"}
    )
    assert missing.status_code == 404

