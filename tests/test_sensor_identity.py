"""P3 sensor identity, filtering, and per-sensor summary tests."""

import uuid

import pytest

import app as app_module


def _client():
    return app_module.app.test_client()


def _login_as(client, user_id):
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["user_id"] = user_id


def _sample_flow(**overrides):
    flow = {
        "src_ip": "10.2.3.4",
        "dst_ip": "10.9.8.7",
        "src_port": 51515,
        "dst_port": 443,
        "protocol": 6,
        "flow_duration": 1200,
        "tot_fwd_pkts": 4,
        "tot_bwd_pkts": 3,
        "flow_byts_s": 120.0,
        "flow_pkts_s": 6.0,
    }
    flow.update(overrides)
    return flow


@pytest.fixture()
def sensor_tenancy():
    suffix = uuid.uuid4().hex[:8]
    with app_module.app.app_context():
        tenant_a = app_module.Tenant(slug=f"sensor-a-{suffix}", name="Sensor A", retention_days=30)
        tenant_b = app_module.Tenant(slug=f"sensor-b-{suffix}", name="Sensor B", retention_days=30)
        app_module.db.session.add_all([tenant_a, tenant_b])
        app_module.db.session.flush()

        analyst_a = app_module.User(
            tenant_id=tenant_a.id,
            email=f"analyst-a-{suffix}@example.test",
            display_name="analyst a",
            password_hash="not-used",
            role="analyst",
            auth_source="local",
            is_active=True,
        )
        app_module.db.session.add(analyst_a)
        app_module.db.session.flush()

        flows = {
            "a_eth_benign": app_module.Flow(
                tenant_id=tenant_a.id, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                predicted_label="BENIGN", is_attack=False,
                sensor_id="sensor-a", interface="Ethernet",
            ),
            "a_eth_attack": app_module.Flow(
                tenant_id=tenant_a.id, src_ip="10.0.0.3", dst_ip="10.0.0.4",
                predicted_label="DDoS", is_attack=True,
                sensor_id="sensor-a", interface="Ethernet",
            ),
            "a_wifi_attack": app_module.Flow(
                tenant_id=tenant_a.id, src_ip="10.0.0.5", dst_ip="10.0.0.6",
                predicted_label="DDoS", is_attack=True,
                sensor_id="sensor-b", interface="Wi-Fi",
            ),
            "a_unattributed": app_module.Flow(
                tenant_id=tenant_a.id, src_ip="10.0.0.7", dst_ip="10.0.0.8",
                predicted_label="BENIGN", is_attack=False,
            ),
            # Same sensor name in another tenant must never leak into tenant A.
            "b_same_name": app_module.Flow(
                tenant_id=tenant_b.id, src_ip="10.1.0.1", dst_ip="10.1.0.2",
                predicted_label="DDoS", is_attack=True,
                sensor_id="sensor-a", interface="Ethernet",
            ),
        }
        app_module.db.session.add_all(flows.values())
        app_module.db.session.commit()

        ids = {
            "tenant_a": tenant_a.id,
            "tenant_b": tenant_b.id,
            "analyst_a": analyst_a.id,
            "suffix": suffix,
        }
        ids.update({key: flow.id for key, flow in flows.items()})

    yield ids

    with app_module.app.app_context():
        flow_ids = [
            row[0]
            for row in app_module.db.session.query(app_module.Flow.id)
            .filter(app_module.Flow.tenant_id.in_([ids["tenant_a"], ids["tenant_b"]]))
            .all()
        ]
        app_module._delete_flows(flow_ids)
        app_module.User.query.filter_by(id=ids["analyst_a"]).delete(synchronize_session=False)
        app_module.AuditEvent.query.filter(
            app_module.AuditEvent.tenant_id.in_([ids["tenant_a"], ids["tenant_b"]])
        ).delete(synchronize_session=False)
        app_module.Tenant.query.filter(
            app_module.Tenant.id.in_([ids["tenant_a"], ids["tenant_b"]])
        ).delete(synchronize_session=False)
        app_module.db.session.commit()


def test_ingest_persists_sensor_and_interface():
    client = _client()
    response = client.post(
        "/api/flows",
        json=_sample_flow(sensor_id="edge-01", interface="Ethernet"),
    )
    assert response.status_code == 201, response.get_data(as_text=True)
    payload = response.get_json()
    assert payload["sensor_id"] == "edge-01"
    assert payload["interface"] == "Ethernet"

    with app_module.app.app_context():
        stored = app_module.db.session.get(app_module.Flow, payload["id"])
        assert stored.sensor_id == "edge-01"
        assert stored.interface == "Ethernet"
        app_module._delete_flows([payload["id"]])


def test_ingest_falls_back_to_interface_for_sensor_identity():
    client = _client()
    response = client.post("/api/flows", json=_sample_flow(input_interface="Wi-Fi"))
    assert response.status_code == 201, response.get_data(as_text=True)
    payload = response.get_json()
    assert payload["sensor_id"] == "Wi-Fi"
    assert payload["interface"] == "Wi-Fi"

    with app_module.app.app_context():
        app_module._delete_flows([payload["id"]])


def test_ingest_rejects_overlong_sensor_identity():
    client = _client()
    response = client.post("/api/flows", json=_sample_flow(sensor_id="x" * 81))
    assert response.status_code == 400


def test_ingest_does_not_invent_identity():
    client = _client()
    response = client.post("/api/flows", json=_sample_flow())
    assert response.status_code == 201, response.get_data(as_text=True)
    payload = response.get_json()
    assert payload["sensor_id"] is None
    assert payload["interface"] is None

    with app_module.app.app_context():
        app_module._delete_flows([payload["id"]])


def test_flow_list_filters_by_sensor_and_tenant(sensor_tenancy):
    client = _client()
    _login_as(client, sensor_tenancy["analyst_a"])

    response = client.get("/api/flows?limit=50&sensor_id=sensor-a")
    assert response.status_code == 200
    body = response.get_json()
    ids = {row["id"] for row in body["flows"]}
    assert ids == {sensor_tenancy["a_eth_benign"], sensor_tenancy["a_eth_attack"]}
    assert sensor_tenancy["b_same_name"] not in ids


def test_flow_list_filters_by_interface(sensor_tenancy):
    client = _client()
    _login_as(client, sensor_tenancy["analyst_a"])

    body = client.get("/api/flows?limit=50&interface=Wi-Fi").get_json()
    ids = {row["id"] for row in body["flows"]}
    assert ids == {sensor_tenancy["a_wifi_attack"]}


def test_sensor_summary_is_tenant_scoped(sensor_tenancy):
    client = _client()
    _login_as(client, sensor_tenancy["analyst_a"])

    response = client.get("/api/sensors/summary")
    assert response.status_code == 200
    body = response.get_json()
    by_name = {row["sensor_id"]: row for row in body["sensors"] if row["sensor_id"]}

    assert by_name["sensor-a"]["total"] == 2
    assert by_name["sensor-a"]["attacks"] == 1
    assert by_name["sensor-a"]["benign"] == 1
    assert by_name["sensor-b"]["total"] == 1
    assert by_name["sensor-b"]["attacks"] == 1
    # Tenant B's identically named sensor is not counted.
    assert sum(row["total"] for row in body["sensors"]) == 4
    assert body["unattributed_flows"] == 1


def test_console_snapshot_filters_by_sensor(sensor_tenancy):
    client = _client()
    _login_as(client, sensor_tenancy["analyst_a"])

    response = client.get("/api/console/snapshot?limit=50&sensor_id=sensor-b")
    assert response.status_code == 200
    body = response.get_json()
    ids = {row["id"] for row in body["flows"]}
    assert ids == {sensor_tenancy["a_wifi_attack"]}
    assert {row["sensor_id"] for row in body["sensors"] if row["sensor_id"]} == {"sensor-a", "sensor-b"}
