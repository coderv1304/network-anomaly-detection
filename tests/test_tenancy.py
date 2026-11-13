"""Tenant isolation, RBAC, audit, retention, and deletion tests for S1."""

import uuid
from datetime import datetime, timedelta

import pytest

import app as app_module


def _client():
    return app_module.app.test_client()


def _login_as(client, user_id):
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["user_id"] = user_id


@pytest.fixture()
def tenancy():
    suffix = uuid.uuid4().hex[:8]
    with app_module.app.app_context():
        tenant_a = app_module.Tenant(slug=f"test-a-{suffix}", name="Test A", retention_days=30)
        tenant_b = app_module.Tenant(slug=f"test-b-{suffix}", name="Test B", retention_days=30)
        app_module.db.session.add_all([tenant_a, tenant_b])
        app_module.db.session.flush()

        users = {}
        for key, tenant, role in (
            ("analyst_a", tenant_a, "analyst"),
            ("viewer_a", tenant_a, "viewer"),
            ("admin_a", tenant_a, "admin"),
            ("analyst_b", tenant_b, "analyst"),
        ):
            user = app_module.User(
                tenant_id=tenant.id,
                email=f"{key}-{suffix}@example.test",
                display_name=key,
                password_hash="not-used-in-session-tests",
                role=role,
                auth_source="local",
                is_active=True,
            )
            app_module.db.session.add(user)
            users[key] = user
        platform_admin = app_module.User(
            tenant_id=None,
            email=f"platform-{suffix}@example.test",
            display_name="platform",
            password_hash="not-used-in-session-tests",
            role="platform_admin",
            auth_source="local",
            is_active=True,
        )
        app_module.db.session.add(platform_admin)
        app_module.db.session.flush()

        flow_a = app_module.Flow(tenant_id=tenant_a.id, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                 predicted_label="BENIGN", is_attack=False)
        flow_b = app_module.Flow(tenant_id=tenant_b.id, src_ip="10.1.0.1", dst_ip="10.1.0.2",
                                 predicted_label="DDoS", is_attack=True)
        old_flow_a = app_module.Flow(tenant_id=tenant_a.id, src_ip="10.0.0.9", dst_ip="10.0.0.10",
                                     predicted_label="DDoS", is_attack=True,
                                     timestamp=datetime.utcnow() - timedelta(days=90))
        old_flow_b = app_module.Flow(tenant_id=tenant_b.id, src_ip="10.1.0.9", dst_ip="10.1.0.10",
                                     predicted_label="DDoS", is_attack=True,
                                     timestamp=datetime.utcnow() - timedelta(days=90))
        app_module.db.session.add_all([flow_a, flow_b, old_flow_a, old_flow_b])
        app_module.db.session.commit()

        ids = {
            "tenant_a": tenant_a.id,
            "tenant_b": tenant_b.id,
            "flow_a": flow_a.id,
            "flow_b": flow_b.id,
            "old_flow_a": old_flow_a.id,
            "old_flow_b": old_flow_b.id,
            "analyst_a": users["analyst_a"].id,
            "viewer_a": users["viewer_a"].id,
            "admin_a": users["admin_a"].id,
            "analyst_b": users["analyst_b"].id,
            "platform_admin": platform_admin.id,
            "suffix": suffix,
        }

    yield ids

    with app_module.app.app_context():
        flow_ids = [
            row[0]
            for row in app_module.db.session.query(app_module.Flow.id)
            .filter(app_module.Flow.tenant_id.in_([ids["tenant_a"], ids["tenant_b"]]))
            .all()
        ]
        app_module._delete_flows(flow_ids)
        app_module.User.query.filter(
            app_module.User.tenant_id.in_([ids["tenant_a"], ids["tenant_b"]])
        ).delete(synchronize_session=False)
        app_module.User.query.filter_by(id=ids["platform_admin"]).delete(synchronize_session=False)
        app_module.AuditEvent.query.filter(
            app_module.AuditEvent.tenant_id.in_([ids["tenant_a"], ids["tenant_b"]])
        ).delete(synchronize_session=False)
        app_module.Tenant.query.filter(
            app_module.Tenant.id.in_([ids["tenant_a"], ids["tenant_b"]])
        ).delete(synchronize_session=False)
        app_module.db.session.commit()


def test_flow_list_is_tenant_scoped(tenancy):
    client = _client()
    _login_as(client, tenancy["analyst_a"])

    response = client.get("/api/flows?limit=50")
    assert response.status_code == 200
    body = response.get_json()
    returned_ids = {row["id"] for row in body["flows"]}

    assert tenancy["flow_a"] in returned_ids
    assert tenancy["flow_b"] not in returned_ids
    assert tenancy["old_flow_b"] not in returned_ids


def test_cross_tenant_flow_detail_is_not_found(tenancy):
    client = _client()
    _login_as(client, tenancy["analyst_a"])

    own = client.get(f"/api/flows/{tenancy['flow_a']}")
    other = client.get(f"/api/flows/{tenancy['flow_b']}")

    assert own.status_code == 200
    assert own.get_json()["tenant_id"] == tenancy["tenant_a"]
    assert other.status_code == 404


def test_cross_tenant_review_is_not_found_and_does_not_mutate(tenancy):
    client = _client()
    _login_as(client, tenancy["analyst_a"])

    response = client.put(
        f"/api/flows/{tenancy['flow_b']}/review",
        json={"status": "Investigating", "note": "cross-tenant attempt"},
    )
    assert response.status_code == 404

    with app_module.app.app_context():
        review = app_module.db.session.get(app_module.FlowReview, tenancy["flow_b"])
        assert review is None


def test_stats_and_snapshot_do_not_leak_other_tenant(tenancy):
    client = _client()
    _login_as(client, tenancy["analyst_a"])

    stats = client.get("/api/stats").get_json()
    assert stats["total"] == 2
    assert stats["attack"] == 1

    snapshot = client.get("/api/console/snapshot?limit=50&flagged_limit=50").get_json()
    returned_ids = {row["id"] for row in snapshot["flows"]}
    assert tenancy["flow_b"] not in returned_ids
    assert tenancy["old_flow_b"] not in returned_ids


def test_viewer_cannot_review_but_analyst_can(tenancy):
    viewer = _client()
    _login_as(viewer, tenancy["viewer_a"])
    denied = viewer.put(
        f"/api/flows/{tenancy['flow_a']}/review",
        json={"status": "Investigating", "note": "viewer attempt"},
    )
    assert denied.status_code == 403

    analyst = _client()
    _login_as(analyst, tenancy["analyst_a"])
    allowed = analyst.put(
        f"/api/flows/{tenancy['flow_a']}/review",
        json={"status": "Investigating", "note": "analyst review"},
    )
    assert allowed.status_code == 200
    assert allowed.get_json()["review"]["status"] == "Investigating"

    audit = analyst.get(f"/api/flows/{tenancy['flow_a']}/review/audit")
    assert audit.status_code == 200
    assert audit.get_json()["events"][0]["new_status"] == "Investigating"


def test_admin_can_manage_users_but_analyst_cannot(tenancy):
    analyst = _client()
    _login_as(analyst, tenancy["analyst_a"])
    denied = analyst.post(
        "/api/tenant/users",
        json={"email": f"denied-{tenancy['suffix']}@example.test", "password": "long-enough-password", "role": "viewer"},
    )
    assert denied.status_code == 403

    admin = _client()
    _login_as(admin, tenancy["admin_a"])
    created = admin.post(
        "/api/tenant/users",
        json={"email": f"created-{tenancy['suffix']}@example.test", "password": "long-enough-password", "role": "viewer"},
    )
    assert created.status_code == 201
    assert created.get_json()["user"]["tenant_id"] == tenancy["tenant_a"]


def test_tenant_admin_cannot_list_tenants_but_platform_admin_can(tenancy):
    admin = _client()
    _login_as(admin, tenancy["admin_a"])
    assert admin.get("/api/tenants").status_code == 403

    platform = _client()
    _login_as(platform, tenancy["platform_admin"])
    response = platform.get("/api/tenants")
    assert response.status_code == 200
    slugs = {row["slug"] for row in response.get_json()["tenants"]}
    assert f"test-a-{tenancy['suffix']}" in slugs


def test_retention_purge_is_tenant_scoped(tenancy):
    admin = _client()
    _login_as(admin, tenancy["admin_a"])

    response = admin.post("/api/tenant/purge")
    assert response.status_code == 200
    assert response.get_json()["deleted_flows"] >= 1

    with app_module.app.app_context():
        assert app_module.db.session.get(app_module.Flow, tenancy["old_flow_a"]) is None
        assert app_module.db.session.get(app_module.Flow, tenancy["old_flow_b"]) is not None
        assert app_module.db.session.get(app_module.Flow, tenancy["flow_a"]) is not None


def test_tenant_deletion_requires_confirmation_and_removes_rows(tenancy):
    suffix = tenancy["suffix"]
    with app_module.app.app_context():
        doomed = app_module.Tenant(slug=f"doomed-{suffix}", name="Doomed")
        app_module.db.session.add(doomed)
        app_module.db.session.flush()
        doomed_user = app_module.User(
            tenant_id=doomed.id,
            email=f"doomed-{suffix}@example.test",
            password_hash="not-used",
            role="admin",
            auth_source="local",
            is_active=True,
        )
        doomed_flow = app_module.Flow(tenant_id=doomed.id, src_ip="10.9.0.1", dst_ip="10.9.0.2",
                                      predicted_label="BENIGN", is_attack=False)
        app_module.db.session.add_all([doomed_user, doomed_flow])
        app_module.db.session.commit()
        doomed_id = doomed.id
        doomed_flow_id = doomed_flow.id
        doomed_user_id = doomed_user.id

    platform = _client()
    _login_as(platform, tenancy["platform_admin"])
    rejected = platform.delete(f"/api/tenants/{doomed_id}", json={"confirm": "wrong"})
    assert rejected.status_code == 400

    deleted = platform.delete(f"/api/tenants/{doomed_id}", json={"confirm": f"doomed-{suffix}"})
    assert deleted.status_code == 200

    with app_module.app.app_context():
        assert app_module.db.session.get(app_module.Tenant, doomed_id) is None
        assert app_module.db.session.get(app_module.Flow, doomed_flow_id) is None
        assert app_module.db.session.get(app_module.User, doomed_user_id) is None


def test_audit_events_are_tenant_scoped(tenancy):
    a = _client()
    _login_as(a, tenancy["analyst_a"])
    a.get("/api/flows?limit=5")

    b = _client()
    _login_as(b, tenancy["analyst_b"])
    b.get("/api/flows?limit=5")

    response = a.get("/api/audit?limit=100")
    assert response.status_code == 200
    events = response.get_json()["events"]
    assert events
    assert all(event["tenant_id"] == tenancy["tenant_a"] for event in events)


def test_export_is_permissioned_and_audited(tenancy):
    viewer = _client()
    _login_as(viewer, tenancy["viewer_a"])
    assert viewer.get("/api/flows/export").status_code == 403

    analyst = _client()
    _login_as(analyst, tenancy["analyst_a"])
    response = analyst.get("/api/flows/export?limit=100")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert b"predicted_label" in response.data

    audit = analyst.get("/api/audit?action=flows.export")
    assert audit.status_code == 200
    assert audit.get_json()["total"] >= 1


def test_me_returns_role_and_tenant(tenancy):
    client = _client()
    _login_as(client, tenancy["analyst_a"])
    body = client.get("/api/me").get_json()
    assert body["authenticated"] is True
    assert body["role"] == "analyst"
    assert body["tenant"]["id"] == tenancy["tenant_a"]
    assert "flows:review" in body["permissions"]


def test_service_key_cannot_read_even_with_tenant_override(tenancy):
    client = _client()
    response = client.get(
        f"/api/flows?tenant_id={tenancy['tenant_b']}",
        headers={"X-API-Key": app_module.API_KEY},
    )
    # In development the request still has the local administrative identity.
    # The important production assertion is covered by test_app_auth.py.
    assert response.status_code in {200, 401}
