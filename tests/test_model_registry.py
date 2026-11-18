"""S3: model registry, artifact verification, promotion, rollback, and
serving provenance.

The registry is file-based. These tests use synthetic bundles so they do not
depend on the large evaluated artifacts, plus one integration test against the
real serving path.
"""

import json

import joblib
import pytest
from sklearn.preprocessing import LabelEncoder

import app as app_module
from training import model_registry as registry

FEATURES = ["f1", "f2", "f3"]


def _write_bundle(path, features=None, threshold=0.5):
    features = features or FEATURES
    bundle = {
        "pipeline": "synthetic-pipeline",
        "feature_names": features,
        "label_encoder": LabelEncoder().fit(["BENIGN", "FTP-Patator"]),
        "task": "multiclass",
        "attack_threshold": threshold,
        "threshold_selection_max_fpr": 0.01,
    }
    joblib.dump(bundle, path)
    return str(path)


def _register(reg, artifact, version="v1", **kwargs):
    return registry.register_model(
        reg,
        "synthetic",
        version,
        artifact,
        role="serving",
        **kwargs,
    )


def test_register_approve_activate_and_deployment_check(tmp_path):
    reg = str(tmp_path / "registry.json")
    artifact = _write_bundle(tmp_path / "model.pkl")

    entry = _register(reg, artifact)
    assert entry["feature_count"] == len(FEATURES)
    assert entry["verification"] == "sha256"
    assert entry["status"] == "candidate"
    assert "\\" not in entry["artifact_path"]
    assert entry["threshold_policy"]["threshold"] == 0.5

    # A candidate cannot be activated.
    with pytest.raises(registry.RegistryError):
        registry.activate_model(reg, "synthetic", "v1", "tester")

    registry.approve_model(reg, "synthetic", "v1", "approver")
    registry.activate_model(reg, "synthetic", "v1", "tester")

    report = registry.deployment_check(reg, artifact)
    assert report["ok"] is True
    assert report["serving_sha256"] == entry["artifact_sha256"]
    assert report["feature_schema_version"] == entry["feature_schema_version"]
    assert report["threshold_policy"]["threshold"] == 0.5


def test_deployment_check_rejects_tampered_artifact(tmp_path):
    reg = str(tmp_path / "registry.json")
    artifact = _write_bundle(tmp_path / "model.pkl")
    _register(reg, artifact)
    registry.approve_model(reg, "synthetic", "v1", "approver")
    registry.activate_model(reg, "synthetic", "v1", "tester")

    with open(artifact, "ab") as handle:
        handle.write(b"tampered")

    with pytest.raises(registry.DeploymentCheckError):
        registry.deployment_check(reg, artifact)


def test_deployment_check_rejects_expected_hash_mismatch(tmp_path):
    reg = str(tmp_path / "registry.json")
    artifact = _write_bundle(tmp_path / "model.pkl")
    _register(reg, artifact)
    registry.approve_model(reg, "synthetic", "v1", "approver")
    registry.activate_model(reg, "synthetic", "v1", "tester")

    with pytest.raises(registry.DeploymentCheckError):
        registry.deployment_check(reg, artifact, expected_sha256="0" * 64)


def test_schema_mismatch_is_refused(tmp_path):
    reg = str(tmp_path / "registry.json")
    artifact = _write_bundle(tmp_path / "model.pkl")
    _register(reg, artifact)
    registry.approve_model(reg, "synthetic", "v1", "approver")
    registry.activate_model(reg, "synthetic", "v1", "tester")

    with open(reg, encoding="utf-8") as handle:
        document = json.load(handle)
    document["models"]["synthetic"]["versions"]["v1"]["feature_schema_sha256"] = "0" * 64
    with open(reg, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)

    with pytest.raises(registry.DeploymentCheckError):
        registry.deployment_check(reg, artifact)


def test_rollback_activates_a_previous_approved_version(tmp_path):
    reg = str(tmp_path / "registry.json")
    v1 = _write_bundle(tmp_path / "v1.pkl", threshold=0.5)
    v2 = _write_bundle(tmp_path / "v2.pkl", threshold=0.6)

    _register(reg, v1, version="v1")
    _register(reg, v2, version="v2")
    for version in ("v1", "v2"):
        registry.approve_model(reg, "synthetic", version, "approver")

    registry.activate_model(reg, "synthetic", "v1", "tester")
    registry.activate_model(reg, "synthetic", "v2", "tester")
    assert registry.active_entry(reg)["version"] == "v2"

    registry.rollback_model(reg, "synthetic", "v1", "tester")
    assert registry.active_entry(reg)["version"] == "v1"

    with open(reg, encoding="utf-8") as handle:
        history = json.load(handle)["models"]["synthetic"]["history"]
    assert history[-1]["action"] == "rollback"
    assert history[-1]["version"] == "v1"


def test_rollback_requires_an_approved_target(tmp_path):
    reg = str(tmp_path / "registry.json")
    artifact = _write_bundle(tmp_path / "model.pkl")
    _register(reg, artifact, version="v1")

    with pytest.raises(registry.RegistryError):
        registry.rollback_model(reg, "synthetic", "v1", "tester")


def test_signed_entries_verify_and_detect_tampering(tmp_path):
    reg = str(tmp_path / "registry.json")
    artifact = _write_bundle(tmp_path / "model.pkl")
    entry = _register(reg, artifact, signing_key="test-signing-key")

    assert entry["verification"] == "sha256+hmac"
    assert entry["signature"]["algorithm"] == "HMAC-SHA256"
    assert registry.verify_entry(entry, signing_key="test-signing-key")["ok"] is True

    tampered = json.loads(json.dumps(entry))
    tampered["threshold_policy"]["threshold"] = 0.99
    with pytest.raises(registry.VerificationError):
        registry.verify_signature(tampered, "test-signing-key")

    # A signed entry cannot be verified without the key.
    with pytest.raises(registry.VerificationError):
        registry.verify_signature(entry, None)


def test_registry_status_reports_active_and_versions(tmp_path):
    reg = str(tmp_path / "registry.json")
    artifact = _write_bundle(tmp_path / "model.pkl")
    _register(reg, artifact)
    registry.approve_model(reg, "synthetic", "v1", "approver")
    registry.activate_model(reg, "synthetic", "v1", "tester")

    status = registry.registry_status(reg)
    assert status["active"] == {"model_id": "synthetic", "version": "v1"}
    assert status["models"]["synthetic"]["v1"]["status"] == "approved"
    assert status["models"]["synthetic"]["v1"]["approved_by"] == "approver"


def _sample_flow():
    return {
        "src_ip": "10.1.2.3",
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


def test_serving_ingest_records_model_provenance():
    client = app_module.app.test_client()
    response = client.post("/api/flows", json=_sample_flow())
    assert response.status_code == 201, response.get_data(as_text=True)
    payload = response.get_json()

    provenance = payload["provenance"]
    assert provenance["model_version"] == app_module._serving_artifact["model_version"]
    assert provenance["artifact_sha256"] == app_module._serving_artifact["hash"]
    assert provenance["feature_schema_version"] == app_module._serving_artifact["feature_schema_version"]
    assert provenance["threshold_policy"] == app_module._serving_artifact["threshold_policy"]["name"]
    assert provenance["calibration_version"] == "uncalibrated"
    assert provenance["decision_basis"] in {"attack_probability_threshold", "argmax"}
    assert provenance["model_argmax_label"]

    with app_module.app.app_context():
        stored = app_module.db.session.get(app_module.Flow, payload["id"])
        assert stored is not None
        assert stored.model_version == provenance["model_version"]
        assert stored.artifact_sha256 == provenance["artifact_sha256"]
        assert stored.feature_schema_version == provenance["feature_schema_version"]
        assert stored.threshold_policy == provenance["threshold_policy"]
        assert stored.calibration_version == provenance["calibration_version"]
        assert stored.decision_basis == provenance["decision_basis"]


def test_csv_export_includes_provenance_columns():
    client = app_module.app.test_client()
    assert client.post("/api/flows", json=_sample_flow()).status_code == 201

    with app_module.app.app_context():
        tenant = app_module.db.session.get(app_module.Tenant, app_module.DEFAULT_TENANT_ID)
        admin = app_module.User.query.filter_by(role="admin", tenant_id=tenant.id).first()
        if admin is None:
            admin = app_module.User(
                tenant_id=tenant.id,
                email="registry-export@example.test",
                display_name="registry export",
                password_hash="not-used",
                role="admin",
                auth_source="local",
                is_active=True,
            )
            app_module.db.session.add(admin)
            app_module.db.session.commit()
        admin_id = admin.id

    with client.session_transaction() as session:
        session["authenticated"] = True
        session["user_id"] = admin_id

    response = client.get("/api/flows/export?limit=10")
    assert response.status_code == 200
    header = response.data.splitlines()[0].decode("utf-8")
    for column in (
        "model_version",
        "artifact_sha256",
        "feature_schema_version",
        "threshold_policy",
        "calibration_version",
        "decision_basis",
    ):
        assert column in header
