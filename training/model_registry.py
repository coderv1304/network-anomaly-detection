"""Model registry, version pinning, verification, promotion, and rollback.

The registry is a small JSON document that records the artifact hash, feature
schema, threshold policy, calibration version, and approval state for every
model version. It is intentionally file-based so it can be reviewed, diffed,
and backed up with the repository. It is not a replacement for a managed
artifact store; it is the version-pinning and verification layer that prevents
the serving process from silently loading an unapproved artifact.

Security model
--------------
* Every entry records the artifact SHA-256 and the feature-schema SHA-256.
* Entries may be signed with HMAC-SHA256 using ``MODEL_SIGNING_KEY``. When no
  key is configured, the entry is hash-verified only and says so explicitly.
* Promotion requires a successful verification. Activation requires an
  approved entry. Rollback requires an approved target version.
* ``deployment_check`` fails when the serving artifact's hash or feature
  schema differs from the active approved entry.

Registry schema (version 1.0)
-----------------------------
{
  "schema_version": "1.0",
  "updated_at": "...",
  "active": {"model_id": "...", "version": "..."},
  "models": {
    "<model_id>": {
      "versions": {
        "<version>": {
          "model_id", "version", "role", "status",
          "artifact_path", "artifact_sha256", "artifact_size",
          "feature_schema_version", "feature_schema_sha256",
          "feature_count", "features",
          "threshold_policy": {...},
          "calibration_version", "calibration_method",
          "calibration_artifact", "calibration_artifact_sha256",
          "dataset_sha256", "training_config",
          "python_version", "scikit_learn_version",
          "created_at", "created_by", "approved_at", "approved_by",
          "signature": {"algorithm": "HMAC-SHA256", "value": "..."} | null,
          "verification": "sha256+hmac" | "sha256",
          "notes"
        }
      },
      "history": [...]
    }
  }
}
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import UTC, datetime

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DEFAULT_REGISTRY_PATH = os.path.join("models", "registry", "registry.json")
REGISTRY_SCHEMA_VERSION = "1.0"
FEATURE_SCHEMA_LABEL = "CIC-IDS-2017 CICFlowMeter 80-feature schema"


class RegistryError(RuntimeError):
    """Base class for registry failures."""


class VerificationError(RegistryError):
    """An artifact or entry failed verification."""


class DeploymentCheckError(RegistryError):
    """The serving artifact does not match the approved active artifact."""


def now_utc() -> str:
    return datetime.now(UTC).isoformat()


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_json(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def feature_schema_sha256(feature_names: list[str]) -> str:
    return sha256_json([str(value) for value in feature_names])


def feature_schema_version(feature_names: list[str]) -> str:
    digest = feature_schema_sha256(feature_names)
    return f"cic-ids-2017-{len(feature_names)}f-{digest[:12]}"


def new_registry() -> dict:
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "updated_at": now_utc(),
        "active": None,
        "models": {},
    }


def load_registry(path: str = DEFAULT_REGISTRY_PATH) -> dict:
    if not os.path.isfile(path):
        return new_registry()
    with open(path, encoding="utf-8") as handle:
        registry = json.load(handle)
    if registry.get("schema_version") != REGISTRY_SCHEMA_VERSION:
        raise RegistryError(
            f"Unsupported registry schema {registry.get('schema_version')!r}; "
            f"expected {REGISTRY_SCHEMA_VERSION!r}"
        )
    registry.setdefault("models", {})
    registry.setdefault("active", None)
    return registry


def save_registry(path: str, registry: dict) -> None:
    registry["updated_at"] = now_utc()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(registry, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def _signing_key_bytes(signing_key: str | bytes | None) -> bytes | None:
    if signing_key is None:
        signing_key = os.environ.get("MODEL_SIGNING_KEY")
    if signing_key is None or signing_key == "":
        return None
    if isinstance(signing_key, str):
        return signing_key.encode("utf-8")
    return signing_key


def _entry_payload(entry: dict) -> dict:
    # ``signature`` and ``verification`` are envelope metadata, not part of the
    # signed content. Signing the content only means the verification label can
    # be set after the signature is computed without invalidating it.
    return {
        key: value
        for key, value in entry.items()
        if key not in {"signature", "verification"}
    }


def sign_entry(entry: dict, signing_key: str | bytes | None) -> dict | None:
    key = _signing_key_bytes(signing_key)
    if key is None:
        return None
    digest = hmac.new(key, canonical_json(_entry_payload(entry)).encode("utf-8"), hashlib.sha256)
    return {"algorithm": "HMAC-SHA256", "value": digest.hexdigest()}


def verify_signature(entry: dict, signing_key: str | bytes | None) -> bool:
    signature = entry.get("signature")
    if not signature:
        return True
    key = _signing_key_bytes(signing_key)
    if key is None:
        raise VerificationError(
            "Entry is signed but MODEL_SIGNING_KEY is not configured; cannot verify"
        )
    expected = hmac.new(
        key, canonical_json(_entry_payload(entry)).encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, str(signature.get("value", ""))):
        raise VerificationError("Entry signature does not match")
    return True


def _bundle_metadata(artifact_path: str) -> dict:
    import joblib

    bundle = joblib.load(artifact_path)
    if not isinstance(bundle, dict) or "pipeline" not in bundle or "feature_names" not in bundle:
        raise RegistryError(f"{artifact_path} is not a recognized model bundle")
    feature_names = [str(value) for value in bundle["feature_names"]]
    label_encoder = bundle.get("label_encoder")
    classes = [str(value) for value in label_encoder.classes_] if label_encoder is not None else []
    return {
        "feature_names": feature_names,
        "classes": classes,
        "task": bundle.get("task"),
        "bundle_threshold": bundle.get("attack_threshold"),
        "bundle_threshold_max_fpr": bundle.get("threshold_selection_max_fpr"),
    }


def _registry_path(path: str) -> str:
    """Store artifact paths in a portable, repository-relative form."""
    return os.path.normpath(path).replace("\\", "/")


def register_model(
    registry_path: str,
    model_id: str,
    version: str,
    artifact_path: str,
    *,
    role: str = "research",
    threshold_policy: dict | None = None,
    calibration_version: str = "uncalibrated",
    calibration_method: str = "none",
    calibration_artifact: str | None = None,
    dataset_sha256: dict | None = None,
    training_config: dict | None = None,
    created_by: str = "operator",
    signing_key: str | bytes | None = None,
    notes: str = "",
    status: str = "candidate",
) -> dict:
    """Register one model version without approving or activating it."""
    if role not in {"serving", "research"}:
        raise RegistryError("role must be 'serving' or 'research'")
    if status not in {"candidate", "approved", "retired"}:
        raise RegistryError("status must be candidate, approved, or retired")
    if not os.path.isfile(artifact_path):
        raise RegistryError(f"Artifact does not exist: {artifact_path}")

    bundle = _bundle_metadata(artifact_path)
    features = bundle["feature_names"]
    artifact_digest = sha256_file(artifact_path)
    schema_digest = feature_schema_sha256(features)
    schema_version = feature_schema_version(features)

    if threshold_policy is None:
        threshold_policy = {
            "name": "bundle_attack_threshold" if bundle["bundle_threshold"] is not None else "argmax",
            "threshold": bundle["bundle_threshold"],
            "max_fpr": bundle["bundle_threshold_max_fpr"],
            "selected_on": "recorded in artifact",
            "score": "1 - P(BENIGN)",
            "decision": (
                "attack_score >= threshold"
                if bundle["bundle_threshold"] is not None
                else "argmax predicted class != BENIGN"
            ),
        }
    if not isinstance(threshold_policy, dict) or "name" not in threshold_policy:
        raise RegistryError("threshold_policy must be a dict with a name")
    if threshold_policy.get("threshold") is None and "argmax" not in str(threshold_policy.get("decision", "")).lower():
        raise RegistryError("threshold_policy must include a threshold or an explicit argmax decision")

    calibration_digest = None
    if calibration_artifact:
        if not os.path.isfile(calibration_artifact):
            raise RegistryError(f"Calibration artifact does not exist: {calibration_artifact}")
        calibration_digest = sha256_file(calibration_artifact)

    entry = {
        "model_id": model_id,
        "version": version,
        "role": role,
        "status": status,
        "artifact_path": _registry_path(artifact_path),
        "artifact_sha256": artifact_digest,
        "artifact_size": os.path.getsize(artifact_path),
        "feature_schema_version": schema_version,
        "feature_schema_sha256": schema_digest,
        "feature_schema_label": FEATURE_SCHEMA_LABEL,
        "feature_count": len(features),
        "features": features,
        "task": bundle.get("task"),
        "classes": bundle.get("classes", []),
        "threshold_policy": threshold_policy,
        "calibration_version": calibration_version,
        "calibration_method": calibration_method,
        "calibration_artifact": _registry_path(calibration_artifact) if calibration_artifact else None,
        "calibration_artifact_sha256": calibration_digest,
        "dataset_sha256": dataset_sha256 or {},
        "training_config": training_config or {},
        "python_version": sys.version.split()[0],
        "created_at": now_utc(),
        "created_by": created_by,
        "approved_at": None,
        "approved_by": None,
        "verification": "sha256",
        "notes": notes,
    }
    signature = sign_entry(entry, signing_key)
    entry["signature"] = signature
    entry["verification"] = "sha256+hmac" if signature else "sha256"

    registry = load_registry(registry_path)
    model = registry["models"].setdefault(model_id, {"versions": {}, "history": []})
    if version in model["versions"]:
        raise RegistryError(f"{model_id} version {version} is already registered")
    model["versions"][version] = entry
    model["history"].append({
        "action": "register",
        "version": version,
        "at": now_utc(),
        "actor": created_by,
        "artifact_sha256": artifact_digest,
    })
    save_registry(registry_path, registry)
    return entry


def _get_entry(registry: dict, model_id: str, version: str) -> dict:
    try:
        return registry["models"][model_id]["versions"][version]
    except KeyError as exc:
        raise RegistryError(f"Unknown model version {model_id}/{version}") from exc


def verify_entry(
    entry: dict,
    *,
    base_dir: str = ".",
    signing_key: str | bytes | None = None,
    expected_bundle_features: list[str] | None = None,
) -> dict:
    """Verify an entry's artifact hash, schema, threshold, calibration, and signature."""
    errors = []
    warnings = []
    artifact_path = entry.get("artifact_path")
    if not artifact_path:
        errors.append("artifact_path is missing")
    elif not os.path.isfile(artifact_path):
        # Allow registry-relative paths when the caller runs from elsewhere.
        candidate = os.path.join(base_dir, artifact_path)
        if os.path.isfile(candidate):
            artifact_path = candidate
        else:
            errors.append(f"artifact does not exist: {entry.get('artifact_path')}")
    if artifact_path and os.path.isfile(artifact_path):
        actual_hash = sha256_file(artifact_path)
        if not hmac.compare_digest(actual_hash, str(entry.get("artifact_sha256", ""))):
            errors.append("artifact SHA-256 does not match the registry entry")
        if int(entry.get("artifact_size", -1)) not in {-1, os.path.getsize(artifact_path)}:
            errors.append("artifact size does not match the registry entry")
        if expected_bundle_features is not None:
            expected_hash = feature_schema_sha256(expected_bundle_features)
            if not hmac.compare_digest(expected_hash, str(entry.get("feature_schema_sha256", ""))):
                errors.append("bundle feature schema does not match the registry entry")
        else:
            try:
                bundle = _bundle_metadata(artifact_path)
                if feature_schema_sha256(bundle["feature_names"]) != entry.get("feature_schema_sha256"):
                    errors.append("artifact feature schema does not match the registry entry")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"could not read artifact feature schema: {exc}")

    policy = entry.get("threshold_policy") or {}
    if not policy.get("name"):
        errors.append("threshold_policy is missing")
    elif policy.get("threshold") is None and "argmax" not in str(policy.get("decision", "")).lower():
        errors.append("threshold_policy has neither a threshold nor an explicit argmax decision")

    if not entry.get("calibration_version"):
        errors.append("calibration_version is missing")
    if entry.get("calibration_artifact"):
        calibration_path = entry["calibration_artifact"]
        if not os.path.isfile(calibration_path):
            candidate = os.path.join(base_dir, calibration_path)
            if os.path.isfile(candidate):
                calibration_path = candidate
            else:
                errors.append(f"calibration artifact does not exist: {entry['calibration_artifact']}")
        if calibration_path and os.path.isfile(calibration_path):
            if sha256_file(calibration_path) != entry.get("calibration_artifact_sha256"):
                errors.append("calibration artifact SHA-256 does not match the registry entry")

    try:
        verify_signature(entry, signing_key)
    except VerificationError as exc:
        errors.append(str(exc))

    if not entry.get("signature"):
        warnings.append("entry is hash-verified only; configure MODEL_SIGNING_KEY to sign entries")
    if entry.get("status") != "approved":
        warnings.append(f"entry status is {entry.get('status')!r}, not 'approved'")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "model_id": entry.get("model_id"),
        "version": entry.get("version"),
        "status": entry.get("status"),
        "artifact_path": artifact_path,
        "artifact_sha256": entry.get("artifact_sha256"),
        "feature_schema_version": entry.get("feature_schema_version"),
        "feature_schema_sha256": entry.get("feature_schema_sha256"),
        "threshold_policy": policy,
        "calibration_version": entry.get("calibration_version"),
        "signature_algorithm": (entry.get("signature") or {}).get("algorithm"),
    }


def approve_model(
    registry_path: str,
    model_id: str,
    version: str,
    approver: str,
    *,
    signing_key: str | bytes | None = None,
    base_dir: str = ".",
) -> dict:
    registry = load_registry(registry_path)
    entry = _get_entry(registry, model_id, version)
    report = verify_entry(entry, base_dir=base_dir, signing_key=signing_key)
    if not report["ok"]:
        raise VerificationError("; ".join(report["errors"]))
    if entry["status"] == "retired":
        raise RegistryError("A retired version cannot be approved; register a new version")
    entry["status"] = "approved"
    entry["approved_at"] = now_utc()
    entry["approved_by"] = approver
    registry["models"][model_id]["history"].append({
        "action": "approve",
        "version": version,
        "at": now_utc(),
        "actor": approver,
        "artifact_sha256": entry["artifact_sha256"],
    })
    save_registry(registry_path, registry)
    return entry


def activate_model(
    registry_path: str,
    model_id: str,
    version: str,
    actor: str,
    *,
    signing_key: str | bytes | None = None,
    base_dir: str = ".",
) -> dict:
    registry = load_registry(registry_path)
    entry = _get_entry(registry, model_id, version)
    if entry["status"] != "approved":
        raise RegistryError("Only an approved version can be activated")
    report = verify_entry(entry, base_dir=base_dir, signing_key=signing_key)
    if not report["ok"]:
        raise VerificationError("; ".join(report["errors"]))
    previous = registry.get("active")
    registry["active"] = {"model_id": model_id, "version": version}
    registry["models"][model_id]["history"].append({
        "action": "activate",
        "version": version,
        "previous": previous,
        "at": now_utc(),
        "actor": actor,
        "artifact_sha256": entry["artifact_sha256"],
    })
    save_registry(registry_path, registry)
    return entry


def rollback_model(
    registry_path: str,
    model_id: str,
    target_version: str,
    actor: str,
    *,
    signing_key: str | bytes | None = None,
    base_dir: str = ".",
) -> dict:
    """Activate a previously approved version and record the rollback."""
    registry = load_registry(registry_path)
    entry = _get_entry(registry, model_id, target_version)
    if entry["status"] != "approved":
        raise RegistryError("Rollback target must be an approved version")
    report = verify_entry(entry, base_dir=base_dir, signing_key=signing_key)
    if not report["ok"]:
        raise VerificationError("; ".join(report["errors"]))
    previous = registry.get("active")
    if previous == {"model_id": model_id, "version": target_version}:
        raise RegistryError("Rollback target is already active")
    registry["active"] = {"model_id": model_id, "version": target_version}
    registry["models"][model_id]["history"].append({
        "action": "rollback",
        "version": target_version,
        "previous": previous,
        "at": now_utc(),
        "actor": actor,
        "artifact_sha256": entry["artifact_sha256"],
    })
    save_registry(registry_path, registry)
    return entry


def active_entry(registry_path: str = DEFAULT_REGISTRY_PATH) -> dict | None:
    registry = load_registry(registry_path)
    active = registry.get("active")
    if not active:
        return None
    return _get_entry(registry, active["model_id"], active["version"])


def resolve_serving_path(
    registry_path: str = DEFAULT_REGISTRY_PATH,
    explicit_path: str | None = None,
    fallback: str = os.path.join("models", "model_bundle_rf_day_based_seed42.pkl"),
) -> str:
    """Return the explicit path, else the active registry artifact, else the evaluated seed 42 bundle."""
    if explicit_path:
        return explicit_path
    if os.path.isfile(registry_path):
        entry = active_entry(registry_path)
        if entry and entry.get("artifact_path"):
            return entry["artifact_path"]
    return fallback


def deployment_check(
    registry_path: str = DEFAULT_REGISTRY_PATH,
    serving_path: str | None = None,
    *,
    model_id: str | None = None,
    signing_key: str | bytes | None = None,
    expected_sha256: str | None = None,
    require_approved: bool = True,
) -> dict:
    """Fail when the serving artifact differs from the approved active artifact."""
    registry = load_registry(registry_path)
    active = registry.get("active")
    if not active:
        raise DeploymentCheckError("Registry has no active model version")
    if model_id is not None and active.get("model_id") != model_id:
        raise DeploymentCheckError(
            f"Active model is {active.get('model_id')}/{active.get('version')}, not {model_id}"
        )
    entry = _get_entry(registry, active["model_id"], active["version"])
    if require_approved and entry.get("status") != "approved":
        raise DeploymentCheckError(
            f"Active model {active['model_id']}/{active['version']} is not approved"
        )
    report = verify_entry(entry, signing_key=signing_key)
    if not report["ok"]:
        raise DeploymentCheckError("Active registry entry failed verification: " + "; ".join(report["errors"]))

    serving_path = serving_path or entry["artifact_path"]
    if not os.path.isfile(serving_path):
        raise DeploymentCheckError(f"Serving artifact does not exist: {serving_path}")
    serving_hash = sha256_file(serving_path)
    if not hmac.compare_digest(serving_hash, entry["artifact_sha256"]):
        raise DeploymentCheckError(
            "Serving artifact SHA-256 does not match the approved active artifact "
            f"({serving_hash} != {entry['artifact_sha256']})"
        )
    if expected_sha256 and not hmac.compare_digest(serving_hash, expected_sha256.strip().lower()):
        raise DeploymentCheckError("Serving artifact does not match MODEL_SHA256")
    bundle = _bundle_metadata(serving_path)
    if feature_schema_sha256(bundle["feature_names"]) != entry["feature_schema_sha256"]:
        raise DeploymentCheckError("Serving artifact feature schema does not match the approved entry")
    if entry["threshold_policy"].get("threshold") is not None:
        if bundle.get("bundle_threshold") is None:
            raise DeploymentCheckError("Approved threshold policy has a threshold but the bundle does not")
        if abs(float(bundle["bundle_threshold"]) - float(entry["threshold_policy"]["threshold"])) > 1e-12:
            raise DeploymentCheckError("Bundle attack threshold does not match the approved threshold policy")

    return {
        "ok": True,
        "registry_path": registry_path,
        "active": active,
        "serving_path": serving_path,
        "serving_sha256": serving_hash,
        "approved_sha256": entry["artifact_sha256"],
        "feature_schema_version": entry["feature_schema_version"],
        "feature_schema_sha256": entry["feature_schema_sha256"],
        "threshold_policy": entry["threshold_policy"],
        "calibration_version": entry["calibration_version"],
        "signature_algorithm": (entry.get("signature") or {}).get("algorithm"),
        "entry": entry,
    }


def registry_status(registry_path: str = DEFAULT_REGISTRY_PATH) -> dict:
    registry = load_registry(registry_path)
    active = registry.get("active")
    models = {}
    for model_id, model in registry.get("models", {}).items():
        models[model_id] = {
            version: {
                "status": entry.get("status"),
                "role": entry.get("role"),
                "artifact_path": entry.get("artifact_path"),
                "artifact_sha256": entry.get("artifact_sha256"),
                "feature_schema_version": entry.get("feature_schema_version"),
                "threshold_policy": entry.get("threshold_policy"),
                "calibration_version": entry.get("calibration_version"),
                "approved_by": entry.get("approved_by"),
                "approved_at": entry.get("approved_at"),
                "verification": entry.get("verification"),
            }
            for version, entry in model.get("versions", {}).items()
        }
    return {"schema_version": registry.get("schema_version"), "active": active, "models": models}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default=DEFAULT_REGISTRY_PATH)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    register = sub.add_parser("register", help="Register a candidate version")
    register.add_argument("--model-id", required=True)
    register.add_argument("--version", required=True)
    register.add_argument("--artifact", required=True)
    register.add_argument("--role", choices=["serving", "research"], default="research")
    register.add_argument("--threshold", type=float)
    register.add_argument("--max-fpr", type=float)
    register.add_argument("--threshold-name", default="global_validation_max_fpr")
    register.add_argument("--calibration-version", default="uncalibrated")
    register.add_argument("--calibration-method", default="none")
    register.add_argument("--calibration-artifact")
    register.add_argument("--created-by", default="operator")
    register.add_argument("--notes", default="")
    register.add_argument("--signing-key")

    approve = sub.add_parser("approve", help="Approve a verified version")
    approve.add_argument("--model-id", required=True)
    approve.add_argument("--version", required=True)
    approve.add_argument("--approver", required=True)
    approve.add_argument("--signing-key")

    activate = sub.add_parser("activate", help="Activate an approved version")
    activate.add_argument("--model-id", required=True)
    activate.add_argument("--version", required=True)
    activate.add_argument("--actor", required=True)
    activate.add_argument("--signing-key")

    rollback = sub.add_parser("rollback", help="Activate a previous approved version")
    rollback.add_argument("--model-id", required=True)
    rollback.add_argument("--to-version", required=True)
    rollback.add_argument("--actor", required=True)
    rollback.add_argument("--signing-key")

    verify = sub.add_parser("verify", help="Verify one entry")
    verify.add_argument("--model-id", required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--signing-key")

    sub.add_parser("status", help="Show registry status")

    check = sub.add_parser("deployment-check", help="Compare serving artifact to active entry")
    check.add_argument("--serving-path", required=True)
    check.add_argument("--model-id")
    check.add_argument("--expected-sha256")
    check.add_argument("--signing-key")

    args = parser.parse_args()
    if args.command == "register":
        policy = {
            "name": args.threshold_name,
            "threshold": args.threshold,
            "max_fpr": args.max_fpr,
            "selected_on": "validation",
            "score": "1 - P(BENIGN)",
            "decision": "attack_score >= threshold" if args.threshold is not None else "argmax predicted class != BENIGN",
        }
        entry = register_model(
            args.registry, args.model_id, args.version, args.artifact,
            role=args.role,
            threshold_policy=policy,
            calibration_version=args.calibration_version,
            calibration_method=args.calibration_method,
            calibration_artifact=args.calibration_artifact,
            created_by=args.created_by,
            signing_key=args.signing_key,
            notes=args.notes,
        )
        output = {"registered": entry["model_id"], "version": entry["version"], "artifact_sha256": entry["artifact_sha256"]}
    elif args.command == "approve":
        entry = approve_model(args.registry, args.model_id, args.version, args.approver, signing_key=args.signing_key)
        output = {"approved": entry["model_id"], "version": entry["version"]}
    elif args.command == "activate":
        entry = activate_model(args.registry, args.model_id, args.version, args.actor, signing_key=args.signing_key)
        output = {"active": entry["model_id"], "version": entry["version"]}
    elif args.command == "rollback":
        entry = rollback_model(args.registry, args.model_id, args.to_version, args.actor, signing_key=args.signing_key)
        output = {"rolled_back_to": entry["model_id"], "version": entry["version"]}
    elif args.command == "verify":
        registry = load_registry(args.registry)
        entry = _get_entry(registry, args.model_id, args.version)
        output = verify_entry(entry, signing_key=args.signing_key)
        if not output["ok"]:
            print(json.dumps(output, indent=2) if args.json else "; ".join(output["errors"]), file=sys.stderr)
            return 1
    elif args.command == "status":
        output = registry_status(args.registry)
    else:
        output = deployment_check(
            args.registry, args.serving_path, model_id=args.model_id,
            signing_key=args.signing_key, expected_sha256=args.expected_sha256,
        )
        output.pop("entry", None)
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
