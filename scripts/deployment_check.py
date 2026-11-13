"""Deployment gate: fail when the serving artifact is not the approved artifact.

This wrapper is meant to run in CI and in the container entrypoint before the
application accepts traffic. It exits non-zero on any mismatch so a deployment
cannot silently serve an unapproved, tampered, or schema-mismatched artifact.

Usage:
    python scripts/deployment_check.py
    python scripts/deployment_check.py --serving-path models/model_bundle_rf_day_based_seed42.pkl
    python scripts/deployment_check.py --json

Environment:
    MODEL_REGISTRY_PATH   default models/registry/registry.json
    MODEL_SIGNING_KEY     required only when registry entries are signed
    MODEL_SHA256          optional additional pin
"""

from __future__ import annotations

import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.model_registry import (  # noqa: E402
    DEFAULT_REGISTRY_PATH,
    DeploymentCheckError,
    RegistryError,
    deployment_check,
    resolve_serving_path,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--registry",
        default=os.environ.get("MODEL_REGISTRY_PATH", DEFAULT_REGISTRY_PATH),
    )
    parser.add_argument(
        "--serving-path",
        default=resolve_serving_path(
            os.environ.get("MODEL_REGISTRY_PATH", DEFAULT_REGISTRY_PATH),
            os.environ.get("MODEL_ARTIFACT_PATH") or None,
        ),
    )
    parser.add_argument("--model-id", default=None)
    parser.add_argument("--expected-sha256", default=os.environ.get("MODEL_SHA256") or None)
    parser.add_argument("--signing-key", default=os.environ.get("MODEL_SIGNING_KEY") or None)
    parser.add_argument("--allow-unapproved", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        report = deployment_check(
            args.registry,
            args.serving_path,
            model_id=args.model_id,
            signing_key=args.signing_key,
            expected_sha256=args.expected_sha256,
            require_approved=not args.allow_unapproved,
        )
    except (DeploymentCheckError, RegistryError) as exc:
        message = {"ok": False, "error": str(exc)}
        if args.json:
            print(json.dumps(message, indent=2, sort_keys=True))
        else:
            print(f"DEPLOYMENT CHECK FAILED: {exc}", file=sys.stderr)
        return 1

    report.pop("entry", None)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("Deployment check passed.")
        print(f"  active:            {report['active']['model_id']}/{report['active']['version']}")
        print(f"  serving artifact:  {report['serving_path']}")
        print(f"  serving sha256:    {report['serving_sha256']}")
        print(f"  approved sha256:   {report['approved_sha256']}")
        print(f"  feature schema:    {report['feature_schema_version']}")
        print(f"  threshold policy:  {report['threshold_policy'].get('name')}")
        print(f"  threshold:         {report['threshold_policy'].get('threshold')}")
        print(f"  calibration:       {report['calibration_version']}")
        print(f"  signature:         {report.get('signature_algorithm') or 'hash-verified only'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
