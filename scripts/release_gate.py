#!/usr/bin/env python3
"""S8 release gate: aggregate the evidence required for a 9/10 claim.

The gate is deliberately conservative. It passes only when every required
artifact exists, is machine-readable, and reports a passing state. A missing
external artifact is reported as ``blocked`` rather than silently skipped.

The gate never edits evidence and never infers a pass from prose. If a claim
cannot be checked from a machine-readable file, the check stays blocked.

Usage:
    python scripts/release_gate.py
    python scripts/release_gate.py --json docs/s8_release_gate.json
    python scripts/release_gate.py --skip-deployment

Exit codes:
    0  every check passed
    1  at least one check failed or is blocked
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

PASS = "pass"
FAIL = "fail"
BLOCKED = "blocked"


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError):
        return None


def _check(check_id, requirement, source, status, observed, detail, remediation):
    return {
        "id": check_id,
        "requirement": requirement,
        "source": source,
        "status": status,
        "pass": status == PASS,
        "observed": observed,
        "detail": detail,
        "remediation": remediation,
    }


def _missing(check_id, requirement, source, detail, remediation):
    return _check(
        check_id,
        requirement,
        source,
        BLOCKED,
        "missing evidence file",
        detail,
        remediation,
    )


def _detection_check(root, d9):
    source = "docs/COST_SENSITIVE_RESULTS.json"
    if d9 is None:
        return _missing(
            "detection_gate",
            "The D9 cost-sensitive detection gate must pass.",
            source,
            "The machine-readable D9 result is absent or unreadable.",
            "Re-run scripts/cost_sensitive_eval.py and commit the result.",
        )
    gate = d9.get("release_gate") or {}
    failed = [row.get("id") for row in gate.get("checks", []) if not row.get("pass")]
    passed = gate.get("passed") is True and not failed
    return _check(
        "detection_gate",
        "The D9 cost-sensitive detection gate must pass on every check.",
        source,
        PASS if passed else FAIL,
        gate.get("verdict") or "no verdict",
        (
            "All D9 detection checks pass."
            if passed
            else "Failed D9 checks: " + ", ".join(str(item) for item in failed)
        ),
        "Resolve the failed D9 checks in docs/COST_MODEL_AND_RELEASE_GATE.md. "
        "Do not raise the detection score until they pass.",
    )


def _artifact_check(d9, deployment_report):
    source = "scripts/deployment_check.py + docs/COST_SENSITIVE_RESULTS.json"
    requirement = (
        "The served artifact must be the artifact that was evaluated and gated, "
        "and the deployment hash check must pass."
    )
    if deployment_report is None:
        return _missing(
            "artifact_identity",
            requirement,
            source,
            "Deployment check was skipped or produced no report.",
            "Run scripts/deployment_check.py against the approved registry entry.",
        )
    deployment_ok = deployment_report.get("ok") is True
    d9_identity = next(
        (
            row
            for row in (d9 or {}).get("release_gate", {}).get("checks", [])
            if row.get("id") == "artifact_identity"
        ),
        None,
    )
    identity_ok = bool(d9_identity and d9_identity.get("pass"))
    observed = deployment_report.get("serving_sha256") or deployment_report.get("error") or "unknown"
    if not deployment_ok:
        detail = f"Deployment check failed: {deployment_report.get('error', 'unknown error')}"
    elif not identity_ok:
        detail = (
            "The deployment hash matches the registry, but the served artifact is not "
            "the artifact described by the detection evaluation: "
            + str((d9_identity or {}).get("observed", "not reported"))
        )
    else:
        detail = "Serving hash, registry entry, and evaluated artifact agree."
    return _check(
        "artifact_identity",
        requirement,
        source,
        PASS if deployment_ok and identity_ok else FAIL,
        observed,
        detail,
        "Serve, evaluate, and gate the same artifact before any release claim.",
    )


def _security_check(root, security):
    source = "docs/security_gate.json"
    if security is None:
        return _missing(
            "security_gate",
            "The container security gate must pass with no actionable findings.",
            source,
            "The security gate result is absent or unreadable.",
            "Rebuild and rescan the image, then run scripts/security_gate.py.",
        )
    critical = len(security.get("critical") or [])
    fixable = len(security.get("fixable") or [])
    secrets = len(security.get("secrets") or [])
    misconfigurations = len(security.get("misconfigurations") or [])
    passed = (
        security.get("passed") is True
        and critical == 0
        and fixable == 0
        and secrets == 0
        and misconfigurations == 0
    )
    return _check(
        "security_gate",
        "No critical, fixable, secret, or failed-misconfiguration findings.",
        source,
        PASS if passed else FAIL,
        {
            "critical": critical,
            "fixable": fixable,
            "secrets": secrets,
            "misconfigurations": misconfigurations,
            "unfixed_baseline_total": security.get("unfixed_baseline_total", 0),
        },
        (
            "The security gate passes. Unfixed base-image advisories remain accepted risk."
            if passed
            else "Actionable container findings are present."
        ),
        "Fix every actionable finding and rebuild the image.",
    )


def _secret_check(root, secret_scan):
    source = "docs/secret_scan.json"
    if secret_scan is None:
        return _missing(
            "secret_scan",
            "The git-visible working tree must contain no detected secrets.",
            source,
            "The secret scan result is absent or unreadable.",
            "Run scripts/secret_scan.py and commit the result.",
        )
    count = int(secret_scan.get("finding_count", 0) or 0)
    return _check(
        "secret_scan",
        "The git-visible working tree must contain no detected secrets.",
        source,
        PASS if count == 0 else FAIL,
        {
            "finding_count": count,
            "files_scanned": secret_scan.get("files_scanned"),
            "tracked_files_scanned": secret_scan.get("tracked_files_scanned"),
            "untracked_files_scanned": secret_scan.get("untracked_files_scanned"),
        },
        "No secrets detected in git-visible files." if count == 0 else "Secret findings are present.",
        "Remove and rotate every detected credential, then rescan.",
    )


def _external_review_check(root):
    source = "docs/s8_external_review.json"
    review = _load_json(os.path.join(root, source))
    if review is None:
        return _missing(
            "external_review",
            "An external security and readiness review must be completed and critical/high findings closed.",
            source,
            "No external review record exists. The review has not been commissioned.",
            "Commission an external reviewer and record scope, findings, and closure.",
        )
    status = str(review.get("status", "unknown")).lower()
    critical_open = int(review.get("critical_open", 0) or 0)
    high_open = int(review.get("high_open", 0) or 0)
    passed = status == "completed" and critical_open == 0 and high_open == 0
    if status != "completed":
        state = BLOCKED
    else:
        state = PASS if passed else FAIL
    return _check(
        "external_review",
        "An external security and readiness review must be completed and critical/high findings closed.",
        source,
        state,
        {
            "status": status,
            "reviewer": review.get("reviewer"),
            "critical_open": critical_open,
            "high_open": high_open,
            "report": review.get("report"),
        },
        (
            "External review completed with no open critical/high findings."
            if passed
            else "The external review is not complete or has open critical/high findings."
        ),
        "Track every finding to closure and publish the signed review report.",
    )


def _pilot_check(root):
    source = "docs/s7_pilot_analysis.json"
    pilot = _load_json(os.path.join(root, source))
    if pilot is None:
        return _missing(
            "prospective_pilot",
            "A real human-review pilot must be completed against predeclared criteria.",
            source,
            "No real pilot result exists. Synthetic self-tests are not evidence.",
            "Recruit a consenting design partner and run the pre-registered pilot.",
        )
    evidence_status = str(pilot.get("evidence_status", "")).upper()
    synthetic = "SYNTHETIC" in evidence_status or "SELFTEST" in str(pilot.get("verdict", "")).upper()
    verdict = str(pilot.get("verdict", "")).upper()
    reviewed = int((pilot.get("summary") or {}).get("reviewed_alerts", 0) or 0)
    passed = not synthetic and verdict == "PASS" and reviewed >= 300
    if synthetic:
        state = FAIL
    else:
        state = PASS if passed else FAIL
    return _check(
        "prospective_pilot",
        "A real human-review pilot must be completed against predeclared criteria.",
        source,
        state,
        {"evidence_status": evidence_status, "verdict": verdict, "reviewed_alerts": reviewed},
        (
            "Real pilot completed and passed the predeclared criteria."
            if passed
            else "The pilot is synthetic, incomplete, or below the predeclared sample size."
        ),
        "Run the S7 pilot and publish real dispositions, review times, and support load.",
    )


def _slo_check(root):
    source = "docs/load_test_results.json"
    load = _load_json(os.path.join(root, source))
    if load is None:
        return _missing(
            "slo_compliance",
            "Measured ingest p95 must be <= 250 ms at 20 flows/s with >= 99.5% success.",
            source,
            "The load-test result is absent or unreadable.",
            "Run scripts/load_test.py at the declared SLO rate.",
        )
    step = next(
        (row for row in load.get("steps", []) if float(row.get("declared_flow_rate") or 0) == 20.0),
        None,
    )
    if step is None:
        return _missing(
            "slo_compliance",
            "Measured ingest p95 must be <= 250 ms at 20 flows/s with >= 99.5% success.",
            source,
            "No 20 flows/s step exists in the load test.",
            "Add a 20 flows/s step to the load test.",
        )
    p95 = float((step.get("latency_ms") or {}).get("p95", 0) or 0)
    success = float(step.get("success_ratio", 0) or 0)
    passed = p95 <= 250.0 and success >= 0.995
    return _check(
        "slo_compliance",
        "Measured ingest p95 must be <= 250 ms at 20 flows/s with >= 99.5% success.",
        source,
        PASS if passed else FAIL,
        {"declared_flow_rate": 20.0, "p95_ms": p95, "success_ratio": success},
        (
            "The measured ingest SLO is met."
            if passed
            else "The measured service fails its own ingest SLO."
        ),
        "Fix persistence latency and backpressure before claiming production readiness.",
    )


def _backup_check(root):
    local_source = "docs/backup_restore_drill.json"
    encrypted_source = "docs/encrypted_backup_drill.json"
    drill = _load_json(os.path.join(root, local_source))
    encrypted = _load_json(os.path.join(root, encrypted_source))
    if drill is None:
        return _missing(
            "backup_restore",
            "Local and encrypted backup/restore drills must pass with integrity and count checks.",
            local_source,
            "The local drill result is absent or unreadable.",
            "Run scripts/backup_restore_drill.py.",
        )
    if encrypted is None:
        return _missing(
            "backup_restore",
            "Local and encrypted backup/restore drills must pass with integrity and count checks.",
            encrypted_source,
            "The encrypted drill result is absent or unreadable.",
            "Run scripts/backup_encrypted.py.",
        )
    checks = drill.get("checks") or {}
    encrypted_checks = encrypted.get("checks") or {}
    required_encrypted = {
        name: value
        for name, value in encrypted_checks.items()
        if name != "offsite_hash_matches" and value is not None
    }
    passed = (
        drill.get("status") == "pass"
        and bool(checks)
        and all(checks.values())
        and encrypted.get("status") == "pass"
        and bool(required_encrypted)
        and all(required_encrypted.values())
        and encrypted_checks.get("offsite_hash_matches") is not False
    )
    return _check(
        "backup_restore",
        "Local and encrypted backup/restore drills must pass with integrity and count checks.",
        f"{local_source}; {encrypted_source}",
        PASS if passed else FAIL,
        {
            "local_status": drill.get("status"),
            "local_checks": checks,
            "encrypted_status": encrypted.get("status"),
            "encrypted_checks": encrypted_checks,
        },
        (
            "The local and encrypted backup/restore drills pass. Operated off-host durability and site RPO/RTO remain unproven."
            if passed
            else "A backup/restore drill is incomplete or failed."
        ),
        "Fix the restore path. Production also needs operated off-host storage and measured RPO/RTO.",
    )


def _sbom_check(root):
    source = "docs/sbom.cdx.json"
    sbom = _load_json(os.path.join(root, source))
    if sbom is None:
        return _missing(
            "sbom",
            "A CycloneDX SBOM must exist and contain components.",
            source,
            "The SBOM is absent or unreadable.",
            "Generate an SBOM with syft and commit it.",
        )
    components = len(sbom.get("components") or [])
    passed = str(sbom.get("bomFormat", "")).lower() == "cyclonedx" and components > 0
    return _check(
        "sbom",
        "A CycloneDX SBOM must exist and contain components.",
        source,
        PASS if passed else FAIL,
        {"bomFormat": sbom.get("bomFormat"), "components": components},
        "SBOM present with components." if passed else "The SBOM is empty or malformed.",
        "Regenerate the SBOM from the built image.",
    )


def _deployment_report(root):
    try:
        from training.model_registry import (
            DEFAULT_REGISTRY_PATH,
            DeploymentCheckError,
            RegistryError,
            deployment_check,
            resolve_serving_path,
        )
    except Exception as exc:  # noqa: BLE001 - report, do not crash the gate
        return {"ok": False, "error": f"registry module unavailable: {exc}"}

    registry_path = os.environ.get("MODEL_REGISTRY_PATH", DEFAULT_REGISTRY_PATH)
    serving_path = resolve_serving_path(
        registry_path, os.environ.get("MODEL_ARTIFACT_PATH") or None
    )
    try:
        report = deployment_check(registry_path, serving_path)
    except (DeploymentCheckError, RegistryError) as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"deployment check raised: {exc}"}
    report.pop("entry", None)
    return report


def evaluate(root=None, *, deployment_report=None, check_deployment=True):
    """Return the full gate verdict for a repository root."""
    root = os.path.abspath(root or PROJECT_ROOT)
    d9 = _load_json(os.path.join(root, "docs", "COST_SENSITIVE_RESULTS.json"))
    security = _load_json(os.path.join(root, "docs", "security_gate.json"))
    secret_scan = _load_json(os.path.join(root, "docs", "secret_scan.json"))

    if deployment_report is None and check_deployment:
        deployment_report = _deployment_report(root)

    checks = [
        _detection_check(root, d9),
        _artifact_check(d9, deployment_report),
        _security_check(root, security),
        _secret_check(root, secret_scan),
        _external_review_check(root),
        _pilot_check(root),
        _slo_check(root),
        _backup_check(root),
        _sbom_check(root),
    ]

    statuses = {row["status"] for row in checks}
    if FAIL in statuses:
        verdict = "FAIL"
    elif BLOCKED in statuses:
        verdict = "BLOCKED"
    else:
        verdict = "PASS"

    return {
        "phase": "S8",
        "gate": "9/10 detection and SaaS readiness claim",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo_root": root,
        "verdict": verdict,
        "passed": verdict == "PASS",
        "counts": {
            "checks": len(checks),
            "pass": sum(1 for row in checks if row["status"] == PASS),
            "fail": sum(1 for row in checks if row["status"] == FAIL),
            "blocked": sum(1 for row in checks if row["status"] == BLOCKED),
        },
        "checks": checks,
        "consequence": (
            "No 9/10 detection or SaaS readiness claim is allowed. "
            "Keep detection at 4/10 and production SaaS at 3/10 until every check passes."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=PROJECT_ROOT)
    parser.add_argument("--json", dest="json_path", help="Optional verdict output path")
    parser.add_argument(
        "--skip-deployment",
        action="store_true",
        help="Do not run the serving-artifact deployment check (marks it blocked).",
    )
    args = parser.parse_args(argv)

    verdict = evaluate(args.repo_root, check_deployment=not args.skip_deployment)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(verdict, handle, indent=2, sort_keys=True)
            handle.write("\n")

    print(f"S8 release gate: {verdict['verdict']} ({verdict['counts']})")
    for row in verdict["checks"]:
        print(f"  [{row['status'].upper():7}] {row['id']}: {row['detail']}")
    print(verdict["consequence"])
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
