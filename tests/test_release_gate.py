"""Tests for the S8 release gate (scripts/release_gate.py)."""

import json
import subprocess
import sys
from pathlib import Path

from scripts.release_gate import evaluate

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _passing_evidence(root):
    docs = root / "docs"
    _write(
        docs / "COST_SENSITIVE_RESULTS.json",
        {
            "release_gate": {
                "passed": True,
                "verdict": "PASS",
                "checks": [{"id": "artifact_identity", "pass": True}],
            }
        },
    )
    _write(
        docs / "security_gate.json",
        {
            "passed": True,
            "critical": [],
            "fixable": [],
            "secrets": [],
            "misconfigurations": [],
            "unfixed_baseline_total": 0,
        },
    )
    _write(docs / "secret_scan.json", {"finding_count": 0, "tracked_files_scanned": 10})
    _write(
        docs / "s8_external_review.json",
        {"status": "completed", "critical_open": 0, "high_open": 0, "reviewer": "reviewer", "report": "report.pdf"},
    )
    _write(
        docs / "s7_pilot_analysis.json",
        {"evidence_status": "REAL PILOT", "verdict": "PASS", "summary": {"reviewed_alerts": 300}},
    )
    _write(
        docs / "load_test_results.json",
        {"steps": [{"declared_flow_rate": 20.0, "latency_ms": {"p95": 200.0}, "success_ratio": 0.999}]},
    )
    _write(docs / "backup_restore_drill.json", {"status": "pass", "checks": {"integrity": True}})
    _write(
        docs / "encrypted_backup_drill.json",
        {
            "status": "pass",
            "checks": {
                "source_integrity_ok": True,
                "backup_integrity_ok": True,
                "decrypted_hash_matches_backup": True,
                "restored_integrity_ok": True,
                "offsite_hash_matches": True,
            },
        },
    )
    _write(docs / "sbom.cdx.json", {"bomFormat": "CycloneDX", "components": [{"name": "pkg"}]})


def test_all_checks_pass(tmp_path):
    _passing_evidence(tmp_path)
    verdict = evaluate(tmp_path, deployment_report={"ok": True})
    assert verdict["verdict"] == "PASS"
    assert verdict["passed"] is True
    assert verdict["counts"] == {"checks": 9, "pass": 9, "fail": 0, "blocked": 0}


def test_missing_external_review_is_blocked(tmp_path):
    _passing_evidence(tmp_path)
    (tmp_path / "docs" / "s8_external_review.json").unlink()
    verdict = evaluate(tmp_path, deployment_report={"ok": True})
    assert verdict["verdict"] == "BLOCKED"
    review = next(row for row in verdict["checks"] if row["id"] == "external_review")
    assert review["status"] == "blocked"


def test_failing_detection_gate_fails(tmp_path):
    _passing_evidence(tmp_path)
    _write(
        tmp_path / "docs" / "COST_SENSITIVE_RESULTS.json",
        {
            "release_gate": {
                "passed": False,
                "verdict": "FAIL",
                "checks": [{"id": "artifact_identity", "pass": False}],
            }
        },
    )
    verdict = evaluate(tmp_path, deployment_report={"ok": True})
    assert verdict["verdict"] == "FAIL"
    detection = next(row for row in verdict["checks"] if row["id"] == "detection_gate")
    assert detection["status"] == "fail"


def test_deployment_failure_fails_artifact_identity(tmp_path):
    _passing_evidence(tmp_path)
    verdict = evaluate(tmp_path, deployment_report={"ok": False, "error": "hash mismatch"})
    assert verdict["verdict"] == "FAIL"
    artifact = next(row for row in verdict["checks"] if row["id"] == "artifact_identity")
    assert artifact["status"] == "fail"
    assert "hash mismatch" in artifact["detail"]


def test_synthetic_pilot_is_rejected(tmp_path):
    _passing_evidence(tmp_path)
    _write(
        tmp_path / "docs" / "s7_pilot_analysis.json",
        {"evidence_status": "SYNTHETIC SELF-TEST", "verdict": "SELFTEST_ONLY", "summary": {"reviewed_alerts": 440}},
    )
    verdict = evaluate(tmp_path, deployment_report={"ok": True})
    pilot = next(row for row in verdict["checks"] if row["id"] == "prospective_pilot")
    assert pilot["status"] == "fail"
    assert verdict["verdict"] == "FAIL"


def test_missing_encrypted_backup_drill_is_blocked(tmp_path):
    _passing_evidence(tmp_path)
    (tmp_path / "docs" / "encrypted_backup_drill.json").unlink()
    verdict = evaluate(tmp_path, deployment_report={"ok": True})
    backup = next(row for row in verdict["checks"] if row["id"] == "backup_restore")
    assert backup["status"] == "blocked"
    assert verdict["verdict"] == "BLOCKED"


def test_failed_encrypted_backup_checks_fail(tmp_path):
    _passing_evidence(tmp_path)
    _write(
        tmp_path / "docs" / "encrypted_backup_drill.json",
        {"status": "fail", "checks": {"decrypted_hash_matches_backup": False}},
    )
    verdict = evaluate(tmp_path, deployment_report={"ok": True})
    backup = next(row for row in verdict["checks"] if row["id"] == "backup_restore")
    assert backup["status"] == "fail"
    assert verdict["verdict"] == "FAIL"


def test_cli_exit_codes(tmp_path):
    _passing_evidence(tmp_path)
    output = tmp_path / "gate.json"
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "release_gate.py"),
            "--repo-root",
            str(tmp_path),
            "--skip-deployment",
            "--json",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    # Deployment is blocked when skipped, so the gate cannot pass.
    assert result.returncode == 1
    verdict = json.loads(output.read_text(encoding="utf-8"))
    artifact = next(row for row in verdict["checks"] if row["id"] == "artifact_identity")
    assert artifact["status"] == "blocked"
