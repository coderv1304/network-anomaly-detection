"""Tests for the container security gate (scripts/security_gate.py)."""

import json
import subprocess
import sys
from pathlib import Path

from scripts.security_gate import evaluate

REPO_ROOT = Path(__file__).resolve().parent.parent


def _report(vulnerabilities=None, secrets=None, misconfigurations=None):
    return {
        "Results": [
            {
                "Target": "test-image (debian 13)",
                "Class": "os-pkgs",
                "Vulnerabilities": vulnerabilities or [],
                "Secrets": secrets or [],
                "Misconfigurations": misconfigurations or [],
            }
        ]
    }


def test_clean_report_passes():
    verdict = evaluate(_report())
    assert verdict["passed"] is True
    assert verdict["unfixed_baseline_total"] == 0


def test_unfixed_os_findings_are_reported_but_do_not_fail():
    verdict = evaluate(
        _report(
            vulnerabilities=[
                {
                    "VulnerabilityID": "CVE-2099-0001",
                    "Severity": "HIGH",
                    "PkgName": "util-linux",
                    "InstalledVersion": "1.0",
                }
            ]
        )
    )
    assert verdict["passed"] is True
    assert verdict["unfixed_baseline_total"] == 1
    assert verdict["unfixed_baseline"]["os-pkgs:HIGH"] == 1


def test_fixable_and_critical_findings_fail():
    verdict = evaluate(
        _report(
            vulnerabilities=[
                {
                    "VulnerabilityID": "CVE-2099-0002",
                    "Severity": "MEDIUM",
                    "PkgName": "example",
                    "InstalledVersion": "1.0",
                    "FixedVersion": "1.1",
                },
                {
                    "VulnerabilityID": "CVE-2099-0003",
                    "Severity": "CRITICAL",
                    "PkgName": "example",
                    "InstalledVersion": "1.0",
                },
            ]
        )
    )
    assert verdict["passed"] is False
    assert len(verdict["fixable"]) == 1
    assert len(verdict["critical"]) == 1


def test_secrets_and_failed_misconfigurations_fail():
    verdict = evaluate(
        _report(
            secrets=[{"RuleID": "aws-key", "Title": "AWS key", "StartLine": 3}],
            misconfigurations=[
                {"ID": "DS-0001", "Severity": "HIGH", "Status": "FAIL"},
                {"ID": "DS-0002", "Severity": "LOW", "Status": "PASS"},
            ],
        )
    )
    assert verdict["passed"] is False
    assert len(verdict["secrets"]) == 1
    assert len(verdict["misconfigurations"]) == 1


def test_cli_exit_codes_and_json_output(tmp_path):
    report_path = tmp_path / "trivy.json"
    output_path = tmp_path / "gate.json"
    report_path.write_text(json.dumps(_report()), encoding="utf-8")

    passing = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "security_gate.py"),
            "--report",
            str(report_path),
            "--json",
            str(output_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert passing.returncode == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["passed"] is True

    report_path.write_text(
        json.dumps(
            _report(
                vulnerabilities=[
                    {
                        "VulnerabilityID": "CVE-2099-0004",
                        "Severity": "HIGH",
                        "PkgName": "runtime",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                    }
                ]
            )
        ),
        encoding="utf-8",
    )
    failing = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "security_gate.py"),
            "--report",
            str(report_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert failing.returncode == 1
    assert "FAIL" in failing.stdout
