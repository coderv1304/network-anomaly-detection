#!/usr/bin/env python3
"""Fail a release on actionable container findings.

This gate is deliberately narrow. It fails on findings an engineer can fix
today and reports the rest:

* fail: any CRITICAL vulnerability
* fail: any vulnerability with a fixed version available (HIGH, MEDIUM, or LOW)
* fail: any secret
* fail: any misconfiguration whose status is not PASS

Unfixed OS-package findings inherited from the official base image do not fail
the build, but they are counted and printed. That keeps the baseline visible
instead of hiding it in an ignore file. The base image is refreshed by rebuilding
on a schedule; see docs/SECURITY_AND_COMPLIANCE.md.

Usage:
    python scripts/security_gate.py --report docs/trivy_image.json
    python scripts/security_gate.py --report docs/trivy_image.json \\
        --json docs/security_gate.json

Exit codes:
    0  no actionable findings
    1  actionable findings present (or the report is unreadable)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone


def evaluate(report: dict) -> dict:
    """Return a structured verdict for a Trivy JSON report."""
    critical = []
    fixable = []
    unfixed = Counter()
    secrets = []
    misconfigurations = []

    for result in report.get("Results", []):
        target = result.get("Target", "unknown")
        class_ = result.get("Class", "unknown")

        for secret in result.get("Secrets") or []:
            secrets.append(
                {
                    "target": target,
                    "rule": secret.get("RuleID"),
                    "title": secret.get("Title"),
                    "line": secret.get("StartLine"),
                }
            )

        for misconfig in result.get("Misconfigurations") or []:
            if misconfig.get("Status") == "PASS":
                continue
            misconfigurations.append(
                {
                    "target": target,
                    "id": misconfig.get("ID"),
                    "severity": misconfig.get("Severity"),
                    "title": misconfig.get("Title"),
                    "status": misconfig.get("Status"),
                }
            )

        for vuln in result.get("Vulnerabilities") or []:
            entry = {
                "target": target,
                "class": class_,
                "id": vuln.get("VulnerabilityID"),
                "severity": vuln.get("Severity"),
                "package": vuln.get("PkgName"),
                "installed": vuln.get("InstalledVersion"),
                "fixed": vuln.get("FixedVersion"),
                "status": vuln.get("Status"),
            }
            if vuln.get("Severity") == "CRITICAL":
                critical.append(entry)
            if vuln.get("FixedVersion"):
                fixable.append(entry)
            else:
                unfixed[(class_, vuln.get("Severity"))] += 1

    actionable = bool(critical or fixable or secrets or misconfigurations)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not actionable,
        "critical": critical,
        "fixable": fixable,
        "unfixed_baseline": {
            f"{class_}:{severity}": count
            for (class_, severity), count in sorted(unfixed.items())
        },
        "unfixed_baseline_total": sum(unfixed.values()),
        "secrets": secrets,
        "misconfigurations": misconfigurations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, help="Trivy JSON report path")
    parser.add_argument("--json", dest="json_path", help="Optional verdict output path")
    args = parser.parse_args()

    try:
        with open(args.report, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError) as err:
        print(f"[security-gate] cannot read {args.report}: {err}", file=sys.stderr)
        return 1

    verdict = evaluate(report)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(verdict, handle, indent=2)
            handle.write("\n")

    print(f"[security-gate] report: {args.report}")
    print(f"[security-gate] critical: {len(verdict['critical'])}")
    print(f"[security-gate] fixable:  {len(verdict['fixable'])}")
    print(f"[security-gate] secrets:   {len(verdict['secrets'])}")
    print(f"[security-gate] misconfig: {len(verdict['misconfigurations'])}")
    print(
        "[security-gate] unfixed baseline: "
        f"{verdict['unfixed_baseline_total']} "
        f"{dict(verdict['unfixed_baseline'])}"
    )

    for entry in verdict["critical"]:
        print(f"  CRITICAL {entry['id']} {entry['package']} ({entry['target']})")
    for entry in verdict["fixable"]:
        print(
            f"  FIXABLE {entry['severity']} {entry['id']} {entry['package']} "
            f"{entry['installed']} -> {entry['fixed']}"
        )
    for entry in verdict["secrets"]:
        print(f"  SECRET {entry['rule']} {entry['target']}:{entry['line']}")
    for entry in verdict["misconfigurations"]:
        print(f"  MISCONFIG {entry['id']} {entry['severity']} {entry['target']}")

    if verdict["passed"]:
        print("[security-gate] PASS: no actionable findings")
        return 0
    print("[security-gate] FAIL: actionable findings must be fixed or reclassified")
    return 1


if __name__ == "__main__":
    sys.exit(main())
