"""Scan git-visible files for likely committed secrets.

This is a conservative, reproducible check, not a replacement for a dedicated
secret scanner. Trivy's secret scanner is also run in the S4 security scan.
The script scans tracked files plus untracked files that are not gitignored, so
new work in the working tree is covered before it is committed. Ignored files
such as `.env`, `instance/`, `venv/`, and backups remain out of scope.

Usage:
    python scripts/secret_scan.py
    python scripts/secret_scan.py --json docs/secret_scan.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    (
        "generic_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*"
            r"['\"]([^'\"]{12,})['\"]"
        ),
    ),
]

ALLOW_VALUE_FRAGMENTS = (
    "replace",
    "placeholder",
    "changeme",
    "example",
    "test",
    "not-used",
    "dummy",
    "your-",
    "xxxx",
    "${",
    "{{",
    "<",
    "correct horse",
)

SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".svg",
    ".pkl",
    ".npz",
    ".pdf",
    ".woff",
    ".woff2",
    ".ttf",
}


def _git_files(*args: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _candidate_files() -> tuple[list[str], list[str]]:
    tracked = _git_files("--cached")
    untracked = _git_files("--others", "--exclude-standard")
    candidates = sorted(set(tracked) | set(untracked))
    return candidates, untracked


def scan() -> dict:
    findings = []
    scanned = 0
    candidates, untracked = _candidate_files()
    untracked_set = set(untracked)
    untracked_count = 0
    for relative in candidates:
        if os.path.splitext(relative)[1].lower() in SKIP_SUFFIXES:
            continue
        path = os.path.join(PROJECT_ROOT, relative)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
        except OSError:
            continue
        scanned += 1
        if relative in untracked_set:
            untracked_count += 1
        for line_number, line in enumerate(lines, start=1):
            if len(line) > 4000:
                continue
            for rule, pattern in PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                value = match.group(1) if match.groups() else match.group(0)
                lowered = value.lower()
                if any(fragment in lowered for fragment in ALLOW_VALUE_FRAGMENTS):
                    continue
                findings.append(
                    {
                        "rule": rule,
                        "file": relative.replace("\\", "/"),
                        "line": line_number,
                        "match": value[:12] + "…" if len(value) > 12 else value,
                    }
                )
                break
    return {
        "tool": "scripts/secret_scan.py",
        "files_scanned": scanned,
        "tracked_files_scanned": scanned - untracked_count,
        "untracked_files_scanned": untracked_count,
        "findings": findings,
        "finding_count": len(findings),
        "note": (
            "Scans tracked files plus untracked files that are not gitignored. "
            "A clean result does not prove the absence of secrets in git history, "
            "ignored environment files, build artifacts, or external systems. "
            "Rotate any credential that has ever been committed."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", default=None, help="Write the report to this path")
    args = parser.parse_args()

    report = scan()
    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
