#!/usr/bin/env python
"""Exercise the documented SQLite backup and restore procedure.

The drill never modifies the live database. It:

1. takes a consistent online backup with the SQLite backup API;
2. records hashes, sizes, table counts, and ``PRAGMA integrity_check``;
3. damages a disposable copy (deletes every flow row);
4. restores the backup over that copy with the SQLite backup API;
5. restores again to a brand-new file and compares hashes;
6. writes a machine-readable result to ``docs/backup_restore_drill.json``.

The live database is only read. A passing drill proves the procedure works for
this schema and data volume; it does not prove that an operator will run it, or
that a backup is stored off-host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_database(path: Path) -> dict:
    connection = sqlite3.connect(path)
    try:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        counts = {
            table: connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            for table in tables
        }
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        fingerprint = hashlib.sha256()
        for table in tables:
            fingerprint.update(table.encode("utf-8"))
            for row in connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid'):
                fingerprint.update(repr(row).encode("utf-8"))
        logical_sha256 = fingerprint.hexdigest()
    finally:
        connection.close()
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "page_count": page_count,
        "page_size": page_size,
        "tables": counts,
        "logical_sha256": logical_sha256,
        "integrity_check": integrity,
    }


def sqlite_backup(source: Path, target: Path) -> None:
    """Copy a SQLite database with the online backup API."""
    target.parent.mkdir(parents=True, exist_ok=True)
    source_connection = sqlite3.connect(source)
    target_connection = sqlite3.connect(target)
    try:
        source_connection.backup(target_connection)
        target_connection.commit()
    finally:
        target_connection.close()
        source_connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="instance/network_anomaly.db")
    parser.add_argument("--artifact-dir", default="docs/backup_restore_artifacts")
    parser.add_argument("--output", default="docs/backup_restore_drill.json")
    args = parser.parse_args()

    source = Path(args.source).resolve()
    artifact_dir = Path(args.artifact_dir).resolve()
    if not source.exists():
        raise SystemExit(f"Source database not found: {source}")
    artifact_dir.mkdir(parents=True, exist_ok=True)

    started = time.perf_counter()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = artifact_dir / f"network_anomaly-{timestamp}.db"
    damaged = artifact_dir / f"network_anomaly-{timestamp}.damaged.db"
    restored = artifact_dir / f"network_anomaly-{timestamp}.restored.db"
    fresh = artifact_dir / f"network_anomaly-{timestamp}.fresh-restore.db"

    source_info = inspect_database(source)
    sqlite_backup(source, backup)
    backup_info = inspect_database(backup)

    # Damage a disposable copy so the restore has to repair real loss.
    shutil.copy2(backup, damaged)
    damage_connection = sqlite3.connect(damaged)
    try:
        damage_connection.execute("DELETE FROM flow")
        damage_connection.commit()
    finally:
        damage_connection.close()
    damaged_info = inspect_database(damaged)

    restore_started = time.perf_counter()
    # Restore over the damaged copy, the way an operator would restore in
    # place after stopping the service. The backup is the source; the damaged
    # file is the target.
    shutil.copy2(damaged, restored)
    backup_connection = sqlite3.connect(backup)
    restore_connection = sqlite3.connect(restored)
    try:
        backup_connection.backup(restore_connection)
        restore_connection.commit()
    finally:
        restore_connection.close()
        backup_connection.close()
    restored_info = inspect_database(restored)

    # Also restore to a fresh path, proving the backup is self-contained.
    fresh.unlink(missing_ok=True)
    sqlite_backup(backup, fresh)
    fresh_info = inspect_database(fresh)
    restore_seconds = time.perf_counter() - restore_started

    checks = {
        "backup_counts_match_source": backup_info["tables"] == source_info["tables"],
        "backup_integrity_ok": backup_info["integrity_check"] == "ok",
        "damage_removed_flows": damaged_info["tables"].get("flow") == 0,
        "restore_counts_match_backup": restored_info["tables"] == backup_info["tables"],
        "restore_integrity_ok": restored_info["integrity_check"] == "ok",
        "restore_logical_sha256_matches_backup": restored_info["logical_sha256"] == backup_info["logical_sha256"],
        "fresh_restore_count_matches": fresh_info["tables"] == backup_info["tables"],
        "fresh_restore_integrity_ok": fresh_info["integrity_check"] == "ok",
        "fresh_restore_hash_matches_backup": fresh_info["sha256"] == backup_info["sha256"],
    }
    passed = all(checks.values())

    report = {
        "drill": "sqlite backup and restore",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "source": source_info,
        "backup": backup_info,
        "damaged_copy": damaged_info,
        "restored_over_damaged_copy": restored_info,
        "fresh_restore": fresh_info,
        "checks": checks,
        "status": "pass" if passed else "fail",
        "duration_seconds": round(time.perf_counter() - started, 3),
        "restore_seconds": round(restore_seconds, 3),
        "notes": [
            "The live database was read only; every mutation happened on disposable copies.",
            "The backup is local. It is not encrypted and not off-host; production needs both.",
            "A passing drill does not establish a recovery point objective or an off-site backup.",
        ],
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
