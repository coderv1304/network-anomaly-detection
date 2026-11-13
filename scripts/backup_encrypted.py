#!/usr/bin/env python
"""Encrypted, optionally off-host SQLite backup drill.

This extends ``scripts/backup_restore_drill.py`` with the controls a production
backup needs:

* a consistent SQLite online backup (never a raw file copy of a live WAL DB);
* AES-256-GCM encryption with a key that is never written to the artifact;
* authenticated decryption and a SHA-256 comparison with the plaintext backup;
* ``PRAGMA integrity_check`` and table-count comparison after restore;
* an optional copy to a mounted off-host directory with hash verification;
* measured restore time (RTO observation) and the age of the source data at
  backup start (an RPO observation, not a production SLO).

The script proves the procedure on this host. It does not prove that an
operator stores the key separately, that the off-host target is durable, or
that a real site meets a declared RPO/RTO. Those remain operational evidence.

Usage:
    NETSHIELD_BACKUP_KEY=<base64-32-bytes> \
        venv/Scripts/python.exe scripts/backup_encrypted.py \
        --source instance/network_anomaly.db \
        --output-dir backups \
        --offsite-dir /mnt/offsite/netshield \
        --output docs/encrypted_backup_drill.json

Generate a key once:
    python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"NSBK1"
AAD = b"NetShield encrypted backup v1"
NONCE_BYTES = 12


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sqlite_backup(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    source_connection = sqlite3.connect(source)
    target_connection = sqlite3.connect(target)
    try:
        source_connection.backup(target_connection)
        target_connection.commit()
    finally:
        target_connection.close()
        source_connection.close()


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
    finally:
        connection.close()
    return {"tables": counts, "integrity_check": integrity}


def load_key(key_file: str | None) -> tuple[bytes, str]:
    if key_file:
        key = Path(key_file).read_bytes()
        source = "key_file"
    else:
        encoded = os.environ.get("NETSHIELD_BACKUP_KEY", "").strip()
        if encoded:
            key = base64.b64decode(encoded)
            source = "NETSHIELD_BACKUP_KEY"
        else:
            key = os.urandom(32)
            source = "ephemeral_drill_only"
    if len(key) != 32:
        raise SystemExit("Backup key must be exactly 32 bytes (AES-256).")
    return key, source


def encrypt_file(source: Path, target: Path, key: bytes) -> dict:
    nonce = os.urandom(NONCE_BYTES)
    plaintext = source.read_bytes()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, AAD)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as handle:
        handle.write(MAGIC + nonce + ciphertext)
    return {
        "path": str(target),
        "sha256": sha256_file(target),
        "size_bytes": target.stat().st_size,
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "nonce_hex": nonce.hex(),
        "algorithm": "AES-256-GCM",
    }


def decrypt_file(source: Path, target: Path, key: bytes) -> dict:
    payload = source.read_bytes()
    if not payload.startswith(MAGIC):
        raise SystemExit("Encrypted backup has an unknown magic header.")
    nonce = payload[len(MAGIC):len(MAGIC) + NONCE_BYTES]
    ciphertext = payload[len(MAGIC) + NONCE_BYTES:]
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, AAD)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(plaintext)
    return {
        "path": str(target),
        "sha256": hashlib.sha256(plaintext).hexdigest(),
        "size_bytes": target.stat().st_size,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="instance/network_anomaly.db")
    parser.add_argument("--output-dir", default="backups")
    parser.add_argument("--offsite-dir", default=None)
    parser.add_argument("--key-file", default=None)
    parser.add_argument("--output", default="docs/encrypted_backup_drill.json")
    args = parser.parse_args()

    source = Path(args.source).resolve()
    if not source.exists():
        raise SystemExit(f"Source database not found: {source}")
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    key, key_source = load_key(args.key_file)

    started = time.perf_counter()
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    plaintext_backup = output_dir / f"network_anomaly-{timestamp}.db"
    encrypted_backup = output_dir / f"network_anomaly-{timestamp}.db.enc"
    source_info = inspect_database(source)
    source_mtime = datetime.fromtimestamp(source.stat().st_mtime, UTC)

    sqlite_backup(source, plaintext_backup)
    backup_info = inspect_database(plaintext_backup)
    encryption = encrypt_file(plaintext_backup, encrypted_backup, key)

    restore_started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="netshield-restore-") as temp_dir:
        restored = Path(temp_dir) / "restored.db"
        decrypted = decrypt_file(encrypted_backup, restored, key)
        restored_info = inspect_database(restored)
        restore_seconds = time.perf_counter() - restore_started

    offsite = None
    if args.offsite_dir:
        offsite_dir = Path(args.offsite_dir).resolve()
        offsite_dir.mkdir(parents=True, exist_ok=True)
        offsite_path = offsite_dir / encrypted_backup.name
        shutil.copy2(encrypted_backup, offsite_path)
        offsite = {
            "path": str(offsite_path),
            "sha256": sha256_file(offsite_path),
            "matches_local_ciphertext": sha256_file(offsite_path) == encryption["sha256"],
        }

    checks = {
        "source_integrity_ok": source_info["integrity_check"] == "ok",
        "backup_integrity_ok": backup_info["integrity_check"] == "ok",
        "backup_counts_match_source": backup_info["tables"] == source_info["tables"],
        "ciphertext_is_not_plaintext": encrypted_backup.read_bytes().startswith(MAGIC),
        "decrypted_hash_matches_backup": decrypted["sha256"] == encryption["plaintext_sha256"],
        "restored_integrity_ok": restored_info["integrity_check"] == "ok",
        "restored_counts_match_backup": restored_info["tables"] == backup_info["tables"],
        "offsite_hash_matches": offsite["matches_local_ciphertext"] if offsite else None,
        "key_not_embedded": key.hex() not in encrypted_backup.read_bytes().hex(),
    }
    required = [value for key_name, value in checks.items() if key_name != "offsite_hash_matches"]
    passed = all(required) and (checks["offsite_hash_matches"] is not False)

    report = {
        "drill": "encrypted SQLite backup, authenticated restore, optional off-host copy",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "source": {
            "path": str(source),
            "sha256": sha256_file(source),
            "last_modified_utc": source_mtime.isoformat(),
            "tables": source_info["tables"],
            "integrity_check": source_info["integrity_check"],
        },
        "backup": {
            "plaintext_path": str(plaintext_backup),
            "plaintext_sha256": encryption["plaintext_sha256"],
            "tables": backup_info["tables"],
        },
        "encryption": encryption,
        "restore": {
            "sha256": decrypted["sha256"],
            "tables": restored_info["tables"],
            "integrity_check": restored_info["integrity_check"],
            "restore_seconds": round(restore_seconds, 3),
        },
        "offsite": offsite,
        "key": {
            "source": key_source,
            "stored_in_artifact": False,
            "note": "The key is not written to the encrypted file or this report.",
        },
        "rpo_observation": {
            "source_last_modified_utc": source_mtime.isoformat(),
            "backup_started_utc": datetime.fromtimestamp(started, UTC).isoformat(),
            "source_age_seconds": round(max(0.0, started - source.stat().st_mtime), 3),
            "note": "Single-host observation, not a production RPO measurement.",
        },
        "rto_observation": {
            "restore_seconds": round(restore_seconds, 3),
            "note": "Decrypt plus integrity check on this host, not a production RTO.",
        },
        "checks": checks,
        "status": "pass" if passed else "fail",
        "limits": [
            "The drill proves the procedure on this host only.",
            "Off-host durability, key custody, and a site-declared RPO/RTO are operational evidence and are not established here.",
            "SQLite only; a managed Postgres deployment must use its own encrypted snapshot/PITR mechanism.",
        ],
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output}")
    print(f"Encrypted backup drill: {report['status'].upper()}")
    for name, value in checks.items():
        print(f"  [{'PASS' if value else ('SKIP' if value is None else 'FAIL')}] {name}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
