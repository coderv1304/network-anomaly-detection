"""Encrypted backup drill tests: roundtrip, tamper detection, key handling."""

import os
import sqlite3
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from scripts import backup_encrypted


def _make_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE flow (id INTEGER PRIMARY KEY, label TEXT)")
        connection.executemany(
            "INSERT INTO flow (label) VALUES (?)",
            [("BENIGN",), ("DDoS",), ("BENIGN",)],
        )
        connection.commit()
    finally:
        connection.close()


def test_encrypt_decrypt_roundtrip(tmp_path):
    key = os.urandom(32)
    source = tmp_path / "source.db"
    _make_db(source)

    encrypted = tmp_path / "source.db.enc"
    metadata = backup_encrypted.encrypt_file(source, encrypted, key)
    assert metadata["algorithm"] == "AES-256-GCM"
    assert encrypted.read_bytes().startswith(backup_encrypted.MAGIC)

    restored = tmp_path / "restored.db"
    result = backup_encrypted.decrypt_file(encrypted, restored, key)
    assert result["sha256"] == metadata["plaintext_sha256"]
    assert restored.read_bytes() == source.read_bytes()


def test_tampered_ciphertext_fails_authentication(tmp_path):
    key = os.urandom(32)
    source = tmp_path / "source.db"
    _make_db(source)

    encrypted = tmp_path / "source.db.enc"
    backup_encrypted.encrypt_file(source, encrypted, key)

    payload = bytearray(encrypted.read_bytes())
    payload[-1] ^= 0xFF
    encrypted.write_bytes(bytes(payload))

    with pytest.raises(InvalidTag):
        backup_encrypted.decrypt_file(encrypted, tmp_path / "restored.db", key)


def test_wrong_key_fails_authentication(tmp_path):
    key = os.urandom(32)
    source = tmp_path / "source.db"
    _make_db(source)

    encrypted = tmp_path / "source.db.enc"
    backup_encrypted.encrypt_file(source, encrypted, key)

    with pytest.raises(InvalidTag):
        backup_encrypted.decrypt_file(encrypted, tmp_path / "restored.db", os.urandom(32))


def test_key_length_is_enforced(monkeypatch):
    monkeypatch.delenv("NETSHIELD_BACKUP_KEY", raising=False)
    monkeypatch.setenv("NETSHIELD_BACKUP_KEY", "c2hvcnQ=")  # b"short"
    with pytest.raises(SystemExit):
        backup_encrypted.load_key(None)
