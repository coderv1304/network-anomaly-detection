"""RFC 6238 TOTP, encrypted secret storage, and recovery codes.

This module deliberately uses only the standard library plus ``cryptography``
(already a runtime dependency) so the local MFA path has no extra package or
network surface. It is used by the Flask app and by ``scripts/mfa_admin.py``.

Security notes
--------------
- TOTP secrets are encrypted at rest with a Fernet key derived from
  ``SECRET_KEY``. Rotating ``SECRET_KEY`` therefore invalidates existing
  enrollments; the operator must re-enroll or disable MFA first.
- Verification accepts a +/- 1 step window (30 s period) and returns the matched
  step so callers can reject replay of the same code.
- Recovery codes are stored only as password hashes and are removed on use.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from urllib.parse import quote, urlencode

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

TOTP_DIGITS = 6
TOTP_PERIOD_SECONDS = 30
TOTP_WINDOW_STEPS = 1
RECOVERY_CODE_COUNT = 8
RECOVERY_CODE_LENGTH = 10
SECRET_BYTES = 20
_ENCRYPTED_PREFIX = "enc:v1:"


class MfaError(ValueError):
    """Raised when an MFA secret or code cannot be processed."""


def generate_secret(byte_count: int = SECRET_BYTES) -> str:
    """Return a new base32 TOTP secret without padding."""

    if byte_count < 16:
        raise MfaError("TOTP secrets must be at least 128 bits")
    return base64.b32encode(secrets.token_bytes(byte_count)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    cleaned = (secret or "").strip().replace(" ", "").upper()
    if not cleaned:
        raise MfaError("Empty TOTP secret")
    padding = "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned + padding, casefold=True)
    except Exception as exc:  # noqa: BLE001 - normalise to one error type
        raise MfaError("Invalid base32 TOTP secret") from exc


def code_at(secret: str, timestamp: float | None = None, step_offset: int = 0) -> str:
    """Return the TOTP code for ``timestamp`` shifted by ``step_offset`` steps."""

    key = _decode_secret(secret)
    now = time.time() if timestamp is None else float(timestamp)
    counter = int(now // TOTP_PERIOD_SECONDS) + step_offset
    if counter < 0:
        raise MfaError("TOTP counter cannot be negative")
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_code(
    secret: str,
    code: str,
    timestamp: float | None = None,
    window: int = TOTP_WINDOW_STEPS,
) -> int | None:
    """Return the matched TOTP step, or ``None`` when the code is invalid.

    All candidates in the window are compared without early exit so a caller
    cannot infer how close a wrong code was.
    """

    digits = "".join(character for character in str(code or "") if character.isdigit())
    if len(digits) != TOTP_DIGITS:
        return None
    now = time.time() if timestamp is None else float(timestamp)
    current_step = int(now // TOTP_PERIOD_SECONDS)
    matched: int | None = None
    for offset in range(-window, window + 1):
        step = current_step + offset
        if step < 0:
            continue
        expected = code_at(secret, timestamp=step * TOTP_PERIOD_SECONDS)
        if hmac.compare_digest(expected, digits) and matched is None:
            matched = step
    return matched


def provisioning_uri(secret: str, account_name: str, issuer: str = "NetShield") -> str:
    """Return an ``otpauth://`` URI for authenticator apps."""

    label = quote(f"{issuer}:{account_name}", safe="")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": TOTP_DIGITS,
            "period": TOTP_PERIOD_SECONDS,
        }
    )
    return f"otpauth://totp/{label}?{query}"


def _fernet(key_material: str) -> Fernet:
    if not key_material:
        raise MfaError("Missing encryption key material")
    digest = hashlib.sha256(key_material.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(secret: str, key_material: str) -> str:
    """Encrypt a TOTP secret for storage."""

    token = _fernet(key_material).encrypt(secret.encode("ascii"))
    return _ENCRYPTED_PREFIX + token.decode("ascii")


def decrypt_secret(value: str, key_material: str) -> str:
    """Decrypt a stored secret.

    Unprefixed values are treated as legacy plaintext so an operator can
    migrate an existing enrollment without locking the account out.
    """

    if not value:
        raise MfaError("No MFA secret is enrolled")
    if not value.startswith(_ENCRYPTED_PREFIX):
        return value
    try:
        plaintext = _fernet(key_material).decrypt(value[len(_ENCRYPTED_PREFIX) :].encode("ascii"))
    except InvalidToken as exc:
        raise MfaError("Stored MFA secret cannot be decrypted with the current key") from exc
    return plaintext.decode("ascii")


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Return human-readable single-use recovery codes."""

    codes = []
    for _ in range(count):
        raw = base64.b32encode(secrets.token_bytes(8)).decode("ascii").rstrip("=")
        compact = raw[:RECOVERY_CODE_LENGTH].upper()
        codes.append(f"{compact[:5]}-{compact[5:]}")
    return codes


def normalize_recovery_code(code: str) -> str:
    return "".join(character for character in str(code or "").upper() if character.isalnum())


def hash_recovery_codes(codes: list[str]) -> str:
    """Hash recovery codes for storage as a JSON array."""

    return json.dumps([generate_password_hash(normalize_recovery_code(code)) for code in codes])


def load_recovery_hashes(stored: str | None) -> list[str]:
    if not stored:
        return []
    try:
        value = json.loads(stored)
    except (TypeError, ValueError):
        return []
    return [item for item in value if isinstance(item, str) and item]


def match_recovery_code(stored: str | None, supplied: str) -> tuple[bool, str | None]:
    """Return ``(matched, remaining_stored_json)`` for a supplied recovery code."""

    hashes = load_recovery_hashes(stored)
    normalized = normalize_recovery_code(supplied)
    if not normalized:
        return False, stored
    remaining = list(hashes)
    matched_index: int | None = None
    for index, hashed in enumerate(hashes):
        if check_password_hash(hashed, normalized) and matched_index is None:
            matched_index = index
    if matched_index is None:
        return False, stored
    remaining.pop(matched_index)
    return True, json.dumps(remaining)
