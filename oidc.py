"""Minimal OpenID Connect authorization-code client with PKCE.

The module is intentionally provider-agnostic and has no Flask dependency so it
can be unit-tested against a fake provider. It implements the security-critical
pieces a deployment needs before it can call itself SSO-ready:

- discovery document validation,
- authorization-code flow with state, nonce, and PKCE (S256),
- token exchange,
- RS256 ID-token signature verification against the provider JWKS,
- issuer, audience, authorized-party, nonce, expiry, and issued-at checks.

Only RS256 is accepted. ``none``, HMAC algorithms, and RSA-vs-HMAC confusion are
rejected explicitly. A real deployment must still complete an integration test
against the chosen identity provider and an external security review.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from hmac import compare_digest
from urllib.parse import urlencode

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DEFAULT_TIMEOUT_SECONDS = 5.0
ALLOWED_ALGORITHMS = frozenset({"RS256"})
REQUIRED_DISCOVERY_FIELDS = ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")


class OidcError(ValueError):
    """Raised when discovery, the token exchange, or token validation fails."""


def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str) or not segment:
        raise OidcError("Empty JWT segment")
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except Exception as exc:  # noqa: BLE001 - normalise to one error type
        raise OidcError("Malformed base64url segment") from exc


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_json_segment(segment: str, label: str) -> dict:
    try:
        value = json.loads(_b64url_decode(segment))
    except (TypeError, ValueError) as exc:
        raise OidcError(f"Malformed JWT {label}") from exc
    if not isinstance(value, dict):
        raise OidcError(f"JWT {label} must be a JSON object")
    return value


def discover(issuer: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """Fetch and validate an OpenID Connect discovery document."""

    issuer = (issuer or "").strip().rstrip("/")
    if not issuer:
        raise OidcError("OIDC issuer is not configured")
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        document = response.json()
    except requests.RequestException as exc:
        raise OidcError(f"OIDC discovery failed: {exc.__class__.__name__}") from exc
    except ValueError as exc:
        raise OidcError("OIDC discovery returned invalid JSON") from exc

    if not isinstance(document, dict):
        raise OidcError("OIDC discovery document must be an object")
    missing = [field for field in REQUIRED_DISCOVERY_FIELDS if not document.get(field)]
    if missing:
        raise OidcError(f"OIDC discovery is missing: {', '.join(missing)}")
    if str(document["issuer"]).rstrip("/") != issuer:
        raise OidcError("OIDC discovery issuer does not match the configured issuer")
    return document


def pkce_pair() -> tuple[str, str]:
    """Return ``(verifier, S256 challenge)`` for a single authorization flow."""

    verifier = secrets.token_urlsafe(64)[:96]
    challenge = _b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def build_authorization_url(
    discovery: dict,
    client_id: str,
    redirect_uri: str,
    scopes: str,
    state: str,
    nonce: str,
    code_challenge: str,
    extra_params: dict | None = None,
) -> str:
    """Build the provider authorization URL for the code flow."""

    if not client_id or not redirect_uri:
        raise OidcError("OIDC client id and redirect URI are required")
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes or "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if extra_params:
        for key, value in extra_params.items():
            params.setdefault(key, value)
    endpoint = discovery.get("authorization_endpoint")
    if not endpoint:
        raise OidcError("OIDC discovery has no authorization endpoint")
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{urlencode(params)}"


def _post_token_request(
    endpoint: str,
    data: dict,
    client_id: str,
    client_secret: str | None,
    auth_method: str,
    timeout: float,
) -> dict:
    headers = {"Accept": "application/json"}
    auth = None
    if client_secret:
        if auth_method == "client_secret_post":
            data = {**data, "client_secret": client_secret}
        else:
            auth = (client_id, client_secret)
    try:
        response = requests.post(
            endpoint, data=data, auth=auth, headers=headers, timeout=timeout
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        raise OidcError(f"OIDC token exchange failed: {exc.__class__.__name__}") from exc
    except ValueError as exc:
        raise OidcError("OIDC token endpoint returned invalid JSON") from exc
    if not isinstance(payload, dict) or not payload.get("id_token"):
        raise OidcError("OIDC token response has no id_token")
    return payload


def exchange_code(
    discovery: dict,
    client_id: str,
    client_secret: str | None,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    auth_method: str = "client_secret_basic",
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Exchange an authorization code for tokens."""

    if not code:
        raise OidcError("Authorization code is missing")
    endpoint = discovery.get("token_endpoint")
    if not endpoint:
        raise OidcError("OIDC discovery has no token endpoint")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    return _post_token_request(
        endpoint, data, client_id, client_secret, auth_method, timeout
    )


def fetch_jwks(jwks_uri: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """Fetch the provider signing keys."""

    try:
        response = requests.get(
            jwks_uri, timeout=timeout, headers={"Accept": "application/json"}
        )
        response.raise_for_status()
        document = response.json()
    except requests.RequestException as exc:
        raise OidcError(f"OIDC JWKS fetch failed: {exc.__class__.__name__}") from exc
    except ValueError as exc:
        raise OidcError("OIDC JWKS endpoint returned invalid JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise OidcError("OIDC JWKS document has no key set")
    return document


def _rsa_key_from_jwk(jwk: dict):
    if jwk.get("kty") != "RSA":
        raise OidcError("Only RSA signing keys are supported")
    if jwk.get("use") not in (None, "sig"):
        raise OidcError("JWK is not a signing key")
    try:
        modulus = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        exponent = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except (KeyError, ValueError) as exc:
        raise OidcError("Malformed RSA JWK") from exc


def _select_key(jwks: dict, kid: str):
    candidates = [
        key
        for key in jwks.get("keys", [])
        if isinstance(key, dict)
        and key.get("kid") == kid
        and key.get("kty") == "RSA"
        and key.get("use") in (None, "sig")
    ]
    if not candidates:
        raise OidcError("No matching signing key for the ID token")
    return _rsa_key_from_jwk(candidates[0])


def verify_id_token(
    id_token: str,
    discovery: dict,
    client_id: str,
    nonce: str,
    jwks: dict | None = None,
    leeway: int = 60,
    now: float | None = None,
    allowed_algorithms: frozenset[str] = ALLOWED_ALGORITHMS,
) -> dict:
    """Verify an RS256 ID token and return its claims."""

    if not isinstance(id_token, str):
        raise OidcError("ID token is missing")
    parts = id_token.split(".")
    if len(parts) != 3:
        raise OidcError("ID token is not a compact JWS")
    header = _decode_json_segment(parts[0], "header")
    claims = _decode_json_segment(parts[1], "payload")
    signature = _b64url_decode(parts[2])

    algorithm = header.get("alg")
    if algorithm not in allowed_algorithms:
        raise OidcError(f"Unsupported ID token algorithm: {algorithm!r}")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise OidcError("ID token has no key identifier")

    if jwks is None:
        jwks_uri = discovery.get("jwks_uri")
        if not jwks_uri:
            raise OidcError("OIDC discovery has no JWKS URI")
        jwks = fetch_jwks(jwks_uri)
    key = _select_key(jwks, kid)
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise OidcError("Invalid ID token signature") from exc

    expected_issuer = str(discovery.get("issuer", "")).rstrip("/")
    if str(claims.get("iss", "")).rstrip("/") != expected_issuer:
        raise OidcError("ID token issuer mismatch")
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if client_id not in audiences:
        raise OidcError("ID token audience mismatch")
    if claims.get("azp") is not None and claims.get("azp") != client_id:
        raise OidcError("ID token authorized party mismatch")
    if not compare_digest(str(claims.get("nonce", "")), str(nonce or "")):
        raise OidcError("ID token nonce mismatch")

    current = time.time() if now is None else float(now)
    try:
        expires_at = float(claims["exp"])
    except (KeyError, TypeError, ValueError) as exc:
        raise OidcError("ID token has no valid expiry") from exc
    if current > expires_at + leeway:
        raise OidcError("ID token has expired")
    for field in ("iat", "nbf"):
        if claims.get(field) is None:
            continue
        try:
            value = float(claims[field])
        except (TypeError, ValueError) as exc:
            raise OidcError(f"ID token has an invalid {field}") from exc
        if value > current + leeway:
            raise OidcError(f"ID token {field} is in the future")

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise OidcError("ID token has no subject")
    return claims
