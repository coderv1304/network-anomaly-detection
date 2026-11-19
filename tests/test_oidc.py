"""OpenID Connect client and SSO route tests against a fake provider."""

import base64
import hashlib
import json
import time
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import werkzeug
from importlib.metadata import version

import app as app_module
from domain import oidc as oidc_module
def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _jwk(private_key):
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": "test-kid",
        "alg": "RS256",
        "n": _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


def _sign(private_key, claims, header=None):
    header = header or {"alg": "RS256", "typ": "JWT", "kid": "test-kid"}
    signing_input = ".".join(
        [
            _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8")),
        ]
    )
    signature = private_key.sign(
        signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    return f"{signing_input}.{_b64url(signature)}"


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(signing_key):
    return {"keys": [_jwk(signing_key)]}


@pytest.fixture()
def discovery():
    return {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/authorize",
        "token_endpoint": "https://idp.example.test/token",
        "jwks_uri": "https://idp.example.test/jwks",
    }


def _claims(**overrides):
    claims = {
        "iss": "https://idp.example.test",
        "aud": "netshield-client",
        "azp": "netshield-client",
        "sub": "subject-123",
        "nonce": "nonce-123",
        "email": "oidc-user@example.test",
        "email_verified": True,
        "name": "OIDC User",
        "iat": int(time.time()) - 10,
        "exp": int(time.time()) + 300,
    }
    claims.update(overrides)
    return claims


# ---------------------------------------------------------------------------
# Module-level token validation
# ---------------------------------------------------------------------------


def test_valid_id_token_is_accepted(discovery, signing_key, jwks):
    token = _sign(signing_key, _claims())
    claims = oidc_module.verify_id_token(
        token, discovery, "netshield-client", "nonce-123", jwks=jwks
    )
    assert claims["sub"] == "subject-123"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"nonce": "other"}, "nonce"),
        ({"aud": "another-client"}, "audience"),
        ({"iss": "https://evil.example.test"}, "issuer"),
        ({"azp": "another-client"}, "authorized party"),
        ({"exp": int(time.time()) - 3600}, "expired"),
        ({"iat": int(time.time()) + 3600}, "future"),
    ],
)
def test_id_token_rejects_bad_claims(discovery, signing_key, jwks, overrides, message):
    token = _sign(signing_key, _claims(**overrides))
    with pytest.raises(oidc_module.OidcError, match=message):
        oidc_module.verify_id_token(
            token, discovery, "netshield-client", "nonce-123", jwks=jwks
        )


def test_id_token_rejects_hmac_and_unsigned_algorithms(discovery, signing_key, jwks):
    for algorithm in ("HS256", "none"):
        token = _sign(signing_key, _claims(), header={"alg": algorithm, "kid": "test-kid"})
        with pytest.raises(oidc_module.OidcError, match="algorithm"):
            oidc_module.verify_id_token(
                token, discovery, "netshield-client", "nonce-123", jwks=jwks
            )


def test_id_token_rejects_tampering_and_unknown_key(discovery, signing_key, jwks):
    token = _sign(signing_key, _claims())
    header, payload, signature = token.split(".")
    tampered = f"{header}.{_b64url(json.dumps(_claims(sub='attacker')).encode())}.{signature}"
    with pytest.raises(oidc_module.OidcError, match="signature"):
        oidc_module.verify_id_token(
            tampered, discovery, "netshield-client", "nonce-123", jwks=jwks
        )

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    unknown = _sign(other, _claims(), header={"alg": "RS256", "kid": "unknown"})
    with pytest.raises(oidc_module.OidcError, match="signing key"):
        oidc_module.verify_id_token(
            unknown, discovery, "netshield-client", "nonce-123", jwks=jwks
        )


def test_pkce_challenge_and_authorization_url(discovery):
    verifier, challenge = oidc_module.pkce_pair()
    assert 43 <= len(verifier) <= 96
    assert challenge == _b64url(hashlib.sha256(verifier.encode("ascii")).digest())

    url = oidc_module.build_authorization_url(
        discovery,
        "netshield-client",
        "https://netshield.example.test/auth/oidc/callback",
        "openid email",
        "state-123",
        "nonce-123",
        challenge,
    )
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    assert parsed.netloc == "idp.example.test"
    assert query["response_type"] == ["code"]
    assert query["state"] == ["state-123"]
    assert query["nonce"] == ["nonce-123"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [challenge]


# ---------------------------------------------------------------------------
# Flask SSO routes
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(werkzeug, "__version__", version("Werkzeug"), raising=False)
    monkeypatch.setattr(app_module.limiter, "enabled", False)
    return app_module.app.test_client()


@pytest.fixture()
def oidc_user():
    suffix = uuid.uuid4().hex[:8]
    with app_module.app.app_context():
        tenant = app_module.Tenant(
            slug=f"oidc-{suffix}", name="OIDC Test", retention_days=30
        )
        app_module.db.session.add(tenant)
        app_module.db.session.flush()
        user = app_module.User(
            tenant_id=tenant.id,
            email=f"oidc-{suffix}@example.test",
            display_name="OIDC Test User",
            role="analyst",
            auth_source="oidc",
            is_active=True,
        )
        app_module.db.session.add(user)
        app_module.db.session.commit()
        return {"id": user.id, "email": user.email, "tenant_id": tenant.id}


def _configure(monkeypatch, claims):
    monkeypatch.setattr(app_module, "OIDC_ENABLED", True)
    monkeypatch.setattr(app_module, "OIDC_ISSUER", "https://idp.example.test")
    monkeypatch.setattr(app_module, "OIDC_CLIENT_ID", "netshield-client")
    monkeypatch.setattr(app_module, "OIDC_CLIENT_SECRET", "secret")
    monkeypatch.setattr(
        app_module,
        "OIDC_REDIRECT_URI",
        "https://netshield.example.test/auth/oidc/callback",
    )
    monkeypatch.setattr(app_module, "OIDC_JIT_PROVISIONING", False)
    monkeypatch.setattr(app_module, "OIDC_LINK_LOCAL_ACCOUNTS", False)
    monkeypatch.setattr(
        app_module.oidc_module,
        "discover",
        lambda issuer, timeout=5.0: {
            "issuer": "https://idp.example.test",
            "authorization_endpoint": "https://idp.example.test/authorize",
            "token_endpoint": "https://idp.example.test/token",
            "jwks_uri": "https://idp.example.test/jwks",
        },
    )
    monkeypatch.setattr(
        app_module.oidc_module,
        "exchange_code",
        lambda *args, **kwargs: {"id_token": "fake-token"},
    )
    monkeypatch.setattr(
        app_module.oidc_module,
        "verify_id_token",
        lambda *args, **kwargs: claims,
    )


def _start(client):
    response = client.get("/auth/oidc/login")
    assert response.status_code == 302
    with client.session_transaction() as session:
        return session["oidc_flow"]["state"]


def test_oidc_login_redirects_with_state_nonce_and_pkce(client, monkeypatch):
    _configure(monkeypatch, _claims())
    state = _start(client)
    response = client.get("/auth/oidc/login")
    query = parse_qs(urlparse(response.headers["Location"]).query)
    assert query["state"] != [state]
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["code_challenge"][0]) >= 43


def test_oidc_callback_establishes_session_for_provisioned_user(
    client, monkeypatch, oidc_user
):
    _configure(monkeypatch, _claims(email=oidc_user["email"]))
    state = _start(client)
    response = client.get(f"/auth/oidc/callback?code=abc&state={state}")
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["authenticated"] is True
        assert session["user_id"] == oidc_user["id"]
        assert session["auth_source"] == "oidc"
        assert "oidc_flow" not in session


def test_oidc_callback_rejects_state_mismatch(client, monkeypatch, oidc_user):
    _configure(monkeypatch, _claims(email=oidc_user["email"]))
    _start(client)
    response = client.get("/auth/oidc/callback?code=abc&state=wrong")
    assert response.status_code == 400
    with client.session_transaction() as session:
        assert "authenticated" not in session


def test_oidc_callback_rejects_unprovisioned_user_by_default(client, monkeypatch):
    _configure(monkeypatch, _claims(email="missing@example.test"))
    state = _start(client)
    response = client.get(f"/auth/oidc/callback?code=abc&state={state}")
    assert response.status_code == 403
    with app_module.app.app_context():
        assert app_module.User.query.filter_by(email="missing@example.test").first() is None


def test_oidc_callback_jit_provisioning_creates_viewer(client, monkeypatch):
    _configure(monkeypatch, _claims(email="new-oidc@example.test"))
    monkeypatch.setattr(app_module, "OIDC_JIT_PROVISIONING", True)
    monkeypatch.setattr(app_module, "OIDC_DEFAULT_TENANT_SLUG", "default")
    state = _start(client)
    response = client.get(f"/auth/oidc/callback?code=abc&state={state}")
    assert response.status_code == 302
    with app_module.app.app_context():
        user = app_module.User.query.filter_by(email="new-oidc@example.test").first()
        assert user is not None
        assert user.auth_source == "oidc"
        assert user.role == "viewer"


def test_oidc_callback_refuses_to_link_existing_local_account(client, monkeypatch):
    suffix = uuid.uuid4().hex[:8]
    email = f"local-{suffix}@example.test"
    with app_module.app.app_context():
        tenant = app_module.Tenant(
            slug=f"local-{suffix}", name="Local", retention_days=30
        )
        app_module.db.session.add(tenant)
        app_module.db.session.flush()
        app_module.db.session.add(
            app_module.User(
                tenant_id=tenant.id,
                email=email,
                display_name="Local User",
                role="analyst",
                auth_source="local",
                is_active=True,
            )
        )
        app_module.db.session.commit()

    _configure(monkeypatch, _claims(email=email))
    state = _start(client)
    response = client.get(f"/auth/oidc/callback?code=abc&state={state}")
    assert response.status_code == 403
    assert b"Single sign-on could not be completed" in response.data


def test_oidc_callback_requires_verified_email(client, monkeypatch, oidc_user):
    _configure(monkeypatch, _claims(email=oidc_user["email"], email_verified=False))
    state = _start(client)
    response = client.get(f"/auth/oidc/callback?code=abc&state={state}")
    assert response.status_code == 403


def test_oidc_routes_are_hidden_when_disabled(client):
    assert client.get("/auth/oidc/login").status_code == 404
    assert client.get("/auth/oidc/callback").status_code == 404

