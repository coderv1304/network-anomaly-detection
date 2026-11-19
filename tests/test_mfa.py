"""MFA: RFC 6238 vectors, encryption, recovery codes, login, and API."""

import uuid
from datetime import datetime

import pytest
import werkzeug
from importlib.metadata import version
from werkzeug.security import generate_password_hash

import app as app_module
from domain import mfa as mfa_module
RFC_SECRET_ASCII = "12345678901234567890"
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


@pytest.fixture()
def client(monkeypatch):
    # Flask 2.3 references this attribute, removed in Werkzeug 3.
    monkeypatch.setattr(werkzeug, "__version__", version("Werkzeug"), raising=False)
    monkeypatch.setattr(app_module.limiter, "enabled", False)
    return app_module.app.test_client()


@pytest.fixture()
def local_user():
    suffix = uuid.uuid4().hex[:8]
    with app_module.app.app_context():
        tenant = app_module.Tenant(
            slug=f"mfa-{suffix}", name="MFA Test", retention_days=30
        )
        app_module.db.session.add(tenant)
        app_module.db.session.flush()
        user = app_module.User(
            tenant_id=tenant.id,
            email=f"mfa-{suffix}@example.test",
            display_name="MFA Test User",
            password_hash=generate_password_hash("correct horse battery staple"),
            role="analyst",
            auth_source="local",
            is_active=True,
        )
        app_module.db.session.add(user)
        app_module.db.session.commit()
        return {"id": user.id, "email": user.email, "tenant_id": tenant.id}


def _csrf(client):
    client.get("/login")
    with client.session_transaction() as session:
        return session.get("csrf_token")


def _password_step(client, email, password="correct horse battery staple"):
    token = _csrf(client)
    return client.post(
        "/login",
        data={"csrf_token": token, "email": email, "password": password},
    )


def _otp_step(client, code):
    token = _csrf(client)
    return client.post("/login", data={"csrf_token": token, "otp": code})


def _enable_mfa(user_id, secret=None, recovery_codes=None):
    secret = secret or mfa_module.generate_secret()
    recovery_codes = recovery_codes or mfa_module.generate_recovery_codes()
    with app_module.app.app_context():
        user = app_module.db.session.get(app_module.User, user_id)
        user.totp_secret = mfa_module.encrypt_secret(secret, app_module.app.config["SECRET_KEY"])
        user.totp_enabled = True
        user.totp_confirmed_at = datetime.utcnow()
        user.totp_last_step = None
        user.mfa_recovery_hashes = mfa_module.hash_recovery_codes(recovery_codes)
        app_module.db.session.commit()
    return secret, recovery_codes


def _sign_in_session(client, user):
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["user_id"] = user["id"]
        session["username"] = user["email"]
        session["tenant_id"] = user["tenant_id"]
        session["role"] = "analyst"
        session["auth_source"] = "local"


# ---------------------------------------------------------------------------
# TOTP and storage primitives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ],
)
def test_rfc6238_vectors_truncated_to_six_digits(timestamp, expected):
    assert mfa_module.code_at(RFC_SECRET, timestamp=timestamp) == expected
    assert mfa_module.verify_code(RFC_SECRET, expected, timestamp=timestamp) == int(
        timestamp // 30
    )


def test_verify_code_accepts_previous_and_next_step_but_not_far_steps():
    timestamp = 1_700_000_000
    previous = mfa_module.code_at(RFC_SECRET, timestamp=timestamp - 30)
    following = mfa_module.code_at(RFC_SECRET, timestamp=timestamp + 30)
    two_steps_back = mfa_module.code_at(RFC_SECRET, timestamp=timestamp - 60)

    assert mfa_module.verify_code(RFC_SECRET, previous, timestamp=timestamp) is not None
    assert mfa_module.verify_code(RFC_SECRET, following, timestamp=timestamp) is not None
    assert mfa_module.verify_code(RFC_SECRET, two_steps_back, timestamp=timestamp) is None
    assert mfa_module.verify_code(RFC_SECRET, "abcdef", timestamp=timestamp) is None


def test_secret_encryption_roundtrip_and_wrong_key():
    key = "test-secret-key-material"
    stored = mfa_module.encrypt_secret(RFC_SECRET, key)
    assert stored.startswith("enc:v1:")
    assert RFC_SECRET not in stored
    assert mfa_module.decrypt_secret(stored, key) == RFC_SECRET
    with pytest.raises(mfa_module.MfaError):
        mfa_module.decrypt_secret(stored, "different-key")
    # Legacy plaintext remains readable for migration.
    assert mfa_module.decrypt_secret(RFC_SECRET, key) == RFC_SECRET


def test_recovery_codes_are_hashed_single_use_and_normalized():
    codes = mfa_module.generate_recovery_codes(count=3)
    assert len(codes) == 3
    stored = mfa_module.hash_recovery_codes(codes)
    assert codes[0] not in stored

    lowered = codes[0].lower()
    matched, remaining = mfa_module.match_recovery_code(stored, lowered)
    assert matched is True
    assert len(mfa_module.load_recovery_hashes(remaining)) == 2

    matched_again, _ = mfa_module.match_recovery_code(remaining, codes[0])
    assert matched_again is False


# ---------------------------------------------------------------------------
# Login flow
# ---------------------------------------------------------------------------


def test_password_login_without_mfa_establishes_session(client, local_user, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(app_module, "AUTH_REQUIRED", True)
    response = _password_step(client, local_user["email"])
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session.get("authenticated") is True


def test_mfa_login_challenges_then_accepts_totp(client, local_user, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(app_module, "AUTH_REQUIRED", True)
    secret, _ = _enable_mfa(local_user["id"])

    response = _password_step(client, local_user["email"])
    assert response.status_code == 200
    assert b"Authentication code" in response.data
    with client.session_transaction() as session:
        assert session.get("authenticated") is None
        assert session.get("mfa_pending", {}).get("user_id") == local_user["id"]

    bad = _otp_step(client, "000000")
    assert bad.status_code == 401
    assert b"not valid" in bad.data

    good = _otp_step(client, mfa_module.code_at(secret))
    assert good.status_code == 302
    with client.session_transaction() as session:
        assert session.get("authenticated") is True
        assert session.get("mfa_pending") is None


def test_mfa_login_accepts_single_use_recovery_code(client, local_user, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(app_module, "AUTH_REQUIRED", True)
    _, recovery_codes = _enable_mfa(local_user["id"])

    _password_step(client, local_user["email"])
    response = _otp_step(client, recovery_codes[0].lower())
    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session.get("authenticated") is True

    # The same recovery code cannot be used again.
    with client.session_transaction() as session:
        session.clear()
    _password_step(client, local_user["email"])
    reuse = _otp_step(client, recovery_codes[0])
    assert reuse.status_code == 401


def test_mfa_rejects_replayed_totp_step(client, local_user, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(app_module, "AUTH_REQUIRED", True)
    secret, _ = _enable_mfa(local_user["id"])
    code = mfa_module.code_at(secret)
    current_step = int(app_module.time.time() // mfa_module.TOTP_PERIOD_SECONDS)
    with app_module.app.app_context():
        user = app_module.db.session.get(app_module.User, local_user["id"])
        user.totp_last_step = current_step
        app_module.db.session.commit()

    _password_step(client, local_user["email"])
    response = _otp_step(client, code)
    assert response.status_code == 401


def test_mfa_locks_out_after_repeated_failures(client, local_user, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(app_module, "AUTH_REQUIRED", True)
    _enable_mfa(local_user["id"])
    _password_step(client, local_user["email"])
    for _ in range(app_module.MFA_MAX_ATTEMPTS):
        response = _otp_step(client, "000000")
    assert response.status_code == 429
    with client.session_transaction() as session:
        assert session.get("mfa_pending") is None


def test_unreadable_secret_fails_closed(client, local_user, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(app_module, "AUTH_REQUIRED", True)
    with app_module.app.app_context():
        user = app_module.db.session.get(app_module.User, local_user["id"])
        user.totp_secret = "enc:v1:not-a-valid-token"
        user.totp_enabled = True
        app_module.db.session.commit()

    response = _password_step(client, local_user["email"])
    assert response.status_code == 503
    assert b"misconfigured" in response.data
    with client.session_transaction() as session:
        assert session.get("authenticated") is None


# ---------------------------------------------------------------------------
# Enrollment API
# ---------------------------------------------------------------------------


def test_enrollment_requires_password_and_never_stores_plaintext(client, local_user):
    _sign_in_session(client, local_user)
    missing = client.post("/api/me/mfa/enroll", json={})
    assert missing.status_code == 401

    response = client.post(
        "/api/me/mfa/enroll",
        json={"password": "correct horse battery staple"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["enabled"] is False
    assert payload["provisioning_uri"].startswith("otpauth://totp/")
    assert len(payload["recovery_codes"]) == mfa_module.RECOVERY_CODE_COUNT

    with app_module.app.app_context():
        user = app_module.db.session.get(app_module.User, local_user["id"])
        assert user.totp_secret.startswith("enc:v1:")
        assert payload["secret"] not in user.totp_secret
        assert payload["recovery_codes"][0] not in (user.mfa_recovery_hashes or "")


def test_enrollment_confirm_enable_status_and_disable(client, local_user):
    _sign_in_session(client, local_user)
    enroll = client.post(
        "/api/me/mfa/enroll",
        json={"password": "correct horse battery staple"},
    ).get_json()
    secret = enroll["secret"]

    invalid = client.post("/api/me/mfa/confirm", json={"code": "000000"})
    assert invalid.status_code == 400

    confirmed = client.post(
        "/api/me/mfa/confirm", json={"code": mfa_module.code_at(secret)}
    )
    assert confirmed.status_code == 200
    assert confirmed.get_json()["enabled"] is True

    status = client.get("/api/me/mfa").get_json()
    assert status["enabled"] is True
    assert status["recovery_codes_remaining"] == mfa_module.RECOVERY_CODE_COUNT

    # Re-enrollment is refused while enabled.
    again = client.post(
        "/api/me/mfa/enroll",
        json={"password": "correct horse battery staple"},
    )
    assert again.status_code == 409

    disabled = client.post(
        "/api/me/mfa/disable",
        json={
            "password": "correct horse battery staple",
            "code": mfa_module.code_at(secret),
        },
    )
    assert disabled.status_code == 200
    assert disabled.get_json()["enabled"] is False
    assert client.get("/api/me/mfa").get_json()["enabled"] is False


def test_disable_requires_current_factor(client, local_user):
    _sign_in_session(client, local_user)
    enroll = client.post(
        "/api/me/mfa/enroll",
        json={"password": "correct horse battery staple"},
    ).get_json()
    client.post("/api/me/mfa/confirm", json={"code": mfa_module.code_at(enroll["secret"])})

    wrong = client.post(
        "/api/me/mfa/disable",
        json={"password": "correct horse battery staple", "code": "000000"},
    )
    assert wrong.status_code == 400
    assert client.get("/api/me/mfa").get_json()["enabled"] is True


def test_enrollment_rejects_identity_provider_accounts(client):
    suffix = uuid.uuid4().hex[:8]
    with app_module.app.app_context():
        tenant = app_module.Tenant(slug=f"idp-{suffix}", name="IdP", retention_days=30)
        app_module.db.session.add(tenant)
        app_module.db.session.flush()
        user = app_module.User(
            tenant_id=tenant.id,
            email=f"idp-{suffix}@example.test",
            display_name="IdP User",
            role="analyst",
            auth_source="trusted-proxy-sso",
            is_active=True,
        )
        app_module.db.session.add(user)
        app_module.db.session.commit()
        user_id = user.id
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["user_id"] = user_id
        session["auth_source"] = "trusted-proxy-sso"
    response = client.post("/api/me/mfa/enroll", json={"password": "x"})
    assert response.status_code == 409
    assert "identity provider" in response.get_json()["error"]


# ---------------------------------------------------------------------------
# Account security page
# ---------------------------------------------------------------------------


def test_account_page_renders_local_enrollment_surface(client, local_user, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(app_module, "AUTH_REQUIRED", True)
    _sign_in_session(client, local_user)

    response = client.get("/account")
    assert response.status_code == 200
    text = response.data.decode("utf-8")
    assert "Multi-factor authentication" in text
    assert "Begin enrollment" in text
    assert "managed by the identity provider" not in text


def test_account_page_reflects_enabled_mfa(client, local_user, monkeypatch):
    monkeypatch.setattr(app_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(app_module, "AUTH_REQUIRED", True)
    _sign_in_session(client, local_user)
    _enable_mfa(local_user["id"])

    response = client.get("/account")
    assert response.status_code == 200
    text = response.data.decode("utf-8")
    assert "Enabled" in text
    assert "Disable MFA" in text


def test_account_page_explains_identity_provider_accounts(client):
    suffix = uuid.uuid4().hex[:8]
    with app_module.app.app_context():
        tenant = app_module.Tenant(slug=f"idp-page-{suffix}", name="IdP", retention_days=30)
        app_module.db.session.add(tenant)
        app_module.db.session.flush()
        user = app_module.User(
            tenant_id=tenant.id,
            email=f"idp-page-{suffix}@example.test",
            display_name="IdP Page User",
            role="analyst",
            auth_source="trusted-proxy-sso",
            is_active=True,
        )
        app_module.db.session.add(user)
        app_module.db.session.commit()
        user_id = user.id
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["user_id"] = user_id
        session["auth_source"] = "trusted-proxy-sso"
    response = client.get("/account")
    assert response.status_code == 200
    assert b"managed by the identity provider" in response.data

