# Staging, migrations, MFA, and SSO

This document records what is implemented, what is tested, and what is still a
release blocker. It does not upgrade the product score. The honest scorecard
remains detection **4/10**, production SaaS **3/10**, research demo **6/10**,
evidence **9/10**, and UI **8/10**.

## 1. Environments

| `NETSHIELD_ENV` | Authentication | Database | Local capture | Intended use |
|---|---|---|---|---|
| `development` | Optional local identity | SQLite allowed | Opt-in | Research, tests, UI work |
| `staging` | Required | PostgreSQL only | Forced off | Release rehearsal |
| `production` | Required | PostgreSQL only | Forced off | Customer-facing service |

`staging` and `production` share the same startup requirements: `SECRET_KEY`,
`LIVE_CAPTURE_API_KEY`, `NETSHIELD_ADMIN_PASSWORD_HASH`, `DATABASE_URL`,
`SOCKETIO_ALLOWED_ORIGINS`, `RATELIMIT_STORAGE_URI`, and `MODEL_SHA256`.
SQLite and `memory://` rate-limit storage are rejected. Session cookies are
`Secure` in both modes. A filled template is in
[`.env.staging.example`](../.env.staging.example). `tests/test_staging_config.py`
imports the app in a subprocess and proves that these unsafe combinations fail
startup, including incomplete OIDC configuration and a non-HTTPS issuer.

Staging is a configuration profile and a preflight gate. It is **not** an
operated staging environment with a separate account, DNS, TLS certificate,
database, or deployment history. That remains missing evidence.

## 2. Alembic migrations

The schema is now versioned with Alembic.

- Baseline revision: `f68710d807f3` (`migrations/versions/`).
- Metadata source: `app.py` SQLAlchemy models.
- URL source: `DATABASE_URL` or the Flask `SQLALCHEMY_DATABASE_URI`; no
  credential is stored in `alembic.ini`.
- Development and tests still use `db.create_all()` plus the idempotent
  additive helpers. Staging and production **do not** create tables at import.

Deploy sequence:

```bash
# Fresh database
python -m alembic upgrade head

# Existing database that was created by create_all before Alembic existed.
# Verify the tables and columns first, then stamp the baseline once.
python -m alembic stamp head

# Inspect state
python -m alembic current
python -m alembic history --verbose
```

`domain/migrations_runtime.py` checks the database revision during startup when
`MIGRATIONS_REQUIRED=true` (the default in staging and production). Startup
fails closed if the database is unversioned, behind, or ahead of the code. This
is deliberate: a process must not serve against an unexpected schema.

The baseline creates `flow`, `tenants`, `audit_events`, `flow_reviews`,
`flow_review_audit`, and `users`, including the MFA columns. The test
`tests/test_migrations.py` runs the real `alembic upgrade head` command against
a temporary database and compares the resulting table set with the SQLAlchemy
metadata.

There is no production migration history yet: only the baseline exists. A real
site must add a migration for every subsequent schema change and rehearse the
upgrade against a staging snapshot.

## 3. Preflight gate

```bash
NETSHIELD_ENV=staging venv/Scripts/python.exe scripts/preflight.py
NETSHIELD_ENV=staging venv/Scripts/python.exe scripts/preflight.py --check-oidc
NETSHIELD_ENV=staging venv/Scripts/python.exe scripts/preflight.py --json
```

The gate checks:

- environment name, required settings, placeholder values, and key length;
- PostgreSQL rather than SQLite, and shared rate-limit storage;
- database connectivity with `SELECT 1`;
- current Alembic revision;
- approved model artifact and SHA-256 through `scripts/deployment_check.py`;
- disabled local capture and demo streaming;
- encrypted-backup key shape and optional off-host destination;
- `cryptography` and `alembic` import;
- optional live OIDC discovery.

A pass is not an external review, a pilot, or proof that an off-host backup is
durable. Those remain blockers.

## 4. Multi-factor authentication

Local password accounts support TOTP (RFC 6238, SHA-1, 6 digits, 30-second
period) with a ±1 step window and replay rejection.

- Secrets are Fernet-encrypted with a key derived from `SECRET_KEY`. Rotating
  `SECRET_KEY` makes existing enrollments unreadable; login then fails closed
  with a 503 rather than silently skipping MFA.
- Eight single-use recovery codes are shown once and stored only as password
  hashes. A used code is removed.
- The login challenge is a separate step after password verification. Five
  failed second-factor attempts end the challenge.
- Ten failed enrollments per minute are rate-limited by the login limiter.
- `/account` is the self-service surface: enroll, view recovery-code count,
  confirm, disable, copy/download codes.
- `scripts/mfa_admin.py` is the shell-access break-glass path:
  `status`, `enroll`, `confirm`, `disable`. It cannot be called remotely.
- Every login, MFA challenge, success, failure, enrollment, confirmation, and
  disable event is audited.

Tests cover RFC 6238 vectors, encryption and wrong-key failure, single-use
recovery codes, challenge/lockout, replay rejection, fail-closed enrollment,
API authentication, and the account page. This is implemented account MFA, not
a claim that every tenant has enrolled.

## 5. OIDC SSO

`domain/oidc.py` implements the authorization-code flow with:

- discovery-document validation;
- `state`, `nonce`, and PKCE S256;
- code exchange with `client_secret_basic` or `client_secret_post`;
- RS256 ID-token verification against the provider JWKS;
- issuer, audience, `azp`, nonce, expiry, `iat`, and `nbf` checks;
- explicit rejection of `none`, HMAC, and non-RS256 algorithms;
- verified-email enforcement by default.

Routes:

- `GET /auth/oidc/login`
- `GET /auth/oidc/callback`

Provisioning policy:

- Existing `auth_source='oidc'` users sign in normally.
- Unknown users are denied unless `OIDC_JIT_PROVISIONING=true`; JIT users are
  created in `OIDC_DEFAULT_TENANT` with `OIDC_DEFAULT_ROLE` (default `viewer`).
- Existing local or trusted-proxy accounts are not linked by email unless
  `OIDC_LINK_LOCAL_ACCOUNTS=true`. The default prevents an IdP email claim from
  taking over a local account.
- `OIDC_REQUIRE_VERIFIED_EMAIL=true` is the default.
- OIDC is disabled unless `OIDC_ENABLED=true`; the routes return 404 otherwise.
- Production and staging validate HTTPS issuer/redirect URLs at startup.

Tests use a locally generated RSA key, a fake JWKS, and a mocked provider. They
cover valid tokens, wrong nonce/audience/issuer/`azp`, expiry, future `iat`,
tampered signatures, unknown keys, PKCE, state mismatch, unprovisioned users,
JIT provisioning, local-account linking refusal, unverified email, and disabled
routes.

**Not tested:** a real Okta/Entra/Keycloak/Auth0 tenant, provider-specific claim
quirks, clock skew beyond the ±60 s leeway, token revocation, back-channel or
RP-initiated logout, SCIM provisioning, and group-to-role mapping. OIDC remains
a code-level capability until a real provider integration is completed.

## 6. What is still missing

- An external penetration test and external readiness review.
- A managed secret store; `SECRET_KEY` and backup keys are still injected as
  environment variables.
- An operated staging environment with its own DNS, TLS, database, and
  deployment history.
- A real OIDC provider integration.
- Off-host encrypted backup with site-measured RPO/RTO.
- Billing, support load measurement, and a design-partner pilot.
- Sustained SLO evidence above 20 flows/s.
