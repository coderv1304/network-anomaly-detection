"""Staging/production preflight checks."""

import base64
import os
import sys

import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import preflight  # noqa: E402


def _valid_env(**overrides):
    env = {
        "NETSHIELD_ENV": "staging",
        "SECRET_KEY": "s" * 48,
        "LIVE_CAPTURE_API_KEY": "k" * 48,
        "NETSHIELD_ADMIN_PASSWORD_HASH": "pbkdf2:sha256:" + "a" * 64,
        "MODEL_SHA256": "a" * 64,
        "SOCKETIO_ALLOWED_ORIGINS": "https://netshield.example.test",
        "RATELIMIT_STORAGE_URI": "redis://redis:6379/0",
        "DATABASE_URL": "postgresql://netshield:pass@db:5432/netshield",
        "ENABLE_LOCAL_CAPTURE": "false",
        "NETSHIELD_DEMO_STREAM": "false",
        "MIGRATIONS_REQUIRED": "true",
        "NETSHIELD_BACKUP_KEY": base64.b64encode(b"x" * 32).decode(),
        "OIDC_ENABLED": "true",
        "OIDC_ISSUER": "https://idp.example.test",
        "OIDC_CLIENT_ID": "netshield",
        "OIDC_REDIRECT_URI": "https://netshield.example.test/auth/oidc/callback",
        "OIDC_DEFAULT_ROLE": "viewer",
    }
    env.update(overrides)
    return env


def _statuses(checks):
    return {item["check"]: item["status"] for item in checks}


def test_valid_staging_environment_passes_static_checks():
    checks = preflight.static_checks(_valid_env())
    statuses = _statuses(checks)
    assert statuses["environment"] == "pass"
    assert statuses["database_url"] == "pass"
    assert statuses["oidc"] == "pass"
    assert statuses["backup_key"] == "pass"
    assert all(status != "fail" for status in statuses.values())


@pytest.mark.parametrize(
    ("overrides", "check"),
    [
        ({"NETSHIELD_ENV": "development"}, "environment"),
        ({"SECRET_KEY": "change-me"}, "secret_key"),
        ({"DATABASE_URL": "sqlite:///local.db"}, "database_url"),
        ({"RATELIMIT_STORAGE_URI": "memory://"}, "rate_limit_storage"),
        ({"ENABLE_LOCAL_CAPTURE": "true"}, "local_capture"),
        ({"NETSHIELD_DEMO_STREAM": "true"}, "demo_stream"),
        ({"MIGRATIONS_REQUIRED": "false"}, "migrations_required"),
        ({"OIDC_ENABLED": "true", "OIDC_ISSUER": ""}, "oidc"),
        ({"NETSHIELD_BACKUP_KEY": "not-base64"}, "backup_key"),
        ({"NETSHIELD_BACKUP_KEY": ""}, "backup_key"),
    ],
)
def test_static_checks_fail_closed(overrides, check):
    statuses = _statuses(preflight.static_checks(_valid_env(**overrides)))
    assert statuses[check] == "fail"


def test_oidc_is_a_warning_when_disabled():
    statuses = _statuses(preflight.static_checks(_valid_env(OIDC_ENABLED="false")))
    assert statuses["oidc"] == "warn"
