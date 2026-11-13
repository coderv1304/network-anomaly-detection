"""Staging and production configuration must fail closed at startup."""

import os
import subprocess
import sys

import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _base_env():
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": PROJECT_ROOT,
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
            "METRICS_ENABLED": "false",
            "NETSHIELD_SKIP_BOOTSTRAP": "true",
        }
    )
    env.pop("OIDC_ENABLED", None)
    env.pop("OIDC_ISSUER", None)
    env.pop("OIDC_CLIENT_ID", None)
    env.pop("OIDC_REDIRECT_URI", None)
    env.pop("OIDC_CLIENT_SECRET", None)
    return env


def _import_app(env):
    return subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"DATABASE_URL": "sqlite:///local.db"}, "require a managed database"),
        ({"RATELIMIT_STORAGE_URI": "memory://"}, "require shared storage"),
        ({"SECRET_KEY": ""}, "Missing required production/staging settings"),
    ],
)
def test_staging_startup_rejects_release_unsafe_settings(overrides, message):
    env = _base_env()
    env.update(overrides)
    completed = _import_app(env)
    assert completed.returncode != 0
    assert message in (completed.stderr + completed.stdout)


def test_staging_startup_rejects_incomplete_oidc_configuration():
    env = _base_env()
    env.update({"OIDC_ENABLED": "true", "OIDC_ISSUER": "https://idp.example.test"})
    completed = _import_app(env)
    assert completed.returncode != 0
    assert "OIDC is enabled but missing settings" in (completed.stderr + completed.stdout)


def test_staging_startup_rejects_plain_http_issuer():
    env = _base_env()
    env.update(
        {
            "OIDC_ENABLED": "true",
            "OIDC_ISSUER": "http://idp.example.test",
            "OIDC_CLIENT_ID": "netshield",
            "OIDC_REDIRECT_URI": "https://netshield.example.test/auth/oidc/callback",
        }
    )
    completed = _import_app(env)
    assert completed.returncode != 0
    assert "OIDC_ISSUER must use HTTPS" in (completed.stderr + completed.stdout)
