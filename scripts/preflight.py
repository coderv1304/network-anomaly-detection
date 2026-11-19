#!/usr/bin/env python
"""Preflight gate for a staging or production NetShield deployment.

This is the last automated check before a release starts serving. It is
deliberately stricter than ``scripts/deployment_check.py``: that script proves
artifact identity, while this one also proves the environment looks like a
release environment rather than a developer laptop.

Usage:
    NETSHIELD_ENV=staging venv/Scripts/python.exe scripts/preflight.py
    NETSHIELD_ENV=production venv/Scripts/python.exe scripts/preflight.py --check-oidc
    venv/Scripts/python.exe scripts/preflight.py --json

Exit codes:
    0  all required checks pass (warnings may remain)
    1  at least one required check failed

This gate cannot commission an external review, run a pilot, prove off-host
durability, or validate a real identity provider. It reports what it can see.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from urllib.parse import urlparse

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.environ.setdefault("NETSHIELD_SKIP_BOOTSTRAP", "true")
os.environ.setdefault("METRICS_ENABLED", "false")

from sqlalchemy import create_engine, text  # noqa: E402

from domain.migrations_runtime import MigrationStateError, assert_database_current  # noqa: E402
from training.model_registry import (  # noqa: E402
    DEFAULT_REGISTRY_PATH,
    DeploymentCheckError,
    RegistryError,
    deployment_check,
    resolve_serving_path,
)

PLACEHOLDERS = {
    "change-me",
    "changeme",
    "replace-me",
    "replaceme",
    "password",
    "secret",
    "example",
    "test",
    "todo",
}


def _result(checks, name, status, detail):
    checks.append({"check": name, "status": status, "detail": detail})


def _present(value, minimum=1):
    return isinstance(value, str) and len(value.strip()) >= minimum


def _looks_placeholder(value):
    lowered = (value or "").strip().lower()
    if lowered in PLACEHOLDERS:
        return True
    return lowered.startswith(("change-me", "changeme", "replace-me", "replaceme", "your-", "<"))


def static_checks(env):
    """Return checks that do not need a database connection."""

    checks = []
    environment = (env.get("NETSHIELD_ENV") or "development").strip().lower()
    if environment not in {"staging", "production"}:
        _result(
            checks,
            "environment",
            "fail",
            f"NETSHIELD_ENV={environment!r}; expected staging or production",
        )
    else:
        _result(checks, "environment", "pass", environment)

    for name, minimum in (
        ("SECRET_KEY", 32),
        ("LIVE_CAPTURE_API_KEY", 32),
        ("NETSHIELD_ADMIN_PASSWORD_HASH", 20),
        ("MODEL_SHA256", 64),
        ("SOCKETIO_ALLOWED_ORIGINS", 8),
        ("RATELIMIT_STORAGE_URI", 8),
    ):
        value = env.get(name, "")
        if not _present(value, minimum):
            _result(checks, name.lower(), "fail", f"missing or shorter than {minimum} chars")
        elif _looks_placeholder(value):
            _result(checks, name.lower(), "fail", "looks like a placeholder value")
        else:
            _result(checks, name.lower(), "pass", "present")

    database_url = env.get("DATABASE_URL", "")
    if not database_url:
        _result(checks, "database_url", "fail", "DATABASE_URL is not set")
    elif database_url.lower().startswith("sqlite:"):
        _result(checks, "database_url", "fail", "SQLite is not a release database")
    else:
        parsed = urlparse(database_url.replace("postgresql+psycopg://", "postgresql://"))
        if parsed.scheme not in {"postgres", "postgresql"}:
            _result(
                checks,
                "database_url",
                "fail",
                f"expected PostgreSQL, got {parsed.scheme or 'unknown'}",
            )
        elif not parsed.hostname:
            _result(checks, "database_url", "fail", "DATABASE_URL has no host")
        else:
            _result(checks, "database_url", "pass", f"{parsed.hostname}/{parsed.path.lstrip('/')}")

    rate_limit_uri = env.get("RATELIMIT_STORAGE_URI", "")
    if rate_limit_uri.startswith("memory://"):
        _result(checks, "rate_limit_storage", "fail", "memory:// is process-local")
    elif rate_limit_uri:
        _result(checks, "rate_limit_storage", "pass", urlparse(rate_limit_uri).scheme or "configured")

    if (env.get("ENABLE_LOCAL_CAPTURE") or "false").strip().lower() == "true":
        _result(checks, "local_capture", "fail", "local capture must be disabled in a release")
    else:
        _result(checks, "local_capture", "pass", "disabled")

    if (env.get("NETSHIELD_DEMO_STREAM") or "false").strip().lower() == "true":
        _result(checks, "demo_stream", "fail", "demo streaming must be disabled in a release")
    else:
        _result(checks, "demo_stream", "pass", "disabled")

    if (env.get("MIGRATIONS_REQUIRED") or "true").strip().lower() != "true":
        _result(checks, "migrations_required", "fail", "MIGRATIONS_REQUIRED must be true")
    else:
        _result(checks, "migrations_required", "pass", "enabled")

    if (env.get("TRUSTED_PROXY_SSO") or "false").strip().lower() == "true":
        _result(
            checks,
            "trusted_proxy_sso",
            "warn",
            "legacy shared-secret SSO is enabled; prefer OIDC",
        )

    oidc_enabled = (env.get("OIDC_ENABLED") or "false").strip().lower() == "true"
    if oidc_enabled:
        missing = [
            name
            for name in ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_REDIRECT_URI")
            if not _present(env.get(name, ""))
        ]
        if missing:
            _result(checks, "oidc", "fail", "missing " + ", ".join(missing))
        else:
            issuer = env["OIDC_ISSUER"]
            redirect = env["OIDC_REDIRECT_URI"]
            if not issuer.startswith("https://") or not redirect.startswith("https://"):
                _result(checks, "oidc", "fail", "issuer and redirect URI must use HTTPS")
            elif (env.get("OIDC_DEFAULT_ROLE") or "viewer") not in {
                "viewer",
                "analyst",
                "admin",
            }:
                _result(checks, "oidc", "fail", "OIDC_DEFAULT_ROLE is not a known role")
            else:
                _result(checks, "oidc", "pass", "configured")
    else:
        _result(checks, "oidc", "warn", "OIDC is disabled; SSO is not available")

    backup_key = env.get("NETSHIELD_BACKUP_KEY", "")
    if not backup_key:
        _result(checks, "backup_key", "fail", "NETSHIELD_BACKUP_KEY is not set")
    else:
        try:
            import base64

            raw = base64.b64decode(backup_key, validate=True)
            if len(raw) != 32:
                raise ValueError("key is not 32 bytes")
            _result(checks, "backup_key", "pass", "32-byte key present")
        except (ValueError, TypeError):
            _result(checks, "backup_key", "fail", "key is not base64-encoded 32 bytes")

    offsite = env.get("NETSHIELD_OFFSITE_BACKUP_DIR", "")
    if offsite:
        _result(checks, "offsite_backup", "pass", "destination configured")
    else:
        _result(
            checks,
            "offsite_backup",
            "warn",
            "no off-host backup destination configured; durability is unproven",
        )

    try:
        import cryptography  # noqa: F401
        import alembic  # noqa: F401

        _result(checks, "runtime_modules", "pass", "cryptography and alembic import")
    except ImportError as exc:
        _result(checks, "runtime_modules", "fail", f"missing module: {exc.name}")

    return checks


def database_checks(env):
    checks = []
    database_url = env.get("DATABASE_URL", "")
    if not database_url or database_url.lower().startswith("sqlite:"):
        return checks
    try:
        engine = create_engine(database_url, pool_pre_ping=True)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        _result(checks, "database_connectivity", "pass", "SELECT 1 succeeded")
        try:
            revision = assert_database_current(engine)
            _result(checks, "migrations", "pass", f"at {revision}")
        except MigrationStateError as exc:
            _result(checks, "migrations", "fail", str(exc))
    except Exception as exc:  # noqa: BLE001 - report, do not leak the URL
        _result(
            checks,
            "database_connectivity",
            "fail",
            f"{exc.__class__.__name__}: cannot connect",
        )
    return checks


def artifact_checks(env):
    checks = []
    try:
        serving_path = resolve_serving_path(
            env.get("MODEL_REGISTRY_PATH", DEFAULT_REGISTRY_PATH),
            env.get("MODEL_ARTIFACT_PATH") or None,
        )
        report = deployment_check(
            env.get("MODEL_REGISTRY_PATH", DEFAULT_REGISTRY_PATH),
            serving_path,
            signing_key=env.get("MODEL_SIGNING_KEY") or None,
            expected_sha256=env.get("MODEL_SHA256") or None,
            require_approved=True,
        )
        _result(
            checks,
            "model_artifact",
            "pass",
            f"{report['active']['model_id']} sha256 {report['serving_sha256'][:12]}",
        )
    except (DeploymentCheckError, RegistryError) as exc:
        _result(checks, "model_artifact", "fail", str(exc))
    return checks


def oidc_discovery_check(env):
    if (env.get("OIDC_ENABLED") or "false").strip().lower() != "true":
        return []
    try:
        from domain import oidc as oidc_module
        document = oidc_module.discover(env["OIDC_ISSUER"])
        return [
            {
                "check": "oidc_discovery",
                "status": "pass",
                "detail": document.get("issuer", ""),
            }
        ]
    except Exception as exc:  # noqa: BLE001 - report the class only
        return [
            {
                "check": "oidc_discovery",
                "status": "fail",
                "detail": f"{exc.__class__.__name__}: discovery failed",
            }
        ]


def evaluate(env, check_oidc=False):
    checks = (
        static_checks(env)
        + database_checks(env)
        + artifact_checks(env)
        + (oidc_discovery_check(env) if check_oidc else [])
    )
    failed = [item for item in checks if item["status"] == "fail"]
    warned = [item for item in checks if item["status"] == "warn"]
    return {
        "ok": not failed,
        "summary": {"pass": len(checks) - len(failed) - len(warned), "fail": len(failed), "warn": len(warned)},
        "checks": checks,
        "note": (
            "A passing preflight is not an external review, a pilot, or proof that "
            "an off-host backup is durable. Those remain release blockers."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--check-oidc",
        action="store_true",
        help="Also fetch the OIDC discovery document (network call)",
    )
    args = parser.parse_args(argv)
    report = evaluate(os.environ, check_oidc=args.check_oidc)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for item in report["checks"]:
            print(f"[{item['status'].upper():5}] {item['check']}: {item['detail']}")
        summary = report["summary"]
        print(
            f"preflight: {'PASS' if report['ok'] else 'FAIL'} "
            f"({summary['pass']} pass, {summary['fail']} fail, {summary['warn']} warn)"
        )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

