"""Flask research application for batch flow analysis and stored-flow review.

The application accepts flow CSV and PCAP/PCAPNG uploads, runs local model
inference, and exposes stored prediction records through a browser dashboard.
The dashboard polls the API. Optional local PyFlowMeter capture is disabled by
default and is experimental; capture-to-training feature parity is unverified.
This application is not a validated production network detection service.

REST API
--------
POST /api/flows              -> ingest a flow record (collector endpoint)
GET  /api/flows              -> paginated stored flow history
GET  /api/flows/<id>         -> one stored flow record
GET  /api/stats              -> counts by predicted label
GET  /api/incidents          -> host/window multi-signal incidents
GET  /api/unmapped-features  -> feature-mapping diagnostic
"""

import os
import re
import csv
import io
import json
import hashlib
import math
import secrets
import statistics
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from functools import wraps
from hmac import compare_digest

import joblib
import numpy as np
import pandas as pd
from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import inspect, text
from werkzeug.security import check_password_hash, generate_password_hash

from feature_mapper import (
    FEATURE_NAME_OVERRIDES,
    UNMAPPED_LOG,
    _auto_normalize,
    normalize_flow_features,
)
from evidence_accumulator import (
    EvidenceAccumulator,
    Observation,
    isolation_confidence,
    load_calibrator,
)
from pcap_parser import pcap_to_flows as _pcap_to_flows
import mfa as mfa_module
import oidc as oidc_module
from threat_intel import lookup_abuseipdb
from monitoring.prometheus_metrics import (
    ALERT_DELIVERY_FAILURES,
    ALERT_DELIVERY_LATENCY,
    ALERTS_EMITTED,
    API_LATENCY,
    API_REQUESTS,
    BUILD_INFO,
    FLOW_STORE_ROWS,
    INGEST_BACKPRESSURE_REJECTIONS,
    INGEST_BATCH_SIZE,
    INGEST_FLOWS,
    INGEST_INFLIGHT,
    INGEST_QUEUE_DEPTH,
    INGEST_RATE_LIMITED,
    INGEST_REQUESTS,
    INGEST_STAGE_LATENCY,
    PREDICTION_ERRORS,
    PREDICTION_LABELS,
    PREDICTION_LATENCY,
    STORAGE_LATENCY,
    STORAGE_OPERATIONS,
    start_metrics_server,
)
from monitoring.structured_logging import configure_structured_logging
from training.model_registry import (
    active_entry,
    deployment_check,
    feature_schema_sha256,
    feature_schema_version,
    resolve_serving_path,
)

# ---------------------------------------------------------------------
# Live capture interface selection (used by the capture thread started at
# the bottom of this file).
#
# NETSHIELD_CAPTURE_INTERFACE accepts:
#   auto       the adapter that owns the OS default route right now — works
#              for Wi-Fi, Ethernet, mobile hotspot / USB tethering, VPN, or
#              any other connectivity without configuration changes
#   all        every adapter that has an IP address, captured simultaneously
#   loopback   the loopback adapter only
#   a comma-separated list of adapter names, descriptions, IPs, or Npcap GUIDs
# ---------------------------------------------------------------------
CAPTURE_INTERFACE = os.environ.get(
    "NETSHIELD_CAPTURE_INTERFACE",
    "auto",
)
CAPTURE_STATUS = {
    "state": "not_started",
    "interface": CAPTURE_INTERFACE,
    "interfaces": [],
    "unknown_interfaces": [],
    "flows_received": 0,
    "last_flow_at": None,
    "message": "Start the application with python app.py to enable packet capture.",
    "capture_requested": os.environ.get("ENABLE_LOCAL_CAPTURE", "false").lower() == "true",
    "demo_stream_enabled": os.environ.get("NETSHIELD_DEMO_STREAM", "false").lower() == "true",
    "prediction_boundary": (
        "Flow predictions are unvalidated on live capture: no labelled live "
        "traffic exists, the live extractor's flag counts are 0/1 indicators, "
        "and the two extractors disagree on several numeric features."
    ),
}

APP_ENV = os.environ.get("NETSHIELD_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"
IS_STAGING = APP_ENV == "staging"
# Staging uses the same authentication, cookie, database, and rate-limit
# requirements as production. It exists to rehearse a release, not to run with
# development conveniences.
AUTH_REQUIRED = IS_PRODUCTION or IS_STAGING
MIGRATIONS_REQUIRED = os.environ.get(
    "MIGRATIONS_REQUIRED", "true" if AUTH_REQUIRED else "false"
).strip().lower() == "true"
MODEL_REGISTRY_PATH = os.environ.get("MODEL_REGISTRY_PATH", "models/registry/registry.json")
MODEL_SIGNING_KEY = os.environ.get("MODEL_SIGNING_KEY") or None
REQUIRE_APPROVED_MODEL = os.environ.get(
    "REQUIRE_APPROVED_MODEL", "true" if AUTH_REQUIRED else "false"
).strip().lower() == "true"
DEFAULT_TENANT_SLUG = os.environ.get("NETSHIELD_DEFAULT_TENANT", "default").strip().lower() or "default"
DEFAULT_TENANT_NAME = os.environ.get("NETSHIELD_DEFAULT_TENANT_NAME", "Default tenant")
ADMIN_EMAIL = os.environ.get("NETSHIELD_ADMIN_EMAIL", "admin@localhost").strip().lower()
TRUSTED_PROXY_SSO = os.environ.get("NETSHIELD_TRUSTED_PROXY_SSO", "false").lower() == "true"
PROXY_SHARED_SECRET = os.environ.get("NETSHIELD_PROXY_SHARED_SECRET", "")
INGEST_TENANT_SLUG = os.environ.get("NETSHIELD_INGEST_TENANT", DEFAULT_TENANT_SLUG).strip().lower()

# OpenID Connect SSO. Disabled unless an operator supplies an issuer, client,
# and explicit redirect URI. JIT provisioning and linking existing local
# accounts are opt-in because both widen the identity trust boundary.
OIDC_ENABLED = os.environ.get("OIDC_ENABLED", "false").strip().lower() == "true"
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").strip().rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "").strip()
OIDC_SCOPES = os.environ.get("OIDC_SCOPES", "openid email profile").strip()
OIDC_TOKEN_AUTH_METHOD = os.environ.get(
    "OIDC_TOKEN_AUTH_METHOD", "client_secret_basic"
).strip()
OIDC_EMAIL_CLAIM = os.environ.get("OIDC_EMAIL_CLAIM", "email").strip() or "email"
OIDC_NAME_CLAIM = os.environ.get("OIDC_NAME_CLAIM", "name").strip() or "name"
OIDC_REQUIRE_VERIFIED_EMAIL = os.environ.get(
    "OIDC_REQUIRE_VERIFIED_EMAIL", "true"
).strip().lower() == "true"
OIDC_JIT_PROVISIONING = os.environ.get(
    "OIDC_JIT_PROVISIONING", "false"
).strip().lower() == "true"
OIDC_LINK_LOCAL_ACCOUNTS = os.environ.get(
    "OIDC_LINK_LOCAL_ACCOUNTS", "false"
).strip().lower() == "true"
OIDC_DEFAULT_ROLE = os.environ.get("OIDC_DEFAULT_ROLE", "viewer").strip() or "viewer"
OIDC_DEFAULT_TENANT_SLUG = os.environ.get(
    "OIDC_DEFAULT_TENANT", DEFAULT_TENANT_SLUG
).strip().lower() or DEFAULT_TENANT_SLUG
OIDC_FLOW_SESSION_KEY = "oidc_flow"
OIDC_FLOW_TTL_SECONDS = 300

_required_production_settings = (
    "SECRET_KEY",
    "LIVE_CAPTURE_API_KEY",
    "NETSHIELD_ADMIN_PASSWORD_HASH",
    "DATABASE_URL",
    "SOCKETIO_ALLOWED_ORIGINS",
    "RATELIMIT_STORAGE_URI",
    "MODEL_SHA256",
)
if AUTH_REQUIRED:
    _missing = [name for name in _required_production_settings if not os.environ.get(name)]
    if _missing:
        raise RuntimeError("Missing required production/staging settings: " + ", ".join(_missing))
    if os.environ["DATABASE_URL"].lower().startswith("sqlite:"):
        raise RuntimeError("Production and staging require a managed database; SQLite is for local research only.")
    if os.environ["RATELIMIT_STORAGE_URI"].startswith("memory://"):
        raise RuntimeError("Production and staging rate limits require shared storage, for example Redis.")
    if OIDC_ENABLED:
        _missing_oidc = [
            name
            for name, value in (
                ("OIDC_ISSUER", OIDC_ISSUER),
                ("OIDC_CLIENT_ID", OIDC_CLIENT_ID),
                ("OIDC_REDIRECT_URI", OIDC_REDIRECT_URI),
            )
            if not value
        ]
        if _missing_oidc:
            raise RuntimeError(
                "OIDC is enabled but missing settings: " + ", ".join(_missing_oidc)
            )
        if not OIDC_ISSUER.startswith("https://"):
            raise RuntimeError("OIDC_ISSUER must use HTTPS in production.")
        if not OIDC_REDIRECT_URI.startswith("https://"):
            raise RuntimeError("OIDC_REDIRECT_URI must use HTTPS in production.")
        if OIDC_DEFAULT_ROLE not in {"viewer", "analyst", "admin"}:
            raise RuntimeError("OIDC_DEFAULT_ROLE must be viewer, analyst, or admin.")

_configured_api_key = os.environ.get("LIVE_CAPTURE_API_KEY")
API_KEY = _configured_api_key or secrets.token_urlsafe(32)
_secret_key = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(32)
_allowed_origins = [
    origin.strip()
    for origin in os.environ.get(
        "SOCKETIO_ALLOWED_ORIGINS",
        "http://localhost:5000,http://127.0.0.1:5000",
    ).split(",")
    if origin.strip()
]

app = Flask(__name__)
app.config["SECRET_KEY"] = _secret_key
database_url = os.environ.get("DATABASE_URL", "sqlite:///network_anomaly.db")
if database_url.startswith("postgres://"):
    database_url = "postgresql+psycopg://" + database_url[len("postgres://"):]
elif database_url.startswith("postgresql://"):
    database_url = "postgresql+psycopg://" + database_url[len("postgresql://"):]
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", str(50 * 1024 * 1024)))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = AUTH_REQUIRED
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_REFRESH_EACH_REQUEST"] = False
app.config["JSON_SORT_KEYS"] = False

configure_structured_logging(app)
BUILD_INFO.labels(
    version=os.environ.get("NETSHIELD_VERSION", "dev"),
    environment=APP_ENV,
).set(1)

# Bounded ingest admission. Classification plus persistence is synchronous, so
# a hard concurrency ceiling is the backpressure point: callers receive 503 +
# Retry-After instead of the process accumulating unbounded work.
INGEST_MAX_INFLIGHT = max(1, int(os.environ.get("INGEST_MAX_INFLIGHT", "4")))
INGEST_QUEUE_TIMEOUT_MS = max(0, int(os.environ.get("INGEST_QUEUE_TIMEOUT_MS", "250")))
# Declared analyst alert budget. This is a reporting cap over a rolling window,
# not a threshold retune. The default matches the D9 100-alert/10k sensitivity
# point; the actual operating budget must be supplied by the site.
ALERT_BUDGET_PER_10K = max(0, int(os.environ.get("ALERT_BUDGET_PER_10K", "100")))
ALERT_BUDGET_WINDOW_MINUTES = max(1, int(os.environ.get("ALERT_BUDGET_WINDOW_MINUTES", "60")))
_INGEST_ADMISSION = threading.BoundedSemaphore(INGEST_MAX_INFLIGHT)
_INGEST_DEPTH_LOCK = threading.Lock()
_INGEST_WAITING = 0
_INGEST_ACTIVE = 0

@app.route('/service-worker.js')
def service_worker():
    response = send_from_directory('static', 'service-worker.js')
    response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
    # Never let browsers/CDNs cache the SW file itself — it's how updates propagate.
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Service-Worker-Allowed'] = '/'
    return response
 
 
@app.route('/manifest.json')
def manifest_alias():
    # Optional convenience alias so /manifest.json also works;
    # the canonical file lives at /static/manifest.json.
    response = send_from_directory('static', 'manifest.json')
    response.headers['Content-Type'] = 'application/manifest+json'
    return response
 
 
@app.route('/offline.html')
def offline_page():
    return send_from_directory('static', 'offline.html')
 
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins=_allowed_origins, async_mode="threading")
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    default_limits=[],
)


def _queue_state() -> dict:
    with _INGEST_DEPTH_LOCK:
        waiting = _INGEST_WAITING
        active = _INGEST_ACTIVE
    return {
        "max_inflight": INGEST_MAX_INFLIGHT,
        "inflight": active,
        "waiting": waiting,
        "admission_timeout_ms": INGEST_QUEUE_TIMEOUT_MS,
    }


def _backpressure_response():
    INGEST_BACKPRESSURE_REJECTIONS.inc()
    INGEST_REQUESTS.labels(outcome="rejected_backpressure").inc()
    retry_after = max(1, math.ceil(INGEST_QUEUE_TIMEOUT_MS / 1000))
    app.logger.warning(
        "ingest.backpressure",
        extra={
            "event": "ingest",
            "outcome": "rejected_backpressure",
            "queue_depth": _queue_state()["waiting"],
        },
    )
    return (
        jsonify(
            {
                "error": "Ingest is saturated; retry shortly.",
                "request_id": getattr(g, "request_id", None),
                "retry_after_seconds": retry_after,
            }
        ),
        503,
        {"Retry-After": str(retry_after)},
    )


def ingest_admission(view_func):
    """Bound concurrent ingest work and reject predictably when saturated."""

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        global _INGEST_WAITING, _INGEST_ACTIVE
        with _INGEST_DEPTH_LOCK:
            _INGEST_WAITING += 1
            INGEST_QUEUE_DEPTH.set(_INGEST_WAITING)
        try:
            acquired = _INGEST_ADMISSION.acquire(
                timeout=INGEST_QUEUE_TIMEOUT_MS / 1000
            )
        finally:
            with _INGEST_DEPTH_LOCK:
                _INGEST_WAITING -= 1
                INGEST_QUEUE_DEPTH.set(_INGEST_WAITING)
        if not acquired:
            return _backpressure_response()
        with _INGEST_DEPTH_LOCK:
            _INGEST_ACTIVE += 1
        INGEST_INFLIGHT.inc()
        try:
            return view_func(*args, **kwargs)
        finally:
            INGEST_INFLIGHT.dec()
            with _INGEST_DEPTH_LOCK:
                _INGEST_ACTIVE -= 1
            _INGEST_ADMISSION.release()

    return wrapped


@app.errorhandler(429)
def rate_limit_exceeded(error):
    if request.endpoint == "ingest_flow":
        INGEST_RATE_LIMITED.inc()
    retry_after = getattr(error, "retry_after", None) or 60
    app.logger.warning(
        "request.rate_limited",
        extra={
            "event": "rate_limit",
            "outcome": "rejected_rate_limited",
            "status": 429,
        },
    )
    return (
        jsonify(
            {
                "error": "Rate limit exceeded.",
                "request_id": getattr(g, "request_id", None),
                "retry_after_seconds": retry_after,
            }
        ),
        429,
        {"Retry-After": str(retry_after)},
    )


@app.errorhandler(503)
def service_unavailable(error):
    return (
        jsonify(
            {
                "error": "Service temporarily unavailable.",
                "request_id": getattr(g, "request_id", None),
            }
        ),
        503,
        {"Retry-After": "1"},
    )

# Metrics are opt-in so importing the application has no network side effects.
if os.environ.get("METRICS_ENABLED", "false").lower() == "true":
    start_metrics_server(
        int(os.environ.get("METRICS_PORT", "8000")),
        addr=os.environ.get("METRICS_HOST", "127.0.0.1"),
    )
# API key auth for write endpoints
# ---------------------------------------------------------------------
def require_api_key(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        supplied = request.headers.get("X-API-Key")
        if not supplied and not AUTH_REQUIRED and request.remote_addr in {"127.0.0.1", "::1"}:
            supplied = request.args.get("api_key")
        if not (supplied and compare_digest(supplied, API_KEY)) and current_identity() is None:
            return jsonify({"error": "Missing or invalid API key"}), 401
        return view_func(*args, **kwargs)

    return wrapped


def csrf_token():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_security_template_values():
    artifact_hash = (_serving_artifact.get("hash") or "") if "_serving_artifact" in globals() else ""
    return {
        "csrf_token": csrf_token,
        "auth_enabled": AUTH_REQUIRED,
        "demo_enabled": os.environ.get("NETSHIELD_DEMO_STREAM", "false").lower() == "true",
        "scope_artifact_hash_prefix": artifact_hash[:12] if artifact_hash else "unavailable",
        "scope_evidence_date": "2026-11-12",
    }


@app.before_request
def enforce_production_authentication():
    g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    g.request_started = time.perf_counter()
    g.route_template = request.url_rule.rule if request.url_rule else request.path
    identity = current_identity()
    if identity is not None:
        g.tenant_id = identity.get("tenant_id")
        g.actor = identity.get("actor")

    if not AUTH_REQUIRED:
        return None

    public_endpoints = {"static", "service_worker", "manifest_alias", "offline_page", "login", "healthz", "readyz", "oidc_login", "oidc_callback"}
    if request.endpoint in public_endpoints:
        return None

    # Collector credentials are write-only: a service key may ingest flows,
    # but cannot read customer data or mutate analyst reviews.
    is_collector_ingest = request.endpoint == "ingest_flow" and request.method == "POST"
    supplied_key = request.headers.get("X-API-Key") if is_collector_ingest else None
    has_service_key = bool(supplied_key and compare_digest(supplied_key, API_KEY))
    has_session = identity is not None
    if not has_session and not has_service_key:
        if request.path.startswith("/api/") or request.path == "/predict":
            return jsonify({"error": "Authentication required"}), 401
        return redirect(url_for("login"))

    if has_session and request.method not in {"GET", "HEAD", "OPTIONS"}:
        # Trusted-proxy SSO is a server-to-server integration authenticated by
        # the shared secret, not a browser cookie flow. Still require the secret
        # on the request so a leaked session alone cannot bypass CSRF.
        if identity.get("auth_source") == "trusted-proxy-sso":
            supplied_proxy_secret = request.headers.get("X-NetShield-Proxy-Secret", "")
            if supplied_proxy_secret and compare_digest(supplied_proxy_secret, PROXY_SHARED_SECRET):
                return None
        supplied_csrf = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        expected_csrf = session.get("csrf_token", "")
        if not supplied_csrf or not compare_digest(supplied_csrf, expected_csrf):
            return jsonify({"error": "Invalid CSRF token"}), 400
    return None


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    # All assets are served from this origin and Google Fonts was removed, so
    # require-corp does not block any subresource the UI needs.
    response.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'",
    )
    # HTML, JSON, and error responses can contain flow metadata; never let a
    # shared or browser cache store them. Static assets keep their own caching.
    if not request.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "no-store")
    if AUTH_REQUIRED and request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    request_id = getattr(g, "request_id", None)
    if request_id:
        response.headers["X-Request-ID"] = request_id
    started = getattr(g, "request_started", None)
    if started is not None:
        duration = time.perf_counter() - started
        route = getattr(g, "route_template", None) or request.path
        API_LATENCY.labels(request.method, route).observe(duration)
        API_REQUESTS.labels(request.method, route, str(response.status_code)).inc()
        if request.path not in {"/healthz", "/readyz"} and not request.path.startswith("/static/"):
            app.logger.info(
                "request.complete",
                extra={
                    "event": "http_request",
                    "status": response.status_code,
                    "duration_ms": round(duration * 1000, 3),
                    "outcome": (
                        "ok"
                        if response.status_code < 400
                        else "client_error"
                        if response.status_code < 500
                        else "server_error"
                    ),
                },
            )
    return response


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.route("/readyz")
def readyz():
    try:
        db.session.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        app.logger.exception("readiness.database_failed")
        return jsonify({"status": "not_ready", "reason": "database"}), 503
    return jsonify({"status": "ready", "ingest": _queue_state()})


MFA_PENDING_SESSION_KEY = "mfa_pending"
MFA_PENDING_TTL_SECONDS = 300
MFA_MAX_ATTEMPTS = 5


def _user_mfa_secret(user):
    """Decrypt a user's TOTP secret, logging (not raising) a key mismatch."""

    if user is None or not user.totp_secret:
        return None
    try:
        return mfa_module.decrypt_secret(user.totp_secret, app.config["SECRET_KEY"])
    except mfa_module.MfaError:
        app.logger.error("mfa.secret_decrypt_failed", extra={"user_id": user.id})
        return None


def _begin_mfa_challenge(user):
    session[MFA_PENDING_SESSION_KEY] = {
        "user_id": user.id,
        "expires_at": int(time.time()) + MFA_PENDING_TTL_SECONDS,
        "attempts": 0,
    }


def _clear_mfa_challenge():
    session.pop(MFA_PENDING_SESSION_KEY, None)


def _pending_mfa_user():
    pending = session.get(MFA_PENDING_SESSION_KEY)
    if not isinstance(pending, dict):
        return None
    if int(pending.get("expires_at", 0)) < int(time.time()):
        _clear_mfa_challenge()
        return None
    user = db.session.get(User, pending.get("user_id"))
    if user is None or not user.is_active or not user.totp_enabled:
        _clear_mfa_challenge()
        return None
    return user


def _verify_second_factor(user, otp, allow_same_step=False):
    """Return ``"totp"``, ``"recovery_code"``, or ``None`` and update state.

    Login rejects replay of the same time step. Disabling MFA may accept the
    current step because it is a password-gated state change, not a new session.
    """

    secret = _user_mfa_secret(user)
    if secret:
        matched_step = mfa_module.verify_code(secret, otp)
        if matched_step is not None:
            if user.totp_last_step is None:
                accepted = True
            elif allow_same_step:
                accepted = matched_step >= user.totp_last_step
            else:
                accepted = matched_step > user.totp_last_step
            if accepted:
                user.totp_last_step = matched_step
                return "totp"
    matched, remaining = mfa_module.match_recovery_code(user.mfa_recovery_hashes, otp)
    if matched:
        user.mfa_recovery_hashes = remaining
        return "recovery_code"
    return None


def _finish_login(user, method):
    _clear_mfa_challenge()
    user.last_login_at = datetime.utcnow()
    db.session.commit()
    _establish_session(user, user.auth_source or "local")
    record_audit(
        "auth.login",
        "user",
        user.id,
        detail={"method": method},
        tenant_id=user.tenant_id,
        actor=user.email,
        actor_role=user.role,
        commit=True,
    )
    return redirect(url_for("index"))


def _mfa_step_response(user, error=None, status=200):
    pending = session.get(MFA_PENDING_SESSION_KEY, {})
    return (
        render_template(
            "login.html",
            mfa_step=True,
            mfa_attempts_remaining=max(
                0, MFA_MAX_ATTEMPTS - int(pending.get("attempts", 0))
            ),
            error=error,
        ),
        status,
    )


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if not AUTH_REQUIRED and not TRUSTED_PROXY_SSO:
        return redirect(url_for("index"))
    if request.method == "GET":
        if _pending_mfa_user() is not None:
            return _mfa_step_response(None)
        return render_template("login.html")

    supplied_csrf = request.form.get("csrf_token", "")
    if not supplied_csrf or not compare_digest(supplied_csrf, session.get("csrf_token", "")):
        return render_template("login.html", error="Session expired. Reload this page and try again."), 400

    pending_user = _pending_mfa_user()
    if pending_user is not None:
        otp = (request.form.get("otp") or "").strip()
        if not otp:
            return _mfa_step_response(pending_user, "Enter your authentication code.", 401)
        method = _verify_second_factor(pending_user, otp)
        if method is None:
            pending = session.get(MFA_PENDING_SESSION_KEY, {})
            attempts = int(pending.get("attempts", 0)) + 1
            record_audit(
                "auth.mfa",
                "user",
                pending_user.id,
                outcome="failure",
                detail={"attempts": attempts},
                tenant_id=pending_user.tenant_id,
                actor=pending_user.email,
                actor_role=pending_user.role,
                commit=True,
            )
            db.session.rollback()
            if attempts >= MFA_MAX_ATTEMPTS:
                _clear_mfa_challenge()
                return (
                    render_template(
                        "login.html",
                        error="Too many verification attempts. Sign in again.",
                    ),
                    429,
                )
            pending["attempts"] = attempts
            session[MFA_PENDING_SESSION_KEY] = pending
            return _mfa_step_response(
                pending_user, "That code is not valid. Try again.", 401
            )
        record_audit(
            "auth.mfa",
            "user",
            pending_user.id,
            detail={"method": method},
            tenant_id=pending_user.tenant_id,
            actor=pending_user.email,
            actor_role=pending_user.role,
            commit=True,
        )
        return _finish_login(pending_user, f"password+{method}")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password", "")
    user = None

    if email:
        candidate = User.query.filter_by(email=email, is_active=True).first()
        if candidate and candidate.password_hash and check_password_hash(candidate.password_hash, password):
            user = candidate
    else:
        # Legacy single-admin login remains supported for existing deployments.
        password_hash = os.environ.get("NETSHIELD_ADMIN_PASSWORD_HASH", "")
        if password_hash and password and check_password_hash(password_hash, password):
            user = User.query.filter_by(email=ADMIN_EMAIL, is_active=True).first()

    if user is None:
        record_audit(
            "auth.login",
            "user",
            email or ADMIN_EMAIL,
            outcome="failure",
            detail={"method": "password"},
            actor=email or "unknown",
            actor_role="anonymous",
            tenant_id=current_tenant_id(),
            commit=True,
        )
        return render_template("login.html", error="Sign-in failed. Check your credentials and try again."), 401

    if user.totp_enabled:
        if _user_mfa_secret(user) is None:
            # Fail closed. Skipping MFA because the key changed would silently
            # downgrade the account.
            record_audit(
                "auth.mfa",
                "user",
                user.id,
                outcome="failure",
                detail={"reason": "secret_unreadable"},
                tenant_id=user.tenant_id,
                actor=user.email,
                actor_role=user.role,
                commit=True,
            )
            return (
                render_template(
                    "login.html",
                    error="Multi-factor authentication is misconfigured for this account. Contact an administrator.",
                ),
                503,
            )
        _begin_mfa_challenge(user)
        record_audit(
            "auth.mfa",
            "user",
            user.id,
            detail={"method": "challenge"},
            tenant_id=user.tenant_id,
            actor=user.email,
            actor_role=user.role,
            commit=True,
        )
        return _mfa_step_response(user)

    return _finish_login(user, "password")


@app.route("/logout", methods=["POST"])
def logout():
    identity = current_identity()
    if identity:
        record_audit("auth.logout", "user", identity.get("user_id"), commit=True)
    session.clear()
    return redirect(url_for("login" if AUTH_REQUIRED else "index"))


@app.context_processor
def _auth_template_context():
    return {"oidc_enabled": OIDC_ENABLED}


def _current_oidc_flow():
    flow = session.get(OIDC_FLOW_SESSION_KEY)
    if not isinstance(flow, dict):
        return None
    if int(flow.get("expires_at", 0)) < int(time.time()):
        session.pop(OIDC_FLOW_SESSION_KEY, None)
        return None
    return flow


def _oidc_failure(reason, status=400, detail=None):
    session.pop(OIDC_FLOW_SESSION_KEY, None)
    record_audit(
        "auth.oidc",
        "user",
        None,
        outcome="failure",
        detail={"reason": reason, **(detail or {})},
        actor="anonymous",
        actor_role="anonymous",
        commit=True,
    )
    app.logger.warning("auth.oidc.failure", extra={"reason": reason})
    return (
        render_template(
            "login.html",
            error="Single sign-on could not be completed. Start the sign-in again.",
        ),
        status,
    )


@app.route("/auth/oidc/login")
@limiter.limit("10 per minute")
def oidc_login():
    """Start an OpenID Connect authorization-code flow with PKCE."""

    if not OIDC_ENABLED:
        abort(404)
    try:
        discovery = oidc_module.discover(OIDC_ISSUER)
    except oidc_module.OidcError as exc:
        app.logger.error("auth.oidc.discovery_failed", extra={"reason": str(exc)})
        return (
            render_template(
                "login.html",
                error="Single sign-on is temporarily unavailable. Contact an administrator.",
            ),
            503,
        )
    verifier, challenge = oidc_module.pkce_pair()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    session[OIDC_FLOW_SESSION_KEY] = {
        "state": state,
        "nonce": nonce,
        "code_verifier": verifier,
        "expires_at": int(time.time()) + OIDC_FLOW_TTL_SECONDS,
    }
    try:
        target = oidc_module.build_authorization_url(
            discovery,
            OIDC_CLIENT_ID,
            OIDC_REDIRECT_URI,
            OIDC_SCOPES,
            state,
            nonce,
            challenge,
        )
    except oidc_module.OidcError as exc:
        app.logger.error("auth.oidc.authorize_failed", extra={"reason": str(exc)})
        return _oidc_failure("authorization_url", 503)
    return redirect(target)


@app.route("/auth/oidc/callback")
@limiter.limit("30 per minute")
def oidc_callback():
    """Complete the OIDC flow and establish a local session."""

    if not OIDC_ENABLED:
        abort(404)
    flow = _current_oidc_flow()
    if flow is None:
        return _oidc_failure("expired_or_missing_flow", 400)

    if request.args.get("error"):
        return _oidc_failure(
            "provider_error",
            401,
            {"provider_error": str(request.args.get("error"))[:80]},
        )

    supplied_state = request.args.get("state", "")
    if not compare_digest(str(supplied_state), str(flow.get("state", ""))):
        return _oidc_failure("state_mismatch", 400)
    code = request.args.get("code", "")
    if not code:
        return _oidc_failure("missing_code", 400)

    try:
        discovery = oidc_module.discover(OIDC_ISSUER)
        tokens = oidc_module.exchange_code(
            discovery,
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET or None,
            code,
            OIDC_REDIRECT_URI,
            flow.get("code_verifier", ""),
            auth_method=OIDC_TOKEN_AUTH_METHOD,
        )
        claims = oidc_module.verify_id_token(
            tokens["id_token"],
            discovery,
            OIDC_CLIENT_ID,
            flow.get("nonce", ""),
        )
    except oidc_module.OidcError as exc:
        return _oidc_failure("token_validation", 401, {"detail": str(exc)[:160]})
    finally:
        session.pop(OIDC_FLOW_SESSION_KEY, None)

    email = str(claims.get(OIDC_EMAIL_CLAIM) or "").strip().lower()
    if not email or "@" not in email:
        return _oidc_failure("missing_email", 403)
    if OIDC_REQUIRE_VERIFIED_EMAIL and claims.get("email_verified") is not True:
        return _oidc_failure("email_not_verified", 403)

    user = User.query.filter_by(email=email).first()
    if user is not None and not user.is_active:
        return _oidc_failure("inactive_account", 403, {"email": email})
    if user is not None and (user.auth_source or "local") != "oidc":
        if not OIDC_LINK_LOCAL_ACCOUNTS:
            return _oidc_failure(
                "account_method_mismatch", 403, {"auth_source": user.auth_source}
            )
    if user is None:
        if not OIDC_JIT_PROVISIONING:
            return _oidc_failure("account_not_provisioned", 403, {"email": email})
        tenant = Tenant.query.filter_by(
            slug=OIDC_DEFAULT_TENANT_SLUG, is_active=True
        ).first()
        if tenant is None:
            return _oidc_failure("default_tenant_missing", 503)
        user = User(
            tenant_id=tenant.id,
            email=email,
            display_name=str(claims.get(OIDC_NAME_CLAIM) or email)[:120],
            role=OIDC_DEFAULT_ROLE,
            auth_source="oidc",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()
        record_audit(
            "auth.oidc.provision",
            "user",
            user.id,
            detail={"email": email, "role": user.role},
            tenant_id=user.tenant_id,
            actor="oidc-provider",
            actor_role="system",
            commit=True,
        )

    _establish_session(user, "oidc")
    record_audit(
        "auth.login",
        "user",
        user.id,
        detail={"method": "oidc", "issuer": OIDC_ISSUER},
        tenant_id=user.tenant_id,
        actor=user.email,
        actor_role=user.role,
        commit=True,
    )
    return redirect(url_for("index"))


@socketio.on("connect")
def authorize_socket_connection(auth=None):
    if AUTH_REQUIRED and current_identity() is None:
        return False
    return True


# ---------------------------------------------------------------------
# Database model
# ---------------------------------------------------------------------
# ---------------------------------------------------------------------
# Tenancy, identity, and audit models
# ---------------------------------------------------------------------
class Tenant(db.Model):
    """A tenant boundary. Every stored flow, review, and audit row belongs to one."""

    __tablename__ = "tenants"
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    retention_days = db.Column(db.Integer, nullable=False, default=30)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    deleted_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id,
            "slug": self.slug,
            "name": self.name,
            "is_active": self.is_active,
            "retention_days": self.retention_days,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
        }


class User(db.Model):
    """A local or trusted-proxy identity. Platform admins may have no tenant."""

    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(120), nullable=False, default="")
    password_hash = db.Column(db.String(255))
    role = db.Column(db.String(32), nullable=False, default="viewer", index=True)
    auth_source = db.Column(db.String(24), nullable=False, default="local")
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)
    # TOTP MFA. The secret is Fernet-encrypted with a key derived from
    # SECRET_KEY; recovery codes are stored only as password hashes.
    totp_secret = db.Column(db.Text)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    totp_confirmed_at = db.Column(db.DateTime)
    totp_last_step = db.Column(db.Integer)
    mfa_recovery_hashes = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "email": self.email,
            "display_name": self.display_name,
            "role": self.role,
            "auth_source": self.auth_source,
            "is_active": self.is_active,
            "mfa_enabled": bool(self.totp_enabled),
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() + "Z" if self.last_login_at else None,
        }


class AuditEvent(db.Model):
    """Append-only security and data-access audit event.

    There is deliberately no update or delete route. Retention and tenant
    deletion are the only operations that remove audit rows, and both are
    themselves audited.
    """

    __tablename__ = "audit_events"
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True)
    actor = db.Column(db.String(254), nullable=False)
    actor_role = db.Column(db.String(32), nullable=False)
    action = db.Column(db.String(80), nullable=False, index=True)
    resource_type = db.Column(db.String(64))
    resource_id = db.Column(db.String(80))
    outcome = db.Column(db.String(24), nullable=False, default="success")
    detail = db.Column(db.Text, nullable=False, default="")
    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    def to_dict(self):
        detail = {}
        if self.detail:
            try:
                detail = json.loads(self.detail)
            except (TypeError, ValueError):
                detail = {"raw": self.detail}
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "actor_role": self.actor_role,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "outcome": self.outcome,
            "detail": detail,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() + "Z" if self.created_at else None,
        }


class Flow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, nullable=True, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    src_ip = db.Column(db.String(64))
    dst_ip = db.Column(db.String(64))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(16))
    predicted_label = db.Column(db.String(64), index=True)
    is_attack = db.Column(db.Boolean, index=True)
    # P3 sensor identity: which collector/interface produced the record. These
    # are nullable because legacy rows and uploads have no sensor identity.
    sensor_id = db.Column(db.String(80), nullable=True, index=True)
    interface = db.Column(db.String(120), nullable=True, index=True)
    # S3 provenance: every stored prediction records which artifact produced it
    # and which decision rule was applied. These columns are nullable so an
    # older database can be migrated in place.
    model_version = db.Column(db.String(64))
    artifact_sha256 = db.Column(db.String(64))
    feature_schema_version = db.Column(db.String(64))
    threshold_policy = db.Column(db.String(64))
    calibration_version = db.Column(db.String(64))
    attack_score = db.Column(db.Float)
    model_argmax_label = db.Column(db.String(64))
    decision_basis = db.Column(db.String(32))
    threshold_value = db.Column(db.Float)
    review = db.relationship(
        "FlowReview", uselist=False, back_populates="flow", cascade="all, delete-orphan", lazy="joined"
    )

    def __init__(
        self,
        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        protocol=None,
        predicted_label=None,
        is_attack=False,
        timestamp=None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.predicted_label = predicted_label
        self.is_attack = is_attack
        if timestamp is not None:
            self.timestamp = timestamp

    def to_dict(self):
        review = self.review
        if review is not None and review.tenant_id not in (None, self.tenant_id):
            review = None
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "predicted_label": self.predicted_label,
            "is_attack": self.is_attack,
            "sensor_id": self.sensor_id,
            "interface": self.interface,
            "provenance": {
                "model_version": self.model_version,
                "artifact_sha256": self.artifact_sha256,
                "feature_schema_version": self.feature_schema_version,
                "threshold_policy": self.threshold_policy,
                "threshold_value": self.threshold_value,
                "calibration_version": self.calibration_version,
                "decision_basis": self.decision_basis,
                "attack_score": self.attack_score,
                "model_argmax_label": self.model_argmax_label,
            },
            "persisted": True,
            "review": {
                "status": review.status,
                "note": review.note,
                "updated_at": review.updated_at.isoformat() + "Z" if review.updated_at else None,
                "updated_by": review.updated_by,
            } if review else {
                "status": "Unreviewed",
                "note": "",
                "updated_at": None,
                "updated_by": None,
            },
        }


class FlowReview(db.Model):
    __tablename__ = "flow_reviews"
    flow_id = db.Column(db.Integer, db.ForeignKey("flow.id", ondelete="CASCADE"), primary_key=True)
    tenant_id = db.Column(db.Integer, nullable=True, index=True)
    status = db.Column(db.String(24), nullable=False, default="Unreviewed")
    note = db.Column(db.String(2000), nullable=False, default="")
    updated_by = db.Column(db.String(80), nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    flow = db.relationship("Flow", back_populates="review")


class FlowReviewAudit(db.Model):
    __tablename__ = "flow_review_audit"
    id = db.Column(db.Integer, primary_key=True)
    flow_id = db.Column(db.Integer, db.ForeignKey("flow.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = db.Column(db.Integer, nullable=True, index=True)
    actor = db.Column(db.String(80), nullable=False)
    previous_status = db.Column(db.String(24), nullable=False)
    new_status = db.Column(db.String(24), nullable=False)
    note_changed = db.Column(db.Boolean, nullable=False, default=False)
    changed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    flow = db.relationship("Flow")


# ---------------------------------------------------------------------
# Schema bootstrap and default tenant
# ---------------------------------------------------------------------
def _ensure_tenant_columns():
    """Add tenant_id to pre-existing SQLite/Postgres tables.

    ``db.create_all()`` creates the column on a fresh database but does not
    alter an existing table. This is intentionally a small, idempotent
    migration rather than a full migration framework; a production deployment
    should replace it with Alembic.
    """

    inspector = inspect(db.engine)
    existing_tables = set(inspector.get_table_names())
    for table in ("flow", "flow_reviews", "flow_review_audit"):
        if table not in existing_tables:
            continue
        columns = {column["name"] for column in inspector.get_columns(table)}
        if "tenant_id" not in columns:
            db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN tenant_id INTEGER"))
            db.session.commit()
        try:
            db.session.execute(
                text(f"CREATE INDEX IF NOT EXISTS ix_{table}_tenant_id ON {table} (tenant_id)")
            )
            db.session.commit()
        except Exception:  # noqa: BLE001 - index creation is best effort
            db.session.rollback()


def _ensure_flow_provenance_columns():
    """Add S3 provenance columns to a pre-existing ``flow`` table.

    ``db.create_all()`` only creates columns on a fresh database. This is the
    same idempotent, best-effort migration style as ``_ensure_tenant_columns``;
    a production deployment should use Alembic.
    """
    inspector = inspect(db.engine)
    if "flow" not in set(inspector.get_table_names()):
        return
    existing = {column["name"] for column in inspector.get_columns("flow")}
    additions = {
        "model_version": "VARCHAR(64)",
        "artifact_sha256": "VARCHAR(64)",
        "feature_schema_version": "VARCHAR(64)",
        "threshold_policy": "VARCHAR(64)",
        "calibration_version": "VARCHAR(64)",
        "attack_score": "FLOAT",
        "model_argmax_label": "VARCHAR(64)",
        "decision_basis": "VARCHAR(32)",
        "threshold_value": "FLOAT",
        # P3 sensor identity. Existing rows stay NULL and are reported as
        # unattributed rather than being assigned a fabricated sensor.
        "sensor_id": "VARCHAR(80)",
        "interface": "VARCHAR(120)",
    }
    for name, column_type in additions.items():
        if name in existing:
            continue
        # ``name`` and ``column_type`` come only from the hardcoded ``additions``
        # mapping above, never from request data, so this DDL is not injectable.
        db.session.execute(
            text(f"ALTER TABLE flow ADD COLUMN {name} {column_type}")  # nosec B608
        )
        db.session.commit()
    for index_name, column in (
        ("ix_flow_sensor_id", "sensor_id"),
        ("ix_flow_interface", "interface"),
    ):
        try:
            db.session.execute(
                text(f"CREATE INDEX IF NOT EXISTS {index_name} ON flow ({column})")  # nosec B608
            )
            db.session.commit()
        except Exception:  # noqa: BLE001 - index creation is best effort
            db.session.rollback()


def _ensure_user_mfa_columns():
    """Add MFA columns to a pre-existing ``users`` table.

    Same idempotent bootstrap style as the other helpers. A production
    deployment should apply these through the migration framework (see
    ``migrations/``) instead of relying on startup DDL.
    """

    inspector = inspect(db.engine)
    if "users" not in set(inspector.get_table_names()):
        return
    existing = {column["name"] for column in inspector.get_columns("users")}
    additions = {
        "totp_secret": "TEXT",
        "totp_enabled": "BOOLEAN",
        "totp_confirmed_at": "DATETIME",
        "totp_last_step": "INTEGER",
        "mfa_recovery_hashes": "TEXT",
    }
    for name, column_type in additions.items():
        if name in existing:
            continue
        # ``name`` and ``column_type`` are hardcoded above, never request data.
        db.session.execute(
            text(f"ALTER TABLE users ADD COLUMN {name} {column_type}")  # nosec B608
        )
        db.session.commit()
    db.session.execute(text("UPDATE users SET totp_enabled = FALSE WHERE totp_enabled IS NULL"))
    db.session.commit()


def _bootstrap_tenant_and_admin():
    tenant = Tenant.query.filter_by(slug=DEFAULT_TENANT_SLUG).first()
    if tenant is None:
        tenant = Tenant(slug=DEFAULT_TENANT_SLUG, name=DEFAULT_TENANT_NAME, retention_days=30)
        db.session.add(tenant)
        db.session.commit()

    # Backfill every pre-tenancy row to the default tenant. Existing rows are
    # never silently discarded; the backfill is idempotent.
    for table in ("flow", "flow_reviews", "flow_review_audit"):
        # The table names are hardcoded literals in this tuple, never user input.
        db.session.execute(
            text(f"UPDATE {table} SET tenant_id = :tenant_id WHERE tenant_id IS NULL"),  # nosec B608
            {"tenant_id": tenant.id},
        )
    db.session.commit()

    admin_hash = os.environ.get("NETSHIELD_ADMIN_PASSWORD_HASH")
    if admin_hash:
        admin = User.query.filter_by(email=ADMIN_EMAIL).first()
        if admin is None:
            admin = User(
                tenant_id=tenant.id,
                email=ADMIN_EMAIL,
                display_name="Tenant administrator",
                password_hash=admin_hash,
                role="admin",
                auth_source="local",
                is_active=True,
            )
            db.session.add(admin)
        else:
            # Keep the environment-provided bootstrap credential authoritative
            # for the legacy single-admin account.
            admin.tenant_id = admin.tenant_id or tenant.id
            admin.password_hash = admin_hash
            admin.role = "admin"
            admin.is_active = True
        db.session.commit()

    return tenant


def _configure_sqlite_pragmas():
    """Tune local SQLite for concurrent ingest without changing durability semantics.

    WAL lets the console read while ingest writes; ``synchronous=NORMAL`` avoids
    an fsync per commit in WAL mode and is the standard local-research setting.
    Production is Postgres and never takes this path.
    """
    if not db.engine.url.drivername.startswith("sqlite"):
        return
    for statement in (
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA busy_timeout=5000",
        "PRAGMA temp_store=MEMORY",
    ):
        try:
            db.session.execute(text(statement))
        except Exception:  # noqa: BLE001 - tuning must not block startup
            db.session.rollback()
    db.session.commit()


def _bootstrap_development_schema():
    """Create and upgrade the schema for local research and tests.

    Staging and production use the Alembic migration chain instead; running
    ``db.create_all()`` there would make the schema depend on import order and
    would not produce a reviewable migration record.
    """
    _configure_sqlite_pragmas()
    db.create_all()
    _ensure_tenant_columns()
    _ensure_flow_provenance_columns()
    _ensure_user_mfa_columns()
    return _bootstrap_tenant_and_admin()


SKIP_BOOTSTRAP = (
    os.environ.get("NETSHIELD_SKIP_BOOTSTRAP", "false").strip().lower() == "true"
)
DEFAULT_TENANT = None
DEFAULT_TENANT_ID = None
if not SKIP_BOOTSTRAP:
    with app.app_context():
        if MIGRATIONS_REQUIRED:
            _configure_sqlite_pragmas()
            from migrations_runtime import assert_database_current

            assert_database_current(db.engine)
            DEFAULT_TENANT = _bootstrap_tenant_and_admin()
        else:
            DEFAULT_TENANT = _bootstrap_development_schema()
        DEFAULT_TENANT_ID = DEFAULT_TENANT.id
        try:
            FLOW_STORE_ROWS.set(db.session.query(Flow).count())
        except Exception:  # noqa: BLE001 - metrics must not block startup
            app.logger.exception("Could not initialize flow-store gauge")


# ---------------------------------------------------------------------
# Identity, roles, tenant scoping, and audit helpers
# ---------------------------------------------------------------------
ROLE_PERMISSIONS = {
    "viewer": {"flows:read", "stats:read", "console:read", "me:read"},
    "analyst": {
        "flows:read",
        "stats:read",
        "console:read",
        "flows:review",
        "flows:export",
        "audit:read",
        "me:read",
    },
    "admin": {
        "flows:read",
        "stats:read",
        "console:read",
        "flows:review",
        "flows:export",
        "audit:read",
        "me:read",
        "tenant:admin",
        "users:manage",
        "retention:manage",
    },
    "platform_admin": {
        "flows:read",
        "stats:read",
        "console:read",
        "flows:review",
        "flows:export",
        "audit:read",
        "me:read",
        "tenant:admin",
        "users:manage",
        "retention:manage",
        "tenants:manage",
        "platform:admin",
    },
}


def _identity_payload(user, auth_source):
    if user is None or not user.is_active:
        return None
    if user.role not in ROLE_PERMISSIONS:
        return None
    tenant = db.session.get(Tenant, user.tenant_id) if user.tenant_id else None
    if user.role != "platform_admin" and (tenant is None or not tenant.is_active):
        return None
    return {
        "user_id": user.id,
        "tenant_id": tenant.id if tenant else None,
        "tenant_slug": tenant.slug if tenant else None,
        "tenant_name": tenant.name if tenant else None,
        "actor": user.email,
        "display_name": user.display_name or user.email,
        "role": user.role,
        "auth_source": auth_source or user.auth_source,
        "permissions": sorted(ROLE_PERMISSIONS.get(user.role, set())),
    }


def current_identity():
    """Resolve the request identity from session, trusted proxy SSO, or dev mode."""
    if hasattr(g, "_netshield_identity"):
        return g._netshield_identity

    identity = None
    user_id = session.get("user_id")
    if user_id:
        user = db.session.get(User, user_id)
        identity = _identity_payload(user, session.get("auth_source", "local"))

    if identity is None and TRUSTED_PROXY_SSO and PROXY_SHARED_SECRET:
        supplied_secret = request.headers.get("X-NetShield-Proxy-Secret", "")
        principal = (request.headers.get("X-NetShield-User") or "").strip().lower()
        if supplied_secret and compare_digest(supplied_secret, PROXY_SHARED_SECRET) and principal:
            user = User.query.filter_by(email=principal, is_active=True).first()
            identity = _identity_payload(user, "trusted-proxy-sso")
            if identity is not None:
                session.permanent = True
                session["authenticated"] = True
                session["user_id"] = user.id
                session["username"] = user.email
                session["tenant_id"] = user.tenant_id
                session["role"] = user.role
                session["auth_source"] = "trusted-proxy-sso"

    if identity is None and not AUTH_REQUIRED:
        # Local development remains usable without a login, but it is explicitly
        # an administrative development identity, not a production user.
        tenant = db.session.get(Tenant, DEFAULT_TENANT_ID)
        identity = {
            "user_id": None,
            "tenant_id": tenant.id,
            "tenant_slug": tenant.slug,
            "tenant_name": tenant.name,
            "actor": "local-user",
            "display_name": "Local development user",
            "role": "admin",
            "auth_source": "development",
            "permissions": sorted(ROLE_PERMISSIONS["admin"]),
        }

    g._netshield_identity = identity
    return identity


def current_tenant_id():
    identity = current_identity()
    if identity and identity.get("tenant_id"):
        return identity["tenant_id"]
    return DEFAULT_TENANT_ID if DEFAULT_TENANT_ID is not None else None


def requested_tenant_id():
    """Resolve a platform-admin tenant override, otherwise the caller's tenant."""
    identity = current_identity()
    tenant_id = current_tenant_id()
    if identity and identity.get("role") == "platform_admin":
        raw = request.args.get("tenant_id")
        if raw is None and request.is_json:
            body = request.get_json(silent=True)
            if isinstance(body, dict):
                raw = body.get("tenant_id")
        if raw is not None:
            try:
                candidate = int(raw)
            except (TypeError, ValueError):
                return None
            tenant = db.session.get(Tenant, candidate)
            if tenant and tenant.is_active:
                return candidate
            return None
    return tenant_id


def tenant_scoped(model):
    """Return a query for ``model`` constrained to the request tenant."""
    tenant_id = requested_tenant_id()
    if tenant_id is None:
        # An invalid platform-admin override must return no rows, never all rows.
        return model.query.filter(model.tenant_id == -1)
    return model.query.filter(model.tenant_id == tenant_id)


def require_permission(permission):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            identity = current_identity()
            if identity is None:
                return jsonify({"error": "Authentication required"}), 401
            if permission not in identity.get("permissions", set()):
                return jsonify({"error": "Forbidden"}), 403
            return view_func(*args, **kwargs)

        return wrapped

    return decorator


def record_audit(action, resource_type=None, resource_id=None, outcome="success", detail=None,
                 tenant_id=None, actor=None, actor_role=None, commit=False):
    """Append one audit event. Callers normally commit with their own transaction."""
    identity = current_identity()
    event = AuditEvent(
        tenant_id=tenant_id if tenant_id is not None else (identity["tenant_id"] if identity else None),
        actor=actor or (identity["actor"] if identity else "anonymous"),
        actor_role=actor_role or (identity["role"] if identity else "anonymous"),
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        outcome=outcome,
        detail=json.dumps(detail, sort_keys=True, default=str)[:4000] if detail else "",
        ip_address=(request.remote_addr or "")[:64],
        user_agent=(request.user_agent.string or "")[:255],
    )
    db.session.add(event)
    if commit:
        db.session.commit()
    return event


def _delete_flows(flow_ids):
    """Delete flows and their derived review rows in the current transaction."""
    if not flow_ids:
        return
    FlowReview.query.filter(FlowReview.flow_id.in_(flow_ids)).delete(synchronize_session=False)
    FlowReviewAudit.query.filter(FlowReviewAudit.flow_id.in_(flow_ids)).delete(synchronize_session=False)
    Flow.query.filter(Flow.id.in_(flow_ids)).delete(synchronize_session=False)


def _establish_session(user, auth_source):
    session.clear()
    session.permanent = True
    session["authenticated"] = True
    session["user_id"] = user.id
    session["username"] = user.email
    session["tenant_id"] = user.tenant_id
    session["role"] = user.role
    session["auth_source"] = auth_source
    csrf_token()


# ---------------------------------------------------------------------
# Load and verify trusted model artifacts
# ---------------------------------------------------------------------
_configured_model_path = os.environ.get("MODEL_ARTIFACT_PATH", "").strip()
model_bundle_path = _configured_model_path or "models/model_bundle_rf_day_based_seed42.pkl"
model_artifact_source = "environment" if _configured_model_path else "default"
# The registry is the source of truth for what is approved to serve. When no
# explicit MODEL_ARTIFACT_PATH is supplied, load the active registry artifact
# instead of a convenience copy. This keeps serving, evaluation, and gating on
# the same bytes and prevents a stale convenience artifact from drifting.
if not _configured_model_path:
    model_bundle_path = resolve_serving_path(MODEL_REGISTRY_PATH)
    if os.path.isfile(MODEL_REGISTRY_PATH):
        model_artifact_source = "registry_active_entry"
model_bundle = None
expected_model_sha256 = os.environ.get("MODEL_SHA256", "").strip().lower()
if AUTH_REQUIRED and not os.path.isfile(model_bundle_path):
    raise RuntimeError("Production requires a versioned model bundle at MODEL_ARTIFACT_PATH")
if os.path.isfile(model_bundle_path):
    if expected_model_sha256:
        digest = hashlib.sha256()
        with open(model_bundle_path, "rb") as artifact_file:
            for chunk in iter(lambda: artifact_file.read(1024 * 1024), b""):
                digest.update(chunk)
        if not compare_digest(digest.hexdigest(), expected_model_sha256):
            raise RuntimeError("Model artifact SHA-256 does not match MODEL_SHA256")
    elif AUTH_REQUIRED:
        raise RuntimeError("Production model bundle integrity verification is required")
    model_bundle = joblib.load(model_bundle_path)
    if not isinstance(model_bundle, dict) or not {"pipeline", "label_encoder", "feature_names"}.issubset(model_bundle):
        raise RuntimeError("Model artifact bundle has an invalid schema")
    inference_pipeline = model_bundle["pipeline"]
    label_encoder = model_bundle["label_encoder"]
    feature_names = model_bundle["feature_names"]
    model = None
    scaler = None
else:
    # Development compatibility for older local artifacts. Production never
    # permits this split-artifact loading path.
    model_pipeline_path = os.environ.get("MODEL_PIPELINE_PATH", "models/pipeline.pkl")
    inference_pipeline = joblib.load(model_pipeline_path) if os.path.isfile(model_pipeline_path) else None
    model = None if inference_pipeline is not None else joblib.load("models/random_forest.pkl")
    scaler = None if inference_pipeline is not None else joblib.load("models/scaler.pkl")
    label_encoder = joblib.load("models/label_encoder.pkl")
    feature_names = joblib.load("models/feature_names.pkl")
if inference_pipeline is not None:
    pipeline_features = getattr(inference_pipeline.named_steps.get("sanitizer"), "expected_features", None)
    if pipeline_features:
        feature_names = list(pipeline_features)

_serving_artifact = {
    "file": None,
    "hash": None,
    "algorithm": None,
    "task": None,
    "classes": [],
    "threshold": None,
    "threshold_applied": False,
    "model_version": "unregistered",
    "feature_schema_version": None,
    "feature_schema_sha256": None,
    "threshold_policy": None,
    "calibration_version": "uncalibrated",
    "calibration_method": "none",
    "registry_verified": False,
    "registry_status": "not_checked",
    "approved_artifact_sha256": None,
    "artifact_source": model_artifact_source,
}
try:
    _serving_path = model_bundle_path if model_bundle is not None else os.environ.get(
        "MODEL_PIPELINE_PATH", "models/pipeline.pkl"
    )
    if os.path.isfile(_serving_path):
        _serving_artifact["file"] = os.path.basename(_serving_path)
        _serving_artifact["hash"] = hashlib.sha256(open(_serving_path, "rb").read()).hexdigest()
    if isinstance(model_bundle, dict):
        _serving_artifact["task"] = model_bundle.get("task")
        _serving_artifact["threshold"] = model_bundle.get("attack_threshold")
    if inference_pipeline is not None:
        _classifier = inference_pipeline.named_steps.get("classifier")
        _serving_artifact["algorithm"] = type(_classifier).__name__ if _classifier is not None else None
    if label_encoder is not None:
        _serving_artifact["classes"] = [str(value) for value in label_encoder.classes_]
    if feature_names:
        _serving_artifact["feature_schema_version"] = feature_schema_version(feature_names)
        _serving_artifact["feature_schema_sha256"] = feature_schema_sha256(feature_names)
except Exception:  # noqa: BLE001 - provenance display must never break the page
    app.logger.exception("Could not describe the serving artifact")


# Resolve the approved registry entry before accepting traffic. In production
# this is a hard gate: a missing registry, an unapproved active version, or a
# serving artifact whose hash differs from the approved artifact aborts start.
_serving_policy = None
_serving_threshold = None
try:
    if os.path.isfile(MODEL_REGISTRY_PATH):
        _registry_entry = active_entry(MODEL_REGISTRY_PATH)
        if _registry_entry is not None:
            _registry_report = deployment_check(
                MODEL_REGISTRY_PATH,
                model_bundle_path,
                signing_key=MODEL_SIGNING_KEY,
                expected_sha256=expected_model_sha256 or None,
                require_approved=REQUIRE_APPROVED_MODEL,
            )
            _serving_artifact.update({
                "model_version": _registry_entry["version"],
                "feature_schema_version": _registry_entry["feature_schema_version"],
                "feature_schema_sha256": _registry_entry["feature_schema_sha256"],
                "threshold_policy": _registry_entry["threshold_policy"],
                "calibration_version": _registry_entry["calibration_version"],
                "calibration_method": _registry_entry["calibration_method"],
                "registry_verified": True,
                "registry_status": "active_artifact_matches_registry",
                "approved_artifact_sha256": _registry_entry["artifact_sha256"],
            })
            _serving_policy = _registry_entry["threshold_policy"]
        elif REQUIRE_APPROVED_MODEL:
            raise RuntimeError("Model registry has no active model version")
        else:
            _serving_artifact["registry_status"] = "no_active_version"
    elif REQUIRE_APPROVED_MODEL:
        raise RuntimeError("REQUIRE_APPROVED_MODEL is set but the registry does not exist")
    else:
        _serving_artifact["registry_status"] = "registry_not_found"
except Exception as exc:  # noqa: BLE001
    if REQUIRE_APPROVED_MODEL:
        raise
    _serving_artifact["registry_status"] = f"not_verified: {exc}"
    app.logger.warning("Model registry verification failed: %s", exc)

if _serving_policy is None:
    _serving_threshold = (
        model_bundle.get("attack_threshold") if isinstance(model_bundle, dict) else None
    )
    _serving_policy = {
        "name": "bundle_attack_threshold" if _serving_threshold is not None else "argmax",
        "threshold": _serving_threshold,
        "max_fpr": (
            model_bundle.get("threshold_selection_max_fpr")
            if isinstance(model_bundle, dict) else None
        ),
        "selected_on": "recorded in artifact",
        "score": "1 - P(BENIGN)",
        "decision": (
            "attack_score >= threshold" if _serving_threshold is not None
            else "argmax predicted class != BENIGN"
        ),
    }
else:
    _serving_threshold = _serving_policy.get("threshold")
_serving_artifact["threshold"] = _serving_threshold
_serving_artifact["threshold_applied"] = _serving_threshold is not None
_serving_artifact["threshold_policy"] = _serving_policy


# ---------------------------------------------------------------------
# Multi-signal evidence accumulation (Slips-style host/window incidents)
# ---------------------------------------------------------------------
# This layer is deliberately additive. It does not change the per-flow
# prediction, the serving threshold, or the stored Flow row. It groups scored
# flows by (tenant, source IP, time window) so three independent signals can
# corroborate before an operator sees an incident.
def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


MULTI_SIGNAL_ENABLED = (
    os.environ.get("ENABLE_MULTI_SIGNAL_EVIDENCE", "true").lower() == "true"
)
THREAT_INTEL_ON_INGEST = (
    os.environ.get("NETSHIELD_THREAT_INTEL_ON_INGEST", "false").lower() == "true"
)
_EVIDENCE_ACCUMULATOR = EvidenceAccumulator(
    window_seconds=_env_int("NETSHIELD_EVIDENCE_WINDOW_SECONDS", 300),
    incident_threshold=_env_float("NETSHIELD_INCIDENT_RISK_THRESHOLD", 70.0),
)
_CALIBRATOR = None
_CALIBRATION_METADATA = {}
_CALIBRATION_STATUS = "uncalibrated"
_CALIBRATION_PATH = os.environ.get(
    "NETSHIELD_CALIBRATION_PATH", "models/calibration_rf_day_based_seed42.json"
)
_calibration_artifact_hash = None
try:
    if os.path.isfile(_CALIBRATION_PATH):
        _calibrator_candidate, _calibration_metadata = load_calibrator(_CALIBRATION_PATH)
        _calibration_artifact_hash = _calibration_metadata.get("artifact_sha256")
        if (
            _calibration_artifact_hash
            and _serving_artifact.get("hash")
            and _calibration_artifact_hash == _serving_artifact.get("hash")
        ):
            _CALIBRATOR = _calibrator_candidate
            _CALIBRATION_METADATA = _calibration_metadata
            _CALIBRATION_STATUS = _calibration_metadata.get(
                "calibration_version", "calibrated"
            )
        else:
            _CALIBRATION_STATUS = "calibration_hash_mismatch"
    else:
        _CALIBRATION_STATUS = "calibration_artifact_missing"
except Exception as exc:  # noqa: BLE001 - calibration must never break serving
    _CALIBRATION_STATUS = f"calibration_load_failed: {exc}"
    app.logger.warning("Could not load calibration artifact: %s", exc)

_ISOLATION_BUNDLE = None
_ISOLATION_LOAD_ATTEMPTED = False


def _load_isolation_bundle():
    """Load the seeded Isolation Forest bundle once, if it is present."""
    global _ISOLATION_BUNDLE, _ISOLATION_LOAD_ATTEMPTED
    if _ISOLATION_LOAD_ATTEMPTED:
        return _ISOLATION_BUNDLE
    _ISOLATION_LOAD_ATTEMPTED = True
    path = os.environ.get(
        "NETSHIELD_ISOLATION_BUNDLE",
        "models/model_bundle_if_day_based_seed42.pkl",
    )
    try:
        if os.path.isfile(path):
            bundle = joblib.load(path)
            if isinstance(bundle, dict) and "pipeline" in bundle:
                _ISOLATION_BUNDLE = bundle
    except Exception as exc:  # noqa: BLE001 - optional signal
        app.logger.warning("Could not load isolation-forest bundle: %s", exc)
    return _ISOLATION_BUNDLE


def _calibrated_probability(raw_score):
    """Calibrate the RF attack score only when the artifact hash matches."""
    if raw_score is None:
        return None
    if _CALIBRATOR is None:
        return float(raw_score)
    try:
        return float(_CALIBRATOR(float(raw_score)))
    except Exception:  # noqa: BLE001
        return float(raw_score)



def _classifier_probabilities(estimator, row):
    """Return (attack_score, argmax_label) from a fitted estimator."""
    classifier = getattr(estimator, "named_steps", {}).get("classifier", estimator)
    if hasattr(estimator, "predict_proba"):
        probabilities = estimator.predict_proba(row)[0]
        encoded_classes = list(classifier.classes_)
        benign_encoded = label_encoder.transform(["BENIGN"])[0]
        benign_index = encoded_classes.index(benign_encoded)
        attack_score = float(1.0 - probabilities[benign_index])
        argmax_encoded = encoded_classes[int(np.argmax(probabilities))]
        argmax_label = str(label_encoder.inverse_transform([argmax_encoded])[0])
        return attack_score, argmax_label
    prediction = estimator.predict(row)
    return None, str(label_encoder.inverse_transform(prediction)[0])


def _classifier_probabilities_batch(estimator, rows):
    """Return per-row (attack_score, argmax_label) with one estimator call."""
    classifier = getattr(estimator, "named_steps", {}).get("classifier", estimator)
    if hasattr(estimator, "predict_proba"):
        probabilities = estimator.predict_proba(rows)
        encoded_classes = list(classifier.classes_)
        benign_encoded = label_encoder.transform(["BENIGN"])[0]
        benign_index = encoded_classes.index(benign_encoded)
        attack_scores = 1.0 - probabilities[:, benign_index]
        argmax_encoded = probabilities.argmax(axis=1)
        argmax_labels = label_encoder.inverse_transform(argmax_encoded)
        return (
            [float(value) for value in attack_scores],
            [str(value) for value in argmax_labels],
        )
    predictions = estimator.predict(rows)
    labels = label_encoder.inverse_transform(predictions)
    return [None] * len(labels), [str(value) for value in labels]


def _isolation_confidences(flow_dicts: list[dict]) -> list[float | None]:
    """Score a batch with the optional Isolation Forest and normalise it.

    The raw ``-decision_function`` value is unbounded. ``isolation_confidence``
    maps the validation threshold to 0.5 and keeps ordering, so the accumulator
    consumes a bounded corroborating signal rather than a second hard label.
    """
    bundle = _load_isolation_bundle()
    if not bundle or not MULTI_SIGNAL_ENABLED:
        return [None] * len(flow_dicts)
    if_names = list(bundle.get("feature_names") or [])
    threshold = bundle.get("threshold")
    if not if_names or threshold is None:
        return [None] * len(flow_dicts)
    try:
        rows = [normalize_flow_features(flow, if_names) for flow in flow_dicts]
        frame = pd.DataFrame(rows).apply(pd.to_numeric, errors="coerce")
        frame = frame.reindex(columns=if_names, fill_value=np.nan)
        raw_scores = -np.asarray(bundle["pipeline"].decision_function(frame), dtype=float)
        return [
            isolation_confidence(float(value), float(threshold))
            for value in raw_scores
        ]
    except Exception:  # noqa: BLE001 - the optional signal must not break scoring
        app.logger.exception("Isolation-forest scoring failed")
        return [None] * len(flow_dicts)



def classify_flows_with_evidence(flow_dicts: list[dict]) -> list[dict]:
    """Classify a batch of raw flows with a single model call.

    Batch inference matters for ingest latency: per-row DataFrame construction
    and one ``predict_proba`` call per flow dominated the 20 flows/s SLO path.
    The threshold, argmax, and provenance semantics are identical to the
    single-flow path.
    """
    if not flow_dicts:
        return []
    started = time.perf_counter()
    normalized_rows = [normalize_flow_features(flow, feature_names) for flow in flow_dicts]
    frame = pd.DataFrame(normalized_rows)
    frame = frame.apply(pd.to_numeric, errors="coerce")

    try:
        if inference_pipeline is not None:
            # Keep absent features as NaN so the fitted SimpleImputer applies the
            # training-partition median. Reindexing with 0 would make every missing
            # feature look like a real measurement and bypass imputation entirely.
            # FlowSanitizer also converts +/-inf to NaN before the imputer runs.
            frame = frame.reindex(columns=feature_names, fill_value=np.nan)
            attack_scores, argmax_labels = _classifier_probabilities_batch(
                inference_pipeline, frame
            )
        else:
            # The legacy scaler/model pair cannot accept NaN, so retain the
            # historical zero-fill behaviour for that fallback path only.
            frame = frame.reindex(columns=feature_names, fill_value=0)
            frame = frame.fillna(0)
            frame.replace([np.inf], 999999, inplace=True)
            frame.replace([-np.inf], -999999, inplace=True)
            X_scaled = scaler.transform(frame)
            attack_scores, argmax_labels = _classifier_probabilities_batch(model, X_scaled)
    except Exception:
        PREDICTION_ERRORS.labels("live").inc()
        raise
    finally:
        PREDICTION_LATENCY.labels("live").observe(time.perf_counter() - started)

    evidence_rows = []
    isolation_confidences = _isolation_confidences(flow_dicts)
    for attack_score, argmax_label, isolation_conf in zip(
        attack_scores, argmax_labels, isolation_confidences
    ):
        if argmax_label is None:
            raise RuntimeError("Model produced no label")
        calibrated_score = _calibrated_probability(attack_score)
        if _serving_threshold is not None and attack_score is not None:
            is_attack = bool(attack_score >= float(_serving_threshold))
            decision_basis = "attack_probability_threshold"
        else:
            is_attack = argmax_label != "BENIGN"
            decision_basis = "argmax"
        predicted_label = (
            argmax_label if argmax_label != "BENIGN" else "ATTACK"
        ) if is_attack else "BENIGN"
        PREDICTION_LABELS.labels("live", str(predicted_label)).inc()
        evidence_rows.append(
            {
                "predicted_label": predicted_label,
                "argmax_label": argmax_label,
                "attack_score": attack_score,
                "calibrated_attack_probability": calibrated_score,
                "calibration_status": _CALIBRATION_STATUS,
                "isolation_confidence": isolation_conf,
                "is_attack": is_attack,
                "decision_basis": decision_basis,
                "threshold": _serving_threshold,
                "threshold_policy": _serving_policy.get("name") if _serving_policy else None,
                "model_version": _serving_artifact.get("model_version"),
                "artifact_sha256": _serving_artifact.get("hash"),
                "feature_schema_version": _serving_artifact.get("feature_schema_version"),
                "calibration_version": _serving_artifact.get("calibration_version"),
            }
        )
    return evidence_rows


def classify_flow_with_evidence(flow_dict: dict) -> dict:
    """Classify one raw flow and return the thresholded decision plus provenance.

    The documented threshold policy is applied to the attack score
    ``1 - P(BENIGN)``. When no threshold is available the decision falls back
    to argmax and says so. The raw argmax label is preserved separately so the
    threshold decision never hides what the multiclass model predicted.
    """
    return classify_flows_with_evidence([flow_dict])[0]


def classify_flow(flow_dict: dict) -> str:
    """Backward-compatible label-only wrapper around the evidence path."""
    return classify_flow_with_evidence(flow_dict)["predicted_label"]
def _extract_flow_field(flow_dict: dict, *keys, default=None):
    """Safely extract the first non-None matching key from flow_dict,
    preventing issues where 0 or false values are ignored by 'or' chaining."""
    for k in keys:
        if k in flow_dict and flow_dict[k] is not None:
            return flow_dict[k]
    return default


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _flow_event_time(flow_dict):
    """Return an epoch timestamp for evidence windows.

    Collectors may send epoch seconds, epoch milliseconds, or an ISO string.
    An unparseable or absent timestamp uses receipt time; the incident record
    remains useful even when the collector omits time.
    """
    raw = _extract_flow_field(
        flow_dict, "timestamp", "Timestamp", "event_time", "first_seen"
    )
    if raw is None:
        return time.time()
    try:
        value = float(raw)
        if value > 1e12:  # milliseconds
            value /= 1000.0
        if math.isfinite(value):
            return value
    except (TypeError, ValueError):
        pass
    try:
        text = str(raw).strip().replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return time.time()


def _accumulate_flow_evidence(tenant_id, flow_dict, evidence, src_ip, dst_ip, dst_port):
    """Feed one scored flow into the host/window accumulator.

    Returns the affected window summary or ``None`` when the flow has no usable
    source address. This function is best-effort: a failure is logged and never
    turns a successful ingest into a 500.
    """
    if not MULTI_SIGNAL_ENABLED:
        return None
    source = str(src_ip or "").strip()
    if not source or source in {"—", "Not present in upload"}:
        return None
    reputation_score = None
    if THREAT_INTEL_ON_INGEST and evidence.get("is_attack"):
        try:
            reputation_score = lookup_abuseipdb(source).get("abuse_score")
        except Exception:  # noqa: BLE001 - optional enrichment
            app.logger.warning("Threat-intel lookup failed for ingest enrichment")
    try:
        return _EVIDENCE_ACCUMULATOR.observe(
            Observation(
                source_ip=source,
                timestamp=_flow_event_time(flow_dict),
                supervised_probability=evidence.get("calibrated_attack_probability"),
                unsupervised_confidence=evidence.get("isolation_confidence"),
                reputation_score=reputation_score,
                supervised_calibration=evidence.get("calibration_status")
                or "uncalibrated",
                destination_ip=str(dst_ip or ""),
                destination_port=dst_port,
                tenant_id=tenant_id,
                flow_id=evidence.get("flow_id"),
            )
        )
    except Exception:  # noqa: BLE001 - evidence is additive
        app.logger.exception("Evidence accumulation failed for one flow")
        return None


def _clean_identity_value(value, max_length):
    """Normalize a collector-supplied sensor or interface label.

    Returns ``None`` for empty values and raises ``ValueError`` when the label
    exceeds the stored column width. Control characters are stripped so a
    label cannot forge terminal or UI output.
    """
    if value is None:
        return None
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", str(value)).strip()
    if not cleaned:
        return None
    if len(cleaned) > max_length:
        raise ValueError(f"identity label exceeds {max_length} characters")
    return cleaned


# ---------------------------------------------------------------------
# Research evidence context
# ---------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

_PARITY_AUDIT = {
    "required_features": 80,
    # The upload (PCAP) parser now emits all 80 training features: bulk
    # statistics, active/idle times, per-direction header bytes, initial TCP
    # windows, per-direction flag counts, data-packet counts, and both
    # packet-length-extreme names are measured per flow. The PyFlowMeter live
    # path maps all 80 names but drops ICMP and IPv6 flows, and the two
    # extractors still disagree on matched-flow numeric features. Neither path
    # has CICFlowMeter ground truth, so parity is still not demonstrated.
    "generated_features": 80,
    "direct_matches": 80,
    "match_rate": 100.0,
    "missing_features": 0,
    "dummy_features": 0,
    "live_schema_names": 80,
    "live_flows": 4,
    "reference_flows": 6,
    "matched_flows": 4,
    "reference_only_flows": 2,
    "reference_only_reason": "ICMP and IPv6 are dropped by the live ip and (tcp or udp) filter",
    "unmatched_live_flows": 0,
    "ambiguous_live_flows": 0,
    "missing_list": [],
    "dummy_list": [],
    "known_divergences": [
        "The live path's flag features are 0/1 indicators, not counts (pyflowmeter FlagCount.has_flag).",
        "The live path aliases CWE Flag Count to Fwd URG Flags (pyflowmeter bug).",
        "The live path overwrites Init_Win_bytes_backward on every reverse packet.",
        "Rate, inter-arrival, and packet-length statistics still differ between the two extractors.",
        "No CICFlowMeter ground truth exists for either path.",
    ],
}


def _load_json(relative_path, default):
    path = os.path.join(BASE_DIR, relative_path)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def _mean_std(values):
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return None, None
    mean = statistics.mean(clean)
    std = statistics.stdev(clean) if len(clean) > 1 else 0.0
    return mean, std


def _research_context():
    """Load only the frozen artifacts used by the workbench.

    The UI renders these values directly so that display claims can be traced
    to a JSON artifact in the repository rather than typed by hand.
    """
    summary = _load_json("docs/summary_metrics.json", {})
    rf_seed42 = _load_json("models/metrics_rf_day_based_seed42.json", {})
    manifest = _load_json("models/model_manifest_rf_day_based_seed42.json", {})
    feedback = _load_json("models/feedback_simulation_results.json", {})
    drift = _load_json("models/drift_monitoring_results.json", [])
    prevalence_source = _load_json("docs/PREVALENCE_EVAL.json", {})

    prevalence_rows = []
    for row in prevalence_source.get("prevalence", []):
        ppv_ci = row.get("ppv_ci95") or [None, None]
        alerts_ci = row.get("alerts_per_10k_ci95") or [None, None]
        prevalence_rows.append({
            "p": row.get("p"),
            "ppv": row.get("ppv"),
            "ppv_low": ppv_ci[0] if len(ppv_ci) > 0 else None,
            "ppv_high": ppv_ci[1] if len(ppv_ci) > 1 else None,
            "alerts": row.get("alerts_per_10k"),
            "alerts_low": alerts_ci[0] if len(alerts_ci) > 0 else None,
            "alerts_high": alerts_ci[1] if len(alerts_ci) > 1 else None,
            "break_even_fp": row.get("break_even_per_flow"),
            "break_even_alerts": row.get("break_even_all_alerts"),
        })
    prevalence_five = []
    for row in prevalence_source.get("five_seed", []):
        prevalence_five.append({
            "p": row.get("p"),
            "ppv_from_mean_rates": row.get("ppv_from_mean_rates"),
            "ppv_mean": row.get("ppv_mean"),
            "ppv_sd": row.get("ppv_sd"),
            "alerts_mean": row.get("alerts_per_10k_mean"),
            "alerts_sd": row.get("alerts_per_10k_sd"),
            "break_even_alerts": row.get("break_even_all_alerts_mean"),
        })

    baselines = []
    for key in ("rf", "lr", "if"):
        entry = summary.get(key, {})
        stats = entry.get("summary", {})
        def pick(metric):
            block = stats.get(metric, {})
            return block.get("mean"), block.get("std")
        pr_mean, pr_std = pick("pr_auc")
        roc_mean, roc_std = pick("roc_auc")
        rec_mean, rec_std = pick("recall_at_frozen_threshold")
        fpr_mean, fpr_std = pick("fpr_at_frozen_threshold")
        alert_mean, alert_std = pick("alert_rate")
        fit_mean, fit_std = pick("fit_seconds")
        baselines.append({
            "id": key,
            "name": entry.get("name", key.upper()),
            "pr_auc": [pr_mean, pr_std],
            "roc_auc": [roc_mean, roc_std],
            "recall": [rec_mean, rec_std],
            "fpr": [fpr_mean, fpr_std],
            "alert_rate": [alert_mean, alert_std],
            "fit_seconds": [fit_mean, fit_std],
        })

    families = []
    for name, row in (rf_seed42.get("attack_family_detection") or {}).items():
        families.append({
            "name": name,
            "support": row.get("support", 0),
            "detected": row.get("detected", 0),
            "recall": row.get("recall", 0.0),
            "seen_in_training": row.get("seen_in_training", False),
        })
    families.sort(key=lambda item: item["recall"])

    budgets = []
    none_runs = [
        run for run in feedback.get("individual_runs", [])
        if run.get("policy") == "none" and run.get("seed") == 42
    ]
    if none_runs:
        evaluation = none_runs[0].get("alert_budget_evaluation", {})
        for key, row in (evaluation.get("fixed_budgets") or {}).items():
            budgets.append({
                "id": key,
                "label": key.replace("top_", "Top-") + " alerts",
                "kind": "Fixed volume",
                "k": row.get("budget_k"),
                "threshold": row.get("effective_threshold"),
                "precision": row.get("precision"),
                "recall": row.get("recall"),
                "fp_per_10k": row.get("fp_per_10k_benign"),
                "families": row.get("per_family_recall", {}),
            })
        for key, row in (evaluation.get("budgets_per_10k") or {}).items():
            budgets.append({
                "id": key,
                "label": key.replace("_per_10k", " per 10,000 flows"),
                "kind": "Rate based",
                "k": row.get("budget_k"),
                "threshold": row.get("effective_threshold"),
                "precision": row.get("precision"),
                "recall": row.get("recall"),
                "fp_per_10k": row.get("fp_per_10k_benign"),
                "families": row.get("per_family_recall", {}),
            })
        budgets.sort(key=lambda item: item["k"] or 0)

    grouped = {}
    for run in feedback.get("individual_runs", []):
        grouped.setdefault((run.get("policy"), run.get("budget")), []).append(run)
    policy_labels = {
        "none": "No feedback",
        "random": "Random sampling",
        "top_alert": "Top-alert triage",
        "uncertainty": "Uncertainty sampling",
    }
    feedback_rows = []
    for (policy, budget), runs in sorted(grouped.items(), key=lambda item: (item[0][1], item[0][0])):
        pr_mean, pr_std = _mean_std([run.get("pr_auc") for run in runs])
        rec_mean, rec_std = _mean_std([run.get("binary_metrics", {}).get("recall") for run in runs])
        fpr_mean, fpr_std = _mean_std([run.get("binary_metrics", {}).get("fpr") for run in runs])
        prec_mean, prec_std = _mean_std([run.get("binary_metrics", {}).get("precision") for run in runs])
        bot_mean, bot_std = _mean_std([
            run.get("per_family_recall", {}).get("Bot", {}).get("recall") for run in runs
        ])
        feedback_rows.append({
            "policy": policy,
            "policy_label": policy_labels.get(policy, policy),
            "budget": budget,
            "pr_auc": [pr_mean, pr_std],
            "recall": [rec_mean, rec_std],
            "fpr": [fpr_mean, fpr_std],
            "precision": [prec_mean, prec_std],
            "bot_recall": [bot_mean, bot_std],
        })

    feedback_named = {
        f"{row['policy']}_{row['budget']}": row for row in feedback_rows
    }

    drift_rows = []
    for window in drift:
        metrics = window.get("unsupervised_metrics", {})
        truth = window.get("ground_truth_performance", {})
        drift_rows.append({
            "window": window.get("window"),
            "flows": window.get("flow_count"),
            "flagged": metrics.get("features_flagged"),
            "warning": metrics.get("drift_warning_triggered"),
            "degraded": truth.get("performance_degraded"),
            "recall": truth.get("test_recall"),
            "verdict": window.get("monitor_evaluation"),
        })

    operating = rf_seed42.get("operating_threshold", {})
    return {
        "dataset": {
            "name": "CIC-IDS-2017",
            "source": "Canadian Institute for Cybersecurity, University of New Brunswick",
            "license": "Academic, non-commercial research use",
            "total_flows": 2830540,
            "features": 80,
            "caveat": "Scripted attacks in a controlled laboratory VLAN, not production traffic.",
        },
        "splits": {
            "train": {"label": "Training", "days": "Monday to Tuesday", "flows": 975789,
                      "labels": "BENIGN, FTP-Patator, SSH-Patator"},
            "validation": {"label": "Validation", "days": "Wednesday", "flows": 692686,
                           "labels": "DoS families, Heartbleed"},
            "test": {"label": "Test", "days": "Thursday to Friday", "flows": 1162065,
                     "labels": "Web attacks, Infiltration, Botnet, PortScan, DDoS"},
            "review": {"label": "Feedback review", "days": "Thursday", "flows": 458825,
                       "labels": "Web attacks, Infiltration"},
            "evaluation": {"label": "Feedback evaluation", "days": "Friday", "flows": 703240,
                           "labels": "Botnet, PortScan, DDoS"},
            "friday_attacks": 288923,
            "friday_benign": 414317,
            "unseen_test_rows": 291139,
        },
        "model": {
            "name": "Random Forest",
            "seed": manifest.get("seed", 42),
            "hash": manifest.get("model_sha256"),
            "file": manifest.get("model_file"),
            "features": manifest.get("feature_count", 80),
            "trained_classes": manifest.get("trained_classes", []),
            "unseen_labels": manifest.get("unseen_test_labels", []),
            "python": manifest.get("python_version"),
            "sklearn": manifest.get("scikit_learn_version"),
            "task": manifest.get("task"),
            "split_mode": manifest.get("split_mode"),
            "dataset_hashes": manifest.get("dataset_sha256", {}),
            "threshold": operating.get("threshold"),
            "validation_fpr": operating.get("validation_fpr"),
            "validation_tpr": operating.get("validation_tpr"),
            "test": operating.get("test", {}),
            "binary_pr_auc": rf_seed42.get("binary_pr_auc"),
            "binary_roc_auc": rf_seed42.get("binary_roc_auc"),
            "macro_f1": rf_seed42.get("macro_f1"),
            "weighted_f1": rf_seed42.get("weighted_f1"),
            "calibration": rf_seed42.get("calibration", {}),
        },
        "serving": _serving_artifact,
        "baselines": baselines,
        "families": families,
        "budgets": budgets,
        "feedback": feedback_rows,
        "feedback_named": feedback_named,
        "drift": drift_rows,
        "prevalence": {
            "available": bool(prevalence_source),
            "method": prevalence_source.get("method"),
            "seed": prevalence_source.get("seed"),
            "benchmark": prevalence_source.get("benchmark_prevalence"),
            "rows": prevalence_rows,
            "five_seed": prevalence_five,
            "d9": prevalence_source.get("d9_break_even_1_21"),
            "notes": prevalence_source.get("notes", []),
        },
        "parity": _PARITY_AUDIT,
        "feedback_meta": {
            "seeds": feedback.get("seeds", []),
            "total_runs": feedback.get("total_runs", 0),
            "policies": feedback.get("policies", []),
        },
    }


# ---------------------------------------------------------------------
# Page Routes
# ---------------------------------------------------------------------
@app.route("/")
@app.route("/console")
def index():
    """Live capture console: the primary product surface."""
    return render_template("console.html")


@app.route("/research")
@app.route("/upload")
def research():
    """Research workbench: frozen evaluation evidence and provenance."""
    return render_template("index.html", research=_research_context())


@app.route("/account")
def account():
    """Account security surface for local password accounts and MFA."""
    identity = current_identity()
    user = (
        db.session.get(User, identity.get("user_id"))
        if identity and identity.get("user_id")
        else None
    )
    local_account = bool(user and (user.auth_source or "local") == "local")
    return render_template(
        "account.html",
        identity=identity,
        mfa_supported=local_account,
        mfa_enabled=bool(user and user.totp_enabled),
    )


@app.route("/dashboard")
def dashboard():
    """Legacy stored-flow dashboard, permanently superseded by the live console."""
    return redirect("/", code=301)


# ---------------------------------------------------------------------
# Batch Flow Analysis API
# ---------------------------------------------------------------------
@app.route("/predict", methods=["POST"])
@limiter.limit("10 per minute")
@require_permission("flows:read")
def predict_csv():
    """Accept CSV flow rows, PCAP/PCAPNG captures, or the built-in sample dataset."""
    try:
        df = None
        packet_count = None
        capture_type = "CSV flow export"
        capture_filename = None
        sample_meta = None
        if "file" in request.files and request.files["file"].filename != "":
            file = request.files["file"]
            filename = file.filename.lower()
            if filename.endswith((".pcap", ".pcapng")):
                try:
                    df, _, packet_count = _pcap_to_flows(file.stream)
                except ValueError as e:
                    return jsonify({"error": str(e)}), 400
                capture_type = "Scapy PCAP dissector"
                capture_filename = os.path.basename(file.filename)
            elif filename.endswith(".csv"):
                try:
                    df = pd.read_csv(file, nrows=250_001, low_memory=False)
                except Exception as e:  # noqa: BLE001
                    app.logger.info("UTF-8 CSV decode failed; trying Latin-1 fallback: %s", e)
                    file.seek(0)
                    file.seek(0)
                    df = pd.read_csv(file, encoding="cp1252", nrows=250_001, low_memory=False)
            else:
                return jsonify({"error": "Only .csv, .pcap, and .pcapng files are supported."}), 415
        elif request.args.get("sample") or ((request.get_json(silent=True) or {}).get("sample") is not None):
            sample_kind = str(
                request.args.get("sample")
                or (request.get_json(silent=True) or {}).get("sample")
            ).strip().lower()
            if sample_kind in ("diverse", "network", "mixed"):
                sample_filename = "network_test_dataset.csv"
                capture_type = "Diverse labeled sample (not held-out Friday only)"
            elif sample_kind in ("true", "1", "heldout", "test", "friday"):
                sample_filename = "test_dataset.csv"
                capture_type = "Held-out Friday sample"
            else:
                return jsonify({"error": "Unknown sample selection."}), 400

            candidate_paths = [
                os.path.join("data", "samples", sample_filename),
                sample_filename,
            ]
            sample_path = next((p for p in candidate_paths if os.path.exists(p)), None)
            if not sample_path:
                return jsonify({"error": "Sample dataset file not found on server."}), 404
            sample_frame = pd.read_csv(sample_path)
            sample_rows_available = len(sample_frame)
            df = sample_frame.head(1500)
            capture_filename = sample_filename
            sample_meta = {
                "kind": sample_kind,
                "file": sample_filename,
                "rows_available": sample_rows_available,
                "rows_evaluated": len(df),
                "note": (
                    "This sample contains labels, but the table shows model predictions. "
                    "Labels are not used for scoring in this view."
                ),
            }
        else:
            return jsonify({"error": "No file uploaded or sample requested."}), 400

        if df is None or df.empty:
            return jsonify({"error": "Uploaded CSV file is empty or unreadable."}), 400
        if len(df) > 250_000:
            return jsonify({"error": "CSV exceeds the 250,000-row analysis limit."}), 413
        if len(df.columns) > 256:
            return jsonify({"error": "CSV exceeds the 256-column analysis limit."}), 413

        # Clean whitespace from column names
        df.columns = df.columns.str.strip()

        # Build column mapping dictionary
        mapped_cols = {}
        expected_set = set(feature_names)
        for col in df.columns:
            if col == "Packet Dissector":
                continue
            if col in expected_set:
                mapped_cols[col] = col
            elif col in FEATURE_NAME_OVERRIDES:
                mapped_cols[col] = FEATURE_NAME_OVERRIDES[col]
            else:
                guess = _auto_normalize(col)
                if guess in expected_set:
                    mapped_cols[col] = guess
                else:
                    UNMAPPED_LOG.add(col)

        renamed_df = df.rename(columns=mapped_cols)
        mapped_feature_count = len(set(mapped_cols.values()) & expected_set)
        feature_coverage = mapped_feature_count / max(1, len(expected_set))
        if feature_coverage < 0.5:
            return jsonify({
                "error": "Too few model features were recognized. Check the export schema and feature mapping.",
                "recognized_features": mapped_feature_count,
                "required_features": len(expected_set),
            }), 422
        feature_df = renamed_df.reindex(columns=feature_names, fill_value=np.nan)
        feature_df = feature_df.apply(pd.to_numeric, errors="coerce")

        prediction_started = time.perf_counter()
        try:
            if inference_pipeline is not None:
                # The pipeline sanitizes +/-inf to NaN and median-imputes using
                # statistics fitted on the training partition only.
                preds = inference_pipeline.predict(feature_df)
                probabilities = inference_pipeline.predict_proba(feature_df)
            else:
                feature_df.replace([np.inf], 999999, inplace=True)
                feature_df.replace([-np.inf], -999999, inplace=True)
                X_scaled = scaler.transform(feature_df.fillna(0))
                preds = model.predict(X_scaled)
                probabilities = model.predict_proba(X_scaled)
        except Exception:
            PREDICTION_ERRORS.labels("batch").inc()
            raise
        finally:
            PREDICTION_LATENCY.labels("batch").observe(
                time.perf_counter() - prediction_started
            )
        telemetry_df = feature_df.fillna(0)
        argmax_labels = label_encoder.inverse_transform(preds)

        # Apply the same documented decision policy as the live ingest path.
        # The batch view previously showed raw argmax, which silently ignored
        # the attack threshold recorded in the serving bundle. The argmax label
        # is retained for display and audit, but `is_attack` follows the policy.
        classifier = getattr(inference_pipeline, "named_steps", {}).get("classifier")
        try:
            encoded_classes = list(classifier.classes_) if classifier is not None else []
            benign_encoded = label_encoder.transform(["BENIGN"])[0]
            benign_index = encoded_classes.index(benign_encoded)
            attack_scores = 1.0 - probabilities[:, benign_index]
        except (AttributeError, ValueError, IndexError):
            attack_scores = None
        if _serving_threshold is not None and attack_scores is not None:
            attack_flags = attack_scores >= float(_serving_threshold)
            decision_basis = "attack_probability_threshold"
        else:
            attack_flags = np.asarray([str(value) != "BENIGN" for value in argmax_labels])
            decision_basis = "argmax"
        labels = np.asarray([
            (argmax if str(argmax) != "BENIGN" else "ATTACK") if flag else "BENIGN"
            for argmax, flag in zip(argmax_labels, attack_flags)
        ])

        unique_labels, label_counts = np.unique(labels, return_counts=True)
        attack_types = {str(lbl): int(cnt) for lbl, cnt in zip(unique_labels, label_counts)}
        for label_value, count_value in zip(unique_labels, label_counts):
            PREDICTION_LABELS.labels("batch", str(label_value)).inc(int(count_value))

        total = len(labels)
        benign = int(np.sum(~attack_flags))
        attack = int(np.sum(attack_flags))

        # Generate sample details (up to 150 rows) for the frontend data table.
        # Include every predicted non-benign row first, then fill with evenly
        # spaced benign rows. A plain head slice can hide the only alert in the
        # batch, which makes the summary and the table appear to disagree.
        sample_flows = []
        max_samples = min(total, 150)
        if total <= max_samples:
            sample_indices = list(range(total))
        else:
            attack_indices = [i for i in range(total) if str(labels[i]) != "BENIGN"]
            benign_indices = [i for i in range(total) if str(labels[i]) == "BENIGN"]
            selected = attack_indices[:max_samples]
            remaining = max_samples - len(selected)
            if remaining > 0 and benign_indices:
                step = max(1, len(benign_indices) // remaining)
                selected.extend(benign_indices[::step][:remaining])
            if len(selected) < max_samples:
                chosen = set(selected)
                for i in range(total):
                    if i not in chosen:
                        selected.append(i)
                        chosen.add(i)
                    if len(selected) >= max_samples:
                        break
            sample_indices = sorted(set(selected))[:max_samples]

        for i in sample_indices:
            row_dict = df.iloc[i]
            src_ip = str(_extract_flow_field(row_dict, "Source IP", "src_ip", "src_ip_addr", default="Not present in upload"))
            dst_ip = str(_extract_flow_field(row_dict, "Destination IP", "dst_ip", "dst_ip_addr", default="Not present in upload"))
            src_port = str(_extract_flow_field(row_dict, "Source Port", "src_port", default=""))
            dst_port = str(_extract_flow_field(row_dict, "Destination Port", "dst_port", default=""))
            raw_proto = str(_extract_flow_field(row_dict, "Protocol", "protocol", default="6")).strip()

            if raw_proto in ("6", "6.0", "TCP"):
                protocol_str = "TCP"
            elif raw_proto in ("17", "17.0", "UDP"):
                protocol_str = "UDP"
            elif raw_proto in ("1", "1.0", "ICMP"):
                protocol_str = "ICMP"
            else:
                protocol_str = raw_proto or "TCP"

            lbl = str(labels[i])
            is_atk = bool(attack_flags[i])

            # Telemetry metrics from feature_df
            f_duration = float(telemetry_df.iloc[i].get("Flow Duration", 0))
            f_bytes_s = float(telemetry_df.iloc[i].get("Flow Bytes/s", 0))
            f_pkts_s = float(telemetry_df.iloc[i].get("Flow Packets/s", 0))
            f_fwd_pkts = int(telemetry_df.iloc[i].get("Total Fwd Packets", 0))
            f_bwd_pkts = int(telemetry_df.iloc[i].get("Total Backward Packets", 0))
            f_syn = int(telemetry_df.iloc[i].get("SYN Flag Count", 0))
            f_rst = int(telemetry_df.iloc[i].get("RST Flag Count", 0))
            f_ack = int(telemetry_df.iloc[i].get("ACK Flag Count", 0))
            f_fin = int(telemetry_df.iloc[i].get("FIN Flag Count", 0))

            # MITRE ATT&CK Mapping
            iface = "pcap" if packet_count is not None else "batch"
            packet_dissector = row_dict.get("Packet Dissector")
            if not isinstance(packet_dissector, dict):
                packet_dissector = None

            sample_flows.append({
                "id": f"batch-{uuid.uuid4().hex[:8]}-{i + 1}",
                "row_index": i + 1,
                "persisted": False,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol_str,
                "predicted_label": lbl,
                "is_attack": is_atk,
                "provenance": {
                    "model_version": _serving_artifact.get("model_version"),
                    "artifact_sha256": _serving_artifact.get("hash"),
                    "feature_schema_version": _serving_artifact.get("feature_schema_version"),
                    "threshold_policy": (_serving_policy or {}).get("name"),
                    "threshold_value": _serving_threshold,
                    "calibration_version": _serving_artifact.get("calibration_version"),
                    "decision_basis": decision_basis,
                    "attack_score": float(attack_scores[i]) if attack_scores is not None else None,
                    "model_argmax_label": str(argmax_labels[i]),
                },
                "mitre": None,
                "interface": iface,
                "interface_label": "Uploaded capture" if packet_count is not None else "CSV upload",
                "l2_meta": None,
                "threat_intel": {
                    "asn": "Not enriched",
                    "geo": "Not enriched",
                    "abuse_score": None,
                    "total_reports": None,
                    "provider_status": "pending" if is_atk else "not_queried",
                    "tag": "Reputation not queried"
                },
                "incident": {
                    "status": "Unreviewed",
                    "analyst": "Unassigned",
                    "sla_deadline": None
                },
                "soar": None,
                "duration_us": f"{f_duration:.0f}",
                "bytes_s": f"{f_bytes_s:.1f}",
                "pkts_s": f"{f_pkts_s:.1f}",
                "fwd_pkts": f_fwd_pkts,
                "bwd_pkts": f_bwd_pkts,
                "flags": {
                    "syn": f_syn,
                    "ack": f_ack,
                    "rst": f_rst,
                    "fin": f_fin
                },
                "shap": [],
                "packet_dissector": packet_dissector
            })

        if sample_meta is not None:
            sample_meta["display_rows"] = len(sample_flows)
            sample_meta["display_strategy"] = (
                "All predicted non-benign rows first, then evenly spaced benign rows."
            )

        public_source_ips = list(dict.fromkeys(
            flow["src_ip"] for flow in sample_flows if flow["is_attack"]
        ))[:20]
        abuse_results = {}
        if os.environ.get("NETSHIELD_THREAT_INTEL_ENABLED", "false").lower() == "true":
            with ThreadPoolExecutor(max_workers=5) as executor:
                abuse_results = dict(zip(public_source_ips, executor.map(lookup_abuseipdb, public_source_ips)))

        for flow in sample_flows:
            if not flow["is_attack"]:
                continue
            reputation = abuse_results.get(flow["src_ip"], {"status": "not_queried", "abuse_score": None})
            intel = flow["threat_intel"]
            intel["provider_status"] = reputation["status"]
            intel["abuse_score"] = reputation.get("abuse_score")
            intel["total_reports"] = reputation.get("total_reports")
            if reputation["status"] == "live":
                intel["asn"] = reputation.get("isp", "Unknown ISP")
                intel["geo"] = reputation.get("country", "Unknown")
                intel["tag"] = "Tor exit node" if reputation.get("is_tor") else reputation.get("usage_type", "Unknown")
            elif reputation["status"] == "not_configured":
                intel["tag"] = "Set ABUSEIPDB_API_KEY to enable live checks"
            elif reputation["status"] == "private_address":
                intel["tag"] = "Private address; external lookup skipped"
            elif reputation["status"] == "unavailable":
                intel["tag"] = "AbuseIPDB temporarily unavailable"

        return jsonify({
            "total": total,
            "benign": benign,
            "attack": attack,
            "attack_types": attack_types,
            "sample_flows": sample_flows,
            "decision": {
                "basis": decision_basis,
                "threshold": _serving_threshold,
                "threshold_policy": (_serving_policy or {}).get("name"),
                "calibration_version": _serving_artifact.get("calibration_version"),
                "model_version": _serving_artifact.get("model_version"),
                "artifact_sha256": _serving_artifact.get("hash"),
                "feature_schema_version": _serving_artifact.get("feature_schema_version"),
            },
            "sensor_fleet": [],
            "sensor_status": "No sensor inventory is connected to this research prototype.",
            "ingestion": {
                "type": capture_type,
                "filename": capture_filename,
                "packets_dissected": packet_count,
                "flows_extracted": len(df) if packet_count is not None else None,
                "sample": sample_meta,
            }
        })
    except Exception:  # noqa: BLE001
        app.logger.exception("Batch analysis failed")
        return jsonify({"error": "Analysis failed. Check the server log using the request timestamp."}), 500


@app.route("/api/soar/webhook", methods=["POST"])
def simulate_soar_webhook():
    """Acknowledge a mock integration event without sending external messages."""
    payload = request.get_json(silent=True) or {}
    channel = payload.get("channel")
    if channel not in {"slack", "pagerduty"}:
        return jsonify({"error": "channel must be slack or pagerduty"}), 400
    event_id = str(uuid.uuid4())
    return jsonify({
        "status": "simulated",
        "channel": channel,
        "event_id": event_id,
        "destination": "#soc-alerts (mock)" if channel == "slack" else "NetShield Demo Service (mock)",
        "message": str(payload.get("message", "Security alert dispatched"))[:500],
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "external_delivery": False
    }), 202


# ---------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------
@app.route("/api/flows", methods=["POST"])
@limiter.limit(os.environ.get("INGEST_RATE_LIMIT", "60 per second;1200 per minute"))
@require_api_key
@ingest_admission
def ingest_flow():
    """Ingest one flow or a pyflowmeter batch from the live capture client."""
    body = request.get_json(silent=True)
    if not isinstance(body, (dict, list)) or not body:
        INGEST_REQUESTS.labels(outcome="rejected_invalid").inc()
        return jsonify({"error": "A JSON object or flow batch is required"}), 400

    is_batch = isinstance(body, dict) and isinstance(body.get("flows"), list)
    flow_dicts = body["flows"] if is_batch else [body]
    if not flow_dicts or any(not isinstance(flow, dict) for flow in flow_dicts):
        INGEST_REQUESTS.labels(outcome="rejected_invalid").inc()
        return jsonify({"error": "No valid flow records received"}), 400
    if len(flow_dicts) > 500:
        INGEST_REQUESTS.labels(outcome="rejected_invalid").inc()
        return jsonify({"error": "A batch may contain at most 500 flows"}), 413
    INGEST_BATCH_SIZE.observe(len(flow_dicts))

    records = []
    identity = current_identity()
    if identity is not None:
        tenant_id = identity.get("tenant_id")
    else:
        ingest_tenant = Tenant.query.filter_by(slug=INGEST_TENANT_SLUG, is_active=True).first()
        if ingest_tenant is None:
            return jsonify({"error": "Ingest tenant is not configured or is inactive"}), 403
        tenant_id = ingest_tenant.id
    classify_started = time.perf_counter()
    try:
        evidence_rows = classify_flows_with_evidence(flow_dicts)
        for flow_dict, evidence in zip(flow_dicts, evidence_rows):
            label = evidence["predicted_label"]
            try:
                sensor_id = _clean_identity_value(
                    _extract_flow_field(flow_dict, "sensor_id", "collector_id", "sensor"), 80
                )
                interface = _clean_identity_value(
                    _extract_flow_field(flow_dict, "interface", "input_interface", "iface"), 120
                )
            except ValueError:
                return jsonify({"error": "sensor_id or interface is outside the supported length"}), 400
            # A collector that reports only an adapter name still gets a stable
            # sensor identity. No identity is fabricated when neither is sent.
            if sensor_id is None:
                sensor_id = interface
            src_ip = str(_extract_flow_field(flow_dict, "src_ip", "Source IP", "src_ip_addr") or "—")
            dst_ip = str(_extract_flow_field(flow_dict, "dst_ip", "Destination IP", "dst_ip_addr") or "—")
            src_port = _safe_int(_extract_flow_field(flow_dict, "src_port", "Source Port"))
            dst_port = _safe_int(_extract_flow_field(flow_dict, "dst_port", "Destination Port"))
            if len(src_ip) > 64 or len(dst_ip) > 64 or (src_port is not None and not 0 <= src_port <= 65535) or (dst_port is not None and not 0 <= dst_port <= 65535):
                return jsonify({"error": "Flow address or port is outside the supported range"}), 400
            raw_proto = str(_extract_flow_field(flow_dict, "protocol", "Protocol", default="")).strip()
            protocol_str = {
                "6": "TCP", "6.0": "TCP", "17": "UDP", "17.0": "UDP",
                "1": "ICMP", "1.0": "ICMP", "58": "ICMPv6", "58.0": "ICMPv6",
            }.get(raw_proto, raw_proto.upper() or "TCP")
            pred_label = str(label) if label else "BENIGN"
            records.append(Flow(
                tenant_id=tenant_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol_str,
                predicted_label=pred_label,
                is_attack=bool(evidence["is_attack"]),
                sensor_id=sensor_id,
                interface=interface,
                model_version=evidence.get("model_version"),
                artifact_sha256=evidence.get("artifact_sha256"),
                feature_schema_version=evidence.get("feature_schema_version"),
                threshold_policy=evidence.get("threshold_policy"),
                calibration_version=evidence.get("calibration_version"),
                attack_score=evidence.get("attack_score"),
                model_argmax_label=evidence.get("argmax_label"),
                decision_basis=evidence.get("decision_basis"),
                threshold_value=evidence.get("threshold"),
            ))
            _accumulate_flow_evidence(
                tenant_id, flow_dict, evidence, src_ip, dst_ip, dst_port
            )
    except Exception:  # noqa: BLE001
        INGEST_REQUESTS.labels(outcome="failed").inc()
        INGEST_FLOWS.labels(outcome="failed").inc(len(flow_dicts))
        app.logger.exception("Flow batch classification failed")
        return jsonify({"error": "Flow classification failed"}), 500
    finally:
        INGEST_STAGE_LATENCY.labels("classify").observe(
            time.perf_counter() - classify_started
        )

    persist_started = time.perf_counter()
    try:
        db.session.add_all(records)
        db.session.flush()
        # Build response payloads while the flushed objects are still in the
        # identity map. The previous per-row refresh() issued one SELECT per
        # flow after commit and dominated ingest latency.
        payloads = [record.to_dict() for record in records]
        if identity is None:
            actor = "service:" + hashlib.sha256(API_KEY.encode("utf-8")).hexdigest()[:12]
            record_audit(
                "flows.ingest",
                "flow_batch",
                None,
                detail={"accepted": len(records), "source": "service-key"},
                tenant_id=tenant_id,
                actor=actor,
                actor_role="service",
            )
        else:
            record_audit(
                "flows.ingest",
                "flow_batch",
                None,
                detail={"accepted": len(records), "source": "session"},
                tenant_id=tenant_id,
            )
        db.session.commit()
        STORAGE_OPERATIONS.labels("insert", "success").inc()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        STORAGE_OPERATIONS.labels("insert", "failure").inc()
        INGEST_REQUESTS.labels(outcome="failed").inc()
        INGEST_FLOWS.labels(outcome="failed").inc(len(records))
        app.logger.exception("Flow batch persistence failed")
        return jsonify({"error": "Flow records could not be stored"}), 500
    finally:
        STORAGE_LATENCY.labels("insert").observe(time.perf_counter() - persist_started)
        INGEST_STAGE_LATENCY.labels("persist").observe(time.perf_counter() - persist_started)
    CAPTURE_STATUS["flows_received"] += len(records)
    CAPTURE_STATUS["last_flow_at"] = datetime.utcnow().isoformat() + "Z"
    FLOW_STORE_ROWS.inc(len(records))

    for payload in payloads:
        emit_started = time.perf_counter()
        try:
            socketio.emit("new_flow", payload)
            if payload.get("is_attack"):
                ALERTS_EMITTED.labels("socketio").inc()
            ALERT_DELIVERY_LATENCY.labels("socketio").observe(
                time.perf_counter() - emit_started
            )
        except Exception:  # noqa: BLE001
            ALERT_DELIVERY_FAILURES.labels("socketio").inc()
            app.logger.exception("Alert delivery failed")
    INGEST_REQUESTS.labels(outcome="accepted").inc()
    INGEST_FLOWS.labels(outcome="accepted").inc(len(records))
    app.logger.info(
        "ingest.accepted",
        extra={
            "event": "ingest",
            "outcome": "accepted",
            "flow_count": len(records),
            "queue_depth": _queue_state()["waiting"],
        },
    )
    response_payload = {"accepted": len(payloads), "flows": payloads} if is_batch else payloads[0]
    if isinstance(response_payload, dict):
        response_payload = {**response_payload, "request_id": getattr(g, "request_id", None)}
    return jsonify(response_payload), 201


@app.route("/api/flows", methods=["GET"])
@limiter.limit(os.environ.get("READ_RATE_LIMIT", "120 per minute"))
@require_permission("flows:read")
def list_flows():
    try:
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "limit and offset must be integers"}), 400
    if not 1 <= limit <= 500 or not 0 <= offset <= 1_000_000_000:
        return jsonify({"error": "limit must be 1–500 and offset must be non-negative"}), 400
    only_attacks = request.args.get("attacks_only", "false").lower() == "true"
    sensor_filter = request.args.get("sensor_id")
    interface_filter = request.args.get("interface")
    if sensor_filter is not None and (not sensor_filter.strip() or len(sensor_filter) > 80):
        return jsonify({"error": "sensor_id must be 1-80 characters"}), 400
    if interface_filter is not None and (not interface_filter.strip() or len(interface_filter) > 120):
        return jsonify({"error": "interface must be 1-120 characters"}), 400

    query = tenant_scoped(Flow).order_by(Flow.timestamp.desc())
    if only_attacks:
        query = query.filter(Flow.is_attack.is_(True))
    if sensor_filter:
        query = query.filter(Flow.sensor_id == sensor_filter.strip())
    if interface_filter:
        query = query.filter(Flow.interface == interface_filter.strip())

    total = query.count()
    rows = query.offset(offset).limit(limit).all()
    record_audit(
        "flows.list",
        "flow",
        None,
        detail={
            "limit": limit,
            "offset": offset,
            "attacks_only": only_attacks,
            "sensor_id": sensor_filter,
            "interface": interface_filter,
            "returned": len(rows),
        },
        commit=True,
    )
    return jsonify(
        {
            "total": total,
            "limit": limit,
            "offset": offset,
            "flows": [r.to_dict() for r in rows],
        }
    )


@app.route("/api/flows/export", methods=["GET"])
@limiter.limit("10 per minute")
@require_permission("flows:export")
def export_flows():
    """Tenant-scoped CSV export. Every export is audited."""
    try:
        limit = int(request.args.get("limit", 10000))
    except (TypeError, ValueError):
        return jsonify({"error": "limit must be an integer"}), 400
    if not 1 <= limit <= 50000:
        return jsonify({"error": "limit must be between 1 and 50000"}), 400

    rows = tenant_scoped(Flow).order_by(Flow.id.desc()).limit(limit).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "sensor_id", "interface", "predicted_label", "is_attack",
        "review_status", "review_note",
        "model_version", "artifact_sha256", "feature_schema_version",
        "threshold_policy", "threshold_value", "calibration_version",
        "decision_basis", "attack_score", "model_argmax_label",
    ])
    for row in rows:
        review = row.review
        if review is not None and review.tenant_id not in (None, row.tenant_id):
            review = None
        writer.writerow([
            row.id,
            row.timestamp.isoformat() if row.timestamp else "",
            row.src_ip or "",
            row.dst_ip or "",
            row.src_port if row.src_port is not None else "",
            row.dst_port if row.dst_port is not None else "",
            row.protocol or "",
            row.sensor_id or "",
            row.interface or "",
            row.predicted_label or "",
            row.is_attack,
            review.status if review else "Unreviewed",
            review.note if review else "",
            row.model_version or "",
            row.artifact_sha256 or "",
            row.feature_schema_version or "",
            row.threshold_policy or "",
            row.threshold_value if row.threshold_value is not None else "",
            row.calibration_version or "",
            row.decision_basis or "",
            row.attack_score if row.attack_score is not None else "",
            row.model_argmax_label or "",
        ])
    record_audit(
        "flows.export",
        "flow",
        None,
        detail={"rows": len(rows), "limit": limit, "format": "csv"},
        commit=True,
    )
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=netshield-flows.csv"},
    )


@app.route("/api/flows/<int:flow_id>", methods=["GET"])
@require_permission("flows:read")
def get_flow(flow_id):
    record = tenant_scoped(Flow).filter(Flow.id == flow_id).first_or_404()
    record_audit("flows.read", "flow", record.id, commit=True)
    return jsonify(record.to_dict())


@app.route("/api/flows/<int:flow_id>/review", methods=["PUT"])
@limiter.limit("30 per minute")
@require_permission("flows:review")
def update_flow_review(flow_id):
    """Persist one analyst review and append an audit event atomically."""
    record = tenant_scoped(Flow).filter(Flow.id == flow_id).first_or_404()
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "A JSON object is required"}), 400

    allowed_statuses = {"Unreviewed", "New", "Investigating", "Suppressed", "Closed"}
    status = body.get("status")
    note = body.get("note", "")
    if status not in allowed_statuses:
        return jsonify({"error": "status must be Unreviewed, New, Investigating, Suppressed, or Closed"}), 400
    if not isinstance(note, str):
        return jsonify({"error": "note must be a string"}), 400
    note = note.strip()
    if len(note) > 2000:
        return jsonify({"error": "note must be at most 2000 characters"}), 413

    review = record.review
    previous_status = review.status if review else "Unreviewed"
    previous_note = review.note if review else ""
    note_changed = note != previous_note
    changed = status != previous_status or note_changed
    if not changed:
        return jsonify({"review": record.to_dict()["review"], "changed": False})

    identity = current_identity()
    actor = str(identity["actor"])[:80] if identity else "local-user"

    if review is None:
        review = FlowReview(
            flow_id=record.id,
            tenant_id=record.tenant_id,
            status=status,
            note=note,
            updated_by=actor,
        )
        db.session.add(review)
    else:
        review.tenant_id = record.tenant_id
        review.status = status
        review.note = note
        review.updated_by = actor
        review.updated_at = datetime.utcnow()
    db.session.add(FlowReviewAudit(
        flow_id=record.id,
        tenant_id=record.tenant_id,
        actor=actor,
        previous_status=previous_status,
        new_status=status,
        note_changed=note_changed,
    ))
    record_audit(
        "flows.review",
        "flow",
        record.id,
        detail={
            "previous_status": previous_status,
            "new_status": status,
            "note_changed": note_changed,
        },
        tenant_id=record.tenant_id,
    )
    try:
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()
        app.logger.exception("Flow review update failed")
        return jsonify({"error": "Review could not be saved"}), 500
    return jsonify({"review": record.to_dict()["review"], "changed": True})


@app.route("/api/flows/<int:flow_id>/review/audit", methods=["GET"])
@require_permission("audit:read")
def get_flow_review_audit(flow_id):
    tenant_scoped(Flow).filter(Flow.id == flow_id).first_or_404()
    rows = (FlowReviewAudit.query.filter_by(flow_id=flow_id, tenant_id=current_tenant_id())
            .order_by(FlowReviewAudit.changed_at.desc(), FlowReviewAudit.id.desc())
            .limit(100).all())
    record_audit("flows.review_audit_read", "flow", flow_id, commit=True)
    return jsonify({"events": [{
        "actor": row.actor,
        "previous_status": row.previous_status,
        "new_status": row.new_status,
        "note_changed": row.note_changed,
        "changed_at": row.changed_at.isoformat() + "Z",
    } for row in rows]})


def _stats_payload():
    base = tenant_scoped(Flow)
    total = base.count()
    attacks = base.filter(Flow.is_attack.is_(True)).count()
    benign = total - attacks

    breakdown = (
        tenant_scoped(Flow)
        .with_entities(Flow.predicted_label, db.func.count(Flow.id))
        .group_by(Flow.predicted_label)
        .all()
    )
    return {
        "total": total,
        "benign": benign,
        "attack": attacks,
        "attack_types": {label: count for label, count in breakdown},
        "ingest": _queue_state(),
    }


def _alert_budget_payload(window_minutes: int | None = None) -> dict:
    """Report whether the frozen detector is inside a declared alert budget.

    This is a reporting cap, not a retuned threshold. The served threshold is
    unchanged; the payload says how many alerts it produced in the window and
    how many the declared budget allows. A negative ``remaining_alerts`` means
    the queue is over budget and must be reported, not silently dropped.
    """
    window = int(window_minutes or ALERT_BUDGET_WINDOW_MINUTES)
    since = datetime.utcnow() - timedelta(minutes=window)
    scoped = tenant_scoped(Flow).filter(Flow.timestamp >= since)
    total = scoped.count()
    alerts = scoped.filter(Flow.is_attack.is_(True)).count()
    allowed = ALERT_BUDGET_PER_10K * total / 10_000.0 if total else 0.0
    alert_rate = (alerts / total) if total else 0.0
    if total == 0:
        state = "no_data"
    elif alerts <= allowed:
        state = "within_budget"
    else:
        state = "over_budget"
    return {
        "policy": "declared_fixed_alert_budget",
        "budget_per_10k_flows": ALERT_BUDGET_PER_10K,
        "window_minutes": window,
        "flows": total,
        "alerts": alerts,
        "alert_rate": round(alert_rate, 6),
        "allowed_alerts": round(allowed, 3),
        "remaining_alerts": round(allowed - alerts, 3),
        "state": state,
        "queue": _queue_state(),
        "note": (
            "The serving threshold is frozen. This cap reports over-budget "
            "alert volume; it never suppresses or auto-remediates a flow."
        ),
    }


def _sensor_summary_payload():
    """Tenant-scoped per-sensor counts and last-seen time.

    Sensor identity is collector-supplied and nullable. Rows without an
    identity are reported as unattributed instead of being assigned to a
    default sensor.
    """
    rows = (
        tenant_scoped(Flow)
        .with_entities(
            Flow.sensor_id,
            Flow.interface,
            Flow.is_attack,
            db.func.count(Flow.id),
            db.func.max(Flow.timestamp),
        )
        .group_by(Flow.sensor_id, Flow.interface, Flow.is_attack)
        .all()
    )
    sensors = {}
    for sensor_id, interface, is_attack, count, last_seen in rows:
        key = (sensor_id, interface)
        entry = sensors.setdefault(
            key,
            {
                "sensor_id": sensor_id,
                "interface": interface,
                "total": 0,
                "attacks": 0,
                "benign": 0,
                "last_seen": None,
            },
        )
        entry["total"] += count
        if is_attack:
            entry["attacks"] += count
        else:
            entry["benign"] += count
        if last_seen is not None and (entry["last_seen"] is None or last_seen > entry["last_seen"]):
            entry["last_seen"] = last_seen

    ordered = sorted(sensors.values(), key=lambda row: row["total"], reverse=True)
    for entry in ordered:
        entry["last_seen"] = entry["last_seen"].isoformat() + "Z" if entry["last_seen"] else None
        entry["attributed"] = entry["sensor_id"] is not None
    return {
        "sensors": ordered,
        "sensor_count": sum(1 for row in ordered if row["sensor_id"] is not None),
        "unattributed_flows": sum(row["total"] for row in ordered if row["sensor_id"] is None),
    }


@app.route("/api/stats", methods=["GET"])
@limiter.limit(os.environ.get("READ_RATE_LIMIT", "120 per minute"))
@require_permission("stats:read")
def stats():
    return jsonify(_stats_payload())


@app.route("/api/sensors/summary", methods=["GET"])
@limiter.limit(os.environ.get("READ_RATE_LIMIT", "120 per minute"))
@require_permission("console:read")
def sensor_summary():
    """Per-sensor health summary for the console. Tenant-scoped."""
    payload = _sensor_summary_payload()
    record_audit(
        "sensors.summary",
        "sensor",
        None,
        detail={"sensor_count": payload["sensor_count"], "unattributed_flows": payload["unattributed_flows"]},
        commit=True,
    )
    return jsonify(payload)


@app.route("/api/incidents", methods=["GET"])
@limiter.limit(os.environ.get("READ_RATE_LIMIT", "120 per minute"))
@require_permission("console:read")
def list_incidents():
    """Host/window incidents accumulated from independent signals.

    The accumulator is in-memory and resets on restart. It is an alert-triage
    view, not a persistence layer and not a ground-truth label source.
    """
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        return jsonify({"error": "limit must be an integer"}), 400
    if not 1 <= limit <= 500:
        return jsonify({"error": "limit must be 1-500"}), 400
    open_only = request.args.get("open_only", "true").lower() == "true"
    payload = _EVIDENCE_ACCUMULATOR.snapshot(
        tenant_id=requested_tenant_id(), open_only=open_only, limit=limit
    )
    payload["enabled"] = MULTI_SIGNAL_ENABLED
    payload["in_memory"] = True
    payload["calibration_status"] = _CALIBRATION_STATUS
    payload["isolation_forest_loaded"] = _load_isolation_bundle() is not None
    payload["threat_intel_on_ingest"] = THREAT_INTEL_ON_INGEST
    return jsonify(payload)


# ---------------------------------------------------------------------
# Identity, tenant administration, retention, and audit API
# ---------------------------------------------------------------------
@app.route("/api/me", methods=["GET"])
def me():
    identity = current_identity()
    if identity is None:
        return jsonify({"authenticated": False}), 401
    tenant = db.session.get(Tenant, identity["tenant_id"]) if identity.get("tenant_id") else None
    return jsonify({
        "authenticated": True,
        "actor": identity["actor"],
        "display_name": identity["display_name"],
        "role": identity["role"],
        "auth_source": identity["auth_source"],
        "permissions": identity["permissions"],
        "tenant": tenant.to_dict() if tenant else None,
    })


def _current_user_for_mfa():
    """Resolve the signed-in local user, or return an error response tuple."""

    identity = current_identity()
    if identity is None:
        return None, (jsonify({"error": "Authentication required"}), 401)
    user_id = identity.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if user is None:
        return None, (
            jsonify({"error": "MFA requires a signed-in local account"}), 400
        )
    if (user.auth_source or "local") != "local":
        return None, (
            jsonify(
                {
                    "error": "MFA for this account is managed by the identity provider",
                }
            ),
            409,
        )
    return user, None


@app.route("/api/me/mfa", methods=["GET"])
def me_mfa_status():
    user, error = _current_user_for_mfa()
    if error:
        return error
    remaining = len(mfa_module.load_recovery_hashes(user.mfa_recovery_hashes))
    return jsonify(
        {
            "enabled": bool(user.totp_enabled),
            "method": "totp" if user.totp_enabled else None,
            "confirmed_at": (
                user.totp_confirmed_at.isoformat() + "Z"
                if user.totp_confirmed_at
                else None
            ),
            "recovery_codes_remaining": remaining,
        }
    )


@app.route("/api/me/mfa/enroll", methods=["POST"])
def me_mfa_enroll():
    """Start TOTP enrollment. Requires the current password and returns codes once."""

    user, error = _current_user_for_mfa()
    if error:
        return error
    if user.totp_enabled:
        return (
            jsonify(
                {
                    "error": "MFA is already enabled. Disable it before enrolling a new authenticator."
                }
            ),
            409,
        )
    body = request.get_json(silent=True) or {}
    password = str(body.get("password") or "")
    if not user.password_hash or not check_password_hash(user.password_hash, password):
        record_audit(
            "auth.mfa.enroll",
            "user",
            user.id,
            outcome="failure",
            detail={"reason": "password"},
            tenant_id=user.tenant_id,
            actor=user.email,
            actor_role=user.role,
            commit=True,
        )
        return jsonify({"error": "Password is incorrect"}), 401

    secret = mfa_module.generate_secret()
    recovery_codes = mfa_module.generate_recovery_codes()
    user.totp_secret = mfa_module.encrypt_secret(secret, app.config["SECRET_KEY"])
    user.totp_enabled = False
    user.totp_confirmed_at = None
    user.totp_last_step = None
    user.mfa_recovery_hashes = mfa_module.hash_recovery_codes(recovery_codes)
    db.session.commit()
    record_audit(
        "auth.mfa.enroll",
        "user",
        user.id,
        detail={"stage": "pending_confirmation"},
        tenant_id=user.tenant_id,
        actor=user.email,
        actor_role=user.role,
        commit=True,
    )
    return jsonify(
        {
            "enabled": False,
            "secret": secret,
            "provisioning_uri": mfa_module.provisioning_uri(secret, user.email),
            "recovery_codes": recovery_codes,
            "next": "POST /api/me/mfa/confirm with the current authenticator code",
        }
    )


@app.route("/api/me/mfa/confirm", methods=["POST"])
def me_mfa_confirm():
    user, error = _current_user_for_mfa()
    if error:
        return error
    secret = _user_mfa_secret(user)
    if secret is None:
        return (
            jsonify({"error": "No pending enrollment. Start enrollment first."}), 409
        )
    body = request.get_json(silent=True) or {}
    matched_step = mfa_module.verify_code(secret, str(body.get("code") or ""))
    if matched_step is None:
        record_audit(
            "auth.mfa.confirm",
            "user",
            user.id,
            outcome="failure",
            tenant_id=user.tenant_id,
            actor=user.email,
            actor_role=user.role,
            commit=True,
        )
        return jsonify({"error": "That code is not valid"}), 400
    user.totp_enabled = True
    user.totp_confirmed_at = datetime.utcnow()
    user.totp_last_step = matched_step
    db.session.commit()
    record_audit(
        "auth.mfa.confirm",
        "user",
        user.id,
        detail={"stage": "enabled"},
        tenant_id=user.tenant_id,
        actor=user.email,
        actor_role=user.role,
        commit=True,
    )
    return jsonify({"enabled": True, "method": "totp"})


@app.route("/api/me/mfa/disable", methods=["POST"])
def me_mfa_disable():
    """Disable MFA. Requires both the password and a current factor."""

    user, error = _current_user_for_mfa()
    if error:
        return error
    body = request.get_json(silent=True) or {}
    password = str(body.get("password") or "")
    if not user.password_hash or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Password is incorrect"}), 401
    if not user.totp_enabled:
        return jsonify({"enabled": False, "detail": "MFA was not enabled"})
    method = _verify_second_factor(
        user, str(body.get("code") or ""), allow_same_step=True
    )
    if method is None:
        record_audit(
            "auth.mfa.disable",
            "user",
            user.id,
            outcome="failure",
            detail={"reason": "invalid_factor"},
            tenant_id=user.tenant_id,
            actor=user.email,
            actor_role=user.role,
            commit=True,
        )
        db.session.rollback()
        return jsonify({"error": "A current authenticator or recovery code is required"}), 400

    user.totp_secret = None
    user.totp_enabled = False
    user.totp_confirmed_at = None
    user.totp_last_step = None
    user.mfa_recovery_hashes = None
    db.session.commit()
    record_audit(
        "auth.mfa.disable",
        "user",
        user.id,
        detail={"method": method},
        tenant_id=user.tenant_id,
        actor=user.email,
        actor_role=user.role,
        commit=True,
    )
    return jsonify({"enabled": False})


def _validate_tenant_slug(slug):
    import re

    return bool(re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", slug or ""))


@app.route("/api/tenants", methods=["GET", "POST"])
@require_permission("tenants:manage")
def tenants():
    if request.method == "GET":
        rows = Tenant.query.order_by(Tenant.slug.asc()).all()
        record_audit("tenants.list", "tenant", None, commit=True)
        return jsonify({"tenants": [row.to_dict() for row in rows]})

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "A JSON object is required"}), 400
    slug = str(body.get("slug", "")).strip().lower()
    name = str(body.get("name", "")).strip()
    if not _validate_tenant_slug(slug):
        return jsonify({"error": "slug must match [a-z0-9][a-z0-9-]{1,62}"}), 400
    if not name or len(name) > 120:
        return jsonify({"error": "name is required and must be at most 120 characters"}), 400
    if Tenant.query.filter_by(slug=slug).first() is not None:
        return jsonify({"error": "tenant slug already exists"}), 409
    try:
        retention_days = int(body.get("retention_days", 30))
    except (TypeError, ValueError):
        return jsonify({"error": "retention_days must be an integer"}), 400
    if not 1 <= retention_days <= 3650:
        return jsonify({"error": "retention_days must be between 1 and 3650"}), 400

    tenant = Tenant(slug=slug, name=name, retention_days=retention_days)
    db.session.add(tenant)
    db.session.flush()
    record_audit("tenants.create", "tenant", tenant.id, detail={"slug": slug, "name": name})
    db.session.commit()
    return jsonify({"tenant": tenant.to_dict()}), 201


@app.route("/api/tenants/<int:tenant_id>", methods=["DELETE"])
@require_permission("platform:admin")
def delete_tenant(tenant_id):
    tenant = db.session.get(Tenant, tenant_id)
    if tenant is None:
        return jsonify({"error": "Tenant not found"}), 404
    if tenant.slug == DEFAULT_TENANT_SLUG:
        return jsonify({"error": "The default tenant cannot be deleted"}), 400
    body = request.get_json(silent=True) or {}
    if body.get("confirm") != tenant.slug:
        return jsonify({"error": "Send {\"confirm\": \"<tenant slug>\"} to delete this tenant"}), 400

    slug = tenant.slug
    flow_ids = [row[0] for row in db.session.query(Flow.id).filter(Flow.tenant_id == tenant_id).all()]
    _delete_flows(flow_ids)
    User.query.filter_by(tenant_id=tenant_id).delete(synchronize_session=False)
    AuditEvent.query.filter_by(tenant_id=tenant_id).delete(synchronize_session=False)
    db.session.delete(tenant)
    record_audit(
        "tenants.delete",
        "tenant",
        tenant_id,
        detail={"slug": slug, "deleted_flows": len(flow_ids)},
        tenant_id=None,
    )
    db.session.commit()
    return jsonify({"deleted": True, "tenant_id": tenant_id, "deleted_flows": len(flow_ids)})


@app.route("/api/tenant", methods=["GET"])
@require_permission("tenant:admin")
def tenant_info():
    tenant = db.session.get(Tenant, current_tenant_id())
    if tenant is None:
        return jsonify({"error": "Tenant not found"}), 404
    return jsonify({
        "tenant": tenant.to_dict(),
        "flow_count": tenant_scoped(Flow).count(),
        "user_count": User.query.filter_by(tenant_id=tenant.id).count(),
        "audit_event_count": AuditEvent.query.filter_by(tenant_id=tenant.id).count(),
    })


@app.route("/api/tenant/retention", methods=["GET", "PUT"])
@require_permission("retention:manage")
def tenant_retention():
    tenant = db.session.get(Tenant, current_tenant_id())
    if tenant is None:
        return jsonify({"error": "Tenant not found"}), 404
    if request.method == "GET":
        return jsonify({"tenant_id": tenant.id, "retention_days": tenant.retention_days})

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "A JSON object is required"}), 400
    try:
        retention_days = int(body.get("retention_days"))
    except (TypeError, ValueError):
        return jsonify({"error": "retention_days must be an integer"}), 400
    if not 1 <= retention_days <= 3650:
        return jsonify({"error": "retention_days must be between 1 and 3650"}), 400
    previous = tenant.retention_days
    tenant.retention_days = retention_days
    record_audit(
        "tenant.retention_update",
        "tenant",
        tenant.id,
        detail={"previous_days": previous, "new_days": retention_days},
    )
    db.session.commit()
    return jsonify({"tenant_id": tenant.id, "retention_days": tenant.retention_days})


@app.route("/api/tenant/purge", methods=["POST"])
@limiter.limit("5 per minute")
@require_permission("retention:manage")
def purge_tenant_data():
    tenant = db.session.get(Tenant, current_tenant_id())
    if tenant is None:
        return jsonify({"error": "Tenant not found"}), 404
    cutoff = datetime.utcnow() - timedelta(days=tenant.retention_days)
    flow_ids = [
        row[0]
        for row in db.session.query(Flow.id)
        .filter(Flow.tenant_id == tenant.id, Flow.timestamp < cutoff)
        .all()
    ]
    _delete_flows(flow_ids)
    record_audit(
        "tenant.retention_purge",
        "tenant",
        tenant.id,
        detail={"deleted_flows": len(flow_ids), "cutoff": cutoff.isoformat() + "Z"},
    )
    db.session.commit()
    return jsonify({"deleted_flows": len(flow_ids), "cutoff": cutoff.isoformat() + "Z"})


@app.route("/api/tenant/users", methods=["GET", "POST"])
@require_permission("users:manage")
def tenant_users():
    tenant_id = current_tenant_id()
    if request.method == "GET":
        rows = User.query.filter_by(tenant_id=tenant_id).order_by(User.email.asc()).all()
        record_audit("users.list", "user", None, commit=True)
        return jsonify({"users": [row.to_dict() for row in rows]})

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "A JSON object is required"}), 400
    email = str(body.get("email", "")).strip().lower()
    password = body.get("password", "")
    role = str(body.get("role", "viewer")).strip().lower()
    display_name = str(body.get("display_name", "")).strip()[:120]
    if "@" not in email or len(email) > 254:
        return jsonify({"error": "A valid email is required"}), 400
    if not isinstance(password, str) or len(password) < 12:
        return jsonify({"error": "password must be at least 12 characters"}), 400
    if role not in {"viewer", "analyst", "admin"}:
        return jsonify({"error": "role must be viewer, analyst, or admin"}), 400
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"error": "A user with that email already exists"}), 409

    user = User(
        tenant_id=tenant_id,
        email=email,
        display_name=display_name,
        password_hash=generate_password_hash(password),
        role=role,
        auth_source="local",
        is_active=True,
    )
    db.session.add(user)
    db.session.flush()
    record_audit("users.create", "user", user.id, detail={"email": email, "role": role})
    db.session.commit()
    return jsonify({"user": user.to_dict()}), 201


@app.route("/api/tenant/users/<int:user_id>", methods=["PATCH"])
@require_permission("users:manage")
def update_tenant_user(user_id):
    user = User.query.filter_by(id=user_id, tenant_id=current_tenant_id()).first()
    if user is None:
        return jsonify({"error": "User not found"}), 404
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "A JSON object is required"}), 400
    changes = {}
    if "role" in body:
        role = str(body["role"]).strip().lower()
        if role not in {"viewer", "analyst", "admin"}:
            return jsonify({"error": "role must be viewer, analyst, or admin"}), 400
        changes["role"] = {"previous": user.role, "new": role}
        user.role = role
    if "is_active" in body:
        is_active = bool(body["is_active"])
        changes["is_active"] = {"previous": user.is_active, "new": is_active}
        user.is_active = is_active
    if not changes:
        return jsonify({"error": "No supported fields supplied"}), 400
    record_audit("users.update", "user", user.id, detail=changes)
    db.session.commit()
    return jsonify({"user": user.to_dict()})


@app.route("/api/audit", methods=["GET"])
@require_permission("audit:read")
def audit_events():
    try:
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "limit and offset must be integers"}), 400
    if not 1 <= limit <= 500 or offset < 0:
        return jsonify({"error": "limit must be 1-500 and offset must be non-negative"}), 400

    query = tenant_scoped(AuditEvent)
    action = request.args.get("action")
    if action:
        query = query.filter(AuditEvent.action == action)
    total = query.count()
    rows = query.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).offset(offset).limit(limit).all()
    record_audit("audit.read", "audit_event", None, detail={"limit": limit, "offset": offset}, commit=True)
    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [row.to_dict() for row in rows],
    })


@app.route("/api/console/snapshot", methods=["GET"])
@limiter.limit(os.environ.get("CONSOLE_RATE_LIMIT", "120 per minute"))
@require_permission("console:read")
def console_snapshot():
    """One request for the console: capture state, stored counts, recent flows.

    ``after_id`` lets the console fetch only records newer than the newest one
    it already holds. ``flagged_limit`` adds recent predicted non-benign rows
    to the first load, because the newest slice can be entirely benign while
    older flagged records still need to be reviewable. The response is a
    read-only projection; it never mutates capture state or model output.
    """
    try:
        limit = int(request.args.get("limit", 150))
        after_id = int(request.args.get("after_id", 0))
        flagged_limit = int(request.args.get("flagged_limit", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "limit, after_id, and flagged_limit must be integers"}), 400
    if not 1 <= limit <= 500 or after_id < 0 or not 0 <= flagged_limit <= 500:
        return jsonify({"error": "limit must be 1-500, after_id non-negative, flagged_limit 0-500"}), 400

    sensor_filter = request.args.get("sensor_id")
    interface_filter = request.args.get("interface")
    if sensor_filter is not None and (not sensor_filter.strip() or len(sensor_filter) > 80):
        return jsonify({"error": "sensor_id must be 1-80 characters"}), 400
    if interface_filter is not None and (not interface_filter.strip() or len(interface_filter) > 120):
        return jsonify({"error": "interface must be 1-120 characters"}), 400

    query = tenant_scoped(Flow).order_by(Flow.id.desc())
    if after_id:
        query = query.filter(Flow.id > after_id)
    if sensor_filter:
        query = query.filter(Flow.sensor_id == sensor_filter.strip())
    if interface_filter:
        query = query.filter(Flow.interface == interface_filter.strip())
    rows = query.limit(limit).all()

    if flagged_limit and not after_id:
        seen = {row.id for row in rows}
        flagged_query = tenant_scoped(Flow).filter(Flow.is_attack.is_(True))
        if sensor_filter:
            flagged_query = flagged_query.filter(Flow.sensor_id == sensor_filter.strip())
        if interface_filter:
            flagged_query = flagged_query.filter(Flow.interface == interface_filter.strip())
        flagged_rows = flagged_query.order_by(Flow.id.desc()).limit(flagged_limit).all()
        rows.extend(row for row in flagged_rows if row.id not in seen)
        rows.sort(key=lambda row: row.id, reverse=True)

    return jsonify(
        {
            "capture": CAPTURE_STATUS,
            "stats": _stats_payload(),
            "alert_budget": _alert_budget_payload(),
            "sensors": _sensor_summary_payload()["sensors"],
            "flows": [row.to_dict() for row in rows],
            "server_time": datetime.utcnow().isoformat() + "Z",
        }
    )


@app.route("/api/artifacts", methods=["GET"])
@require_permission("flows:read")
def model_artifacts():
    """Return SHA-256 hashes and metadata from stored model manifests.

    Reads all model_manifest_*.json files in the models/ directory and
    returns their contents. This powers the provenance table in the UI.
    No labels or test data are exposed through this endpoint.
    """
    import glob
    import json

    manifests = []
    manifest_glob = os.path.join(os.path.dirname(__file__), "models", "model_manifest_*.json")
    for path in sorted(glob.glob(manifest_glob)):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            manifests.append(data)
        except Exception as exc:  # noqa: BLE001
            manifests.append({"path": os.path.basename(path), "error": str(exc)})
    record_audit("models.read", "model_artifact", None, detail={"count": len(manifests)}, commit=True)
    return jsonify({"manifests": manifests, "count": len(manifests)})


@app.route("/api/capture-status", methods=["GET"])
@require_permission("console:read")
def capture_status():
    return jsonify(CAPTURE_STATUS)


@app.route("/api/unmapped-features", methods=["GET"])
@require_permission("console:read")
def unmapped_features():
    """Debug helper: raw feature names sent by live_capture.py that could
    NOT be matched to the model's expected feature_names. Use this to
    fill in FEATURE_NAME_OVERRIDES in feature_mapper.py."""
    return jsonify({"unmapped": sorted(UNMAPPED_LOG)})


@app.route("/api/threat-intel", methods=["GET"])
@require_permission("stats:read")
def threat_intel_summary():
    """Report observable application totals without inventing IOCs or risk scores."""
    total = tenant_scoped(Flow).count()
    attacks = tenant_scoped(Flow).filter(Flow.is_attack.is_(True)).count()
    return jsonify({
        "flow_count": total,
        "flagged_flow_count": attacks,
        "flagged_flow_ratio": round(attacks / max(1, total), 4),
        "ratio_is_calibrated_risk": False,
        "enrichment": {
            "provider": "AbuseIPDB",
            "enabled": (
                os.environ.get("NETSHIELD_THREAT_INTEL_ENABLED", "false").lower() == "true"
                and bool(os.environ.get("ABUSEIPDB_API_KEY"))
            ),
            "source_records_returned": 0,
        },
    })


@app.route("/api/layer2-attacks", methods=["GET"])
def layer2_attack_catalog():
    """Explicitly report that link-layer signatures are not implemented."""
    return jsonify({
        "available": False,
        "status": "not_implemented",
        "message": "This prototype analyzes flow features and does not implement link-layer attack detection.",
    }), 501


@app.route("/api/simulate-flow", methods=["POST"])
@limiter.limit("30 per minute")
@require_permission("console:read")
def simulate_flow():
    """Emit a visibly marked synthetic fixture without writing it to flow history."""
    if os.environ.get("NETSHIELD_DEMO_STREAM", "false").lower() != "true":
        return jsonify({"error": "Synthetic demo traffic is disabled."}), 404

    import random

    # Demo fixtures only: this randomness never feeds a security decision.
    labels = ["BENIGN", "BENIGN", "BENIGN", "DDoS", "PortScan", "Web Attack – Brute Force"]
    label = random.choice(labels)  # nosec B311
    is_attack = label != "BENIGN"
    payload = {
        "id": f"demo-{uuid.uuid4().hex[:12]}",
        "persisted": False,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": f"198.51.100.{random.randint(1, 254)}" if is_attack else f"192.0.2.{random.randint(1, 254)}",  # nosec B311
        "dst_ip": f"192.0.2.{random.randint(1, 254)}",  # nosec B311
        "src_port": random.randint(1024, 65535),  # nosec B311
        "dst_port": random.choice([80, 443, 22, 53]),  # nosec B311
        "protocol": random.choice(["TCP", "TCP", "UDP"]),  # nosec B311
        "predicted_label": label,
        "is_attack": is_attack,
        "simulation": True,
        "prediction_source": "synthetic_fixture_not_model_output",
        "interface": "demo",
        "threat_intel": {"provider_status": "not_queried", "tag": "Synthetic fixture; no enrichment"},
        "incident": {"status": "Demo only", "analyst": "Not assigned"},
        "shap": [],
    }
    socketio.emit("new_flow", payload)
    return jsonify(payload), 201



def _run_flask_server(port: int):
    # 0.0.0.0 is the deliberate container bind address in production; local
    # development stays on loopback unless NETSHIELD_BIND_HOST overrides it.
    host = os.environ.get("NETSHIELD_BIND_HOST", "0.0.0.0" if AUTH_REQUIRED else "127.0.0.1")  # nosec B104
    socketio.run(app, host=host, port=port, debug=False, use_reloader=False)


def _wait_for_server(base_url: str, timeout_seconds: int = 15) -> bool:
    import requests

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            response = requests.get(f"{base_url}/healthz", timeout=1)
            response.raise_for_status()
            return True
        except requests.RequestException:
            time.sleep(0.5)
    return False


def _start_live_capture(base_url: str):
    """Start physical packet capture; synthetic ingestion is opt-in.

    Interface selection is documented in ``capture_interfaces``: ``auto``
    follows the OS default route (Wi-Fi, Ethernet, mobile hotspot, USB
    tethering, VPN, ...), ``all`` captures on every adapter with an address,
    and explicit names/descriptions/IPs/GUIDs are matched. Each interface runs
    in its own sniffer; one adapter failing never stops the others.
    """
    if AUTH_REQUIRED or os.environ.get("ENABLE_LOCAL_CAPTURE", "false").lower() != "true":
        CAPTURE_STATUS.update(state="disabled", message="Local packet capture is disabled; configure an external collector.")
        return
    CAPTURE_STATUS.update(
        state="starting",
        message=f"Resolving capture interfaces for selection {CAPTURE_INTERFACE!r}",
    )
    try:
        from pyflowmeter.features.context.packet_direction import PacketDirection
        from pyflowmeter.features.flow_bytes import FlowBytes
        from pyflowmeter.sniffer import create_sniffer
    except ImportError:
        print("[app] pyflowmeter not installed or available — packet capture is unavailable.")
        CAPTURE_STATUS.update(
            state="unavailable",
            message="pyflowmeter is unavailable; install project requirements to capture packets.",
        )
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[app] Stopped cleanly.")
        return

    try:
        from capture_interfaces import format_capture_interfaces, resolve_capture_interfaces
    except ImportError:
        CAPTURE_STATUS.update(
            state="unavailable",
            message="Scapy is unavailable; install project requirements to enumerate adapters.",
        )
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[app] Stopped cleanly.")
        return

    # Patch a known pyflowmeter bug
    def patched_get_bulk_rate(self, packet_direction):
        if packet_direction == PacketDirection.FORWARD:
            if self.feature.forward_bulk_count != 0 and self.feature.forward_bulk_duration != 0:
                return self.feature.forward_bulk_size / self.feature.forward_bulk_duration
        else:
            if self.feature.backward_bulk_count != 0 and self.feature.backward_bulk_duration != 0:
                return self.feature.backward_bulk_size / self.feature.backward_bulk_duration
        return 0

    FlowBytes.get_bulk_rate = patched_get_bulk_rate

    try:
        print(format_capture_interfaces())
    except Exception as err:  # noqa: BLE001 - diagnostics must never kill capture
        print(f"[app] Could not enumerate adapters for diagnostics: {err}")

    resolved, unknown = resolve_capture_interfaces(CAPTURE_INTERFACE)
    if unknown:
        print(f"[app] WARNING: interface entries not in the adapter list: {', '.join(unknown)}")
    if not resolved:
        CAPTURE_STATUS.update(
            state="error",
            message=f"No capture interface matched selection {CAPTURE_INTERFACE!r}.",
            interfaces=[],
            unknown_interfaces=unknown,
        )
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[app] Stopped cleanly.")
        return

    interface_states = [{"interface": name, "state": "starting", "message": ""} for name in resolved]
    CAPTURE_STATUS.update(
        interface=", ".join(resolved),
        interfaces=interface_states,
        unknown_interfaces=unknown,
        message=f"Starting capture on {len(resolved)} interface(s): {', '.join(resolved)}",
    )

    capture_url = f"{base_url}/api/flows?api_key={API_KEY}"
    print(f"[app] Starting live capture on {len(resolved)} interface(s): {', '.join(resolved)}")
    print(f"[app] Flows will be sent internally to: {base_url}/api/flows")
    print("[app] Press Ctrl+C to stop everything.\n")

    sniffers = []
    for entry in interface_states:
        name = entry["interface"]
        try:
            sniffer = create_sniffer(
                input_interface=name,
                to_csv=False,
                server_endpoint=capture_url,
            )
            sniffer.start()
            sniffers.append(sniffer)
            entry.update(state="listening", message=f"Packet capture listening on {name}")
        except Exception as err:  # noqa: BLE001 - one adapter failing must not stop the rest
            print(f"[app] Capture failed on {name}: {err}")
            entry.update(state="error", message=f"Capture failed on {name}: {err}")

    listening = [entry for entry in interface_states if entry["state"] == "listening"]
    if listening:
        CAPTURE_STATUS.update(
            state="listening",
            message=(
                f"Packet capture listening on {', '.join(entry['interface'] for entry in listening)}"
                + (f" ({len(interface_states) - len(listening)} interface(s) failed)" if len(listening) < len(interface_states) else "")
            ),
        )
    else:
        CAPTURE_STATUS.update(
            state="error",
            message="All capture interfaces failed to start; no packets will be ingested.",
        )

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[app] Stopping capture...")
        for sniffer in sniffers:
            try:
                sniffer.stop()
                sniffer.join()
            except Exception as err:  # noqa: BLE001
                print(f"[app] Error stopping a sniffer: {err}")
        print("[app] Stopped cleanly.")


if __name__ == "__main__":
    import threading
    import time

    port = int(os.environ.get("PORT", "5000"))
    base_url = f"http://127.0.0.1:{port}"

    server_thread = threading.Thread(target=_run_flask_server, args=(port,), daemon=True)
    server_thread.start()

    print(f"[app] Waiting for server to come up at {base_url} ...")
    if not _wait_for_server(base_url):
        print("[app] WARNING: server did not respond in time — capture may fail to connect.")
    else:
        print(f"[app] NetShield ready: {base_url}/")

    if os.environ.get("ENABLE_LOCAL_CAPTURE", "false").lower() == "true" and not AUTH_REQUIRED:
        _start_live_capture(base_url)
    else:
        CAPTURE_STATUS.update(
            state="disabled",
            message=(
                "Local packet capture is disabled; stored records and external "
                "collector ingestion are available."
            ),
        )
        server_thread.join()
