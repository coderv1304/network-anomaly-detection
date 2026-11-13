"""Structured JSON logging and request-scoped trace context.

This is intentionally lightweight: every request gets a request ID, every log
record is one JSON object, and ingest/prediction/storage stages emit timing
spans. It is log-based tracing, not a distributed tracing backend. A real
deployment should forward these records to a collector (for example the
OpenTelemetry Collector) and add W3C trace propagation at the ingress.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime

from flask import g, has_request_context, request

_EXTRA_FIELDS = (
    "event",
    "request_id",
    "method",
    "path",
    "route",
    "status",
    "duration_ms",
    "tenant_id",
    "actor",
    "outcome",
    "stage",
    "queue_depth",
    "flow_count",
    "label",
    "error",
)


class RequestContextFilter(logging.Filter):
    """Attach request-scoped fields to every record without call-site changes."""

    def filter(self, record: logging.LogRecord) -> bool:
        if has_request_context():
            record.request_id = getattr(g, "request_id", None)
            record.method = request.method
            record.path = request.path
            record.route = getattr(g, "route_template", None) or request.endpoint
            record.tenant_id = getattr(g, "tenant_id", None)
            record.actor = getattr(g, "actor", None)
        return True


class JsonFormatter(logging.Formatter):
    """Render one JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


class StageTimer:
    """Context manager that logs and times one named stage.

    Example::

        with StageTimer(app.logger, "ingest.persist", flow_count=len(records)):
            db.session.commit()
    """

    def __init__(self, logger: logging.Logger, stage: str, **fields):
        self.logger = logger
        self.stage = stage
        self.fields = fields
        self.started = 0.0

    def __enter__(self):
        self.started = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        duration_ms = (time.perf_counter() - self.started) * 1000
        level = logging.ERROR if exc_type is not None else logging.INFO
        self.logger.log(
            level,
            "stage.complete" if exc_type is None else "stage.failed",
            extra={
                "event": "stage",
                "stage": self.stage,
                "duration_ms": round(duration_ms, 3),
                "error": str(exc) if exc is not None else None,
                **self.fields,
            },
        )
        return False


def configure_structured_logging(app) -> None:
    """Install JSON logging on the Flask app logger and root logger."""
    formatter = JsonFormatter()
    context_filter = RequestContextFilter()

    for handler in list(app.logger.handlers):
        app.logger.removeHandler(handler)
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    stream.addFilter(context_filter)
    app.logger.addHandler(stream)
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False

    root = logging.getLogger()
    if not any(isinstance(handler.formatter, JsonFormatter) for handler in root.handlers):
        root_handler = logging.StreamHandler()
        root_handler.setFormatter(formatter)
        root_handler.addFilter(context_filter)
        root.addHandler(root_handler)
        root.setLevel(logging.INFO)
