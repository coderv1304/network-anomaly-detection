"""Prometheus metrics for the NetShield service.

Metric names use the ``netshield_`` prefix so they are unambiguous when this
service shares a Prometheus server with others. The four SLO-facing groups are
ingest, prediction, storage, and API latency, plus alert delivery.

The legacy ``packets_total``/``inference_latency_seconds`` names are kept as
aliases for older dashboards; new code should use the ``netshield_`` names.
"""

from prometheus_client import Counter, Gauge, Histogram, start_http_server

# ---------------------------------------------------------------------------
# Build information
# ---------------------------------------------------------------------------
BUILD_INFO = Gauge(
    "netshield_build_info",
    "Static build metadata; value is always 1.",
    ["version", "environment"],
)

# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------
INGEST_REQUESTS = Counter(
    "netshield_ingest_requests_total",
    "Ingest requests by terminal outcome.",
    ["outcome"],
)
INGEST_FLOWS = Counter(
    "netshield_ingest_flows_total",
    "Individual flow records by terminal outcome.",
    ["outcome"],
)
INGEST_BATCH_SIZE = Histogram(
    "netshield_ingest_batch_size",
    "Flows per ingest request.",
    buckets=[1, 5, 10, 25, 50, 100, 250, 500],
)
INGEST_STAGE_LATENCY = Histogram(
    "netshield_ingest_stage_seconds",
    "Time spent in each ingest stage.",
    ["stage"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
)
INGEST_INFLIGHT = Gauge(
    "netshield_ingest_inflight",
    "Ingest requests currently being classified or persisted.",
)
INGEST_QUEUE_DEPTH = Gauge(
    "netshield_ingest_queue_depth",
    "Ingest requests waiting for an admission slot.",
)
INGEST_BACKPRESSURE_REJECTIONS = Counter(
    "netshield_ingest_backpressure_rejections_total",
    "Ingest requests rejected because the bounded admission queue was full.",
)
INGEST_RATE_LIMITED = Counter(
    "netshield_ingest_rate_limited_total",
    "Ingest requests rejected by the rate limiter.",
)

# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------
PREDICTION_LATENCY = Histogram(
    "netshield_prediction_seconds",
    "Model inference latency by path.",
    ["path"],
    buckets=[0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1],
)
PREDICTION_ERRORS = Counter(
    "netshield_prediction_errors_total",
    "Prediction failures by path.",
    ["path"],
)
PREDICTION_LABELS = Counter(
    "netshield_prediction_labels_total",
    "Predicted labels by serving path.",
    ["path", "label"],
)

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
STORAGE_OPERATIONS = Counter(
    "netshield_storage_operations_total",
    "Database operations by operation and outcome.",
    ["operation", "outcome"],
)
STORAGE_LATENCY = Histogram(
    "netshield_storage_seconds",
    "Database operation latency.",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
)
FLOW_STORE_ROWS = Gauge(
    "netshield_flow_store_rows",
    "Rows currently stored in the flow table (all tenants).",
)

# ---------------------------------------------------------------------------
# API latency
# ---------------------------------------------------------------------------
API_REQUESTS = Counter(
    "netshield_api_requests_total",
    "HTTP requests by method, route template, and status.",
    ["method", "route", "status"],
)
API_LATENCY = Histogram(
    "netshield_api_latency_seconds",
    "HTTP request latency by method and route template.",
    ["method", "route"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
)

# ---------------------------------------------------------------------------
# Alert delivery (in-app SocketIO push today)
# ---------------------------------------------------------------------------
ALERTS_EMITTED = Counter(
    "netshield_alerts_emitted_total",
    "Alert payloads emitted by delivery channel.",
    ["channel"],
)
ALERT_DELIVERY_LATENCY = Histogram(
    "netshield_alert_delivery_seconds",
    "Alert delivery latency by channel.",
    ["channel"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
)
ALERT_DELIVERY_FAILURES = Counter(
    "netshield_alert_delivery_failures_total",
    "Alert delivery failures by channel.",
    ["channel"],
)

# ---------------------------------------------------------------------------
# Backward-compatible aliases
# ---------------------------------------------------------------------------
PACKETS_TOTAL = INGEST_FLOWS
ACTIVE_FLOWS = INGEST_INFLIGHT
DROPPED_PACKETS = INGEST_BACKPRESSURE_REJECTIONS
INFERENCE_LATENCY = PREDICTION_LATENCY


def start_metrics_server(port=8000, addr="127.0.0.1"):
    """Expose Prometheus metrics on an explicitly selected interface."""
    return start_http_server(port, addr=addr)
