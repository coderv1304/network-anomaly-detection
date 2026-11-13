# Reliability, SLOs, and On-Call (Phase S2)

*Status: controls implemented and measured on a single host. The 20 flows/s ingest
latency SLO now passes after batch inference, removal of per-row refresh queries,
and SQLite WAL tuning. Capacity above 20 flows/s was not re-measured, and the
service is not production ready.*

This document defines the service-level objectives, the metrics that measure
them, the alerting rules, the backpressure policy, and the on-call ownership
model. Every number in the "Measured" sections comes from
`docs/load_test_results.json`, produced by `scripts/load_test.py` against the
real HTTP surface of this application.

## 1. Honest summary

| Question | Answer |
| --- | --- |
| Are SLOs defined? | Yes, below. |
| Are SLIs instrumented? | Yes: Prometheus metrics, JSON request logs, stage timings, `/readyz`. |
| Is the service SLO-compliant? | **At 20 flows/s, yes** for ingest latency: latest run p95 164.9 ms with 100% success. Capacity above 20 flows/s was not re-measured, so no higher-rate claim is made. |
| Is it production ready? | **No.** Single process, SQLite, development WSGI server, no distributed tracing, no multi-host failover. |
| What is the measured failure point? | The pre-optimization sweep first saw 503 backpressure at **50 flows/s** (batch size 10). The optimized path has not been swept above 20 flows/s. |

## 2. Service-level objectives

Targets are stated for a single-process reference deployment. They are the
standard this project is judged against, not a claim that it currently meets it.

| SLO | SLI | Definition | Target | Window | Measured today |
| --- | --- | --- | --- | --- | --- |
| Ingest availability | `netshield_ingest_requests_total` | accepted / all ingest requests | >= 99.5% | 30 days | 100% at 20 flows/s in the latest run; the pre-optimization sweep reached 46.1% success across 20–400 flows/s |
| Ingest latency | `netshield_api_latency_seconds{route="/api/flows"}` | p95 request latency | <= 250 ms | 5 min rolling | **164.9 ms p95 at 20 flows/s** (latest); pre-optimization 641 ms |
| Console latency | `netshield_api_latency_seconds{route="/api/console/snapshot"}` | p95 request latency | <= 500 ms | 5 min rolling | Not measured under load in this run; console polling was not part of the sweep |
| Alert delivery | `netshield_alerts_emitted_total`, `netshield_alert_delivery_failures_total` | failures / emitted | <= 0.1% | 30 days | 0 failures observed; only the in-app SocketIO channel exists |
| Readiness | `/readyz` | HTTP 200 after DB `SELECT 1` | 99.9% | 30 days | 200 throughout the run |

**Error budget.** At a 99.5% ingest-availability target the 30-day budget is
0.5% of requests. The pre-optimization load test consumed that budget in minutes
at 50 flows/s. A sustained multi-hour run is still required before any
availability claim.

**Why 250 ms.** Ingest is synchronous: classify, persist, audit, emit. A 250 ms
p95 keeps a single collector's backlog bounded. It is a deliberately strict
target that the original SQLite + single-process design failed; batching
inference and removing per-row refreshes brought the 20 flows/s p95 to 164.9 ms.

## 3. Instrumentation

### Metrics (`monitoring/prometheus_metrics.py`)

| Group | Metrics |
| --- | --- |
| Ingest | `netshield_ingest_requests_total{outcome}`, `netshield_ingest_flows_total{outcome}`, `netshield_ingest_batch_size`, `netshield_ingest_stage_seconds{stage}`, `netshield_ingest_inflight`, `netshield_ingest_queue_depth`, `netshield_ingest_backpressure_rejections_total`, `netshield_ingest_rate_limited_total` |
| Prediction | `netshield_prediction_seconds{path}`, `netshield_prediction_errors_total{path}`, `netshield_prediction_labels_total{path,label}` |
| Storage | `netshield_storage_operations_total{operation,outcome}`, `netshield_storage_seconds{operation}`, `netshield_flow_store_rows` |
| API | `netshield_api_requests_total{method,route,status}`, `netshield_api_latency_seconds{method,route}` |
| Alerts | `netshield_alerts_emitted_total{channel}`, `netshield_alert_delivery_seconds{channel}`, `netshield_alert_delivery_failures_total{channel}` |
| Build | `netshield_build_info{version,environment}` |

Metrics are opt-in via `METRICS_ENABLED=true` so importing the app has no
network side effect. Scrape `http://127.0.0.1:8000/metrics`.

Legacy names (`packets_total`, `active_flows`, `dropped_packets`,
`inference_latency_seconds`) are aliases kept for older dashboards. Note that
`active_flows` now aliases a gauge of in-flight ingest requests, not a flow
count, and `dropped_packets` aliases backpressure rejections, not packet drops.
New dashboards must use the `netshield_` names.

### Structured logs (`monitoring/structured_logging.py`)

Every log record is one JSON object. Request-scoped fields (`request_id`,
`method`, `path`, `route`, `tenant_id`, `actor`) are injected by a filter.
`StageTimer` emits `stage.complete` / `stage.failed` with `duration_ms`.

Sample ingest record from the smoke test:

```json
{"ts":"2026-11-08T03:27:09.258793+00:00","level":"INFO","logger":"app","message":"ingest.accepted","event":"ingest","request_id":"de2a6c4ee3a94af3919a9e2f694ba952","method":"POST","path":"/api/flows","route":"/api/flows","tenant_id":1,"actor":"local-user","outcome":"accepted","queue_depth":0,"flow_count":1}
```

### Traces

Tracing is log-based stage timing, not a distributed trace. There is no W3C
trace propagation and no collector. Adding OpenTelemetry is future work.

### Health endpoints

- `GET /healthz` — liveness, returns `{"status":"ok"}`.
- `GET /readyz` — readiness, runs `SELECT 1` and returns the ingest queue state.
  Returns 503 with `{"status":"not_ready","reason":"database"}` if the DB fails.

## 4. Rate limits and backpressure policy

### Rate limits

| Endpoint | Limit | Override |
| --- | --- | --- |
| `POST /api/flows` | 60 per second; 1200 per minute | `INGEST_RATE_LIMIT` |
| `GET /api/flows` | 120 per minute | `READ_RATE_LIMIT` |
| `GET /api/stats` | 120 per minute | `READ_RATE_LIMIT` |
| `GET /api/console/snapshot` | 120 per minute | `CONSOLE_RATE_LIMIT` |
| `POST /predict` | 10 per minute | — |
| `POST /login` | 5 per minute | — |

A rate-limited request returns HTTP 429 with a JSON body containing
`request_id` and `retry_after_seconds`, plus a `Retry-After` header. Ingest
rate-limit rejections increment `netshield_ingest_rate_limited_total`.

The limiter uses `memory://` storage by default, which is per-process. Set
`RATELIMIT_STORAGE_URI` to a shared backend (for example Redis) before running
more than one process, otherwise each process enforces its own budget.

### Bounded admission (backpressure)

Classification plus persistence is synchronous, so the backpressure point is
concurrency, not a queue:

- `INGEST_MAX_INFLIGHT` (default 4) caps concurrent ingest work.
- `INGEST_QUEUE_TIMEOUT_MS` (default 250) is how long a request waits for a slot.
- A request that cannot get a slot within the timeout gets HTTP 503 with a JSON
  body and `Retry-After`, and increments
  `netshield_ingest_backpressure_rejections_total`.
- `netshield_ingest_inflight` and `netshield_ingest_queue_depth` expose the
  current state; `/readyz` and `/api/stats` also report it.

**Policy.** Shedding load with an explicit 503 + `Retry-After` is preferred over
unbounded queueing, because an unbounded queue converts a throughput problem
into a latency and memory problem. Collectors must honour `Retry-After` and
back off exponentially. The service does not silently drop accepted work.

## 5. Load test: method and results

Method: `scripts/load_test.py`, 8 worker threads, batch size 10, 8 seconds per
step, declared flow rates 20/50/100/200/400 per second, against
`POST /api/flows` with a real API key. Success = HTTP 201. The server ran with
`NETSHIELD_DEMO_STREAM=false`, SQLite, and metrics on.

**Pre-optimization sweep.** This table records the original single-process
design before batch inference, removal of per-row refresh queries, and SQLite
WAL tuning. It is retained as the saturation baseline, not as the current
behavior.

| Declared flows/s | Achieved flows/s | Requests | Success | 429 | 503 | p50 ms | p95 ms | p99 ms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 20 | 20.0 | 18 | 100.0% | 0 | 0 | 447 | 641 | 642 |
| 50 | 49.9 | 45 | 80.0% | 0 | 9 | 869 | 978 | 1082 |
| 100 | 85.0 | 75 | 49.3% | 0 | 38 | 487 | 1372 | 1401 |
| 200 | 121.4 | 104 | 34.6% | 0 | 68 | 357 | 1332 | 1527 |
| 400 | 128.2 | 112 | 32.1% | 0 | 76 | 337 | 1300 | 1423 |

**Post-optimization 20 flows/s run.** 2 workers, batch size 10, 15 seconds.

| Declared flows/s | Achieved flows/s | Requests | Success | 429 | 503 | p50 ms | p95 ms | p99 ms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 20 | 20.0 | 32 | 100.0% | 0 | 0 | 130.8 | **164.9** | 291.0 |

**Claim boundary.** The 20 flows/s ingest-latency SLO now passes. The
pre-optimization sweep remains the only measured saturation behavior: first 503
backpressure at a declared 50 flows/s, with throughput saturating near 128
flows/s of attempted work. The optimized path must be re-swept above 20 flows/s
before any higher-rate capacity or availability claim.

**Rate limiter not exercised.** Batch size 10 kept the request rate under the
60 req/s ingest limit, so every rejection was 503 backpressure and none was 429.
The 429 path is covered by unit tests but not by this load sweep. A future sweep
should use batch size 1 to drive request rates above 60/s.

**What this does not measure.** Single host, single process, local SQLite, no
network latency, no console polling under load, no concurrent analytics. It is a
lower bound on capacity, not a capacity claim.

## 6. Alerts and dashboard

- `monitoring/prometheus_alerts.yml` defines alerts for ingest error/backpressure
  ratio, backpressure activity, queue depth, persistence p95, console p95,
  prediction errors, alert-delivery failures, and scrape failure.
- `monitoring/grafana_dashboard.json` (uid `netshield-slo`) panels ingest
  outcomes, queue depth and in-flight, ingest stage p95, API p95 by route,
  prediction errors and alert-delivery failures, flow-store rows, and attack
  prediction rate.

Both files are validated as well-formed (JSON/YAML). They reference only metric
names that the application actually exports.

| Alert | Severity | Condition |
| --- | --- | --- |
| `NetShieldIngestUnavailable` | page | failed+backpressure > 1% of ingest requests for 10m |
| `NetShieldIngestBackpressure` | ticket | any backpressure rejection in 5m |
| `NetShieldIngestQueueWaiting` | ticket | queue depth > 0 for 5m |
| `NetShieldIngestLatencyHigh` | ticket | persist p95 > 250 ms for 10m |
| `NetShieldConsoleLatencyHigh` | ticket | console p95 > 500 ms for 10m |
| `NetShieldPredictionErrors` | page | any prediction error in 5m |
| `NetShieldAlertDeliveryFailures` | page | any alert-delivery failure in 5m |
| `NetShieldNotReady` | page | Prometheus cannot scrape for 2m |

## 7. On-call ownership and escalation

This is a single-maintainer research project, so ownership is nominal. The
table records the intended model, not a staffed rota.

| Tier | Owner | Responsibility | Response target |
| --- | --- | --- | --- |
| Primary | Service maintainer | Triage page alerts, decide rollback vs. mitigation | 30 min (business hours), best effort otherwise |
| Secondary | Data/model owner | Inference errors, label/feature regressions, model rollback | 4 h |
| Escalation | Project owner | Customer-facing impact, data-loss decisions, disabling ingest | 1 business day |

**Runbook for `NetShieldIngestUnavailable`:**

1. Check `/readyz` and `/healthz`. A failing `/readyz` points at the database.
2. Check `netshield_ingest_inflight` and `netshield_ingest_queue_depth`. If
   in-flight is pinned at `INGEST_MAX_INFLIGHT`, the service is saturated.
3. Check `netshield_ingest_stage_seconds{stage="persist"}`. A rising persist p95
   points at database contention or disk.
4. Mitigate: ask collectors to honour `Retry-After`; raise
   `INGEST_MAX_INFLIGHT` only after confirming the database can absorb it; or
   move to a real WSGI server and a non-SQLite database.
5. If predictions are wrong rather than slow, roll back the model bundle using
   `models/model_manifest_*.json` hashes.

**What is not covered.** No paging integration, no 24/7 rota, no automated
failover, no multi-region story, and no incident-response drill. A local SQLite
backup/restore drill has been run and passes (see
[`backup_restore_drill.json`](backup_restore_drill.json) and the
[operations runbook](OPERATIONS_RUNBOOK.md)), but the backup is not off-host or
encrypted and no RPO/RTO is established. Those remain prerequisites for a
production on-call commitment and are not implemented.

## 8. Exit-gate checklist

| Gate item | Status | Evidence |
| --- | --- | --- |
| SLOs for ingest availability, console latency, alert delivery | Done | Section 2 |
| Metrics added | Done | `monitoring/prometheus_metrics.py`; `/metrics` populated after the load test |
| Structured logs | Done | `monitoring/structured_logging.py`; JSON records in the smoke test |
| Traces | Partial | Stage timings and request IDs only; no distributed tracing |
| Rate limits | Done | Section 4; 429 handler with `Retry-After` |
| Queue backpressure | Done | Bounded admission; 503 + `Retry-After`; gauges |
| Load test and failure point | Done | Section 5; pre-optimization failure at 50 flows/s; optimized 20 flows/s p95 164.9 ms |
| On-call ownership/escalation | Documented | Section 7; not staffed |
| No production-readiness claim without measured compliance | Honoured | 20 flows/s latency SLO met; higher-rate capacity and availability unproven |

## 9. Reproduce

```bash
# Terminal 1: start the service with metrics
LIVE_CAPTURE_API_KEY=loadtest-key DATABASE_URL=sqlite:///loadtest.db \
  NETSHIELD_DEMO_STREAM=false PORT=5050 METRICS_ENABLED=true METRICS_PORT=8000 \
  venv/Scripts/python.exe app.py

# Terminal 2: readiness, then load
curl -s http://127.0.0.1:5050/readyz
venv/Scripts/python.exe scripts/load_test.py \
  --base-url http://127.0.0.1:5050 --api-key loadtest-key \
  --rates 20,50,100,200,400 --duration 8 --workers 8 --batch-size 10

# Terminal 3: confirm metrics moved
curl -s http://127.0.0.1:8000/metrics | grep netshield_
```
