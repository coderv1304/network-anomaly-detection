# Multi-Signal Host/Window Evidence

**Status:** experimental, additive triage layer. It does not change the serving
model, the per-flow decision, or stored `Flow` rows.
**Module:** [`../domain/evidence_accumulator.py`](../domain/evidence_accumulator.py).
**API:** `GET /api/incidents`.
**Tests:** [`../tests/test_evidence_accumulator.py`](../tests/test_evidence_accumulator.py),
[`../tests/test_incidents_api.py`](../tests/test_incidents_api.py).
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.

## 1. Why aggregate evidence

A single per-flow probability is a weak alerting unit. At realistic attack
prevalence most threshold crossings are false positives, and one score cannot
distinguish a noisy flow from a sustained host-level event. This layer groups
scored flows by `(tenant, source IP, time window)` and only opens an incident
when more than one independent signal corroborates the host.

It is inspired by Slips-style behavioural evidence accumulation, but it is a
small, dependency-free implementation, not a port of Slips.

## 2. Signals and caps

| Signal | Source | Maximum points per window | Minimum before contribution |
| --- | --- | ---: | ---: |
| `supervised` | Random Forest `1 - P(BENIGN)`, calibrated when available | 50 | 0.50 |
| `unsupervised` | Isolation Forest `-decision_function`, mapped to 0-1 | 35 | 0.50 |
| `reputation` | AbuseIPDB confidence, optional | 45 | 50 / 100 |

Points are linear between the minimum and 1.0 (or 100 for reputation), and are
capped **per signal per window**. Sending 10,000 flows from one host cannot
raise the score above the cap. More flows increase `flow_count`, destination
fan-out, and evidence samples, not unbounded risk.

## 3. Incident policy

Defaults:

- Window: **300 seconds**, aligned to epoch multiples.
- Incident threshold: **70 risk points**.
- Minimum independent signals: **2**.

With the default weights, no single signal can reach 70 on its own (maximum
50, 35, or 45), so two signals are required in practice even if the signal-count
setting were lowered by accident. An incident opens the first time the policy is
met inside a window and remains open for that window.

These are product-policy defaults, not statistically optimised values. They were
not selected or tuned on a labelled external test set.

## 4. Wiring in the app

On each ingested flow, after the per-flow prediction:

1. The raw attack score is calibrated only if the calibration artifact's
   `artifact_sha256` matches the serving artifact hash. Otherwise the status is
   `calibration_hash_mismatch`, `calibration_artifact_missing`, or
   `uncalibrated`, and that status is recorded on the observation. The shipped
   isotonic artifact is hash-matched but has held-out ECE ≈ 0.208, so the value
   is weakly calibrated and is not shown as a confidence percentage.
2. The optional Isolation Forest bundle is loaded once and scored. The raw
   anomaly score is centred so that the validation threshold maps to confidence
   `0.5`. This is a monotone presentation transform, **not** a calibrated
   probability.
3. AbuseIPDB lookup during ingest is **off by default**. Set
   `NETSHIELD_THREAT_INTEL_ON_INGEST=true` to enable it for flows already
   classified as attacks.
4. The observation is added to the accumulator. Accumulation is best-effort: an
   exception is logged and never turns a successful ingest into a 500.

Calibration and Isolation Forest are optional. If either artifact is absent, the
corresponding signal contributes zero unless a caller supplies it explicitly.

## 5. API

```http
GET /api/incidents?limit=50&open_only=true
```

Response fields:

| Field | Meaning |
| --- | --- |
| `enabled` | `ENABLE_MULTI_SIGNAL_EVIDENCE` |
| `in_memory` | Always `true`; restart clears state |
| `calibration_status` | Calibration artifact state |
| `isolation_forest_loaded` | Whether the optional bundle loaded |
| `threat_intel_on_ingest` | Whether ingest-time reputation is enabled |
| `window_seconds`, `incident_threshold`, `min_signals` | Active policy |
| `incidents[]` | Open windows, highest risk first |
| `incidents[].risk_points` | Sum of capped signal points, not a probability |
| `incidents[].points`, `signal_hits`, `last_values` | Per-signal contribution |
| `incidents[].evidence` | Last 12 human-readable contributions |
| `incidents[].distinct_destination_ports` / `_ips` | Fan-out, capped at 500 each |
| `incidents[].sample_flow_ids` | Up to 10 flow identifiers |

The endpoint is tenant-scoped through the normal request identity and requires
`console:read`.

## 6. Configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `ENABLE_MULTI_SIGNAL_EVIDENCE` | `true` | Enable accumulation during ingest |
| `NETSHIELD_EVIDENCE_WINDOW_SECONDS` | `300` | Window length |
| `NETSHIELD_INCIDENT_RISK_THRESHOLD` | `70` | Points needed to open |
| `NETSHIELD_CALIBRATION_PATH` | `models/calibration_rf_day_based_seed42.json` | Calibration artifact |
| `NETSHIELD_ISOLATION_BUNDLE` | `models/model_bundle_if_day_based_seed42.pkl` | Isolation Forest bundle |
| `NETSHIELD_THREAT_INTEL_ON_INGEST` | `false` | Reputation lookup during ingest |

## 7. Limits

- **Not validated detection.** The 70-point/2-signal policy is a triage design,
  not a measured detector. A labelled evaluation of the *calibrated
  single-signal* variant now exists ([WINDOW_INCIDENT_EVAL.md](WINDOW_INCIDENT_EVAL.md)):
  no Wednesday grid point met the 0.1% benign-window false-incident target, the
  frozen point transferred to a 0.79% benign-window rate on Thursday-Friday, and
  at 0.1% flow prevalence window precision and recall were both 0.0000. The
  default multi-signal policy itself remains unmeasured, and this evaluation does
  not license any precision or recall claim for it.
- **In-memory only.** State is lost on restart and is not shared across
  processes. A multi-worker deployment will show per-worker incidents. There is
  no database migration or durable incident table.
- **Risk points are not probabilities.** Do not present them as confidence.
- **Destination tracking is capped** at 500 ports and 500 IPs per window, and
  only 12 windows are retained per source. Very high fan-out is truncated.
- **The unsupervised signal is not calibrated**; it is a bounded monotone
  transform of the Isolation Forest decision score.
- **Ingest-time scoring costs CPU.** The optional Isolation Forest adds one
  transform and decision-function call per ingested flow. The documented
  20 flows/s load test predates this layer, so capacity at that rate is not
  re-established here.
- **No response action.** An incident is a review object. NetShield still does
  not block, quarantine, or change firewall state.

## 8. Reproduction

```bash
venv/Scripts/python.exe -m pytest tests/test_evidence_accumulator.py tests/test_incidents_api.py -q
```
