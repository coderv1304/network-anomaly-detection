# Test Suite (`tests/`)

Automated tests validating preprocessing, feature extraction parity, API behavior, tenancy, sensor identity, reliability controls, the model registry, and the release gates.

## Running tests

Run pytest from the repository root with the project virtual environment:

```bash
venv/Scripts/python.exe -m pytest tests/ -q
```

Go flow-assembly tests live in `capture/` and run with `go test ./...`.

## Structure

| File | What it covers |
| --- | --- |
| `test_preprocessing.py` | Cleaning, NaN/Inf handling, and column stripping. |
| `test_feature_mapper.py` | Normalization and mapping between live packet features and trained model feature names. |
| `test_parity_live_capture.py` | Upload-parser and live-capture feature parity, including known gaps. |
| `test_pcap_parser.py` | PCAP/PCAPNG parsing and malformed-input behavior. |
| `test_pipeline.py` | Training/evaluation pipeline behavior. |
| `test_explainability.py` | Offline SHAP/explainability helpers. |
| `test_threat_intel.py` | Optional AbuseIPDB enrichment and caching behavior. |
| `test_app_auth.py` | Authentication and API-key boundaries. |
| `test_tenancy.py` | Cross-tenant read, write, review, retention, audit, and deletion isolation. |
| `test_sensor_identity.py` | P3 sensor identity, ingest fallback, filtering, per-sensor summary, and tenant isolation. |
| `test_reliability.py` | Metrics, request IDs, rate limits, and backpressure. |
| `test_model_registry.py` | Artifact provenance, registry verification, deployment gate, and CSV export. |
| `test_capture_interfaces.py` | Cross-platform adapter selection (`auto`, `all`, loopback, explicit lists). |
| `test_pilot_analysis.py` | S7 pilot-analysis harness and its synthetic self-test guard. |
| `test_security_gate.py` | Container security-gate pass/fail rules. |
| `test_release_gate.py` | S8 nine-check release gate, blocked evidence, and CLI exit codes. |

A passing test suite proves the code paths behave as tested. It does not prove detection efficacy, live feature parity, SaaS readiness, or that an external review occurred.
