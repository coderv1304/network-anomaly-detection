# NetShield — Network Anomaly Detection

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Go 1.22+](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-pytest%20%7C%20Go-informational)](#testing)

**An end-to-end network-flow anomaly detection project combining machine learning, packet analysis, a real-time monitoring dashboard, and reproducible evaluation tooling.**

NetShield explores the practical gap between strong benchmark results and useful network monitoring: data leakage, class imbalance, dataset quality, and feature mismatch between offline flow exports and live capture. It is built around CIC-IDS-2017 and is intended for education, experimentation, and controlled lab use—not as a production intrusion-prevention system.

> **Project maturity:** The Flask analysis and dashboard application is the primary runnable experience. The Go capture program is an experimental standalone prototype; it is not yet a production-ready replacement for the Python capture/inference path. See [limitations](#limitations-and-responsible-use) before interpreting model results.

## Highlights

- **Analyze traffic files:** Upload flow CSVs and PCAP/PCAPNG captures through the web interface. PCAP data is dissected and grouped into flows before classification.
- **Classify network flows:** A trained scikit-learn Random Forest predicts benign and CIC-IDS-2017 attack labels.
- **Monitor live flows:** The Flask-SocketIO dashboard displays incoming flow events and aggregate benign/attack counts. Live capture uses PyFlowMeter and requires a supported network adapter and capture privileges.
- **Persist and inspect results:** SQLite stores classified flows; REST endpoints expose flow history, individual records, counts, and capture status.
- **Normalize extractor features:** A mapping layer translates capture-tool feature names to the model's expected CIC-style names and reports unmapped fields for diagnosis.
- **Enrich public IPs (optional):** AbuseIPDB lookups are available for public IP addresses when configured. Private and invalid IPs are not sent to the provider; in-memory caching is enabled, with optional Redis caching.
- **Evaluate and explain the model:** Training utilities provide dataset audits, leak-free preprocessing pipelines, multiple evaluation metrics, baseline comparisons, and offline SHAP feature analysis.
- **Run locally or in containers:** Docker and Compose files are included as experimental deployment paths; live packet capture requires additional host/network configuration.
- **Install as a web app:** The dashboard includes a web app manifest, service worker, and offline page for Progressive Web App support.

### Demo and response behavior

The dashboard includes demo-flow generation and SOAR-style response controls for UI demonstrations. These are **simulations**: they do not generate real attack traffic, block hosts, or send Slack/PagerDuty messages. Simulated flows are disabled on application startup unless `NETSHIELD_DEMO_STREAM=true` is set. The UI's per-flow attribution cards are illustrative; use the offline SHAP analysis artifacts for model feature analysis, not the cards as calibrated explanations.

## Screens and workflows

| Workflow | What it does |
| --- | --- |
| Batch analysis | Submit a CIC-IDS-style CSV, PCAP, or PCAPNG file and review model predictions and traffic summaries. |
| Live dashboard | View the live event stream, connectivity/capture status, and persisted flow statistics. |
| Model development | Audit data, train/evaluate pipelines, compare baselines, and select candidate features. |
| Capture prototype | Capture or replay packets with the separate Go flow assembler and emit flow records as JSON. |

## Architecture

```text
CSV / PCAP / PCAPNG ──> Flask analysis API ──> feature normalization ──> Random Forest
                               │                                      │
                               ├── SQLite flow history <──────────────┘
                               ├── REST API + Socket.IO ──> web dashboard
                               └── optional AbuseIPDB enrichment

Network adapter ──> PyFlowMeter ──> live-flow API ──> inference and dashboard

Go capture prototype ──> packet parsing and 5-tuple flow assembly ──> JSON stdout
```

The Go program can read a live interface or a PCAP file. It currently emits basic flow records and is a separate prototype; it does not implement the Python model's complete feature set or connect directly to the inference API.

### Repository map

```text
app.py                         Flask app, dashboard routes, inference, and live capture startup
feature_mapper.py              Capture-to-model feature name normalization
pcap_parser.py                 PCAP/PCAPNG parsing for batch analysis
threat_intel.py                Optional AbuseIPDB lookup and caching
training/                      Preprocessing, training, evaluation, audits, and SHAP analysis
capture/                       Standalone Go packet capture and flow assembly prototype
templates/ and static/         Dashboard, batch-analysis UI, and PWA assets
extension/                     Browser-extension UI prototype
monitoring/                    Prometheus metrics endpoint setup
models/                        Serialized model and preprocessing artifacts
data/samples/                  Small CSV datasets for tests and demonstrations
docs/                          Model card, dataset audit, benchmarks, and design documentation
tests/                         Python tests; Go tests live in capture/
```

## Quick start

### Requirements

- Python 3.10 or newer
- Git
- For live packet capture: a supported capture driver (Npcap on Windows or libpcap on Linux/macOS), a valid interface name, and the privileges required by that driver

### Install and run

```bash
git clone https://github.com/coderv1304/network-anomaly-detection.git
cd network-anomaly-detection

python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# Linux / macOS
source .venv/bin/activate
```

Install dependencies and launch:

```bash
python -m pip install -r requirements.txt
python app.py
```

Open [http://localhost:5000](http://localhost:5000) for batch analysis or [http://localhost:5000/dashboard](http://localhost:5000/dashboard) for live monitoring. Try a CSV in `data/samples/` to explore batch analysis without setting up packet capture.

`python app.py` starts the web server and attempts to start packet capture. If capture is unavailable, the web application may still be available, while capture status reports the failure or unavailable state. Use `NETSHIELD_CAPTURE_INTERFACE` to configure the adapter. Use `NETSHIELD_DEMO_STREAM=true` only when you intentionally want synthetic flows for a demo.

### Optional integrations and limits

| Setting | Purpose |
| --- | --- |
| `ABUSEIPDB_API_KEY` | Enables AbuseIPDB reputation lookups for eligible public IP addresses. |
| `REDIS_URL` | Enables optional Redis-backed one-hour caching for AbuseIPDB results; an in-memory cache is used otherwise. |
| `NETSHIELD_CAPTURE_INTERFACE` | Overrides the configured live-capture interface name. |
| `LIVE_CAPTURE_API_KEY` | Sets the API key required by the live-flow ingestion endpoint. Configure a strong value outside local development. |
| `NETSHIELD_DEMO_STREAM` | Set to `true` to enable synthetic dashboard flow generation. Off by default. |
| `PORT` | Changes the Flask-SocketIO server port; defaults to `5000`. |

Uploads are limited to 50 MB by the Flask application, and PCAP parsing enforces a 250,000-packet limit. A phone hotspot does not expose the phone's complete cellular traffic or traffic from other hotspot clients to this computer's capture interface.

## Model development and evaluation

The project includes a separate model-development workflow in `training/`:

```bash
# Run the dataset audit on the included sample data
python training/audit_dataset.py --data-dir data/samples --output docs/DATASET_AUDIT.md

# Train/evaluate using the supported sample data and a stratified split
python training/train_pipeline.py --data-dir data/samples --split-mode random --model rf

# Run the Python test suite
pytest tests/ -v

# Run Go capture tests
cd capture
go test ./...
```

To run a day-based evaluation, provide the complete CIC-IDS-2017 data directory and use `--split-mode day_based`. The raw benchmark dataset is not included here; obtain it from the [official CIC-IDS-2017 source](https://www.unb.ca/cic/datasets/ids-2017.html). The model card documents the dataset subsets used by this project.

### Evaluation caveat

Do not interpret accuracy from a random row split as expected performance on new networks. CIC-IDS-2017 is imbalanced and has documented data-quality limitations; repeated or temporally related traffic can make random splits optimistic. The committed baseline benchmark reports a **Random Forest macro-F1 of 0.1072 ± 0.0030** across its documented runs, despite a much higher weighted-F1, illustrating the challenge of minority attack classes. Review [the benchmark report](docs/BENCHMARK_RESULTS.md), [dataset audit](docs/DATASET_AUDIT.md), and [model card](docs/MODEL_CARD.md) for methodology, caveats, and current model details.

The training utilities implement a preprocessing pipeline that fits imputation and scaling on training data only. The currently served `app.py` path loads the serialized model and scaler artifacts in `models/`; validate the exact artifacts and evaluation split before making claims about model quality or deployment suitability.

## API overview

The Flask application exposes these primary endpoints:

| Endpoint | Purpose |
| --- | --- |
| `POST /predict` | Analyze an uploaded CSV, PCAP/PCAPNG, or configured sample dataset. |
| `POST /api/flows` | Ingest one or more live flow records; requires `X-API-Key` or the configured `api_key` query parameter. |
| `GET /api/flows` | Retrieve paginated flow history; supports `limit`, `offset`, and `attacks_only=true`. |
| `GET /api/flows/<id>` | Retrieve a flow by database ID. |
| `GET /api/stats` | Return total, benign, attack, and label counts. |
| `GET /api/capture-status` | Return live-capture state and status details. |
| `GET /api/unmapped-features` | Inspect feature names that the mapper could not match. |
| `GET /metrics` | Prometheus metrics endpoint on port `8000`. |

Socket.IO emits a `new_flow` event when flows are added, allowing the dashboard to update without polling the flow list.

## Testing

```bash
pytest tests/ -v
```

The Python suite covers preprocessing, feature mapping, PCAP parsing, pipeline evaluation, explainability helpers, and threat-intelligence behavior. Go flow-assembly tests can be run from the `capture/` directory:

```bash
go test ./...
```

## Further documentation

- [Model card and limitations](docs/MODEL_CARD.md)
- [Benchmark results](docs/BENCHMARK_RESULTS.md)
- [Dataset audit](docs/DATASET_AUDIT.md)
- [SHAP feature-selection report](docs/FEATURE_SELECTION_SHAP.md)
- [Training workflow](training/README.md)
- [Go capture prototype](capture/README.md)
- [Deployment notes](deploy/README.md)
- [Test suite notes](tests/README.md)
- [Software requirements specification](docs/srs/README.md)

## Limitations and responsible use

- This is a research and portfolio project, not a validated production NIDS. Predictions should be reviewed by a human and should not trigger automated blocking decisions.
- The model is based on CIC-IDS-2017 and may not generalize to current, real-world traffic. Dataset imbalance, labeling issues, feature-extractor differences, and distribution drift remain material concerns.
- The current live-capture and batch-serving paths depend on model artifacts and feature mappings that require validation against the capture environment.
- PCAP analysis can involve sensitive network data. Analyze only traffic you are authorized to inspect and protect uploaded captures and resulting logs.
- Attack-traffic generation utilities must only be used in isolated environments that you own or are authorized to test.
- AbuseIPDB enrichment sends eligible public IP addresses to the third-party service when enabled; configure it only if that disclosure is acceptable for your environment.
- SOAR-style dashboard actions and generated demo flows are simulations, not real containment or alert delivery.

## License

Released under the [MIT License](LICENSE).
