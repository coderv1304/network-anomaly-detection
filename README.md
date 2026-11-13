<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:4B6CB7,100:8E54E9&height=210&section=header&text=NetShield&fontSize=70&fontColor=ffffff&animation=fadeIn&fontAlignY=35&desc=Network%20Anomaly%20Detection%20%7C%20ML%20for%20Volumetric%20%26%20Scanning%20Traffic&descAlignY=56&descSize=17" width="100%"/>

<a href="https://github.com/coderv1304/network-anomaly-detection">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=21&pause=1000&color=8E54E9&center=true&vCenter=true&width=820&lines=Flow-based+anomaly+detection+on+CIC-IDS-2017;Random+Forest+%2B+frozen+Tier+A+schema;Flask+console+%2B+research+workbench;Honest+benchmarks%2C+including+negative+results;Research+prototype%2C+not+a+production+NIDS" alt="Typing SVG"/>
</a>

<br/>

<img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white"/>
<img src="https://img.shields.io/badge/scikit--learn-1.5-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white"/>
<img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=for-the-badge&logo=go&logoColor=white"/>
<img src="https://img.shields.io/badge/License-MIT-2ea44f?style=for-the-badge"/>

<br/>

<img src="https://img.shields.io/badge/Tests-pytest%20%7C%20Go-informational?style=for-the-badge&logo=pytest&logoColor=white"/>
<img src="https://img.shields.io/badge/Status-Research%20Prototype-orange?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Scope-Volumetric%20%26%20Scanning-8E54E9?style=for-the-badge"/>

<br/><br/>

<a href="http://localhost:5000">🖥️ Console</a> •
<a href="http://localhost:5000/research">🔬 Research Workbench</a> •
<a href="docs/MODEL_CARD.md">🧠 Model Card</a> •
<a href="docs/CLAIM_EVIDENCE_MATRIX.md">📋 Claim Matrix</a> •
<a href="docs/PHASE_STATUS.md">📌 Phase Status</a>

</div>

---

## 🛡️ About NetShield

**NetShield** is an end-to-end network-flow analysis application that scores traffic for volumetric and scanning behavior using a Random Forest model trained on CIC-IDS-2017.

It is built to explore the gap between strong benchmark numbers and useful monitoring: leakage, class imbalance, dataset quality, and feature mismatch between offline flow exports and live capture. The project ships a Flask operator console, a research workbench, batch PCAP/CSV analysis, an optional Go capture collector, and reproducible evaluation tooling.

| | |
|---|---|
| 🎯 Project Type | Research prototype / engineering portfolio project |
| 🧪 Detection Scope | Flow-based volumetric and scanning behavior only |
| 📊 Primary Dataset | CIC-IDS-2017 (day-based split) |
| 🌍 Transfer Datasets | CIC-IDS-2018, UNSW-NB15 (negative transfer, documented) |
| 🤖 Serving Model | Random Forest, 80 statistical flow features |
| 🔑 Serving Artifact | `models/model_bundle_rf_day_based_seed42.pkl` |
| 🔒 Artifact SHA-256 | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` |
| ⚖️ Decision Rule | `1 - P(BENIGN) >= 0.002515048908954043` |
| 🖥️ Console Stack | Flask • Flask-SocketIO • SQLite • Chart.js |
| 📦 Capture Stack | Go collector • Python PCAP parser • optional Npcap/libpcap |
| 🚀 Ops Surface | Docker • Prometheus/Grafana • GitHub Actions security gates |
| 📍 Status | Research prototype • not production-ready |

> **Frozen scope (P0):** NetShield is a flow-based detector for volumetric and scanning behavior. It is **not** a general NIDS. Live accuracy is unvalidated. Botnet, web attacks, infiltration, zero-day, and blocking are out of scope. Every public claim maps to an artifact in the [claim–evidence matrix](docs/CLAIM_EVIDENCE_MATRIX.md).

---

## 🧰 Tech Stack & Tools

### Core Application

<p>
<img src="https://skillicons.dev/icons?i=python,flask,sqlite,js,html,css" />
</p>

### Machine Learning & Data

<p>
<img src="https://skillicons.dev/icons?i=sklearn,pandas,numpy,jupyter" />
</p>

### Capture, Deployment & Observability

<p>
<img src="https://skillicons.dev/icons?i=go,docker,linux,bash,git,githubactions,prometheus,grafana,redis" />
</p>

**Also used:** pytest • Bandit • pip-audit • Trivy • SHAP • Alembic • Gunicorn • Ruff

---

## 🏗️ Architecture

```mermaid
flowchart LR
    A[PCAP / CSV upload] --> B[Flow parser]
    L[Go live collector] --> B
    B --> C[Feature mapper]
    C --> D[Random Forest bundle]
    D --> E[Score + frozen threshold]
    E --> F[(SQLite)]
    F --> G[Flask operator console]
    F --> H[Research workbench]
    G --> I[Review, audit, retention]
    H --> J[Evaluation reports]
```

**Two runnable surfaces:**

- **Operator console** (`/`) — live flow queue, filters, sensor identity, review workflow, alert-budget status, provenance, and audit trail.
- **Research workbench** (`/research`) — evaluation reports, threshold policy, prevalence analysis, calibration, cost model, and cross-dataset results.

**Optional capture path:** the Go collector can stream live flow records when a capture driver and interface are configured. Live accuracy is **not validated**; the console is the primary runnable surface.

---

## 📊 Evidence Snapshot

All numbers below are from the frozen evaluation protocol. They are development evidence, not a blind confirmatory test, and they are reported with their limitations.

| Evaluation | Result | Reading |
| --- | --- | --- |
| Serving model | RF, day-based split, seed 42, 80 features | Monday–Tuesday train, Wednesday validation, Thursday–Friday test |
| Test partition | 1,162,065 flows, 291,139 positives (25.05%) | Benchmark prevalence is high; real networks are far sparser |
| Seed-42 test | PR-AUC **0.7900**, ROC-AUC **0.7816** | Strong on the benchmark split |
| Seed-42 operating point | FPR **0.725%**, recall **57.94%**, precision **96.39%** | At a **15.06%** alert rate |
| Five-seed variation | PR-AUC **0.7472 ± 0.0749**, FPR **4.11% ± 3.27%**, recall **58.30% ± 14.79%** | The threshold does not transfer cleanly across seeds |
| Prevalence 0.1% (seed 42) | PPV **7.40%**, **78.27** alerts per 10k flows | Precision collapses outside the benchmark base rate |
| CIC-IDS-2018 transfer | ROC-AUC **0.7241**, AP **0.2048** | Frozen threshold emits **0 alerts** |
| UNSW-NB15 transfer | ROC-AUC **0.3793**, AP **0.1028** | Frozen threshold emits **0 alerts** |
| Cross-dataset conclusion | **Negative / partial transfer** | Reported, not tuned away |

> **What this does not mean:** a matching artifact hash is provenance, not detection evidence. High benchmark precision is not a production claim. See [PREVALENCE_EVAL.md](docs/PREVALENCE_EVAL.md), [CROSS_DATASET.md](docs/CROSS_DATASET.md), and [COST_MODEL_AND_RELEASE_GATE.md](docs/COST_MODEL_AND_RELEASE_GATE.md).

---

## 🚀 Quick Start

### Requirements

- Python 3.10 or newer
- Git
- Optional live capture: Npcap (Windows) or libpcap (Linux/macOS), a valid interface, and the privileges required by that driver

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

Open:

- **Console:** [http://localhost:5000](http://localhost:5000)
- **Research workbench:** [http://localhost:5000/research](http://localhost:5000/research)
- **Batch upload:** [http://localhost:5000/upload](http://localhost:5000/upload)

Upload a CIC-IDS-2017-format CSV to explore batch analysis. Raw datasets and sample CSVs are not versioned because of size and licensing; point the app at your own local copy. Live packet capture stays disabled unless `ENABLE_LOCAL_CAPTURE=true` is explicitly set.

### Local container run

```bash
cp .env.example .env
docker compose up --build
```

The included Dockerfile and Compose file are for a **loopback-bound local demo**, not a production deployment. The container runs as a non-root user and does not receive packet-capture capabilities. Do not mount customer data or expose this configuration publicly.

### Optional integrations

| Setting | Purpose |
| --- | --- |
| `ABUSEIPDB_API_KEY` | Optional reputation lookups for eligible public IPs |
| `ENABLE_LOCAL_CAPTURE` | Enables the local packet-capture adapter |
| `NETSHIELD_CAPTURE_INTERFACE` | Selects the capture interface |
| `NETSHIELD_DEMO_STREAM` | Emits synthetic fixtures for demos only |
| `AUTH_REQUIRED` | Enables authentication and the production artifact gate |

Full configuration and operational notes: [LIVE_CAPTURE_OPERATIONS.md](docs/LIVE_CAPTURE_OPERATIONS.md) and [OPERATIONS_RUNBOOK.md](docs/OPERATIONS_RUNBOOK.md).

---

## 🧪 Testing

```bash
# Python suite
python -m pytest tests -q

# Go collector
cd capture
go test ./...
cd ..

# Repository security gates
python scripts/secret_scan.py
python scripts/deployment_check.py
```

The CI workflow in `.github/workflows/security.yml` runs the Python suite, a secret scan, the model registry/deployment gate, `pip-audit`, a Docker build, a Trivy image scan, and the S8 release gate.

---

## 📁 Repository Map

```text
network-anomaly-detection/
├── app.py                     # Flask app: console, research workbench, API
├── live_capture.py            # Optional Python capture adapter
├── pcap_parser.py             # PCAP/CSV flow parsing
├── feature_mapper.py          # Schema mapping to the model feature order
├── models/                    # Serving bundle, registry, metrics, manifests
├── training/                  # Training, audit, benchmark, SHAP pipelines
├── scripts/                   # Evaluation, gates, drift, release tooling
├── monitoring/                # Prometheus metrics and Grafana dashboard
├── capture/                   # Go live-capture collector
├── extension/                 # Browser extension prototype
├── templates/ static/         # Operator console and workbench UI
├── tests/                     # Python and frontend tests
├── docs/                      # Protocols, reports, runbooks, claim matrix
├── deploy/ migrations/        # Deployment and database migration assets
└── .github/workflows/         # CI security and test workflow
```

Model artifacts are local or registry-managed. The serving bundle and registry are included so a clone can reproduce the documented operating point; larger per-seed experiment bundles are regenerable and gitignored. See [models/README.md](models/README.md).

---

## 📚 Documentation

| Area | Document |
| --- | --- |
| Scope and claims | [SCOPE_AND_CLAIMS.md](docs/SCOPE_AND_CLAIMS.md) • [CLAIM_EVIDENCE_MATRIX.md](docs/CLAIM_EVIDENCE_MATRIX.md) |
| Model and evaluation | [MODEL_CARD.md](docs/MODEL_CARD.md) • [EVALUATION_PROTOCOL_V2.md](docs/EVALUATION_PROTOCOL_V2.md) |
| Benchmarks | [BENCHMARK_RESULTS.md](docs/BENCHMARK_RESULTS.md) • [BASELINE_RESULTS_V2.md](docs/BASELINE_RESULTS_V2.md) |
| Prevalence and cost | [PREVALENCE_EVAL.md](docs/PREVALENCE_EVAL.md) • [COST_MODEL_AND_RELEASE_GATE.md](docs/COST_MODEL_AND_RELEASE_GATE.md) |
| Cross-dataset transfer | [CROSS_DATASET.md](docs/CROSS_DATASET.md) • [CROSS_DATASET_MAPPING.md](docs/CROSS_DATASET_MAPPING.md) |
| Features and labels | [PORTABLE_FEATURES.md](docs/PORTABLE_FEATURES.md) • [LABEL_POLICY.md](docs/LABEL_POLICY.md) |
| Operations | [OPERATIONS_RUNBOOK.md](docs/OPERATIONS_RUNBOOK.md) • [INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md) |
| Security | [SECURITY_AND_COMPLIANCE.md](docs/SECURITY_AND_COMPLIANCE.md) • [PRODUCT_BOUNDARY_AND_THREAT_MODEL.md](docs/PRODUCT_BOUNDARY_AND_THREAT_MODEL.md) |
| Tenancy and access | [TENANCY_AND_ACCESS_CONTROL.md](docs/TENANCY_AND_ACCESS_CONTROL.md) |
| Phase status | [PHASE_STATUS.md](docs/PHASE_STATUS.md) |

---

## ⚠️ Limitations and Responsible Use

- **Not a general NIDS.** The frozen scope is volumetric and scanning behavior. Botnet, web attacks, infiltration, zero-day, and arbitrary novel attacks are out of scope.
- **Live accuracy is unvalidated.** Offline benchmark results do not transfer automatically to live capture, and the live BPF path drops ICMP and IPv6 while the upload path keeps them.
- **Benchmark prevalence is unrealistic.** At 25.05% positives the model looks strong; at 0.1% prevalence precision falls sharply.
- **Cross-dataset transfer is negative.** CIC-IDS-2018 and UNSW-NB15 do not reproduce the CIC-IDS-2017 operating point. The frozen threshold emits zero alerts on both.
- **The serving model is uncalibrated.** The console deliberately shows no confidence percentage.
- **Console labels are model predictions, not ground truth.**
- **No containment.** NetShield does not block hosts, change firewalls, or execute response actions.
- **Do not use as a production intrusion-prevention system.** Use it for education, experimentation, and controlled lab work.

---

<div align="center">

## 🤝 Let's Connect

<a href="https://github.com/coderv1304">
<img src="https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github&logoColor=white"/>
</a>
<a href="https://www.linkedin.com/in/varun-nair-019574400">
<img src="https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=for-the-badge&logo=linkedin&logoColor=white"/>
</a>
<a href="mailto:coderv1304@gmail.com">
<img src="https://img.shields.io/badge/Email-Contact%20Me-D14836?style=for-the-badge&logo=gmail&logoColor=white"/>
</a>
<a href="https://varun-portfolio-rouge.vercel.app/">
<img src="https://img.shields.io/badge/Portfolio-Visit-8E54E9?style=for-the-badge&logo=vercel&logoColor=white"/>
</a>

<br/><br/>

**Flow-based detection. Reproducible evaluation. Honest results.**

*Measure the gap. Document the failure. Improve the evidence.*

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:8E54E9,100:4B6CB7&height=110&section=footer" width="100%"/>

</div>
