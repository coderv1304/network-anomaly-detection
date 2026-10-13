# 🚨 Network Anomaly Detection

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](#tech-stack)
[![Go: 1.22+](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](#capture-pipeline)
[![Status: Phase 0 Foundation](https://img.shields.io/badge/Status-Phase%200%20(Foundation)-orange.svg)](#project-roadmap)

A machine learning and systems engineering project for network traffic anomaly detection. Built to investigate the generalization limits, feature parity, and real-time capture trade-offs of ML-based Intrusion Detection Systems (NIDS) using the **CIC-IDS-2017** benchmark and a high-performance **Go** packet capture pipeline.

> **GitHub Repository Metadata:**
> - **Description:** *"End-to-end network intrusion detection investigating ML generalization, CIC-IDS-2017 feature parity, and real-time Go packet flow capture."*
> - **Topics:** `network-security`, `intrusion-detection`, `cicids2017`, `machine-learning`, `random-forest`, `gopacket`, `anomaly-detection`, `cybersecurity`

---

## 📌 Problem & Scope

Supervised ML models trained on synthetic benchmark datasets often achieve misleadingly high accuracy (>99%) under random row splits, but fail on live enterprise traffic due to:
1. **Data Leakage & Temporal Invalidation:** Flows from identical TCP sessions appearing in both train and test splits.
2. **Benchmark Artifacts & Label Noise:** Known labeling discrepancies in CIC-IDS-2017 ([Engelen et al., 2021](https://doi.org/10.1016/j.cose.2021.102371)).
3. **Feature Parity Mismatch:** Differences between offline flow extractors (e.g., Java `CICFlowMeter`) and real-time network sniffers.

This project addresses these challenges with a leak-free ML evaluation pipeline, rigorous day-based evaluation, and a custom Go flow-assembler with verified mathematical feature parity.

---

## 🏗️ Repository Architecture

The codebase follows a modular separation of concerns between packet capture, training, serving, and documentation:

```text
network-anomaly-detection/
├── capture/                  # High-performance Go packet sniffer & 5-tuple flow assembler
│   └── README.md             # Go architecture, gopacket, and drop accounting
├── inference/                # Python serving layer (REST & WebSocket inference API)
│   └── README.md             # Serving architecture, ONNX export, and schema validation
├── training/                 # Offline ML pipelines, dataset audit, and baseline experiments
│   ├── create_samples.py     # Reproducible sampling from raw CIC-IDS-2017 datasets
│   ├── relocate_samples.py   # Utility to migrate root sample CSVs into data/samples/
│   └── README.md             # ML rigor, day-based split strategy, and SHAP ablation
├── deploy/                   # Containerization and orchestration
│   └── README.md             # Multi-stage Docker, Compose, and Kubernetes specs
├── docs/                     # Scientific & engineering documentation
│   ├── MODEL_CARD.md         # Formal model card (Mitchell et al. 2019 framework)
│   ├── LITERATURE_SEARCH.md  # Problem statement & related-work comparison matrix
│   └── srs/                  # Software Requirements Specification (SRS) generator
├── data/
│   ├── samples/              # Curated small evaluation CSVs for testing and demo
│   └── README.md             # Download instructions for raw multi-GB CIC-IDS-2017 CSVs
├── models/                   # Serialized model artifacts (tracked via Git LFS / releases)
│   └── README.md             # Artifact inventory and loading specifications
├── tests/                    # Automated test suite
│   ├── test_preprocessing.py # Preprocessing & NaN/Inf sanitization tests
│   └── README.md             # Pytest instructions
├── static/                   # Dashboard CSS, JavaScript, and assets
├── templates/                # Dashboard HTML templates
├── app.py                    # Current Flask web application & prototype capture backend
├── train_model.py            # Baseline model training script
├── feature_mapper.py         # Live-to-model feature translation layer
├── requirements.txt          # Python dependencies
├── LICENSE                   # MIT License
└── README.md
```

---

## 🗺️ Project Roadmap & Execution Plan

| Phase | Focus Area | Status | Key Deliverables |
| :--- | :--- | :--- | :--- |
| **Phase 0** | **Foundation** | 🟡 *In Progress* | Honesty pass, clean layout (`capture/`, `inference/`, etc.), Model Card, literature matrix, sample dataset isolation. |
| **Phase 1** | **ML Rigor** | ⚪ *Planned* | Leak-free `sklearn.pipeline`, day-based temporal splits, Macro-F1 / PR-AUC, Engelen et al. dataset audit, SHAP feature selection. |
| **Phase 2** | **Go Capture Pipeline** | ⚪ *Planned* | `gopacket` 5-tuple flow table, bounded queues with drop accounting, 15–20 reduced feature extractor, CICFlowMeter parity test. |
| **Phase 3** | **Engineering Signals** | ⚪ *Planned* | Multi-stage Dockerfiles, GitHub Actions CI (ruff, pytest, go test -race), Prometheus metrics, security hardening. |
| **Phase 4** | **Empirical Evidence** | ⚪ *Planned* | `tcpreplay` throughput benchmarks, isolated lab with labeled attacks (SYN flood, port scan), drift analysis (PSI/KS). |
| **Phase 5** | **Release & Publication** | ⚪ *Planned* | v1.0 release with Zenodo DOI, reproducible 1-command benchmark, formal technical paper. |

---

## 🛠️ Tech Stack

| Domain | Technologies |
| :--- | :--- |
| **Network Capture** | Go 1.22+, `gopacket`, `libpcap` / `Npcap` |
| **Machine Learning** | Python 3.10+, Scikit-Learn, LightGBM, Pandas, NumPy, Joblib |
| **Serving & Web** | Flask, Flask-SocketIO, Gunicorn (Migrating to FastAPI) |
| **Testing & CI** | `pytest`, `golangci-lint`, GitHub Actions |
| **Metrics & Observability** | Prometheus, Grafana |
| **Persistence** | SQLite, Joblib artifacts, Git LFS |

---

## 🚀 Quickstart (Current Flask Application)

### 1. Prerequisites
- Python 3.10 or higher
- Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/coderv1304/network-anomaly-detection.git
cd network-anomaly-detection

# Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the Dashboard
```bash
python app.py
```
Open your browser at `http://localhost:5000` to access the dashboard and upload sample network flow CSVs from `data/samples/`.

### 4. Run Automated Tests
```bash
pytest tests/ -v
```

---

## 📄 Documentation Links

- **Model Details & Limitations:** [`docs/MODEL_CARD.md`](docs/MODEL_CARD.md)
- **Problem Statement & Related Work:** [`docs/LITERATURE_SEARCH.md`](docs/LITERATURE_SEARCH.md)
- **Go Capture Specification:** [`capture/README.md`](capture/README.md)
- **Training & ML Roadmap:** [`training/README.md`](training/README.md)
- **Software Requirements Specification (SRS):** [`docs/srs/README.md`](docs/srs/README.md)

---

## ⚖️ License & Ethics

- **License:** Released under the [MIT License](LICENSE).
- **Ethics & Security Notice:** Attack generation scripts and test harness tools included in this project must only be executed within private, isolated lab environments or local virtual networks that you own and control.
