<div align="center">

# 🛡️ AI-Driven Network Traffic Anomaly Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.org/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

*A Flask web application that classifies uploaded network flow CSVs as benign or one of 14 attack types using a Random Forest model.*

[Overview](#-overview) • [Features](#-features) • [Architecture](#-system-architecture) • [Technology Stack](#-technology-stack) • [Getting Started](#-installation--setup) • [Usage](#-usage) • [Roadmap](#-roadmap--not-yet-implemented)

</div>

---

## 📌 Overview

This project is a **Random Forest–based Intrusion Detection System (IDS)** trained on the **CIC-IDS-2017 dataset**. It exposes a simple Flask web app where a user uploads a network-flow CSV and gets back a classification breakdown (benign vs. each attack type) in JSON.

The scope of what's currently implemented is intentionally modest — a working training pipeline and a working batch-prediction web endpoint. Some ambitions for the project (live streaming dashboard, containerization, CI/CD, DevSecOps/AIOps tooling) are **not yet built** and are tracked honestly in the [Roadmap](#-roadmap--not-yet-implemented) section rather than presented as existing features.

---

## ✨ Features

What's actually working today:

- 📊 **Batch CSV Analysis** — Upload a network-flow CSV via `/predict`; the app cleans it, aligns columns to the training feature set, scales it, and returns a JSON summary: total flows, benign count, attack count, and a per-attack-type breakdown.
- 🧹 **Robust CSV Handling** — Tries multiple encodings (`utf-8`, `latin1`, `ISO-8859-1`, `cp1252`), strips whitespace from column headers, replaces `±Inf` with large finite sentinels, and fills `NaN` with column medians — all tuned to known quirks of CIC-IDS-2017 exports.
- 🌲 **Multiclass Detection** — The trained Random Forest distinguishes BENIGN traffic from 14 attack categories (per the CIC-IDS-2017 label set).
- 🏋️ **Reproducible Training Pipeline** (`train_model.py`) — Loads and combines multiple CIC-IDS-2017 CSVs, downcast-optimizes memory, drops duplicates/NaNs/Infs, fits a `RandomForestClassifier`, and saves the model + scaler + label encoder + feature list to `models/`.
- 🖥️ **Upload Page & Dashboard Route** — `index.html` (upload UI) and a `/dashboard` route/template exist in the app, though the dashboard currently renders a static template with no live data feed wired up (see Roadmap).
- 🚀 **Deployable via Gunicorn** — `Procfile` is configured for a `gunicorn app:app` style deploy (e.g., Heroku-type platforms).

---

## 📐 System Architecture

This reflects what's actually in `app.py` today — a single Flask process, no WebSocket layer, no live traffic ingestion.

```
┌──────────────────┐
│   User Browser    │
└─────────┬─────────┘
          │ HTTP (GET / POST)
          ▼
┌───────────────────────────┐
│      Flask App (app.py)    │
│  ─────────────────────────│
│  GET  /            → index.html (upload page)
│  GET  /dashboard    → dashboard.html (static template)
│  POST /predict       → CSV upload + classification
└─────────┬──────────────────┘
          │
          ▼
┌────────────────────────────┐
│   Preprocessing (in-request)│
│  - encoding fallback         │
│  - column strip/clean        │
│  - inf/NaN handling          │
│  - column alignment          │
│  - StandardScaler.transform  │
└─────────┬───────────────────┘
          │
          ▼
┌────────────────────────────┐
│  Loaded Model Artifacts      │
│  (models/*.pkl, loaded once  │
│   at process startup)        │
│  - random_forest.pkl         │
│  - scaler.pkl                │
│  - label_encoder.pkl         │
│  - feature_names.pkl         │
└─────────┬───────────────────┘
          │ predictions
          ▼
┌────────────────────────────┐
│   JSON Response              │
│  { total, benign, attack,    │
│    attack_types: {...} }     │
└────────────────────────────┘
```

There is currently no separate simulator, capture agent, or WebSocket/streaming layer feeding the `/dashboard` route — everything runs through the single request/response cycle above.

---

## 🧰 Technology Stack

| Layer        | Technology (from `requirements.txt`)                         |
| ------------ | -------------------------------------------------------------- |
| **Backend**  | Python, Flask 2.3.2, pandas 2.2.3, numpy 2.1.3, scikit-learn 1.5.2, joblib 1.4.2 |
| **Serving**  | gunicorn (via `Procfile`)                                       |
| **Frontend** | HTML templates (`templates/index.html`, `templates/dashboard.html`), static assets in `static/` |
| **ML Model** | Random Forest (`RandomForestClassifier`, 100 trees), `StandardScaler`, `LabelEncoder` |

No Docker, no CI/CD tooling, no monitoring stack (Prometheus/Grafana), and no experiment-tracking tooling (MLflow) appear in the dependency list or repo — see Roadmap.

---

## 📁 Project Structure

Reflects the actual repository file listing:

```
network-anomaly-detection/
├── app.py                    # Flask web server (index, dashboard, /predict)
├── train_model.py            # Model training pipeline
├── create_and_test.py        # Utility script (present in repo)
├── your_script.py            # Utility script (present in repo)
├── usecase.puml              # PlantUML use-case diagram
├── requirements.txt          # Python dependencies
├── Procfile                  # gunicorn start command
├── network_test_dataset.csv  # Sample/test data
├── test_dataset.csv          # Sample/test data
├── models/                   # Saved ML artifacts
│   ├── random_forest.pkl
│   ├── scaler.pkl
│   ├── label_encoder.pkl
│   └── feature_names.pkl
├── templates/                # HTML templates
│   ├── index.html
│   └── dashboard.html
├── static/                   # CSS/JS assets
├── .gitignore
├── LICENSE                   # MIT
└── README.md
```

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.10+ (repo dependencies were pinned against this)
- pip

### 1. Clone the repository

```bash
git clone https://github.com/coderv1304/network-anomaly-detection.git
cd network-anomaly-detection
```

### 2. Set up a virtual environment

```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Model artifacts

Pre-trained artifacts are expected in `models/` (`random_forest.pkl`, `scaler.pkl`, `label_encoder.pkl`, `feature_names.pkl`). If you need to retrain, see [Training Your Own Model](#-training-your-own-model) below — you'll need to supply your own CIC-IDS-2017 CSVs in a `data/` folder, since raw data is not included in the repo.

### 5. Run the app

```bash
python app.py
```

Then open `http://127.0.0.1:5000`.

---

## 🧪 Usage

### Batch CSV Analysis

1. Go to the home page and upload a network-flow CSV.
2. The `/predict` endpoint cleans, aligns, and scales the data, then returns a JSON response:
   ```json
   {
     "total": 1000,
     "benign": 850,
     "attack": 150,
     "attack_types": { "BENIGN": 850, "DDoS": 90, "PortScan": 60 }
   }
   ```
3. The uploaded CSV must contain the same feature columns the model was trained on (CIC-IDS-2017 schema); `Flow ID`, `Source IP`, `Destination IP`, `Timestamp`, and `Label` columns are dropped automatically if present.

### Dashboard Page

`/dashboard` currently renders a template but is not yet wired to a live data source — see Roadmap.

---

## 🏋️ Training Your Own Model

`train_model.py` trains on a configurable list of CIC-IDS-2017 CSV files:

```python
DATA_FOLDER = "data"
OUTPUT_DIR = "models"
TEST_SIZE = 0.2
N_ESTIMATORS = 100

CSV_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]
```

Run it with:

```bash
python train_model.py
```

The script:
- Loads each CSV with encoding fallback (`utf-8` → `latin1` → `ISO-8859-1` → `cp1252`)
- Downcasts numeric dtypes to reduce memory use
- Drops duplicate rows and any rows with `Inf`/`NaN` values
- Fits a `RandomForestClassifier(n_estimators=100, random_state=42)`
- Saves `random_forest.pkl`, `scaler.pkl`, `label_encoder.pkl`, and `feature_names.pkl` to `models/`

> Accuracy figures depend entirely on which CSV subset you train on — no fixed number is claimed here since it wasn't independently verified against a specific released model file.

---

## 🗺️ Roadmap / Not Yet Implemented

Being explicit about the gap between ambition and current code, so this list only contains things **not present** in the repo right now:

- [ ] Dockerfile / docker-compose for containerized deployment
- [ ] CI/CD pipeline (GitHub Actions: lint, SAST, dependency scanning)
- [ ] Live traffic simulator / real capture ingestion feeding `/dashboard`
- [ ] WebSocket or Socket.IO layer for real-time dashboard updates
- [ ] Automated tests (`tests/` directory)
- [ ] Data drift detection / automated retraining
- [ ] Model registry (e.g., MLflow)
- [ ] Explainability (SHAP) integration
- [ ] Prometheus + Grafana metrics
- [ ] Automated incident alerting (Slack/email webhooks)

---

## 📊 Dataset

This project uses the **CIC-IDS-2017** dataset (Canadian Institute for Cybersecurity). Raw CSV files are not included in the repo due to size — download them from the [official CIC-IDS-2017 page](https://www.unb.ca/cic/datasets/ids-2017.html) and place them in a `data/` folder before running `train_model.py`.

---

## 📄 License

This project is licensed under the MIT License. See `LICENSE` for details.

---

**Built by Varun Nair and Prapti Sharma | Academic Project | 2025–27**
