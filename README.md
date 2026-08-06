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

<div align="center" style="margin: 20px 0;">

<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 850 480" width="100%" height="100%" style="background-color: #0d1117; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <defs>
    <!-- Gradients -->
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0d1117" />
      <stop offset="100%" stop-color="#161b22" />
    </linearGradient>
    
    <linearGradient id="clientGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1f6feb" />
      <stop offset="100%" stop-color="#1158c7" />
    </linearGradient>

    <linearGradient id="flaskGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#238636" />
      <stop offset="100%" stop-color="#2ea043" />
    </linearGradient>

    <linearGradient id="pipeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#8957e5" />
      <stop offset="100%" stop-color="#6e40c9" />
    </linearGradient>

    <linearGradient id="modelGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#d29922" />
      <stop offset="100%" stop-color="#bb8009" />
    </linearGradient>

    <linearGradient id="responseGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#da3633" />
      <stop offset="100%" stop-color="#b62324" />
    </linearGradient>

    <!-- Filters & Shadows -->
    <filter id="dropShadow" x="-10%" y="-10%" width="120%" height="120%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.4"/>
    </filter>

    <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#58a6ff" />
    </marker>
    <marker id="arrow-green" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#3fb950" />
    </marker>
  </defs>

  <!-- Background Base -->
  <rect width="850" height="480" fill="url(#bgGrad)" rx="12" stroke="#30363d" stroke-width="1"/>

  <!-- Grid Lines (Subtle) -->
  <g opacity="0.05" stroke="#ffffff" stroke-width="1">
    <line x1="0" y1="60" x2="850" y2="60" />
    <line x1="0" y1="120" x2="850" y2="120" />
    <line x1="0" y1="180" x2="850" y2="180" />
    <line x1="0" y1="240" x2="850" y2="240" />
    <line x1="0" y1="300" x2="850" y2="300" />
    <line x1="0" y1="360" x2="850" y2="360" />
    <line x1="0" y1="420" x2="850" y2="420" />
  </g>

  <!-- Title Banner -->
  <text x="425" y="38" text-anchor="middle" fill="#f0f6fc" font-size="18" font-weight="700" letter-spacing="0.5">SYSTEM ARCHITECTURE & DATA FLOW</text>

  <!-- System Boundary Box -->
  <rect x="220" y="70" width="600" height="380" fill="#161b22" rx="10" stroke="#30363d" stroke-width="1.5" stroke-dasharray="6,6" />
  <text x="235" y="95" fill="#8b949e" font-size="12" font-weight="600" letter-spacing="1">FLASK BACKEND &amp; INFERENCE ENGINE</text>

  <!-- 1. CLIENT / USER -->
  <g transform="translate(30, 150)" filter="url(#dropShadow)">
    <rect width="150" height="220" fill="#161b22" rx="8" stroke="#30363d" stroke-width="1.5"/>
    <rect width="150" height="36" fill="url(#clientGrad)" rx="8" />
    <!-- Fix rx top corners -->
    <rect y="20" width="150" height="16" fill="url(#clientGrad)"/>
    <text x="75" y="23" text-anchor="middle" fill="#ffffff" font-size="13" font-weight="700">Client / Browser</text>
    
    <!-- Client Content -->
    <rect x="15" y="55" width="120" height="40" fill="#21262d" rx="5" stroke="#30363d"/>
    <text x="75" y="72" text-anchor="middle" fill="#c9d1d9" font-size="11" font-weight="600">CSV Upload</text>
    <text x="75" y="87" text-anchor="middle" fill="#8b949e" font-size="9">(CIC-IDS-2017)</text>

    <rect x="15" y="105" width="120" height="40" fill="#21262d" rx="5" stroke="#30363d"/>
    <text x="75" y="122" text-anchor="middle" fill="#c9d1d9" font-size="11" font-weight="600">Web UI (index.html)</text>
    <text x="75" y="137" text-anchor="middle" fill="#8b949e" font-size="9">Drag &amp; Drop Interface</text>

    <rect x="15" y="155" width="120" height="50" fill="#21262d" rx="5" stroke="#30363d"/>
    <text x="75" y="173" text-anchor="middle" fill="#c9d1d9" font-size="11" font-weight="600">Dashboard UI</text>
    <text x="75" y="188" text-anchor="middle" fill="#8b949e" font-size="9">Static Template</text>
    <text x="75" y="198" text-anchor="middle" fill="#e3b341" font-size="8 font-weight="bold">(Not Wired Live)</text>
  </g>

  <!-- Flow Arrow 1: Upload CSV -->
  <path d="M 180 200 L 250 200" stroke="#58a6ff" stroke-width="2.5" marker-end="url(#arrow)" />
  <text x="215" y="190" text-anchor="middle" fill="#58a6ff" font-size="10" font-weight="600">POST /predict</text>

  <!-- 2. FLASK APP LAYER -->
  <g transform="translate(255, 130)" filter="url(#dropShadow)">
    <rect width="160" height="260" fill="#161b22" rx="8" stroke="#30363d" stroke-width="1.5"/>
    <rect width="160" height="36" fill="url(#flaskGrad)" rx="8" />
    <rect y="20" width="160" height="16" fill="url(#flaskGrad)"/>
    <text x="80" y="23" text-anchor="middle" fill="#ffffff" font-size="13" font-weight="700">Flask Server (app.py)</text>

    <!-- App Routes -->
    <rect x="12" y="50" width="136" height="32" fill="#21262d" rx="4" stroke="#30363d"/>
    <text x="80" y="70" text-anchor="middle" fill="#7ee787" font-size="10" font-family="monospace">/ (Index Route)</text>

    <rect x="12" y="90" width="136" height="32" fill="#21262d" rx="4" stroke="#30363d"/>
    <text x="80" y="110" text-anchor="middle" fill="#7ee787" font-size="10" font-family="monospace">/dashboard</text>

    <rect x="12" y="130" width="136" height="112" fill="#21262d" rx="4" stroke="#2ea043" stroke-width="1"/>
    <text x="80" y="150" text-anchor="middle" fill="#7ee787" font-size="11" font-weight="700" font-family="monospace">/predict API</text>
    <text x="80" y="170" text-anchor="middle" fill="#c9d1d9" font-size="9">• CSV Stream Reader</text>
    <text x="80" y="186" text-anchor="middle" fill="#c9d1d9" font-size="9">• JSON Formatter</text>
    <text x="80" y="202" text-anchor="middle" fill="#c9d1d9" font-size="9">• Metric Aggregator</text>
    <text x="80" y="226" text-anchor="middle" fill="#8b949e" font-size="8">(Gunicorn WSGI)</text>
  </g>

  <!-- Flow Arrow 2: To Preprocessing -->
  <path d="M 415 260 L 450 260" stroke="#58a6ff" stroke-width="2.5" marker-end="url(#arrow)" />

  <!-- 3. PREPROCESSING PIPELINE -->
  <g transform="translate(455, 130)" filter="url(#dropShadow)">
    <rect width="170" height="260" fill="#161b22" rx="8" stroke="#30363d" stroke-width="1.5"/>
    <rect width="170" height="36" fill="url(#pipeGrad)" rx="8" />
    <rect y="20" width="170" height="16" fill="url(#pipeGrad)"/>
    <text x="85" y="23" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="700">Data Preprocessing</text>

    <g transform="translate(12, 50)">
      <rect width="146" height="36" fill="#21262d" rx="4" stroke="#30363d"/>
      <text x="73" y="18" text-anchor="middle" fill="#d2a8ff" font-size="10" font-weight="600">Encoding Fallback</text>
      <text x="73" y="30" text-anchor="middle" fill="#8b949e" font-size="8">utf-8, latin1, cp1252</text>
    </g>

    <g transform="translate(12, 94)">
      <rect width="146" height="36" fill="#21262d" rx="4" stroke="#30363d"/>
      <text x="73" y="18" text-anchor="middle" fill="#d2a8ff" font-size="10" font-weight="600">Header &amp; Inf Cleaning</text>
      <text x="73" y="30" text-anchor="middle" fill="#8b949e" font-size="8">Strip spaces, replace Inf</text>
    </g>

    <g transform="translate(12, 138)">
      <rect width="146" height="36" fill="#21262d" rx="4" stroke="#30363d"/>
      <text x="73" y="18" text-anchor="middle" fill="#d2a8ff" font-size="10" font-weight="600">Feature Alignment</text>
      <text x="73" y="30" text-anchor="middle" fill="#8b949e" font-size="8">Align with feature_names.pkl</text>
    </g>

    <g transform="translate(12, 182)">
      <rect width="146" height="66" fill="#21262d" rx="4" stroke="#30363d"/>
      <text x="73" y="20" text-anchor="middle" fill="#d2a8ff" font-size="10" font-weight="600">Missing Value Imputation</text>
      <text x="73" y="36" text-anchor="middle" fill="#8b949e" font-size="8">Fill NaN with Medians</text>
      <text x="73" y="52" text-anchor="middle" fill="#d2a8ff" font-size="10" font-weight="600">&amp; Standard Scaling</text>
    </g>
  </g>

  <!-- Flow Arrow 3: To Inference -->
  <path d="M 625 260 L 660 260" stroke="#58a6ff" stroke-width="2.5" marker-end="url(#arrow)" />

  <!-- 4. ML MODEL & ARTIFACTS -->
  <g transform="translate(665, 110)" filter="url(#dropShadow)">
    <rect width="140" height="300" fill="#161b22" rx="8" stroke="#30363d" stroke-width="1.5"/>
    <rect width="140" height="36" fill="url(#modelGrad)" rx="8" />
    <rect y="20" width="140" height="16" fill="url(#modelGrad)"/>
    <text x="70" y="23" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="700">Model Artifacts</text>

    <!-- Artifact Items -->
    <rect x="10" y="48" width="120" height="48" fill="#21262d" rx="4" stroke="#f0883e" stroke-width="1"/>
    <text x="60" y="66" text-anchor="middle" fill="#f0883e" font-size="9" font-weight="700">Random Forest</text>
    <text x="60" y="80" text-anchor="middle" fill="#8b949e" font-size="8">random_forest.pkl</text>

    <rect x="10" y="104" width="120" height="42" fill="#21262d" rx="4" stroke="#30363d"/>
    <text x="60" y="121" text-anchor="middle" fill="#c9d1d9" font-size="9" font-weight="600">StandardScaler</text>
    <text x="60" y="135" text-anchor="middle" fill="#8b949e" font-size="8">scaler.pkl</text>

    <rect x="10" y="154" width="120" height="42" fill="#21262d" rx="4" stroke="#30363d"/>
    <text x="60" y="171" text-anchor="middle" fill="#c9d1d9" font-size="9" font-weight="600">LabelEncoder</text>
    <text x="60" y="185" text-anchor="middle" fill="#8b949e" font-size="8">label_encoder.pkl</text>

    <rect x="10" y="204" width="120" height="42" fill="#21262d" rx="4" stroke="#30363d"/>
    <text x="60" y="221" text-anchor="middle" fill="#c9d1d9" font-size="9" font-weight="600">Feature Names</text>
    <text x="60" y="235" text-anchor="middle" fill="#8b949e" font-size="8">feature_names.pkl</text>

    <text x="70" y="275" text-anchor="middle" fill="#79c0ff" font-size="9" font-weight="600">14 Attack Types</text>
    <text x="70" y="288" text-anchor="middle" fill="#79c0ff" font-size="9" font-weight="600">+ BENIGN</text>
  </g>

  <!-- Return Flow Arrow (JSON Response) -->
  <path d="M 335 390 L 335 430 L 105 430 L 105 375" fill="none" stroke="#3fb950" stroke-width="2" stroke-dasharray="4,4" marker-end="url(#arrow-green)"/>
  <rect x="160" y="418" width="130" height="22" fill="#0d1117" rx="4" stroke="#2ea043" stroke-width="1"/>
  <text x="225" y="433" text-anchor="middle" fill="#3fb950" font-size="9" font-weight="700">JSON Prediction Breakdown</text>

</svg>

</div>

`/dashboard` renders a static template with no data source behind it. There is currently no separate simulator, capture agent, or WebSocket/streaming layer — everything else runs through the single request/response cycle: browser → Flask route → preprocessing → loaded model artifacts → JSON response.

---

## 🧰 Technology Stack

| Layer        | Technology (from `requirements.txt`)                               |
| ------------ | ------------------------------------------------------------------ |
| **Backend**  | Python, Flask 2.3.2, pandas 2.2.3, numpy 2.1.3, scikit-learn 1.5.2, joblib 1.4.2 |
| **Serving**  | gunicorn (via `Procfile`)                                          |
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
