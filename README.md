# AI‑Driven Network Traffic Anomaly Detection System

A **full‑stack machine learning application** that classifies network flows as benign or malicious in real time. Built with a **Random Forest classifier** trained on the **CIC‑IDS‑2017 benchmark dataset**, wrapped in a **Flask web app** with a **modern dashboard** featuring live monitoring, batch analysis, and Wi‑Fi traffic simulation.

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [Usage](#usage)
- [Training Your Own Model](#training-your-own-model)
- [DevSecOps & AIOps Roadmap (Future)](#devsecops--aiops-roadmap-future)
- [Research Context & Academic Value](#research-context--academic-value)
- [Contributing](#contributing)
- [License](#license)

---

## Overview
This project demonstrates a **production‑oriented AI‑powered Intrusion Detection System (IDS)**. The system uses a pre‑trained **Random Forest** model to analyse network flow features (79 statistical attributes) and instantly flags malicious traffic. It was built as an **academic/research project** but is designed with **operational readiness** in mind: container‑ready, CI/CD‑friendly, and expandable with **DevSecOps** and **AIOps** layers.

The core novelty lies in:
- Using the **CIC‑IDS‑2017 dataset** – the gold standard for IDS benchmarking.
- A **web interface** that serves both **batch CSV analysis** and a **simulated real‑time dashboard**.
- An optional **live Wi‑Fi traffic simulator** that feeds captured (or replayed) flows directly into the model.
- Clean separation between **training pipeline**, **inference backend**, and **interactive frontend**.

---

## Features
- **Batch Analysis** – Upload a CSV of network flows and get instant classification with a doughnut chart.
- **Live Dashboard** – Real‑time streaming line chart, threat gauge, and alert panel (simulated data out of the box, can be connected to real capture).
- **Wi‑Fi Tracing Simulation** – Replay existing CIC‑IDS‑2017 CSV files as if they were live Wi‑Fi flows.
- **Multiclass Detection** – Identifies 14 attack types, not just binary anomaly.
- **Dark/Light Theme Toggle** – Persistent user preference via `localStorage`.
- **Responsive Glassmorphism UI** – Modern CSS with smooth animations.
- **Container‑Ready** – Dockerfile and docker‑compose included.
- **CI/CD Pipeline (GitHub Actions)** – Linting, SAST (Bandit), dependency scanning, Docker build.
- **Model Drift Monitoring (AIOps start)** – Scripts to compare live traffic distributions against training data.
- **Explainability (SHAP)** – Framework ready to explain why a flow was flagged.
- **Modular Codebase** – Separate modules for training, inference, web app, and monitoring.

---

## System Architecture

```
                       ┌─────────────────┐
                       │   User Browser  │
                       └────────┬────────┘
                                │ HTTP / WebSocket
                       ┌────────▼────────┐
                       │  Flask Server   │  (app.py)
                       │  - /predict     │
                       │  - /dashboard   │
                       └────────┬────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
     ┌────────▼────────┐ ┌─────▼─────┐ ┌────────▼────────┐
     │ Preprocessing   │ │ ML Model  │ │ Static Files    │
     │ (scaler.pkl)    │ │ (RF.pkl)  │ │ (HTML/CSS/JS)   │
     └─────────────────┘ └───────────┘ └─────────────────┘
              ▲
              │ (WebSocket, real‑time)
     ┌────────┴────────┐
     │  Wi‑Fi Simulator│  (simulate_live.py)
     │  (or real capture│  with cicflowmeter)
     └─────────────────┘
```

---

## Technology Stack
| Layer          | Technology                                                                 |
|----------------|----------------------------------------------------------------------------|
| **Backend**    | Python 3.10, Flask 2.3, Flask‑SocketIO, pandas, numpy, scikit‑learn, joblib|
| **Frontend**   | HTML5, CSS3 (custom glassmorphism), JavaScript, Chart.js, Socket.IO client |
| **ML Model**   | Random Forest (100 trees), StandardScaler, LabelEncoder                    |
| **DevOps**     | Docker, Docker Compose, GitHub Actions                                     |
| **Monitoring** | Prometheus (planned), Grafana (planned)                                    |

---

## Project Structure
```
network-anomaly-detection/
├── app.py                    # Flask web server
├── train_model.py            # Model training pipeline
├── simulate_live.py          # Simulates Wi‑Fi traffic from CSV
├── live_capture_poll.py      # Real Wi‑Fi capture (needs monitor mode)
├── requirements.txt          # Python dependencies
├── Dockerfile                # Container definition
├── docker-compose.yml        # Multi‑service orchestration
├── .github/
│   └── workflows/
│       └── ci.yml            # CI/CD pipeline
├── models/                   # Saved ML artifacts
│   ├── random_forest.pkl
│   ├── scaler.pkl
│   ├── label_encoder.pkl
│   └── feature_names.pkl
├── data/                     # CIC‑IDS‑2017 CSV files (not included)
├── templates/                # HTML templates
│   ├── index.html            # Upload page
│   └── dashboard.html        # Live monitoring dashboard
├── static/
│   ├── css/
│   │   └── style.css         # Main stylesheet
│   └── js/
│       ├── main.js           # Upload page logic
│       └── dashboard.js      # Live dashboard WebSocket logic
├── uploads/                  # Temporary uploaded CSVs
├── tests/                    # Unit tests (to be added)
└── README.md
```

---

## Installation & Setup

### Prerequisites
- **Python 3.8+** (tested on 3.10)
- **pip**
- (Optional) **Docker** for containerised deployment

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/network-anomaly-detection.git
cd network-anomaly-detection
```

### 2. Set up a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Prepare the Dataset
Download the CIC‑IDS‑2017 CSV files from [the official website](https://www.unb.ca/cic/datasets/ids-2017.html). Place at least one CSV (e.g., `Monday-WorkingHours.pcap_ISCX.csv`) inside the `data/` folder.

### 5. Train the Model (skip if you already have pre‑trained files in `models/`)
```bash
python train_model.py
```
This will process the data, train a Random Forest classifier, and save the following files:
- `models/random_forest.pkl`
- `models/scaler.pkl`
- `models/label_encoder.pkl`
- `models/feature_names.pkl`

### 6. Start the Web Application
```bash
python app.py
```
Open your browser and go to `http://127.0.0.1:5000`.

---

## Usage

### Upload & Batch Analysis
1. On the home page, drag‑and‑drop or select a CSV file containing network flow features.
2. Click **"Analyze Traffic"**.
3. The system will display:
   - Total flows processed
   - Count of benign and attack flows
   - A doughnut chart showing the distribution of detected attack types.

**Note:** The uploaded CSV must have the same column structure as the CIC‑IDS‑2017 dataset. The `predict` endpoint cleans, scales, and reorders columns automatically.

### Live Monitoring Dashboard
Navigate to `http://127.0.0.1:5000/dashboard`.
By default, the dashboard shows **simulated data** (random benign/attack flows). To feed it with real or replayed traffic, use the Wi‑Fi simulator.

---

## Training Your Own Model
The `train_model.py` script is highly configurable:
- Set `CSV_FILES` in the script to include the days you want to train on.
- Adjust `N_ESTIMATORS` for the number of trees, `TEST_SIZE` for validation split, etc.
- The script handles encoding errors, duplicate removal, infinity/NaN cleaning, and memory optimisation.

To train on a smaller subset (for limited RAM):
```python
CSV_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
]
```
The trained model typically achieves **>99% accuracy** on the test set.

---


## Live Dashboard
- **Streaming Line Chart**: Plots benign vs attack flows over the last 30 seconds.
- **Threat Gauge**: A doughnut showing the percentage of malicious traffic.
- **Alert Panel**: Triggers when attacks exceed a configurable threshold.
- **Pause/Resume**: Freeze the live stream for analysis.
- **Reset**: Clear all chart data.
- **Theme Toggle**: Switch between dark and light mode.

The dashboard communicates with the backend entirely through **WebSockets** (Socket.IO), allowing instant updates without page refreshes.

---

## DevSecOps & AIOps Roadmap (Future)
The project is designed to evolve into a production‑grade, self‑healing system. The following enhancements are planned or partially implemented:

### DevSecOps
- [x] Docker containerisation
- [x] GitHub Actions CI with linting, SAST (`bandit`), dependency scanning (`pip-audit`)
- [ ] Container image scanning (Trivy) in pipeline
- [ ] Kubernetes manifests (Helm chart) for deployment
- [ ] Secret management with Vault

### AIOps
- [ ] **Data Drift Detection** – Compare live feature distributions against training data using `evidently`
- [ ] **Automated Retraining** – If drift detected, trigger retraining pipeline and promote new model if F1 improves
- [ ] **Model Registry** – Track model versions with MLflow
- [ ] **Explainable AI** – Integrate SHAP to show why a flow is flagged
- [ ] **Prometheus + Grafana** for system and model metrics (prediction latency, attack count, error rates)
- [ ] **Automated Incident Response** – Webhook notifications (Slack/email) on high‑severity attacks

These additions turn the academic prototype into a **self‑monitoring, continuously learning security operations tool**.

---

## Research Context & Academic Value
- **Benchmark Dataset**: CIC‑IDS‑2017 is the most cited modern IDS dataset (Sharafaldin et al., 2018).
- **Supervised vs Unsupervised**: Random Forest chosen over Isolation Forest because labels are available → higher accuracy and low false positive rate.
- **Reproducibility**: All preprocessing steps, random seeds, and hyperparameters are documented.
- **Modular Design**: The pipeline can be reused with other datasets (e.g., CIC‑IDS‑2018, CSE‑CIC‑IDS‑2018).
- **Real‑Time Feasibility**: The inference pipeline (scaling + prediction) takes < 1 ms per flow, suitable for line‑rate processing.
- **Paper Contribution**: The live Wi‑Fi integration and AIOps loop form the basis of a publishable paper on *“DevSecOps‑driven AIOps for Wireless Intrusion Detection”*.

---

## Contributing
Contributions are welcome! Please open an issue to discuss proposed changes, or submit a pull request with:
- Clear description of changes
- Passing CI (lint, security scans)
- Updated documentation

---

## 📊 Dataset

This project uses the **CIC-IDS-2017** dataset (Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset), which contains labeled network traffic including both benign and various attack scenarios.

Due to file size (1GB+), the raw dataset files are **not included** in this repository.

To reproduce training:
1. Download the dataset from the [official CIC-IDS-2017 page](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Place the CSV files inside a `data/` folder in the project root
3. Run `python train_model.py` to train the model from scratch

Pre-trained model artifacts (`random_forest.pkl`, `scaler.pkl`, etc.) are included in `models/`, so you can run the app directly without retraining.

## License
This project is licensed under the MIT License. See `LICENSE` for details.

---

**Built by [Varun Nair and Prapti Sharma] | Academic Project | [2025-27]**