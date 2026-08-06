<div align="center">

# 🛡️ AI-Driven Network Traffic Anomaly Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.org/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![CI/CD](https://github.com/your-username/network-anomaly-detection/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/network-anomaly-detection/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

*A full-stack machine learning application that classifies network flows into benign or 14 attack types in real time.*

[Key Features](#-features) • [Architecture](#-system-architecture) • [Technology Stack](#-technology-stack) • [Getting Started](#-installation--setup) • [Usage](#-usage) • [Roadmap](#-devsecops--aiops-roadmap-future)

</div>

---

## 📌 Overview

This project demonstrates a **production-oriented AI-powered Intrusion Detection System (IDS)**. Driven by a **Random Forest classifier** trained on the benchmark **CIC-IDS-2017 dataset**, the system analyzes 79 statistical network flow attributes to flag malicious traffic instantly.

While built as an academic/research project, it is designed with **operational readiness** in mind: fully containerized, CI/CD-integrated, and ready for **DevSecOps** and **AIOps** extensions.

> [!NOTE]
> **Core Novelty & Highlights:**
> - **Gold Standard Benchmark:** Built on the CIC-IDS-2017 dataset for high-accuracy threat recognition.
> - **Multi-Class Detection:** Identifies 14 specific attack types beyond simple binary classification.
> - **Interactive Interfaces:** Features both batch CSV analysis and a live streaming WebSocket dashboard.
> - **Wi-Fi Simulation Engine:** Includes a live traffic simulator to feed captured/replayed flows directly into the inference model.
> - **Low-Latency Inference:** Processed in < 1 ms per flow, making real-time monitoring viable.

---

## ✨ Features

- 📊 **Batch Analysis:** Upload CSV flow capture files for instant classification accompanied by interactive donut chart visualizations.
- ⚡ **Live WebSocket Dashboard:** Real-time throughput metrics, streaming line charts, dynamic threat gauges, and automated alerting panels.
- 📡 **Wi-Fi Traffic Simulator:** Replay pre-recorded dataset CSVs to emulate live network capture feeds seamlessly.
- 🎨 **Responsive Glassmorphism UI:** Modern CSS frontend featuring dynamic theme persistence (Dark/Light mode via `localStorage`).
- 🐳 **Container-Ready:** Includes optimized `Dockerfile` and `docker-compose.yml` configurations for effortless deployment.
- 🔒 **CI/CD Pipeline:** Integrated GitHub Actions workflow covering linting, SAST security scans (`bandit`), and dependency audit checks.
- 👁️ **Model Observability Ready:** Pre-structured modules for tracking data drift and explainability (SHAP).

---

## 📐 System Architecture

### Architecture Diagram

```mermaid
![Uploading Screenshot_2026-08-06-11-01-46-109_com.android.chrome-edit.jpg…]()
