# Model Artifacts Directory

This directory stores trained scikit-learn models and preprocessing artifacts:
- `random_forest.pkl` (~73 MB) — Trained Random Forest classifier
- `scaler.pkl` (~4.6 KB) — `StandardScaler` feature transformer
- `label_encoder.pkl` (~800 B) — Multi-class target label encoder
- `feature_names.pkl` (~1.5 KB) — Feature order specification

> **Storage Notice**: Binary `.pkl` models exceeding 50 MB are not tracked directly in plain Git to prevent repository bloat. Track them with [Git LFS](https://git-lfs.github.com/) or download from GitHub Release tags.

For architecture details, training parameters, performance metrics, and known dataset limitations, refer to:
👉 [docs/MODEL_CARD.md](../docs/MODEL_CARD.md)
