# Model Training & ML Rigor (`training/`)

This directory houses the leak-free scikit-learn training pipelines, dataset audit tools, baseline benchmarks, and SHAP explainability for CIC-IDS-2017.

## Modules

### 1. `preprocessor.py`
Provides `FlowSanitizer` and `build_leak_free_pipeline()`:
- Encapsulates `SimpleImputer`, `StandardScaler`, and the classifier inside an `sklearn.pipeline.Pipeline`.
- Guarantees that imputation statistics and scaling parameters are fitted **strictly on training splits**, completely eliminating data leakage.
- Enforces deterministic feature ordering and strips non-generalizable network identifiers (`Flow ID`, IP addresses, `Timestamp`).

### 2. `evaluate.py`
Evaluation engine computing:
- **Macro-F1** and Weighted-F1 across all traffic classes.
- **Per-class Precision, Recall, and F1-score**.
- **PR-AUC** and **ROC-AUC**.
- **False Positive Rate (FPR)** at operational detection rates (e.g., FPR @ 95% TPR and FPR @ 99% TPR).
- Normalized and unnormalized confusion matrices.

### 3. `audit_dataset.py`
Automated dataset hygiene audit based on the critique by **Engelen et al. (2021)**:
```bash
python training/audit_dataset.py --data-dir data/samples --output docs/DATASET_AUDIT.md
```
Audits duplicate flow records, infinite/NaN values, negative/zero durations, and class imbalance.

### 4. `train_pipeline.py`
Trains models with full pipeline encapsulation and Day-based or stratified splits:
```bash
# Day-Based Split (Train: Mon-Wed, Test: Thu-Fri)
python training/train_pipeline.py --data-dir data --split-mode day_based --model rf

# Stratified Split (on sample data)
python training/train_pipeline.py --data-dir data/samples --split-mode random --model rf
```
Saves the unified `models/pipeline.pkl` and exports legacy components for seamless backward compatibility with `app.py`.

### 5. `benchmark_baselines.py`
Runs multi-model baselines across random seeds (Logistic Regression, Random Forest, LightGBM, and Isolation Forest):
```bash
python training/benchmark_baselines.py --data-dir data/samples --seeds 3 --output docs/BENCHMARK_RESULTS.md
```
Measures training duration and per-sample latency (in µs) to establish empirical benchmarks.

### 6. `explainability_shap.py`
Calculates feature importance and TreeSHAP values, and selects the optimal reduced feature set (15–20 features) for real-time packet extraction in Go:
```bash
python training/explainability_shap.py --data-dir data/samples --n-features 18 --output-json models/selected_features.json
```
Generates detailed explainability documentation in `docs/FEATURE_SELECTION_SHAP.md`.

### 7. `create_samples.py`
Generates stratified sample evaluation CSVs from the multi-gigabyte raw CIC-IDS-2017 files:
```bash
python training/create_samples.py --n-per-class 2000
```
