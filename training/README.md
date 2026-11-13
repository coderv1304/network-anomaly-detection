# Model Training & ML Rigor (`training/`)

This directory houses the leak-free scikit-learn training pipelines, dataset audit tools, baseline benchmarks, and SHAP explainability for CIC-IDS-2017.

## Modules

### 1. `preprocessor.py`
Provides `FlowSanitizer` and `build_leak_free_pipeline()`:
- Encapsulates `SimpleImputer`, `StandardScaler`, and the classifier inside an `sklearn.pipeline.Pipeline`.
- Fits imputation statistics and scaling parameters **only on the training partition**; this prevents preprocessing leakage but does not prevent all possible dataset or split leakage.
- Enforces deterministic feature ordering and strips non-generalizable network identifiers (`Flow ID`, IP addresses, `Timestamp`).

### 2. `evaluate.py`
Evaluation engine computing:
- **Macro-F1** and Weighted-F1 across all traffic classes.
- **Per-class Precision, Recall, and F1-score**, including explicit zero-support rows.
- **Per-class PR-AUC / average precision** for classes with model probability outputs.
- Binary attack-versus-benign PR-AUC, ROC-AUC, and FPR at 95% and 99% TPR when both test groups are represented.
- Multiclass Brier score and 10-bin expected calibration error (diagnostics, not proof that probabilities are calibrated).
- Fixed-vocabulary normalized and unnormalized confusion matrices; test-only labels are retained as unseen.

### 3. `audit_dataset.py`
Automated dataset hygiene audit based on the critique by **Engelen et al. (2021)**:
```bash
python training/audit_dataset.py --data-dir data/samples --output docs/DATASET_AUDIT.md
```
Audits duplicate flow records, infinite/NaN values, negative/zero durations, and class imbalance.

### 4. `train_pipeline.py`
Trains models with full pipeline encapsulation and Day-based or stratified splits:
```bash
# Temporal holdout (Train: Mon-Tue, validation: Wed, final test: Thu-Fri)
python training/train_pipeline.py --data-dir data --split-mode day_based --model rf

# Stratified Split (on sample data)
python training/train_pipeline.py --data-dir data/samples --split-mode random --model rf
```
Fits preprocessing and label vocabulary on training rows only. The day-based protocol trains on Monday/Tuesday, selects the attack threshold on Wednesday under the requested `--max-fpr` budget (default 1%), and reports the frozen threshold on Thursday/Friday. Requires all configured CIC day files and records unseen validation/test labels explicitly. Random row splits remain exploratory and are labeled as such. Saves a versioned model bundle, SHA-256 artifact manifest, metrics JSON, and a `models/model_bundle.pkl` convenience copy for local inference. The convenience copy is not the serving default: the app resolves the registry-active artifact (currently `models/model_bundle_rf_day_based_seed42.pkl`). Production should use the versioned bundle and the hash from its manifest. This protocol does not establish performance on another dataset, network, or capture tool.

Optional imbalance settings are explicit model variants, for example `--class-weight balanced_subsample` for Random Forest. They are included in metrics/manifests and versioned artifact names; compare them on the same frozen split before selecting a candidate.

For open-set research, `--task binary_attack` maps every non-`BENIGN` training label to `ATTACK`. It retains original family labels in evaluation metadata and reports family-level recall at the validation-selected threshold. This is an experimental detection mode; it does not identify attack families and is not the application's serving model. Run it on the same temporal split and compare against the multiclass baseline before making efficacy claims.

### 5. `benchmark_baselines.py`
Runs multi-model baselines across random seeds (Logistic Regression, Random Forest, LightGBM, and Isolation Forest):
```bash
python training/benchmark_baselines.py --data-dir data/samples --seeds 3 --output docs/BENCHMARK_RESULTS.md
```
Measures training duration and per-sample latency (in µs) to establish empirical benchmarks.

### 6. `feature_parity.py`
Compares a reference flow CSV with the Scapy upload parser on the same capture. This is the reference-CSV path, not a live-path test; the PyFlowMeter live path is measured by `parity_live_capture.py` and reported in `docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md`:
```bash
python training/feature_parity.py --reference-csv path/to/export.csv --pcap path/to/same-capture.pcap --output docs/FEATURE_PARITY_RESULTS.json
```
It pairs only unique bidirectional 5-tuples, reports ambiguous/unmatched keys, feature error distributions, and input hashes. Reused tuples and differing timeout/direction semantics limit coverage; low match coverage makes the numerical parity results incomplete. This is feature-extractor evidence, not detection-quality evidence.

### 6a. `parity_live_capture.py`
Builds a deterministic capture, runs the PyFlowMeter live session and the Scapy upload parser on the same bytes, and reports flow coverage, unmatched/ambiguous flows, per-feature error distributions, malformed-input behaviour, and the upload-parser regression lists (currently empty because all 80 features are produced):
```bash
venv/Scripts/python.exe training/parity_live_capture.py
```

### 7. `explainability_shap.py`
Calculates feature importance and TreeSHAP values, and selects the optimal reduced feature set (15–20 features) for real-time packet extraction in Go:
```bash
python training/explainability_shap.py --data-dir data/samples --n-features 18 --output-json models/selected_features.json
```
Generates detailed explainability documentation in `docs/FEATURE_SELECTION_SHAP.md`.

### 8. `create_samples.py`
Generates stratified sample evaluation CSVs from the multi-gigabyte raw CIC-IDS-2017 files:
```bash
python training/create_samples.py --n-per-class 2000
```
