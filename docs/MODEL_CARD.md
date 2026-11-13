# Model Card: CIC-IDS-2017 Flow Classification Research Prototype

This card describes the research model and its current evidence. It is not a security certification or a claim of production detection performance.

**Frozen scope:** flow-based detector for volumetric and scanning behavior. Not a general NIDS. Live accuracy is unvalidated. Botnet, web attacks, infiltration, zero-day, and blocking are out of scope. See [`SCOPE_AND_CLAIMS.md`](SCOPE_AND_CLAIMS.md) and the [`CLAIM_EVIDENCE_MATRIX.md`](CLAIM_EVIDENCE_MATRIX.md).

## Model

- **Task:** Supervised multi-class classification of statistical IP flow features into CIC-IDS-2017 labels.
- **Estimator:** Random Forest (`sklearn.ensemble.RandomForestClassifier`); model artifacts are serialized and must only be loaded from trusted, integrity-checked sources.
- **Intended use:** Offline research and batch analysis of flow records that match the documented feature schema.
- **Out of scope:** Payload inspection, universal zero-day detection, complete NDR coverage, automated containment, or unsupervised anomaly discovery.
- **Input:** The loaded pipeline artifact currently exposes 80 expected statistical flow features. Flow identifiers and labels are not model features; confirm the exact feature list from the artifact used for each run.

## Data and preprocessing

The project uses CIC-IDS-2017 files documented in the repository. The dataset is a controlled capture from 2017 with known quality and labeling limitations; it is not representative evidence for current enterprise networks by itself. Consult [DATASET_AUDIT.md](DATASET_AUDIT.md) and [LITERATURE_SEARCH.md](LITERATURE_SEARCH.md) for provenance and context.

The training workflow in `training/` applies preprocessing inside a scikit-learn pipeline so learned imputation/scaling is fitted on the training partition. Training scripts and the serialized model served by `app.py` are distinct artifacts. Record the model hash, feature schema, training command, seed, dependency versions, and evaluation report together for each release. Do not assume a local pickle corresponds to the benchmark merely because both use a Random Forest.

## Current evidence

The [benchmark report](BENCHMARK_RESULTS.md) documents three random-row seeds on the included sample CSVs. Random Forest macro-F1 is **0.1072 ± 0.0037** and weighted-F1 is **0.7417**. Per-class precision, recall, F1, and PR-AUC plus Brier/ECE diagnostics are reported. This is not a day-holdout or external-environment result and must not be described as production detection quality. FPR at 95% TPR is selected from the test ROC curve post hoc; it is not a validated operational threshold.

The first full-data Monday/Tuesday train, Wednesday validation, Thursday/Friday test experiment is documented in [TEMPORAL_HOLDOUT_RESULTS.md](TEMPORAL_HOLDOUT_RESULTS.md), with three estimator seeds. Macro-F1 was **0.0857** in all three runs; only BENIGN, FTP-Patator, and SSH-Patator were learned, and seven test labels were unseen. At a per-seed threshold selected under a 1% validation FPR budget, test FPR ranged from **0.725% to 6.896%** and binary recall from **46.78% to 57.94%**. This is evidence of temporal/open-set failure and threshold instability, not successful generalization. The serving application now applies the attack-score threshold recorded in the evaluated seed 42 Random Forest bundle and is registered as uncalibrated. See [THRESHOLD_POLICY_V2.md](THRESHOLD_POLICY_V2.md) and [CALIBRATION_V2.md](CALIBRATION_V2.md).

The D2 pipeline audit in [DATA_PIPELINE_AUDIT.md](DATA_PIPELINE_AUDIT.md) found defects that affect every result above: all eight source CSVs carry a duplicate physical `Fwd Header Length` header, Thursday WebAttacks requires `cp1252` and contains 288,602 trailing unlabeled rows, and the partitions contain both within-partition and cross-partition duplicates. Validation contains 252,672 rows from DoS families absent from training, so threshold selection sees families the model never learned. Results produced before these defects were identified are not directly comparable to a future corrected pipeline.

The D3 controlled comparison in [BASELINE_RESULTS_V2.md](BASELINE_RESULTS_V2.md) keeps the frozen split and threshold rule and adds majority, port-memorisation, and ephemeral-destination rule baselines. Random Forest has the best PR-AUC (**0.7472 ± 0.0749**) but a five-seed test FPR of **4.11% ± 3.27%** and Bot recall of **0.94% ± 0.82%**. No baseline passes all predeclared gates, so the 9/10 detection claim remains unsupported.

The serving artifact is the same evaluated three-class Random Forest bundle (`models/model_bundle_rf_day_based_seed42.pkl`, registry-active `serving-rf-day-based-seed42-v1`). It applies the recorded attack-score threshold and is registered as uncalibrated because the available isotonic artifact fails the 0.05 ECE gate. See [scope and claims](SCOPE_AND_CLAIMS.md) for the artifact hashes, label space, and threshold policy, and [model registry and deployment](MODEL_REGISTRY_AND_DEPLOYMENT.md) for the active version, hash/schema pins, and deployment gate.

## Reliability and serving evidence

The S2 work in [SLO_AND_ONCALL.md](SLO_AND_ONCALL.md) defines ingest availability, ingest latency, console latency, and alert-delivery SLOs and instruments them with Prometheus metrics, JSON request logs, stage timings, rate limits, and bounded ingest admission. The latest 20 flows/s run measured p95 **164.9 ms** with 100% success, so the local ingest-latency SLO passes after batch inference, removal of per-row refresh queries, and SQLite WAL tuning. The pre-optimization sweep first produced HTTP 503 backpressure at **50 flows/s** (batch size 10), and capacity above 20 flows/s was not re-measured. The service is not production ready and has no staffed on-call rota.

The P1 audit in [FEATURE_PARITY_LIVE_CAPTURE_V2.md](FEATURE_PARITY_LIVE_CAPTURE_V2.md) compares the PyFlowMeter live path with the Scapy upload parser on one deterministic capture. The live path maps all 80 feature names but drops ICMP and IPv6; the upload path now produces all 80 features with no missing or constant values. Neither path has been compared with a CICFlowMeter row from the same bytes, and no labelled live traffic exists. Live capture is therefore not validated.

The D4 work in [THRESHOLD_POLICY_V2.md](THRESHOLD_POLICY_V2.md) selects a global threshold on Wednesday validation and applies it unchanged to Thursday and Friday across seeds 42–46. The validation FPR budget does not transfer: five-seed mean test FPR is 4.11% ± 3.27%, ranging from 0.73% to 7.85%, with per-day breaches. D5 in [CALIBRATION_V2.md](CALIBRATION_V2.md) fits temperature scaling and isotonic regression on validation only. Isotonic calibration lowers Brier score and ECE relative to uncalibrated, but held-out ECE remains high and varies by day and family, and calibration does not change the ranking or the alert budget. The served Random Forest is registered as uncalibrated because the available isotonic artifact fails the ECE gate, so no confidence percentage is shown.

## Limitations and safe use

1. CIC-IDS-2017 has documented labeling, flow-generation, and synthetic-traffic limitations, and the D2 audit confirms duplicate headers, encoding defects, trailing unlabeled rows, and duplicate flows in this repository's copies.
2. Offline feature extraction and this project's capture/parser paths differ. The upload parser now produces 80/80 features, but the two Python extractors still disagree on some rate, inter-arrival, and flag features, and the PyFlowMeter live path drops ICMP and IPv6.
3. Performance on modern networks and independent datasets has not been established.
4. A model classification is a prediction, not a verified incident. Human review is required before operational decisions.
5. Do not use this prototype for production blocking or as the sole security control.
6. The single-process service passes the 20 flows/s ingest-latency SLO once (p95 164.9 ms), but bounded admission produced HTTP 503 at 50 flows/s in the pre-optimization sweep and higher-rate capacity is unmeasured.

## Next evaluation gates

Follow the [evaluation protocol](EVALUATION_PROTOCOL.md). The existing CIC-IDS-2017 weekday result is development evidence and is not a blind final test for future model choices. Evaluate known-family temporal classification and unseen-family attack flagging separately on fresh, class-covered data; report fixed alert budgets and per-family support; then validate feature parity and replicate on an independent dataset. Include exact commands and artifact hashes in each report.
