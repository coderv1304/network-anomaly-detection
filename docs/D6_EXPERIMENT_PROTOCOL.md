# D6 Experiment Protocol — Rare and Unseen Attack Families (Botnet Priority)

**Status:** predeclared before running the new D6 arms. The final-test partition is not used for model, feature, threshold, calibration, or blend selection.
**Date:** 2026-11-10.
**Supersedes:** nothing. This is an additional Track B experiment under [`EVALUATION_PROTOCOL_V2.md`](EVALUATION_PROTOCOL_V2.md).

## Question

Can an attack detector raise recall for attack families that are absent or rare in training, especially **Bot**, without breaking the 1% false-positive gate?

This is an attack-versus-benign question. It is **not** unseen-family identification, zero-day detection, or a claim that Bot flows can be labelled as Bot.

## Frozen data and partitions

The existing day-based CIC-IDS-2017 partition is reused unchanged:

| Partition | Files | Rows | Purpose |
| --- | --- | ---: | --- |
| Train | Monday + Tuesday | 975,789 | Fit preprocessing, model, and augmentation |
| Validation | Wednesday | 692,686 | Select threshold, calibration, and hybrid blend only |
| Final test | Thursday + Friday | 1,162,065 | Report once; no tuning |

Training labels are only `BENIGN`, `FTP-Patator`, and `SSH-Patator`. Validation adds DoS families. The final test adds `Bot`, `DDoS`, `PortScan`, `Infiltration`, and three Web Attack families. Therefore **every final-test attack family is unseen in training**, and Bot is also unseen in validation. This is the intended Track B condition, not an accident.

Source file hashes and the 80-feature schema are recorded in [`DATA_PIPELINE_AUDIT.md`](DATA_PIPELINE_AUDIT.md) and [`EVIDENCE_PACKAGE.md`](EVIDENCE_PACKAGE.md). The feature schema is `cic-ids-2017-80f-45cd75ce849b`.

### Resource deviation (declared)

The full training partition is too large to refit several arms repeatedly on the 8 GB development machine. All new arms therefore use the same memory-safe training sample:

- **all 13,835 training attack rows**;
- **200,000 benign rows sampled deterministically with seed 42** from the 961,954 training benign rows.

The sample is identical for every arm and every estimator seed. This keeps arm-to-arm comparisons fair. Absolute numbers are not directly interchangeable with the full-data Random Forest baseline. The report includes the frozen full-data Random Forest as a **reference arm** using the cached predictions in `models/eval_cache/`, so the cost of the subsample is visible.

## Predeclared arms

| Arm | What it tests | Fitting data | Score |
| --- | --- | --- | --- |
| **R — reference** | Frozen full-data Random Forest already evaluated under the protocol | Cached full-data model, no retraining | `1 - P(BENIGN)` |
| **A — class weighting** | Whether balancing rare *seen* attack rows helps | Benign + all training attacks, `class_weight='balanced_subsample'` | `P(ATTACK)` |
| **B — family-aware augmentation** | Whether label-preserving interpolation inside known attack families broadens the attack manifold | A's rows plus interpolated rows generated separately inside each known training attack family (FTP-Patator, SSH-Patator) | `P(ATTACK)` |
| **C1 — open-set Isolation Forest (primary)** | Whether a benign-only novelty model flags unseen families | Benign-only sample | `-score_samples` (higher = more anomalous) |
| **C2 — PCA reconstruction (sensitivity)** | Whether linear subspace novelty flags unseen families | Benign-only sample | Mean squared reconstruction error |
| **C3 — Mahalanobis distance (sensitivity)** | Whether covariance novelty flags unseen families | Benign-only sample | Regularised Mahalanobis distance |
| **D — hybrid (secondary)** | Whether supervised and novelty scores are complementary | A and C1 scores combined with a validation-selected weight | `alpha * sup + (1 - alpha) * novelty` |

The primary comparison required by the phase is **A vs B vs C1**. C2, C3, and D are declared sensitivity/secondary arms and cannot replace a negative A/B/C1 result.

## Selection rules

1. **Threshold:** for every arm and every seed, select the highest validation attack recall subject to validation FPR ≤ 1%, using only Wednesday labels. Apply that threshold unchanged to Thursday and Friday.
2. **Hybrid weight:** choose `alpha` from `{0.0, 0.25, 0.5, 0.75, 1.0}` by validation binary average precision (threshold-free). Then select the threshold as in rule 1. The test labels are never used.
3. **Calibration:** fit a one-dimensional Platt scaler on the validation attack score. Report calibrated Brier and ECE on test. This uses validation labels only.
4. **Estimator seeds:** `42, 43, 44, 45, 46` for every retrained arm. The sampled training rows are fixed across seeds.
5. **No test tuning:** if a test result is disappointing, it is reported. It is not used to choose another arm, feature, threshold, calibration, or blend.

## Required reporting

Per arm and seed:

- Binary PR-AUC, ROC-AUC, and Brier/ECE.
- Test FPR, attack recall, precision, alert rate, and alerts per 10,000 benign flows.
- Per-family support and attack-flag recall, with `seen_in_training` marked.
- Per-family one-vs-rest average precision.
- Results split by Thursday and Friday, including Friday-only Bot recall.
- Top-K alert budgets of 50 and 100 alerts per 10,000 eligible flows.
- Mean and sample standard deviation over the five estimator seeds.
- Wilson intervals for recall proportions where support permits.

## Gates and interpretation

| Gate | Target | Consequence |
| --- | --- | --- |
| Benign FPR at frozen threshold | ≤ 1% on test | Hard gate |
| Alert rate at frozen threshold | ≤ 2% of flows | Hard gate |
| Bot recall | ≥ 0.70 desired, ≥ 0.50 minimum | Family gate; support 1,966 flows is sufficient |
| Calibration | ECE ≤ 0.05 | Cross-cutting gate |
| Differential vs reference | Direction and seed spread must be reported | No arm is called an improvement without a stable margin |

A family result is descriptive only when support is 30–99 and is not a recall claim below 30 flows. Infiltration (36 flows) and SQL Injection (21 flows) are therefore descriptive/unsupported, not evidence of success.

## Honest outcomes allowed

- **Positive:** an arm raises Bot recall materially above the reference at ≤1% FPR and the seed spread does not overlap the reference.
- **Mixed:** it raises recall but breaks FPR/alert/calibration gates. This is a trade-off, not a win.
- **Negative:** it does not raise Bot recall without unacceptable false positives. The detection score does not move.

The result will be written to `docs/UNSEEN_FAMILY_AND_BOTNET.md` and `docs/d6_unseen_family_results.json`.
