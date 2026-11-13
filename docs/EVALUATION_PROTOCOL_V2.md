# Evaluation Protocol v2 — Per-Family Gates (Phase D1)

**Status:** frozen before any further model or threshold tuning.
**Supersedes:** `docs/EVALUATION_PROTOCOL.md` for all new experiments. The v1 document remains the historical protocol for already-inspected results.
**Date:** 2026-11-08.

## Integrity statement

The CIC-IDS-2017 weekday split and the existing RF, Logistic Regression, Isolation Forest, drift, and feedback results have already been inspected. They are **development evidence**, not a blind final test. No result in this repository may be described as confirmatory until it is produced on a fresh period or an independent dataset under this protocol.

The final test partition is read once per declared experiment. It must not be used to choose a model, feature set, threshold, calibration method, alert budget, or family target.

## Research question

How well do flow-based detectors perform when traffic changes over time or attack families are missing from training, and what analyst alert burden do they impose at a fixed review budget?

## Two evaluation tracks

### Track A — known-family temporal evaluation

Purpose: estimate multiclass and binary behaviour when the test period contains attack families represented in the training vocabulary.

Rules:

- Use chronological, contiguous time blocks. Do not randomly distribute individual flows for the primary result.
- Publish label coverage per partition before fitting any model.
- A family is **covered** only if it appears in training, validation, and final test.
- Select model settings, calibration, and thresholds on training and validation only.
- If a dataset cannot supply adequate temporal coverage, mark Track A **not feasible on that dataset**. A random row split is not a substitute.

### Track B — attack-family holdout evaluation

Purpose: measure whether flows from families absent from training receive an attack score. This is **unseen-family attack flagging**, not family identification and not universal zero-day detection.

Rules:

- Predeclare held-out families and their counts before training.
- Keep all flows from a held-out family out of the multiclass training vocabulary.
- Keep chronological separation between train, validation, and final test.
- Validation may contain the predeclared held-out families to select an attack-versus-benign threshold.
- Retain each held-out family's original label in evaluation so it cannot be collapsed into a known class.
- Report per-family attack-flag recall separately for every held-out family.

## Partition rules

| Partition | Purpose | Allowed use |
| --- | --- | --- |
| Train | Fit preprocessing, vocabulary, model, calibration | Model fitting only |
| Validation | Select threshold, calibration, alert budget policy, early stopping | Selection only |
| Final test | Report frozen results | Read once, no tuning |
| External | Second dataset or real capture | Report only, no retuning on the original data |

- Record exact file names, SHA-256 values, row counts, time ranges, and label maps.
- Fit imputers, scalers, feature selection, calibration, and label vocabularies on training data only.
- Remove identifiers and features unavailable at inference time.
- Report duplicate counts, missing values, infinities, and feature-name mismatches before training.
- If a preprocessing defect is fixed, mark prior results **not comparable** and say why.

## Minimum support and claim rules

| Final-test support for a family | What may be claimed |
| --- | --- |
| At least 100 flows | A family-level estimate with uncertainty. Still not independent replication. |
| 30–99 flows | Descriptive only; label the interval as unstable. |
| Fewer than 30 flows | No family-level recall or precision claim. Report the count and say the data cannot support the claim. |

Support counts are reported for every family in every partition. Correlated flows are not independent samples; a 100-flow floor does not turn them into independent observations.

## Threshold selection

- Attack score is `1 - P(BENIGN)` for models that produce a benign probability.
- Select the threshold on **validation only** by maximizing attack recall subject to validation FPR **≤ 1%**.
- Record the threshold, validation FPR, validation recall, tie behaviour, and the validation period.
- Freeze the threshold before final testing.
- Apply the frozen threshold unchanged to every final-test day and every seed.
- Report test FPR, recall, precision, alert rate, and alerts per 10,000 benign flows **per day and per seed**.
- If the threshold cannot hold the FPR budget on a day or seed, report the operating cost explicitly. Do not retune on test data.
- Compare, where justified:
  - one global frozen threshold;
  - per-family thresholds selected on validation;
  - a day-aware policy only if the day signal is available before prediction and is not derived from test labels.
- The serving path must either apply the documented threshold or label its output as unthresholded argmax. As of S3, the serving path applies the attack-score threshold recorded in its bundle and stores the decision basis; the raw argmax label is retained for audit.

## Alert-budget evaluation

- Predeclare budgets before reading final test results. The default budgets are **50 and 100 alerts per 10,000 eligible flows**.
- For each budget report precision, recall, per-family recall among selected alerts, false positives per 10,000 benign flows, and total alert volume.
- State whether a budget was under-filled or over-filled.
- Keep threshold results and top-K budget results separate. They answer different operational questions.
- Do not select the budget after seeing final-test precision.

## Primary metrics

### Track A — known-family multiclass

- Per-family support, precision, recall, F1, and PR-AUC where defined.
- Macro-F1 and weighted-F1 shown together; neither is used alone for selection.
- Confusion matrix.
- False-positive count and FPR on benign flows.
- Calibration diagnostics: Brier score, ECE, reliability diagram. Label them diagnostics unless a calibration method was fitted on a separate calibration partition.
- Runtime and artifact hash.

### Track B — unseen-family and binary

- Binary PR-AUC, ROC-AUC, and average precision.
- Frozen-threshold FPR, recall/TPR, precision, alert rate, and alerts per 10,000 benign flows.
- Per-family support and attack-flag recall for every held-out family.
- Whether each family appeared in training.
- Recall and precision at each predeclared top-K alert budget.
- Calibration diagnostics for the binary score.

### Uncertainty

- Use the fixed seed set `42, 43, 44, 45, 46` for estimator variation.
- Report every seed, the mean, and the sample standard deviation.
- Report day-level and capture-level results separately.
- Use Wilson intervals for proportions and bootstrap intervals for PR-AUC/ROC-AUC where support permits.
- Do not describe seed variation on one fixed split as a confidence interval or independent replication.
- If only one test period exists, state that population-level uncertainty cannot be estimated reliably.

## Per-family targets for a 9/10 detection claim

These targets are **predeclared gates**, not achieved results. They apply to the frozen threshold and to each final-test day and seed. A target is met only if the point estimate meets it **and** the lower bound of its uncertainty interval is not below the target by more than the predeclared tolerance.

| Family | Recall target | Precision target | Minimum final-test support | Rationale |
| --- | ---: | ---: | ---: | --- |
| Botnet / Bot | ≥ 0.70 | ≥ 0.50 | 100 | The current 1.12% recall is the primary failure. A 9/10 claim is impossible while this remains near zero. |
| DDoS | ≥ 0.85 | ≥ 0.90 | 100 | High-volume, comparatively separable family. |
| PortScan | ≥ 0.85 | ≥ 0.85 | 100 | Common, high-volume family with clear flow structure. |
| Web Brute Force | ≥ 0.85 | ≥ 0.85 | 100 | Current recall is already high; regression is not acceptable. |
| Infiltration | ≥ 0.60 | ≥ 0.50 | 100 | Low-support, hard family; target is deliberately lower but still explicit. |
| SQL Injection | ≥ 0.70 | ≥ 0.50 | 100 | Current recall is weak relative to XSS. |
| XSS | ≥ 0.85 | ≥ 0.85 | 100 | Current recall is high; regression is not acceptable. |

### Cross-cutting gates

- Benign FPR **≤ 1%** on every final-test day and every seed, not only on validation.
- Alert rate at the frozen threshold **≤ 2%** of eligible flows, or an explicit cost-sensitive justification for a higher rate.
- Calibrated probabilities with ECE **≤ 0.05** and a reported Brier score on held-out data.
- No family-level claim below the minimum-support rule.
- Per-day and per-seed results published, not only an aggregate.
- External validation on a second dataset or a real capture with documented feature mapping.
- A prospective human-review pilot with measured analyst time and false-positive cost.
- A cost-sensitive evaluation with explicit false-positive and missed-attack costs.

If any cross-cutting gate fails, the detection score stays below 9 regardless of aggregate PR-AUC.

## Model and baseline comparison

Run the same partitions and feature schema for each candidate:

1. Majority-class and simple rule baseline.
2. Logistic Regression baseline.
3. Current Random Forest baseline.
4. One justified unsupervised or novelty-detection baseline for Track B, with fitting data and threshold method stated.

Record model parameters, runtime, artifact hash, source hashes, and feature-schema version for every run. Do not select a model using weighted F1 or accuracy alone. Explicitly report which baselines fail the Botnet gate.

## Calibration

- Fit calibration on a partition that is not the final test.
- Compare the uncalibrated score with at least one method (temperature scaling or isotonic regression).
- Report ECE, Brier score, reliability diagrams by family and by day, and decision-curve analysis.
- Explain how calibration changes the threshold and alert budget.
- Do not show a confidence value in the UI unless it is produced by a calibrated model and linked to this evidence.

## Analyst-feedback experiment

- Compare no feedback, random review selection, and uncertainty-based selection under the same label budget.
- Select examples from an earlier review batch, reveal existing dataset labels only after selection, update the model under a documented policy, and evaluate on a later untouched period.
- Report labels requested, per-family metrics, false-positive burden, and later-period performance.
- Prevent later-period labels from influencing earlier decisions.
- Describe this as **simulated analyst feedback**, not a human study.

## Drift-monitoring experiment

- Track selected feature distributions and model scores in time order.
- Evaluate warning delay, missed degradation, and false warnings.
- Do not use test labels to trigger warnings.
- Keep drift results separate from attack classification.
- The current audit (3 true warnings, 2 false warnings, 2 missed degradations, 0 correctly quiet) is a development result, not a validated monitor.

## Release gate

A 9/10 detection claim is allowed only when all of the following are true:

1. Track A and Track B both pass their per-family targets on a fresh, class-covered final test.
2. FPR is ≤ 1% on every final-test day and every seed at the frozen threshold.
3. Calibration gates pass on held-out data.
4. A second dataset or real capture passes with documented feature mapping.
5. A prospective pilot measures analyst time and false-positive cost.
6. A cost-sensitive evaluation shows the detector is useful under a declared cost model.
7. The serving artifact, feature schema, threshold policy, and evaluation artifact are the same versioned release.

Until then, the honest detection score remains **4/10**, not 9/10.

## Current status against this protocol

| Gate | Status |
| --- | --- |
| Track A temporal class coverage | Not established on a fresh blind period |
| Track B unseen-family holdout | Development evidence only; the D6 five-seed experiment is negative ([report](UNSEEN_FAMILY_AND_BOTNET.md)) |
| Botnet recall ≥ 0.70 | **Fails** (D6 reference 0.94% ± 0.82%; best arm 20.7% ± 16.6% but at 8.65% FPR and a 29.4% alert rate) |
| FPR ≤ 1% on every day and seed | **Fails** (five-seed FPR 4.11% ± 3.27%) |
| Calibrated probabilities | Not completed (ECE 0.25; served RF registered uncalibrated) |
| External validation | **Blocked** — no independent dataset on disk; one 11-flow operator-declared-benign real capture only ([report](EXTERNAL_VALIDATION.md)) |
| Prospective pilot | **Not run** — D8 protocol and S7 pre-registration exist, but no design partner or human data ([S7 outcome](S7_PILOT_OUTCOME.md)) |
| Cost-sensitive gate | **FAIL** — FPR, alert rate, Bot recall, calibration, external data, pilot, and site cost model fail; artifact identity and five-seed reporting pass ([report](COST_MODEL_AND_RELEASE_GATE.md)) |
| Serving/evaluation artifact identity | **Match** (registry-active seed 42 RF hash equals evaluated manifest) |

## Reporting rules

- Publish coverage tables before results.
- Publish exact commands, data hashes, model hashes, configuration, and machine-readable metrics.
- Include negative results, low-support classes, threshold failures, and deviations from this protocol.
- If final-test data influenced any choice, label the result exploratory and use fresh data for confirmation.
- Do not claim production detection, zero-day detection, or analyst-time savings from benchmark replay alone.
