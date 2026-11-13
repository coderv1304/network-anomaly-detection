# Evaluation Protocol v1

> **Superseded for new experiments:** see [Evaluation Protocol v2](EVALUATION_PROTOCOL_V2.md) for frozen per-family gates, minimum support, threshold rules, and the 9/10 release gate. This v1 document remains the historical protocol for already-inspected results.

## Status and integrity statement

This document defines the next evaluation protocol. It is written after the full CIC-IDS-2017 weekday results and several model comparisons have already been examined. Therefore, those files and results are **development data**, not a blind or preregistered final test. No retrospective wording should imply otherwise. Confirmatory claims require an untouched later capture period or a separately acquired dataset whose labels and outcomes are not used during model or threshold selection.

The current full weekday split remains useful as a reproducible failure-analysis baseline. Historical baseline details are in [TEMPORAL_HOLDOUT_RESULTS.md](TEMPORAL_HOLDOUT_RESULTS.md).

## Research question

How do time and attack-family shifts affect flow-based detection quality and alert burden, and does a limited analyst-review budget improve detection on a later untouched period?

## Separate evaluation tracks

### Track A: known-family temporal evaluation

Purpose: estimate classification behavior when the test period contains attack families represented in the training vocabulary.

- Use chronological, contiguous time blocks. Do not randomly distribute individual flows across partitions for the primary result.
- Require the primary test families to be present in training, validation, and final test. Publish the per-partition label coverage before fitting any model.
- Select model settings and thresholds using training and validation periods only. Keep the final test period untouched.
- If the selected dataset cannot provide adequate temporal class coverage, mark this track **not feasible on that dataset**. Do not relabel a random row split as temporal evidence.
- Report family-specific metrics only with support counts. Treat families with fewer than 100 test flows as descriptive/exploratory, not as stable family-level estimates. This flow-count floor does not make correlated flows independent.

### Track B: unseen-family evaluation

Purpose: assess whether flows from attack families absent from the classifier's training vocabulary receive an attack score, not whether the model can name an unknown family.

- Select held-out attack families before training and record the selection rule and counts. Keep all flows from each held-out family out of the multiclass training vocabulary.
- Preserve chronological separation between train, validation, and final test periods. Validation may contain the predeclared held-out families to select an attack-versus-benign threshold; the final test period remains later and untouched.
- For the multiclass model, retain each held-out family's original label in evaluation so it cannot be silently collapsed into a known family.
- For the binary model, map non-benign training labels to `ATTACK`, but report final-test recall separately for every original family.
- Call the outcome **unseen-family attack flagging**. Do not call a binary alert a family identification or universal zero-day detection.
- If the data does not contain enough temporal support for this design, report that limitation and obtain another dataset or capture rather than weakening the split after seeing results.

## Data and preprocessing controls

1. Record dataset source, license, acquisition notes, file SHA-256 values, row counts, label mapping, software versions, and feature schema.
2. Audit missing values, infinities, duplicate records, label decoding, time ranges, and train/test feature overlap before model fitting.
3. Fit imputers, scalers, feature selection, and learned label vocabularies on training data only.
4. Remove identifiers and any feature not available at the intended inference point. Record all excluded columns.
5. Report exact class counts and the fraction of test rows whose attack families were absent during training.
6. Keep the already-inspected CIC-IDS-2017 weekdays as development evidence. Reserve a fresh period or independent dataset for confirmatory claims.

## Models and comparisons

Run the same partitions and feature schema for each candidate:

- Majority-class and simple rule baseline.
- Logistic Regression baseline.
- Current Random Forest baseline.
- One justified unsupervised or novelty-detection baseline for the unseen-family track, with its fitting data and threshold-selection method stated explicitly.

Use a fixed, declared seed set (42, 43, 44, 45, 46) for estimator-variance checks. Seed variation is not a substitute for variation across independent days, sites, or datasets. Record model parameters, runtime, artifact hash, and source hashes for every run. Do not tune against the final test results.

## Threshold and alert-budget procedure

- Define attack score as `1 - P(BENIGN)` for models that produce a benign probability.
- Select a threshold on validation data only by maximizing validation attack recall subject to validation FPR no greater than 1%. Record the selected threshold, validation FPR, validation recall, and tie behavior.
- Freeze that threshold before final testing. Report test FPR, recall, precision, alert rate, and alerts per 10,000 benign flows.
- Separately evaluate top-K budgets of 50 and 100 alerts per 10,000 eligible flows. Report precision and recall at each K; do not treat top-K and threshold results as interchangeable.
- Report when a requested budget cannot be met or when the score distribution produces too few/too many alerts. Never silently retune on test data.

## Required metrics

### Known-family track

- Per-family support, precision, recall, and F1.
- Macro-F1 and weighted-F1, shown together and not used alone.
- Per-family average precision/PR-AUC where defined, confusion matrix, and false-positive counts.
- Multiclass Brier score and calibration diagnostics, labeled as diagnostics unless a calibration method is fitted on a separate calibration partition.

### Unseen-family and binary track

- Binary average precision, PR-AUC, and ROC-AUC.
- Frozen-threshold FPR, recall/TPR, precision, alert rate, and alerts per 10,000 benign flows.
- Per-family support and recall for every held-out family, plus whether that family appeared in training.
- Recall and precision at each fixed top-K alert budget.

### Uncertainty and variation

- Report every predeclared estimator seed, the mean, and sample standard deviation.
- Report day/capture-level results separately. Do not describe three seeds on one fixed split as a confidence interval or independent replication.
- Use temporal-block resampling only as a sensitivity analysis when there are enough independent blocks; explain that it does not replace additional capture periods.
- If only one test period or too few independent periods are available, state that population-level uncertainty cannot be estimated reliably.

## Analyst-feedback experiment

This experiment is a later phase and must not be blended into the baseline test:

- Compare no updates, random review selection, and uncertainty-based selection using the same label budget.
- Select examples from an earlier review batch, reveal their existing dataset labels only after selection, update the model under a documented procedure, and evaluate on a later untouched batch.
- Report number of labels requested, per-family metrics, false-positive burden, and later-period performance.
- Describe this as simulated analyst feedback. Do not claim measured analyst-workload reduction without a prospective human study.

## Reporting and stop rules

- Publish coverage tables before results, exact commands, data hashes, model hashes, configuration, and machine-readable metrics.
- Include negative results, low-support classes, threshold failures, and deviations from this protocol.
- If a family is absent from training, do not report a multiclass family recall as though it were a recognized class. Report its attack-flag recall separately.
- If test data influenced model choice, feature choice, threshold policy, or this protocol, label the result exploratory and use fresh data for confirmation.
- Do not claim production detection, successful zero-day detection, or analyst-time savings based solely on benchmark replay.

## Current execution status

- Historical CIC-IDS-2017 day split: completed and inspected; development/failure-analysis evidence only.
- Class-covered temporal test: not yet established with a fresh blind final period.
- Independent-dataset confirmation: not completed.
- Feature parity against the exact same PCAP/export capture: not completed.
- Analyst-feedback simulation: not completed.
