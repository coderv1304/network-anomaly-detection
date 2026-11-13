# Research Proposal: Network-Flow Detection Under Distribution Shift and Analyst Alert Budgets

## Problem statement

Network-flow classifiers are often evaluated on precomputed benchmark features and random row splits, while operational use involves later traffic, incomplete attack-family coverage, and limited analyst review capacity. Random-split metrics can therefore obscure whether alerts remain useful under time or family shifts. This project separates known-family temporal classification from unseen-family attack flagging, measures alert burden, and proposes a controlled simulation of limited analyst feedback. Paired PCAP replay is a supporting validity check, not the primary research contribution.

## Research question

**How do temporal and attack-family shifts affect flow-based detection quality and analyst alert burden, and does limited analyst review improve detection on a later untouched period?**

## Hypothesis

Attack families absent from the classifier vocabulary cannot be named by its closed-set multiclass head; binary attack scoring may flag some such flows but could vary substantially by family. A threshold selected on one validation period may not meet the same false-positive or alert-volume budget later. Under a fixed label budget, uncertainty-based review may improve a later-period metric over random review, but this must be tested on untouched later data and may not hold. Each statement is a testable hypothesis, not a promised outcome.

## Proposed method

1. Freeze dataset versions, source hashes, parser versions, feature definitions, label mapping, and random seeds. The already inspected CIC-IDS-2017 weekday files remain development data, not a blind final test.
2. Follow [Evaluation Protocol v1](EVALUATION_PROTOCOL.md): report class coverage before fitting, separate class-covered temporal evaluation from unseen-family evaluation, and use an untouched later period or independent dataset for confirmation.
3. Compare declared simple baselines, Logistic Regression, Random Forest, and one justified novelty-detection baseline with training-only preprocessing.
4. Select thresholds on validation data only; report frozen test metrics plus precision and recall at fixed alert budgets. Include per-family results and support counts.
5. Simulate random and uncertainty-based analyst review using fixed label budgets, revealing labels only after selecting reviewed items and evaluating on a later untouched batch. Label this as simulated feedback.
6. Report per-class precision/recall, macro and weighted F1, PR-AUC, confusion matrices, frozen-threshold FPR, calibration diagnostics, alert volume, labels requested, and uncertainty. Do not treat seed variation as day- or site-level uncertainty.
7. As a supporting validity check, produce paired feature tables from the same PCAP using the reference exporter and project parser. The [parity utility](../training/feature_parity.py) pairs unique bidirectional 5-tuples and reports ambiguous/unmatched records; add timestamp matching when reliable correspondence is available.

## Expected contribution

The defensible contribution is an auditable comparison of known-family and unseen-family behavior under temporal separation, measured at both frozen thresholds and fixed analyst alert budgets, followed by a controlled label-budget feedback simulation if fresh data is available. The project does not claim a new universal detector. The study must review prior open-set and drift-aware IDS work before making any novelty claim, and it must report negative findings directly.

## Existing evidence and gap

The sample benchmark reports Random Forest macro-F1 **0.1072 ± 0.0037** and weighted-F1 **0.7417** on random row splits. A full day holdout was run with three estimator seeds: train Monday/Tuesday, validate Wednesday, and test Thursday/Friday. Macro-F1 was **0.0857** in all runs; only BENIGN, FTP-Patator, and SSH-Patator were in the training vocabulary, while seven test labels covering 291,139 test rows were unseen. The validation-selected binary thresholds produced a mean test recall of **53.61% ± 5.98%** and mean FPR of **2.87% ± 3.49%**. The binary open-set experiment also had low and seed-variable recall. These results are development/failure-analysis evidence, not a blind confirmation or evidence of a generally effective detector. See [the full temporal report](TEMPORAL_HOLDOUT_RESULTS.md). Parser/model feature parity and independent-dataset performance remain unverified.

## Reproducibility and ethics

Publish scripts, configuration, exact commands, dependency lock/version data, seeds, hashes, and dataset acquisition instructions. Respect dataset licenses and do not republish restricted captures. Use isolated lab traffic or data collected with explicit authorization; minimize IP retention and avoid sending private telemetry to third parties. Do not enable automated response. Preserve a final test set from model selection and document deviations before analysis.

## Deliverables

- Dataset and feature provenance manifest
- Separate known-family and unseen-family results at threshold and alert-budget operating points
- Reproducible training/evaluation command and machine-readable metrics
- Simulated analyst-feedback comparison, only if a fresh later-period evaluation can be reserved
- Paired parser parity report and per-feature error tables, as a supporting validation
- Model card tied to a specific artifact hash
- Limitations, failure analysis, and a short presentation of research findings

## Project status

Three estimator-seed runs of one full-data temporal holdout and several model checks are complete and documented in [the result report](TEMPORAL_HOLDOUT_RESULTS.md). The data has been inspected and cannot act as a blind test for future choices. The proposal remains incomplete until the protocol's data-feasibility audit is complete and confirmation is run on fresh, class-covered temporal data; analyst-feedback simulation, a second dataset, and paired PCAP/flow-export parity are not yet complete.
