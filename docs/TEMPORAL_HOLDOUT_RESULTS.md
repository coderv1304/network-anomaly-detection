# Full CIC-IDS-2017 Temporal Holdout: Failure Analysis

## Summary

This is a reproducible three-seed run of the current Random Forest pipeline on the full local CIC-IDS-2017 day files. It is a failure analysis, not evidence that the application is ready to detect production attacks. Mean ± sample standard deviation describes only variation across three estimator seeds on the same fixed data split; it is not a confidence interval.

These files and results have been inspected and used for model comparisons. Under the [current evaluation protocol](EVALUATION_PROTOCOL.md), they are development evidence and cannot serve as a blind confirmatory test for future model choices.

| Item | Result |
|---|---:|
| Training partition | Monday + Tuesday, 975,789 rows |
| Validation partition | Wednesday, 692,686 rows |
| Final test partition | Thursday + Friday, 1,162,065 rows |
| Features | 80 |
| Estimator | Random Forest, 100 trees, seeds 42, 43, 44 |
| Learned labels | BENIGN, FTP-Patator, SSH-Patator |
| Test labels unseen during training | 7 labels, 291,139 rows (25.05% of test) |
| Multiclass macro-F1 | 0.0857 ± 0.0000 |
| Weighted-F1 | 0.6421 ± 0.0000 |
| Attack average precision / PR-AUC / ROC-AUC | 0.6223 ± 0.0627 / 0.7393 ± 0.0815 / 0.7523 ± 0.0433 |
| Multiclass Brier score / ECE (10 bins) | 0.4955 ± 0.0004 / 0.2473 ± 0.0003 |
| FPR at 95% TPR | 100% for all seeds |

The classifier correctly assigned **zero** test examples to every attack-family label in the test set. The high weighted-F1 is dominated by BENIGN traffic and must not be presented without macro-F1 and per-class results. At 95% attack recall, the score ranking would flag all benign traffic.

## Frozen binary operating point

For each seed, an attack-versus-benign threshold was selected using Wednesday validation data only, with a maximum allowed validation FPR of 1%. Each threshold was then frozen and measured on Thursday/Friday:

| Metric | Wednesday validation, mean ± std | Thursday/Friday test, mean ± std |
|---|---:|---:|
| FPR | 0.599% ± 0.280% | 2.872% ± 3.488% |
| TPR / recall | 3.609% ± 0.831% | 53.608% ± 5.983% |
| Precision | — | 86.919% ± 15.190% |
| All-flow alert rate | — | 15.583% ± 1.138% |

Per-seed final-test FPR was 0.725%, 0.993%, and 6.896%; the target was not stable across model seeds despite validation selection under the 1% budget. Per-seed thresholds were 0.00251505, 0.00185520, and 0.00936364, respectively.

| Seed | Frozen threshold | Validation TPR | Test FPR | Test TPR | Test precision | Test alert rate |
|---:|---:|---:|---:|---:|---:|---:|
| 42 | 0.00251505 | 4.587% | 0.725% | 57.943% | 96.390% | 15.060% |
| 43 | 0.00185520 | 3.264% | 0.993% | 56.100% | 94.969% | 14.800% |
| 44 | 0.00936364 | 2.975% | 6.896% | 46.782% | 69.398% | 16.889% |

These thresholds illustrate substantial day-to-day and seed-to-seed instability: average validation recall was only 3.61%, and test FPR ranged from 0.725% to 6.896%. The alert rate is also high. These are dataset-specific retrospective results, not a safe operational threshold or a promise of customer-network performance. Binary detection merges all attack types; it does not identify the family.

## Alternative model checks

Two variants were tested on the same split:

| Model | Seeds | Attack average precision | Attack ROC-AUC | Frozen-threshold test recall | Frozen-threshold test FPR |
|---|---|---:|---:|---:|---:|
| Random Forest, default weights | 42–44 | 0.622 ± 0.063 | 0.752 ± 0.043 | 53.61% ± 5.98% | 2.87% ± 3.49% |
| Random Forest, `balanced_subsample` | 42–44 | 0.608 ± 0.097 | 0.792 ± 0.063 | 26.95% ± 41.82% | 2.07% ± 2.35% |
| Logistic Regression, default weights | 42 | 0.399 | 0.700 | 3.52% | 2.66% |
| Binary attack-vs-benign Random Forest, `balanced_subsample` | 42–44 | 0.352 ± 0.063 | 0.583 ± 0.044 | 11.67% ± 11.84% | 0.69% ± 0.24% |

Class weighting raised ROC-AUC on average but made the frozen-threshold result highly seed-sensitive: recall ranged from 1.32% to 75.20%. It is not a robust improvement and did not displace the seed 42 Random Forest. Logistic Regression was weaker on this split. Per-seed full metrics and model hashes are retained under ignored local folders `scratch/cic-temporal-balanced/` and `scratch/cic-temporal-logistic/`.

## Open-set binary experiment

An additional variant groups every non-benign training label into `ATTACK`, uses `balanced_subsample`, and selects a threshold on Wednesday under the same 1% FPR budget. All Thursday/Friday attack families are absent from the training labels. Across seeds 42–44, average precision was 0.352 ± 0.063 and ROC-AUC was 0.583 ± 0.044. At the frozen threshold, test recall was only 11.67% ± 11.84%, while FPR was 0.69% ± 0.24%; recall ranged from 2.18% to 24.94%. It detected web-attack families much more consistently than PortScan or DDoS, and missed nearly all Bot rows. This is not a useful general unseen-attack detector. It demonstrates why aggregate metrics and a single operating threshold hide family-specific failures.

The full per-seed metrics, family recalls, hashes, and thresholds are generated under ignored local folder `scratch/cic-binary-attack/`. Reproduce with the three seed values above and `--task binary_attack --class-weight balanced_subsample`; this option is an experimental analysis path, not a deployment model.

## Class coverage

Training contained 961,954 BENIGN rows, 7,938 FTP-Patator rows, and 5,897 SSH-Patator rows. The final test set contained BENIGN, Bot, DDoS, Infiltration, PortScan, and three Web Attack labels. The seven non-benign test labels were absent from the training vocabulary. The Wednesday validation set also contained five attack-family labels absent from training.

This split therefore tests a hard temporal/open-set condition, but it cannot establish ordinary closed-set multiclass performance on all CIC attack families. The result demonstrates that a day split alone can leave the model without required class coverage. A stronger study should pre-register multiple temporal protocols, report class coverage before fitting, and add an independently sourced dataset.

## Reproduction

```powershell
venv\Scripts\python.exe training\train_pipeline.py `
  --data-dir data `
  --output-dir scratch\cic-temporal-holdout `
  --split-mode day_based `
  --model rf `
  --n-trees 100 `
  --seed 42 `
  --max-fpr 0.01
venv\Scripts\python.exe training\train_pipeline.py --data-dir data --output-dir scratch\cic-temporal-holdout --split-mode day_based --model rf --n-trees 100 --seed 43 --max-fpr 0.01
venv\Scripts\python.exe training\train_pipeline.py --data-dir data --output-dir scratch\cic-temporal-holdout --split-mode day_based --model rf --n-trees 100 --seed 44 --max-fpr 0.01
```

The run used Python 3.12.10 and scikit-learn 1.5.2. Preprocessing and label encoding were fit on training rows only. The complete metrics JSON, versioned bundle, pipeline, and manifest are generated in the ignored local `scratch/cic-temporal-holdout/` directory. The metrics record the exact source file list, row counts, threshold, class metrics, and run timings.

The eight source CSV SHA-256 values and each model bundle SHA-256 are recorded in the local run manifests. Obtain the licensed CIC-IDS-2017 files separately; raw data is not included in the repository.

## Limitations and next experiment

- Three estimator seeds on one fixed split; no confidence interval, additional temporal split, or between-dataset replication yet.
- A single benchmark dataset; no independent network, capture sensor, or later-period dataset.
- PCAP-to-feature parity has not been measured on a paired capture/export.
- Day-specific class coverage differs sharply; results are not comparable to random row-split estimates.
- No probability calibration procedure was applied; Brier/ECE are diagnostics.
- The serving app applies the attack-score threshold recorded in the registry-active Random Forest bundle, the same artifact evaluated here. The serving entry is registered as uncalibrated. See [THRESHOLD_POLICY_V2.md](THRESHOLD_POLICY_V2.md) and [MODEL_REGISTRY_AND_DEPLOYMENT.md](MODEL_REGISTRY_AND_DEPLOYMENT.md).
- No analyst workload, latency under load, drift, packet loss, or deployment safety study was performed.

Next: preregister a temporal evaluation where train and test contain the same attack families, then separately hold out families to test open-set behavior. Quantify uncertainty with day-level resampling, run paired PCAP parity, and replicate on a second dataset before making efficacy claims.
