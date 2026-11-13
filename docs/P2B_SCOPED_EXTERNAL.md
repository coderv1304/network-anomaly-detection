# P2B Scoped External Comparison (CIC-IDS-2018 DoS/DDoS)

**Status:** scoped external result.
**Scope:** CIC-IDS-2018 DoS and DDoS only. PortScan is absent from the dataset and is not evaluated or claimed. This is a scoped external comparison, not a general volumetric/scanning validation.
**Date:** 2026-11-13.
**Artifact:** [`p2b_scoped_external.json`](p2b_scoped_external.json).
**Script:** [`../scripts/p2b_scoped_external.py`](../scripts/p2b_scoped_external.py).

## 1. Amendment

The preregistered P2B protocol uses the CIC-IDS-2017 day split. That split
cannot fit a supervised head: Monday–Tuesday has zero volumetric/scanning
positives, and the Wednesday validation families are disjoint from the
Friday test families. The approved amendment is an A4-scoped external run:
train, validate, and test on a leakage-safe group split of CIC-IDS-2018 for
DoS and DDoS only. PortScan is absent from the dataset and is not claimed.

## 2. Split

| Partition | Rows | DoS | DDoS | Benign |
| --- | ---: | ---: | ---: | ---: |
| Train | 8,204,045 | 161,950 | 542,897 | 7,499,198 |
| Validation | 1,756,302 | 34,510 | 115,741 | 1,606,051 |
| Test | 1,757,180 | 35,038 | 117,317 | 1,604,825 |

Group split: `group_hash_split: complete-feature hash mod 100; buckets 0-69 train, 70-84 validation, 85-99 test`.

**Coverage gate:** **PASS**. DoS and DDoS are present in train, validation, and test, and the validation/test family sets overlap. PortScan is absent from the dataset and is outside this scoped claim.

| Family | Train | Validation | Test | Pass |
| --- | ---: | ---: | ---: | :---: |
| DoS | 161,950 | 34,510 | 35,038 | yes |
| DDoS | 542,897 | 115,741 | 117,317 | yes |

PortScan is **absent** from CIC-IDS-2018. No scan-detection claim is made.

## 3. Protocol

| Item | Value |
| --- | --- |
| Seeds | 42, 43, 44, 45, 46 |
| Budgets | 10, 100 alerts / 10k |
| Training cap | 800,000 rows (validation/test scored in full) |
| Threshold partition | validation only |
| Test partition | held out; one pass |

## 4. Results at 100 alerts / 10k

| Method | Seed | Recall | FPR | PPV @ benchmark | ROC-AUC | AP | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| logistic_regression | 42 | 10.12% | 0.16% | 85.44% | 0.9426 | 0.6125 | 0.1104 | 0.1835 |
| logistic_regression | 43 | 10.12% | 0.16% | 85.44% | 0.9426 | 0.6125 | 0.1104 | 0.1835 |
| logistic_regression | 44 | 10.12% | 0.16% | 85.44% | 0.9426 | 0.6125 | 0.1104 | 0.1835 |
| logistic_regression | 45 | 10.12% | 0.16% | 85.44% | 0.9426 | 0.6125 | 0.1104 | 0.1835 |
| logistic_regression | 46 | 10.12% | 0.16% | 85.44% | 0.9426 | 0.6125 | 0.1104 | 0.1835 |
| random_forest | 46 | 4.06% | 0.00% | 100.00% | 0.9992 | 0.9919 | 0.0069 | 0.0087 |
| random_forest | 45 | 3.96% | 0.00% | 100.00% | 0.9992 | 0.9920 | 0.0069 | 0.0093 |
| random_forest | 44 | 1.06% | 0.00% | 100.00% | 0.9992 | 0.9920 | 0.0068 | 0.0090 |
| random_forest | 43 | 0.23% | 0.00% | 100.00% | 0.9992 | 0.9920 | 0.0068 | 0.0088 |
| isolation_forest | 43 | 0.21% | 1.06% | 1.89% | 0.4861 | 0.0851 | — | — |
| rate_bytes | 0 | 0.03% | 1.08% | 0.23% | 0.3706 | 0.0713 | — | — |
| random_forest | 42 | 0.02% | 0.00% | 100.00% | 0.9992 | 0.9918 | 0.0068 | 0.0088 |
| composite_bytes_syn | 0 | 0.01% | 1.10% | 0.10% | 0.3623 | 0.0693 | — | — |
| composite_packets_syn | 0 | 0.00% | 1.10% | 0.03% | 0.3668 | 0.0627 | — | — |
| syn | 0 | 0.00% | 0.63% | 0.05% | 0.4758 | 0.0865 | — | — |
| isolation_forest | 42 | 0.00% | 1.07% | 0.02% | 0.4903 | 0.0835 | — | — |
| isolation_forest | 44 | 0.00% | 1.08% | 0.00% | 0.4835 | 0.0846 | — | — |
| isolation_forest | 45 | 0.00% | 1.08% | 0.00% | 0.4914 | 0.0876 | — | — |
| isolation_forest | 46 | 0.00% | 1.08% | 0.00% | 0.4757 | 0.0828 | — | — |
| rate_packets | 0 | 0.00% | 0.13% | 0.00% | 0.3772 | 0.0638 | — | — |

## 5. Per-family recall at 100 alerts / 10k

| Method | Seed | DoS recall | DDoS recall |
| --- | ---: | ---: | ---: |
| logistic_regression | 42 | 0.00% | 13.14% |
| logistic_regression | 43 | 0.00% | 13.14% |
| logistic_regression | 44 | 0.00% | 13.14% |
| logistic_regression | 45 | 0.00% | 13.14% |
| logistic_regression | 46 | 0.00% | 13.14% |
| random_forest | 46 | 1.39% | 4.86% |
| random_forest | 45 | 5.38% | 3.54% |
| random_forest | 44 | 4.63% | 0.00% |
| random_forest | 43 | 0.00% | 0.30% |
| isolation_forest | 43 | 0.00% | 0.28% |
| rate_bytes | 0 | 0.04% | 0.02% |
| random_forest | 42 | 0.00% | 0.03% |
| composite_bytes_syn | 0 | 0.05% | 0.00% |
| composite_packets_syn | 0 | 0.01% | 0.00% |
| syn | 0 | 0.01% | 0.00% |
| isolation_forest | 42 | 0.00% | 0.00% |
| isolation_forest | 44 | 0.00% | 0.00% |
| isolation_forest | 45 | 0.00% | 0.00% |
| isolation_forest | 46 | 0.00% | 0.00% |
| rate_packets | 0 | 0.00% | 0.00% |

## 6. McNemar: Random Forest vs the best validation rule

The comparison rule is selected on validation only. The test labels never
influence the choice. Holm adjustment covers the two budgets and three
families (six tests).

| Budget | Family | Rule | RF recall | Rule recall | b | c | p | Holm p |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | DoS | syn | 0.00% | 0.00% | 0 | 0 | 1.0000 | 1.0000 |
| 10 | DDoS | syn | 0.03% | 0.00% | 31 | 0 | 0.0000 | 0.0000 |
| 10 | all | syn | 0.02% | 0.00% | 31 | 0 | 0.0000 | 0.0000 |
| 100 | DoS | rate_bytes | 0.00% | 0.04% | 0 | 13 | 0.0002 | 0.0007 |
| 100 | DDoS | rate_bytes | 0.03% | 0.02% | 31 | 28 | 0.7948 | 1.0000 |
| 100 | all | rate_bytes | 0.02% | 0.03% | 17437 | 41 | 0.0000 | 0.0000 |

## 7. Reading

At 100 alerts per 10,000 flows, the best method is `logistic_regression` with recall 10.12% at FPR 0.16%. Random Forest seed 42 reaches recall 0.02% at FPR 0.00%. The supervised comparison is therefore negative or mixed; it is reported as-is and not tuned on test. This is a scoped CIC-IDS-2018 DoS/DDoS result, not a PortScan or general claim.

## 8. What does not change

- Serving artifact and threshold: unchanged.
- P2B remains a **scoped external** result, not a general P2B pass.
- PortScan and scan detection remain out of scope.
- Detection and SaaS scores are unchanged.

## 9. Reproduction

```bash
venv/Scripts/python.exe scripts/p2b_scoped_external.py \
  --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete"
venv/Scripts/python.exe -m pytest tests/test_p2b_scoped_external.py -q
```

