# Probability Calibration on Held-Out Days (D5)

Generated: 2026-11-09T11:22:26.074548+00:00

## Scope

Calibration is evaluated for the binary attack score `1 - P(BENIGN)` from the frozen Random Forest bundles for seeds 42-46. Temperature scaling and isotonic regression are fitted on the Wednesday validation partition only and applied unchanged to Thursday and Friday.

Multiclass calibration is not attempted. The model has three output classes (BENIGN, FTP-Patator, SSH-Patator), while the validation partition contains BENIGN and DoS families and the test partition contains seven unseen attack families. A multiclass calibration target is not identifiable across those partitions. The binary attack score is the score used by the threshold policy, so it is the relevant calibration target.

- Validation rows: 692,686 (Wednesday)
- Test rows: 1,162,065 (Thursday 458,825; Friday 703,240)
- ECE: 10 equal-width bins, weighted by bin population.
- Brier score: mean squared error of the binary attack probability.

## Overall calibration

| Method | ECE (mean ± sd) | Brier (mean ± sd) | Log loss (mean ± sd) |
|---|---|---|---|
| uncalibrated | 0.2462 ± 0.0020 | 0.2430 ± 0.0031 | 2.0012 ± 0.3932 |
| temperature | 0.2257 ± 0.0451 | 0.1773 ± 0.0052 | 0.5426 ± 0.0110 |
| isotonic | 0.2020 ± 0.0238 | 0.1602 ± 0.0161 | 0.5067 ± 0.0370 |

The uncalibrated score is already a poor probability: its ECE is far above the 0.05 gate in the evaluation protocol. Temperature scaling and isotonic regression improve the probability scale on validation, but they do not change the ranking. The held-out ECE and Brier values below show whether the improvement transfers.

## Per-seed calibration

| Seed | Method | ECE | Brier | Log loss |
|---|---|---|---|---|
| 42 | uncalibrated | 0.2477 | 0.2452 | 2.0691 |
| 42 | temperature | 0.2493 | 0.1757 | 0.5391 |
| 42 | isotonic | 0.2075 | 0.1440 | 0.4654 |
| 43 | uncalibrated | 0.2473 | 0.2444 | 2.0707 |
| 43 | temperature | 0.2420 | 0.1760 | 0.5397 |
| 43 | isotonic | 0.2255 | 0.1514 | 0.4884 |
| 44 | uncalibrated | 0.2470 | 0.2450 | 2.2988 |
| 44 | temperature | 0.1700 | 0.1836 | 0.5558 |
| 44 | isotonic | 0.1857 | 0.1831 | 0.5584 |
| 45 | uncalibrated | 0.2427 | 0.2379 | 1.3223 |
| 45 | temperature | 0.2788 | 0.1702 | 0.5276 |
| 45 | isotonic | 0.2216 | 0.1522 | 0.4916 |
| 46 | uncalibrated | 0.2461 | 0.2427 | 2.2450 |
| 46 | temperature | 0.1884 | 0.1811 | 0.5507 |
| 46 | isotonic | 0.1698 | 0.1706 | 0.5296 |

## Reliability by day (seed 42)

| Day | Method | ECE | Brier | Rows |
|---|---|---|---|---|
| Thursday | uncalibrated | 0.0042 | 0.0041 | 458,825 |
| Thursday | temperature | 0.3319 | 0.1141 | 458,825 |
| Thursday | isotonic | 0.3567 | 0.1311 | 458,825 |
| Friday | uncalibrated | 0.4066 | 0.4025 | 703,240 |
| Friday | temperature | 0.2053 | 0.2158 | 703,240 |
| Friday | isotonic | 0.1192 | 0.1524 | 703,240 |

Thursday's uncalibrated ECE is low because Thursday is dominated by BENIGN flows and the attack prevalence is very low; a low ECE there does not mean the score is calibrated on Friday. Friday's uncalibrated ECE is 0.4066. The day-level split is the relevant comparison, not the pooled number.

Reliability diagrams:

- [Overall reliability, seed 42](figures/reliability_seed42_overall.svg)
- [Reliability by day, seed 42](figures/reliability_seed42_by_day.svg)
- [Reliability by family, seed 42](figures/reliability_seed42_by_family.svg)

## Reliability by family (seed 42)

| Family | Rows | Uncalibrated ECE | Isotonic ECE | Uncalibrated Brier | Isotonic Brier |
|---|---|---|---|---|---|
| BENIGN | 870,926 | 0.0002 | 0.3576 | 0.0000 | 0.1294 |
| Bot | 1,966 | 0.9998 | 0.6394 | 0.9995 | 0.4119 |
| DDoS | 128,027 | 0.9869 | 0.3089 | 0.9742 | 0.1603 |
| Infiltration | 36 | 0.9819 | 0.3513 | 0.9650 | 0.1926 |
| PortScan | 158,930 | 0.9918 | 0.3721 | 0.9841 | 0.2086 |
| Web Attack - Brute Force | 1,507 | 0.9217 | 0.1650 | 0.8508 | 0.0509 |
| Web Attack - Sql Injection | 21 | 0.9852 | 0.4185 | 0.9710 | 0.2437 |
| Web Attack - XSS | 652 | 0.9193 | 0.1498 | 0.8462 | 0.0394 |

Small families (Infiltration, SQL Injection) have unstable estimates. Their ECE can look good or bad because a handful of rows changes the observed frequency. Do not treat those rows as a family-level calibration guarantee.

The family table also exposes a failure that the aggregate Brier score hides: isotonic calibration fitted on Wednesday lowers overall Brier but makes BENIGN calibration much worse (ECE 0.3576) because the validation day contains DoS attacks that the model scores in the same range as benign test flows. Aggregate calibration is not family-level calibration. Do not present a single calibrated confidence number as if it were valid for every family.

## Decision-curve analysis (seed 42)

| Threshold probability | Uncalibrated net benefit | Temperature net benefit | Isotonic net benefit | Treat all |
|---|---|---|---|---|
| 0.01 | 0.0597 | 0.2430 | 0.2430 | 0.2430 |
| 0.02 | 0.0223 | 0.2352 | 0.2352 | 0.2352 |
| 0.05 | 0.0085 | 0.2111 | 0.2111 | 0.2111 |
| 0.10 | 0.0009 | 0.1673 | 0.1673 | 0.1673 |
| 0.15 | 0.0005 | 0.1183 | 0.1183 | 0.1183 |
| 0.20 | 0.0004 | 0.0632 | 0.0632 | 0.0632 |
| 0.25 | 0.0002 | 0.0007 | 0.0007 | 0.0007 |
| 0.30 | 0.0001 | -0.0707 | -0.0707 | -0.0707 |
| 0.40 | 0.0000 | 0.1355 | 0.1396 | -0.2491 |
| 0.50 | 0.0000 | 0.0000 | 0.1382 | -0.4989 |

The decision curve is a net-benefit view, not a deployment policy. It assumes the stated threshold probability is the clinically or operationally relevant trade-off. For a security queue, the more useful operational control is the alert budget, which is rank-based and therefore unchanged by monotonic calibration.

## Interaction with the threshold and alert budget

Temperature scaling and isotonic regression are monotonic transformations. They change the probability values and the numeric threshold, but not the ordering of flows. Consequences:

1. A top-K alert budget selects the same flows before and after calibration. Calibration does not fix the alert-volume problem.
2. A probability-threshold policy must reselect its threshold on calibrated validation scores. Keeping the uncalibrated threshold after calibration changes the operating point.
3. A calibrated probability is only meaningful if the calibration artifact is versioned and linked to the model artifact and feature schema. The serving path must not display a confidence value unless that link exists.

Threshold interaction by seed:

| Seed | Method | Uncalibrated threshold | Reselected threshold | Test FPR at reselected | Test FPR with uncalibrated threshold |
|---|---|---|---|---|---|
| 42 | temperature | 0.00251505 | 0.42576547 | 0.73% | 100.00% |
| 42 | isotonic | 0.00251505 | 0.88384652 | 0.55% | 100.00% |
| 43 | temperature | 0.00185520 | 0.42204178 | 0.99% | 100.00% |
| 43 | isotonic | 0.00185520 | 0.76541632 | 0.64% | 100.00% |
| 44 | temperature | 0.00936364 | 0.44199306 | 6.90% | 100.00% |
| 44 | isotonic | 0.00936364 | 0.81767416 | 6.90% | 100.00% |
| 45 | temperature | 0.01000000 | 0.44281198 | 7.85% | 100.00% |
| 45 | isotonic | 0.01000000 | 0.78178149 | 7.85% | 100.00% |
| 46 | temperature | 0.00712097 | 0.43859181 | 4.07% | 100.00% |
| 46 | isotonic | 0.00712097 | 0.86250001 | 4.00% | 100.00% |

The reselected thresholds preserve the decisions because the transformations are monotonic. The last column shows what happens when the uncalibrated threshold is left in place: the operating point changes. That is a versioning failure, not a calibration improvement.

Ranking invariance (Spearman correlation with the uncalibrated score):

| Seed | Temperature | Isotonic |
|---|---|---|
| 42 | 0.988100 | 0.941060 |
| 43 | 1.000000 | 0.952696 |
| 44 | 1.000000 | 0.945554 |
| 45 | 1.000000 | 0.963881 |
| 46 | 1.000000 | 0.996603 |

Spearman is below 1.0 where the transformation creates ties or isotonic plateaus; the ordering is preserved up to those ties. A top-K budget selects the same set except for tie-breaking at the cut point. Calibration does not create new separability.

## Serving path and UI

The serving artifact is the evaluated Random Forest bundle `models/model_bundle_rf_day_based_seed42.pkl` (registry-active `serving-rf-day-based-seed42-v1`, SHA-256 `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`). It is registered as `uncalibrated` because the available isotonic calibration artifact has held-out ECE ≈0.208 and fails the 0.05 gate. The console therefore does not show a confidence percentage. It may show the thresholded decision, the threshold policy, and the model/artifact provenance. The D5 calibration artifacts describe this RF configuration, but their held-out results still fail the gate.

## Honest conclusion

- The uncalibrated attack score is not a probability an analyst should trust.
- Temperature scaling and isotonic regression improve validation calibration, but their held-out ECE must be read from the tables above; they do not solve the day shift.
- Calibration does not change the ranking or the alert budget. It changes the probability scale and the numeric threshold.
- The UI must not show a confidence value until the serving artifact has its own calibration artifact linked to its hash and feature schema.

## Reproduction

```bash
python -m training.threshold_calibration_v2 --force
pytest tests -q
```

Artifacts: `docs\CALIBRATION_V2.md`, `docs/calibration_v2.json`, and `models/calibration_rf_day_based_seed*.json`.
