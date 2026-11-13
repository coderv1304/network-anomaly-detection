# Threshold Policy Across Day Shift (D4)

Generated: 2026-11-09T11:22:26.071183+00:00

## What was measured

One attack-score threshold per seed was selected on the Wednesday validation partition at a maximum false-positive rate of 1%. The threshold was then applied unchanged to Thursday and Friday. No test label was used to choose a threshold.

- Validation rows: 692,686 (Wednesday)
- Test rows: 1,162,065 (Thursday 458,825; Friday 703,240)
- Seeds: 42, 43, 44, 45, 46
- Attack score: `1 - P(BENIGN)` from the frozen Random Forest bundle.

The primary policy is the global validation threshold. The per-predicted-class and day-aware policies are comparisons, not replacements selected on test.

## Primary global policy

| Seed | Validation FPR | Validation TPR | Test FPR | Recall | Precision | Alert rate | Alerts |
|---|---|---|---|---|---|---|---|
| 42 | 0.52% | 4.59% | 0.73% | 57.94% | 96.39% | 15.06% | 175,012 |
| 43 | 0.92% | 3.26% | 0.99% | 56.10% | 94.97% | 14.80% | 171,980 |
| 44 | 0.36% | 2.97% | 6.90% | 46.78% | 69.40% | 16.89% | 196,258 |
| 45 | 0.34% | 2.80% | 7.85% | 83.19% | 77.99% | 26.72% | 310,553 |
| 46 | 0.43% | 4.49% | 4.07% | 47.48% | 79.59% | 14.95% | 173,678 |

The validation target does not transfer. The five-seed mean test FPR is 4.11% with a standard deviation of 3.27%. The worst seed is 7.85%.

Per-family recall at the frozen threshold, by seed:

| Family | Seed 42 | Seed 43 | Seed 44 | Seed 45 | Seed 46 |
|---|---|---|---|---|---|
| Bot | 1.12% | 0.31% | 0.05% | 1.07% | 2.14% |
| DDoS | 63.56% | 63.94% | 49.84% | 63.65% | 63.73% |
| Infiltration | 55.56% | 38.89% | 25.00% | 33.33% | 30.56% |
| PortScan | 53.66% | 49.96% | 44.30% | 99.81% | 34.35% |
| Web Attack - Brute Force | 90.71% | 94.43% | 90.25% | 94.69% | 90.64% |
| Web Attack - Sql Injection | 42.86% | 38.10% | 28.57% | 42.86% | 42.86% |
| Web Attack - XSS | 93.56% | 94.79% | 93.71% | 95.71% | 93.87% |

## Per-day results at the frozen threshold

The aggregate test FPR hides day-level breaches. For seed 42 the aggregate FPR is 0.73%, but Thursday alone is 1.06%. The threshold is not stable within the held-out period, let alone across seeds.

### Seed 42

| Day | Flows | FPR | Recall | Precision | Alert rate | Alerts |
|---|---|---|---|---|---|---|
| Thursday | 458,825 | 1.06% | 90.52% | 29.38% | 1.49% | 6,828 |
| Friday | 703,240 | 0.36% | 57.69% | 99.11% | 23.92% | 168,184 |

Per-family recall by day:

| Day | Family | Support | Detected | Recall |
|---|---|---|---|---|
| Thursday | Infiltration | 36 | 20 | 55.56% |
| Thursday | Web Attack - Brute Force | 1,507 | 1,367 | 90.71% |
| Thursday | Web Attack - Sql Injection | 21 | 9 | 42.86% |
| Thursday | Web Attack - XSS | 652 | 610 | 93.56% |
| Friday | Bot | 1,966 | 22 | 1.12% |
| Friday | DDoS | 128,027 | 81,380 | 63.56% |
| Friday | PortScan | 158,930 | 85,286 | 53.66% |

### Seed 43

| Day | Flows | FPR | Recall | Precision | Alert rate | Alerts |
|---|---|---|---|---|---|---|
| Thursday | 458,825 | 1.14% | 93.10% | 28.45% | 1.58% | 7,251 |
| Friday | 703,240 | 0.84% | 55.82% | 97.90% | 23.42% | 164,729 |

Per-family recall by day:

| Day | Family | Support | Detected | Recall |
|---|---|---|---|---|
| Thursday | Infiltration | 36 | 14 | 38.89% |
| Thursday | Web Attack - Brute Force | 1,507 | 1,423 | 94.43% |
| Thursday | Web Attack - Sql Injection | 21 | 8 | 38.10% |
| Thursday | Web Attack - XSS | 652 | 618 | 94.79% |
| Friday | Bot | 1,966 | 6 | 0.31% |
| Friday | DDoS | 128,027 | 81,863 | 63.94% |
| Friday | PortScan | 158,930 | 79,396 | 49.96% |

### Seed 44

| Day | Flows | FPR | Recall | Precision | Alert rate | Alerts |
|---|---|---|---|---|---|---|
| Thursday | 458,825 | 12.53% | 89.62% | 3.36% | 12.90% | 59,184 |
| Friday | 703,240 | 0.69% | 46.45% | 97.91% | 19.49% | 137,074 |

Per-family recall by day:

| Day | Family | Support | Detected | Recall |
|---|---|---|---|---|
| Thursday | Infiltration | 36 | 9 | 25.00% |
| Thursday | Web Attack - Brute Force | 1,507 | 1,360 | 90.25% |
| Thursday | Web Attack - Sql Injection | 21 | 6 | 28.57% |
| Thursday | Web Attack - XSS | 652 | 611 | 93.71% |
| Friday | Bot | 1,966 | 1 | 0.05% |
| Friday | DDoS | 128,027 | 63,808 | 49.84% |
| Friday | PortScan | 158,930 | 70,405 | 44.30% |

### Seed 45

| Day | Flows | FPR | Recall | Precision | Alert rate | Alerts |
|---|---|---|---|---|---|---|
| Thursday | 458,825 | 14.22% | 93.50% | 3.09% | 14.60% | 66,995 |
| Friday | 703,240 | 0.82% | 83.12% | 98.60% | 34.63% | 243,558 |

Per-family recall by day:

| Day | Family | Support | Detected | Recall |
|---|---|---|---|---|
| Thursday | Infiltration | 36 | 12 | 33.33% |
| Thursday | Web Attack - Brute Force | 1,507 | 1,427 | 94.69% |
| Thursday | Web Attack - Sql Injection | 21 | 9 | 42.86% |
| Thursday | Web Attack - XSS | 652 | 624 | 95.71% |
| Friday | Bot | 1,966 | 21 | 1.07% |
| Friday | DDoS | 128,027 | 81,495 | 63.65% |
| Friday | PortScan | 158,930 | 158,624 | 99.81% |

### Seed 46

| Day | Flows | FPR | Recall | Precision | Alert rate | Alerts |
|---|---|---|---|---|---|---|
| Thursday | 458,825 | 7.45% | 90.16% | 5.55% | 7.85% | 36,030 |
| Friday | 703,240 | 0.34% | 47.15% | 98.97% | 19.57% | 137,648 |

Per-family recall by day:

| Day | Family | Support | Detected | Recall |
|---|---|---|---|---|
| Thursday | Infiltration | 36 | 11 | 30.56% |
| Thursday | Web Attack - Brute Force | 1,507 | 1,366 | 90.64% |
| Thursday | Web Attack - Sql Injection | 21 | 9 | 42.86% |
| Thursday | Web Attack - XSS | 652 | 612 | 93.87% |
| Friday | Bot | 1,966 | 42 | 2.14% |
| Friday | DDoS | 128,027 | 81,591 | 63.73% |
| Friday | PortScan | 158,930 | 54,593 | 34.35% |

## Policy comparison

The table reports the five-seed mean and standard deviation of test FPR, recall, precision, and alert rate. The global policy is the only policy selected entirely on validation and applied unchanged to every test day.

| Policy | FPR | Recall | Precision | Alert rate |
|---|---|---|---|---|
| Global validation threshold | 4.11% ± 3.27% | 58.30% ± 14.79% | 83.67% ± 11.64% | 17.68% ± 5.12% |
| Per-predicted-class threshold | 4.11% ± 3.27% | 58.30% ± 14.79% | 83.67% ± 11.64% | 17.68% ± 5.12% |
| Day-aware score quantile | 2.96% ± 2.39% | 15.66% ± 7.96% | 66.71% ± 16.00% | 6.14% ± 3.20% |
| RF argmax (no threshold) | 0.00% ± 0.00% | 0.00% ± 0.00% | 0.00% ± 0.00% | 0.00% ± 0.00% |

The RF argmax row is all zeros because the evaluated Random Forest only learned `BENIGN`, `FTP-Patator`, and `SSH-Patator`, and the Thursday/Friday test partition contains none of the latter two. Argmax therefore predicts `BENIGN` for every test flow. That is a multiclass label-coverage failure, not a working detector; it is why the binary attack-score threshold exists at all.

### Per-predicted-class policy

This policy selects a threshold for each predicted class (BENIGN, FTP-Patator, SSH-Patator) on validation. It is label-free at serving time because the predicted class is available. It is not a per-true-family policy: the test attack families are unseen.

Seed 42: `BENIGN` = 0.00251505 (validation); `FTP-Patator` = 0.00251505 (global fallback); `SSH-Patator` = 0.00251505 (global fallback)
Seed 43: `BENIGN` = 0.00185520 (validation); `FTP-Patator` = 0.00185520 (global fallback); `SSH-Patator` = 0.00185520 (global fallback)
Seed 44: `BENIGN` = 0.00936364 (validation); `FTP-Patator` = 0.00936364 (global fallback); `SSH-Patator` = 0.00936364 (global fallback)
Seed 45: `BENIGN` = 0.01000000 (validation); `FTP-Patator` = 0.01000000 (global fallback); `SSH-Patator` = 0.01000000 (global fallback)
Seed 46: `BENIGN` = 0.00712097 (validation); `FTP-Patator` = 0.00712097 (global fallback); `SSH-Patator` = 0.00712097 (global fallback)

In this split the policy collapses to the global policy: the Wednesday validation partition contains BENIGN and DoS families, so the model never predicts FTP-Patator or SSH-Patator there. Both class-specific thresholds therefore fall back to the global threshold. A genuine per-predicted-class policy would need validation data that exercises those predicted classes.

### Per-true-family policy

Not applicable. A per-family threshold can only be selected for a family that appears in validation with both benign and attack rows. The held-out test attack families are different from the validation attack families, so there is no validation-selected threshold to apply.

- Validation families: BENIGN, DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris, Heartbleed
- Test families: BENIGN, Bot, DDoS, Infiltration, PortScan, Web Attack - Brute Force, Web Attack - Sql Injection, Web Attack - XSS
- Overlap: BENIGN

### Day-aware score-quantile policy

This policy uses the validation-selected alert rate and takes that quantile of each test day's unlabeled score distribution. It is label-free but not a frozen threshold: it adapts to the test day's score distribution. It is reported as an operational alternative, not as a validation-selected policy.

| Seed | Validation alert rate | Thursday threshold | Friday threshold | Test FPR | Recall | Alerts |
|---|---|---|---|---|---|---|
| 42 | 2.00% | 0.00077790 | 0.04000000 | 1.02% | 7.66% | 31,176 |
| 43 | 1.77% | 0.00155327 | 0.03000000 | 0.75% | 11.96% | 41,337 |
| 44 | 1.31% | 0.01000000 | 0.03000000 | 6.59% | 20.61% | 117,387 |
| 45 | 1.24% | 0.03000000 | 0.04000000 | 2.56% | 27.05% | 101,059 |
| 46 | 1.91% | 0.01000000 | 0.05000000 | 3.88% | 11.01% | 65,850 |

The day-aware policy keeps the alert rate near the validation rate, but it does not hold the false-positive rate: seed 44 still reaches 6.59% FPR. It also gives up most recall because it spends the budget on the highest-scoring flows, which are dominated by DDoS and PortScan. It is a label-free operational control, not a fix for threshold transfer.

## Operational cost when the threshold does not transfer

Assumption: 5 analyst minutes per alert. The cost below is the measured alert volume and false-positive volume at the frozen threshold, not a staffing recommendation.

| Seed | Day | Alerts | False positives | FPR | Excess FPR over 1% | Alert review hours | FP review hours |
|---|---|---|---|---|---|---|---|
| 42 | Thursday | 6,828 | 4,822 | 1.06% | 0.06% | 569.0 | 401.8 |
| 42 | Friday | 168,184 | 1,496 | 0.36% | 0.00% | 14015.3 | 124.7 |
| 43 | Thursday | 7,251 | 5,188 | 1.14% | 0.14% | 604.2 | 432.3 |
| 43 | Friday | 164,729 | 3,464 | 0.84% | 0.00% | 13727.4 | 288.7 |
| 44 | Thursday | 59,184 | 57,198 | 12.53% | 11.53% | 4932.0 | 4766.5 |
| 44 | Friday | 137,074 | 2,860 | 0.69% | 0.00% | 11422.8 | 238.3 |
| 45 | Thursday | 66,995 | 64,923 | 14.22% | 13.22% | 5582.9 | 5410.2 |
| 45 | Friday | 243,558 | 3,418 | 0.82% | 0.00% | 20296.5 | 284.8 |
| 46 | Thursday | 36,030 | 34,032 | 7.45% | 6.45% | 3002.5 | 2836.0 |
| 46 | Friday | 137,648 | 1,422 | 0.34% | 0.00% | 11470.7 | 118.5 |

The highest measured cost is not a small calibration error. At the worst seed and day, the frozen threshold generates tens of thousands of false positives, which is thousands of analyst hours at five minutes per alert. That is the operating cost of claiming a 1% FPR bound without a policy that transfers.

False-positive rate is not the whole cost. On Friday the attack prevalence is high, so the same threshold produces more than 160,000 alerts for every seed even when the measured FPR is below 1%. At five minutes per alert that is over 13,000 review hours per day. The operating cost includes alert volume, not only false positives.

## Serving-path decision

The serving bundle is now the evaluated seed 42 Random Forest (`models/model_bundle_rf_day_based_seed42.pkl`, registry-active `serving-rf-day-based-seed42-v1`). It contains `attack_threshold=0.002515048908954043` and `threshold_selection_max_fpr=0.01`. The serving path now applies that attack-score threshold and records the decision basis, threshold, artifact hash, feature-schema version, model version, and calibration version on every stored prediction. The raw argmax label is stored separately so the threshold decision is auditable.

## Honest conclusion

- A threshold selected on Wednesday validation does not preserve a 1% FPR on Thursday and Friday.
- Seed 42 is not representative. Reporting only seed 42 hides the five-seed spread and the worst-case operating cost.
- Per-predicted-class thresholds are implementable but do not solve the unseen-family problem.
- A day-aware quantile policy can hold an alert-rate budget, but it is not a validation-selected threshold and it uses each day's unlabeled score distribution.
- The serving artifact is now the evaluated artifact. The threshold policy is applied to the same seed 42 RF bytes, which still have only three output classes and still fail the FPR, alert-rate, Bot-recall, calibration, external, and pilot gates.

## Reproduction

```bash
python -m training.threshold_calibration_v2 --force
pytest tests -q
```

Artifacts: `docs\THRESHOLD_POLICY_V2.md` and `docs/threshold_policy_v2.json`.
