# D6 — Rare and Unseen Attack Families, Botnet Priority

**Status:** **complete and negative.** No predeclared arm raises Bot recall to the 0.50 minimum gate at the ≤1% false-positive gate. The detection score does **not** move.
**Date:** 2026-11-10.
**Protocol:** [`D6_EXPERIMENT_PROTOCOL.md`](D6_EXPERIMENT_PROTOCOL.md) (predeclared before the run).
**Machine-readable result:** [`d6_unseen_family_results.json`](d6_unseen_family_results.json).
**Runner:** `training/d6_unseen_family.py`.
**Run log:** [`d6_run.log`](d6_run.log) — exit code 0, 2,276.2 s.

## 1. Verdict in one table

| Question | Answer |
| --- | --- |
| Did any arm reach Bot recall ≥ 0.50 at ≤1% test FPR? | **No.** |
| Did any arm reach the desired Bot recall ≥ 0.70? | **No.** |
| Did any arm keep test FPR ≤ 1% on every seed and every day? | **No.** |
| Did any arm combine a ≤2% alert rate with useful recall? | **No.** C1 meets the alert budget at 0.73% ± 0.37% but detects only 0.41% of attacks. |
| Did any arm reach ECE ≤ 0.05? | **No.** |
| Is there a stable improvement over the frozen reference? | **No.** The only arm with materially higher mean Bot recall (B) breaks the FPR, alert-rate, and calibration gates and has a 0.02–0.47 seed spread. |
| Does this support a rare-family or zero-day detection claim? | **No.** |
| Does the detection score change? | **No. Detection remains 4/10.** |

This is the honest negative outcome that the protocol allowed. It is not a failed implementation; it is the experiment working as intended and rejecting the hypothesis.

## 2. What was tested

The existing day-based CIC-IDS-2017 partition was reused unchanged:

| Partition | Files | Rows | Use |
| --- | --- | ---: | --- |
| Train | Monday + Tuesday | 975,789 | Fit preprocessing and model |
| Validation | Wednesday | 692,686 | Threshold, calibration, hybrid weight only |
| Final test | Thursday + Friday | 1,162,065 | Report once; no tuning |

Training attack labels are only `FTP-Patator` and `SSH-Patator`. Validation adds DoS families. The final test adds `Bot`, `DDoS`, `PortScan`, `Infiltration`, and Web Attacks. **Every final-test family is unseen in training, and Bot is unseen in validation.** That is the intended condition.

All retrained arms use the same memory-safe sample declared in the protocol: all 13,835 training attack rows plus 199,941 usable benign rows from a 200,000-row deterministic draw (seed 42), for 213,776 rows total. The frozen full-data Random Forest is arm **R**, scored from `models/eval_cache/`, so the cost of the subsample is visible.

**Comparability note.** The retrained arms score 1,450,815 Thursday+Friday rows (579,741 attacks, 871,074 benign), while the cached reference and the D9 cost model use the 1,162,065-row deduplicated partition. Rates are comparable; absolute alert counts between arms are not. This report therefore compares rates, and the D9 report uses the reference partition.

Predeclared gates:

| Gate | Target |
| --- | --- |
| Test FPR at the frozen threshold | ≤ 1% |
| Alert rate | ≤ 2% of flows |
| Bot recall | ≥ 0.50 minimum, ≥ 0.70 desired |
| Calibration | ECE ≤ 0.05 |
| Differential vs reference | Direction and seed spread reported; no unstable margin called an improvement |

## 3. Overall results (five seeds: 42–46, mean ± sample std)

| Arm | Test FPR | Recall | Precision | Alert rate | PR-AUC | ECE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| **R** full-data RF reference | 0.0411 ± 0.0327 | 0.5830 ± 0.1479 | 0.8367 ± 0.1164 | 0.1768 ± 0.0512 | 0.6432 ± 0.0886 | 0.2500 ± 0.0383 |
| **A** class weighting | 0.0186 ± 0.0172 | 0.2855 ± 0.2800 | 0.8977 ± 0.0606 | 0.1253 ± 0.1158 | 0.7023 ± 0.1801 | 0.2069 ± 0.1478 |
| **B** family-aware augmentation | 0.0865 ± 0.0137 | 0.6054 ± 0.3040 | 0.7930 ± 0.0948 | 0.2939 ± 0.1244 | 0.7379 ± 0.1331 | 0.1790 ± 0.0849 |
| **C1** Isolation Forest (primary open-set) | 0.0095 ± 0.0046 | 0.0041 ± 0.0031 | 0.1772 ± 0.1240 | 0.0073 ± 0.0037 | 0.3895 ± 0.0108 | 0.2878 ± 0.0112 |
| **C2** PCA reconstruction | 0.0227 ± 0.0000 | 0.1154 ± 0.0000 | 0.7719 ± 0.0000 | 0.0597 ± 0.0000 | 0.5373 ± 0.0000 | 0.2069 ± 0.0000 |
| **C3** Mahalanobis | 0.0243 ± 0.0000 | 0.1261 ± 0.0000 | 0.7751 ± 0.0000 | 0.0650 ± 0.0000 | 0.8009 ± 0.0000 | 0.1583 ± 0.0000 |
| **D** hybrid supervised + C1 | 0.0132 ± 0.0017 | 0.1235 ± 0.0768 | 0.7123 ± 0.3753 | 0.0573 ± 0.0308 | 0.6148 ± 0.1425 | 0.2232 ± 0.0313 |

C2 and C3 are deterministic once the fixed sample is set, so their seed std is zero by construction. They are sensitivity arms and cannot replace a negative A/B/C1 result.

Only C1 keeps mean FPR below 1% (0.95% ± 0.46%), and it detects almost nothing (recall 0.41%). R's mean FPR is 4.11%, with two seeds below 1% but seeds 44 and 45 reaching 6.9% and 7.8%; A (1.86%) and D (1.32%) are also above the 1% gate. No arm combines low FPR with useful recall.

## 4. Bot results — the predeclared primary family

Bot support in the test partition is **1,966 flows**, enough to estimate recall, though not enough for narrow intervals on rare sub-behaviours.

| Arm | Bot recall mean ± std | Per-seed Bot recall | Bot at 50 alerts/10k | Bot at 100 alerts/10k |
| --- | ---: | --- | ---: | ---: |
| **R** reference | **0.0094 ± 0.0082** | 0.0112, 0.0031, 0.0005, 0.0107, 0.0214 | 0.0000 | 0.0001 |
| **A** class weighting | 0.0027 ± 0.0061 | 0.0000, 0.0000, 0.0137, 0.0000, 0.0000 | 0.0000 | 0.0000 |
| **B** family-aware augmentation | **0.2069 ± 0.1659** | 0.1144, 0.2157, 0.0224, 0.4664, 0.2157 | 0.0000 | 0.0003 |
| **C1** Isolation Forest | 0.0000 ± 0.0000 | 0.0000, 0.0000, 0.0000, 0.0000, 0.0000 | 0.0000 | 0.0008 |
| **C2** PCA reconstruction | 0.0219 ± 0.0000 | 0.0219 (all seeds) | 0.0020 | 0.0041 |
| **C3** Mahalanobis | 0.0224 ± 0.0000 | 0.0224 (all seeds) | 0.0020 | 0.0051 |
| **D** hybrid | 0.0062 ± 0.0086 | 0.0000, 0.0173, 0.0137, 0.0000, 0.0000 | 0.0045 | 0.0049 |

**B is the only arm with a non-trivial Bot signal, and it fails the operating constraints.** Its mean Bot recall is 0.2069, still below the 0.50 minimum, and the seed spread is 0.0224–0.4664. It also produces an 8.65% mean test FPR and a 29.4% alert rate. That is roughly **865 false positives per 10,000 benign flows**. At a fixed 100-alert budget it detects 0.03% of Bot flows. The apparent Bot gain is therefore bought with an unusable alert volume and is not a deployable improvement.

The open-set arms (C1–C3) are the strongest evidence against the simple hypothesis that "benign-only novelty will catch Bot". C1 detects **zero** Bot flows at the frozen threshold across all five seeds (0.08% at a 100-alert budget). C2 and C3 detect about 2.2% at the threshold and 0.4–0.5% at a 100-alert budget. Anomaly scores are dominated by other traffic differences, not by botnet behaviour.

## 5. Per-family results

### 5.1 Frozen reference R

| Family | Support | Recall mean ± std | Seen in training |
| --- | ---: | ---: | --- |
| Bot | 1,966 | 0.0094 ± 0.0082 | no |
| DDoS | 128,027 | 0.6095 ± 0.0621 | no |
| Infiltration | 36 | 0.3667 ± 0.1169 | no (descriptive only) |
| PortScan | 158,930 | 0.5642 ± 0.2533 | no |
| Web Attack — Brute Force | 1,507 | 0.9214 ± 0.0221 | no |
| Web Attack — SQL Injection | 21 | 0.3905 ± 0.0621 | no (descriptive only) |
| Web Attack — XSS | 652 | 0.9433 ± 0.0091 | no |

The reference is not a uniformly weak model. It detects Web Attacks well and PortScan/DDoS moderately. The failure is concentrated in **Bot**, which is also the stealthiest family and the one the phase prioritised. A detector can look respectable on aggregate recall while missing the family that matters most for this question.

### 5.2 Arm B (the only arm with a Bot gain)

| Family | Support | Recall mean ± std |
| --- | ---: | ---: |
| Bot | 1,966 | 0.2069 ± 0.1659 |
| DDoS | 128,027 | 0.1938 ± 0.2539 |
| Infiltration | 36 | 0.3278 ± 0.1152 (descriptive) |
| PortScan | 158,930 | 0.9478 ± 0.0917 |

B improves PortScan and Bot but collapses DDoS recall. It is not a broad improvement; it shifts the error profile. That shift is consistent with augmentation inside the two known brute-force families widening the attack manifold toward scan-like traffic, not toward botnet command-and-control.

### 5.3 Unsupported families

Infiltration (36 flows) and SQL Injection (21 flows) are below the protocol's 30–99 descriptive band. They are reported for completeness and are **not** recall claims. No conclusion should be drawn from them.

## 6. Day-level results

The frozen Wednesday threshold does not transfer cleanly to Thursday and Friday. This is the same pathology documented in [`THRESHOLD_POLICY_V2.md`](THRESHOLD_POLICY_V2.md), now visible inside the D6 arms.

| Arm | Thursday FPR | Thursday recall | Friday FPR | Friday recall | Friday Bot |
| --- | ---: | ---: | ---: | ---: | ---: |
| R | 0.0728 ± 0.0617 | 0.9138 ± 0.0179 | 0.0061 ± 0.0024 | 0.5805 ± 0.1489 | 0.0094 |
| A | 0.0269 ± 0.0309 | 0.2050 ± 0.4439 | 0.0095 ± 0.0052 | 0.3666 ± 0.1854 | 0.0027 |
| B | 0.1448 ± 0.0036 | 0.6022 ± 0.5435 | 0.0223 ± 0.0249 | 0.6086 ± 0.1382 | 0.2069 |
| C1 | 0.0016 ± 0.0005 | 0.0000 ± 0.0000 | 0.0181 ± 0.0091 | 0.0081 ± 0.0062 | 0.0000 |
| C2 | 0.0044 ± 0.0000 | 0.0000 ± 0.0000 | 0.0428 ± 0.0000 | 0.2315 ± 0.0000 | 0.0219 |
| C3 | 0.0051 ± 0.0000 | 0.0000 ± 0.0000 | 0.0456 ± 0.0000 | 0.2529 ± 0.0000 | 0.0224 |
| D | 0.0059 ± 0.0048 | 0.0028 ± 0.0036 | 0.0212 ± 0.0058 | 0.2450 ± 0.1514 | 0.0062 |

Consequences:

- The reference's high aggregate recall is largely Thursday recall. On Friday it falls to 0.58 and Bot recall is 0.94%.
- B is the only arm with meaningful Friday Bot recall (20.7%), but Friday FPR is still 2.2% on average and Thursday FPR is 14.5%.
- C1–C3 detect almost nothing on Thursday. Their Friday signal is not transferable detection; it is a day-specific score shift.
- No arm has a stable, low-FPR operating point on both days. A pooled five-seed mean hides this, which is why the per-day table is mandatory.

## 7. Calibration

No arm reaches ECE ≤ 0.05. The best mean is C3 at 0.158, still more than three times the gate; the reference is 0.250. Calibration on Wednesday does not survive the Thursday/Friday distribution shift. Since the served Random Forest is also explicitly uncalibrated, this is a cross-cutting failure, not just a D6 artefact. See [`CALIBRATION_V2.md`](CALIBRATION_V2.md).

## 8. Why the hypothesis failed

1. **The label signal is too thin.** Training contains only two brute-force families. A supervised model can separate "brute force" from benign, but that boundary is not the botnet boundary.
2. **Bot traffic overlaps benign traffic in these 80 features.** Flow-level duration, packet counts, and inter-arrival summaries for botnet C2 can look like ordinary periodic or long-lived sessions. The model has no label or feature that encodes command-and-control semantics.
3. **Benign-only novelty is the wrong detector for this shift.** C1 flags outliers in the benign manifold. Bot flows are not necessarily far from the benign manifold in this feature space; when novelty does fire, it fires on other families.
4. **Augmentation inside known families cannot invent a new family.** Interpolating FTP/SSH brute-force rows broadens that manifold, not the Bot manifold. The small Bot gain in B is an incidental shift in the decision boundary, with a large false-positive cost.
5. **The threshold transfer problem dominates.** A threshold chosen on Wednesday does not preserve 1% FPR on Thursday/Friday. Even a better-ranked model would still need per-day calibration or a different operating policy.

## 9. What the result means for the score

Detection remains **4/10**. This experiment adds real held-out evidence, but the evidence is negative. It rules out several cheap fixes:

- class weighting does not fix rare-family recall;
- within-family augmentation does not fix unseen-family recall;
- benign-only Isolation Forest, PCA, and Mahalanobis novelty do not catch Bot;
- a validation-selected hybrid of supervised and novelty scores does not either.

What it does **not** rule out:

- a different feature set with protocol semantics, beaconing/periodicity, TLS/SNI or DNS features, and host-level context;
- training on actual botnet traffic from an independent capture (Bot-IoT, ToN-IoT, or a consented site capture);
- sequence/window models over multiple flows rather than single-flow tabular classifiers;
- per-day or per-site calibration with a measured false-positive budget;
- an analyst-in-the-loop triage model optimised for a fixed alert budget rather than a global threshold.

Any of those would need a new predeclared experiment and new held-out evidence. None of them is implemented here, so none of them can be claimed.

## 10. Reproduction

```bash
venv/Scripts/python.exe training/d6_unseen_family.py \
  --seeds 42,43,44,45,46 \
  --output docs/d6_unseen_family_results.json
```

Expected runtime on the 8 GB development machine: about 38 minutes. The runner uses only Wednesday labels for threshold, calibration, and hybrid-weight selection. If the result is disappointing, the protocol forbids changing the arm, feature, threshold, calibration, or blend in response and re-reporting only the better run.

## 11. Limitations

- One dataset (CIC-IDS-2017), one lab, one feature extractor, and an 80-feature flow schema.
- The retrained arms use a 213,776-row sample, not the full 975,789-row training partition. The reference arm is full-data, so arm-to-arm absolute counts differ.
- Bot support is 1,966 flows. The confidence interval on Bot recall is wide; the conclusion is "far below the gate", not a precise recall estimate.
- Thursday and Friday are pooled in the primary aggregate, with a per-day breakdown reported above.
- Test duplicates remain in the retrained-arm partition because the full test rows are used. The reference partition is deduplicated. This is a declared deviation, not a hidden one.
- No external dataset, no real botnet capture, and no human labels were available. See [`EXTERNAL_VALIDATION.md`](EXTERNAL_VALIDATION.md).
- This is a detection experiment, not a claim that Bot flows can be attributed to a botnet or a campaign.

## 12. Decision

**Do not claim rare-family, unseen-family, zero-day, or botnet detection capability.** Do not raise the detection score. The correct next step is a new feature and data programme (protocol/DNS/TLS/periodicity features plus an independent botnet capture) with a new predeclared protocol, not another threshold sweep on the same features.
