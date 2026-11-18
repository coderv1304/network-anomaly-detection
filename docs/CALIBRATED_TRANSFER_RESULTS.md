# Calibrated Cross-Dataset Transfer (Phase 1/2)

**Generated:** 2026-11-17T02:54:28.127278+00:00  
**Artifact:** `calibrated-transfer-v1`  
**Feature schema:** 8 portable-ratio features (`50b17ff0342dafe9...`)  
**Seed:** 42  
**Serving artifact:** `model_bundle_rf_day_based_seed42.pkl` unchanged (`fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`)

## 1. Protocol feasibility

The requested split trains on **Monday, Tuesday**, calibrates on **Wednesday**, and tests on **Thursday, Friday**.

| Partition | Rows | Benign | In-scope positive |
|---|---:|---:|---:|
| Monday-Tuesday (requested train) | 915770 | 915770 | 0 |

**Strict protocol fittable:** **no**. Monday-Tuesday contains zero in-scope positive rows: Monday is benign-only and Tuesday carries only FTP/SSH Patator, which the frozen policy excludes. A supervised classifier cannot be fitted.

**Executed protocol:** `wednesday_group_split_fallback`. Train: 1268799 rows (1132173 benign / 136626 positive). Calibration: 180552 rows (123430 benign / 57122 positive). Test: 1023182 rows (804347 benign / 218835 positive).

> **Protocol deviation.** The literal Monday-Tuesday training split has zero in-scope positives, so it cannot fit either candidate. Wednesday groups were split 70/30 by a deterministic group hash (group key: source and destination IP/port plus transport protocol plus normalised label), 70% joined the Monday-Tuesday benign rows in training and 30% formed a disjoint calibration partition. Thursday-Friday and every external dataset were never used for fitting or threshold selection.

Training/calibration group overlap: **0**. Thursday-Friday and external rows were never used for fitting or threshold selection.

## 2. Operating thresholds from Wednesday benign scores

| Model | Target FPR | Threshold | Realized benign FPR | Benign max | Saturated |
|---|---:|---:|---:|---:|---:|
| A | 0.005 | 0.4655 | 0.00292 | 1.0000 | no |
| A | 0.001 | 0.9997 | 0.00071 | 1.0000 | yes |
| B | 0.005 | 0.1647 | 0.00346 | 0.9959 | no |
| B | 0.001 | 0.4942 | 0.00100 | 0.9959 | no |
| Baseline (matched policy) | 0.005 | 0.4506 | 0.00222 | 1.0000 | no |
| Baseline (matched policy) | 0.001 | 0.9609 | 0.00002 | 1.0000 | no |

The guard is `0.001 < threshold < 0.99`. A saturated threshold would silence the detector; none of the calibrated candidates may be promoted if any target is saturated.

## 3. Thursday-Friday natural prevalence

| Model | Threshold | ROC-AUC | PR-AUC | FPR | Precision | Recall | Alerts | Alert rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline (published threshold) | 1.0000 | 0.9745 | 0.8999 | 0.00000 | n/a | 0.0000 | 0 | 0.00000 |
| Candidate A | 0.4655 | 0.8514 | 0.4793 | 0.02277 | 0.0046 | 0.0004 | 18397 | 0.01798 |
| Candidate B | 0.1647 | 0.8218 | 0.4464 | 0.01189 | 0.1596 | 0.0083 | 11383 | 0.01113 |

Thursday is benign-only in the frozen scope; Friday supplies DDoS and PortScan. Natural prevalence: 0.21388.

## 4. Thursday-Friday at 0.1% prevalence

All 804347 benign test rows are kept; 805 of 218835 positives are sampled with seed 42. Realized prevalence: 0.00100.

| Model | Threshold | PPV (precision) | Recall | Alerts per 10k | Alerts | TP | FP |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline (published threshold) | 1.0000 | n/a | 0.0000 | 0.0000 | 0 | 0 | 0 |
| Candidate A | 0.4655 | 0.0000 | 0.0000 | 227.4477 | 18313 | 0 | 18313 |
| Candidate B | 0.1647 | 0.0006 | 0.0075 | 118.8844 | 9572 | 6 | 9566 |

## 5. Matched-scope external transfer

Both external datasets were filtered to the same DoS/DDoS/scanning scope before scoring. Thresholds are the CIC-IDS-2017 Wednesday benign-FPR thresholds; no external label was used to choose them.

| Dataset | Model | Threshold | ROC-AUC | PR-AUC | FPR | Precision | Recall | Alerts | Rows |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| cicids2018 | Baseline (published threshold) | 1.0000 | 0.7685 | 0.1859 | 0.00000 | n/a | 0.0000 | 0 | 13547083 |
| cicids2018 | Candidate A | 0.4655 | 0.7837 | 0.2105 | 0.01056 | 0.0547 | 0.0076 | 140062 | 13547083 |
| cicids2018 | Candidate B | 0.1647 | 0.7764 | 0.2047 | 0.00280 | 0.1849 | 0.0079 | 43078 | 13547083 |
| unsw_nb15 | Baseline (published threshold) | 1.0000 | 0.4945 | 0.1145 | 0.00000 | n/a | 0.0000 | 0 | 38627 |
| unsw_nb15 | Candidate A | 0.4655 | 0.5931 | 0.1561 | 0.00050 | 0.2917 | 0.0016 | 24 | 38627 |
| unsw_nb15 | Candidate B | 0.1647 | 0.5683 | 0.1688 | 0.00126 | 0.1731 | 0.0020 | 52 | 38627 |

- **cicids2018**: raw 16233002, benign 13484708, positive 1918233, dropped 830061 (including 0 `- Attempted`).
- **unsw_nb15**: raw 82332, benign 37000, positive 7585, dropped 37747 (including 0 `- Attempted`).

## 6. Baseline vs Candidate A vs Candidate B

| Dataset | Model | Threshold | ROC-AUC | PR-AUC | FPR | Precision | Recall | Alerts | Rows |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Thursday-Friday | Baseline (published threshold) | 1.0000 | 0.9745 | 0.8999 | 0.00000 | n/a | 0.0000 | 0 | 1023182 |
| Thursday-Friday | Candidate A | 0.4655 | 0.8514 | 0.4793 | 0.02277 | 0.0046 | 0.0004 | 18397 | 1023182 |
| Thursday-Friday | Candidate B | 0.1647 | 0.8218 | 0.4464 | 0.01189 | 0.1596 | 0.0083 | 11383 | 1023182 |
| cicids2018 | Baseline (published threshold) | 1.0000 | 0.7685 | 0.1859 | 0.00000 | n/a | 0.0000 | 0 | 13547083 |
| cicids2018 | Candidate A | 0.4655 | 0.7837 | 0.2105 | 0.01056 | 0.0547 | 0.0076 | 140062 | 13547083 |
| cicids2018 | Candidate B | 0.1647 | 0.7764 | 0.2047 | 0.00280 | 0.1849 | 0.0079 | 43078 | 13547083 |
| unsw_nb15 | Baseline (published threshold) | 1.0000 | 0.4945 | 0.1145 | 0.00000 | n/a | 0.0000 | 0 | 38627 |
| unsw_nb15 | Candidate A | 0.4655 | 0.5931 | 0.1561 | 0.00050 | 0.2917 | 0.0016 | 24 | 38627 |
| unsw_nb15 | Candidate B | 0.1647 | 0.5683 | 0.1688 | 0.00126 | 0.1731 | 0.0020 | 52 | 38627 |

> **Baseline caveat.** The P3B baseline was fitted with a stratified group split over all CIC-IDS-2017 days, so part of Thursday-Friday was in its training data and its ROC-AUC/PR-AUC are optimistic. Its published threshold is 1.000000 and produced zero alerts, which is the saturation failure this experiment isolates. Read the baseline rows as a ranking reference, not a clean holdout.

## 7. What the evidence supports

- Candidate A still saturates at target FPR 0.001, so that operating point is unusable.
- Candidate B removes threshold saturation at both benign-FPR targets (0.005 and 0.001).
- Thursday-Friday FPR for Candidate A is 0.0228 at a threshold selected for 0.005 on Wednesday (4.6x the target). The benign-FPR guarantee does not transfer across days.
- Natural-prevalence recall for Candidate A is 0.0004, so the operating point misses almost every attack.
- Thursday-Friday FPR for Candidate B is 0.0119 at a threshold selected for 0.005 on Wednesday (2.4x the target). The benign-FPR guarantee does not transfer across days.
- Natural-prevalence recall for Candidate B is 0.0083, so the operating point misses almost every attack.
- At 0.1% prevalence, Candidate A has precision 0.000, recall 0.000, and 227 alerts per 10,000 rows. At this prevalence precision is set by the false-positive rate.
- At 0.1% prevalence, Candidate B has precision 0.001, recall 0.007, and 119 alerts per 10,000 rows. At this prevalence precision is set by the false-positive rate.
- Matched-scope cicids2018 (prevalence 0.074, 13547083 rows): A: ROC-AUC 0.784, PR-AUC 0.210, recall 0.0076; B: ROC-AUC 0.776, PR-AUC 0.205, recall 0.0079.
- cicids2018 ranking is weak-to-moderate (best ROC-AUC 0.784); transfer is demonstrated only as a ranking signal, not as an operating detector.
- Matched-scope unsw_nb15 (prevalence 0.114, 38627 rows): A: ROC-AUC 0.593, PR-AUC 0.156, recall 0.0016; B: ROC-AUC 0.568, PR-AUC 0.169, recall 0.0020.
- unsw_nb15 ranking is close to chance (best ROC-AUC 0.593); this dataset does not support a claim of cross-dataset detection.
- Mean matched-scope external PR-AUC: baseline 0.1502, Candidate A 0.1833, Candidate B 0.1868. The baseline's Thursday-Friday scores are optimistic because its group split included Thursday-Friday rows, so the external comparison is the fair one.

## 8. Promotion decision

- Saturation eliminated (both targets, both candidates): **no**
- Saturation eliminated by candidate: A = **no**, B = **yes**
- Protocol matches the requested day split: **no**
- Beats the baseline on matched-scope external PR-AUC: **yes**
- Best candidate by external mean PR-AUC: **B**
- Promoted to serving: **no**

Not promoted. The requested Monday-Tuesday matched-scope training partition has zero positives, so the executed Wednesday group-split fallback is a protocol deviation. The serving artifact and registry stay unchanged.

## 9. Limitations

- The literal Monday-Tuesday training split has zero in-scope positives in CIC-IDS-2017. The benchmark reports that finding and executes the documented Wednesday group-split fallback; it is not a literal day split.
- The scope is volumetric DoS/DDoS and scanning only. Web, brute-force, bot, infiltration, exploit, fuzzer, shellcode, backdoor, analysis, and worm rows are dropped, never scored as benign.
- Every '- Attempted' row is excluded from both classes.
- Thresholds are selected from Wednesday benign scores only. Thursday-Friday labels and external labels are never used to choose a threshold.
- CIC-IDS-2018 is used only for DoS/DDoS (no PortScan rows are present). UNSW-NB15 is used only for DoS/Reconnaissance.
- Average precision is prevalence-sensitive. Compare the same rows and the same threshold; the natural-prevalence and 0.1% tables are not interchangeable.
- The portable-ratio transform removes scale-dependent magnitudes, not every capture artifact. Flow timeout, capture point, and labelling policy still differ.
- The serving artifact and the frozen Tier A schema are unchanged. No candidate is promoted to serving while the requested protocol is infeasible.
- The P3B baseline bundle is a gitignored, regenerable research artifact. When it is absent, baseline thresholded values come from docs/portable_transfer_results.json and ROC-AUC/AP are reported as unavailable.
- The P3B baseline was fitted with a stratified group split over all CIC-IDS-2017 days, so some Thursday-Friday rows were in its training partition and its test ROC-AUC/PR-AUC are optimistic. Its published threshold is 1.000000 and produced zero alerts by construction. Read the baseline rows as a ranking reference, not a clean holdout.
- The fallback split is group-disjoint under the repository's (5-tuple, normalised label) group key. Because the key includes the label, one 5-tuple can appear in training as one family and in calibration as another.

