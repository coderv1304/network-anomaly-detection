# Host/Window Incident Evaluation (Phase 3)

**Generated:** 2026-11-18T03:51:34.927315+00:00  
**Artifact:** `window-incident-eval-v1`  
**Candidate:** Candidate A (`RandomForestClassifier`, sigmoid (Platt))  
**Seed:** 42  
**Serving artifact:** `model_bundle_rf_day_based_seed42.pkl` unchanged (`fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`)

## 1. Protocol

Wednesday selects the window parameters; Thursday-Friday is scored once after they are frozen. No Thursday-Friday label contributes to any choice.

- Provenance: `wednesday_group_split_fallback`
- Train: 1268799 rows (1132173 benign / 136626 positive)
- Wednesday calibration: 180552 rows (123430 benign / 57122 positive)
- Thursday-Friday test: 1023182 rows (804347 benign / 218835 positive)
- Training/calibration group overlap: 0

> **Protocol deviation.** The literal Monday-Tuesday training split has zero in-scope positives, so it cannot fit either candidate. Wednesday groups were split 70/30 by a deterministic group hash (group key: source and destination IP/port plus transport protocol plus normalised label), 70% joined the Monday-Tuesday benign rows in training and 30% formed a disjoint calibration partition. Thursday-Friday and every external dataset were never used for fitting or threshold selection.

- Grouping key: `(Source IP, floor(epoch_seconds / 300) * 300)`  
- Window: 300 s  
- Per-flow score: `points = min(per_flow_cap, 100 * max(0, (p - p_floor) / (1 - p_floor)))`  
- Per-flow cap: 50.0  
- Per-window cap: 100.0  
- Incident threshold: 100.0  
- p_floor: 0.8

## 2. Wednesday-only parameter selection

Target: benign-window false-incident rate <= **0.0010** over 12564 benign and 21 malicious Wednesday windows (12585 total).

Selected `p_floor = 0.80`, `incident_threshold = 100.0` -> Wednesday benign-window FPR **0.00422**, Wednesday window recall **0.8571**. Feasible grid point: **no**.

| p_floor | threshold | Wednesday benign-window FPR | Wednesday window recall | Feasible |
|---:|---:|---:|---:|---:|
| 0.30 | 55.0 | 0.02483 | 0.9048 | no |
| 0.30 | 60.0 | 0.02451 | 0.9048 | no |
| 0.30 | 65.0 | 0.02436 | 0.9048 | no |
| 0.30 | 70.0 | 0.02428 | 0.9048 | no |
| 0.30 | 75.0 | 0.01839 | 0.9048 | no |
| 0.30 | 80.0 | 0.01823 | 0.9048 | no |
| 0.30 | 90.0 | 0.01775 | 0.9048 | no |
| 0.30 | 100.0 | 0.01417 | 0.9048 | no |
| 0.40 | 55.0 | 0.01480 | 0.9048 | no |
| 0.40 | 60.0 | 0.01480 | 0.9048 | no |
| 0.40 | 65.0 | 0.01377 | 0.9048 | no |
| 0.40 | 70.0 | 0.01258 | 0.9048 | no |
| 0.40 | 75.0 | 0.01146 | 0.9048 | no |
| 0.40 | 80.0 | 0.01043 | 0.9048 | no |
| 0.40 | 90.0 | 0.00971 | 0.9048 | no |
| 0.40 | 100.0 | 0.00899 | 0.9048 | no |
| 0.50 | 55.0 | 0.00533 | 0.8571 | no |
| 0.50 | 60.0 | 0.00517 | 0.8571 | no |
| 0.50 | 65.0 | 0.00509 | 0.8571 | no |
| 0.50 | 70.0 | 0.00493 | 0.8571 | no |
| 0.50 | 75.0 | 0.00493 | 0.8571 | no |
| 0.50 | 80.0 | 0.00493 | 0.8571 | no |
| 0.50 | 90.0 | 0.00478 | 0.8571 | no |
| 0.50 | 100.0 | 0.00478 | 0.8571 | no |
| 0.60 | 55.0 | 0.00486 | 0.8571 | no |
| 0.60 | 60.0 | 0.00486 | 0.8571 | no |
| 0.60 | 65.0 | 0.00486 | 0.8571 | no |
| 0.60 | 70.0 | 0.00478 | 0.8571 | no |
| 0.60 | 75.0 | 0.00478 | 0.8571 | no |
| 0.60 | 80.0 | 0.00478 | 0.8571 | no |
| 0.60 | 90.0 | 0.00478 | 0.8571 | no |
| 0.60 | 100.0 | 0.00478 | 0.8571 | no |
| 0.70 | 55.0 | 0.00478 | 0.8571 | no |
| 0.70 | 60.0 | 0.00478 | 0.8571 | no |
| 0.70 | 65.0 | 0.00478 | 0.8571 | no |
| 0.70 | 70.0 | 0.00478 | 0.8571 | no |
| 0.70 | 75.0 | 0.00478 | 0.8571 | no |
| 0.70 | 80.0 | 0.00478 | 0.8571 | no |
| 0.70 | 90.0 | 0.00454 | 0.8571 | no |
| 0.70 | 100.0 | 0.00430 | 0.8571 | no |
| 0.80 | 55.0 | 0.00462 | 0.8571 | no |
| 0.80 | 60.0 | 0.00454 | 0.8571 | no |
| 0.80 | 65.0 | 0.00438 | 0.8571 | no |
| 0.80 | 70.0 | 0.00430 | 0.8571 | no |
| 0.80 | 75.0 | 0.00430 | 0.8571 | no |
| 0.80 | 80.0 | 0.00430 | 0.8571 | no |
| 0.80 | 90.0 | 0.00422 | 0.8571 | no |
| 0.80 | 100.0 | 0.00422 | 0.8571 | no |
| 0.90 | 55.0 | 0.00422 | 0.8571 | no |
| 0.90 | 60.0 | 0.00422 | 0.8571 | no |
| 0.90 | 65.0 | 0.00422 | 0.8571 | no |
| 0.90 | 70.0 | 0.00422 | 0.8571 | no |
| 0.90 | 75.0 | 0.00422 | 0.8571 | no |
| 0.90 | 80.0 | 0.00422 | 0.8571 | no |
| 0.90 | 90.0 | 0.00422 | 0.8571 | no |
| 0.90 | 100.0 | 0.00422 | 0.8571 | no |

## 3. Single-flow vs 300 s host/window at 0.1% flow prevalence

Deterministic positive downsampling (`seed=42`): all 804347 benign rows kept, 805 of 218835 positives sampled, realised prevalence **0.00100**.

| Alerting unit | Threshold | Units | Alerts | Precision (PPV) | Recall | F1 | per 10k flows |
|---|---:|---:|---:|---:|---:|---:|---:|
| Single flow | 0.4655 | 805152 | 14325 | 0.0000 | 0.0000 | n/a | 177.9167 |
| 300 s host/window incident | 100.0 | 47187 | 372 | 0.0000 | 0.0000 | n/a | 4.6202 |

Window truth here is the primary definition: a window is malicious if it contains at least one attack flow. Attack-flow coverage: **0.0000** of attack flows fall inside an alerted window.

## 4. Natural Thursday-Friday prevalence

1023182 flows, prevalence **0.21388**.

| Alerting unit | Threshold | Units | Alerts | Precision (PPV) | Recall | F1 | per 10k flows |
|---|---:|---:|---:|---:|---:|---:|---:|
| Single flow | 0.4655 | 1023182 | 14349 | 0.0017 | 0.0001 | 0.0002 | 140.2390 |
| 300 s host/window incident | 100.0 | 47194 | 375 | 0.0080 | 0.1667 | 0.0153 | 3.6650 |

## 5. Burst sensitivity (`sum(y_true) >= 3`)

| Regime | Alerting unit | Precision | Recall | F1 | Alerts / incidents |
|---|---|---:|---:|---:|---:|
| Natural | Single flow | 0.0017 | 0.0001 | 0.0002 | 14349 |
| Natural | Window (burst) | 0.0080 | 0.1875 | 0.0153 | 375 |
| 0.1% | Single flow | 0.0000 | 0.0000 | n/a | 14325 |
| 0.1% | Window (burst) | 0.0000 | 0.0000 | n/a | 372 |

## 6. Mean flows-to-detection inside malicious windows

| Regime | Malicious windows | Triggered | Mean attack flows before trigger | Median | Mean flows before trigger |
|---|---:|---:|---:|---:|---:|
| Natural | 18 | 3 | 696.33 | 799.0 | 696.33 |
| 0.1% | 10 | 0 | n/a | n/a | n/a |

## 7. Threshold-free ranking on each unit

The frozen threshold is one operating point. These numbers ignore it and ask whether the unit orders malicious above benign at all.

| Regime | Unit | Positives | ROC-AUC | PR-AUC |
|---|---|---:|---:|---:|
| Natural | Flow | 218835 | 0.8514 | 0.4793 |
| Natural | Window (>=1) | 18 | 0.5753 | 0.0017 |
| Natural | Window (>=3) | 16 | 0.5858 | 0.0018 |
| 0.1% | Flow | 805 | 0.8486 | 0.0035 |
| 0.1% | Window (>=1) | 10 | 0.4912 | 0.0002 |
| 0.1% | Window (>=3) | 9 | 0.4912 | 0.0002 |

PR-AUC is not comparable across units with different prevalence, which is why both the positive count and ROC-AUC are shown.

- Natural: 375 of 47194 windows (0.79%) reach the 100-point cap (375 incidents). The frozen threshold equals the cap, so this is also exactly the alert set: the score carries no resolution above the operating point.
- 0.1%: 372 of 47187 windows (0.79%) reach the 100-point cap (372 incidents). The frozen threshold equals the cap, so this is also exactly the alert set: the score carries no resolution above the operating point.

## 8. Matched false-alarm budget

The two units do not spend the same budget: a flow threshold bounds per-flow false positives, the window threshold bounds per-window false incidents. This section re-prices the flow detector at the window policy's benign false-alarm count.

| Regime | Implied flow FPR budget | Flow threshold | Flow precision | Flow recall | Flow alerts |
|---|---:|---:|---:|---:|---:|
| Natural | 0.00005865 | 0.999999977 | 0.0000 | 0.0000 | 52 |
| 0.1% | 0.00005865 | 0.999999977 | 0.0000 | 0.0000 | 52 |

A `n/a` threshold means the budget is too small for any representable quantile: the flow detector cannot spend that little at all.

Note that the matched threshold ~1.0 sits above almost every calibrated probability, so the flow detector buys its low false-alarm count by alerting almost never.

## 9. Phase 2 reproducibility check

- Published test rows 1023182 vs recomputed 1023182 (match: **yes**)
- Published ROC-AUC 0.8514 vs recomputed 0.8514
- Published PR-AUC 0.4793 vs recomputed 0.4793
- Max absolute delta 0.000003 -> scores reproduce Phase 2: **yes**
- Scores used here: `cache`

## 10. Accumulator parity check

A random sample of 20000 Thursday-Friday flows spanning 3919 windows was replayed through `EvidenceAccumulator(scoring_mode='calibrated')`. Compared windows: 3919; max absolute per-window risk-point delta: 0.00000000; incident flags match: **yes**; overall: **yes**.

The vectorised window sums used for the metrics above are therefore the shipped accumulator's arithmetic, not a reimplementation.

## 11. What this evidence supports

- No grid point reached the 0.1% benign-window false-incident target. The lowest attainable Wednesday rate was 0.00422 (0.80 p_floor, threshold 100.0), so the reported operating point is a fallback and the window policy is not validated at its own target.
- The frozen point transfers to a Thursday-Friday benign-window false-incident rate of 0.00789, 7.9x the 0.1% target, so the Wednesday estimate does not hold on the evaluation days.
- At 0.1% flow prevalence on Thursday-Friday, single-flow alerting at threshold 0.4655 achieves precision 0.0000 with 14325 alerts (177.9167 per 10k flows).
- The 300 s host/window policy produces 372 incidents (4.6202 per 10k flows) at precision 0.0000 and window recall 0.0000.
- Window precision does not exceed flow precision at 0.1% prevalence, so the accumulator does not repair the precision collapse in this regime.
- At natural prevalence the window ranker reaches ROC-AUC 0.5753 against 0.8514 for per-flow ranking (-0.2760); aggregation loses ranking quality as well.
- Part of that loss is structural: 0.79% of natural-prevalence windows sit exactly at the 100-point cap, so the window score behaves almost like a binary flag and ties thousands of windows. The cap bounds a single host's influence but also erases ordering information.
- No malicious window opened an incident in the 0.1% regime, so no flows-to-detection figure exists there.
- When re-priced to the same benign false-alarm count, the flow detector reaches precision 0.0000 and recall 0.0000.
- Downsampling to 0.1% prevalence leaves 10 of the 18 malicious windows that exist at natural prevalence, because positive flows are dropped individually. That strips the within-window co-occurrence windowing depends on: this regime measures sparse labels, not a sparse but bursty attacker, and should not be read as proof that aggregation cannot help in live traffic.
- This evaluates one dataset, one window size, and one candidate. It does not establish live-capture behaviour, and the serving artifact is unchanged.

## 12. Limitations

- A window's ground truth is derived from the flows inside it: `sum(y_true) >= 1` (primary) or `>= 3` (burst). One attack flow therefore makes an entire window malicious, which flatters window recall relative to a per-flow detector.
- The 300-second window is the only window size evaluated. Nothing here says 60 s or 900 s behaves the same way.
- Grouping uses the real `Source IP` column. NAT and campus egress aggregation collapse many real hosts into one key; a shared egress address can therefore accumulate somebody else's evidence.
- The frozen export's timestamps are minute-resolution on the attack days and use an unreliable 12-hour clock. Window boundaries are quantised to the stored minute, and absolute wall-clock time is not meaningful.
- Window parameters were selected on the Wednesday calibration partition, which is the same partition that fitted the Phase 2 sigmoid calibrator. The choice is leakage-safe with respect to Thursday-Friday, but it is not a third independent split.
- The two alerting units consume different false-alarm budgets: a flow threshold bounds per-flow false positives, while the window threshold bounds per-window false incidents. The report states both and adds a matched-budget sensitivity rather than implying the budgets are equal.
- The 0.1% regime is produced by dropping individual positive flows from the Thursday-Friday set. It keeps each flow's score but removes most within-window co-occurrence, so it measures sparse labels rather than a sparse but bursty attacker.
- The serving artifact is untouched. No candidate is promoted by this evaluation.

