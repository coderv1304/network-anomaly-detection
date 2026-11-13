# Rule Baselines (Phase P2A)

**Status:** complete. **Scope:** flow-based volumetric and scanning behavior; not a general NIDS.

**Artifact:** [`rule_baselines.json`](rule_baselines.json). **Script:** [`../scripts/rule_baselines.py`](../scripts/rule_baselines.py).

This report defines the Tier A rule baselines that any later model must beat. It adds no model, does not touch the serving artifact, and does not tune on test labels.

## Data and label policy

| Partition | Days | Rows after dedup | Primary rows | Positives | Negatives | Excluded | Benchmark prevalence |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Validation | Wednesday | 692,686 | 692,675 | 252,660 | 440,015 | 11 | 36.48% |
| Test | Thursday, Friday | 1,162,065 | 1,157,883 | 286,957 | 870,926 | 4,182 | 24.78% |

Primary positives: DDoS, DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris, PortScan. Negative: BENIGN. Excluded labels are removed from the primary metrics and logged in `excluded_diagnostics`.

The Thursday Morning WebAttacks CSV contains empty records. The frozen loader reads them as all-NaN rows, collapses them during `drop_duplicates`, and removes the collapsed row with `dropna(subset=['Label'])`. They are never treated as benign.

## Rules

| Rule | Tier | Formula |
| --- | --- | --- |
| `rate_bytes` | A | score = sanitized Flow Bytes/s |
| `rate_packets` | A | score = sanitized Flow Packets/s |
| `syn` | A | score = syn_ratio * log1p(total_packets + 1) |
| `composite_bytes_syn` | A | score = z(log1p(max(flow_bytes_s, 0))) + z(syn_score); median/IQR fitted on validation only |
| `composite_packets_syn` | A | score = z(log1p(max(flow_packets_s, 0))) + z(syn_score); median/IQR fitted on validation only |
| `fanout` | B | `unique_dst_ports_60s`; **unavailable** without raw packets or a stateful aggregator |

## Threshold selection

Scores are sorted in descending one-based rank. For a budget `B` alerts per 10,000 flows and `N` validation rows, `K = ceil(B * N / 10000)`. If `K >= N`, the threshold is `min(score) - epsilon`. Otherwise the threshold is the score at rank `K + 1`, and the decision is `score > threshold`. Ties at the boundary reduce the alert count; a top score tied more than `K` times yields zero alerts. This is the specified tie behaviour and is preserved as a negative result.

## Validation thresholds

| Rule | Budget / 10k | K | Threshold | Alerts | Alerts / 10k | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `rate_bytes` | 10 | 693 | 4.83e+08 | 651 | 9.40 | 0.0515% | 0.118405% |
| `rate_bytes` | 100 | 6,927 | 1.23e+07 | 6,334 | 91.44 | 0.1005% | 1.381771% |
| `rate_packets` | 10 | 693 | 2e+06 | 98 | 1.41 | 0.0198% | 0.010909% |
| `rate_packets` | 100 | 6,927 | 2e+06 | 98 | 1.41 | 0.0198% | 0.010909% |
| `syn` | 10 | 693 | 0.693147 | 0 | 0.00 | 0.0000% | 0.000000% |
| `syn` | 100 | 6,927 | 0.693147 | 0 | 0.00 | 0.0000% | 0.000000% |
| `composite_bytes_syn` | 10 | 693 | 8.92508 | 648 | 9.36 | 0.0515% | 0.117723% |
| `composite_bytes_syn` | 100 | 6,927 | 8.18458 | 5,095 | 73.56 | 0.0776% | 1.113371% |
| `composite_packets_syn` | 10 | 693 | 7.35667 | 0 | 0.00 | 0.0000% | 0.000000% |
| `composite_packets_syn` | 100 | 6,927 | 7.21175 | 6,417 | 92.64 | 0.0194% | 1.447223% |

## Test results at 10 alerts / 10k

| Rule | Alerts | Alerts / 10k | TP | FP | Recall | FPR | Precision @ benchmark |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `rate_bytes` | 745 | 6.43 | 1 | 744 | 0.000% | 0.0854% | 0.13% |
| `rate_packets` | 113 | 0.98 | 0 | 113 | 0.000% | 0.0130% | 0.00% |
| `syn` | 0 | 0.00 | 0 | 0 | 0.000% | 0.0000% | n/a |
| `composite_bytes_syn` | 738 | 6.37 | 0 | 738 | 0.000% | 0.0847% | 0.00% |
| `composite_packets_syn` | 0 | 0.00 | 0 | 0 | 0.000% | 0.0000% | n/a |

| Rule | 0.0100% | 0.1000% | 1.0000% | 10.0000% | Benchmark |
| --- | ---: | ---: | ---: | ---: | ---: |
| `rate_bytes` | 0.0000% | 0.0004% | 0.0041% | 0.0453% | 0.13% |
| `rate_packets` | 0.0000% | 0.0000% | 0.0000% | 0.0000% | 0.00% |
| `syn` | n/a | n/a | n/a | n/a | n/a |
| `composite_bytes_syn` | 0.0000% | 0.0000% | 0.0000% | 0.0000% | 0.00% |
| `composite_packets_syn` | n/a | n/a | n/a | n/a | n/a |

PPV uses the test TPR/FPR at the frozen validation threshold. The benchmark column is the dataset prevalence, not a site prevalence.

## Test results at 100 alerts / 10k

| Rule | Alerts | Alerts / 10k | TP | FP | Recall | FPR | Precision @ benchmark |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `rate_bytes` | 9,158 | 79.09 | 33 | 9,125 | 0.011% | 1.0477% | 0.36% |
| `rate_packets` | 113 | 0.98 | 0 | 113 | 0.000% | 0.0130% | 0.00% |
| `syn` | 0 | 0.00 | 0 | 0 | 0.000% | 0.0000% | n/a |
| `composite_bytes_syn` | 6,783 | 58.58 | 0 | 6,783 | 0.000% | 0.7788% | 0.00% |
| `composite_packets_syn` | 8,186 | 70.70 | 0 | 8,186 | 0.000% | 0.9399% | 0.00% |

| Rule | 0.0100% | 0.1000% | 1.0000% | 10.0000% | Benchmark |
| --- | ---: | ---: | ---: | ---: | ---: |
| `rate_bytes` | 0.0001% | 0.0011% | 0.0111% | 0.1218% | 0.36% |
| `rate_packets` | 0.0000% | 0.0000% | 0.0000% | 0.0000% | 0.00% |
| `syn` | n/a | n/a | n/a | n/a | n/a |
| `composite_bytes_syn` | 0.0000% | 0.0000% | 0.0000% | 0.0000% | 0.00% |
| `composite_packets_syn` | 0.0000% | 0.0000% | 0.0000% | 0.0000% | 0.00% |

PPV uses the test TPR/FPR at the frozen validation threshold. The benchmark column is the dataset prevalence, not a site prevalence.

## Confidence intervals at 0.1% prevalence

Intervals are 95% Wilson for recall/FPR and 2.5th-97.5th bootstrap percentiles for PPV and alert volume. The bootstrap resamples the thresholded indicator within each class and is deterministic at the recorded seed.

| Rule | Budget / 10k | Recall (95% CI) | FPR (95% CI) | PPV @ 0.1% (95% CI) | Alerts / 10k @ 0.1% (95% CI) |
| --- | ---: | --- | --- | --- | --- |
| `rate_bytes` | 10 | 0.000% (0.0001%-0.0020%) | 0.0854% (0.0795%-0.0918%) | 0.0004% (0.0000%-0.0013%) | 8.53 (7.93-9.15) |
| `rate_bytes` | 100 | 0.011% (0.0082%-0.0161%) | 1.0477% (1.0266%-1.0693%) | 0.0011% (0.0007%-0.0015%) | 104.67 (102.57-106.79) |
| `rate_packets` | 10 | 0.000% (0.0000%-0.0013%) | 0.0130% (0.0108%-0.0156%) | 0.0000% (0.0000%-0.0000%) | 1.30 (1.07-1.54) |
| `rate_packets` | 100 | 0.000% (0.0000%-0.0013%) | 0.0130% (0.0108%-0.0156%) | 0.0000% (0.0000%-0.0000%) | 1.30 (1.07-1.54) |
| `syn` | 10 | 0.000% (0.0000%-0.0013%) | 0.0000% (0.0000%-0.0004%) | n/a (n/a) | 0.00 (0.00-0.00) |
| `syn` | 100 | 0.000% (0.0000%-0.0013%) | 0.0000% (0.0000%-0.0004%) | n/a (n/a) | 0.00 (0.00-0.00) |
| `composite_bytes_syn` | 10 | 0.000% (0.0000%-0.0013%) | 0.0847% (0.0788%-0.0911%) | 0.0000% (0.0000%-0.0000%) | 8.47 (7.87-9.08) |
| `composite_bytes_syn` | 100 | 0.000% (0.0000%-0.0013%) | 0.7788% (0.7606%-0.7975%) | 0.0000% (0.0000%-0.0000%) | 77.80 (75.98-79.65) |
| `composite_packets_syn` | 10 | 0.000% (0.0000%-0.0013%) | 0.0000% (0.0000%-0.0004%) | n/a (n/a) | 0.00 (0.00-0.00) |
| `composite_packets_syn` | 100 | 0.000% (0.0000%-0.0013%) | 0.9399% (0.9199%-0.9604%) | 0.0000% (0.0000%-0.0000%) | 93.90 (91.86-95.92) |

## Per-family recall on test

| Rule | Budget / 10k | DDoS | PortScan |
| --- | ---: | ---: | ---: |
| `rate_bytes` | 10 | 0.001% (1/128,027) | 0.000% (0/158,930) |
| `rate_bytes` | 100 | 0.026% (33/128,027) | 0.000% (0/158,930) |
| `rate_packets` | 10 | 0.000% (0/128,027) | 0.000% (0/158,930) |
| `rate_packets` | 100 | 0.000% (0/128,027) | 0.000% (0/158,930) |
| `syn` | 10 | 0.000% (0/128,027) | 0.000% (0/158,930) |
| `syn` | 100 | 0.000% (0/128,027) | 0.000% (0/158,930) |
| `composite_bytes_syn` | 10 | 0.000% (0/128,027) | 0.000% (0/158,930) |
| `composite_bytes_syn` | 100 | 0.000% (0/128,027) | 0.000% (0/158,930) |
| `composite_packets_syn` | 10 | 0.000% (0/128,027) | 0.000% (0/158,930) |
| `composite_packets_syn` | 100 | 0.000% (0/128,027) | 0.000% (0/158,930) |

## Discrimination

| Rule | Test ROC-AUC | Test PR-AUC |
| --- | ---: | ---: |
| `rate_bytes` | 0.5455 | 0.2506 |
| `rate_packets` | 0.5603 | 0.2996 |
| `syn` | 0.4764 | 0.2478 |
| `composite_bytes_syn` | 0.5263 | 0.2416 |
| `composite_packets_syn` | 0.5382 | 0.2777 |

AUC is threshold-free and is reported for context. It does not rescue a rule that cannot meet an alert budget.

## Excluded-label diagnostics

These rows are excluded from the primary metrics and from threshold selection. The table logs how the frozen thresholds would treat them, nothing more.

| Partition | Rule | Budget / 10k | Label | Support | Alerts | Alert rate |
| --- | --- | ---: | --- | ---: | ---: | ---: |
| validation | `rate_bytes` | 10 | Heartbleed | 11 | 0 | 0.000% |
| validation | `rate_bytes` | 100 | Heartbleed | 11 | 0 | 0.000% |
| validation | `rate_packets` | 10 | Heartbleed | 11 | 0 | 0.000% |
| validation | `rate_packets` | 100 | Heartbleed | 11 | 0 | 0.000% |
| validation | `syn` | 10 | Heartbleed | 11 | 0 | 0.000% |
| validation | `syn` | 100 | Heartbleed | 11 | 0 | 0.000% |
| validation | `composite_bytes_syn` | 10 | Heartbleed | 11 | 0 | 0.000% |
| validation | `composite_bytes_syn` | 100 | Heartbleed | 11 | 0 | 0.000% |
| validation | `composite_packets_syn` | 10 | Heartbleed | 11 | 0 | 0.000% |
| validation | `composite_packets_syn` | 100 | Heartbleed | 11 | 0 | 0.000% |
| test | `rate_bytes` | 10 | Bot | 1,966 | 0 | 0.000% |
| test | `rate_bytes` | 10 | Infiltration | 36 | 0 | 0.000% |
| test | `rate_bytes` | 10 | Web Attack - Brute Force | 1,507 | 0 | 0.000% |
| test | `rate_bytes` | 10 | Web Attack - Sql Injection | 21 | 0 | 0.000% |
| test | `rate_bytes` | 10 | Web Attack - XSS | 652 | 0 | 0.000% |
| test | `rate_bytes` | 100 | Bot | 1,966 | 0 | 0.000% |
| test | `rate_bytes` | 100 | Infiltration | 36 | 0 | 0.000% |
| test | `rate_bytes` | 100 | Web Attack - Brute Force | 1,507 | 0 | 0.000% |
| test | `rate_bytes` | 100 | Web Attack - Sql Injection | 21 | 0 | 0.000% |
| test | `rate_bytes` | 100 | Web Attack - XSS | 652 | 0 | 0.000% |
| test | `rate_packets` | 10 | Bot | 1,966 | 0 | 0.000% |
| test | `rate_packets` | 10 | Infiltration | 36 | 0 | 0.000% |
| test | `rate_packets` | 10 | Web Attack - Brute Force | 1,507 | 0 | 0.000% |
| test | `rate_packets` | 10 | Web Attack - Sql Injection | 21 | 0 | 0.000% |
| test | `rate_packets` | 10 | Web Attack - XSS | 652 | 0 | 0.000% |
| test | `rate_packets` | 100 | Bot | 1,966 | 0 | 0.000% |
| test | `rate_packets` | 100 | Infiltration | 36 | 0 | 0.000% |
| test | `rate_packets` | 100 | Web Attack - Brute Force | 1,507 | 0 | 0.000% |
| test | `rate_packets` | 100 | Web Attack - Sql Injection | 21 | 0 | 0.000% |
| test | `rate_packets` | 100 | Web Attack - XSS | 652 | 0 | 0.000% |
| test | `syn` | 10 | Bot | 1,966 | 0 | 0.000% |
| test | `syn` | 10 | Infiltration | 36 | 0 | 0.000% |
| test | `syn` | 10 | Web Attack - Brute Force | 1,507 | 0 | 0.000% |
| test | `syn` | 10 | Web Attack - Sql Injection | 21 | 0 | 0.000% |
| test | `syn` | 10 | Web Attack - XSS | 652 | 0 | 0.000% |
| test | `syn` | 100 | Bot | 1,966 | 0 | 0.000% |
| test | `syn` | 100 | Infiltration | 36 | 0 | 0.000% |
| test | `syn` | 100 | Web Attack - Brute Force | 1,507 | 0 | 0.000% |
| test | `syn` | 100 | Web Attack - Sql Injection | 21 | 0 | 0.000% |
| test | `syn` | 100 | Web Attack - XSS | 652 | 0 | 0.000% |
| test | `composite_bytes_syn` | 10 | Bot | 1,966 | 0 | 0.000% |
| test | `composite_bytes_syn` | 10 | Infiltration | 36 | 0 | 0.000% |
| test | `composite_bytes_syn` | 10 | Web Attack - Brute Force | 1,507 | 0 | 0.000% |
| test | `composite_bytes_syn` | 10 | Web Attack - Sql Injection | 21 | 0 | 0.000% |
| test | `composite_bytes_syn` | 10 | Web Attack - XSS | 652 | 0 | 0.000% |
| test | `composite_bytes_syn` | 100 | Bot | 1,966 | 0 | 0.000% |
| test | `composite_bytes_syn` | 100 | Infiltration | 36 | 0 | 0.000% |
| test | `composite_bytes_syn` | 100 | Web Attack - Brute Force | 1,507 | 0 | 0.000% |
| test | `composite_bytes_syn` | 100 | Web Attack - Sql Injection | 21 | 0 | 0.000% |
| test | `composite_bytes_syn` | 100 | Web Attack - XSS | 652 | 0 | 0.000% |
| test | `composite_packets_syn` | 10 | Bot | 1,966 | 0 | 0.000% |
| test | `composite_packets_syn` | 10 | Infiltration | 36 | 0 | 0.000% |
| test | `composite_packets_syn` | 10 | Web Attack - Brute Force | 1,507 | 0 | 0.000% |
| test | `composite_packets_syn` | 10 | Web Attack - Sql Injection | 21 | 0 | 0.000% |
| test | `composite_packets_syn` | 10 | Web Attack - XSS | 652 | 0 | 0.000% |
| test | `composite_packets_syn` | 100 | Bot | 1,966 | 0 | 0.000% |
| test | `composite_packets_syn` | 100 | Infiltration | 36 | 0 | 0.000% |
| test | `composite_packets_syn` | 100 | Web Attack - Brute Force | 1,507 | 0 | 0.000% |
| test | `composite_packets_syn` | 100 | Web Attack - Sql Injection | 21 | 0 | 0.000% |
| test | `composite_packets_syn` | 100 | Web Attack - XSS | 652 | 0 | 0.000% |

## Score tie diagnostics

A rule whose maximum validation score is tied across more rows than the smallest budget allows cannot select a non-empty alert set under the strict `score > threshold` rule. The table reports the top tie for every Tier A rule on the primary validation rows.

| Rule | Max validation score | Tied rows | Budget K (10 / 100) | Tie exceeds smallest K |
| --- | ---: | ---: | --- | --- |
| `rate_bytes` | 2.07e+09 | 31 | 693 / 6,927 | no |
| `rate_packets` | 3e+06 | 97 | 693 / 6,927 | no |
| `syn` | 0.693147 | 11,699 | 693 / 6,927 | yes |
| `composite_bytes_syn` | 9.20514 | 31 | 693 / 6,927 | no |
| `composite_packets_syn` | 7.35667 | 1,487 | 693 / 6,927 | yes |

The maximum validation SYN score is `0.693147` and is tied across 11,699 primary validation rows. The tie is dominated by BENIGN: 10,573, DoS Slowhttptest: 604, DoS slowloris: 522. Both budgets require fewer alerts than the size of this tie, so the specified tie rule selects zero alerts. The SYN rule therefore has no usable operating point on this dataset. The `composite_packets_syn` rule inherits that tie through its SYN term and also selects zero validation alerts at the 10/10k budget; at 100/10k it only clears the tie and recovers 49 validation positives.

## Tier B fan-out

Tier B fan-out is **unavailable**: Tier B requires raw packets or a stateful aggregator. The repository contains per-flow CSV exports and no .pcap/.pcapng files, so 60-second destination fan-out cannot be derived. It is not approximated from per-flow columns.

The primary claim is therefore **Tier A only**. Per-flow columns cannot reconstruct 60-second destination fan-out. A stateful aggregator or raw packets are required, and neither exists in the repository.

## Key findings

- At **10 alerts / 10k**, the best Tier A rule is `rate_bytes` with test recall **0.000%** (1 TP), FPR **0.0854%**, and PPV **0.0004%** at 0.1000% prevalence. This is not a viable detector.
- At **100 alerts / 10k**, the best Tier A rule is `rate_bytes` with test recall **0.011%** (33 TP), FPR **1.0477%**, and PPV **0.0011%** at 0.1000% prevalence. This is not a viable detector.
- The `syn` rule is degenerate because of ties; see the diagnostic above.
- `composite_packets_syn` inherits the SYN tie: it selects zero validation alerts at 10/10k because its top tie (1,487 rows) exceeds K=693.
- The composite rules do not beat the best single rate rule at either budget.
- Tier B fan-out is the missing capability for scan detection. Without raw packets or a stateful aggregator, the Tier A baseline cannot represent it honestly.

## Limits

- CIC-IDS-2017 Thursday + Friday is a development test partition that has already been inspected. It is not a blind confirmatory test.
- The benchmark prevalence is a property of this dataset, not a real network.
- Flows within one capture are not independent; the bootstrap intervals are a lower bound on uncertainty.
- The rate repair for zero-duration flows uses a one-microsecond assumption. The repair counts are in the artifact.
- The rules are baselines, not a deployable detector. Detection remains **4/10**.

## Reproduction

```bash
venv/Scripts/python.exe scripts/rule_baselines.py \
  --output docs/rule_baselines.json \
  --report docs/RULE_BASELINES.md
```

