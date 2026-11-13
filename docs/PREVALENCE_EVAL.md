# Prevalence and Alert-Budget Evaluation (Phase P1)

**Status:** complete.
**Date:** 2026-11-13.
**Artifact:** [`PREVALENCE_EVAL.json`](PREVALENCE_EVAL.json).
**Script:** [`../scripts/prevalence_eval.py`](../scripts/prevalence_eval.py).
**Owner:** NetShield maintainers.

This report answers one question: **how much precision survives realistic attack prevalence?** It does not retrain the model, change the threshold, or add detection evidence. It converts the frozen test operating point into prevalence-aware precision, alert volume, and break-even cost ratios.

## Inputs and provenance

| Item | Value |
| --- | --- |
| Model | Random Forest, day-based split, seed 42 (served and evaluated artifact) |
| Artifact SHA-256 | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` |
| Serving version | `serving-rf-day-based-seed42-v1` |
| Threshold | `score >= 0.002515048908954043` |
| Partition | Test: Thursday + Friday, 1,162,065 flows |
| Test positives | 291,139 |
| Test negatives | 870,926 |
| Benchmark prevalence | 291,139 / 1,162,065 = **0.250536** (25.05%) |
| Per-flow scores | `models/eval_cache/rf_seed{42..46}_test.npz` |
| Bootstrap | Stratified over positive and negative scores, 10,000 draws, seed 20261113 |
| Method label | `bootstrap_scores` |

The per-flow score cache exists, so the harness uses the score-bootstrap path. It does not fall back to the parametric path.

**Important:** each seed has its own validation-selected threshold. The five-seed rows use each seed's own threshold, not seed 42's threshold:

| Seed | Threshold |
| ---: | ---: |
| 42 | 0.002515048908954043 |
| 43 | 0.00185520361990954 |
| 44 | 0.009363636363636352 |
| 45 | 0.010000000000000009 |
| 46 | 0.00712097468444628 |

## Definitions

Let `p` be attack prevalence, `TPR` the true-positive rate, and `FPR` the false-positive rate.

```text
PPV(p)            = TPR*p / (TPR*p + FPR*(1-p))
alerts_per_10k(p) = 10000 * (TPR*p + FPR*(1-p))
alerts_per_day(p) = N * (TPR*p + FPR*(1-p))
```

`N` in `alerts_per_day` is an **illustrative** daily flow volume supplied on the command line (1,000,000 in this run). It is not a measured site value.

Break-even ratios:

```text
break_even_per_flow(p)     = FPR*(1-p) / (TPR*p)                    # FP/TP
break_even_with_review(p)  = [FPR*(1-p) + r*(TPR*p + FPR*(1-p))]
                              / (TPR*p)                             # r = c_r / C_FP
break_even_all_alerts(p)   = 1 + break_even_per_flow(p)             # alerts/TP
```

### Cost assumptions

- `C_FP > 0`; costs are per flow; review cost is per alert; no blocking cost is modeled.
- `break_even_per_flow` models a cost only for false positives. True positives are free.
- `break_even_with_review` adds a review cost `c_r` per alert, expressed as `r = c_r / C_FP`.
- `break_even_all_alerts` models D9's convention: every alert, true or false, costs one review. It equals `alerts/TP = 1 + FP/TP`.
- If `C_FP = 0`, the ratio is undefined; the report does not divide by zero.

The two break-even models differ by exactly 1. This is not a rounding difference; it is a different cost basis. The D9 artifact uses `break_even_all_alerts`.

## Seed 42 results

Seed 42 TPR = **0.579428** (Wilson 95% CI 0.577634–0.581220), FPR = **0.007254** (Wilson 95% CI 0.007078–0.007435).

| Prevalence | PPV | PPV 95% CI | Alerts / 10k | Break-even FP/TP | Break-even alerts/TP |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0.0001 (0.01%) | **0.79%** | 0.77–0.81% | **73.12** | 125.19 | 126.19 |
| 0.001 (0.1%) | **7.40%** | 7.24–7.57% | **78.27** | 12.51 | 13.51 |
| 0.01 (1%) | **44.65%** | 44.06–45.26% | **129.76** | 1.24 | 2.24 |
| 0.10 (10%) | **89.87%** | 89.65–90.09% | **644.72** | 0.11 | 1.11 |
| 0.250536 (benchmark) | **96.39%** | 96.31–96.47% | **1,506.04** | 0.04 | 1.04 |

At the benchmark prevalence of 25.05%, precision is 96.39%. At 0.1% prevalence it is 7.40%. At 0.01% prevalence it is 0.79%. The model's apparent precision is almost entirely a property of the benchmark's attack mix, not a stable property of the detector.

## Five-seed results

Each seed uses its own threshold. Two five-seed summaries are reported because averaging is not associative for a nonlinear metric:

- **`ppv_from_mean_rates`**: plug the mean TPR (0.5830) and mean FPR (0.0411) into the PPV formula.
- **`ppv_mean`**: average the five per-seed PPV values. This is the seed-level mean, and it is more sensitive to seeds with very high FPR.

| Prevalence | PPV from mean rates | Per-seed mean PPV ± SD | Alerts / 10k mean ± SD | Break-even alerts/TP mean |
| ---: | ---: | ---: | ---: | ---: |
| 0.0001 | **0.14%** | 0.33% ± 0.33% | 411.19 ± 327.49 | 716.32 |
| 0.001 | **1.40%** | 3.13% ± 3.06% | 416.07 ± 327.68 | 72.47 |
| 0.01 | **12.54%** | 21.52% ± 17.63% | 464.84 ± 329.79 | 8.08 |
| 0.10 | **61.20%** | 65.93% ± 20.88% | 952.58 ± 374.13 | 1.64 |
| 0.250536 | **82.60%** | 83.67% ± 11.64% | 1,768.37 ± 512.49 | 1.21 |

The five-seed mean-rate PPV at 0.1% prevalence is **1.40%**, which matches the acceptance target of about 1.4%. The per-seed mean is 3.13% because seed 42 has a much lower FPR than seeds 44 and 45; averaging PPV rewards that lucky seed less than averaging rates does.

## What the existing 1.21 means

`docs/COST_SENSITIVE_RESULTS.json` reports a five-seed mean break-even ratio of **1.2140** for the served Random Forest at its frozen per-seed thresholds.

That number is **not prevalence-free**. It is the mean of `alerts/TP = 1 + FP/TP` at the benchmark prevalence of **0.250536**. Recomputing it across the grid gives:

| Prevalence | 1 + FP/TP (five-seed mean) |
| ---: | ---: |
| 0.0001 | 716.32 |
| 0.001 | 72.47 |
| 0.01 | 8.08 |
| 0.10 | 1.64 |
| 0.250536 (benchmark) | **1.21** |

At 0.1% prevalence, the detector must save more than **72** analyst reviews for every missed attack to break even under D9's cost model. At the benchmark's 25% prevalence, the same detector needs only **1.21**. Presenting 1.21 without the prevalence assumption overstates the detector's economic case by roughly two orders of magnitude at realistic prevalence.

Under the per-flow false-positive model (`FP/TP`), the same five-seed values are 0.21 at benchmark, 71.47 at 0.1%, and 715.32 at 0.01%.

## Interpretation

1. **Precision is prevalence-bound.** A 96% benchmark precision and a 0.8% precision at 0.01% prevalence describe the same detector. Neither number is wrong; they answer different questions.
2. **Alert volume is dominated by false positives at low prevalence.** At 0.01%, the detector produces about 73 alerts per 10,000 flows while true attacks are about 1 per 10,000. Most of the queue is false positives.
3. **The 1.21 break-even is a benchmark artifact.** It is valid only at 25% attack prevalence. At realistic prevalence, the break-even cost ratio is one to three orders of magnitude higher.
4. **This report is not new detection evidence.** It re-expresses the existing frozen operating point. Detection remains **4/10**.

## Reproduction

```bash
venv/Scripts/python.exe scripts/prevalence_eval.py \
  --metrics models/metrics_rf_day_based_seed42.json \
  --prevalence 0.0001,0.001,0.01,0.10 --benchmark \
  --flows-per-day 1000000 --review-cost-ratio 0.0 \
  --output docs/PREVALENCE_EVAL.json
```

The output is deterministic for the fixed seed 20261113 and 10,000 draws. To test a different review-cost ratio, pass `--review-cost-ratio`. The JSON records the method, seed, draws, threshold source, per-seed thresholds, and confidence intervals.

## Limits

- The test partition is CIC-IDS-2017 Thursday + Friday. It is development evidence that has already been inspected, not a blind confirmatory test.
- The benchmark prevalence (25.05%) is a property of this dataset, not of a real network.
- `alerts_per_day` is illustrative unless a site supplies its own flow volume.
- The cost ratios are relative, not currency. No measured analyst cost or breach cost is used.
- The bootstrap treats flows as independent. Flows within a capture are not independent, so the intervals are a lower bound on uncertainty.
- The score cache is a frozen artifact. If the model, threshold, or cache changes, this report must be regenerated.
