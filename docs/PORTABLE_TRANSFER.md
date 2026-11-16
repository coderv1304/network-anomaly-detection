# Portable-Ratio Cross-Dataset Transfer (P3B)

**Status:** **COMPLETE**
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.
**Direction:** CIC-IDS-2017 -> external.

This experiment is a **separate research candidate**. It does not modify the serving artifact, the frozen Tier A report, or the P3 registry row.

## 1. What changed

The P3 transfer model consumed the 12 Tier A columns directly, including raw duration, packet counts, byte counts, and packet rates. Those columns are portable in availability but not in distribution: CICFlowMeter timing and capture-speed artifacts change their scale across datasets.

This candidate consumes eight bounded ratios and log-scaled per-packet quantities derived from the same inputs:

- `log_bytes_per_packet`
- `log_fwd_bytes_per_packet`
- `log_bwd_bytes_per_packet`
- `fwd_packet_ratio`
- `packet_count_balance`
- `fwd_byte_ratio`
- `log_down_up_ratio`
- `packet_size_asymmetry`

The transform has no fitted parameters and does not use duration, flags, packet-length maxima, IP addresses, ports, or labels.

## 2. Freeze

| Item | Value |
| --- | --- |
| Portable schema version | `portable-ratio-v1` |
| Portable features | 8 |
| Schema hash | `50b17ff0342dafe9b6c8c61cb781ab0cbc8de6c73f048b5ebf8033c8b18d4e39` |
| Transfer model SHA-256 | `cc7b67733a4c5d9db12414ebc3a1c30496972c12493ba03086330341c5d3a618` |
| Serving model SHA-256 | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` |
| Training split | stratified group, 70/15/15, seed 42 |

## 3. Before / after

The baseline column is the frozen P3 Tier A result from `docs/cross_dataset_results.json`. The candidate column is the portable ratio model. Both use the same CIC-IDS-2017 group split, the same external deduplication, and the same validation-only threshold policy.

| Dataset | Metric | P3 Tier A | Portable ratio | Delta |
| --- | --- | ---: | ---: | ---: |
| cic_ids_2018 | ROC-AUC | 0.7241 | 0.7785 | +0.0544 |
| cic_ids_2018 | Average precision | 0.2048 | 0.2271 | +0.0223 |
| cic_ids_2018 | Recall @ 100/10k (rank budget) | 0.0234 | 0.0305 | +0.0071 |
| cic_ids_2018 | PPV @ 100/10k (rank budget) | 0.2009 | 0.2623 | +0.0614 |
| unsw_nb15 | ROC-AUC | 0.3793 | 0.4956 | +0.1163 |
| unsw_nb15 | Average precision | 0.1028 | 0.1088 | +0.0059 |
| unsw_nb15 | Recall @ 100/10k (rank budget) | 0.0073 | 0.0097 | +0.0024 |
| unsw_nb15 | PPV @ 100/10k (rank budget) | 0.0788 | 0.1049 | +0.0261 |

## 4. Portable model in-distribution check

| Partition | Rows | ROC-AUC | Average precision |
| --- | ---: | ---: | ---: |
| train | 1,965,756 | 0.9859 | 0.9299 |
| validation | 423,480 | 0.9859 | 0.9296 |
| test | 423,276 | 0.9859 | 0.9297 |

## 5. External results

> **Saturated operating point.** The validation-selected threshold for `10_per_10k`, `100_per_10k` is `1.000000`. Scores are compared with `>`, so a threshold at the maximum possible score emits zero strict alerts by construction. That is not a measured zero false-positive rate, and it is not a deployable operating point. The rank-budget tables below are the usable ranking diagnostic.

Prevalence and PPV are reported at each dataset's own prevalence. They are **not comparable across datasets**.

### cic_ids_2018

Rows after dedup: **11,717,527**; prevalence: **8.5978%**.

| Budget | Alerts | TP | FP | Recall | FPR | PPV | PPV @ 1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 0 | 0 | 0 | 0.0000% | 0.0000% | — | — |
| 100_per_10k | 0 | 0 | 0 | 0.0000% | 0.0000% | — | — |

**Frozen-threshold diagnostic:** threshold `1.000000`; maximum external score `1.0000`; strict alerts **0**.

The rank-budget table below is a secondary, label-free diagnostic. It picks the external score quantile that spends the budget on the evaluated stream itself.

| Budget | Alerts | TP | FP | Recall | FPR | PPV | PPV @ 1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 11,718 | 4,857 | 6,861 | 0.4821% | 0.0641% | 41.4455% | 7.0637% |
| 100_per_10k | 117,176 | 30,738 | 86,438 | 3.0511% | 0.8071% | 26.2327% | 3.6782% |

**Comparability:** Full 8/8 portable inputs; no imputation.

**Covariate shift (PSI / KS):**

| Feature | PSI | KS | Status |
| --- | ---: | ---: | --- |
| `log_bytes_per_packet` | 0.8518 | 0.1318 | available |
| `log_fwd_bytes_per_packet` | 0.6641 | 0.1893 | available |
| `log_bwd_bytes_per_packet` | 0.8085 | 0.1171 | available |
| `fwd_packet_ratio` | 0.0716 | 0.2000 | available |
| `packet_count_balance` | 0.1447 | 0.2319 | available |
| `fwd_byte_ratio` | 0.1955 | 0.0959 | available |
| `log_down_up_ratio` | 0.1549 | 0.1823 | available |
| `packet_size_asymmetry` | 0.3252 | 0.2596 | available |

### unsw_nb15

Rows after dedup: **38,375**; prevalence: **10.8638%**.

| Budget | Alerts | TP | FP | Recall | FPR | PPV | PPV @ 1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 0 | 0 | 0 | 0.0000% | 0.0000% | — | — |
| 100_per_10k | 0 | 0 | 0 | 0.0000% | 0.0000% | — | — |

**Frozen-threshold diagnostic:** threshold `1.000000`; maximum external score `0.9950`; strict alerts **0**.

The rank-budget table below is a secondary, label-free diagnostic. It picks the external score quantile that spends the budget on the evaluated stream itself.

| Budget | Alerts | TP | FP | Recall | FPR | PPV | PPV @ 1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 39 | 9 | 30 | 0.2159% | 0.0877% | 23.0769% | 2.4260% |
| 100_per_10k | 384 | 40 | 344 | 0.9666% | 1.0048% | 10.4937% | 0.9623% |

**Comparability:** Full portable schema; UNSW-NB15 lacks max-packet and flag columns, but the ratio-only schema does not use them.

**Covariate shift (PSI / KS):**

| Feature | PSI | KS | Status |
| --- | ---: | ---: | --- |
| `log_bytes_per_packet` | 3.5228 | 0.3919 | available |
| `log_fwd_bytes_per_packet` | 6.3530 | 0.7032 | available |
| `log_bwd_bytes_per_packet` | 1.6838 | 0.2554 | available |
| `fwd_packet_ratio` | 0.5134 | 0.2272 | available |
| `packet_count_balance` | 0.2644 | 0.3446 | available |
| `fwd_byte_ratio` | 1.8632 | 0.5021 | available |
| `log_down_up_ratio` | 1.4283 | 0.3765 | available |
| `packet_size_asymmetry` | 0.3619 | 0.1778 | available |

## 6. Interpretation

cic_ids_2018: average precision moved from 0.2048 to 0.2271 (+0.0223); chance-level AP on this stream is its prevalence (8.5978%). ROC-AUC moved from 0.7241 to 0.7785 (+0.0544). unsw_nb15: average precision moved from 0.1028 to 0.1088 (+0.0059); chance-level AP on this stream is its prevalence (10.8638%). ROC-AUC moved from 0.3793 to 0.4956 (+0.1163). The ratio-only schema improved both average precision and ROC-AUC on every external dataset in this run. That is evidence that raw-scale features contributed to the P3 negative transfer, not proof that the detector is production-ready. The weakest absolute result is unsw_nb15: average precision 0.1088 versus prevalence 10.8638% (+0.0001). A small gap above chance is not a deployable operating point. The validation-selected threshold saturated at 1.000000, so the strict-threshold external alert count is zero by construction and is not a measured false-positive rate.

## 7. What this does not prove

- This run trains on the original CIC-IDS-2017 Kaggle export. The DistriNet-corrected CIC-IDS-2017 CSVs are used by a separate strict-policy in-distribution sensitivity (docs/CORRECTED_LABEL_SENSITIVITY.md), not by this external-transfer artifact.
- The portable transform removes raw magnitudes, not every dataset artifact. Flow timeout, packet capture point, and label policy still differ.
- Average precision is prevalence-sensitive. The P3 baseline and this candidate are comparable only when both are evaluated on the same external stream in a full run.
- The external rank-budget table is transductive and is a diagnostic, not a deployable threshold.
- CIC-IDS-2018 covers DoS/DDoS only; PortScan is absent. UNSW-NB15 covers DoS/Reconnaissance only.
- The serving artifact, the frozen Tier A report, and all product claims are unchanged.

## 8. Reproduction

```bash
venv/Scripts/python.exe scripts/portable_transfer.py \
  --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete" \
  --unsw-dir "C:/Users/varun/Downloads/UNSW_NB15"
venv/Scripts/python.exe -m pytest tests/test_portable_features.py -q
```

