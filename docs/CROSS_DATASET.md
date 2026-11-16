# Cross-Dataset Transfer (P3)

**Status:** **PARTIAL**
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.
**Direction:** CIC-IDS-2017 -> external.

This report evaluates the frozen Tier A-only artifact. It does not
evaluate the 80-feature serving model, does not change its threshold, and
does not unblock P2B.

> **Follow-up:** [PORTABLE_TRANSFER.md](PORTABLE_TRANSFER.md) reports P3B, a
> separate 8-feature ratio-only candidate trained on the same CIC-IDS-2017
> export and scored on the same external streams. It improves ranking on both
> datasets but remains weak in absolute terms; it is not a replacement for this
> result or a deployable detector.

## 1. Freeze

| Item | Value |
| --- | --- |
| Tier A features | 12 |
| Schema hash | `159b0298563f36b697628428a0586b0c617c6ff1f1ec3326e33753b07f019cc9` |
| Transfer model SHA-256 | `bf6cb55adddd6ad2dd197fc0dea8ab77f8307ad4ca0fb560acdc3cb5220f246a` |
| Serving model SHA-256 | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` |
| Training split | stratified group, 70/15/15 |

The training split is not the P2B day split. P2B remains blocked because
its Monday-Tuesday partition has zero volumetric/scanning positives. The
group split is a separate transfer protocol and is not a P2B result.

## 2. Training coverage

| Family | Train | Validation | Test |
| --- | ---: | ---: | ---: |
| DDoS | 89,633 | 19,246 | 19,148 |
| DoS GoldenEye | 7,201 | 1,553 | 1,539 |
| DoS Hulk | 161,855 | 34,579 | 34,638 |
| DoS Slowhttptest | 3,851 | 820 | 828 |
| DoS slowloris | 4,131 | 838 | 827 |
| PortScan | 111,253 | 23,836 | 23,841 |

Every required positive family is present in train, validation, and test, and validation/test families overlap.

## 3. External results

Prevalence and PPV are reported at each dataset's own prevalence. They are
**not comparable across datasets**: a raw precision comparison across
different base rates is not meaningful.

Duplicate removal uses the **complete feature row**, not only the 12 Tier A features, so distinct flows that share packet counts and byte totals are not merged. Duplicate groups are collapsed to their first occurrence, which keeps label assignment deterministic.

### cic_ids_2018

Rows after dedup: **11,717,527**; prevalence: **8.5978%**.

| Budget | Alerts | TP | FP | Recall | FPR | PPV | PPV @ 1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 0 | 0 | 0 | 0.0000% | 0.0000% | — | — |
| 100_per_10k | 0 | 0 | 0 | 0.0000% | 0.0000% | — | — |

**Frozen-threshold diagnostics:** threshold `1.000000`; maximum external score `1.0000`; tied rows **333,755** with a positive rate of **20.0896%**. The strict `>` rule therefore emits **0 alerts**, and that is the primary frozen result.

The tie-aware table is a **secondary, post-hoc diagnostic**. It keeps the same threshold and alert budget and fills the budget by uniform random selection among tied scores. It does not change the artifact, schema, or threshold.

| Budget | Expected alerts | Expected TP | Expected FP | Expected recall | Expected FPR | Expected PPV | PPV @ 1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 11,718 | 2,354 | 9,364 | 0.2337% | 0.0874% | 20.0896% | 2.6286% |
| 100_per_10k | 117,176 | 23,540 | 93,636 | 2.3366% | 0.8743% | 20.0896% | 2.6286% |

The next table is a **label-free rank-budget diagnostic**. It picks the score quantile that spends the budget on the evaluated stream itself. It is transductive (it reads the unlabelled external scores) and is reported separately from the frozen threshold.

| Budget | Expected alerts | Expected TP | Expected FP | Expected recall | Expected FPR | Expected PPV | PPV @ 1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 11,718 | 2,354 | 9,364 | 0.2337% | 0.0874% | 20.0896% | 2.6286% |
| 100_per_10k | 117,176 | 23,540 | 93,636 | 2.3366% | 0.8743% | 20.0896% | 2.6286% |

**Ranking (evaluation only):** ROC-AUC `0.7241`, average precision `0.2048`.

| Family | Rows | Expected detected @100 | Expected recall @100 |
| --- | ---: | ---: | ---: |
| DoS | 231,498 | 1,235 | 0.5337% |
| DDoS | 775,955 | 22,305 | 2.8745% |

**Comparability:** Full 12/12 Tier A schema.

**Covariate shift (PSI / KS):**

| Feature | PSI | KS | Status |
| --- | ---: | ---: | --- |
| `flow_duration` | 0.4804 | 0.2378 | available |
| `total_fwd_packets` | 0.0908 | 0.2254 | available |
| `total_backward_packets` | 0.0766 | 0.1812 | available |
| `total_length_of_fwd_packets` | 0.5743 | 0.1925 | available |
| `total_length_of_bwd_packets` | 0.7983 | 0.1488 | available |
| `flow_packets_s` | 0.6238 | 0.2401 | available |
| `flow_bytes_s` | 0.4459 | 0.2481 | available |
| `packet_length_mean` | 0.8276 | 0.1318 | available |
| `packet_length_max` | 1.9907 | 0.1814 | available |
| `syn_flag_count` | 0.0000 | 0.0014 | available |
| `fin_flag_count` | 0.0000 | 0.0298 | available |
| `rst_flag_count` | 0.0000 | 0.2456 | available |

### unsw_nb15

Rows after dedup: **38,375**; prevalence: **10.8638%**.

| Budget | Alerts | TP | FP | Recall | FPR | PPV | PPV @ 1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 0 | 0 | 0 | 0.0000% | 0.0000% | — | — |
| 100_per_10k | 0 | 0 | 0 | 0.0000% | 0.0000% | — | — |

**Frozen-threshold diagnostics:** threshold `1.000000`; maximum external score `0.1855`; tied rows **0** with a positive rate of **0.0000%**. The strict `>` rule therefore emits **0 alerts**, and that is the primary frozen result.

The tie-aware table is a **secondary, post-hoc diagnostic**. It keeps the same threshold and alert budget and fills the budget by uniform random selection among tied scores. It does not change the artifact, schema, or threshold.

| Budget | Expected alerts | Expected TP | Expected FP | Expected recall | Expected FPR | Expected PPV | PPV @ 1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 0 | 0 | 0 | 0.0000% | 0.0000% | — | — |
| 100_per_10k | 0 | 0 | 0 | 0.0000% | 0.0000% | — | — |

The next table is a **label-free rank-budget diagnostic**. It picks the score quantile that spends the budget on the evaluated stream itself. It is transductive (it reads the unlabelled external scores) and is reported separately from the frozen threshold.

| Budget | Expected alerts | Expected TP | Expected FP | Expected recall | Expected FPR | Expected PPV | PPV @ 1% |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 39 | 3 | 36 | 0.0720% | 0.1052% | 7.6923% | 0.6859% |
| 100_per_10k | 384 | 30 | 354 | 0.7261% | 1.0341% | 7.8826% | 0.7042% |

**Ranking (evaluation only):** ROC-AUC `0.3793`, average precision `0.1028`.

| Family | Rows | Expected detected @100 | Expected recall @100 |
| --- | ---: | ---: | ---: |
| DoS | 1,663 | 27 | 1.6398% |
| Reconnaissance | 2,506 | 3 | 0.1197% |

**Comparability:** Partial 8/12 Tier A schema; the four missing columns are median-imputed.

**Covariate shift (PSI / KS):**

| Feature | PSI | KS | Status |
| --- | ---: | ---: | --- |
| `flow_duration` | 3.7583 | 0.2627 | available |
| `total_fwd_packets` | 1.7101 | 0.5451 | available |
| `total_backward_packets` | 2.7823 | 0.4846 | available |
| `total_length_of_fwd_packets` | 5.9615 | 0.6551 | available |
| `total_length_of_bwd_packets` | 1.4835 | 0.4003 | available |
| `flow_packets_s` | 2.2217 | 0.2476 | available |
| `flow_bytes_s` | 0.9648 | 0.3174 | available |
| `packet_length_mean` | 3.5964 | 0.4003 | available |
| `packet_length_max` | — | — | missing_imputed |
| `syn_flag_count` | — | — | missing_imputed |
| `fin_flag_count` | — | — | missing_imputed |
| `rst_flag_count` | — | — | missing_imputed |

## 4. Negative transfer

The frozen strict rule is the primary outcome. It produced zero alerts on both datasets: the validation threshold collapsed to 1.0 on score ties, and UNSW-NB15 never reaches it. The tie-aware and rank-budget tables are secondary diagnostics that do not change the artifact, schema, or threshold; the rank-budget threshold reads only unlabelled external scores. Transfer is reported with numbers, including where it is weak. cic_ids_2018: at a 100-alert/10k budget chosen on the external score quantile, expected recall 2.3366%, expected FPR 0.8743%, expected PPV 20.0896% at 8.5978% prevalence; ROC-AUC 0.7241, average precision 0.2048. The frozen threshold (1.000000) produced 0 strict alerts; the maximum external score was 1.0000. unsw_nb15: at a 100-alert/10k budget chosen on the external score quantile, expected recall 0.7261%, expected FPR 1.0341%, expected PPV 7.8826% at 10.8638% prevalence; ROC-AUC 0.3793, average precision 0.1028. The frozen threshold (1.000000) produced 0 strict alerts; the maximum external score was 0.1855. These are negative or partial results; they are preserved rather than tuned away.

## 5. What does not change

- Serving artifact and threshold: unchanged.
- P2B supervised comparison: still blocked.
- Detection **4/10**, SaaS **3/10**, overall **4.5/10**.
- Tier B remains unavailable.

## 6. Reproduction

```bash
venv/Scripts/python.exe scripts/cross_dataset_transfer.py \
  --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete" \
  --unsw-dir "C:/Users/varun/Downloads/UNSW_NB15"
venv/Scripts/python.exe -m pytest tests/test_cross_dataset_transfer.py -q
```

