# Corrected-Label Sensitivity (P3C)

**Status:** **COMPLETE**
**Scope:** in-distribution sensitivity on the DistriNet CIC-IDS-2017 release. Not an external-transfer result.

This is a **separate research check**. It does not modify the serving
artifact, the frozen Tier A schema, the P3B artifact, or any existing
claim.

## 1. Label policy

The strict frozen policy was applied before any model was trained:

- Case/spelling aliases only: `Portscan` -> `PortScan`, `Botnet` -> `Bot`, `DoS Slowloris` -> `DoS slowloris`, `Web Attack - SQL Injection` -> `Web Attack - Sql Injection`.
- Every `- Attempted` label is excluded. The frozen policy has no
  attempted category, so treating attempted rows as positives would be
  a new policy rather than a sensitivity run.
- `Infiltration - Portscan` and every frozen non-target family are
  excluded for the same reason.

## 2. Data under the policy

- Rows read: **2,099,976**
- Rows kept: **2,008,410**
- Prevalence: **21.2030%**
- Rows with non-finite/negative portable inputs: **0** (cleaned to 0 by the fixed transform)

| Kept label | Rows |
| --- | ---: |
| `BENIGN` | 1,582,566 |
| `DDoS` | 95,144 |
| `DoS GoldenEye` | 7,567 |
| `DoS Hulk` | 158,468 |
| `DoS Slowhttptest` | 1,740 |
| `DoS slowloris` | 3,859 |
| `PortScan` | 159,066 |

| Excluded reason | Rows |
| --- | ---: |
| attempted variant; strict frozen policy excludes | 11,979 |
| corrected-release portscan category; not in frozen policy | 71,767 |
| excluded; botnet | 736 |
| excluded; credential attack | 6,933 |
| excluded; infiltration | 36 |
| excluded; validation-only diagnostic | 11 |
| excluded; web attack | 104 |

> The corrected release is also a re-extraction with fixed
> CICFlowMeter flow boundaries. Differences below are therefore
> **label + extraction**, not label-only.

## 3. Split and model

- Stratified group split, 70/15/15, seed 42.
- Random Forest, 200 trees, seed 42.
- Thresholds selected only on the validation partition.

| Partition | Rows | Positives |
| --- | ---: | ---: |
| train | 1,408,187 | 298,153 |
| validation | 300,807 | 63,941 |
| test | 299,416 | 63,750 |

Coverage gate: **PASS**.

## 4. In-distribution result

| Partition | ROC-AUC | Average precision |
| --- | ---: | ---: |
| train | 0.9989 | 0.9919 |
| validation | 0.9987 | 0.9912 |
| test | 0.9988 | 0.9916 |

## 5. Validation thresholds and test behavior

| Budget | Threshold | Alerts | TP | FP | Recall | FPR | PPV |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10_per_10k | 1.0000 | 0 | 0 | 0 | 0.0000% | 0.0000% | — |
| 100_per_10k | 1.0000 | 0 | 0 | 0 | 0.0000% | 0.0000% | — |

### Per-family recall at 100 alerts/10k

| Family | Rows | Detected | Recall |
| --- | ---: | ---: | ---: |
| `DDoS` | 14,097 | 0 | 0.0000% |
| `DoS GoldenEye` | 1,135 | 0 | 0.0000% |
| `DoS Hulk` | 23,755 | 0 | 0.0000% |
| `DoS Slowhttptest` | 266 | 0 | 0.0000% |
| `DoS slowloris` | 611 | 0 | 0.0000% |
| `PortScan` | 23,886 | 0 | 0.0000% |

## 6. Comparison with the original-Kaggle P3B arm

| Metric | P3B original | P3C corrected | Delta |
| --- | ---: | ---: | ---: |
| ROC-AUC | 0.9859 | 0.9988 | +0.0129 |
| Average precision | 0.9297 | 0.9916 | +0.0618 |
| Test prevalence | 19.0942% | 21.2914% | — |

## 7. Interpretation

The corrected release kept 2,008,410 of 2,099,976 rows under the strict policy (21.2030% positive). On the grouped test partition the portable model reached ROC-AUC 0.9988 and average precision 0.9916. The original-Kaggle P3B arm reached ROC-AUC 0.9859 and average precision 0.9297 under the same split algorithm; the corrected-arm deltas are +0.0129 and +0.0618. Test prevalence was 19.0942% in the original arm and 21.2914% in the corrected arm; average precision is prevalence-sensitive, so the AP comparison needs that context. The validation-selected threshold saturated at 1.000000 for 10_per_10k, 100_per_10k; strict test alerts are therefore zero by construction, not a measured false-positive rate. Because the corrected release is also a CICFlowMeter re-extraction, a difference cannot be attributed to labels alone. This is a sensitivity check, not a replacement for the original result and not external evidence.

## 8. What this does not prove

- The corrected release is both a relabelling and a re-extraction with a fixed CICFlowMeter. A difference from the original Kaggle arm cannot be attributed to labels alone.
- The strict policy excludes every `- Attempted` row. That is a policy choice, not evidence that attempted attacks are harmless.
- This is an in-distribution sensitivity under the P3B stratified-group protocol. It does not report external transfer and does not establish deployability.
- The serving artifact, the frozen Tier A schema, and every existing claim are unchanged.

## 9. Reproduction

```bash
venv/Scripts/python.exe scripts/corrected_label_sensitivity.py \
  --dir data/CICIDS2017_improved
venv/Scripts/python.exe -m pytest tests/test_corrected_label_sensitivity.py -q
```

