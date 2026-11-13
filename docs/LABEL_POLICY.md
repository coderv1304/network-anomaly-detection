# Label Policy (Phase P2A)

**Status:** frozen for P2A.
**Date:** 2026-11-13.
**Artifact:** [`rule_baselines.json`](rule_baselines.json).
**Script:** [`../scripts/rule_baselines.py`](../scripts/rule_baselines.py).
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.

This policy defines the binary target that every P2A rule and every later model is measured against. It uses the exact label strings found in the CIC-IDS-2017 CSV exports. It does not infer labels from filenames, row order, or prose.

## 1. Exact source strings

The following strings are the values observed in the `Label` column after the loader strips leading spaces from the header. The Web Attack strings contain U+2013 EN DASH (`–`), not an ASCII hyphen. `canonical_label` normalises dashes and whitespace before matching.

| Exact string in the data | Canonical form | Role | Family |
| --- | --- | --- | --- |
| `BENIGN` | `BENIGN` | negative | benign |
| `DDoS` | `DDoS` | positive | DDoS |
| `DoS Hulk` | `DoS Hulk` | positive | DoS Hulk |
| `DoS GoldenEye` | `DoS GoldenEye` | positive | DoS GoldenEye |
| `DoS slowloris` | `DoS slowloris` | positive | DoS slowloris |
| `DoS Slowhttptest` | `DoS Slowhttptest` | positive | DoS Slowhttptest |
| `PortScan` | `PortScan` | positive | PortScan |
| `Heartbleed` | `Heartbleed` | excluded | Heartbleed; validation-only diagnostic |
| `Web Attack – Brute Force` | `Web Attack - Brute Force` | excluded | web attack |
| `Web Attack – XSS` | `Web Attack - XSS` | excluded | web attack |
| `Web Attack – Sql Injection` | `Web Attack - Sql Injection` | excluded | web attack |
| `FTP-Patator` | `FTP-Patator` | excluded | credential attack |
| `SSH-Patator` | `SSH-Patator` | excluded | credential attack |
| `Bot` | `Bot` | excluded | botnet |
| `Infiltration` | `Infiltration` | excluded | infiltration |
| empty / missing | `<missing>` | missing | removed by the loader |

Capitalisation matters: `DoS slowloris` has a lowercase `s`, `DoS Slowhttptest` capitalises `Slow`, and `PortScan` has no space. The Web Attack label uses `Sql`, not `SQL`.

## 2. Mapping rules

- `BENIGN` is the only negative label.
- The six volumetric/scanning families are the only positive labels:
  `DDoS`, `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest`,
  `PortScan`.
- `Heartbleed` is excluded from the primary task and reported as a
  validation-only diagnostic. It is present only in the Wednesday validation
  partition.
- Web attacks, FTP/SSH patators, Bot, and Infiltration are excluded. They are
  logged in `excluded_diagnostics` but do not contribute to recall, FPR,
  precision, thresholds, or the benchmark prevalence.
- Any label not listed above is excluded with reason `unmapped label; fail
  closed`. It is never treated as benign.
- Missing labels are not a class. The frozen loader removes them.

The primary metric is **binary any-volumetric/scan**: positive if the canonical
label is one of the six families, negative if it is `BENIGN`. The secondary
metric is per-family recall within the positive families.

## 3. Partition counts

Counts are from [`rule_baselines.json`](rule_baselines.json). `Rows after
dedup` is the frozen partition size. `Primary rows` excludes labels outside the
binary task.

| Partition | Days | Rows after dedup | Primary rows | Positives | Negatives | Excluded | Benchmark prevalence |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Validation | Wednesday | 692,686 | 692,675 | 252,660 | 440,015 | 11 | 36.48% |
| Test | Thursday + Friday | 1,162,065 | 1,157,883 | 286,957 | 870,926 | 4,182 | 24.78% |

Validation label counts after dedup: `BENIGN` 440,015; `DoS Hulk` 231,072;
`DoS GoldenEye` 10,293; `DoS slowloris` 5,796; `DoS Slowhttptest` 5,499;
`Heartbleed` 11.

Test label counts after dedup: `BENIGN` 870,926; `PortScan` 158,930; `DDoS`
128,027; `Bot` 1,966; `Web Attack - Brute Force` 1,507; `Web Attack - XSS` 652;
`Infiltration` 36; `Web Attack - Sql Injection` 21.

The benchmark prevalence is computed from the primary labels only:
`positives / (positives + negatives)`. It is a property of this dataset, not a
real-network prevalence.

## 4. Blank and missing labels

The Thursday Morning WebAttacks CSV contains 288,602 blank records. With
`pandas.read_csv`, those records are all-NaN rows. The frozen loader:

1. concatenates the source files;
2. calls `drop_duplicates()` on the source columns, which collapses the
   288,602 all-NaN records to one row;
3. calls `dropna(subset=["Label"])`, which removes that collapsed row.

Verified command output: 288,602 label-NaN rows, 288,602 all-column-NaN rows,
1 unique blank row, and 0 missing labels in the frozen Thursday partition. The
blank records therefore never enter the primary task and are never treated as
benign.

If a future loader change preserves a blank string instead of NaN, the policy
still classifies it as `missing`, not `BENIGN`.

## 5. Encoding and header quirks

- The WebAttacks CSV requires the `cp1252` fallback. The en dash in the Web
  Attack labels is U+2013 after decoding.
- Raw headers have leading spaces. The loader strips them.
- The raw header contains `Fwd Header Length` twice (raw column positions 40
  and 61). pandas renames the second occurrence to `Fwd Header Length.1`.
  Neither column is part of Tier A.
- The frozen loader uses `drop_duplicates()` before `dropna(subset=["Label"])`,
  matching the training and evaluation loaders. The P2A script reuses
  `training.threshold_calibration_v2._load_partition` rather than
  reimplementing the split.

## 6. Threshold-selection discipline

Thresholds are selected on the validation partition only. The test partition
is loaded after the thresholds are frozen. `select_budget_threshold` accepts
only scores and a budget; it cannot see labels. Test labels are read only to
compute the final descriptive metrics and per-family recall.

No test label, test alert count, or test precision value is used to choose a
rule, a threshold, a budget, or a feature.

## 7. What this policy does not claim

- It does not make the excluded families benign.
- It does not claim that the six positive families are the only attacks that
  matter in production.
- It does not claim that CIC-IDS-2017 prevalence resembles a real network.
- It does not claim that a Tier A rule is a deployable detector.

## 8. Reproduction

```bash
venv/Scripts/python.exe scripts/rule_baselines.py \
  --output docs/rule_baselines.json \
  --report docs/RULE_BASELINES.md
```

The label audit and all partition counts are written to
`docs/rule_baselines.json` under `label_audit` and `partitions`.
