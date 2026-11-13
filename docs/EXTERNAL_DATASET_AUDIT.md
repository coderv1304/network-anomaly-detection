# External Dataset Audit

**Status:** **BLOCKED for training** — the audit records feasibility, not a validated split.
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.
**Artifact:** [`EXTERNAL_DATASET_AUDIT.json`](EXTERNAL_DATASET_AUDIT.json).
**Reproduction:** [`../scripts/external_dataset_audit.py`](../scripts/external_dataset_audit.py).

This audit answers whether the two local external datasets can supply a
leakage-safe train/validation/test split in which every evaluated
volumetric/scanning family appears in all three partitions. It does not
train a model, write a registry row, or change the serving artifact.

## 1. UNSW-NB15

| Property | Value |
| --- | --- |
| Status | **coverage_pass** |
| Official source | https://research.unsw.edu.au/projects/unsw-nb15-dataset |
| Licence | not recorded; verify the official terms and citation before publication |
| Official split | 175,341 train / 82,332 test |
| Filename swap corrected | False |
| Positive families | DoS, Reconnaissance |
| Negative family | Normal |
| Label mismatches | 0 |

### Partitions

| Partition | Rows | Positive rows | Families |
| --- | ---: | ---: | --- |
| train | 69,077 | 6,089 | DoS, Reconnaissance |
| validation | 30,191 | 2,597 | DoS, Reconnaissance |
| test | 52,418 | 3,378 | DoS, Reconnaissance |

### Duplicate leakage

| Check | Train | Test |
| --- | ---: | ---: |
| Raw rows | 175,341 | 82,332 |
| Unique feature rows | 99,268 | 53,371 |
| Duplicate rows within | 45,545 | 20,152 |
| Conflicting groups | 1,772 | 575 |
| Conflicting rows | 30,528 | 8,809 |
| Leakage removed from test | — | 953 |

The `id` column restarts at 1 in the official test set; it is a row index,
not a flow key. The split is a deterministic hash of the 42 non-metadata
feature columns, so duplicate groups stay in one partition. The test
partition is the official test set after removing duplicate and
train-overlapping groups; it is not the untouched official benchmark.

### Coverage gate

**Overall: PASS**

| Family | Train | Validation | Test | Pass |
| --- | ---: | ---: | ---: | --- |
| DoS | 1,710 | 767 | 1,163 | True |
| Reconnaissance | 4,379 | 1,830 | 2,215 | True |

A coverage pass is necessary but not sufficient. Training remains
unauthorized until the schema gap and the random-split estimand are
accepted in a frozen protocol.

### Tier A schema

8/12 features available; 4 missing.

| Feature | Status | Source | Note |
| --- | --- | --- | --- |
| `flow_duration` | rename | dur | seconds; multiply by 1e6 for microseconds |
| `total_fwd_packets` | rename | spkts | — |
| `total_backward_packets` | rename | dpkts | — |
| `total_length_of_fwd_packets` | rename | sbytes | — |
| `total_length_of_bwd_packets` | rename | dbytes | — |
| `flow_packets_s` | derive | — | (spkts + dpkts) / dur; dur > 0 |
| `flow_bytes_s` | derive | — | (sbytes + dbytes) / dur; dur > 0 |
| `packet_length_mean` | derive | — | (sbytes + dbytes) / (spkts + dpkts); zero packets -> 0 |
| `packet_length_max` | missing | — | no max packet length column |
| `syn_flag_count` | missing | — | no flag-count column |
| `fin_flag_count` | missing | — | no flag-count column |
| `rst_flag_count` | missing | — | no flag-count column |

The CIC-trained serving model cannot be applied directly: UNSW lacks
`packet_length_max` and the three flag counts. A UNSW-specific model or a
new adapter would be required, and the result would not be a direct external
validation of the CIC model.

## 2. CIC-IDS-2018

| Property | Value |
| --- | --- |
| Status | **coverage_fail** |
| Official source | https://www.unsw.ca/cic/datasets/ids-2018.html |
| Licence | not recorded; verify the official terms and citation before publication |
| Capture days | 10 (2018-02-14, 2018-02-15, 2018-02-16, 2018-02-20, 2018-02-21, 2018-02-22, 2018-02-23, 2018-02-28, 2018-03-01, 2018-03-02) |
| Suspicious pre-2000 days | 1970-01-05, 1970-01-08, 1970-01-10, 1970-01-11, 1970-01-12 |
| Raw rows | 16,233,002 |
| Repeated header rows removed | 59 |
| Duplicate rows within file | 3,931,926 |
| Cross-file duplicate rows | 221,597 |
| Unique feature-identical flows | 12,079,420 |
| Conflicting duplicate groups | 0 |
| Malformed timestamps | 0 |
| Suspicious timestamps (pre-2000) | 14 |
| Files at the 1,048,575-row cap | 7 of 10 |
| Positive families present | DDoS, DoS |
| Required families missing | PortScan |

### Files

| File | Raw rows | Unique rows | Duplicates | Header rows | Columns | 1M cap |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 02-14-2018.csv | 1,048,575 | 674,808 | 373,767 | 0 | 80 | True |
| 02-15-2018.csv | 1,048,575 | 884,658 | 163,917 | 0 | 80 | True |
| 02-16-2018.csv | 1,048,575 | 626,847 | 421,727 | 1 | 80 | True |
| 02-20-2018.csv | 7,948,748 | 6,120,550 | 1,828,198 | 0 | 84 | False |
| 02-21-2018.csv | 1,048,575 | 561,405 | 487,170 | 0 | 80 | True |
| 02-22-2018.csv | 1,048,575 | 906,923 | 141,652 | 0 | 80 | True |
| 02-23-2018.csv | 1,048,575 | 910,658 | 137,917 | 0 | 80 | True |
| 02-28-2018.csv | 613,104 | 508,780 | 104,291 | 33 | 80 | False |
| 03-01-2018.csv | 331,125 | 282,656 | 48,444 | 25 | 80 | False |
| 03-02-2018.csv | 1,048,575 | 823,732 | 224,843 | 0 | 80 | True |

The 84-column `02-20` export reduces to the same 80-column schema as the
other days after dropping `Flow ID`, `Src IP`, `Src Port`, and `Dst IP`.
Those four columns are direct identifiers and are excluded from the
duplicate hash and from every split.

Seven files have exactly 1,048,575 data rows, which is 2^20 - 1 and the
Excel row ceiling. That is strong evidence of truncation, not of a
complete capture day. Re-acquire those days from the official source
before any fit; a truncated day cannot support a count or a split claim.

### Family counts by capture day

| Day | Benign | DoS | DDoS | PortScan |
| --- | ---: | ---: | ---: | ---: |
| 1970-01-05 | 1 | 0 | 0 | 0 |
| 1970-01-08 | 1 | 0 | 0 | 0 |
| 1970-01-10 | 1 | 0 | 0 | 0 |
| 1970-01-11 | 3 | 0 | 0 | 0 |
| 1970-01-12 | 8 | 0 | 0 | 0 |
| 2018-02-14 | 580,708 | 0 | 0 | 0 |
| 2018-02-15 | 787,380 | 51,314 | 0 | 0 |
| 2018-02-16 | 446,663 | 180,172 | 0 | 0 |
| 2018-02-20 | 5,543,362 | 0 | 575,364 | 0 |
| 2018-02-21 | 360,809 | 0 | 200,591 | 0 |
| 2018-02-22 | 837,509 | 0 | 0 | 0 |
| 2018-02-23 | 826,257 | 0 | 0 | 0 |
| 2018-02-28 | 453,811 | 0 | 0 | 0 |
| 2018-03-01 | 191,071 | 0 | 0 | 0 |
| 2018-03-02 | 676,813 | 0 | 0 | 0 |

### Temporal day split

**Status: coverage_fail**

| Day | Partition |
| --- | --- |
| 2018-02-14 | train |
| 2018-02-15 | train |
| 2018-02-16 | train |
| 2018-02-20 | train |
| 2018-02-21 | train |
| 2018-02-22 | train |
| 2018-02-23 | validation |
| 2018-02-28 | validation |
| 2018-03-01 | test |
| 2018-03-02 | test |

| Partition | Rows | Positive rows |
| --- | ---: | ---: |
| train | 9,658,305 | 1,007,441 |
| validation | 1,335,556 | 0 |
| test | 1,085,545 | 0 |

Required families are absent from the dataset: PortScan. Families absent from at least one partition: DDoS, DoS. Validation and test positive families do not overlap.

A day-based split is also a family split here: every DoS and DDoS
positive falls in the early capture days, so validation and test hold
no volumetric positives. The temporal result is recorded but rejected.
Flows that appear on more than one day are assigned to their first
capture day, so no flow can span partitions.

### Group-hash split

**Status: coverage_fail**

| Partition | Rows | Positive rows | DoS | DDoS | PortScan |
| --- | ---: | ---: | ---: | ---: | ---: |
| train | 8,457,261 | 704,840 | 161,943 | 542,897 | 0 |
| validation | 1,810,652 | 150,248 | 34,507 | 115,741 | 0 |
| test | 1,811,507 | 152,353 | 35,036 | 117,317 | 0 |

Required families are absent from the dataset: PortScan.

The group split keeps feature-identical flows in one partition. It is a
random split, not a temporal one, so it cannot support a claim about
future traffic. It also cannot create the PortScan family.

### Tier A schema

12/12 features available; 0 missing.

All 12 Tier A features exist under CICFlowMeter-2018 names. The blocker
is family coverage and provenance, not the feature schema.

## 3. Decision

- **UNSW-NB15:** usable for a leakage-safe, random-split coverage study, but not as a direct external validation of the CIC-trained model because 4 Tier A features are missing.
- **CIC-IDS-2018:** contains DoS and DDoS across several days but no PortScan at all. A day-based split fails the coverage gate because the positives are concentrated in the early days; a group-hash split can cover DoS and DDoS only. It cannot close A4 for a claim that includes PortScan.
- **Training authorized:** no.
- **P2B status:** blocked.

## 4. Findings

- UNSW-NB15: the official split is 175,341 train / 82,332 test. The local filenames match the official split.
- UNSW-NB15: DoS (volumetric) and Reconnaissance (scanning) are the only in-scope positive families. Both appear in all three proposed partitions, so the coverage gate is PASS.
- UNSW-NB15: feature-identical rows are pervasive. The audit removed 45,545 duplicate train rows, 20,152 duplicate test rows, and 953 test rows that duplicated a train group. It also excluded 1,772 train groups (30,528 rows) and 575 test groups (8,809 rows) whose feature-identical rows had inconsistent labels. A random split without this grouping would leak near-identical flows.
- UNSW-NB15: only 8/12 Tier A features are available. 4 are missing (packet_length_max and the three flag counts). The CIC-trained serving model cannot be applied directly; a UNSW-specific model or a new feature adapter would be required.
- CIC-IDS-2018: the complete local set contains 10 capture day(s) (2018-02-14, 2018-02-15, 2018-02-16, 2018-02-20, 2018-02-21, 2018-02-22, 2018-02-23, 2018-02-28, 2018-03-01, 2018-03-02) and 12,079,420 unique feature-identical flows after removing 3,931,926 within-file and 221,597 cross-file duplicate rows. Observed volumetric families are DDoS, DoS; required families missing from the whole set: PortScan.
- CIC-IDS-2018: the day-based temporal split FAILS the coverage gate. All DoS and DDoS positives fall in the early capture days, so a 60/20/20 day split leaves validation and test with no volumetric positives. A day split is therefore a family split.
- CIC-IDS-2018: a deterministic group-hash split FAILS the coverage gate. It can place DoS and DDoS in all three partitions, but it cannot manufacture a PortScan family that the dataset does not contain, and it is a random split, not a temporal one.
- CIC-IDS-2018: all 12 Tier A features are present under CICFlowMeter-2018 names, and the 84-column 02-20 export reduces to the same 80-column schema after dropping `Flow ID`, `Src IP`, `Src Port`, and `Dst IP`.
- CIC-IDS-2018: data-quality warnings remain. 59 repeated header rows were removed; 14 rows carry pre-2000 (mostly 1970) timestamps; 7 files have exactly 1,048,575 rows, consistent with a 1,000,000-row cap above the header. The 4 GB 02-20 file is not capped and is the only 7.9M-row day.

## 5. What does not change

- Serving artifact and threshold: unchanged.
- Detection **4/10**, SaaS **3/10**, overall **4.5/10**.
- Scope: volumetric/scanning only; no blocking, botnet, web-attack,
  infiltration, zero-day, general NIDS, or production-readiness claim.
- Tier B fan-out remains unavailable.

## 6. Reproduction

```bash
venv/Scripts/python.exe scripts/external_dataset_audit.py \
  --unsw-dir ~/Downloads/UNSW_NB15 \
  --cic-dir "~/Downloads/CIC IDS 2018 Complete" \
  --output docs/EXTERNAL_DATASET_AUDIT.json \
  --report docs/EXTERNAL_DATASET_AUDIT.md
venv/Scripts/python.exe -m pytest tests/test_external_dataset_audit.py -q
```

