# CIDDS-002 Scanning Audit

**Status:** **BLOCKED for training** — the audit records feasibility, not a validated fit.
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.
**Artifact:** [`CIDDS002_AUDIT.json`](CIDDS002_AUDIT.json).
**Reproduction:** [`../scripts/cidds002_audit.py`](../scripts/cidds002_audit.py).

This audit answers whether CIDDS-002 can supply a leakage-safe temporal
split in which the PortScan family appears in train, validation, and test.
It does not train a model, write a registry row, or change the serving
artifact.

## 1. Dataset

| Property | Value |
| --- | --- |
| Status | **coverage_pass** |
| Official source | https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/ |
| Citation | Ring, Wunderlich, Scheuring, Landes, Hotho (2017), Creation of Flow-Based Data Sets for Intrusion Detection, Journal of Information Warfare 16(4). |
| Licence | not recorded; verify the official terms and citation before publication |
| Format | Unidirectional NetFlow |
| Raw rows | 16,161,183 |
| Unique flow keys | 16,131,290 |
| Duplicate records removed | 29,893 |
| Feature-only duplicates kept | 5,579,481 |
| Conflicting duplicate groups | 0 |
| Capture days | 14 |

### Files

| File | Rows | Columns | SHA-256 |
| --- | ---: | ---: | --- |
| week1.csv | 8,185,992 | 16 | `5bb6197012b73839…` |
| week2.csv | 7,975,191 | 16 | `833e2875c57574dc…` |
| attacks_logs_intern.csv | 43 | 8 | `737d3fbf6b82251f…` |

### Rows per capture day

| Day | Rows |
| --- | ---: |
| 2017-08-02 | 1,640,994 |
| 2017-08-03 | 1,573,666 |
| 2017-08-04 | 1,449,953 |
| 2017-08-05 | 130,058 |
| 2017-08-06 | 49,174 |
| 2017-08-07 | 1,511,443 |
| 2017-08-08 | 1,830,704 |
| 2017-08-10 | 1,803,836 |
| 2017-08-11 | 967,920 |
| 2017-08-12 | 429,092 |
| 2017-08-13 | 60,903 |
| 2017-08-14 | 1,543,820 |
| 2017-08-15 | 1,838,795 |
| 2017-08-16 | 1,330,825 |

No traffic was captured on 2017-08-09; the two week files do not
overlap and there is a full-day gap between train and validation.

## 2. Label policy

| Raw value | Meaning | Treatment |
| --- | --- | --- |
| `label=normal` | benign | negative |
| `label=attacker`, `attackType=scan` | scan source | **PortScan** (or PingSweep) |
| `label=victim` | scan target response | excluded |

The raw `attackType` value is `scan`, not `portScan`. Ping sweeps
(`nmap -sP -PE`) are host discovery and are split out of the PortScan
family. Victim flows are excluded rather than treated as benign, so
response traffic cannot inflate the false-positive base.

## 3. Duplicate policy

Duplicate keys are Date first seen plus the 11 NetFlow attributes. The start timestamp is part of the identity: the same 5-tuple and counters recur across days, so feature-only deduplication would delete real traffic and distort prevalence. Feature-only duplicates are reported but kept.

## 4. Temporal split

**Status: coverage_pass**

- Train: 2017-08-02 to 2017-08-08 (week 1)
- Validation: 2017-08-10 to 2017-08-12T03:23:44.203037
- Test: 2017-08-12T03:23:44.203037 to 2017-08-16

The boundary is the end of activityID 29 (`2017-08-12T03:23:44.203037`).
Cutting at midnight would split one nmap run across validation and test.

| Partition | Rows | PortScan flows | Normal | PingSweep |
| --- | ---: | ---: | ---: | ---: |
| train | 8,165,541 | 150,533 | 7,918,499 | 268 |
| validation | 2,778,158 | 80,572 | 2,651,320 | 0 |
| test | 5,187,591 | 101,812 | 5,026,910 | 801 |

### Coverage gate

**Overall: PASS**

| Family | Train | Validation | Test | Pass |
| --- | ---: | ---: | ---: | --- |
| PortScan | 150,533 | 80,572 | 101,812 | True |

Every positive family is present in train, validation, and test, and validation/test families overlap.

### Port-scan types

| Partition | SYN | ACK | FIN | UDP | Other |
| --- | ---: | ---: | ---: | ---: | ---: |
| train | 35,417 | 39,112 | 54,285 | 21,719 | 0 |
| validation | 27,335 | 563 | 25,969 | 26,705 | 0 |
| test | 4,502 | 2,513 | 41,605 | 53,192 | 0 |

## 5. Attacks

| ID | Partition | nmap args | Type | Attacker flows |
| ---: | --- | --- | --- | ---: |
| 1 | train | `nmap args: -sU -T 0` | UDP | 4,398 |
| 2 | train | `nmap args: -sF -T 2` | FIN | 4,540 |
| 3 | train | `nmap args: -sF -T 3` | FIN | 7,232 |
| 4 | train | `nmap args: -sF -T 2` | FIN | 31,764 |
| 5 | train | `nmap args: -n -sP -PE -T 2` | PingSweep | 492 |
| 6 | train | `nmap args: -sU -T 2` | UDP | 7,576 |
| 7 | train | `nmap args: -sA -T 3` | ACK | 5,034 |
| 8 | train | `nmap args: -sA -T 1` | ACK | 4,594 |
| 9 | train | `nmap args: -sF -T 3` | FIN | 5,096 |
| 10 | train | `nmap args: -sA -T 1` | ACK | 11,527 |
| 11 | train | `nmap args: -sF -T 3` | FIN | 39,023 |
| 12 | train | `nmap args: -sS -T 1` | SYN | 11,774 |
| 13 | train | `nmap args: -sU -T 1` | UDP | 10,143 |
| 14 | train | `nmap args: -sS -T 3` | SYN | 5,114 |
| 15 | train | `nmap args: -sS -T 1` | SYN | 7,540 |
| 16 | train | `nmap args: -sU -T 1` | UDP | 2,046 |
| 17 | train | `nmap args: -sA -T 3` | ACK | 40,025 |
| 18 | train | `nmap args: -sA -T 2` | ACK | 4,436 |
| 19 | train | `nmap args: -sU -T 2` | UDP | 9,462 |
| 20 | train | `nmap args: -sS -T 2` | SYN | 35,226 |
| 21 | validation | `nmap args: -sS -T 2` | SYN | 31,953 |
| 22 | validation | `nmap args: -sF -T 1` | FIN | 11,585 |
| 23 | validation | `nmap args: -sU -T 3` | UDP | 27,749 |
| 24 | validation | `nmap args: -sF -T 2` | FIN | 11,532 |
| 25 | validation | `nmap args: -sF -T 3` | FIN | 15,184 |
| 26 | validation | `nmap args: -sF -T 1` | FIN | 11,518 |
| 27 | validation | `nmap args: -sS -T 1` | SYN | 11,716 |
| 28 | validation | `nmap args: -sA -T 1` | ACK | 906 |
| 29 | validation | `nmap args: -sS -T 1` | SYN | 4,695 |
| 30 | test | `nmap args: -sF -T 2` | FIN | 4,424 |
| 31 | test | `nmap args: -sU -T 1` | UDP | 8,524 |
| 32 | test | `nmap args: -sF -T 3` | FIN | 43,312 |
| 33 | test | `nmap args: -sF -T 1` | FIN | 11,604 |
| 34 | test | `nmap args: -n -sP -PE -T 2` | PingSweep | 439 |
| 35 | test | `nmap args: -sA -T 3` | ACK | 5,025 |
| 36 | test | `nmap args: -sF -T 2` | FIN | 11,405 |
| 37 | test | `nmap args: -n -sP -PE -T 1` | PingSweep | 524 |
| 38 | test | `nmap args: -n -sP -PE -T 1` | PingSweep | 472 |
| 39 | test | `nmap args: -sU -T 2` | UDP | 29,210 |
| 40 | test | `nmap args: -sU -T 2` | UDP | 27,298 |
| 41 | test | `nmap args: -sU -T 2` | UDP | 9,486 |
| 42 | test | `nmap args: -sS -T 2` | SYN | 4,441 |
| 43 | test | `nmap args: -sS -T 1` | SYN | 4,517 |

## 6. Tier A schema

9/12 features available; 3 missing.

| Feature | Status | Source | Note |
| --- | --- | --- | --- |
| `flow_duration` | rename | Duration | seconds; multiply by 1e6 for microseconds |
| `total_fwd_packets` | rename | Packets | unidirectional; no backward counterpart |
| `total_backward_packets` | missing | — | unidirectional capture |
| `total_length_of_fwd_packets` | rename | Bytes | unidirectional |
| `total_length_of_bwd_packets` | missing | — | unidirectional capture |
| `flow_packets_s` | derive | — | Packets / Duration; Duration > 0 |
| `flow_bytes_s` | derive | — | Bytes / Duration; Duration > 0 |
| `packet_length_mean` | derive | — | Bytes / Packets; Packets > 0 |
| `packet_length_max` | missing | — | no packet length column |
| `syn_flag_count` | derive | — | Flags contains 'S' |
| `fin_flag_count` | derive | — | Flags contains 'F' |
| `rst_flag_count` | derive | — | Flags contains 'R' |

The missing features are structural, not an ingestion gap: a
unidirectional NetFlow record has no backward counters and no packet
length maximum. CIDDS-002 therefore supports a separate scanning study,
not a validation of the bidirectional serving model.

## 7. Candidate shortlist

| Dataset | PortScan labels | Tier A | Verdict |
| --- | --- | --- | --- |
| **CIDDS-002** | explicit (`label=attacker`, `attackType=scan`) | no (unidirectional NetFlow) | **selected for a separate scanning study** |
| CIC-IDS-2017 Friday afternoon | explicit `PortScan` | yes (80 CICFlowMeter features) | in-domain source; A1f zero-shot only, because PortScan exists only on the test day |
| CIDDS-001 | explicit (`AttackType=portScan`) | no | rejected: port scans only in weeks 1-2 and mixed with DoS/brute force; CIDDS-002 is purpose-built |
| CIC-DDoS2019 | none | n/a | rejected: its own taxonomy classifies `PORTMAP` as a reflection/amplification DDoS subtype, there is no scanning branch, and the release has no benign flows |
| BCCC-CSE-CIC-IDS2018 | unverified | yes | rejected: a re-release of the same 2018 capture that contains no PortScan, and not an independent collection |
| UNSW-NB15 | no (`Reconnaissance` only) | partial (8/12) | external scanning proxy, not a PortScan label |

## 8. Decision

- **CIDDS-002:** usable for a separate, leakage-safe, temporal scanning study with explicit port-scan labels. It is unidirectional NetFlow and cannot validate the bidirectional Tier A serving model.
- **Training authorized:** no.
- **P2B status:** blocked.

## 9. Findings

- CIDDS-002 contains 16,161,183 raw flow records across 14 capture days, and 16,131,290 unique flow keys after removing 29,893 exact duplicate records.
- CIDDS-002 is the only public dataset in this review with explicit port-scan labels and benign traffic in the same capture period: 150,533 train, 80,572 validation, and 101,812 test PortScan flows. The coverage gate is PASS.
- The raw attackType value is 'scan', not 'portScan'. The family mapping uses label=attacker plus attackType=scan, and splits ping sweeps (nmap -sP -PE) out of the PortScan family because they are host discovery, not port scanning.
- Victim flows are excluded, not treated as benign. They are the target's responses to a scan, and putting them in the benign base would distort the false-positive rate at low alert budgets.
- Duplicate policy differs from CIC-IDS-2018 on purpose. CIDDS-002 is unidirectional NetFlow, so Date first seen is part of the flow identity: 5,579,481 feature-only duplicates are reported but kept. Removing them would delete legitimate repeated traffic and change prevalence.
- Only 9/12 Tier A features are available and 3 are missing. The missing ones are the backward counters and packet_length_max, which cannot exist in a unidirectional NetFlow record. This dataset cannot validate the bidirectional serving model; it supports a separate scanning study.
- The validation/test boundary is the end of activityID 29, not midnight. Cutting at midnight would split one nmap run across two partitions.
- The temporal split also shifts the scan-type mix. UDP is 14.4% of train PortScan flows but 52.2% of test, while ACK falls from 26.0% to 2.5%. A PortScan result on this split is partly a scan-type generalization test, not a uniform port-scan benchmark.

## 10. What does not change

- Serving artifact and threshold: unchanged.
- Detection **4/10**, SaaS **3/10**, overall **4.5/10**.
- Scope: volumetric/scanning only; no blocking, botnet, web-attack,
  infiltration, zero-day, general NIDS, or production-readiness claim.
- Tier B fan-out remains unavailable.

## 11. Reproduction

```bash
venv/Scripts/python.exe scripts/cidds002_audit.py \
  --cidds-dir ~/Downloads/CIDDS-002 \
  --output docs/CIDDS002_AUDIT.json \
  --report docs/CIDDS002_AUDIT.md
venv/Scripts/python.exe -m pytest tests/test_cidds002_audit.py -q
```

