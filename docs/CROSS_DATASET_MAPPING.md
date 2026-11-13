# Cross-Dataset Mapping and Freeze

**Status:** **FROZEN before external scoring.**
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.

This file is written before the frozen Tier A model scores any external
label. It records the schema, the model artifact hash, the label mapping,
the feature mapping, and the missing-feature policy.

## 1. Freeze

| Item | Value |
| --- | --- |
| Tier A features | 12 |
| Schema hash | `159b0298563f36b697628428a0586b0c617c6ff1f1ec3326e33753b07f019cc9` |
| Schema version | `cic-ids-2017-12f-159b0298563f` |
| Transfer model | `models/model_bundle_rf_tierA_group_seed42.pkl` |
| Transfer model SHA-256 | `bf6cb55adddd6ad2dd197fc0dea8ab77f8307ad4ca0fb560acdc3cb5220f246a` |
| Serving model SHA-256 | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` |
| Training direction | CIC-IDS-2017 -> external |

The transfer model is a **Tier A-only** Random Forest. It is a separate
research artifact. The 80-feature serving model and its registry row are
not modified. Tier B is unavailable and is not mixed into any transfer
number.

**Deviation recorded:** the external-data audits inspected label
distributions and feature schemas for feasibility before this freeze. No
external detection performance was computed before the freeze. The freeze
covers the model, thresholds, label mapping, and feature mapping used for
scoring.

## 2. Tier A schema

| Feature | Unit | CIC-IDS-2017 column |
| --- | --- | --- |
| `flow_duration` | per-flow | `Flow Duration` |
| `total_fwd_packets` | per-flow | `Total Fwd Packets` |
| `total_backward_packets` | per-flow | `Total Backward Packets` |
| `total_length_of_fwd_packets` | per-flow | `Total Length of Fwd Packets` |
| `total_length_of_bwd_packets` | per-flow | `Total Length of Bwd Packets` |
| `flow_packets_s` | per-flow | `Flow Packets/s` |
| `flow_bytes_s` | per-flow | `Flow Bytes/s` |
| `packet_length_mean` | per-flow | `Packet Length Mean` |
| `packet_length_max` | per-flow | `Max Packet Length` |
| `syn_flag_count` | per-flow | `SYN Flag Count` |
| `fin_flag_count` | per-flow | `FIN Flag Count` |
| `rst_flag_count` | per-flow | `RST Flag Count` |

The schema is the P2A portable Tier A contract. It is frozen at the hash
above; no feature was added, removed, or renamed after external scoring
began.

## 3. Dataset provenance and licences

| Dataset | Version | Source | Licence status |
| --- | --- | --- | --- |
| CIC-IDS-2018 | 10 daily CSVs | https://www.unb.ca/cic/datasets/ids-2018.html | cleared_for_academic_use_with_citation |
| UNSW-NB15 | official train/test CSV | https://research.unsw.edu.au/projects/unsw-nb15-dataset | cleared_for_academic_use_with_citation |
| CIDDS-002 | two-week NetFlow | https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/ | **BLOCKED for Tier A** (not_used_for_tier_a_transfer) |

### cic_ids_2018

> You may redistribute, republish, and mirror the CSE-CIC-IDS2018 dataset in any form. However, any use or redistribution of the data must include a citation to the CSE-CIC-IDS2018 dataset and a link to this page in AWS.

Citation: Sharafaldin, Lashkari, Ghorbani (2018), Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization, ICISSP 2018.

Link: https://registry.opendata.aws/cse-cic-ids2018

### unsw_nb15

> Free use of the UNSW-NB15 dataset for academic research purposes is hereby granted in perpetuity. Use for commercial purposes should be agreed by the authors.

Citation: Moustafa and Slay (2015), UNSW-NB15: a comprehensive data set for network intrusion detection systems, MilCIS 2015, plus the four additional papers listed on the official page.

Link: https://research.unsw.edu.au/projects/unsw-nb15-dataset

CIDDS-002 is unidirectional NetFlow. Its licence terms were not verified
for publication, and it cannot supply the two backward counters or
`packet_length_max`. It is recorded as **BLOCKED for Tier A transfer** and
is not part of any transfer number. See `docs/CIDDS002_AUDIT.md`.

## 4. Feature mapping

### CIC-IDS-2018 — 12/12 available

| Feature | Status | Source column | Note |
| --- | --- | --- | --- |
| `flow_duration` | rename | Flow Duration | — |
| `total_fwd_packets` | rename | Tot Fwd Pkts | — |
| `total_backward_packets` | rename | Tot Bwd Pkts | — |
| `total_length_of_fwd_packets` | rename | TotLen Fwd Pkts | — |
| `total_length_of_bwd_packets` | rename | TotLen Bwd Pkts | — |
| `flow_packets_s` | rename | Flow Pkts/s | — |
| `flow_bytes_s` | rename | Flow Byts/s | — |
| `packet_length_mean` | rename | Pkt Len Mean | — |
| `packet_length_max` | rename | Pkt Len Max | — |
| `syn_flag_count` | rename | SYN Flag Cnt | — |
| `fin_flag_count` | rename | FIN Flag Cnt | — |
| `rst_flag_count` | rename | RST Flag Cnt | — |

### UNSW-NB15 — 8/12 available

| Feature | Status | Source column | Note |
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

## 5. Label mapping

| Dataset | Positive | Negative | Excluded |
| --- | --- | --- | --- |
| CIC-IDS-2018 | `DDoS*`, `DoS*` | `Benign` | Bot, brute force, infiltration, SQL injection, XSS |
| UNSW-NB15 | `DoS`, `Reconnaissance` | `Normal` | Analysis, Backdoor, Exploits, Fuzzers, Generic, Shellcode, Worms |

Unknown labels are excluded, never treated as benign.

## 6. Missing-feature policy

A dataset that lacks a Tier A column receives the CIC-IDS-2017 training
median for that column. The medians are stored in the model manifest and
in the model bundle. A result produced under this policy is reported as a
**partial-schema transfer**, not a full Tier A validation. UNSW-NB15
lacks `packet_length_max`, `syn_flag_count`, `fin_flag_count`, and
`rst_flag_count`; its result is partial-schema.

## 7. Artifact hashes

| File | SHA-256 |
| --- | --- |
| `02-14-2018.csv` | `acff8bc61376ee031d80878ee6099e0b1a87a1bd711d8068298421418c9f8147` |
| `02-15-2018.csv` | `fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b` |
| `02-16-2018.csv` | `1a4919faa0c49c7af97230b0c2d076eba23ee6dd81103a3801d51ac316355d8b` |
| `02-20-2018.csv` | `7287a4d7740a1dddbf330ceb2beb6a4889d33ba63674558a68b5eb50d16711df` |
| `02-21-2018.csv` | `a5f4a1c2689e0aa6566c03a58466de9c407c0be0cbd3cc69306544026611be04` |
| `02-22-2018.csv` | `da33c927018274f9d49b145baa00e4ce0526c25b3b890b34c489e247b5e24544` |
| `02-23-2018.csv` | `d0a7f5059d9823b6e9b392b759e306481a3502d190dea7a1b5502ae079ea069b` |
| `02-28-2018.csv` | `f15e2a12304446058a0186c8ad67de2bd15735a9ba5c70c9a1f4c4242ab06771` |
| `03-01-2018.csv` | `b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf` |
| `03-02-2018.csv` | `d96f38e7496aba83475031e6fb8c6fdf1abf6aa1b71325a917798f3c7de93de1` |
| `unsw_train_official.csv` | `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa` |
| `unsw_test_official.csv` | `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559` |

## 8. Reproduction

```bash
venv/Scripts/python.exe scripts/cross_dataset_transfer.py \
  --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete" \
  --unsw-dir "C:/Users/varun/Downloads/UNSW_NB15"
```

