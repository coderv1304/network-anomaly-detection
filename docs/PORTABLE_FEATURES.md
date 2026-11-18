# Portable Features (Phase P2A)

**Status:** frozen for P2A.
**Date:** 2026-11-13.
**Artifact:** [`rule_baselines.json`](rule_baselines.json).
**Script:** [`../scripts/rule_baselines.py`](../scripts/rule_baselines.py).
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.

This document defines the portable feature contract that any later model must consume. It separates **Tier A** per-flow features, which are available in the CIC-IDS-2017 CSV exports, from **Tier B** windowed features, which require raw packets or a stateful aggregator.

The primary claim in P2A is **Tier A only**. Tier B fan-out is not approximated from per-flow columns.

## 1. Tier A — per-flow schema (required)

Every Tier A feature is computed from one CSV row. No cross-row state, timestamps, or source-keyed window is used.

| Portable name | CIC column after header strip | Unit | Definition | Missing / repair policy |
| --- | --- | --- | --- | --- |
| `flow_duration` | `Flow Duration` | microseconds | Flow duration | Non-finite or negative -> 0 for derived features; counts logged |
| `total_fwd_packets` | `Total Fwd Packets` | packets | Forward packet count | Non-finite or negative -> 0 |
| `total_backward_packets` | `Total Backward Packets` | packets | Backward packet count | Non-finite or negative -> 0 |
| `total_length_of_fwd_packets` | `Total Length of Fwd Packets` | bytes | Forward byte count | Non-finite or negative -> 0 |
| `total_length_of_bwd_packets` | `Total Length of Bwd Packets` | bytes | Backward byte count | Non-finite or negative -> 0 |
| `flow_packets_s` | `Flow Packets/s` | packets/s | Packet rate | Non-finite or negative -> `total_packets / duration_s`; if `duration_s <= 0`, `total_packets * 1e6` |
| `flow_bytes_s` | `Flow Bytes/s` | bytes/s | Byte rate | Non-finite or negative -> `total_bytes / duration_s`; if `duration_s <= 0`, `total_bytes * 1e6` |
| `packet_length_mean` | `Packet Length Mean` | bytes | Mean packet length | Non-finite or negative -> 0 |
| `packet_length_max` | `Max Packet Length` | bytes | Maximum packet length | Non-finite or negative -> 0 |
| `syn_flag_count` | `SYN Flag Count` | count | Packets with SYN | Non-finite or negative -> 0 |
| `fin_flag_count` | `FIN Flag Count` | count | Packets with FIN | Non-finite or negative -> 0 |
| `rst_flag_count` | `RST Flag Count` | count | Packets with RST | Non-finite or negative -> 0 |

**Column-name mismatch:** the prompt calls the maximum packet length `packet_length_max`. The CIC-IDS-2017 column is `Max Packet Length`, not `Packet Length Max`. The script maps the portable name to `Max Packet Length`.

### Derived Tier A features

| Portable name | Definition |
| --- | --- |
| `total_packets` | `total_fwd_packets + total_backward_packets` |
| `total_bytes` | `total_length_of_fwd_packets + total_length_of_bwd_packets` |
| `syn_ratio` | `syn_flag_count / total_packets`, 0 when `total_packets == 0`, clipped to `[0, 1]` |
| `rst_ratio` | `rst_flag_count / total_packets`, 0 when `total_packets == 0`, clipped to `[0, 1]` |
| `short_flow_flag` | `1` when `flow_duration < 1,000,000` microseconds and `total_packets <= 3`, else `0` |

`short_flow_flag` uses microseconds because CIC's `Flow Duration` is in microseconds. `1,000,000` microseconds is one second.

### Rate repair policy

The CIC exports contain a small number of zero-duration and malformed rows. A raw `inf`, `NaN`, or negative rate is not usable as a ranking score, so the script repairs it:

1. If `duration_s > 0`, use `total / duration_s`.
2. If `duration_s <= 0`, use `total * 1e6`. This is the rate implied by a one-microsecond flow: a finite, deliberately conservative upper-bound filler, not a measured rate.
3. The number of repairs, the number of zero-duration repairs, and the number of negative durations are recorded per partition in `partitions.<name>.repairs`.

Repair counts from [`rule_baselines.json`](rule_baselines.json):

| Partition | Negative durations | `flow_packets_s` repaired | `flow_packets_s` zero-duration | `flow_bytes_s` repaired | `flow_bytes_s` zero-duration | Zero-packet flows | Short flows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Validation | 21 | 1,317 | 1,317 | 1,312 | 1,312 | 0 | 226,258 |
| Test | 62 | 931 | 931 | 929 | 929 | 0 | 477,774 |

No `syn_ratio` or `rst_ratio` value exceeded 1 after the ratio was formed. The counts are in the artifact.

## 2. Tier B — windowed schema (optional, unavailable)

Tier B features would be computed over a 60-second window keyed by source IP, with state evicted on inactivity:

| Portable name | Definition |
| --- | --- |
| `unique_dst_ports_60s` | Number of distinct destination ports contacted by one source IP in 60 seconds |
| `unique_dst_hosts_60s` | Number of distinct destination hosts contacted by one source IP in 60 seconds |
| `connection_attempts_60s` | Number of connection attempts by one source IP in 60 seconds |
| `fanout_ratio_60s` | Fan-out ratio over the same window, as defined by the future aggregator |

### Availability

| Dataset | Tier A | Tier B | Reason |
| --- | --- | --- | --- |
| CIC-IDS-2017 | available | **unavailable** | Only per-flow CSV exports; no `.pcap`/`.pcapng` files |
| CIC-IDS-2018 | **partial (DoS/DDoS, no PortScan)** | **unavailable** | Complete 10-day set: 12,079,420 unique feature-identical flows; DoS 231,486 and DDoS 775,955; no PortScan. All 12 Tier A columns exist under CICFlowMeter-2018 names. Seven files sit at the 1,048,575-row cap. See [`EXTERNAL_DATASET_AUDIT.md`](EXTERNAL_DATASET_AUDIT.md). |
| UNSW-NB15 | **partial (8/12)** | **unavailable** | 8 Tier A features are available or derivable; `packet_length_max` and the three flag counts are missing. See [`EXTERNAL_DATASET_AUDIT.md`](EXTERNAL_DATASET_AUDIT.md). |
| CIDDS-002 | **not Tier A (unidirectional NetFlow, 9/12 derivable)** | **unavailable** | Two-week NetFlow capture with explicit port-scan labels: 150,533 train / 80,572 validation / 101,812 test PortScan flows after dedup. The backward counters and `packet_length_max` cannot exist in a unidirectional record. Supports a separate scanning study, not a Tier A validation. See [`CIDDS002_AUDIT.md`](CIDDS002_AUDIT.md). |
| ToN-IoT | not acquired | not acquired | Dataset and license not obtained |
| CIC-IoT-2023 | not acquired | not acquired | Dataset and license not obtained |

Repository audit:

- `data/` contains eight CIC-IDS-2017 flow CSVs.
- `data/samples/` contains two smaller CSVs derived from CIC-IDS-2017.
- `scratch/` is a local, gitignored workspace for regenerable experiment artifacts; it holds no capture files in a fresh clone.
- Recursive search for `.pcap` and `.pcapng` under `data/` and `data/samples/` returns **0 files**.
- The CIC CSV filenames contain `pcap_ISCX`, but their extension is `.csv`; they are per-flow exports, not packet captures.

### Why fan-out is not approximated

Per-flow CSV columns do not contain the information needed to reconstruct 60-second destination fan-out:

- There is no packet timestamp in the portable schema. `Flow Duration` is a duration, not a start time.
- There is no source-keyed window or inactivity eviction.
- The per-flow aggregation has already collapsed connection attempts. Counting distinct `Destination Port` values per row is not a 60-second unique count, and a per-flow `Destination Port` is a property of that flow, not of the source's behavior over a window.

A fan-out rule built from per-flow columns would be a fabricated Tier B feature. It is therefore marked **unavailable** in `rule_baselines.json`, not approximated.

## 3. Metric consequences

The P2A rule baselines use only Tier A features. On the held-out test partition:

- At 10 alerts per 10,000 flows, the best Tier A rule (`rate_bytes`) finds **1** true positive out of 286,957 attack flows and raises 745 alerts. Recall is effectively zero.
- At 100 alerts per 10,000 flows, the best Tier A rule (`rate_bytes`) finds **33** true positives out of 286,957 attack flows and raises 9,158 alerts. Recall is **0.011%**.
- The `syn` rule has no usable operating point: its top validation score is tied across 11,699 primary rows, more than either budget allows, so the specified tie rule selects zero alerts.
- `composite_packets_syn` inherits that SYN tie: its top validation tie spans 1,487 rows, so it also selects zero validation alerts at the 10/10k budget.
- The composite rules do not beat the single rate rule.

These are negative results. They are preserved because they define how weak a Tier A-only baseline is, and because they show why fan-out matters for scanning behavior. They do not change the serving model, its threshold, or its registry row.

## 4. Relationship to the existing model

The existing served model is an 80-feature Random Forest trained on the CIC-IDS-2017 day-based split. It is not a Tier A-only model. P2A does not retrain it, does not replace it, and does not change its threshold.

P2B was audited and is **blocked**: the frozen Monday-Tuesday training partition
contains no volumetric or scanning positives, so supervised LogReg/RF heads
cannot be fitted. See [`VOLUMETRIC_DETECTOR.md`](VOLUMETRIC_DETECTOR.md). Until a
split with training positives is approved:

- The P2A primary claim is Tier A only.
- Tier B fan-out remains unavailable.
- The existing model's benchmark precision remains prevalence-bound; see [`PREVALENCE_EVAL.md`](PREVALENCE_EVAL.md).
- Detection remains **4/10**.

## 5. Reproduction

```bash
venv/Scripts/python.exe scripts/rule_baselines.py \
  --output docs/rule_baselines.json \
  --report docs/RULE_BASELINES.md
```

The feature inventory, repair counts, Tier B availability, and all rule metrics are written to `docs/rule_baselines.json`.
