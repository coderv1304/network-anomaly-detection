# Live-Capture Feature Parity (Phase P1)

*Generated: 2026-11-10T01:13:37.750610+00:00*

> [!CAUTION]
> **Parity is not demonstrated.** Do not label the live path "live validated".
> Neither extractor is the original Java CICFlowMeter used for training, and the
> two paths disagree on flow coverage and on many numeric features.

## 1. What was compared

- **Live path**: `live_capture.py` -> `pyflowmeter` (offline session driver on the same PCAP).
- **Upload path**: `pcap_parser.pcap_to_flows` (Scapy).
- **Capture**: a deterministic synthetic PCAP with IPv4 TCP, IPv4 UDP, ICMP, IPv6 TCP, a partial mid-session flow, and a zero-duration single packet.
- **Schema**: the 80 features in `models/model_manifest_rf_day_based_seed42.json`.

Neither path was compared against a CICFlowMeter-generated row from the same bytes because no CICFlowMeter binary or source PCAP is available in this repository. Agreement between the two Python extractors is necessary but not sufficient for training-schema parity.

This report supersedes the live-path claims in `docs/FEATURE_PARITY_LIVE_CAPTURE.md` and `training/feature_parity.py`, which compare the Scapy upload parser against a reference CSV. Those files remain valid for the reference-CSV upload path only.

## 2. Provenance and schema versions

- Feature schema SHA-256: `45cd75ce849b005c854ef8190a1cbe14d0d1a22daa6aa10e05e767ec6a757be6`
- Expected feature count: 80
- Python: 3.12.10
- pandas: 2.2.3
- scapy: 2.5.0
- pyflowmeter: 0.2.4
- Fixture PCAP SHA-256: `950231e81b1ac9c8cf8e4cf4e85f93d28f854400f52c9c30c10c50e6f2669e37`

## 3. Matching rules

- A flow is keyed by protocol plus the unordered pair of `(IP, port)` endpoints.
- Direction is not part of the key because both extractors orient a flow from its first observed packet.
- A live flow with no reference candidate is **unmatched**.
- A live flow with more than one reference candidate is **ambiguous**; the first candidate is used for feature comparison and the ambiguity is counted separately.
- A reference flow with no live candidate is **reference-only** (the live path did not produce it).

## 4. Flow coverage

| Metric | Value |
| --- | ---: |
| Live flows (PyFlowMeter) | 4 |
| Reference flows (Scapy upload parser) | 6 |
| Matched flows | 4 |
| Unmatched live flows | 0 (0.0%) |
| Reference-only flows | 2 (33.3%) |
| Ambiguous live flows | 0 (0.0%) |

Reference-only flows mean the live path never sees them. On this fixture they are the ICMP and IPv6 flows, which PyFlowMeter's `ip and (tcp or udp)` BPF filter excludes. A production collector that needs ICMP or IPv6 coverage cannot rely on the bundled live client.

## 5. Feature coverage

- Live path coverage after `feature_mapper`: **80 / 80**.
- Upload path coverage: **80 / 80**.
- Upload path features still missing: **0**.
- Upload path hardcoded constants: **0**.

### 5.1 Features the upload parser still never produces (0)


### 5.2 Features the upload parser fills with constants

| Feature | Hardcoded behaviour |
| --- | --- |

Historical note: before the upload-path parity fix, 23 of 80 features were missing and 6 were constants (`Active Mean` was set to the whole flow duration). `pcap_parser.py` now measures all of them: bulk statistics, active/idle times, per-direction header bytes, initial TCP windows, flag counts, data-packet counts, and both names for the packet-length extremes.

## 6. Per-feature error on matched flows

Errors are absolute differences between the live value and the upload-parser value for the same matched flow. `n` is the number of matched flows where both values were finite.

| Feature | n | Mean abs | Median abs | p95 abs | Max abs | Mean rel |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Source Port | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Destination Port | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Protocol | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Flow Duration | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Total Fwd Packets | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Total Backward Packets | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Total Length of Fwd Packets | 4 | 28.0000 | 14.0000 | 61.6000 | 70.0000 | 0.3155 |
| Total Length of Bwd Packets | 4 | 14.0000 | 7.0000 | 37.8000 | 42.0000 | 0.1209 |
| Fwd Packet Length Max | 4 | 14.0000 | 14.0000 | 14.0000 | 14.0000 | 0.2884 |
| Fwd Packet Length Min | 4 | 14.0000 | 14.0000 | 14.0000 | 14.0000 | 0.3279 |
| Fwd Packet Length Mean | 4 | 14.0000 | 14.0000 | 14.0000 | 14.0000 | 0.3155 |
| Fwd Packet Length Std | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd Packet Length Max | 4 | 7.0000 | 7.0000 | 14.0000 | 14.0000 | 0.1026 |
| Bwd Packet Length Min | 4 | 7.0000 | 7.0000 | 14.0000 | 14.0000 | 0.1354 |
| Bwd Packet Length Mean | 4 | 7.0000 | 7.0000 | 14.0000 | 14.0000 | 0.1209 |
| Bwd Packet Length Std | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Flow Bytes/s | 4 | 1100.0000 | 800.0000 | 2620.0000 | 2800.0000 | 0.1281 |
| Flow Packets/s | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Flow IAT Mean | 4 | 2500.0000 | 0.0000 | 8500.0000 | 10000.0000 | 0.2500 |
| Flow IAT Std | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.2500 |
| Flow IAT Max | 4 | 2500.0000 | 0.0000 | 8500.0000 | 10000.0000 | 0.2500 |
| Flow IAT Min | 4 | 2500.0000 | 0.0000 | 8500.0000 | 10000.0000 | 0.2500 |
| Fwd IAT Total | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Fwd IAT Mean | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Fwd IAT Std | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Fwd IAT Max | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Fwd IAT Min | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd IAT Total | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd IAT Mean | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd IAT Std | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd IAT Max | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd IAT Min | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Fwd PSH Flags | 4 | 0.5000 | 0.5000 | 1.0000 | 1.0000 | 0.5000 |
| Bwd PSH Flags | 4 | 0.2500 | 0.0000 | 0.8500 | 1.0000 | 0.2500 |
| Fwd URG Flags | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd URG Flags | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Fwd Header Length | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd Header Length | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Fwd Packets/s | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd Packets/s | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Min Packet Length | 4 | 14.0000 | 14.0000 | 14.0000 | 14.0000 | 0.3279 |
| Max Packet Length | 4 | 14.0000 | 14.0000 | 14.0000 | 14.0000 | 0.2749 |
| Packet Length Mean | 4 | 14.0000 | 14.0000 | 14.0000 | 14.0000 | 0.3071 |
| Packet Length Std | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Packet Length Variance | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| FIN Flag Count | 4 | 0.5000 | 0.0000 | 1.7000 | 2.0000 | 0.2500 |
| SYN Flag Count | 4 | 0.5000 | 0.0000 | 1.7000 | 2.0000 | 0.2500 |
| RST Flag Count | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| PSH Flag Count | 4 | 0.7500 | 0.5000 | 1.8500 | 2.0000 | 0.5000 |
| ACK Flag Count | 4 | 2.0000 | 0.5000 | 6.1000 | 7.0000 | 0.5000 |
| URG Flag Count | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| CWE Flag Count | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| ECE Flag Count | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Down/Up Ratio | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Average Packet Size | 4 | 14.0000 | 14.0000 | 14.0000 | 14.0000 | 0.3071 |
| Avg Fwd Segment Size | 4 | 14.0000 | 14.0000 | 14.0000 | 14.0000 | 0.3155 |
| Avg Bwd Segment Size | 4 | 7.0000 | 7.0000 | 14.0000 | 14.0000 | 0.1209 |
| Fwd Header Length.1 | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Fwd Avg Bytes/Bulk | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Fwd Avg Packets/Bulk | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Fwd Avg Bulk Rate | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd Avg Bytes/Bulk | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd Avg Packets/Bulk | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Bwd Avg Bulk Rate | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Subflow Fwd Packets | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Subflow Fwd Bytes | 4 | 28.0000 | 14.0000 | 61.6000 | 70.0000 | 0.3155 |
| Subflow Bwd Packets | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Subflow Bwd Bytes | 4 | 14.0000 | 7.0000 | 37.8000 | 42.0000 | 0.1209 |
| Init_Win_bytes_forward | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Init_Win_bytes_backward | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| act_data_pkt_fwd | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| min_seg_size_forward | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Active Mean | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Active Std | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Active Max | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Active Min | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Idle Mean | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Idle Std | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Idle Max | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Idle Min | 4 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

Features with `n = 0` are produced by neither path or were not finite on the fixture; they must be imputed before inference. The largest disagreements are expected in rate and inter-arrival features, because the two parsers count packet bytes and timestamps differently.

## 7. Malformed and partial-input behaviour

| Case | Live path | Upload path | Note |
| --- | --- | --- | --- |
| empty capture | 0 flows | 0 flows; ValueError: No IPv4 or IPv6 packets were found in this capture. | Both extractors must reject or return zero flows, not crash the service. |
| non-IP capture | 0 flows | 0 flows; ValueError: No IPv4 or IPv6 packets were found in this capture. | The upload path must return a clean 4xx-style error, not a traceback. |
| truncated TCP header | 1 flows | 1 flows | A truncated transport header must not be treated as a complete flow. |
| partial mid-session flow (no SYN) | 1 flows | 1 flows | Neither path can recover the initial window or true flow start without the handshake. |
| single packet, zero duration | 1 flows | 1 flows | Zero-duration flows must produce finite rates, not divide-by-zero. |

## 8. Confirmed findings

1. **Flow-coverage gap.** The live path drops ICMP and IPv6 because of its BPF filter; the upload path keeps them. The live path is not a superset of the upload path. This matches the training distribution (CIC-IDS-2017 contains IPv4 TCP/UDP flows only) but leaves ICMP/IPv6 traffic unscored by the live path.
2. **Upload-path schema completeness (fixed, measured).** The upload path now emits all 80 training features. Bulk statistics, active/idle times, per-direction header bytes, initial TCP windows, per-direction flag counts, data-packet counts, and both packet-length-extreme names are measured per flow using the PyFlowMeter reference semantics. The previously missing 23 features and 6 constants are listed in section 5 for regression tracking.
3. **Numeric disagreement.** Even on matched flows, rate, inter-arrival, and packet-length statistics differ because the extractors use different packet-length and timestamp conventions.
4. **Flag-count semantics differ.** The upload path emits true per-flow flag counts, matching the training CSV; PyFlowMeter's `FlagCount.has_flag` returns a 0/1 indicator, and PyFlowMeter aliases `CWE Flag Count` to `Fwd URG Flags`. The two paths therefore disagree on flag features for flows with retransmissions, and the live path under-counts flags relative to the training data.
5. **Directionality risk.** Both paths orient flows from the first observed packet. A flow that starts before capture begins will have forward and backward statistics swapped relative to a capture that observed the handshake.
6. **No ground truth.** There is no CICFlowMeter reference row for these bytes, so this report cannot prove training-schema parity; it can only show where the two Python paths disagree.

## 9. Verdict

The live path is **not validated**. Schema coverage is now complete on both paths, but no labelled live traffic exists, the two extractors still disagree on several numeric features, and no CICFlowMeter ground truth is available. Keep the UI and documentation labelled "experimental live capture" and do not claim live detection efficacy.

## 10. Reproduce

```bash
venv/Scripts/python.exe training/parity_live_capture.py
```
