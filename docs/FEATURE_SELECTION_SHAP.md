# Feature Selection & SHAP Explainability Report

*Generated on: 2026-10-13 17:26:18 UTC*

## 1. Selected Reduced Feature Set (15–20 Features for Go Pipeline)
The following reduced feature set balances predictive discrimination with low real-time computational overhead in the Go packet assembler (`capture/`):

| Rank | Feature Name | Domain Group | Importance Score | Live Capture Viability |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `Total Fwd Packets` | Packet Counts & Headers | 0.07527 | ✅ Low overhead in Go flow table |
| 2 | `Subflow Fwd Packets` | Packet Counts & Headers | 0.06810 | ✅ Low overhead in Go flow table |
| 3 | `Flow Bytes/s` | Flow Rates & Windows | 0.05675 | ✅ Low overhead in Go flow table |
| 4 | `Subflow Bwd Packets` | Packet Counts & Headers | 0.05061 | ✅ Low overhead in Go flow table |
| 5 | `Total Backward Packets` | Packet Counts & Headers | 0.04292 | ✅ Low overhead in Go flow table |
| 6 | `Bwd Packets/s` | Flow Rates & Windows | 0.03877 | ✅ Low overhead in Go flow table |
| 7 | `Flow Packets/s` | Flow Rates & Windows | 0.03341 | ✅ Low overhead in Go flow table |
| 8 | `Fwd Packets/s` | Flow Rates & Windows | 0.02601 | ✅ Low overhead in Go flow table |
| 9 | `Subflow Fwd Bytes` | Packet Lengths & Sizes | 0.02496 | ✅ Low overhead in Go flow table |
| 10 | `RST Flag Count` | TCP Flags | 0.02375 | ✅ Low overhead in Go flow table |
| 11 | `Total Length of Fwd Packets` | Packet Lengths & Sizes | 0.02329 | ✅ Low overhead in Go flow table |
| 12 | `Flow Duration` | Timing & Inter-Arrival | 0.01989 | ✅ Low overhead in Go flow table |
| 13 | `Subflow Bwd Bytes` | Packet Lengths & Sizes | 0.01748 | ✅ Low overhead in Go flow table |
| 14 | `SYN Flag Count` | TCP Flags | 0.01720 | ✅ Low overhead in Go flow table |
| 15 | `Active Std` | Timing & Inter-Arrival | 0.01510 | ✅ Low overhead in Go flow table |
| 16 | `Fwd IAT Total` | Timing & Inter-Arrival | 0.01436 | ✅ Low overhead in Go flow table |
| 17 | `Total Length of Bwd Packets` | Packet Lengths & Sizes | 0.01421 | ✅ Low overhead in Go flow table |
| 18 | `Active Max` | Timing & Inter-Arrival | 0.01355 | ✅ Low overhead in Go flow table |

## 2. Feature Group Ablation & Distribution

| Feature Group | Count in Top Set | Total Features Available |
| :--- | :--- | :--- |
| **Packet Counts & Headers** | 4 | 9 |
| **Flow Rates & Windows** | 4 | 13 |
| **Packet Lengths & Sizes** | 4 | 20 |
| **Timing & Inter-Arrival** | 4 | 23 |
| **TCP Flags** | 2 | 12 |

## 3. Engineering Justification for Go Assembler (`capture/`)
1. **Packet Sizes & Length Statistics:** Computing mean and variance of packet lengths in real-time requires only running sums (`sum`, `sum_sq`) with O(1) packet-time complexity.
2. **Inter-Arrival Times (IAT):** Requires only tracking the timestamp of the preceding packet in each flow direction, giving O(1) state per packet.
3. **TCP Flag Counts:** Increments simple integer counters upon inspection of TCP header flags (SYN, FIN, RST, ACK, PSH).
4. **Discarded Features:** Complex bulk transfer statistics and HTTP string features are omitted because they incur high memory footprint with minimal marginal SHAP gain.