# Live Capture Feature Parity Verification Report (Phase 7)

> [!NOTE]
> **Superseded for live-path claims by [Phase P1](FEATURE_PARITY_LIVE_CAPTURE_V2.md).**
> This report audits the Scapy **upload** parser (`pcap_parser.py`) against a
> reference CSV and the 80-feature schema. It does not measure the PyFlowMeter
> **live** path used by `live_capture.py`. The Phase P1 report compares both
> Python extractors on one capture and is the current evidence for live-path
> parity.

> [!CAUTION]
> **Operational Verdict: UNVALIDATED PROTOTYPE / RESEARCH DEMO ONLY**
> - **Feature Parity Claim**: The upload-parser extraction path (`pcap_parser.py`) does **NOT** achieve sufficient feature parity with the CIC-IDS-2017 training pipeline.
> - **Model Integrity Rule**: The application **MUST NOT** claim validated intrusion detection accuracy on live network traffic. The live-capture interface must remain labeled strictly as an **experimental research prototype / demo**.

## 1. Schema & Feature Coverage Audit
- **Total Model Features Required**: 80
- **Features Produced by the Scapy Upload Parser**: 61
- **Direct Feature Matches**: 57 (71.2%)
- **Missing / Uncomputed Features**: 23

### Missing Features List (Defaulted to Imputed/Zero Values)
The following features exist in the training pipeline but cannot be extracted by the Scapy upload parser:

- `Bwd Avg Bulk Rate`
- `Bwd Avg Bytes/Bulk`
- `Bwd Avg Packets/Bulk`
- `Bwd Header Length`
- `Bwd PSH Flags`
- `Bwd URG Flags`
- `CWE Flag Count`
- `ECE Flag Count`
- `Fwd Avg Bulk Rate`
- `Fwd Avg Bytes/Bulk`
- `Fwd Avg Packets/Bulk`
- `Fwd Header Length`
- `Fwd Header Length.1`
- `Fwd PSH Flags`
- `Fwd URG Flags`
- `Init_Win_bytes_backward`
- `Init_Win_bytes_forward`
- `Max Packet Length`
- `Min Packet Length`
- `PSH Flag Count`
- `URG Flag Count`
- `act_data_pkt_fwd`
- `min_seg_size_forward`

### Placeholder / Dummy Features in the Upload Parser
The following features are generated with hardcoded constant values in `pcap_parser.py`:
- `Active Std`: Hardcoded to `0`
- `Idle Mean`: Hardcoded to `0`
- `Idle Std`: Hardcoded to `0`
- `Idle Max`: Hardcoded to `0`
- `Idle Min`: Hardcoded to `0`
- `Active Mean`: Hardcoded to `Flow Duration`

## 2. Robustness & Malformed Packet Stress Testing

| Edge Case / Malformed Scenario | Parser Response | Verdict |
|:---|:---|:---:|
| **Empty Capture** | `PASSED (Cleanly rejected: Invalid or unsupported PCAP/PCAPNG capture.)` | **PASSED** |
| **Non Ip Packets** | `PASSED (Cleanly handled non-IP: No IPv4 or IPv6 packets were found in this capture.)` | **PASSED** |
| **Single Packet Zero Duration** | `PASSED (1 flow extracted, rates finite=True)` | **PASSED** |
| **Half Open Tcp** | `PASSED (Bidirectional flow tracked, flags correct=True)` | **PASSED** |
| **Truncated Tcp Header** | `PASSED (Handled truncated packet, flows=1)` | **PASSED** |

## 3. Root Causes of Numerical Disparity

1. **TCP Initial Window Size Absence**:
   - Features `Init_Win_bytes_forward` and `Init_Win_bytes_backward` carry high feature importance in Random Forest classifiers trained on CIC-IDS-2017.
   - In live captures, if the initial 3-way handshake (SYN/SYN-ACK) is missed, these values are impossible to observe and fall back to `-1` or median imputation.

2. **Flow Directionality Inversion**:
   - In offline datasets, flows are oriented based on the client initiation packet.
   - In live sniffers, the forward direction is assigned to whichever endpoint emits the first observed packet after capture start. If an existing flow is mid-session, forward and backward statistics are completely swapped.

3. **Active/Idle Timeout Heuristics**:
   - The original Java CICFlowMeter implements an internal state machine splitting flows into Active and Idle sub-periods using an activity timeout threshold.
   - The Python implementation sets `Idle Mean = 0` and `Active Mean = Flow Duration`, introducing massive systematic bias on longer-duration flows.

## 4. Required Remediation Before Claiming Live Efficacy

To achieve legitimate feature parity, future engineering must:
1. **Use Unified Flow Generation**: Either extract training records using `pcap_parser.py` from raw PCAPs, or compile the exact same native C/Java flow extractor used by the training pipeline.
2. **Strict Handshake Tracking**: Reject or flag flows that commence without an observed SYN packet as *unverified partial flows*.
3. **Stateful Active/Idle Timers**: Implement sliding-window active/idle timeouts matching the CIC-IDS specification.