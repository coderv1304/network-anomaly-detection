# Live-Capture Operations and Interface Selection (Phase P1/P2)

**Status:** multi-interface **ingest is verified**; live **detection is not
validated**. Do not describe the live path as "live validated", "sensor
validated", or equivalent.

**Date:** 2026-11-10.

This document records how the collector chooses adapters, what was actually run,
and what the result does and does not prove. Feature-level agreement between the
two Python extractors is documented separately in
[FEATURE_PARITY_LIVE_CAPTURE_V2.md](FEATURE_PARITY_LIVE_CAPTURE_V2.md).

## 1. What changed

The collector previously accepted one interface name and assumed a Wi-Fi-style
adapter. It now resolves a selection across Windows, Linux, and macOS:

| Selection | Meaning |
|---|---|
| `auto` (default) | Follow the adapter that owns the default route. Falls back to a non-loopback adapter when offline. |
| `all` | Capture every enumerated adapter, including VPN TUN, Bluetooth PAN, Wi-Fi Direct, WSL, VMware, and loopback. |
| `loopback` | Capture only the loopback adapter. |
| explicit list | Comma-separated adapter names, descriptions, IP addresses, or Npcap GUIDs. |

Name matching is case-insensitive and accepts substrings of the adapter
description, so `"Realtek"` can select an Ethernet adapter whose device name is
not stable. Unknown entries are still attempted, because Npcap GUIDs are not
always enumerable, and are reported as unknown in capture status so a typo cannot
silently shrink coverage.

Each adapter runs in its own capture thread. A failure on one adapter is recorded
and does not stop the others, which is what makes `all` usable on a machine with
virtual or disconnected adapters.

## 2. Measured ingest evidence

These runs used `scripts/live_capture_smoke.py` against the real application on a
Windows host with Npcap. Traffic was generated on the host during the run.

| Selection | Resolved adapters | Flows ingested | Final state | Evidence |
|---|---|---:|---|---|
| `auto` | `Wi-Fi` | 3 | `listening` | `docs/live_capture_smoke_auto.json` |
| `Wi-Fi,\Device\NPF_Loopback` | `Wi-Fi`, `\Device\NPF_Loopback` | 3 | `listening` | `docs/live_capture_smoke_multi.json` |
| `all` | 10 adapters: Bluetooth PAN, Ethernet, ExpressVPN TUN, two Wi-Fi Direct adapters, WSL vEthernet, VMware VMnet1/VMnet8, Wi-Fi, loopback | 7 | `listening` | `docs/live_capture_smoke_all.json` |

This verifies adapter discovery, selection, per-adapter startup, failure
isolation, and flow ingestion. It does **not** verify prediction quality. The
generated traffic has no ground-truth labels, and no CICFlowMeter reference rows
were produced for it.

## 3. Upload-path parity

`pcap_parser.pcap_to_flows` now computes all 80 training features instead of 57.
The parity report (`training/parity_live_capture.py`) records:

| Metric | Value |
|---|---:|
| Live feature-name coverage after mapping | 80 / 80 |
| Upload feature-name coverage | 80 / 80 |
| Upload features missing | 0 |
| Upload hardcoded constants | 0 |
| Matched flows on the synthetic fixture | 4 |
| Unmatched live flows | 0 |
| Reference-only flows | 2 (ICMP and IPv6) |

The upload path now measures bulk statistics, active/idle times, per-direction
header bytes, initial TCP windows, per-direction flag counts, data-packet counts,
and both packet-length-extreme names. The previously missing 23 features and 6
constants are tracked as a regression check in the parity report.

## 4. Known gaps

1. **ICMP and IPv6 are dropped on the live path.** PyFlowMeter applies
   `ip and (tcp or udp)`. The upload path keeps ICMP and IPv6 flows. The training
   data is IPv4 TCP/UDP only, so this is consistent with training, but the live
   path is not a superset of the upload path.
2. **Numeric disagreement remains.** Rate, inter-arrival, and packet-length
   statistics differ between the two extractors even on matched flows because
   they count bytes and timestamps differently.
3. **Flag-count semantics differ.** PyFlowMeter returns 0/1 indicators for some
   flags and aliases `CWE Flag Count` to `Fwd URG Flags`; the upload path emits
   true per-flow counts like the training CSV.
4. **No ground truth.** Neither Python extractor is the original Java
   CICFlowMeter, and no reference row exists for the fixture bytes, so training
   schema parity is not proven.
5. **Directionality.** Both paths orient a flow from its first observed packet.
   A flow that started before capture began can have forward/backward statistics
   swapped.
6. **Adapter scope.** Capturing on a hotspot adapter does not expose the phone's
   cellular traffic or other hotspot clients. Encrypted VPN/TLS payloads remain
   encrypted. `all` can duplicate the same packet across virtual adapters.
7. **Privileges.** Packet capture requires Npcap/libpcap and host privileges. The
   container demo does not receive capture capabilities.

## 5. Operating guidance

```bash
# Discover adapters
python live_capture.py --list

# Run the collector directly
python live_capture.py --interface auto

# Run the app with capture enabled (elevated shell where required)
ENABLE_LOCAL_CAPTURE=true \
NETSHIELD_CAPTURE_INTERFACE=auto \
LIVE_CAPTURE_API_KEY="<strong-key>" \
python app.py

# Inspect resolved adapters and state
curl -s http://127.0.0.1:5000/api/capture-status
```

The live-flow endpoint requires `X-API-Key` or an authenticated browser session.
Predictions are advisory and must not trigger blocking, firewall, or containment
actions. Keep the UI labelled "experimental live capture".

## 6. Verdict

The collector now works across Wi-Fi, Ethernet, VPN, Bluetooth PAN, virtual, and
loopback adapters, and the upload parser is feature-complete. That raises the
research/demo score because the ingest path is demonstrably exercised on real
adapters. It does **not** raise the detection score: ingest is not accuracy, and
no labelled live evaluation has been performed.
