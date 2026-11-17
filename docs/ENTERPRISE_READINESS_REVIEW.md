# Enterprise Readiness Review: What Changed and What Was Refused

**Status:** critical self-review of the SOC/NDR surface. Research prototype, not a production NIDS/IPS.

**Date:** 2026-11-17.

This note answers the common "this looks like an academic project" critique. It separates changes that improve verifiable engineering from changes that would only improve the screenshot.

## 1. The four giveaways

### Giveaway 1: "Upload a CSV to detect attacks"

**Changed:** `/predict` now uses a PCAP/PCAPNG dissector that reports container format, DLT/link type, snaplen, frame and byte counts, truncation, timestamps, protocol mix, and flow count. CSV uploads are labelled by their actual schema (`CICFlowMeter-style flow CSV`, `Zeek-like conn.log flow export`, `Generic flow CSV`), not by a product name.

**Refused:** calling a CSV an "eBPF stream" or a PCAP a "live sensor". A file upload is retrospective forensics.

**Still missing:** a streaming collector with a persistent flow table. `live_capture.py` and Zeek `conn.log` are optional paths; the latter has its own documented feature limits.

### Giveaway 2: "CIC-IDS-2017 Random Forest"

**Changed:** the console already runs a multi-signal accumulator: calibrated supervised score, Isolation Forest confidence, and optional reputation, grouped per source and time window. A single signal cannot open an incident (C-049).

**Refused:** presenting the layer stack as a validated hybrid detector. The portable transfer experiments remain negative/mixed (C-046, C-048). The ensemble is an alert-triage mechanism, not proof of detection efficacy.

**Still missing:** a deterministic L2/L3 heuristic engine with measured precision/recall. `/api/layer2-attacks` is honest: not implemented.

### Giveaway 3: "Naked IPs"

**Changed:** `/api/intel/<ip>` and the flow inspector show ASN, country/city, scope, and optional AbuseIPDB reputation. Missing configuration is visible as unknown/not configured.

**Refused:** shipping a bundled GeoIP database or inventing ASN/reputation for demo IPs. MaxMind licensing and AbuseIPDB keys belong to the operator.

**Still missing:** enrichment accuracy, Tor-exit feeds, and a threat-intel corpus. None are claimed.

### Giveaway 4: "Detection without response"

**Changed:** incident cards carry persisted triage state, internal P1–P4 priority, SLA countdown, notes, dry-run containment commands with rollback, and STIX 2.1 export. Webhook delivery is opt-in and allowlisted.

**Refused:** a one-click "Block" button that pretends to change a firewall. `executed: false` is explicit. CVSS is not used for flow incidents.

**Still missing:** an enforcement plane. That is a product decision with real risk, not a UI feature.

## 2. The five proposed product features

| Proposal | Implemented here | Honest status |
| --- | --- | --- |
| Native PCAP/PCAPNG upload and dissection | `dissect_pcap`, `/predict` metadata | Real file metadata; no live-capture parity |
| Multi-probe fleet health grid | heartbeat API, fleet grid | Collector-reported only; no synthetic bandwidth/drops |
| ASN/GeoIP/reputation enrichment | optional MaxMind + AbuseIPDB | Requires operator DB/key; unknown is explicit |
| Incident lifecycle triage | persisted status/assignee/note/SLA | Internal P1–P4, not CVSS; windows are in-memory |
| Automated SOAR playbooks | dry-run commands, STIX, allowlisted webhook | No firewall execution; no cloud credential |

## 3. Network types: Wi-Fi, Ethernet, cellular, hotspot, VPN

The correct abstraction is **capture vector**, not a consumer connectivity selector. NetShield classifies adapters and link types into `ethernet`, `wlan`, `wwan`, `vpn`, `virtual`, `loopback`, and `unknown`.

Why not a `Wi-Fi | Mobile Data | Hotspot | Internet` dropdown:

- Those labels are not stable network-engineering terms.
- They do not change the model input (L3/L4 flow statistics).
- They imply detection capabilities (deauth floods, evil twins, SIM-swap) that this code does not implement.

What *is* supported is honest provenance: where a probe listens, what link-layer framing a capture used, and which fields a collector reported.

## 4. Verification

```
venv\Scripts\python.exe -m pytest tests -q
node --check static/js/console.js
```

The suite covers capture metadata, PCAP metadata, enrichment unknown states, heartbeat validation, fleet states, severity/SLA, dry-run playbooks, STIX export, webhook allowlisting, and API integration.

## 5. What a reviewer should still reject

- Any claim of live detection accuracy.
- Any claim that the fleet has been deployed at scale.
- Any claim that ASN/GeoIP/reputation is complete or accurate.
- Any claim that containment was executed.
- Any claim that link-layer attacks are detected.
- Any CVSS number attached to a flow incident.
