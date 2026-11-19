# SOC Context: Capture Vectors, Enrichment, Fleet, Triage, and Response

**Status:** implementation note for a research prototype. It describes what the code does and, more importantly, what it refuses to invent. It is not a product datasheet or a production-readiness claim.

**Date:** 2026-11-17.

## 1. Capture vectors are not ML features

Wi-Fi, Ethernet, cellular, and VPN describe Layer-1/2 framing or a deployment context. Once packets reach IP, the detector consumes Layer-3/4 flow statistics (duration, byte/packet rates, IAT, flags, lengths). The capture vector changes *where* a probe listens, not the feature vector.

`domain/capture_metadata.py` classifies adapters into:

| Vector | Typical adapters | Basis |
| --- | --- | --- |
| `ethernet` | `eth0`, `enp3s0`, `eno1` | adapter name heuristic |
| `wlan` | `wlan0`, `Wi-Fi` | adapter name heuristic |
| `wwan` | `wwan0`, `rmnet_data0` | adapter name heuristic |
| `vpn` | `wg0`, `tun0`, `tap0`, `ppp0` | adapter name heuristic |
| `virtual` | `vEthernet`, `veth`, `cni0`, `cali*` | adapter name heuristic |
| `loopback` | `lo`, `lo0` | adapter name heuristic |
| `unknown` | anything unmatched | explicit no-guess fallback |

For PCAP/PCAPNG, the link type comes from libpcap's DLT value (Ethernet, raw IP, 802.11, radiotap, Linux cooked capture, loopback). The response reports the container format, DLT, snaplen, frame and byte counts, truncated-frame count, timestamps, protocol mix, and extracted flow count. It does **not** name the capture interface, because a capture file does not reliably contain one.

The local `/api/capture/interface` endpoint applies the same heuristic to resolved adapters and labels the result as such. No operating-system interface fact is inferred beyond the adapter string.

### What this does not prove

- That a name heuristic identifies the physical medium correctly.
- That live flow features match the training extractor. That remains unvalidated.
- That 802.11 management-frame attacks (deauth floods, evil twins) are detected. NetShield dissects L2 framing for provenance; it does not implement a link-layer IDS. `/api/layer2-attacks` still returns `501 not_implemented`.

## 2. Enrichment: unknown is not clean

`domain/threat_intel.py` supports two independent, optional sources:

- **MaxMind GeoLite2** (`geoip2` package plus operator-supplied `GeoLite2-City.mmdb` and/or `GeoLite2-ASN.mmdb`). Paths come from `NETSHIELD_GEOIP_CITY_DB` / `NETSHIELD_GEOIP_ASN_DB`.
- **AbuseIPDB** (`ABUSEIPDB_API_KEY`), off unless `NETSHIELD_THREAT_INTEL_ENABLED=true` **and** a key is present.

At startup the app loads an operator-local `.env` (via `python-dotenv`, `override=False`) so keys do not have to be exported in the shell. Real environment variables take precedence, `.env` is gitignored, and the tracked-file secret scan excludes it. `GET /api/intel/<ip>?reputation=true` returns `reputation.status = disabled` and makes no HTTP request when the flag or key is absent; it never silently falls back to "clean". `GET /api/threat-intel` reports `configured`, `enabled`, and real per-process counters (`requests_this_process`, `live_responses`, `errors_this_process`), with cached answers not re-counted.

`GET /api/intel/<ip>` returns explicit states: `live`, `not_configured`, `disabled`, `dependency_missing`, `partial`, `unavailable`, `private_address`, `invalid_address`, or `not_queried`. Missing country or ASN values are `null`. The UI renders "Unknown"/"Not available", never a green "clean" badge.

Private, loopback, link-local, reserved, and multicast addresses are never transmitted to a third party.

## 3. Sensor fleet: collector-reported only

`POST /api/sensors/heartbeat` accepts a fixed schema and rejects unknown fields:

```
sensor_id, interface, interface_description, vector, capture_driver, link_type,
link_speed_mbps, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_dropped,
tx_dropped, uptime_seconds, reported_at
```

`GET /api/sensors/fleet` merges the last heartbeat with flow-derived activity and reports `online`, `stale`, or `never_reported`. Age is computed from `received_at`. `rx_drop_rate` is `rx_dropped / rx_packets` only when both are reported.

There is no default driver, no default link speed, and no synthetic packet-drop percentage. A collector that reports only flow counts contributes a `never_reported` row with null link metrics.

## 4. Incident triage: internal priority, not CVSS

`GET /api/incidents` returns the in-memory multi-signal windows. Each row is decorated with:

- `severity`: P1–P4 from NetShield risk points and independent-signal count;
- `triage`: persisted status, assignee, note, acknowledgment time, and SLA state;
- `sla`: acknowledgment target and remaining seconds.

CVSS is deliberately not used. CVSS scores a vulnerability from a vector string; a flow-level risk score cannot be converted into one. The API states `severity.basis = internal_risk_points` and `severity_basis = internal_risk_points_not_cvss`.

`PUT /api/incidents/<incident_id>/triage` stores status, assignee, and note. Acknowledgment is stamped when status moves to `investigating`, `suppressed`, or `remediated`. Detection windows are still in-memory; after a restart, triage rows remain but cannot be joined to a vanished window.

## 5. Response: dry-run and opt-in only

`POST /api/incidents/<incident_id>/playbook` supports two actions:

- `containment_plan` (default): returns exact `nft`/`iptables` commands and rollback with `executed: false`. It refuses non-public source addresses.
- `notify_webhook`: sends a compact incident payload only when `NETSHIELD_SOAR_ENABLED=true`, `NETSHIELD_SOAR_WEBHOOK_URL` is set, and the URL host exactly matches an entry in `NETSHIELD_SOAR_WEBHOOK_ALLOWLIST`. Redirects are disabled. Failures return non-2xx with `delivered: false`.

`GET /api/incidents/<incident_id>/stix` returns a STIX 2.1 bundle. The indicator's `confidence` is the internal risk-point total; its description says so explicitly.

NetShield has no privileged agent, firewall credential, or cloud control-plane token. It does not claim to block, quarantine, or null-route anything.

## 6. Reproduce

```
venv\Scripts\python.exe -m pytest tests/test_capture_metadata.py tests/test_pcap_metadata.py tests/test_threat_intel.py tests/test_sensor_fleet.py tests/test_incident_triage.py tests/test_soar.py tests/test_soc_api.py -q
```

For a live-looking fleet, post a heartbeat:

```
curl -X POST http://127.0.0.1:5000/api/sensors/heartbeat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $NETSHIELD_API_KEY" \
  -d '{"sensor_id":"probe-lab-1","interface":"eth0","capture_driver":"AF_PACKET","rx_packets":1000,"rx_dropped":2}'
```

The values are stored exactly as posted. If the collector lies, the console repeats the lie; provenance is the collector's responsibility.

## 7. Limitations

- No deployed fleet, no live labelled traffic, and no measured enrichment accuracy.
- Capture-vector classification is a name heuristic.
- Detection windows reset on restart; only triage state persists.
- Webhook delivery is opt-in and has not been exercised against a real PagerDuty, Slack, or Splunk endpoint.
- STIX export describes a host/window signal, not a confirmed malicious indicator.
- Link-layer attacks remain out of scope.
