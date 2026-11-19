# NetShield Capture & Sensor (`capture/`)

`capture/` contains the production-oriented Go packet-to-feature and embedded inference sensor for NetShield Aegis. It replaces the earlier experimental collector with a sharded, deterministic flow engine that can replay PCAPs identically across platforms or score live traffic with a cross-platform fallback.

## Layout

- `cmd/netshield-sensor/` — CLI entry point (`--mode`, `--iface`, `--pcap`, `--out`, `--workers`, `--model`, `--manifest`, `--metrics-addr`, `--ingest-url`, `--redis-url`).
- `internal/ingest/` — packet sources, normalization, and symmetric 5-tuple sharding.
- `internal/flow/` — bidirectional flow table, virtual packet clock, timeout sweeps, the canonical 26-feature schema, and the 24-input vector the shipped model was trained on.
- `internal/inference/` — model bundle loading, atomic hot-reload, bounded queue with backpressure shedding, and scorers.
- `internal/state/` — Redis/in-memory host-window accumulator and batched, circuit-broken alert forwarder.
- `internal/metrics/` — Prometheus collectors served on `/metrics`.

## Build tags and portability

The default build is **pure Go / zero-CGo** and is intended to pass on Windows, macOS, and Linux:

- `CGO_ENABLED=0 go build ./...`
- `CGO_ENABLED=0 go test ./...`

Platform- or dependency-specific backends are gated:

- `//go:build linux` — Linux `AF_PACKET` TPACKET_V3 live capture (`internal/ingest/afpacket_linux.go`).
- `//go:build cgo && !windows && !no_pcap` — Unix libpcap live capture (`internal/ingest/libpcap_unix.go`); Windows is excluded to avoid an Npcap SDK/header dependency.
- `//go:build onnx` — in-process ONNX Runtime scorer (`internal/inference/onnx.go`, `github.com/yalue/onnxruntime_go`). The default build uses `internal/inference/onnx_stub.go` plus the manifest-provided linear fallback so scoring still works without C libraries.
- `//go:build !windows` / `//go:build windows` — Unix `SIGHUP` model reload signal vs no-op on Windows.

Offline PCAP replay uses `gopacket/pcapgo` (`PcapFileSource`) with no CGo dependency and works everywhere, including CI and Windows.

## Modes

### Extract (deterministic, offline)

```powershell
cd capture
$env:CGO_ENABLED='0'
go run ./cmd/netshield-sensor --mode=extract --pcap ..\tests\fixtures\sample_synthetic.pcap --out flows.csv --workers 4
```

- Reads packets with capture timestamps from the PCAP header (never `time.Now()`).
- Routes packets by canonical 5-tuple hash so A→B and B→A land on the same shard.
- Emits one CSV row per completed/timed-out flow: the metadata columns `flow_id,src_ip,dst_ip,src_port,dst_port,start_ts` (port and `start_ts` are decimal, `start_ts` in epoch microseconds) followed by the 26 canonical features in `FeatureNames` order.
- Output order is deterministic (start time, then canonical five-tuple), so repeated runs and different worker counts produce byte-identical CSV for the same input.

### Sensor (live scoring / forwarding)

```powershell
cd capture
$env:CGO_ENABLED='0'
go run ./cmd/netshield-sensor `
  --mode=sensor `
  --pcap ..\tests\fixtures\sample_synthetic.pcap `
  --model ..\models\netshield_flow.onnx `
  --manifest ..\models\netshield_flow_manifest.json `
  --metrics-addr :9100 `
  --ingest-url http://localhost:5000 `
  --redis-url redis://localhost:6379/0
```

- `--iface` selects a live interface (Linux AF_PACKET or Unix libpcap when built/available); `--pcap` drives deterministic replay.
- Completed flows enter a bounded inference queue (`cap=16384`). When fill exceeds 85%, low-priority established elephant flows (`syn_cnt==0 && fin_cnt==0 && bytes>1MB`) are shed and `netshield_flows_dropped_backpressure_total` is incremented instead of blocking capture.
- The active model bundle is stored in an `atomic.Pointer` and hot-reloaded when the model/manifest SHA-256 changes (polled every 5s; `SIGHUP` triggers reload on Unix).
- Flagged flows are accumulated per `src_ip` in a 5-minute window. With `--redis-url`, state is stored in Redis sorted sets (`netshield:win:<src_ip>`) via Lua; runtime Redis failures fall back to an in-memory sharded TTL accumulator.
- Alerts are batched to `--ingest-url` (`/api/ingest`, Flask alias of `/api/flows`) every 2s or 256 alerts with exponential backoff and a circuit breaker. API key is read from `--api-key`, `NETSHIELD_INGEST_API_KEY`, or `LIVE_CAPTURE_API_KEY`.

## Flow semantics

- **Key:** `FlowKey{SrcIP [16]byte, DstIP [16]byte, SrcPort uint16, DstPort uint16, Proto uint8, IsIPv6 bool}`. Canonical routing uses lexicographic endpoint ordering + FNV-1a; the directional anchor is preserved and flipped on a reverse `SYN && !ACK` to identify the true TCP initiator.
- **Protocols:** IPv4/IPv6, TCP, UDP, ICMP, ICMPv6 (ICMP ports are 0).
- **Virtual clock:** shard clock is driven by packet capture timestamps (epoch µs). Idle timeout `15s`, active timeout `120s`, sweep every `1s` virtual time. Flows flush on completed bidirectional FIN handshake, on RST, at EOF/shutdown, and when timed out.
- **Canonical schema (26, fixed order):** `protocol`, `duration_sec`, `fwd_pkts`, `bwd_pkts`, `fwd_bytes`, `bwd_bytes`, `fwd_hdr_bytes`, `bwd_hdr_bytes`, `fin_cnt`, `syn_cnt`, `rst_cnt`, `psh_cnt`, `ack_cnt`, `urg_cnt`, `ece_cnt`, `cwr_cnt`, `flow_iat_mean`, `flow_iat_std`, `flow_iat_max`, `pkt_len_mean`, `pkt_len_std`, `pkt_len_max`, `bytes_per_sec`, `pkts_per_sec`, `fwd_bwd_pkt_ratio`, `syn_ack_ratio`. `SchemaVersion` is `netshield-flow-v1`; `SchemaSHA256()` is the digest of the comma-joined names so Python tooling can assert schema equality at startup. Counts are exact (not binary indicators), IAT statistics are microseconds, Welford uses sample (n-1) variance and reports `0.0` below two observations, ratios use `max(denominator, 1)` guards, and every row is sanitized so no value is `NaN` or `Inf`.
- **Model vector (24):** `ModelFeatureNames` keeps the frozen input order of the shipped ONNX classifier (`models/netshield_flow_manifest.json`). The sensor projects the canonical statistics onto that order, so retraining on the 26-feature CSV is a deliberate schema bump rather than silent drift.

## Metrics

Prometheus endpoint: `--metrics-addr` (default `:9100`, empty disables).

- `netshield_packets_received_total`
- `netshield_packets_decode_errors_total`
- `netshield_packets_dropped_kernel_total`
- `netshield_active_flows`
- `netshield_flows_completed_total`
- `netshield_flows_dropped_backpressure_total`
- `netshield_alerts_emitted_total`
- `netshield_inference_duration_seconds` (histogram)
- `netshield_model_info{sha256,backend,version}`

## ONNX export bridge

`training/export_onnx.py` derives the shipped model's 24-input vector from CIC-style flow rows, trains a calibrated `HistGradientBoostingClassifier`, exports `models/netshield_flow.onnx`, and writes `models/netshield_flow_manifest.json` (feature names, threshold, calibration method, SHA-256, fallback coefficients) plus `models/netshield_flow_parity.json`. Parity is validated in-script and by `tests/test_export_onnx.py` (`max |Δ| < 1e-5` over 1,000 rows).

The pinned Python serving bundle `models/model_bundle_rf_day_based_seed42.pkl` (SHA-256 `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`) remains untouched; the ONNX artifacts are a separate sensor inference path.
