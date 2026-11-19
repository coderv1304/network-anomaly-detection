# Optional Zeek `conn.log` Collector

**Status:** parser and CSV converter only; Zeek itself is not bundled.
**Module:** [`../domain/zeek_parser.py`](../domain/zeek_parser.py).
**Tests:** [`../tests/test_zeek_parser.py`](../tests/test_zeek_parser.py).
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.

Zeek is an optional collection path for operators who already run it. It is not a
replacement for the Python PCAP parser and it does not make the live path
validated. The parser accepts the two common `conn.log` encodings, maps records
to the app's canonical flow names, and exposes the ratio-only feature schema.

## 1. Why Zeek

`conn.log` is deterministic and documented. The same fields are produced from a
live interface and from an offline PCAP, so a Zeek deployment avoids
re-implementing CICFlowMeter's state machine a third time. It also gives an
independent collector for comparing the app's own parser against a second
implementation.

It does **not** make the 80-feature serving schema available. `conn.log` lacks
per-packet length maxima, exact per-direction flag counts, header lengths, bulk
statistics, and active/idle timing. Those values are left unavailable rather
than filled with fabricated measurements.

## 2. Supported inputs

| Format | Detection | Notes |
| --- | --- | --- |
| TSV | `#separator` + `#fields` headers | Standard `conn.log`; tab separator by default |
| JSON lines | one object per line with `_path` | `_path` must be `conn` or absent |

Malformed JSON lines, non-`conn` JSON records (for example `http`), and short
TSV rows are skipped. A collector tail therefore does not crash on a partially
written line.

## 3. Field mapping

The parser prefers Zeek's IP-layer byte counters. CIC's `Total Length of Fwd
Packets` counts IP packets (headers included), so `orig_ip_bytes`/`resp_ip_bytes`
are the closest analogue. When those fields are absent, it falls back to
`orig_bytes`/`resp_bytes`, which count application payload only.

| App canonical field | Zeek source | Notes |
| --- | --- | --- |
| `src_ip`, `dst_ip` | `id.orig_h`, `id.resp_h` | Required for host/window evidence |
| `src_port`, `dst_port` | `id.orig_p`, `id.resp_p` | |
| `protocol` / `protocol_number` | `proto` | `tcp`/`udp`/`icmp`/`icmpv6` or number |
| `timestamp` | `ts` | Epoch seconds |
| `flow_id` | `uid` | Zeek connection UID |
| `flow_duration` | `duration` × 1e6 | CIC stores microseconds |
| `tot_fwd_pkts`, `tot_bwd_pkts` | `orig_pkts`, `resp_pkts` | |
| `totlen_fwd_pkts`, `totlen_bwd_pkts` | `orig_ip_bytes`, `resp_ip_bytes` | Falls back to payload bytes |
| `flow_pkts_s`, `flow_byts_s` | derived | `0` when duration is zero |
| `pkt_len_mean` | derived | `0` when there are no packets |

### Flag approximation

Zeek exposes a connection state and a history string, not per-packet flag
counts. The parser maps coarse state membership to a `0`/`1` indicator:

| App field | Zeek `conn_state` values |
| --- | --- |
| `syn_flag_cnt` | `S0`, `S1`, `S2`, `S3`, `SF`, `SH`, `SHR`, `REJ`, `RSTOS0` |
| `fin_flag_cnt` | `SF`, `S1`, `S2`, `S3`, `SH`, `SHR` |
| `rst_flag_cnt` | `REJ`, `RSTO`, `RSTR`, `RSTOS0`, `RSTRH` |

These are **connection-level indicators**, not counts. A flow with five SYNs is
still `1`. Do not compare them numerically with CICFlowMeter flag counts.

## 4. Unavailable fields

| Tier A field | Status | Reason |
| --- | --- | --- |
| `packet_length_max` | `None` | `conn.log` has no per-packet length |
| Exact flag counts | Coarse `0`/`1` only | Only `conn_state` and `history` are logged |
| Header lengths, bulk rates, active/idle | absent | Not in `conn.log` |

`record_to_tier_a()` returns `packet_length_max = None` so the serving pipeline's
imputer handles it explicitly. The value is never invented. Because the 80-feature
serving artifact expects many more columns, a Zeek-only deployment should use the
portable ratio model or a Zeek-specific behavioural detector, not the serving
bundle.

## 5. Usage

Convert to portable ratio rows:

```bash
venv/Scripts/python.exe -m domain.zeek_parser path/to/conn.log --portable
```

Write Tier A-shaped rows for an external consumer:

```bash
venv/Scripts/python.exe -m domain.zeek_parser path/to/conn.log --output conn_tier_a.csv
```

From Python:

```python
from domain.zeek_parser import zeek_to_flows, zeek_to_portable_rows

flows = zeek_to_flows("conn.log", max_records=10_000)
portable = zeek_to_portable_rows("conn.log")
```

`--max-records` caps both paths. The CSV writer emits identifiers plus the 12
Tier A columns, and leaves `packet_length_max` empty.

## 6. Limits and responsible use

- **Not a validated live detector.** This parser changes the collection format,
  not the evidence level. Live accuracy remains unvalidated.
- **No flow reassembly changes.** Zeek's flow timeout is its own; it will not
  match CICFlowMeter's timeout, so duration and rate distributions differ.
- **Privacy.** `conn.log` normally contains source and destination addresses,
  ports, and timing. Apply the same retention and access controls as any other
  flow record.
- **The parser does not start Zeek.** Running Zeek, rotating logs, and
  configuring interfaces remain operator responsibilities.

## 7. Reproduction

```bash
venv/Scripts/python.exe -m pytest tests/test_zeek_parser.py -q
```
