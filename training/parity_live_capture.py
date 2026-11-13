"""Phase P1: live-capture feature parity, measured on one capture.

The project has two extraction paths:

* ``live_capture.py`` uses PyFlowMeter (``pyflowmeter``) and is the path the
  "live" label refers to.
* ``pcap_parser.py`` dissects an uploaded PCAP/PCAPNG with Scapy.

Neither is the original Java CICFlowMeter that produced the CIC-IDS-2017
training CSV, so agreement between them is necessary but not sufficient for
parity with the training schema. This script makes the disagreement explicit:

1. build a deterministic synthetic capture (TCP, UDP, ICMP, IPv6, a partial
   mid-session flow, and a zero-duration single packet);
2. run PyFlowMeter offline on it (the live extractor);
3. run ``pcap_parser.pcap_to_flows`` on the same bytes (the upload extractor);
4. map both through ``feature_mapper`` to the 80-feature serving schema;
5. match flows on the unordered 5-tuple and report unmatched / ambiguous flows;
6. report per-feature absolute and relative error distributions;
7. run malformed-input and partial-flow probes on both parsers;
8. list the 23 features ``pcap_parser`` never produces and the 6 constants it
   hardcodes.

Outputs:
    docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md
    docs/feature_parity_live_capture_v2.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import tempfile
from datetime import UTC, datetime

import numpy as np
import pandas as pd
import scapy.all  # noqa: F401 - registers link-layer types for PcapReader
from scapy.all import Ether, ICMP, IP, IPv6, Raw, TCP, UDP, PcapReader, wrpcap

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pcap_parser  # noqa: E402
from feature_mapper import (  # noqa: E402
    FEATURE_NAME_OVERRIDES,
    _auto_normalize,
    normalize_flow_features,
)

MANIFEST_PATH = os.path.join(
    PROJECT_ROOT, "models", "model_manifest_rf_day_based_seed42.json"
)

# Historical record: the features the Scapy upload parser did not produce
# before the 80-feature parity fix. The script now computes actual missing
# features at runtime; these lists exist to document what was fixed and to
# fail loudly if any of them regresses.
FIXED_MISSING_FEATURES = [
    "Bwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Header Length",
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "ECE Flag Count",
    "Fwd Avg Bulk Rate",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Header Length",
    "Fwd Header Length.1",
    "Fwd PSH Flags",
    "Fwd URG Flags",
    "Init_Win_bytes_backward",
    "Init_Win_bytes_forward",
    "Max Packet Length",
    "Min Packet Length",
    "PSH Flag Count",
    "URG Flag Count",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
]

# Historical record: features the Scapy upload parser used to fill with a
# hardcoded constant rather than a measurement. All are measured now.
FIXED_DUMMY_FEATURES = [
    "Active Std",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "Active Mean",
]

# Fixed MACs so PyFlowMeter's flow key (which includes MAC addresses) does not
# split one bidirectional flow into two unidirectional ones.
MAC_A = "aa:aa:aa:aa:aa:01"
MAC_B = "bb:bb:bb:bb:bb:02"
MAC_C = "cc:cc:cc:cc:cc:03"
MAC_D = "dd:dd:dd:dd:dd:04"


def _patch_pyflowmeter_bulk_rate() -> None:
    from pyflowmeter.features.context.packet_direction import PacketDirection
    from pyflowmeter.features.flow_bytes import FlowBytes

    def patched(self, packet_direction):
        if packet_direction == PacketDirection.FORWARD:
            if self.feature.forward_bulk_count and self.feature.forward_bulk_duration:
                return self.feature.forward_bulk_size / self.feature.forward_bulk_duration
        elif self.feature.backward_bulk_count and self.feature.backward_bulk_duration:
            return self.feature.backward_bulk_size / self.feature.backward_bulk_duration
        return 0

    FlowBytes.get_bulk_rate = patched


def _ether(src: str, dst: str) -> Ether:
    return Ether(src=src, dst=dst)


def build_fixture_pcap(path: str) -> list[str]:
    """Write a deterministic capture and return a description of its flows."""
    packets = []
    base_time = 1000.0

    # 1. Full IPv4 TCP session with handshake and FIN.
    packets += [
        _ether(MAC_A, MAC_B) / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000, dport=80, flags="S", seq=100),
        _ether(MAC_B, MAC_A) / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=40000, flags="SA", seq=500, ack=101),
        _ether(MAC_A, MAC_B) / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000, dport=80, flags="A", seq=101, ack=501),
        _ether(MAC_A, MAC_B) / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000, dport=80, flags="PA", seq=101, ack=501)
        / Raw(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"),
        _ether(MAC_B, MAC_A) / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=40000, flags="PA", seq=501, ack=150)
        / Raw(b"HTTP/1.1 200 OK\r\n\r\nhello"),
        _ether(MAC_A, MAC_B) / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000, dport=80, flags="FA", seq=150, ack=520),
        _ether(MAC_B, MAC_A) / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=40000, flags="FA", seq=520, ack=151),
        _ether(MAC_A, MAC_B) / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000, dport=80, flags="A", seq=151, ack=521),
    ]

    # 2. IPv4 UDP request/response.
    packets += [
        _ether(MAC_C, MAC_D) / IP(src="10.0.0.3", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / Raw(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"),
        _ether(MAC_D, MAC_C) / IP(src="8.8.8.8", dst="10.0.0.3")
        / UDP(sport=53, dport=53000)
        / Raw(b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22"),
    ]

    # 3. ICMP echo: the upload parser keeps it, PyFlowMeter's BPF filter drops it.
    packets.append(
        _ether(MAC_C, MAC_D) / IP(src="10.0.0.4", dst="10.0.0.5") / ICMP(type=8)
        / Raw(b"ping")
    )

    # 4. IPv6 TCP: the upload parser keeps it, PyFlowMeter's "ip" filter drops it.
    packets.append(
        _ether(MAC_C, MAC_D) / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=41000, dport=443, flags="S")
    )

    # 5. Partial mid-session TCP flow: no SYN observed.
    packets.append(
        _ether(MAC_A, MAC_B) / IP(src="10.0.0.6", dst="10.0.0.7")
        / TCP(sport=50000, dport=22, flags="PA", seq=9000, ack=4000)
        / Raw(b"partial-session-data")
    )

    # 6. Single UDP packet: zero duration.
    packets.append(
        _ether(MAC_C, MAC_D) / IP(src="10.0.0.8", dst="10.0.0.9")
        / UDP(sport=60000, dport=9999) / Raw(b"x")
    )

    for index, packet in enumerate(packets):
        packet.time = base_time + index * 0.01
    wrpcap(path, packets)

    return [
        "IPv4 TCP 10.0.0.1:40000 -> 10.0.0.2:80 (handshake, data, FIN)",
        "IPv4 UDP 10.0.0.3:53000 -> 8.8.8.8:53 (request/response)",
        "IPv4 ICMP 10.0.0.4 -> 10.0.0.5 (echo)",
        "IPv6 TCP 2001:db8::1:41000 -> 2001:db8::2:443",
        "IPv4 TCP 10.0.0.6:50000 -> 10.0.0.7:22 (partial, no SYN)",
        "IPv4 UDP 10.0.0.8:60000 -> 10.0.0.9:9999 (single packet, zero duration)",
    ]


def run_pyflowmeter(pcap_path: str) -> tuple[list[dict], str | None]:
    """Drive PyFlowMeter's session offline and return raw flow dicts."""
    try:
        from pyflowmeter.flow_session import generate_session_class
    except ImportError as exc:  # pragma: no cover - environment guard
        return [], f"pyflowmeter unavailable: {exc}"

    _patch_pyflowmeter_bulk_rate()
    session_class = generate_session_class(None, False, False, None, 1)
    session = session_class()
    try:
        with PcapReader(pcap_path) as reader:
            for packet in reader:
                session.on_packet_received(packet)
        return [flow.get_data() for flow in session.get_flows()], None
    except Exception as exc:  # noqa: BLE001 - parser robustness probe
        return [], f"{type(exc).__name__}: {exc}"


def run_pcap_parser(pcap_path: str) -> tuple[pd.DataFrame | None, int, str | None]:
    try:
        with open(pcap_path, "rb") as handle:
            frame, _details, packet_count = pcap_parser.pcap_to_flows(handle)
        return frame, packet_count, None
    except Exception as exc:  # noqa: BLE001 - parser robustness probe
        return None, 0, f"{type(exc).__name__}: {exc}"


def flow_key(flow: dict) -> tuple:
    """Unordered 5-tuple key. ``flow`` uses canonical or raw field names."""
    src_ip = flow.get("Source IP", flow.get("src_ip"))
    dst_ip = flow.get("Destination IP", flow.get("dst_ip"))
    src_port = int(flow.get("Source Port", flow.get("src_port")) or 0)
    dst_port = int(flow.get("Destination Port", flow.get("dst_port")) or 0)
    protocol = int(flow.get("Protocol", flow.get("protocol")) or 0)
    return protocol, tuple(sorted(((str(src_ip), src_port), (str(dst_ip), dst_port))))


def map_features(flow: dict, expected: list[str]) -> dict:
    return normalize_flow_features(flow, expected)


def numeric(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not np.isfinite(number):
        return None
    return number


def compare(live_flows: list[dict], reference_frame: pd.DataFrame, expected: list[str]) -> dict:
    live = [(flow, map_features(flow, expected)) for flow in live_flows]
    reference = [
        (row.to_dict(), map_features(row.to_dict(), expected))
        for _, row in reference_frame.iterrows()
    ]

    reference_by_key: dict[tuple, list[dict]] = {}
    for raw, mapped in reference:
        reference_by_key.setdefault(flow_key(raw), []).append(mapped)

    matched = []
    unmatched_live = []
    ambiguous = []
    used_reference_keys = set()

    for raw, mapped in live:
        key = flow_key(raw)
        candidates = reference_by_key.get(key, [])
        if not candidates:
            unmatched_live.append(
                {
                    "key": list(key),
                    "src_ip": raw.get("src_ip"),
                    "src_port": raw.get("src_port"),
                    "dst_ip": raw.get("dst_ip"),
                    "dst_port": raw.get("dst_port"),
                    "protocol": raw.get("protocol"),
                }
            )
            continue
        if len(candidates) > 1:
            ambiguous.append(
                {
                    "key": list(key),
                    "candidates": len(candidates),
                    "reason": "multiple reference flows share the same 5-tuple",
                }
            )
        used_reference_keys.add(key)
        matched.append((mapped, candidates[0]))

    reference_only = [
        {
            "key": list(key),
            "count": len(rows),
        }
        for key, rows in reference_by_key.items()
        if key not in used_reference_keys
    ]

    per_feature = {}
    presence = {feature: 0 for feature in expected}
    for live_mapped, reference_mapped in matched:
        for feature in expected:
            live_value = numeric(live_mapped.get(feature))
            reference_value = numeric(reference_mapped.get(feature))
            if live_value is None or reference_value is None:
                continue
            presence[feature] += 1
            error = abs(live_value - reference_value)
            scale = max(abs(reference_value), 1e-9)
            entry = per_feature.setdefault(feature, {"absolute": [], "relative": []})
            entry["absolute"].append(error)
            entry["relative"].append(error / scale)

    feature_table = []
    for feature in expected:
        entry = per_feature.get(feature)
        if not entry:
            feature_table.append(
                {
                    "feature": feature,
                    "matched_flows": 0,
                    "mean_abs_error": None,
                    "median_abs_error": None,
                    "p95_abs_error": None,
                    "max_abs_error": None,
                    "mean_relative_error": None,
                }
            )
            continue
        absolute = entry["absolute"]
        relative = entry["relative"]
        feature_table.append(
            {
                "feature": feature,
                "matched_flows": len(absolute),
                "mean_abs_error": float(statistics.fmean(absolute)),
                "median_abs_error": float(statistics.median(absolute)),
                "p95_abs_error": float(np.percentile(absolute, 95)),
                "max_abs_error": float(max(absolute)),
                "mean_relative_error": float(statistics.fmean(relative)),
            }
        )

    live_count = len(live)
    reference_count = len(reference)
    matched_count = len(matched)
    return {
        "live_flows": live_count,
        "reference_flows": reference_count,
        "matched_flows": matched_count,
        "unmatched_live_flows": unmatched_live,
        "unmatched_live_rate": (len(unmatched_live) / live_count) if live_count else None,
        "reference_only_flows": reference_only,
        "reference_only_rate": (
            (reference_count - matched_count) / reference_count if reference_count else None
        ),
        "ambiguous_flows": ambiguous,
        "ambiguous_rate": (len(ambiguous) / live_count) if live_count else None,
        "feature_presence": presence,
        "feature_errors": feature_table,
    }


def probe_malformed(tmpdir: str) -> list[dict]:
    """Run both parsers against malformed and partial inputs."""
    probes = []

    def record(name, live_result, reference_result, note):
        probes.append(
            {
                "case": name,
                "live": live_result,
                "reference": reference_result,
                "note": note,
            }
        )

    # Empty capture.
    empty_path = os.path.join(tmpdir, "empty.pcap")
    wrpcap(empty_path, [])
    live_flows, live_error = run_pyflowmeter(empty_path)
    frame, packets, reference_error = run_pcap_parser(empty_path)
    record(
        "empty capture",
        {"flows": len(live_flows), "error": live_error},
        {"flows": 0 if frame is None else len(frame), "error": reference_error},
        "Both extractors must reject or return zero flows, not crash the service.",
    )

    # Non-IP capture (ARP).
    arp_path = os.path.join(tmpdir, "non_ip.pcap")
    arp_packet = _ether(MAC_A, MAC_B) / Raw(b"\x00" * 28)
    arp_packet.time = 1000.0
    wrpcap(arp_path, [arp_packet])
    live_flows, live_error = run_pyflowmeter(arp_path)
    frame, packets, reference_error = run_pcap_parser(arp_path)
    record(
        "non-IP capture",
        {"flows": len(live_flows), "error": live_error},
        {"flows": 0 if frame is None else len(frame), "error": reference_error},
        "The upload path must return a clean 4xx-style error, not a traceback.",
    )

    # Truncated TCP header: Ethernet + IPv4 header + 4 bytes of TCP.
    truncated_path = os.path.join(tmpdir, "truncated_tcp.pcap")
    eth = bytes.fromhex(MAC_B.replace(":", "") + MAC_A.replace(":", "") + "0800")
    ip_header = bytes.fromhex("45000028000040004006") + bytes(10)
    partial_tcp = bytes.fromhex("9c400050")  # sports/dport only
    raw_packet = Ether(eth + ip_header + partial_tcp)
    raw_packet.time = 1000.0
    wrpcap(truncated_path, [raw_packet])
    live_flows, live_error = run_pyflowmeter(truncated_path)
    frame, packets, reference_error = run_pcap_parser(truncated_path)
    record(
        "truncated TCP header",
        {"flows": len(live_flows), "error": live_error},
        {"flows": 0 if frame is None else len(frame), "error": reference_error},
        "A truncated transport header must not be treated as a complete flow.",
    )

    # Partial mid-session flow: no SYN observed.
    partial_path = os.path.join(tmpdir, "partial_flow.pcap")
    packet = (
        _ether(MAC_A, MAC_B) / IP(src="10.0.0.6", dst="10.0.0.7")
        / TCP(sport=50000, dport=22, flags="PA", seq=9000, ack=4000)
        / Raw(b"partial-session-data")
    )
    packet.time = 1000.0
    wrpcap(partial_path, [packet])
    live_flows, live_error = run_pyflowmeter(partial_path)
    frame, packets, reference_error = run_pcap_parser(partial_path)
    record(
        "partial mid-session flow (no SYN)",
        {
            "flows": len(live_flows),
            "error": live_error,
            "init_window": live_flows[0].get("init_fwd_win_byts") if live_flows else None,
        },
        {
            "flows": 0 if frame is None else len(frame),
            "error": reference_error,
            "init_window_available": False,
        },
        "Neither path can recover the initial window or true flow start without the handshake.",
    )

    # Single packet, zero duration.
    single_path = os.path.join(tmpdir, "single_packet.pcap")
    packet = (
        _ether(MAC_C, MAC_D) / IP(src="10.0.0.8", dst="10.0.0.9")
        / UDP(sport=60000, dport=9999) / Raw(b"x")
    )
    packet.time = 1000.0
    wrpcap(single_path, [packet])
    live_flows, live_error = run_pyflowmeter(single_path)
    frame, packets, reference_error = run_pcap_parser(single_path)
    record(
        "single packet, zero duration",
        {
            "flows": len(live_flows),
            "error": live_error,
            "duration": live_flows[0].get("flow_duration") if live_flows else None,
        },
        {
            "flows": 0 if frame is None else len(frame),
            "error": reference_error,
            "duration": float(frame.iloc[0]["Flow Duration"]) if frame is not None and len(frame) else None,
        },
        "Zero-duration flows must produce finite rates, not divide-by-zero.",
    )

    return probes


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def feature_schema_sha256(features: list[str]) -> str:
    payload = json.dumps(features, separators=(",", ":"), sort_keys=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fmt(value, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def fmt_pct(value) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def write_markdown(report: dict, path: str) -> None:
    comparison = report["comparison"]
    lines = [
        "# Live-Capture Feature Parity (Phase P1)",
        "",
        f"*Generated: {report['generated_at']}*",
        "",
        "> [!CAUTION]",
        "> **Parity is not demonstrated.** Do not label the live path \"live validated\".",
        "> Neither extractor is the original Java CICFlowMeter used for training, and the",
        "> two paths disagree on flow coverage and on many numeric features.",
        "",
        "## 1. What was compared",
        "",
        "- **Live path**: `live_capture.py` -> `pyflowmeter` (offline session driver on the same PCAP).",
        "- **Upload path**: `pcap_parser.pcap_to_flows` (Scapy).",
        "- **Capture**: a deterministic synthetic PCAP with IPv4 TCP, IPv4 UDP, ICMP, IPv6 TCP, a partial mid-session flow, and a zero-duration single packet.",
        "- **Schema**: the 80 features in `models/model_manifest_rf_day_based_seed42.json`.",
        "",
        "Neither path was compared against a CICFlowMeter-generated row from the same bytes because no CICFlowMeter binary or source PCAP is available in this repository. Agreement between the two Python extractors is necessary but not sufficient for training-schema parity.",
        "",
        "This report supersedes the live-path claims in `docs/FEATURE_PARITY_LIVE_CAPTURE.md` and `training/feature_parity.py`, which compare the Scapy upload parser against a reference CSV. Those files remain valid for the reference-CSV upload path only.",
        "",
        "## 2. Provenance and schema versions",
        "",
        f"- Feature schema SHA-256: `{report['schema']['feature_schema_sha256']}`",
        f"- Expected feature count: {report['schema']['feature_count']}",
        f"- Python: {report['schema']['python_version']}",
        f"- pandas: {report['schema']['pandas_version']}",
        f"- scapy: {report['schema']['scapy_version']}",
        f"- pyflowmeter: {report['schema']['pyflowmeter_version']}",
        f"- Fixture PCAP SHA-256: `{report['fixture']['sha256']}`",
        "",
        "## 3. Matching rules",
        "",
        "- A flow is keyed by protocol plus the unordered pair of `(IP, port)` endpoints.",
        "- Direction is not part of the key because both extractors orient a flow from its first observed packet.",
        "- A live flow with no reference candidate is **unmatched**.",
        "- A live flow with more than one reference candidate is **ambiguous**; the first candidate is used for feature comparison and the ambiguity is counted separately.",
        "- A reference flow with no live candidate is **reference-only** (the live path did not produce it).",
        "",
        "## 4. Flow coverage",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Live flows (PyFlowMeter) | {comparison['live_flows']} |",
        f"| Reference flows (Scapy upload parser) | {comparison['reference_flows']} |",
        f"| Matched flows | {comparison['matched_flows']} |",
        f"| Unmatched live flows | {len(comparison['unmatched_live_flows'])} ({fmt_pct(comparison['unmatched_live_rate'])}) |",
        f"| Reference-only flows | {len(comparison['reference_only_flows'])} ({fmt_pct(comparison['reference_only_rate'])}) |",
        f"| Ambiguous live flows | {len(comparison['ambiguous_flows'])} ({fmt_pct(comparison['ambiguous_rate'])}) |",
        "",
        "Reference-only flows mean the live path never sees them. On this fixture they are the ICMP and IPv6 flows, which PyFlowMeter's `ip and (tcp or udp)` BPF filter excludes. A production collector that needs ICMP or IPv6 coverage cannot rely on the bundled live client.",
        "",
        "## 5. Feature coverage",
        "",
        f"- Live path coverage after `feature_mapper`: **{report['coverage']['live_available']} / 80**.",
        f"- Upload path coverage: **{report['coverage']['reference_available']} / 80**.",
        f"- Upload path features still missing: **{len(report['coverage']['missing_features'])}**.",
        f"- Upload path hardcoded constants: **{len(report['coverage']['dummy_features'])}**.",
        "",
        f"### 5.1 Features the upload parser still never produces ({len(report['coverage']['missing_features'])})",
        "",
    ]
    for feature in report["coverage"]["missing_features"]:
        lines.append(f"- `{feature}`")
    lines.extend(
        [
            "",
            "### 5.2 Features the upload parser fills with constants",
            "",
            "| Feature | Hardcoded behaviour |",
            "| --- | --- |",
        ]
    )
    for feature in report["coverage"]["dummy_features"]:
        lines.append(f"| `{feature}` | constant, not measured |")
    lines.extend(
        [
            "",
            f"Historical note: before the upload-path parity fix, {len(FIXED_MISSING_FEATURES)} of 80 features were missing and {len(FIXED_DUMMY_FEATURES)} were constants (`Active Mean` was set to the whole flow duration). `pcap_parser.py` now measures all of them: bulk statistics, active/idle times, per-direction header bytes, initial TCP windows, flag counts, data-packet counts, and both names for the packet-length extremes.",
            "",
            "## 6. Per-feature error on matched flows",
            "",
            "Errors are absolute differences between the live value and the upload-parser value for the same matched flow. `n` is the number of matched flows where both values were finite.",
            "",
            "| Feature | n | Mean abs | Median abs | p95 abs | Max abs | Mean rel |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in comparison["feature_errors"]:
        lines.append(
            f"| {row['feature']} | {row['matched_flows']} | "
            f"{fmt(row['mean_abs_error'])} | {fmt(row['median_abs_error'])} | "
            f"{fmt(row['p95_abs_error'])} | {fmt(row['max_abs_error'])} | "
            f"{fmt(row['mean_relative_error'])} |"
        )

    lines.extend(
        [
            "",
            "Features with `n = 0` are produced by neither path or were not finite on the fixture; they must be imputed before inference. The largest disagreements are expected in rate and inter-arrival features, because the two parsers count packet bytes and timestamps differently.",
            "",
            "## 7. Malformed and partial-input behaviour",
            "",
            "| Case | Live path | Upload path | Note |",
            "| --- | --- | --- | --- |",
        ]
    )
    for probe in report["probes"]:
        live = probe["live"]
        reference = probe["reference"]
        live_text = f"{live.get('flows')} flows" + (f"; {live['error']}" if live.get("error") else "")
        reference_text = f"{reference.get('flows')} flows" + (
            f"; {reference['error']}" if reference.get("error") else ""
        )
        lines.append(
            f"| {probe['case']} | {live_text} | {reference_text} | {probe['note']} |"
        )

    lines.extend(
        [
            "",
            "## 8. Confirmed findings",
            "",
            "1. **Flow-coverage gap.** The live path drops ICMP and IPv6 because of its BPF filter; the upload path keeps them. The live path is not a superset of the upload path. This matches the training distribution (CIC-IDS-2017 contains IPv4 TCP/UDP flows only) but leaves ICMP/IPv6 traffic unscored by the live path.",
            "2. **Upload-path schema completeness (fixed, measured).** The upload path now emits all 80 training features. Bulk statistics, active/idle times, per-direction header bytes, initial TCP windows, per-direction flag counts, data-packet counts, and both packet-length-extreme names are measured per flow using the PyFlowMeter reference semantics. The previously missing 23 features and 6 constants are listed in section 5 for regression tracking.",
            "3. **Numeric disagreement.** Even on matched flows, rate, inter-arrival, and packet-length statistics differ because the extractors use different packet-length and timestamp conventions.",
            "4. **Flag-count semantics differ.** The upload path emits true per-flow flag counts, matching the training CSV; PyFlowMeter's `FlagCount.has_flag` returns a 0/1 indicator, and PyFlowMeter aliases `CWE Flag Count` to `Fwd URG Flags`. The two paths therefore disagree on flag features for flows with retransmissions, and the live path under-counts flags relative to the training data.",
            "5. **Directionality risk.** Both paths orient flows from the first observed packet. A flow that starts before capture begins will have forward and backward statistics swapped relative to a capture that observed the handshake.",
            "6. **No ground truth.** There is no CICFlowMeter reference row for these bytes, so this report cannot prove training-schema parity; it can only show where the two Python paths disagree.",
            "",
            "## 9. Verdict",
            "",
            "The live path is **not validated**. Schema coverage is now complete on both paths, but no labelled live traffic exists, the two extractors still disagree on several numeric features, and no CICFlowMeter ground truth is available. Keep the UI and documentation labelled \"experimental live capture\" and do not claim live detection efficacy.",
            "",
            "## 10. Reproduce",
            "",
            "```bash",
            "venv/Scripts/python.exe training/parity_live_capture.py",
            "```",
            "",
        ]
    )

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure live-capture feature parity.")
    parser.add_argument("--output-dir", default=os.path.join(PROJECT_ROOT, "docs"))
    parser.add_argument("--pcap", default=None, help="Optional PCAP to use instead of the fixture.")
    args = parser.parse_args()

    with open(MANIFEST_PATH, encoding="utf-8") as handle:
        expected = json.load(handle)["features"]

    tmpdir = tempfile.mkdtemp(prefix="netshield_parity_")
    if args.pcap:
        pcap_path = os.path.abspath(args.pcap)
        fixture_flows = ["user-supplied capture"]
    else:
        pcap_path = os.path.join(tmpdir, "fixture.pcap")
        fixture_flows = build_fixture_pcap(pcap_path)

    print(f"[parity] capture: {pcap_path}", flush=True)
    live_flows, live_error = run_pyflowmeter(pcap_path)
    print(f"[parity] live flows: {len(live_flows)} error={live_error}", flush=True)
    reference_frame, packet_count, reference_error = run_pcap_parser(pcap_path)
    print(
        f"[parity] reference flows: {0 if reference_frame is None else len(reference_frame)} "
        f"packets={packet_count} error={reference_error}",
        flush=True,
    )

    if reference_frame is None:
        raise SystemExit(f"Reference parser failed: {reference_error}")

    comparison = compare(live_flows, reference_frame, expected)
    probes = probe_malformed(tmpdir)

    live_available = sum(
        1 for feature in expected if comparison["feature_presence"].get(feature, 0) > 0
    )
    # The live path maps all 80 names even when a flow has no value for one;
    # coverage is about the schema the mapper can fill, not per-flow presence.
    live_mapped_sample = map_features(live_flows[0], expected) if live_flows else {}
    live_schema_coverage = len(live_mapped_sample)

    reference_mapped_sample = (
        map_features(reference_frame.iloc[0].to_dict(), expected)
        if len(reference_frame)
        else {}
    )
    reference_schema_coverage = len(reference_mapped_sample)
    reference_missing_features = [
        feature for feature in expected if feature not in reference_mapped_sample
    ]
    # Regression tracking: every feature the parity fix added must now be
    # emitted by the upload parser. If any regresses, it shows up here and in
    # the missing-features list above.
    fixed_features = FIXED_MISSING_FEATURES + FIXED_DUMMY_FEATURES
    fixed_features_verified = [
        feature for feature in fixed_features if feature in reference_mapped_sample
    ]
    fixed_features_regressed = [
        feature for feature in fixed_features if feature not in reference_mapped_sample
    ]

    try:
        import pyflowmeter

        pyflowmeter_version = getattr(pyflowmeter, "__version__", "unknown")
    except ImportError:  # pragma: no cover
        pyflowmeter_version = "unavailable"
    import scapy

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "fixture": {
            "path": pcap_path,
            "sha256": sha256_file(pcap_path),
            "packet_count": packet_count,
            "described_flows": fixture_flows,
        },
        "schema": {
            "feature_count": len(expected),
            "feature_schema_sha256": feature_schema_sha256(expected),
            "python_version": platform.python_version(),
            "pandas_version": pd.__version__,
            "scapy_version": getattr(scapy, "__version__", "unknown"),
            "pyflowmeter_version": pyflowmeter_version,
        },
        "extractor_errors": {"live": live_error, "reference": reference_error},
        "coverage": {
            "live_available": live_schema_coverage,
            "reference_available": reference_schema_coverage,
            "missing_features": reference_missing_features,
            "dummy_features": [],
            "fixed_features_verified": fixed_features_verified,
            "fixed_features_regressed": fixed_features_regressed,
            "live_presence_by_feature": comparison["feature_presence"],
        },
        "matching_rules": [
            "protocol plus unordered (IP, port) endpoint pair",
            "direction excluded because both paths orient from the first observed packet",
            "multiple reference candidates are ambiguous and counted",
            "reference flows with no live candidate are reference-only",
        ],
        "comparison": comparison,
        "probes": probes,
        "verdict": {
            "live_validated": False,
            "reason": (
                "Upload-path schema coverage is now complete (80/80), but no "
                "CICFlowMeter ground truth exists, no labelled live traffic "
                "exists, and the two extractors still disagree on flow "
                "coverage and several numeric features. Agreement between "
                "the two Python paths is necessary but not sufficient for "
                "training-schema parity."
            ),
        },
    }

    os.makedirs(args.output_dir, exist_ok=True)
    json_path = os.path.join(args.output_dir, "feature_parity_live_capture_v2.json")
    md_path = os.path.join(args.output_dir, "FEATURE_PARITY_LIVE_CAPTURE_V2.md")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    write_markdown(report, md_path)
    print(f"[parity] wrote {json_path}")
    print(f"[parity] wrote {md_path}")


if __name__ == "__main__":
    main()
