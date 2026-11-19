"""Optional Zeek ``conn.log`` collector.

Zeek emits deterministic protocol metadata that behaves the same on a live
interface and on an offline PCAP. That makes it a better optional collector for
the ratio-only detector than another CICFlowMeter reimplementation.

This parser accepts both Zeek TSV logs (``#separator``, ``#fields`` headers) and
JSON-lines logs. It maps ``conn.log`` fields to the 12-column Tier A schema and
to the eight portable ratio features. It is honest about what ``conn.log`` does
not contain: packet-length maxima, true per-direction flag counts, and
inter-arrival statistics are unavailable, so the 80-feature serving model is not
fed fabricated values. Use the portable model or a Zeek-specific behavioural
detector for this path.

This module does not start Zeek. It is a parser and a conversion CLI; running
Zeek remains an operator responsibility.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import os
import sys
from typing import Any, Iterable, Iterator

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.portable_features import (  # noqa: E402
    PORTABLE_FEATURE_NAMES,
    portable_matrix,
)

TIER_A_COLUMNS = (
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
    "flow_packets_s",
    "flow_bytes_s",
    "packet_length_mean",
    "packet_length_max",
    "syn_flag_count",
    "fin_flag_count",
    "rst_flag_count",
)

# Zeek conn_state values. See the Zeek conn.log documentation. These are
# coarse indicators, not exact per-packet flag counts.
_SYN_STATES = {"S0", "S1", "S2", "S3", "SF", "SH", "SHR", "REJ", "RSTOS0"}
_FIN_STATES = {"SF", "S1", "S2", "S3", "SH", "SHR"}
_RST_STATES = {"REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH"}

_PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}


def _to_float(value: Any, default: float = 0.0) -> float:
    if value is None or value == "-" or value == "":
        return default
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default


def _to_int(value: Any, default: int = 0) -> int:
    return int(round(_to_float(value, float(default))))


def _protocol(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in _PROTOCOL_NUMBERS:
        return text.upper()
    if text.isdigit():
        reverse = {number: name for name, number in _PROTOCOL_NUMBERS.items()}
        return reverse.get(int(text), text.upper())
    return text.upper() or "TCP"


def _protocol_number(value: Any) -> int:
    text = str(value or "").strip().lower()
    if text in _PROTOCOL_NUMBERS:
        return _PROTOCOL_NUMBERS[text]
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return 6


def iter_conn_records(source: str | os.PathLike | io.TextIOBase) -> Iterator[dict[str, Any]]:
    """Yield ``conn.log`` records from a TSV or JSON-lines file.

    ``source`` may be a path or an already-open text stream. Non-conn JSON
    records (for example ``http``) are skipped. Malformed lines are skipped
    rather than crashing a collector tail.
    """
    close = False
    if hasattr(source, "read"):
        stream = source
    else:
        stream = open(source, encoding="utf-8", errors="replace")
        close = True
    try:
        fields: list[str] | None = None
        separator = "\t"
        started = False
        for raw_line in stream:
            line = raw_line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#separator"):
                separator = line.split(" ", 1)[1] if " " in line else "\t"
                separator = separator.replace("\\x09", "\t")
                continue
            if line.startswith("#fields"):
                fields = line.split(separator)[1:]
                continue
            if line.startswith("#"):
                continue
            started = True
            if line.lstrip().startswith("{"):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                path = record.get("_path")
                if path not in (None, "conn"):
                    continue
                yield record
                continue
            if fields is None:
                continue
            values = line.split(separator)
            if len(values) < len(fields):
                values.extend(["-"] * (len(fields) - len(values)))
            yield dict(zip(fields, values[: len(fields)]))
        if not started:
            return
    finally:
        if close:
            stream.close()


def record_to_flow(record: dict[str, Any]) -> dict[str, Any]:
    """Map one conn record to the app's raw flow-dict shape."""
    duration_s = _to_float(record.get("duration"), 0.0)
    orig_pkts = _to_int(record.get("orig_pkts"), 0)
    resp_pkts = _to_int(record.get("resp_pkts"), 0)
    orig_bytes = _to_float(
        record.get("orig_ip_bytes", record.get("orig_bytes")), 0.0
    )
    resp_bytes = _to_float(
        record.get("resp_ip_bytes", record.get("resp_bytes")), 0.0
    )
    total_packets = orig_pkts + resp_pkts
    total_bytes = orig_bytes + resp_bytes
    duration_s = max(0.0, duration_s)
    state = str(record.get("conn_state") or "").strip().upper()
    protocol_name = _protocol(record.get("proto"))
    return {
        "src_ip": str(record.get("id.orig_h") or record.get("id_orig_h") or "—"),
        "dst_ip": str(record.get("id.resp_h") or record.get("id_resp_h") or "—"),
        "src_port": _to_int(record.get("id.orig_p", record.get("id_orig_p")), 0),
        "dst_port": _to_int(record.get("id.resp_p", record.get("id_resp_p")), 0),
        "protocol": protocol_name,
        "protocol_number": _protocol_number(record.get("proto")),
        "timestamp": _to_float(record.get("ts"), 0.0),
        "flow_id": str(record.get("uid") or ""),
        # feature_mapper canonical names
        "flow_duration": duration_s * 1_000_000.0,
        "tot_fwd_pkts": orig_pkts,
        "tot_bwd_pkts": resp_pkts,
        "totlen_fwd_pkts": orig_bytes,
        "totlen_bwd_pkts": resp_bytes,
        "flow_pkts_s": total_packets / duration_s if duration_s > 0 else 0.0,
        "flow_byts_s": total_bytes / duration_s if duration_s > 0 else 0.0,
        "pkt_len_mean": total_bytes / total_packets if total_packets > 0 else 0.0,
        "syn_flag_cnt": 1 if state in _SYN_STATES else 0,
        "fin_flag_cnt": 1 if state in _FIN_STATES else 0,
        "rst_flag_cnt": 1 if state in _RST_STATES else 0,
        # Zeek does not expose packet-length maxima or exact flag counts.
        "zeek_conn_state": state,
        "zeek_history": str(record.get("history") or ""),
    }


def record_to_tier_a(record: dict[str, Any]) -> dict[str, float | None]:
    """Return the 12 Tier A columns; unavailable maxima are ``None``.

    ``conn.log`` has no per-packet length maximum. Leaving it ``None`` lets the
    serving pipeline's median imputer handle it and prevents a fabricated
    measurement from entering the model.
    """
    flow = record_to_flow(record)
    return {
        "flow_duration": flow["flow_duration"],
        "total_fwd_packets": flow["tot_fwd_pkts"],
        "total_backward_packets": flow["tot_bwd_pkts"],
        "total_length_of_fwd_packets": flow["totlen_fwd_pkts"],
        "total_length_of_bwd_packets": flow["totlen_bwd_pkts"],
        "flow_packets_s": flow["flow_pkts_s"],
        "flow_bytes_s": flow["flow_byts_s"],
        "packet_length_mean": flow["pkt_len_mean"],
        "packet_length_max": None,
        "syn_flag_count": flow["syn_flag_cnt"],
        "fin_flag_count": flow["fin_flag_cnt"],
        "rst_flag_count": flow["rst_flag_cnt"],
    }


def record_to_portable(record: dict[str, Any]) -> dict[str, float]:
    """Return the eight portable ratio features for one conn record."""
    flow = record_to_flow(record)
    matrix = portable_matrix(
        fwd_packets=__import__("numpy").asarray([flow["tot_fwd_pkts"]]),
        bwd_packets=__import__("numpy").asarray([flow["tot_bwd_pkts"]]),
        fwd_bytes=__import__("numpy").asarray([flow["totlen_fwd_pkts"]]),
        bwd_bytes=__import__("numpy").asarray([flow["totlen_bwd_pkts"]]),
    )[0]
    return {
        name: float(matrix[index])
        for index, name in enumerate(PORTABLE_FEATURE_NAMES)
    }


def zeek_to_flows(
    source: str | os.PathLike | io.TextIOBase,
    *,
    max_records: int | None = None,
) -> list[dict[str, Any]]:
    """Convert a conn.log to the app's raw flow-dict shape."""
    rows = []
    for index, record in enumerate(iter_conn_records(source)):
        if max_records is not None and index >= max_records:
            break
        rows.append(record_to_flow(record))
    return rows


def zeek_to_portable_rows(
    source: str | os.PathLike | io.TextIOBase,
    *,
    max_records: int | None = None,
) -> list[dict[str, float]]:
    """Convert a conn.log to portable ratio rows."""
    rows = []
    for index, record in enumerate(iter_conn_records(source)):
        if max_records is not None and index >= max_records:
            break
        rows.append(record_to_portable(record))
    return rows


def write_tier_a_csv(
    source: str,
    destination: str,
    *,
    max_records: int | None = None,
) -> int:
    """Write the Tier A columns (plus identifiers) for an external consumer."""
    rows = []
    for index, record in enumerate(iter_conn_records(source)):
        if max_records is not None and index >= max_records:
            break
        flow = record_to_flow(record)
        tier_a = record_to_tier_a(record)
        rows.append(
            {
                "src_ip": flow["src_ip"],
                "dst_ip": flow["dst_ip"],
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
                "protocol": flow["protocol"],
                "timestamp": flow["timestamp"],
                **tier_a,
            }
        )
    fieldnames = [
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "timestamp",
        *TIER_A_COLUMNS,
    ]
    with open(destination, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("conn_log", help="Path to a Zeek conn.log (TSV or JSON)")
    parser.add_argument("--output", help="Write Tier A rows to this CSV")
    parser.add_argument("--portable", action="store_true", help="Print portable rows as JSON")
    parser.add_argument("--max-records", type=int, default=None)
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.output:
        count = write_tier_a_csv(args.conn_log, args.output, max_records=args.max_records)
        print(f"wrote {count} rows to {args.output}", flush=True)
        return 0
    rows = zeek_to_portable_rows(args.conn_log, max_records=args.max_records)
    print(json.dumps(rows, indent=2, allow_nan=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
