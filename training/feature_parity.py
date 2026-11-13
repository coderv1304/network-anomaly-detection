"""Compare a reference flow export with the Scapy upload parser.

This is the reference-CSV path: it pairs ``pcap_parser.pcap_to_flows`` rows with
rows from an external flow-export CSV. It is **not** a live-path parity test.
The PyFlowMeter live path is measured separately by
``training/parity_live_capture.py`` and reported in
``docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md``.

Only unique bidirectional 5-tuples are paired. Reused 5-tuples are reported as
ambiguous because the current parser does not split flows using exporter timeout
semantics. The report must therefore not be interpreted as full parity evidence
when many keys are ambiguous or unmatched.
"""

import argparse
import hashlib
import ipaddress
import json
import os
from collections import Counter
from typing import Any

import numpy as np
import pandas as pd

from pcap_parser import pcap_to_flows

IDENTIFIER_COLUMNS = {
    "flow id", "source ip", "destination ip", "timestamp", "label", "packet dissector"
}
PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}


def _protocol_number(value: Any) -> int:
    text = str(value).strip().lower()
    if text in PROTOCOLS:
        return PROTOCOLS[text]
    try:
        return int(float(text))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Unsupported protocol value: {value!r}") from exc


def _endpoint(ip: Any, port: Any) -> tuple[str, int]:
    normalized_ip = str(ipaddress.ip_address(str(ip).strip()))
    try:
        normalized_port = int(float(port))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid transport port: {port!r}") from exc
    if not 0 <= normalized_port <= 65535:
        raise ValueError(f"Transport port is outside 0-65535: {normalized_port}")
    return normalized_ip, normalized_port


def _flow_key(row: pd.Series) -> tuple[int, tuple[tuple[str, int], tuple[str, int]]]:
    src = _endpoint(row["Source IP"], row["Source Port"])
    dst = _endpoint(row["Destination IP"], row["Destination Port"])
    return _protocol_number(row["Protocol"]), tuple(sorted((src, dst)))


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compare_feature_tables(
    reference: pd.DataFrame,
    parsed: pd.DataFrame,
    *,
    absolute_tolerance: float = 1e-6,
    relative_tolerance: float = 1e-3,
) -> dict[str, Any]:
    """Compare feature values only for one-to-one canonical 5-tuple matches."""
    reference = reference.copy()
    parsed = parsed.copy()
    reference.columns = reference.columns.str.strip()
    parsed.columns = parsed.columns.str.strip()
    required = {"Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol"}
    for name, frame in (("reference", reference), ("parsed", parsed)):
        missing = sorted(required - set(frame.columns))
        if missing:
            raise ValueError(f"{name} table is missing required key columns: {', '.join(missing)}")

    reference_keys = [_flow_key(row) for _, row in reference.iterrows()]
    parsed_keys = [_flow_key(row) for _, row in parsed.iterrows()]
    reference_counts = Counter(reference_keys)
    parsed_counts = Counter(parsed_keys)
    ambiguous = {
        key for key, count in reference_counts.items() if count != 1
    } | {key for key, count in parsed_counts.items() if count != 1}
    reference_index = {key: idx for idx, key in enumerate(reference_keys) if reference_counts[key] == 1}
    parsed_index = {key: idx for idx, key in enumerate(parsed_keys) if parsed_counts[key] == 1}
    matched_keys = sorted((set(reference_index) & set(parsed_index)) - ambiguous)
    reference_matched = reference.iloc[[reference_index[key] for key in matched_keys]].reset_index(drop=True)
    parsed_matched = parsed.iloc[[parsed_index[key] for key in matched_keys]].reset_index(drop=True)

    candidate_features = sorted(
        column for column in set(reference.columns) & set(parsed.columns)
        if column.strip().lower() not in IDENTIFIER_COLUMNS
    )
    feature_results: dict[str, Any] = {}
    excluded_non_numeric = []
    for feature in candidate_features:
        ref_values = np.asarray(pd.to_numeric(reference_matched[feature], errors="coerce"), dtype=float)
        parsed_values = np.asarray(pd.to_numeric(parsed_matched[feature], errors="coerce"), dtype=float)
        valid = np.isfinite(ref_values) & np.isfinite(parsed_values)
        if not valid.any():
            excluded_non_numeric.append(feature)
            continue
        ref = ref_values[valid]
        got = parsed_values[valid]
        absolute_error = np.abs(ref - got)
        relative_error = absolute_error / np.maximum(np.maximum(np.abs(ref), np.abs(got)), np.finfo(float).eps)
        within_tolerance = absolute_error <= (absolute_tolerance + relative_tolerance * np.abs(ref))
        feature_results[feature] = {
            "matched_values": int(valid.sum()),
            "missing_or_non_finite": int((~valid).sum()),
            "median_absolute_error": float(np.median(absolute_error)),
            "p95_absolute_error": float(np.quantile(absolute_error, 0.95)),
            "median_symmetric_relative_error": float(np.median(relative_error)),
            "within_tolerance_ratio": float(np.mean(within_tolerance)),
        }

    matched_count = len(matched_keys)
    return {
        "match_rule": "unique bidirectional protocol + canonical endpoint/port tuple",
        "reference_rows": len(reference),
        "parsed_flows": len(parsed),
        "matched_unique_flows": matched_count,
        "ambiguous_reference_keys": sum(count != 1 for count in reference_counts.values()),
        "ambiguous_parsed_keys": sum(count != 1 for count in parsed_counts.values()),
        "unmatched_reference_keys": len(set(reference_counts) - set(parsed_counts)),
        "unmatched_parsed_keys": len(set(parsed_counts) - set(reference_counts)),
        "matched_reference_coverage": matched_count / max(1, len(reference)),
        "features_compared": feature_results,
        "excluded_non_numeric_features": excluded_non_numeric,
        "tolerances": {
            "absolute": absolute_tolerance,
            "relative_to_reference": relative_tolerance,
        },
        "limitations": [
            "A 5-tuple is not a unique flow identity when the same endpoints communicate repeatedly.",
            "Ambiguous or unmatched rows are excluded from feature error statistics.",
            "Forward/backward direction and flow timeout semantics may differ between extractors.",
            "Reconstructed features are not packet-truth labels and this comparison is not detector performance evidence.",
        ],
    }


def run_parity(reference_csv: str, capture_path: str, output_path: str, max_packets: int = 250_000) -> dict[str, Any]:
    reference = pd.read_csv(reference_csv, low_memory=False)
    with open(capture_path, "rb") as capture:
        parsed, _, packet_count = pcap_to_flows(capture, max_packets=max_packets)
    report = compare_feature_tables(reference, parsed)
    report["inputs"] = {
        "reference_csv": os.path.basename(reference_csv),
        "reference_sha256": _sha256_file(reference_csv),
        "capture_file": os.path.basename(capture_path),
        "capture_sha256": _sha256_file(capture_path),
        "packets_parsed": int(packet_count),
    }
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as destination:
        json.dump(report, destination, indent=2, allow_nan=False)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare reference flow features to a PCAP-derived table.")
    parser.add_argument("--reference-csv", required=True, help="Flow CSV exported from the same capture")
    parser.add_argument("--pcap", required=True, help="The exact PCAP/PCAPNG used to produce the reference CSV")
    parser.add_argument("--output", default="docs/FEATURE_PARITY_RESULTS.json")
    parser.add_argument("--max-packets", type=int, default=250_000)
    args = parser.parse_args()
    result = run_parity(args.reference_csv, args.pcap, args.output, args.max_packets)
    print(json.dumps({
        "matched_unique_flows": result["matched_unique_flows"],
        "reference_rows": result["reference_rows"],
        "features_compared": len(result["features_compared"]),
        "output": args.output,
    }, indent=2))
