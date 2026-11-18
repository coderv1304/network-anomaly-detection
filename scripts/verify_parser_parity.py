"""Verify the upload PCAP parser against the frozen serving schema.

The committed ``tests/fixtures/sample_synthetic.pcap`` contains one normal TCP
handshake and one 20-port SYN scan. This script parses it twice and reports:

* whether every frozen feature name is emitted (coverage, not equality with
  CICFlowMeter: the repository has no CICFlowMeter ground truth for this
  capture);
* whether any parsed value is NaN or infinite;
* whether two parses of the same bytes are identical;
* the per-flow flag/port facts the fixture was built to exercise.

A non-zero exit means the parser regressed. The bounds are documented in
``docs/LIVE_CAPTURE_OPERATIONS.md``.

Usage:
    venv/Scripts/python.exe scripts/verify_parser_parity.py
    venv/Scripts/python.exe scripts/verify_parser_parity.py --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys

import joblib
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from pcap_parser import dissect_pcap  # noqa: E402

DEFAULT_PCAP = os.path.join(PROJECT_ROOT, "tests", "fixtures", "sample_synthetic.pcap")
FEATURE_NAMES = os.path.join(PROJECT_ROOT, "models", "feature_names.pkl")

# The fixture expectation, not a claim about arbitrary captures.
EXPECTED_FLOWS = 21  # 20 scan flows + 1 handshake flow
EXPECTED_SCAN_PORTS = 20


def _parse(path: str):
    with open(path, "rb") as handle:
        return dissect_pcap(handle)


def _finite(frame) -> bool:
    numeric = frame.select_dtypes(include="number")
    return bool(np.isfinite(numeric.to_numpy(dtype=float)).all())


def _fingerprint(frame) -> str:
    digest = hashlib.sha256()
    for column in frame.columns:
        digest.update(str(column).encode("utf-8"))
        digest.update(frame[column].round(10).to_csv(index=False).encode("utf-8"))
    return digest.hexdigest()


def verify(path: str) -> dict:
    features = list(joblib.load(FEATURE_NAMES))
    frame, _, metadata = _parse(path)
    second, _, _ = _parse(path)

    parse_errors = []
    if not _finite(frame):
        parse_errors.append("parser emitted NaN or infinite feature values")
    missing = [name for name in features if name not in frame.columns]
    if missing:
        parse_errors.append(f"missing {len(missing)} frozen features: {missing[:5]}")
    if len(frame) != EXPECTED_FLOWS:
        parse_errors.append(
            f"expected {EXPECTED_FLOWS} flows for the fixture, parsed {len(frame)}"
        )
    if _fingerprint(frame) != _fingerprint(second):
        parse_errors.append("two parses of identical bytes disagreed")
    if metadata["frame_count"] != 25:
        parse_errors.append(f"expected 25 frames, read {metadata['frame_count']}")

    scan = frame[frame["Destination Port"].between(20, 39)]
    handshake = frame[(frame["Destination Port"] == 443) & (frame["Source Port"] == 54321)]
    if len(scan) != EXPECTED_SCAN_PORTS:
        parse_errors.append(f"expected {EXPECTED_SCAN_PORTS} scan flows, found {len(scan)}")
    elif int((scan["SYN Flag Count"] > 0).sum()) != EXPECTED_SCAN_PORTS:
        parse_errors.append("scan flows did not record SYN flags")
    if len(handshake) != 1:
        parse_errors.append(f"expected 1 handshake flow on port 443, found {len(handshake)}")
    elif int(handshake["ACK Flag Count"].iloc[0]) < 2:
        parse_errors.append("handshake flow did not record its ACK packets")

    return {
        "pcap": os.path.relpath(path, PROJECT_ROOT).replace("\\", "/"),
        "bytes": os.path.getsize(path),
        "frames": metadata["frame_count"],
        "flows": int(len(frame)),
        "columns": int(len(frame.columns)),
        "feature_names_required": len(features),
        "feature_names_emitted": len([name for name in features if name in frame.columns]),
        "nan_or_inf_values": 0 if _finite(frame) else -1,
        "deterministic_reparse": _fingerprint(frame) == _fingerprint(second),
        "scan_flows": int(len(scan)),
        "handshake_flows": int(len(handshake)),
        "errors": parse_errors,
        "ok": not parse_errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", default=DEFAULT_PCAP)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.pcap):
        print(f"Missing fixture: {args.pcap}", file=sys.stderr)
        return 1
    report = verify(args.pcap)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Parser parity: {'PASS' if report['ok'] else 'FAIL'}")
        print(f"  capture:            {report['pcap']} ({report['bytes']} bytes)")
        print(f"  frames / flows:     {report['frames']} / {report['flows']}")
        print(
            "  frozen features:    "
            f"{report['feature_names_emitted']}/{report['feature_names_required']} emitted"
        )
        print(f"  NaN/Inf values:     {report['nan_or_inf_values']}")
        print(f"  deterministic:      {report['deterministic_reparse']}")
        print(
            f"  scan / handshake:   {report['scan_flows']} / {report['handshake_flows']}"
        )
        for error in report["errors"]:
            print(f"  error: {error}", file=sys.stderr)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
