#!/usr/bin/env python
"""Audit the locally downloaded DistriNet-corrected CIC-IDS-2017 CSV release.

The corrected release is not a drop-in replacement for the original Kaggle CSVs:
column names, label strings, and the ``Attempted Category`` column differ. This
script records provenance and availability only. It does not train or score a
model and it does not change any label policy.

Example:
    venv/Scripts/python.exe scripts/audit_distrinet_cicids2017.py \
        --dir data/CICIDS2017_improved \
        --zip data/CICIDS2017_improved.zip
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from typing import Any

import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.rule_baselines import _sha256_file  # noqa: E402
from training.portable_features import PORTABLE_INPUT_COLUMNS  # noqa: E402

SOURCE_URL = (
    "https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/"
    "CICIDS2017_improved.zip"
)
CITATION = (
    "Liu, Engelen, Lynar, Essam, Joosen (2022), Error Prevalence in NIDS "
    "Datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018, IEEE CNS 2022."
)
LICENSE_NOTE = (
    "The DistriNet page requires citation. The Kaggle mirror (dhoogla/"
    "distrinetcicids2017) lists CC BY-NC-SA 4.0. Verify the current licence "
    "before redistributing the CSVs; this repository does not version them."
)

# Corrected-release column names for the frozen Tier A schema. Unlike the
# original Kaggle export, this release uses singular "Packet" names and
# includes both Fwd-specific and aggregate length columns.
CORRECTED_TIER_A_MAP = {
    "flow_duration": "Flow Duration",
    "total_fwd_packets": "Total Fwd Packet",
    "total_backward_packets": "Total Bwd packets",
    "total_length_of_fwd_packets": "Total Length of Fwd Packet",
    "total_length_of_bwd_packets": "Total Length of Bwd Packet",
    "flow_packets_s": "Flow Packets/s",
    "flow_bytes_s": "Flow Bytes/s",
    "packet_length_mean": "Packet Length Mean",
    "packet_length_max": "Packet Length Max",
    "syn_flag_count": "SYN Flag Count",
    "fin_flag_count": "FIN Flag Count",
    "rst_flag_count": "RST Flag Count",
}

CORRECTED_PORTABLE_MAP = {
    "total_fwd_packets": "Total Fwd Packet",
    "total_backward_packets": "Total Bwd packets",
    "total_length_of_fwd_packets": "Total Length of Fwd Packet",
    "total_length_of_bwd_packets": "Total Length of Bwd Packet",
}


def _read_headers(directory: str) -> tuple[list[str], list[str]]:
    files = sorted(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.lower().endswith(".csv")
    )
    if not files:
        raise FileNotFoundError(f"no CSV files in {directory}")
    columns = list(pd.read_csv(files[0], nrows=0).columns)
    return files, [str(column).strip().lstrip("\ufeff") for column in columns]


def audit(directory: str, zip_path: str | None, max_rows_per_file: int | None) -> dict[str, Any]:
    files, columns = _read_headers(directory)
    column_set = set(columns)

    mappings = {}
    for feature, source in CORRECTED_TIER_A_MAP.items():
        mappings[feature] = {
            "source_column": source,
            "present": source in column_set,
            "note": "" if source in column_set else "column absent in corrected header",
        }

    labels: Counter[str] = Counter()
    attempted: Counter[str] = Counter()
    missing = {source: 0 for source in CORRECTED_TIER_A_MAP.values()}
    file_rows = {}
    total_rows = 0
    for path in files:
        rows = 0
        for chunk in pd.read_csv(path, chunksize=250_000, low_memory=False):
            chunk.columns = [
                str(column).strip().lstrip("\ufeff") for column in chunk.columns
            ]
            if max_rows_per_file is not None:
                remaining = max_rows_per_file - rows
                if remaining <= 0:
                    break
                chunk = chunk.head(remaining)
            if chunk.empty:
                continue
            rows += len(chunk)
            labels.update(chunk["Label"].astype(str).tolist())
            if "Attempted Category" in chunk.columns:
                values = chunk["Attempted Category"].fillna("").astype(str).str.strip()
                attempted.update(values[values != ""].tolist())
            for feature, source in CORRECTED_TIER_A_MAP.items():
                if source in chunk.columns:
                    missing[source] += int(
                        pd.to_numeric(chunk[source], errors="coerce").isna().sum()
                    )
        file_rows[os.path.basename(path)] = rows
        total_rows += rows

    portable_available = sum(
        1
        for source in CORRECTED_PORTABLE_MAP.values()
        if source in column_set
    )
    tier_a_available = sum(
        1 for row in mappings.values() if row["present"]
    )

    payload = {
        "artifact_version": "distrinet-cicids2017-audit-v1",
        "source": {
            "url": SOURCE_URL,
            "citation": CITATION,
            "licence_note": LICENSE_NOTE,
            "zip_path": os.path.relpath(zip_path, PROJECT_ROOT).replace("\\", "/")
            if zip_path
            else None,
            "zip_sha256": _sha256_file(zip_path) if zip_path and os.path.isfile(zip_path) else None,
        },
        "directory": os.path.relpath(directory, PROJECT_ROOT).replace("\\", "/"),
        "files": {
            os.path.basename(path): {
                "bytes": os.path.getsize(path),
                "sha256": _sha256_file(path),
                "rows": file_rows[os.path.basename(path)],
            }
            for path in files
        },
        "rows": total_rows,
        "sample_limit_per_file": max_rows_per_file,
        "columns": columns,
        "column_count": len(columns),
        "label_counts": dict(sorted(labels.items())),
        "attempted_category_counts": dict(sorted(attempted.items())),
        "missing_values": missing,
        "tier_a": {
            "available": tier_a_available,
            "total": len(CORRECTED_TIER_A_MAP),
            "mapping": mappings,
        },
        "portable_inputs": {
            "available": portable_available,
            "total": len(PORTABLE_INPUT_COLUMNS),
            "mapping": CORRECTED_PORTABLE_MAP,
        },
        "notes": [
            "The corrected release uses singular 'Total Fwd Packet'/'Total Bwd packets' names, not the original Kaggle names.",
            "Label strings differ in case and spelling from the frozen POSITIVE_LABELS set; they require an explicit mapping before any supervised use.",
            "Attempted Category is a corrected-release column and is not part of the original label policy.",
            "This audit does not train, score, or tune a model.",
            "The release is consumed by scripts/corrected_label_sensitivity.py under the strict frozen policy; that is an in-distribution sensitivity (see docs/CORRECTED_LABEL_SENSITIVITY.md), not external validation.",
        ],
    }
    return payload


def render(payload: dict[str, Any]) -> str:
    lines = [
        "# DistriNet-Corrected CIC-IDS-2017 Dataset Audit",
        "",
        "**Status:** downloaded and inspected locally; used by the P3C strict-policy sensitivity run.",
        f"**Rows audited:** {payload['rows']:,}",
        f"**Files:** {len(payload['files'])}",
        f"**Source:** <{payload['source']['url']}>",
        "",
        "The corrected release is a different artifact from the original Kaggle",
        "CSV export used by the frozen training protocol. Column names, label",
        "strings, and an extra `Attempted Category` column differ. This audit",
        "records availability and provenance only; it does not change any model,",
        "threshold, or label policy.",
        "",
        "## Files",
        "",
        "| File | Bytes | Rows | SHA-256 |",
        "| --- | ---: | ---: | --- |",
    ]
    for name, row in payload["files"].items():
        lines.append(
            f"| `{name}` | {row['bytes']:,} | {row['rows']:,} | `{row['sha256']}` |"
        )
    lines.extend(
        [
            "",
            "## Schema availability",
            "",
            f"- Tier A: **{payload['tier_a']['available']}/"
            f"{payload['tier_a']['total']}** columns present after the corrected-name mapping.",
            f"- Portable inputs: **{payload['portable_inputs']['available']}/"
            f"{payload['portable_inputs']['total']}** present.",
            "",
            "| Tier A feature | Corrected column | Present |",
            "| --- | --- | --- |",
        ]
    )
    for feature, row in payload["tier_a"]["mapping"].items():
        lines.append(
            f"| `{feature}` | `{row['source_column']}` | "
            f"{'yes' if row['present'] else 'no'} |"
        )
    lines.extend(["", "## Label counts", "", "| Label | Rows |", "| --- | ---: |"])
    for label, count in payload["label_counts"].items():
        lines.append(f"| `{label}` | {count:,} |")
    lines.extend(
        [
            "",
            "## Provenance",
            "",
            f"- Citation: {payload['source']['citation']}",
            f"- Licence note: {payload['source']['licence_note']}",
            f"- Zip SHA-256: `{payload['source']['zip_sha256']}`"
            if payload["source"]["zip_sha256"]
            else "- Zip SHA-256: not recorded",
            "",
            "## Limits",
            "",
        ]
    )
    for note in payload["notes"]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", default="data/CICIDS2017_improved")
    parser.add_argument("--zip", default="data/CICIDS2017_improved.zip")
    parser.add_argument("--max-rows-per-file", type=int, default=None)
    parser.add_argument(
        "--output", default="docs/DISTRINET_CICIDS2017_AUDIT.json"
    )
    parser.add_argument(
        "--report", default="docs/DISTRINET_CICIDS2017_AUDIT.md"
    )
    args = parser.parse_args(argv)

    payload = audit(
        args.dir,
        args.zip if os.path.isfile(args.zip) else None,
        args.max_rows_per_file,
    )
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, allow_nan=False)
        handle.write("\n")
    with open(args.report, "w", encoding="utf-8") as handle:
        handle.write(render(payload))
        handle.write("\n")
    print(f"wrote {args.output}", flush=True)
    print(f"wrote {args.report}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
