#!/usr/bin/env python
"""CIDDS-002 scanning audit for the external PortScan evidence gap.

CIDDS-002 is a two-week, unidirectional NetFlow capture of an emulated small
business network. It is the only public dataset with explicit port-scan labels
and benign traffic in the same capture period, so it is the candidate source for
an independent scanning result.

This script does not train a model, write a registry row, or touch the serving
artifact. It records provenance, label mapping, duplicate policy, a
leakage-safe temporal split, and the family-coverage gate.

Examples:
    python scripts/cidds002_audit.py \
        --cidds-dir ~/Downloads/CIDDS-002 \
        --output docs/CIDDS002_AUDIT.json \
        --report docs/CIDDS002_AUDIT.md
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from typing import Any, Iterable

import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.p2b_protocol_analysis import (  # noqa: E402
    coverage_gate,
    family_day_matrix,
)
from scripts.rule_baselines import _sha256_file  # noqa: E402

ARTIFACT_VERSION = "cidds002-audit-v1"
DEFAULT_CIDDS_DIR = os.path.expanduser(os.path.join("~", "Downloads", "CIDDS-002"))
SERVING_ARTIFACT = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_day_based_seed42.pkl"
)

# The published CSV header. The audit fails loudly if the download changes shape.
EXPECTED_COLUMNS = [
    "Date first seen",
    "Duration",
    "Proto",
    "Src IP Addr",
    "Src Pt",
    "Dst IP Addr",
    "Dst Pt",
    "Packets",
    "Bytes",
    "Flows",
    "Flags",
    "Tos",
    "label",
    "attackType",
    "attackID",
    "attackDescription",
]

# NetFlow attributes that define a flow. Date first seen is part of the identity:
# CIDDS is unidirectional NetFlow and repeats legitimate flows with identical
# counters at different times. Deduplicating on counters alone would delete real
# traffic, so the key keeps the start timestamp.
FEATURE_COLUMNS = [
    "Duration",
    "Proto",
    "Src IP Addr",
    "Src Pt",
    "Dst IP Addr",
    "Dst Pt",
    "Packets",
    "Bytes",
    "Flows",
    "Flags",
    "Tos",
]
FLOW_KEY = ["Date first seen", *FEATURE_COLUMNS]
LABEL_COLUMNS = ["label", "attackType", "attackID", "attackDescription"]

# Label policy. The raw attackType value in this release is "scan", not
# "portScan", and the label column is normal/attacker/victim.
POSITIVE_LABELS = ("PortScan",)
NEGATIVE_LABELS = ("Normal",)
REQUIRED_FAMILIES = ("PortScan",)
PING_SWEEP_FAMILY = "PingSweep"
EXCLUDED_FAMILY = "Excluded"

FAMILY_CODES = {
    "Normal": 0,
    "PortScan": 1,
    PING_SWEEP_FAMILY: 2,
    EXCLUDED_FAMILY: 3,
}
CODE_FAMILIES = {code: name for name, code in FAMILY_CODES.items()}

SCAN_TYPE_CODES = {
    "None": 0,
    "SYN": 1,
    "ACK": 2,
    "FIN": 3,
    "UDP": 4,
    "PingSweep": 5,
    "Other": 6,
}
CODE_SCAN_TYPES = {code: name for name, code in SCAN_TYPE_CODES.items()}

# Temporal split. Week 1 is the training capture. Week 2 is cut at the end of
# the last validation attack (activityID 29) so a single nmap run is never split
# across validation and test.
TRAIN_END = pd.Timestamp("2017-08-09 00:00:00")
WEEK2_START = pd.Timestamp("2017-08-10 00:00:00")
VALIDATION_ATTACK_IDS = tuple(range(21, 30))
TEST_ATTACK_IDS = tuple(range(30, 44))

TIER_A_FEATURES = [
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
]

# Tier A is bidirectional by construction. CIDDS-002 is unidirectional NetFlow,
# so the backward columns cannot exist and the forward columns are not
# equivalents of a bidirectional CICFlowMeter flow.
CIDDS_TIER_A_MAP: dict[str, tuple[str | None, str, str]] = {
    "flow_duration": ("Duration", "rename", "seconds; multiply by 1e6 for microseconds"),
    "total_fwd_packets": ("Packets", "rename", "unidirectional; no backward counterpart"),
    "total_backward_packets": (None, "missing", "unidirectional capture"),
    "total_length_of_fwd_packets": ("Bytes", "rename", "unidirectional"),
    "total_length_of_bwd_packets": (None, "missing", "unidirectional capture"),
    "flow_packets_s": (None, "derive", "Packets / Duration; Duration > 0"),
    "flow_bytes_s": (None, "derive", "Bytes / Duration; Duration > 0"),
    "packet_length_mean": (None, "derive", "Bytes / Packets; Packets > 0"),
    "packet_length_max": (None, "missing", "no packet length column"),
    "syn_flag_count": (None, "derive", "Flags contains 'S'"),
    "fin_flag_count": (None, "derive", "Flags contains 'F'"),
    "rst_flag_count": (None, "derive", "Flags contains 'R'"),
}


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def normalize_text(value: Any) -> str:
    if pd.isna(value):
        return ""
    return " ".join(str(value).split())


def scan_type(description: Any) -> str:
    """Map an nmap argument string to a scan family."""
    text = normalize_text(description)
    if not text or text == "---":
        return "None"
    if "-sP" in text:
        return "PingSweep"
    if "-sS" in text:
        return "SYN"
    if "-sA" in text:
        return "ACK"
    if "-sF" in text:
        return "FIN"
    if "-sU" in text:
        return "UDP"
    return "Other"


def row_family(label: Any, attack_type: Any, description: Any) -> str:
    """Return the canonical family for one row.

    ``normal`` is benign. An ``attacker`` flow during a scan is a scan flow.
    A ``victim`` flow is the target's response and is excluded: it is not scan
    traffic, and treating it as benign would put response traffic into the
    false-positive base.
    """
    label_text = normalize_text(label).lower()
    if label_text == "normal":
        return "Normal"
    if label_text == "attacker" and normalize_text(attack_type).lower() == "scan":
        return PING_SWEEP_FAMILY if scan_type(description) == "PingSweep" else "PortScan"
    return EXCLUDED_FAMILY


def _counts_by(partitions: np.ndarray, families: np.ndarray) -> dict[str, dict[str, int]]:
    names = {0: "train", 1: "validation", 2: "test"}
    keep = (partitions >= 0) & (families != FAMILY_CODES[EXCLUDED_FAMILY])
    combo = partitions[keep].astype(np.int64) * 8 + families[keep].astype(np.int64)
    codes, counts = np.unique(combo, return_counts=True)
    result: dict[str, dict[str, int]] = {name: {} for name in names.values()}
    for code, count in zip(codes, counts):
        part_code, family_code = divmod(int(code), 8)
        result[names[part_code]][CODE_FAMILIES[family_code]] = int(count)
    return result


def _scan_type_counts(
    partitions: np.ndarray, families: np.ndarray, scan_codes: np.ndarray
) -> dict[str, dict[str, int]]:
    names = {0: "train", 1: "validation", 2: "test"}
    keep = (partitions >= 0) & (families == FAMILY_CODES["PortScan"])
    combo = partitions[keep].astype(np.int64) * 16 + scan_codes[keep].astype(np.int64)
    codes, counts = np.unique(combo, return_counts=True)
    result: dict[str, dict[str, int]] = {name: {} for name in names.values()}
    for code, count in zip(codes, counts):
        part_code, scan_code = divmod(int(code), 16)
        name = CODE_SCAN_TYPES[scan_code]
        result[names[part_code]][name] = int(count)
    return result


def _schema_audit(mapping: dict[str, tuple]) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    for feature in TIER_A_FEATURES:
        source, status, note = mapping[feature]
        rows[feature] = {
            "status": status,
            "source_column": source,
            "present": bool(source),
            "note": note,
        }
    return {
        "features": rows,
        "available": sum(1 for row in rows.values() if row["status"] in {"rename", "derive"}),
        "missing": sum(1 for row in rows.values() if row["status"] == "missing"),
        "total": len(TIER_A_FEATURES),
    }


def _first_existing(directory: str, names: Iterable[str]) -> str:
    for name in names:
        path = os.path.join(directory, name)
        if os.path.exists(path):
            return path
    raise FileNotFoundError(f"none of {list(names)} exists in {directory}")


def _locate(directory: str) -> tuple[str, str, str, str]:
    """Resolve the traffic and attack-log paths, accepting one nested folder."""
    root = directory
    if not os.path.isdir(os.path.join(root, "traffic")):
        nested = os.path.join(root, "CIDDS-002")
        if os.path.isdir(os.path.join(nested, "traffic")):
            root = nested
    traffic = os.path.join(root, "traffic")
    logs = os.path.join(root, "attack_logs")
    return (
        root,
        _first_existing(traffic, ["week1.csv"]),
        _first_existing(traffic, ["week2.csv"]),
        _first_existing(logs, ["attacks_logs_intern.csv", "attack_logs_intern.csv"]),
    )


def _read_attack_log(path: str) -> pd.DataFrame:
    log = pd.read_csv(path)
    log.columns = [str(column).strip().lstrip("\ufeff") for column in log.columns]
    for column in ("start", "end"):
        log[column] = pd.to_datetime(log[column], errors="coerce")
    log["activityID"] = pd.to_numeric(log["activityID"], errors="coerce")
    return log


def _file_identity(path: str, rows: int, columns: Iterable[str]) -> dict[str, Any]:
    return {
        "path": path,
        "sha256": _sha256_file(path),
        "bytes": os.path.getsize(path),
        "rows": int(rows),
        "columns": len(list(columns)),
    }


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
def audit_cidds(directory: str, chunksize: int = 400_000) -> dict[str, Any]:
    root, week1_path, week2_path, log_path = _locate(directory)
    log = _read_attack_log(log_path)

    if len(log) != 43:
        raise ValueError(f"expected 43 attack-log rows, found {len(log)}")
    if set(log["activityID"]) != set(range(1, 44)):
        raise ValueError("attack log activityIDs are not exactly 1..43")

    validation_attacks = log[log["activityID"].isin(VALIDATION_ATTACK_IDS)]
    if validation_attacks.empty:
        raise ValueError("no validation attacks found in the attack log")
    boundary = validation_attacks["end"].max()

    hashes: list[np.ndarray] = []
    feature_hashes: list[np.ndarray] = []
    partitions: list[np.ndarray] = []
    families: list[np.ndarray] = []
    scan_codes: list[np.ndarray] = []
    attack_ids: list[np.ndarray] = []
    day_counts: collections.Counter[str] = collections.Counter()
    raw_rows = malformed = 0
    columns: list[str] = []
    per_file_rows: dict[str, int] = {}

    for path in (week1_path, week2_path):
        file_rows = 0
        for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
            chunk.columns = [
                str(column).strip().lstrip("\ufeff") for column in chunk.columns
            ]
            if not columns:
                columns = list(chunk.columns)
            missing = [column for column in EXPECTED_COLUMNS if column not in chunk.columns]
            if missing:
                raise KeyError(f"{os.path.basename(path)} is missing columns: {missing}")
            file_rows += len(chunk)
            raw_rows += len(chunk)

            stamps = pd.to_datetime(chunk["Date first seen"], errors="coerce")
            malformed += int(stamps.isna().sum())
            day_counts.update(
                stamps.dt.strftime("%Y-%m-%d").fillna("NaT").value_counts().to_dict()
            )

            stamp_values = stamps.to_numpy()
            partition = np.full(len(chunk), -1, dtype=np.int8)
            valid = ~pd.isna(stamp_values)
            partition[valid] = np.where(
                stamp_values[valid] < TRAIN_END.to_datetime64(),
                0,
                np.where(stamp_values[valid] <= boundary.to_datetime64(), 1, 2),
            )

            labels = chunk["label"].astype(str).str.strip().str.lower()
            attack_types = chunk["attackType"].astype(str).str.strip().str.lower()
            scan_names = chunk["attackDescription"].map(scan_type)

            family = np.full(len(chunk), FAMILY_CODES[EXCLUDED_FAMILY], dtype=np.int8)
            is_normal = (labels == "normal").to_numpy()
            is_scan = (
                (labels == "attacker") & (attack_types == "scan")
            ).to_numpy()
            is_ping = (scan_names == "PingSweep").to_numpy()
            family[is_normal] = FAMILY_CODES["Normal"]
            family[is_scan & ~is_ping] = FAMILY_CODES["PortScan"]
            family[is_scan & is_ping] = FAMILY_CODES[PING_SWEEP_FAMILY]

            scan_code = np.zeros(len(chunk), dtype=np.int8)
            for name, code in SCAN_TYPE_CODES.items():
                if name == "None":
                    continue
                scan_code[(scan_names == name).to_numpy()] = code

            ids = pd.to_numeric(chunk["attackID"], errors="coerce")
            ids = ids.fillna(0).astype(np.int16).to_numpy()

            key = chunk[FLOW_KEY].astype(str)
            feature_key = chunk[FEATURE_COLUMNS].astype(str)

            hashes.append(
                pd.util.hash_pandas_object(key, index=False)
                .astype("uint64")
                .to_numpy()
            )
            feature_hashes.append(
                pd.util.hash_pandas_object(feature_key, index=False)
                .astype("uint64")
                .to_numpy()
            )
            partitions.append(partition)
            families.append(family)
            scan_codes.append(scan_code)
            attack_ids.append(ids)
        per_file_rows[path] = file_rows

    hashes_array = np.concatenate(hashes)
    feature_hashes_array = np.concatenate(feature_hashes)
    partitions_array = np.concatenate(partitions)
    families_array = np.concatenate(families)
    scan_array = np.concatenate(scan_codes)
    attack_array = np.concatenate(attack_ids)

    unique_hashes, first = np.unique(hashes_array, return_index=True)
    duplicate_rows = int(len(hashes_array) - len(unique_hashes))
    partitions_unique = partitions_array[first]
    families_unique = families_array[first]
    scan_unique = scan_array[first]
    attack_unique = attack_array[first]

    # Feature-only duplicates are reported, never removed: the same 5-tuple and
    # counters recur legitimately across days in a NetFlow capture.
    feature_only_duplicates = int(
        len(feature_hashes_array) - len(np.unique(feature_hashes_array))
    )

    # Same flow key, inconsistent family.
    order = np.lexsort((families_array, hashes_array))
    ordered_hashes = hashes_array[order]
    ordered_families = families_array[order]
    same = ordered_hashes[1:] == ordered_hashes[:-1]
    conflict = same & (ordered_families[1:] != ordered_families[:-1])
    conflicting_groups = int(np.unique(ordered_hashes[1:][conflict]).size)

    counts = _counts_by(partitions_unique, families_unique)
    scan_counts = _scan_type_counts(partitions_unique, families_unique, scan_unique)
    matrix = family_day_matrix(
        counts["train"],
        counts["validation"],
        counts["test"],
        positive_labels=POSITIVE_LABELS,
    )
    gate = coverage_gate(
        matrix,
        positive_labels=POSITIVE_LABELS,
        required_families=REQUIRED_FAMILIES,
    )

    def _partition_payload(name: str) -> dict[str, Any]:
        part_counts = counts[name]
        positives = sum(part_counts.get(label, 0) for label in POSITIVE_LABELS)
        return {
            "rows": int((partitions_unique == {"train": 0, "validation": 1, "test": 2}[name]).sum()),
            "label_counts": dict(sorted(part_counts.items())),
            "positive_rows": int(positives),
            "positive_families": sorted(
                label for label in part_counts if label in POSITIVE_LABELS
            ),
            "scan_types": dict(sorted(scan_counts[name].items())),
        }

    attack_flows: dict[str, int] = {}
    ids, id_counts = np.unique(attack_unique[attack_unique > 0], return_counts=True)
    for attack_id, count in zip(ids, id_counts):
        attack_flows[str(int(attack_id))] = int(count)

    scan_log = log.copy()
    scan_log["scan_type"] = scan_log["description"].map(scan_type)
    attack_table = [
        {
            "activity_id": int(row.activityID),
            "start": row.start.isoformat() if pd.notna(row.start) else None,
            "end": row.end.isoformat() if pd.notna(row.end) else None,
            "nmap_args": normalize_text(row.description),
            "scan_type": row.scan_type,
            "partition": (
                "validation"
                if int(row.activityID) in VALIDATION_ATTACK_IDS
                else "test"
                if int(row.activityID) in TEST_ATTACK_IDS
                else "train"
            ),
            "attacker_flows": attack_flows.get(str(int(row.activityID)), 0),
        }
        for row in scan_log.itertuples(index=False)
    ]

    return {
        "status": "coverage_pass" if gate["overall_pass"] else "coverage_fail",
        "provenance": {
            "directory": root,
            "files": [
                _file_identity(week1_path, per_file_rows[week1_path], columns),
                _file_identity(week2_path, per_file_rows[week2_path], columns),
                _file_identity(log_path, len(log), log.columns),
            ],
            "official_source": (
                "https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/"
            ),
            "citation": (
                "Ring, Wunderlich, Scheuring, Landes, Hotho (2017), "
                "Creation of Flow-Based Data Sets for Intrusion Detection, "
                "Journal of Information Warfare 16(4)."
            ),
            "licence_status": (
                "not recorded; verify the official terms and citation before publication"
            ),
            "release_note": (
                "CIDDS-002 is unidirectional NetFlow. It is a separate scanning "
                "study, not a Tier A validation of the bidirectional CIC model."
            ),
        },
        "label_policy": {
            "raw_label_values": {"normal": "benign", "attacker": "scan source", "victim": "scan target"},
            "raw_attack_type_values": ["---", "scan"],
            "positive_labels": list(POSITIVE_LABELS),
            "negative_labels": list(NEGATIVE_LABELS),
            "required_families": list(REQUIRED_FAMILIES),
            "ping_sweep_policy": (
                "excluded from the PortScan family; nmap -sP -PE is host discovery, "
                "not a port scan"
            ),
            "victim_policy": (
                "excluded: a victim flow is the target's response to a scan, not scan "
                "traffic, and must not enter the benign base"
            ),
            "family_mapping": {
                "Normal": "label == normal",
                "PortScan": "label == attacker, attackType == scan, nmap scan is -sS/-sA/-sF/-sU",
                PING_SWEEP_FAMILY: "label == attacker, attackType == scan, nmap args contain -sP",
                EXCLUDED_FAMILY: "victim flows and every other label",
            },
        },
        "rows": {
            "raw": int(raw_rows),
            "unique_flow_keys": int(len(unique_hashes)),
            "duplicate_rows": duplicate_rows,
            "feature_only_duplicates_not_removed": feature_only_duplicates,
            "conflicting_duplicate_groups": conflicting_groups,
            "malformed_timestamps": int(malformed),
        },
        "duplicate_policy": (
            "Duplicate keys are Date first seen plus the 11 NetFlow attributes. "
            "The start timestamp is part of the identity: the same 5-tuple and "
            "counters recur across days, so feature-only deduplication would delete "
            "real traffic and distort prevalence. Feature-only duplicates are "
            "reported but kept."
        ),
        "capture_days": sorted(day for day in day_counts if day != "NaT"),
        "rows_per_day": {
            day: int(day_counts[day]) for day in sorted(day_counts) if day != "NaT"
        },
        "temporal_split": {
            "method": (
                "temporal_capture_split: week1 train; week2 validation up to the end "
                "of activityID 29; week2 test after it. A whole nmap run stays in one "
                "partition."
            ),
            "train_window": ["2017-08-02", "2017-08-08"],
            "validation_window": ["2017-08-10", boundary.isoformat()],
            "test_window": [boundary.isoformat(), "2017-08-16"],
            "validation_attack_ids": list(VALIDATION_ATTACK_IDS),
            "test_attack_ids": list(TEST_ATTACK_IDS),
            "boundary": boundary.isoformat(),
            "partitions": {
                name: _partition_payload(name)
                for name in ("train", "validation", "test")
            },
            "family_partition_matrix": matrix,
            "coverage_gate": gate,
        },
        "attacks": attack_table,
        "attack_flow_totals": attack_flows,
        "schema": _schema_audit(CIDDS_TIER_A_MAP),
    }


# ---------------------------------------------------------------------------
# Findings and rendering
# ---------------------------------------------------------------------------
def _share(counts: dict[str, int], key: str) -> float:
    total = sum(counts.values())
    return 100.0 * counts.get(key, 0) / total if total else 0.0


def build_findings(payload: dict[str, Any]) -> list[str]:
    cidds = payload["audit"]
    split = cidds["temporal_split"]
    gate = split["coverage_gate"]
    parts = split["partitions"]
    rows = cidds["rows"]
    return [
        (
            "CIDDS-002 contains "
            f"{rows['raw']:,} raw flow records across "
            f"{len(cidds['capture_days'])} capture days, and "
            f"{rows['unique_flow_keys']:,} unique flow keys after removing "
            f"{rows['duplicate_rows']:,} exact duplicate records."
        ),
        (
            "CIDDS-002 is the only public dataset in this review with explicit "
            "port-scan labels and benign traffic in the same capture period: "
            f"{parts['train']['positive_rows']:,} train, "
            f"{parts['validation']['positive_rows']:,} validation, and "
            f"{parts['test']['positive_rows']:,} test PortScan flows. "
            f"The coverage gate is {'PASS' if gate['overall_pass'] else 'FAIL'}."
        ),
        (
            "The raw attackType value is 'scan', not 'portScan'. The family mapping "
            "uses label=attacker plus attackType=scan, and splits ping sweeps "
            "(nmap -sP -PE) out of the PortScan family because they are host "
            "discovery, not port scanning."
        ),
        (
            "Victim flows are excluded, not treated as benign. They are the target's "
            "responses to a scan, and putting them in the benign base would distort "
            "the false-positive rate at low alert budgets."
        ),
        (
            "Duplicate policy differs from CIC-IDS-2018 on purpose. CIDDS-002 is "
            "unidirectional NetFlow, so Date first seen is part of the flow identity: "
            f"{rows['feature_only_duplicates_not_removed']:,} feature-only duplicates "
            "are reported but kept. Removing them would delete legitimate repeated "
            "traffic and change prevalence."
        ),
        (
            f"Only {cidds['schema']['available']}/{cidds['schema']['total']} Tier A "
            f"features are available and {cidds['schema']['missing']} are missing. "
            "The missing ones are the backward counters and packet_length_max, which "
            "cannot exist in a unidirectional NetFlow record. This dataset cannot "
            "validate the bidirectional serving model; it supports a separate "
            "scanning study."
        ),
        (
            "The validation/test boundary is the end of activityID 29, not midnight. "
            "Cutting at midnight would split one nmap run across two partitions."
        ),
        (
            "The temporal split also shifts the scan-type mix. UDP is "
            f"{_share(parts['train']['scan_types'], 'UDP'):.1f}% of train PortScan flows "
            f"but {_share(parts['test']['scan_types'], 'UDP'):.1f}% of test, while ACK "
            f"falls from {_share(parts['train']['scan_types'], 'ACK'):.1f}% to "
            f"{_share(parts['test']['scan_types'], 'ACK'):.1f}%. A PortScan result on this "
            "split is partly a scan-type generalization test, not a uniform port-scan "
            "benchmark."
        ),
    ]


def build_payload(directory: str) -> dict[str, Any]:
    cidds = audit_cidds(directory)
    payload: dict[str, Any] = {
        "artifact_version": ARTIFACT_VERSION,
        "method": "cidds002_scanning_ingestion_and_coverage_audit",
        "scope": (
            "Flow-based detector for volumetric and scanning behavior. "
            "Not a general NIDS. Botnet, web attacks, infiltration, zero-day, "
            "and blocking are out of scope."
        ),
        "dataset": "cidds002",
        "audit": cidds,
        "decision": {
            "p2b_status": "blocked",
            "cidds002_verdict": (
                "usable for a separate, leakage-safe, temporal scanning study with "
                "explicit port-scan labels. It is unidirectional NetFlow and cannot "
                "validate the bidirectional Tier A serving model."
            ),
            "training_authorized": False,
            "reason": (
                "The audit records feasibility and a candidate split. It does not "
                "authorize a fit, a threshold change, or a registry row."
            ),
        },
        "artifact_identity": {
            "serving_artifact": os.path.relpath(SERVING_ARTIFACT, PROJECT_ROOT).replace("\\", "/"),
            "serving_sha256": _sha256_file(SERVING_ARTIFACT)
            if os.path.exists(SERVING_ARTIFACT)
            else None,
            "pandas_version": pd.__version__,
        },
        "notes": [
            "No model is trained, no registry row is written, and the serving artifact is untouched.",
            "CIDDS-002 is unidirectional NetFlow; it is not a Tier A dataset.",
            "The split is temporal and keeps each nmap run in one partition.",
            "Source URL, citation, and licence must be verified before publication.",
        ],
    }
    payload["findings"] = build_findings(payload)
    return payload


def _fmt(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) else str(value)


def render_markdown(payload: dict[str, Any]) -> str:
    cidds = payload["audit"]
    split = cidds["temporal_split"]
    gate = split["coverage_gate"]
    parts = split["partitions"]
    lines: list[str] = []
    lines.append("# CIDDS-002 Scanning Audit")
    lines.append("")
    lines.append("**Status:** **BLOCKED for training** — the audit records feasibility, not a validated fit.")
    lines.append("**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.")
    lines.append("**Artifact:** [`CIDDS002_AUDIT.json`](CIDDS002_AUDIT.json).")
    lines.append("**Reproduction:** [`../scripts/cidds002_audit.py`](../scripts/cidds002_audit.py).")
    lines.append("")
    lines.append("This audit answers whether CIDDS-002 can supply a leakage-safe temporal")
    lines.append("split in which the PortScan family appears in train, validation, and test.")
    lines.append("It does not train a model, write a registry row, or change the serving")
    lines.append("artifact.")
    lines.append("")
    lines.append("## 1. Dataset")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Status | **{cidds['status']}** |")
    lines.append(f"| Official source | {cidds['provenance']['official_source']} |")
    lines.append(f"| Citation | {cidds['provenance']['citation']} |")
    lines.append(f"| Licence | {cidds['provenance']['licence_status']} |")
    lines.append("| Format | Unidirectional NetFlow |")
    lines.append(f"| Raw rows | {_fmt(cidds['rows']['raw'])} |")
    lines.append(f"| Unique flow keys | {_fmt(cidds['rows']['unique_flow_keys'])} |")
    lines.append(f"| Duplicate records removed | {_fmt(cidds['rows']['duplicate_rows'])} |")
    lines.append(
        f"| Feature-only duplicates kept | {_fmt(cidds['rows']['feature_only_duplicates_not_removed'])} |"
    )
    lines.append(f"| Conflicting duplicate groups | {_fmt(cidds['rows']['conflicting_duplicate_groups'])} |")
    lines.append(f"| Capture days | {len(cidds['capture_days'])} |")
    lines.append("")
    lines.append("### Files")
    lines.append("")
    lines.append("| File | Rows | Columns | SHA-256 |")
    lines.append("| --- | ---: | ---: | --- |")
    for item in cidds["provenance"]["files"]:
        lines.append(
            f"| {os.path.basename(item['path'])} | {_fmt(item['rows'])} | "
            f"{item['columns']} | `{item['sha256'][:16]}…` |"
        )
    lines.append("")
    lines.append("### Rows per capture day")
    lines.append("")
    lines.append("| Day | Rows |")
    lines.append("| --- | ---: |")
    for day, count in cidds["rows_per_day"].items():
        lines.append(f"| {day} | {_fmt(count)} |")
    lines.append("")
    lines.append("No traffic was captured on 2017-08-09; the two week files do not")
    lines.append("overlap and there is a full-day gap between train and validation.")
    lines.append("")
    lines.append("## 2. Label policy")
    lines.append("")
    lines.append("| Raw value | Meaning | Treatment |")
    lines.append("| --- | --- | --- |")
    lines.append("| `label=normal` | benign | negative |")
    lines.append("| `label=attacker`, `attackType=scan` | scan source | **PortScan** (or PingSweep) |")
    lines.append("| `label=victim` | scan target response | excluded |")
    lines.append("")
    lines.append("The raw `attackType` value is `scan`, not `portScan`. Ping sweeps")
    lines.append("(`nmap -sP -PE`) are host discovery and are split out of the PortScan")
    lines.append("family. Victim flows are excluded rather than treated as benign, so")
    lines.append("response traffic cannot inflate the false-positive base.")
    lines.append("")
    lines.append("## 3. Duplicate policy")
    lines.append("")
    lines.append(cidds["duplicate_policy"])
    lines.append("")
    lines.append("## 4. Temporal split")
    lines.append("")
    lines.append(f"**Status: {cidds['status']}**")
    lines.append("")
    lines.append(f"- Train: {split['train_window'][0]} to {split['train_window'][1]} (week 1)")
    lines.append(
        f"- Validation: {split['validation_window'][0]} to {split['validation_window'][1]}"
    )
    lines.append(f"- Test: {split['test_window'][0]} to {split['test_window'][1]}")
    lines.append("")
    lines.append(f"The boundary is the end of activityID 29 (`{split['boundary']}`).")
    lines.append("Cutting at midnight would split one nmap run across validation and test.")
    lines.append("")
    lines.append("| Partition | Rows | PortScan flows | Normal | PingSweep |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for name in ("train", "validation", "test"):
        part = parts[name]
        counts = part["label_counts"]
        lines.append(
            f"| {name} | {_fmt(part['rows'])} | {_fmt(counts.get('PortScan', 0))} | "
            f"{_fmt(counts.get('Normal', 0))} | {_fmt(counts.get('PingSweep', 0))} |"
        )
    lines.append("")
    lines.append("### Coverage gate")
    lines.append("")
    lines.append(f"**Overall: {'PASS' if gate['overall_pass'] else 'FAIL'}**")
    lines.append("")
    lines.append("| Family | Train | Validation | Test | Pass |")
    lines.append("| --- | ---: | ---: | ---: | --- |")
    for family, row in gate["families"].items():
        lines.append(
            f"| {family} | {_fmt(row['train'])} | {_fmt(row['validation'])} | "
            f"{_fmt(row['test'])} | {row['pass']} |"
        )
    lines.append("")
    lines.append(gate["reason"])
    lines.append("")
    lines.append("### Port-scan types")
    lines.append("")
    types = ["SYN", "ACK", "FIN", "UDP", "Other"]
    lines.append("| Partition | " + " | ".join(types) + " |")
    lines.append("| --- | " + " | ".join("---:" for _ in types) + " |")
    for name in ("train", "validation", "test"):
        counts = parts[name]["scan_types"]
        lines.append(
            f"| {name} | "
            + " | ".join(_fmt(counts.get(scan, 0)) for scan in types)
            + " |"
        )
    lines.append("")
    lines.append("## 5. Attacks")
    lines.append("")
    lines.append("| ID | Partition | nmap args | Type | Attacker flows |")
    lines.append("| ---: | --- | --- | --- | ---: |")
    for attack in cidds["attacks"]:
        lines.append(
            f"| {attack['activity_id']} | {attack['partition']} | "
            f"`{attack['nmap_args']}` | {attack['scan_type']} | "
            f"{_fmt(attack['attacker_flows'])} |"
        )
    lines.append("")
    lines.append("## 6. Tier A schema")
    lines.append("")
    lines.append(
        f"{cidds['schema']['available']}/{cidds['schema']['total']} features available; "
        f"{cidds['schema']['missing']} missing."
    )
    lines.append("")
    lines.append("| Feature | Status | Source | Note |")
    lines.append("| --- | --- | --- | --- |")
    for feature, row in cidds["schema"]["features"].items():
        lines.append(
            f"| `{feature}` | {row['status']} | {row['source_column'] or '—'} | "
            f"{row['note'] or '—'} |"
        )
    lines.append("")
    lines.append("The missing features are structural, not an ingestion gap: a")
    lines.append("unidirectional NetFlow record has no backward counters and no packet")
    lines.append("length maximum. CIDDS-002 therefore supports a separate scanning study,")
    lines.append("not a validation of the bidirectional serving model.")
    lines.append("")
    lines.append("## 7. Candidate shortlist")
    lines.append("")
    lines.append("| Dataset | PortScan labels | Tier A | Verdict |")
    lines.append("| --- | --- | --- | --- |")
    lines.append(
        "| **CIDDS-002** | explicit (`label=attacker`, `attackType=scan`) | "
        "no (unidirectional NetFlow) | **selected for a separate scanning study** |"
    )
    lines.append(
        "| CIC-IDS-2017 Friday afternoon | explicit `PortScan` | yes (80 CICFlowMeter "
        "features) | in-domain source; A1f zero-shot only, because PortScan exists only "
        "on the test day |"
    )
    lines.append(
        "| CIDDS-001 | explicit (`AttackType=portScan`) | no | rejected: port scans only "
        "in weeks 1-2 and mixed with DoS/brute force; CIDDS-002 is purpose-built |"
    )
    lines.append(
        "| CIC-DDoS2019 | none | n/a | rejected: its own taxonomy classifies `PORTMAP` "
        "as a reflection/amplification DDoS subtype, there is no scanning branch, and "
        "the release has no benign flows |"
    )
    lines.append(
        "| BCCC-CSE-CIC-IDS2018 | unverified | yes | rejected: a re-release of the same "
        "2018 capture that contains no PortScan, and not an independent collection |"
    )
    lines.append(
        "| UNSW-NB15 | no (`Reconnaissance` only) | partial (8/12) | external scanning "
        "proxy, not a PortScan label |"
    )
    lines.append("")
    lines.append("## 8. Decision")
    lines.append("")
    lines.append(f"- **CIDDS-002:** {payload['decision']['cidds002_verdict'].rstrip('.')}.")
    lines.append("- **Training authorized:** no.")
    lines.append("- **P2B status:** blocked.")
    lines.append("")
    lines.append("## 9. Findings")
    lines.append("")
    for finding in payload["findings"]:
        lines.append(f"- {finding}")
    lines.append("")
    lines.append("## 10. What does not change")
    lines.append("")
    lines.append("- Serving artifact and threshold: unchanged.")
    lines.append("- Detection **4/10**, SaaS **3/10**, overall **4.5/10**.")
    lines.append("- Scope: volumetric/scanning only; no blocking, botnet, web-attack,")
    lines.append("  infiltration, zero-day, general NIDS, or production-readiness claim.")
    lines.append("- Tier B fan-out remains unavailable.")
    lines.append("")
    lines.append("## 11. Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append("venv/Scripts/python.exe scripts/cidds002_audit.py \\")
    lines.append("  --cidds-dir ~/Downloads/CIDDS-002 \\")
    lines.append("  --output docs/CIDDS002_AUDIT.json \\")
    lines.append("  --report docs/CIDDS002_AUDIT.md")
    lines.append("venv/Scripts/python.exe -m pytest tests/test_cidds002_audit.py -q")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def run(directory: str, output: str, report: str) -> dict[str, Any]:
    payload = build_payload(directory)
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, allow_nan=False)
        handle.write("\n")
    with open(report, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(payload))
        handle.write("\n")
    print(f"wrote {output}", flush=True)
    print(f"wrote {report}", flush=True)
    return payload


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cidds-dir", default=DEFAULT_CIDDS_DIR)
    parser.add_argument("--output", default="docs/CIDDS002_AUDIT.json")
    parser.add_argument("--report", default="docs/CIDDS002_AUDIT.md")
    args = parser.parse_args(list(argv) if argv is not None else None)
    run(args.cidds_dir, args.output, args.report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
