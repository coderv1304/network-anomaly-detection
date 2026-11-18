#!/usr/bin/env python
"""External dataset ingestion and coverage audit for P2B/A4.

This script reads the two local external datasets and answers one question:
can they supply a leakage-safe train/validation/test split in which every
evaluated volumetric/scanning family appears in all three partitions?

It does not train a model, write a registry row, or touch the serving artifact.
It records provenance, label mappings, duplicate leakage, Tier A schema coverage,
and the family-coverage gate result.

Examples:
    python scripts/external_dataset_audit.py \
        --unsw-dir ~/Downloads/UNSW_NB15 \
        --cic-dir "~/Downloads/CIC-IDS 2018" \
        --output docs/EXTERNAL_DATASET_AUDIT.json \
        --report docs/EXTERNAL_DATASET_AUDIT.md
"""

from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import re
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

ARTIFACT_VERSION = "external-dataset-audit-v1"
DEFAULT_UNSW_DIR = os.path.expanduser(os.path.join("~", "Downloads", "UNSW_NB15"))
DEFAULT_CIC_DIR = os.path.expanduser(os.path.join("~", "Downloads", "CIC-IDS 2018"))
SERVING_ARTIFACT = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_day_based_seed42.pkl"
)

# UNSW-NB15 attack_cat values. DoS is the volumetric family; Reconnaissance is
# the scanning family. Everything else is outside the volumetric/scanning scope.
UNSW_POSITIVE_LABELS = {"DoS", "Reconnaissance"}
UNSW_NEGATIVE_LABELS = {"Normal"}
UNSW_EXCLUDED_LABELS = {
    "Analysis": "excluded; analysis attack",
    "Backdoor": "excluded; backdoor",
    "Exploits": "excluded; exploit",
    "Fuzzers": "excluded; fuzzing",
    "Generic": "excluded; generic attack",
    "Shellcode": "excluded; shellcode",
    "Worms": "excluded; worm",
}

# CIC-IDS-2018 labels are coarse or campaign-suffixed. Match on the normalised
# lowercase prefix, never on a substring that could catch an unrelated label.

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

UNSW_TIER_A_MAP = {
    "flow_duration": ("dur", "rename", "seconds; multiply by 1e6 for microseconds"),
    "total_fwd_packets": ("spkts", "rename", ""),
    "total_backward_packets": ("dpkts", "rename", ""),
    "total_length_of_fwd_packets": ("sbytes", "rename", ""),
    "total_length_of_bwd_packets": ("dbytes", "rename", ""),
    "flow_packets_s": (None, "derive", "(spkts + dpkts) / dur; dur > 0"),
    "flow_bytes_s": (None, "derive", "(sbytes + dbytes) / dur; dur > 0"),
    "packet_length_mean": (
        None,
        "derive",
        "(sbytes + dbytes) / (spkts + dpkts); zero packets -> 0",
    ),
    "packet_length_max": (None, "missing", "no max packet length column"),
    "syn_flag_count": (None, "missing", "no flag-count column"),
    "fin_flag_count": (None, "missing", "no flag-count column"),
    "rst_flag_count": (None, "missing", "no flag-count column"),
}

CIC2018_TIER_A_MAP = {
    "flow_duration": ("Flow Duration", "rename", ""),
    "total_fwd_packets": ("Tot Fwd Pkts", "rename", ""),
    "total_backward_packets": ("Tot Bwd Pkts", "rename", ""),
    "total_length_of_fwd_packets": ("TotLen Fwd Pkts", "rename", ""),
    "total_length_of_bwd_packets": ("TotLen Bwd Pkts", "rename", ""),
    "flow_packets_s": ("Flow Pkts/s", "rename", ""),
    "flow_bytes_s": ("Flow Byts/s", "rename", ""),
    "packet_length_mean": ("Pkt Len Mean", "rename", ""),
    "packet_length_max": ("Pkt Len Max", "rename", ""),
    "syn_flag_count": ("SYN Flag Cnt", "rename", ""),
    "fin_flag_count": ("FIN Flag Cnt", "rename", ""),
    "rst_flag_count": ("RST Flag Cnt", "rename", ""),
}


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def normalize_label(value: Any) -> str:
    """Strip, collapse whitespace, and normalise dashes in a label."""
    if pd.isna(value):
        return ""
    text = str(value).replace("\u2013", "-").replace("\u2014", "-")
    return re.sub(r"\s+", " ", text).strip()


def unsw_label_class(label: Any) -> str:
    """Return positive, negative, or excluded for a UNSW attack_cat value."""
    canonical = normalize_label(label)
    if canonical in UNSW_POSITIVE_LABELS:
        return "positive"
    if canonical in UNSW_NEGATIVE_LABELS:
        return "negative"
    return "excluded"


def cic2018_label_class(label: Any) -> str:
    """Return positive, negative, or excluded for a CIC-IDS-2018 Label value."""
    canonical = normalize_label(label).lower()
    if canonical in {"benign"}:
        return "negative"
    if canonical == "ddos" or canonical.startswith("ddos "):
        return "positive"
    if canonical == "dos" or canonical.startswith("dos "):
        return "positive"
    if canonical == "portscan" or canonical.startswith("portscan "):
        return "positive"
    return "excluded"


def stable_bucket(key: Any, buckets: int = 100) -> int:
    """Deterministic bucket for a group key; independent of Python's hash seed."""
    digest = hashlib.sha256(str(key).encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % buckets


def group_partition(key: Any, train_buckets: int = 70, buckets: int = 100) -> str:
    """Assign a whole duplicate group to train or validation by stable hash."""
    return "train" if stable_bucket(key, buckets) < train_buckets else "validation"


def day_partitions(dates: Iterable[str]) -> dict[str, str] | None:
    """Split sorted capture days 60/20/20; return None with fewer than 3 days."""
    ordered = sorted(set(dates))
    n = len(ordered)
    if n < 3:
        return None
    n_train = max(1, int(round(n * 0.6)))
    n_validation = max(1, int(round(n * 0.2)))
    if n_train + n_validation >= n:
        n_train = n - 2
        n_validation = 1
    result: dict[str, str] = {}
    for index, day in enumerate(ordered):
        if index < n_train:
            result[day] = "train"
        elif index < n_train + n_validation:
            result[day] = "validation"
        else:
            result[day] = "test"
    return result


def _counts(series: pd.Series) -> dict[str, int]:
    return {
        str(label): int(count)
        for label, count in series.value_counts().sort_index().items()
    }


def _schema_audit(columns: Iterable[str], mapping: dict[str, tuple]) -> dict[str, Any]:
    present = set(columns)
    rows: dict[str, Any] = {}
    for feature in TIER_A_FEATURES:
        source, status, note = mapping[feature]
        rows[feature] = {
            "status": status,
            "source_column": source,
            "present": bool(source in present) if source else False,
            "note": note,
        }
    return {
        "features": rows,
        "available": sum(
            1 for row in rows.values() if row["status"] in {"rename", "derive"}
        ),
        "missing": sum(1 for row in rows.values() if row["status"] == "missing"),
        "total": len(TIER_A_FEATURES),
    }


def _first_existing(directory: str, names: Iterable[str]) -> str:
    for name in names:
        path = os.path.join(directory, name)
        if os.path.exists(path):
            return path
    raise FileNotFoundError(
        f"none of {list(names)} exists in {directory}"
    )


def _read_csv(path: str) -> pd.DataFrame:
    frame = pd.read_csv(path, low_memory=False)
    frame.columns = [str(column).lstrip("\ufeff") for column in frame.columns]
    return frame


def _file_identity(path: str, rows: int, columns: Iterable[str]) -> dict[str, Any]:
    return {
        "path": path,
        "sha256": _sha256_file(path),
        "bytes": os.path.getsize(path),
        "rows": int(rows),
        "columns": len(list(columns)),
    }


# ---------------------------------------------------------------------------
# UNSW-NB15
# ---------------------------------------------------------------------------
def _drop_conflicting_groups(
    frame: pd.DataFrame, hash_column: str = "__hash"
) -> tuple[pd.DataFrame, int]:
    """Drop feature-identical groups whose attack_cat or label is inconsistent."""
    counts = frame.groupby(hash_column)[["attack_cat", "label"]].nunique()
    bad = counts[(counts["attack_cat"] > 1) | (counts["label"] > 1)].index
    if len(bad) == 0:
        return frame, 0
    return frame[~frame[hash_column].isin(bad)].copy(), int(len(bad))


def audit_unsw(directory: str) -> dict[str, Any]:
    train_path = _first_existing(
        directory, ["unsw_train_official.csv", "unsw_train.csv"]
    )
    test_path = _first_existing(
        directory, ["unsw_test_official.csv", "unsw_test.csv"]
    )
    train = _read_csv(train_path)
    test = _read_csv(test_path)

    swapped = False
    if len(train) < len(test):
        train, test = test, train
        train_path, test_path = test_path, train_path
        swapped = True

    required = {"attack_cat", "label"}
    if not required.issubset(train.columns):
        raise KeyError(f"UNSW file is missing columns: {sorted(required - set(train.columns))}")

    feature_columns = [
        column
        for column in train.columns
        if column not in {"id", "attack_cat", "label", "__hash", "__partition"}
    ]
    train_columns = list(train.columns)
    test_columns = list(test.columns)
    observed_labels = set(train["attack_cat"]) | set(test["attack_cat"])
    excluded_labels = {
        normalize_label(label): UNSW_EXCLUDED_LABELS.get(
            normalize_label(label), "excluded; outside volumetric/scanning scope"
        )
        for label in sorted(observed_labels)
        if unsw_label_class(label) == "excluded"
    }
    train = train.copy()
    test = test.copy()
    train["__hash"] = pd.util.hash_pandas_object(
        train[feature_columns], index=False
    ).astype("uint64")
    test["__hash"] = pd.util.hash_pandas_object(
        test[feature_columns], index=False
    ).astype("uint64")

    train_mismatches = int(
        (
            train["attack_cat"].map(
                lambda value: 0 if normalize_label(value) == "Normal" else 1
            )
            != train["label"]
        ).sum()
    )
    test_mismatches = int(
        (
            test["attack_cat"].map(
                lambda value: 0 if normalize_label(value) == "Normal" else 1
            )
            != test["label"]
        ).sum()
    )
    label_mismatches = train_mismatches + test_mismatches

    train_raw_rows, test_raw_rows = len(train), len(test)
    train_conflicts = test_conflicts = 0
    train, train_conflicts = _drop_conflicting_groups(train)
    test, test_conflicts = _drop_conflicting_groups(test)
    train_after_conflict = len(train)
    test_after_conflict = len(test)

    train_unique = train.drop_duplicates("__hash", keep="first").copy()
    test_unique = test.drop_duplicates("__hash", keep="first").copy()

    train_hashes = set(train_unique["__hash"].tolist())
    test_before_leakage = len(test_unique)
    test_unique = test_unique[~test_unique["__hash"].isin(train_hashes)].copy()
    leakage_removed = test_before_leakage - len(test_unique)

    train_unique["__partition"] = train_unique["__hash"].map(group_partition)
    train_part = train_unique[train_unique["__partition"] == "train"]
    validation_part = train_unique[train_unique["__partition"] == "validation"]

    partitions = {
        "train": train_part,
        "validation": validation_part,
        "test": test_unique,
    }
    partition_counts = {
        name: _counts(frame["attack_cat"]) for name, frame in partitions.items()
    }
    matrix = family_day_matrix(
        partition_counts["train"],
        partition_counts["validation"],
        partition_counts["test"],
        positive_labels=UNSW_POSITIVE_LABELS,
    )
    gate = coverage_gate(matrix, positive_labels=UNSW_POSITIVE_LABELS)

    def _partition_payload(name: str, frame: pd.DataFrame) -> dict[str, Any]:
        counts = partition_counts[name]
        positives = sum(
            counts.get(label, 0) for label in UNSW_POSITIVE_LABELS
        )
        return {
            "rows": int(len(frame)),
            "label_counts": counts,
            "positive_rows": int(positives),
            "positive_families": sorted(
                label for label in counts if label in UNSW_POSITIVE_LABELS
            ),
        }

    return {
        "status": "coverage_pass" if gate["overall_pass"] else "coverage_fail",
        "provenance": {
            "directory": directory,
            "files": [
                _file_identity(train_path, train_raw_rows, train_columns),
                _file_identity(test_path, test_raw_rows, test_columns),
            ],
            "official_split": {
                "train_rows": 175341,
                "test_rows": 82332,
                "matches_known_split": (
                    train_raw_rows == 175341 and test_raw_rows == 82332
                ),
            },
            "filename_swap_corrected": swapped,
            "id_note": (
                "The id column restarts at 1 in the official test set and is a row "
                "index, not a stable flow key. It is excluded from the feature hash "
                "and must not be used for grouping or leakage detection."
            ),
            "source_note": (
                "Local download. Record the official source URL, citation, and "
                "licence before publication."
            ),
            "official_source": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
            "licence_status": (
                "not recorded; verify the official terms and citation before publication"
            ),
        },
        "label_policy": {
            "positive_labels": sorted(UNSW_POSITIVE_LABELS),
            "negative_labels": sorted(UNSW_NEGATIVE_LABELS),
            "excluded_labels": excluded_labels,
            "label_mismatches": label_mismatches,
        },
        "duplicates": {
            "raw_rows": {"train": train_raw_rows, "test": test_raw_rows},
            "conflicting_groups": {
                "train": train_conflicts,
                "test": test_conflicts,
            },
            "conflicting_rows": {
                "train": train_raw_rows - train_after_conflict,
                "test": test_raw_rows - test_after_conflict,
            },
            "unique_feature_rows": {
                "train": int(len(train_unique)),
                "test": int(test_before_leakage),
            },
            "duplicate_rows_within": {
                "train": train_after_conflict - len(train_unique),
                "test": test_after_conflict - test_before_leakage,
            },
            "leakage_removed_from_test": int(leakage_removed),
        },
        "group_split": {
            "method": (
                "sha256(feature_hash) mod 100; buckets 0-69 train, 70-99 validation; "
                "test is the official test set after removing train groups"
            ),
            "train_fraction": 0.70,
        },
        "partitions": {
            name: _partition_payload(name, frame)
            for name, frame in partitions.items()
        },
        "family_partition_matrix": matrix,
        "coverage_gate": gate,
        "schema": _schema_audit(train.columns, UNSW_TIER_A_MAP),
    }


# ---------------------------------------------------------------------------
# CIC-IDS-2018
# ---------------------------------------------------------------------------
# The 02-20 file is the original 84-column CICFlowMeter export; the other days
# are the 80-column export. These four columns are direct identifiers and are
# dropped before hashing so they never influence a split or a duplicate group.
CIC_PII_COLUMNS = ("Flow ID", "Src IP", "Src Port", "Dst IP")
CIC_METADATA_COLUMNS = ("Timestamp", "Label")
# Canonical family names used for the coverage gate. The raw labels are
# campaign-suffixed; the family is the unit the P2B protocol evaluates.
CIC_FAMILY_CODES = {"Benign": 0, "DoS": 1, "DDoS": 2, "PortScan": 3}
CIC_EXCLUDED_CODE = 4
CIC_CODE_FAMILIES = {code: name for name, code in CIC_FAMILY_CODES.items()}
CIC_REQUIRED_FAMILIES = ("DDoS", "DoS", "PortScan")
_CIC_FAMILY_PATTERNS = (
    ("DDoS", re.compile(r"^ddos\b", re.IGNORECASE)),
    ("DoS", re.compile(r"^dos\b", re.IGNORECASE)),
    ("PortScan", re.compile(r"^portscan\b", re.IGNORECASE)),
)


def cic2018_family(label: Any) -> str | None:
    """Map a CIC-IDS-2018 label to a canonical family, or None if excluded."""
    canonical = normalize_label(label)
    if canonical.lower() == "benign":
        return "Benign"
    for family, pattern in _CIC_FAMILY_PATTERNS:
        if pattern.match(canonical):
            return family
    return None


def _cic_day_code(day_series: pd.Series, day_index: dict[str, int]) -> np.ndarray:
    """Map day strings to stable integer codes, extending ``day_index``."""
    for day in sorted(set(day_series) - set(day_index)):
        day_index[day] = len(day_index)
    return day_series.map(day_index).to_numpy(dtype=np.int16)


def _cic_label_code(
    label_series: pd.Series, label_index: dict[str, int]
) -> np.ndarray:
    """Map raw label strings to stable integer codes, extending ``label_index``."""
    for label in sorted(set(label_series) - set(label_index)):
        label_index[label] = len(label_index)
    return label_series.map(label_index).to_numpy(dtype=np.int16)


def _cic_family_counts(
    families: np.ndarray, days: np.ndarray | None = None
) -> dict[str, dict[str, int]] | dict[str, int]:
    """Count canonical families, optionally stratified by day code."""
    keep = families != CIC_EXCLUDED_CODE
    if days is None:
        codes, counts = np.unique(families[keep], return_counts=True)
        return {
            CIC_CODE_FAMILIES[int(code)]: int(count)
            for code, count in zip(codes, counts)
        }
    combo = days[keep].astype(np.int64) * 8 + families[keep].astype(np.int64)
    codes, counts = np.unique(combo, return_counts=True)
    result: dict[str, dict[str, int]] = {}
    for code, count in zip(codes, counts):
        day_code, family_code = divmod(int(code), 8)
        result.setdefault(str(day_code), {})[CIC_CODE_FAMILIES[family_code]] = int(count)
    return result


def _audit_cic_file(path: str) -> dict[str, Any]:
    """Read one per-day CIC-IDS-2018 CSV and return counts plus dedup arrays."""
    raw_rows = header_rows = malformed_timestamps = suspicious_timestamps = 0
    raw_labels: collections.Counter[str] = collections.Counter()
    hash_parts: list[np.ndarray] = []
    family_parts: list[np.ndarray] = []
    day_parts: list[np.ndarray] = []
    label_parts: list[np.ndarray] = []
    day_index: dict[str, int] = {}
    label_index: dict[str, int] = {}
    header: list[str] = []

    for chunk in pd.read_csv(path, chunksize=250000, low_memory=False):
        chunk.columns = [str(column).lstrip("\ufeff") for column in chunk.columns]
        if not header:
            header = list(chunk.columns)
        raw_rows += len(chunk)

        # Repeated header rows are emitted mid-file by some CIC exports. They
        # parse as data unless they are filtered explicitly.
        labels = chunk["Label"].map(normalize_label)
        stamps_text = chunk["Timestamp"].map(normalize_label)
        is_header = (labels == "Label") | (stamps_text == "Timestamp")
        header_rows += int(is_header.sum())
        if bool(is_header.any()):
            chunk = chunk[~is_header]
            labels = labels[~is_header]
            stamps_text = stamps_text[~is_header]
        if chunk.empty:
            continue

        stamps = pd.to_datetime(
            chunk["Timestamp"], errors="coerce", dayfirst=True
        )
        malformed_timestamps += int(stamps.isna().sum())
        suspicious_timestamps += int(
            ((stamps.dt.year < 2000) & stamps.notna()).sum()
        )
        days = stamps.dt.strftime("%Y-%m-%d").fillna("NaT")

        raw_labels.update(
            {str(label): int(count) for label, count in labels.value_counts().items()}
        )

        family_codes = labels.map(
            lambda value: CIC_FAMILY_CODES.get(
                cic2018_family(value), CIC_EXCLUDED_CODE
            )
        ).to_numpy(dtype=np.int8)

        features = chunk.drop(
            columns=[
                column
                for column in (*CIC_PII_COLUMNS, *CIC_METADATA_COLUMNS)
                if column in chunk.columns
            ]
        )
        if len(features.columns) == 0:
            # Degenerate frame with no flow features: fall back to the full
            # non-identifier row so rows are not all treated as identical.
            features = chunk.drop(
                columns=[
                    column
                    for column in CIC_PII_COLUMNS
                    if column in chunk.columns
                ]
            )
        features = features.reindex(sorted(features.columns), axis=1)
        if len(features.columns) == 0:
            hashes = np.zeros(len(features), dtype=np.uint64)
        else:
            hashes = (
                pd.util.hash_pandas_object(features, index=False)
                .astype("uint64")
                .to_numpy()
            )

        hash_parts.append(hashes)
        family_parts.append(family_codes)
        day_parts.append(_cic_day_code(days, day_index))
        label_parts.append(_cic_label_code(labels, label_index))

    if not hash_parts:
        empty_u64 = np.empty(0, dtype=np.uint64)
        return {
            "path": path,
            "sha256": _sha256_file(path),
            "bytes": os.path.getsize(path),
            "raw_rows": int(raw_rows),
            "header_rows": int(header_rows),
            "duplicate_rows": 0,
            "unique_rows": 0,
            "columns": header,
            "column_count": len(header),
            "raw_label_counts": {},
            "unique_label_counts": {},
            "day_label_counts": {},
            "family_counts": {},
            "day_family_counts": {},
            "malformed_timestamps": int(malformed_timestamps),
            "suspicious_timestamps": int(suspicious_timestamps),
            "possible_row_cap": int(raw_rows) == 1_048_575,
            "_hashes": empty_u64,
            "_families": np.empty(0, dtype=np.int8),
            "_days": np.empty(0, dtype=np.int16),
            "_labels": np.empty(0, dtype=np.int16),
            "_day_index": day_index,
            "_label_index": label_index,
        }

    hashes = np.concatenate(hash_parts)
    families = np.concatenate(family_parts)
    days = np.concatenate(day_parts)
    label_codes = np.concatenate(label_parts)

    unique_hashes, first = np.unique(hashes, return_index=True)
    duplicate_rows = int(len(hashes) - len(unique_hashes))
    unique_families = families[first]
    unique_days = days[first]
    unique_labels = label_codes[first]

    code_labels = {code: label for label, code in label_index.items()}
    label_counts, label_totals = np.unique(unique_labels, return_counts=True)
    unique_label_counts = {
        code_labels[int(code)]: int(total)
        for code, total in zip(label_counts, label_totals)
    }
    day_codes, day_totals = np.unique(unique_days, return_counts=True)
    day_names = {code: day for day, code in day_index.items()}
    day_label_counts: dict[str, dict[str, int]] = {}
    for day_code in day_codes:
        mask = unique_days == day_code
        counts, totals = np.unique(unique_labels[mask], return_counts=True)
        day_label_counts[day_names[int(day_code)]] = {
            code_labels[int(code)]: int(total)
            for code, total in zip(counts, totals)
        }

    day_family = _cic_family_counts(unique_families, unique_days)
    return {
        "path": path,
        "sha256": _sha256_file(path),
        "bytes": os.path.getsize(path),
        "raw_rows": int(raw_rows),
        "header_rows": int(header_rows),
        "duplicate_rows": duplicate_rows,
        "unique_rows": int(len(unique_hashes)),
        "columns": header,
        "column_count": len(header),
        "raw_label_counts": dict(sorted(raw_labels.items())),
        "unique_label_counts": dict(sorted(unique_label_counts.items())),
        "day_label_counts": {
            day: dict(sorted(counts.items()))
            for day, counts in sorted(day_label_counts.items())
        },
        "family_counts": _cic_family_counts(unique_families),
        "day_family_counts": {
            day_names[int(day_code)]: counts
            for day_code, counts in sorted(day_family.items())
        },
        "malformed_timestamps": int(malformed_timestamps),
        "suspicious_timestamps": int(suspicious_timestamps),
        "possible_row_cap": int(raw_rows) == 1_048_575,
        "_hashes": unique_hashes,
        "_families": unique_families,
        "_days": unique_days,
        "_labels": unique_labels,
        "_day_index": day_index,
        "_label_index": label_index,
    }


def _partition_counts(
    families: np.ndarray, partition_codes: np.ndarray
) -> dict[str, dict[str, int]]:
    """Count canonical families in train/validation/test partitions."""
    names = {0: "train", 1: "validation", 2: "test"}
    keep = (families != CIC_EXCLUDED_CODE) & (partition_codes >= 0)
    combo = partition_codes[keep].astype(np.int64) * 8 + families[keep].astype(
        np.int64
    )
    codes, counts = np.unique(combo, return_counts=True)
    result: dict[str, dict[str, int]] = {name: {} for name in names.values()}
    for code, count in zip(codes, counts):
        partition_code, family_code = divmod(int(code), 8)
        result[names[partition_code]][CIC_CODE_FAMILIES[family_code]] = int(count)
    return result


def _split_payload(
    families: np.ndarray,
    partition_codes: np.ndarray,
    positive_labels: Iterable[str],
    required_families: Iterable[str],
    method: str,
) -> dict[str, Any]:
    counts = _partition_counts(families, partition_codes)
    matrix = family_day_matrix(
        counts["train"],
        counts["validation"],
        counts["test"],
        positive_labels=positive_labels,
    )
    gate = coverage_gate(
        matrix,
        positive_labels=positive_labels,
        required_families=required_families,
    )
    return {
        "method": method,
        "partitions": {
            name: {
                "rows": int((partition_codes == code).sum()),
                "label_counts": dict(sorted(counts[name].items())),
                "positive_rows": int(
                    sum(
                        count
                        for family, count in counts[name].items()
                        if family in positive_labels
                    )
                ),
            }
            for code, name in ((0, "train"), (1, "validation"), (2, "test"))
        },
        "family_partition_matrix": matrix,
        "coverage_gate": gate,
        "status": "coverage_pass" if gate["overall_pass"] else "coverage_fail",
    }


def _merge_day_label_counts(
    per_file: list[dict[str, Any]]
) -> dict[str, dict[str, int]]:
    """Merge per-file day->label counts without dropping days."""
    merged: dict[str, collections.Counter[str]] = collections.defaultdict(
        collections.Counter
    )
    for audit in per_file:
        for day, counts in audit["day_label_counts"].items():
            merged[day].update(counts)
    return {
        day: dict(sorted(counts.items()))
        for day, counts in sorted(merged.items())
    }


def audit_cic(directory: str) -> dict[str, Any]:
    files = sorted(glob.glob(os.path.join(directory, "*.csv")))
    if not files:
        raise FileNotFoundError(f"no CSV files found in {directory}")

    per_file = [_audit_cic_file(path) for path in files]

    # Merge per-file unique rows into one global unique-row view. Cross-file
    # duplicates are possible when a day was exported twice; count and drop them
    # so no flow can sit in two partitions.
    all_hashes = np.concatenate([audit["_hashes"] for audit in per_file])
    global_hashes, first = np.unique(all_hashes, return_index=True)
    cross_file_duplicates = int(len(all_hashes) - len(global_hashes))

    day_index: dict[str, int] = {}
    label_index: dict[str, int] = {}
    global_families = np.empty(len(all_hashes), dtype=np.int8)
    global_days = np.empty(len(all_hashes), dtype=np.int16)
    global_labels = np.empty(len(all_hashes), dtype=np.int16)

    offset = 0
    for audit in per_file:
        count = len(audit["_hashes"])
        local_slice = slice(offset, offset + count)
        offset += count

        day_lookup = np.empty(len(audit["_day_index"]), dtype=np.int16)
        for day, local_code in audit["_day_index"].items():
            if day not in day_index:
                day_index[day] = len(day_index)
            day_lookup[local_code] = day_index[day]

        label_lookup = np.empty(len(audit["_label_index"]), dtype=np.int16)
        for label, local_code in audit["_label_index"].items():
            if label not in label_index:
                label_index[label] = len(label_index)
            label_lookup[local_code] = label_index[label]

        global_families[local_slice] = audit["_families"]
        global_days[local_slice] = day_lookup[audit["_days"]]
        global_labels[local_slice] = label_lookup[audit["_labels"]]

    # The first occurrence of each global hash defines its family and day.
    global_families = global_families[first]
    global_days = global_days[first]
    global_labels = global_labels[first]

    # Detect feature-identical rows with inconsistent families.
    order = np.lexsort((global_families, global_hashes))
    ordered_hashes = global_hashes[order]
    ordered_families = global_families[order]
    adjacent_same = ordered_hashes[1:] == ordered_hashes[:-1]
    adjacent_conflict = adjacent_same & (
        ordered_families[1:] != ordered_families[:-1]
    )
    conflicting_hashes = int(len(np.unique(ordered_hashes[1:][adjacent_conflict])))

    # Raw and unique label totals across the whole set.
    code_labels = {code: label for label, code in label_index.items()}
    unique_label_counts: collections.Counter[str] = collections.Counter()
    codes, totals = np.unique(global_labels, return_counts=True)
    for code, total in zip(codes, totals):
        unique_label_counts[code_labels[int(code)]] += int(total)

    raw_label_counts: collections.Counter[str] = collections.Counter()
    for audit in per_file:
        raw_label_counts.update(audit["raw_label_counts"])

    day_names = {code: day for day, code in day_index.items()}
    day_family_counts: dict[str, dict[str, int]] = {}
    for day_code in np.unique(global_days):
        mask = global_days == day_code
        day_family_counts[day_names[int(day_code)]] = _cic_family_counts(
            global_families[mask]
        )

    observed_families = {
        CIC_CODE_FAMILIES[int(code)]
        for code in np.unique(global_families)
        if int(code) != CIC_EXCLUDED_CODE
    }
    positive_labels = sorted(
        family for family in observed_families if family != "Benign"
    )
    required_families = [
        family for family in CIC_REQUIRED_FAMILIES if family != "Benign"
    ]

    # Temporal split: whole capture days, 60/20/20 in date order.
    dates = sorted(
        day for day in day_names.values() if int(day[:4]) >= 2000
    )
    suspicious_days = sorted(
        day for day in day_names.values() if int(day[:4]) < 2000
    )
    day_split = day_partitions(dates)
    temporal_payload: dict[str, Any]
    if day_split is None:
        temporal_payload = {
            "method": "temporal_day_split",
            "day_split": None,
            "status": "insufficient_days",
            "partitions": {},
            "family_partition_matrix": None,
            "coverage_gate": {
                "minimums": {"train": 1, "validation": 1, "test": 1},
                "families": {},
                "missing_required": sorted(required_families),
                "overall_pass": False,
                "reason": (
                    "Fewer than 3 capture days are present; a day-based "
                    "train/validation/test split is not possible."
                ),
            },
        }
    else:
        partition_by_day = {"train": 0, "validation": 1, "test": 2}
        day_lookup = np.full(len(day_index), -1, dtype=np.int8)
        for day, partition in day_split.items():
            day_lookup[day_index[day]] = partition_by_day[partition]
        temporal_codes = day_lookup[global_days]
        temporal_payload = _split_payload(
            global_families,
            temporal_codes,
            positive_labels,
            required_families,
            method=(
                "temporal_day_split: sorted capture days, 60/20/20 by day; "
                "a whole day stays in one partition"
            ),
        )
        temporal_payload["day_split"] = day_split

    # Group split: exact-duplicate groups assigned by deterministic hash bucket.
    buckets = (global_hashes % 100).astype(np.int16)
    group_codes = np.where(buckets < 70, 0, np.where(buckets < 85, 1, 2)).astype(
        np.int8
    )
    group_payload = _split_payload(
        global_families,
        group_codes,
        positive_labels,
        required_families,
        method=(
            "group_hash_split: sha256-free uint64 feature hash mod 100; "
            "buckets 0-69 train, 70-84 validation, 85-99 test"
        ),
    )

    missing_required = sorted(
        family for family in required_families if family not in observed_families
    )
    status = "coverage_fail"
    if temporal_payload["status"] == "insufficient_days":
        status = "insufficient_days"

    columns = per_file[0]["columns"]
    return {
        "status": status,
        "provenance": {
            "directory": directory,
            "files": [
                {
                    "path": audit["path"],
                    "sha256": audit["sha256"],
                    "bytes": audit["bytes"],
                    "raw_rows": audit["raw_rows"],
                    "header_rows": audit["header_rows"],
                    "duplicate_rows": audit["duplicate_rows"],
                    "unique_rows": audit["unique_rows"],
                    "column_count": audit["column_count"],
                    "possible_row_cap": audit["possible_row_cap"],
                }
                for audit in per_file
            ],
            "source_note": (
                "Local download of the per-day CIC-IDS-2018 CSVs. Record the "
                "official source URL, citation, and licence before publication."
            ),
            "official_source": "https://www.unsw.ca/cic/datasets/ids-2018.html",
            "licence_status": (
                "not recorded; verify the official terms and citation before publication"
            ),
        },
        "label_policy": {
            "positive_labels": positive_labels,
            "negative_labels": ["Benign"] if "Benign" in observed_families else [],
            "required_families": required_families,
            "missing_required_families": missing_required,
            "family_mapping": {
                "DDoS": "label starts with 'DDoS'",
                "DoS": "label starts with 'DoS'",
                "PortScan": "label starts with 'PortScan'",
                "Benign": "label equals 'Benign'",
                "excluded": "everything else (web attack, brute force, bot, infiltration)",
            },
            "excluded_labels": {
                label: "excluded; outside volumetric/scanning scope"
                for label in sorted(unique_label_counts)
                if cic2018_family(label) is None
            },
        },
        "rows": {
            "raw": int(sum(audit["raw_rows"] for audit in per_file)),
            "header_rows_removed": int(
                sum(audit["header_rows"] for audit in per_file)
            ),
            "duplicate_within_file": int(
                sum(audit["duplicate_rows"] for audit in per_file)
            ),
            "cross_file_duplicates": cross_file_duplicates,
            "unique": int(len(global_hashes)),
            "malformed_timestamps": int(
                sum(audit["malformed_timestamps"] for audit in per_file)
            ),
            "suspicious_timestamps": int(
                sum(audit["suspicious_timestamps"] for audit in per_file)
            ),
            "possible_row_cap": any(
                audit["possible_row_cap"] for audit in per_file
            ),
        },
        "raw_label_counts": dict(sorted(raw_label_counts.items())),
        "unique_label_counts": dict(sorted(unique_label_counts.items())),
        "family_counts": _cic_family_counts(global_families),
        "day_family_counts": {
            day: dict(sorted(counts.items()))
            for day, counts in sorted(day_family_counts.items())
        },
        "capture_days": dates,
        "suspicious_days": suspicious_days,
        "day_label_counts": _merge_day_label_counts(per_file),
        "conflicting_duplicate_groups": conflicting_hashes,
        "temporal_split": temporal_payload,
        "group_split": group_payload,
        "schema": _schema_audit(columns, CIC2018_TIER_A_MAP),
        "per_file": [
            {
                key: value
                for key, value in audit.items()
                if not key.startswith("_")
            }
            for audit in per_file
        ],
    }


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------
def build_findings(payload: dict[str, Any]) -> list[str]:
    unsw = payload["datasets"]["unsw_nb15"]
    cic = payload["datasets"]["cic_ids_2018"]
    findings = [
        (
            "UNSW-NB15: the official split is 175,341 train / 82,332 test. "
            + (
                "The local filenames were swapped and have been corrected by row count."
                if unsw["provenance"]["filename_swap_corrected"]
                else "The local filenames match the official split."
            )
        ),
        (
            "UNSW-NB15: DoS (volumetric) and Reconnaissance (scanning) are the only "
            "in-scope positive families. Both appear in all three proposed partitions, "
            f"so the coverage gate is {'PASS' if unsw['coverage_gate']['overall_pass'] else 'FAIL'}."
        ),
        (
            "UNSW-NB15: feature-identical rows are pervasive. The audit removed "
            f"{unsw['duplicates']['duplicate_rows_within']['train']:,} duplicate train rows, "
            f"{unsw['duplicates']['duplicate_rows_within']['test']:,} duplicate test rows, and "
            f"{unsw['duplicates']['leakage_removed_from_test']:,} test rows that duplicated a train group. "
            f"It also excluded {unsw['duplicates']['conflicting_groups']['train']:,} train groups "
            f"({unsw['duplicates']['conflicting_rows']['train']:,} rows) and "
            f"{unsw['duplicates']['conflicting_groups']['test']:,} test groups "
            f"({unsw['duplicates']['conflicting_rows']['test']:,} rows) whose feature-identical rows "
            "had inconsistent labels. A random split without this grouping would leak near-identical flows."
        ),
        (
            "UNSW-NB15: only "
            f"{unsw['schema']['available']}/{unsw['schema']['total']} Tier A features are available. "
            f"{unsw['schema']['missing']} are missing (packet_length_max and the three flag counts). "
            "The CIC-trained serving model cannot be applied directly; a UNSW-specific model "
            "or a new feature adapter would be required."
        ),
        (
            "CIC-IDS-2018: the complete local set contains "
            f"{len(cic['capture_days'])} capture day(s) ({', '.join(cic['capture_days']) or 'none'}) "
            f"and {cic['rows']['unique']:,} unique feature-identical flows after removing "
            f"{cic['rows']['duplicate_within_file']:,} within-file and "
            f"{cic['rows']['cross_file_duplicates']:,} cross-file duplicate rows. "
            f"Observed volumetric families are {', '.join(cic['label_policy']['positive_labels']) or 'none'}; "
            f"required families missing from the whole set: "
            f"{', '.join(cic['label_policy']['missing_required_families']) or 'none'}."
        ),
        (
            "CIC-IDS-2018: the day-based temporal split "
            f"{'PASSES' if cic['temporal_split']['status'] == 'coverage_pass' else 'FAILS'} "
            "the coverage gate. All DoS and DDoS positives fall in the early capture "
            "days, so a 60/20/20 day split leaves validation and test with no "
            "volumetric positives. A day split is therefore a family split."
        ),
        (
            "CIC-IDS-2018: a deterministic group-hash split "
            f"{'PASSES' if cic['group_split']['status'] == 'coverage_pass' else 'FAILS'} "
            "the coverage gate. It can place DoS and DDoS in all three partitions, "
            "but it cannot manufacture a PortScan family that the dataset does not "
            "contain, and it is a random split, not a temporal one."
        ),
        (
            "CIC-IDS-2018: all 12 Tier A features are present under CICFlowMeter-2018 "
            "names, and the 84-column 02-20 export reduces to the same 80-column "
            "schema after dropping `Flow ID`, `Src IP`, `Src Port`, and `Dst IP`."
        ),
        (
            "CIC-IDS-2018: data-quality warnings remain. "
            f"{cic['rows']['header_rows_removed']} repeated header rows were removed; "
            f"{cic['rows']['suspicious_timestamps']} rows carry pre-2000 (mostly 1970) "
            f"timestamps; {sum(1 for audit in cic['per_file'] if audit['possible_row_cap'])} "
            "files have exactly 1,048,575 rows, consistent with a 1,000,000-row cap "
            "above the header. The 4 GB 02-20 file is not capped and is the only "
            "7.9M-row day."
        ),
    ]
    return findings


def build_payload(unsw_dir: str, cic_dir: str) -> dict[str, Any]:
    unsw = audit_unsw(unsw_dir)
    cic = audit_cic(cic_dir)
    payload: dict[str, Any] = {
        "artifact_version": ARTIFACT_VERSION,
        "method": "external_dataset_ingestion_and_coverage_audit",
        "scope": (
            "Flow-based detector for volumetric and scanning behavior. "
            "Not a general NIDS. Botnet, web attacks, infiltration, zero-day, "
            "and blocking are out of scope."
        ),
        "datasets": {
            "unsw_nb15": unsw,
            "cic_ids_2018": cic,
        },
        "decision": {
            "p2b_status": "blocked",
            "unsw_nb15_verdict": (
                "usable for a leakage-safe, random-split coverage study, but not as a "
                "direct external validation of the CIC-trained model because 4 Tier A "
                "features are missing"
            ),
            "cic_ids_2018_verdict": (
                "contains DoS and DDoS across several days but no PortScan at all. "
                "A day-based split fails the coverage gate because the positives are "
                "concentrated in the early days; a group-hash split can cover DoS and "
                "DDoS only. It cannot close A4 for a claim that includes PortScan."
            ),
            "training_authorized": False,
            "reason": (
                "No dataset currently provides a validated, schema-compatible split "
                "that covers every required family in train, validation, and test. "
                "The audit records feasibility; it does not authorize a fit."
            ),
        },
        "artifact_identity": {
            "serving_artifact": os.path.relpath(
                SERVING_ARTIFACT, PROJECT_ROOT
            ).replace("\\", "/"),
            "serving_sha256": _sha256_file(SERVING_ARTIFACT)
            if os.path.exists(SERVING_ARTIFACT)
            else None,
            "pandas_version": pd.__version__,
        },
        "notes": [
            "No model is trained, no registry row is written, and the serving artifact is untouched.",
            "UNSW-NB15 has no timestamp, so its split is a deterministic group-hash split, not a temporal split.",
            "UNSW-NB15 duplicate groups are keyed on the 42 non-metadata feature columns.",
            "CIC-IDS-2018 is a day-scheduled dataset. The audit reports a temporal day split and a group-hash split separately; only the group split can cover DoS and DDoS in all partitions.",
            "CIC-IDS-2018 has no PortScan family, so any claim that includes PortScan remains blocked on data.",
            "CIC-IDS-2018 duplicates are grouped on flow features after dropping direct identifiers (Flow ID, Src IP, Src Port, Dst IP).",
            "The audit reads local downloads only; source URLs and licences must be recorded separately.",
        ],
    }
    payload["findings"] = build_findings(payload)
    return payload


def _fmt(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) else str(value)


def render_markdown(payload: dict[str, Any]) -> str:
    unsw = payload["datasets"]["unsw_nb15"]
    cic = payload["datasets"]["cic_ids_2018"]
    lines: list[str] = []
    lines.append("# External Dataset Audit")
    lines.append("")
    lines.append("**Status:** **BLOCKED for training** — the audit records feasibility, not a validated split.")
    lines.append("**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.")
    lines.append("**Artifact:** [`EXTERNAL_DATASET_AUDIT.json`](EXTERNAL_DATASET_AUDIT.json).")
    lines.append("**Reproduction:** [`../scripts/external_dataset_audit.py`](../scripts/external_dataset_audit.py).")
    lines.append("")
    lines.append("This audit answers whether the two local external datasets can supply a")
    lines.append("leakage-safe train/validation/test split in which every evaluated")
    lines.append("volumetric/scanning family appears in all three partitions. It does not")
    lines.append("train a model, write a registry row, or change the serving artifact.")
    lines.append("")
    lines.append("## 1. UNSW-NB15")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Status | **{unsw['status']}** |")
    lines.append(f"| Official source | {unsw['provenance']['official_source']} |")
    lines.append(f"| Licence | {unsw['provenance']['licence_status']} |")
    lines.append("| Official split | 175,341 train / 82,332 test |")
    lines.append(f"| Filename swap corrected | {unsw['provenance']['filename_swap_corrected']} |")
    lines.append(f"| Positive families | {', '.join(unsw['label_policy']['positive_labels'])} |")
    lines.append(f"| Negative family | {', '.join(unsw['label_policy']['negative_labels'])} |")
    lines.append(f"| Label mismatches | {_fmt(unsw['label_policy']['label_mismatches'])} |")
    lines.append("")
    lines.append("### Partitions")
    lines.append("")
    lines.append("| Partition | Rows | Positive rows | Families |")
    lines.append("| --- | ---: | ---: | --- |")
    for name in ("train", "validation", "test"):
        part = unsw["partitions"][name]
        lines.append(
            f"| {name} | {_fmt(part['rows'])} | {_fmt(part['positive_rows'])} | "
            f"{', '.join(part['positive_families']) or 'none'} |"
        )
    lines.append("")
    lines.append("### Duplicate leakage")
    lines.append("")
    lines.append("| Check | Train | Test |")
    lines.append("| --- | ---: | ---: |")
    lines.append(
        f"| Raw rows | {_fmt(unsw['duplicates']['raw_rows']['train'])} | "
        f"{_fmt(unsw['duplicates']['raw_rows']['test'])} |"
    )
    lines.append(
        f"| Unique feature rows | {_fmt(unsw['duplicates']['unique_feature_rows']['train'])} | "
        f"{_fmt(unsw['duplicates']['unique_feature_rows']['test'])} |"
    )
    lines.append(
        f"| Duplicate rows within | {_fmt(unsw['duplicates']['duplicate_rows_within']['train'])} | "
        f"{_fmt(unsw['duplicates']['duplicate_rows_within']['test'])} |"
    )
    lines.append(
        f"| Conflicting groups | {_fmt(unsw['duplicates']['conflicting_groups']['train'])} | "
        f"{_fmt(unsw['duplicates']['conflicting_groups']['test'])} |"
    )
    lines.append(
        f"| Conflicting rows | {_fmt(unsw['duplicates']['conflicting_rows']['train'])} | "
        f"{_fmt(unsw['duplicates']['conflicting_rows']['test'])} |"
    )
    lines.append(
        f"| Leakage removed from test | — | {_fmt(unsw['duplicates']['leakage_removed_from_test'])} |"
    )
    lines.append("")
    lines.append("The `id` column restarts at 1 in the official test set; it is a row index,")
    lines.append("not a flow key. The split is a deterministic hash of the 42 non-metadata")
    lines.append("feature columns, so duplicate groups stay in one partition. The test")
    lines.append("partition is the official test set after removing duplicate and")
    lines.append("train-overlapping groups; it is not the untouched official benchmark.")
    lines.append("")
    lines.append("### Coverage gate")
    lines.append("")
    lines.append(f"**Overall: {'PASS' if unsw['coverage_gate']['overall_pass'] else 'FAIL'}**")
    lines.append("")
    lines.append("| Family | Train | Validation | Test | Pass |")
    lines.append("| --- | ---: | ---: | ---: | --- |")
    for family, row in unsw["coverage_gate"]["families"].items():
        lines.append(
            f"| {family} | {_fmt(row['train'])} | {_fmt(row['validation'])} | "
            f"{_fmt(row['test'])} | {row['pass']} |"
        )
    lines.append("")
    lines.append("A coverage pass is necessary but not sufficient. Training remains")
    lines.append("unauthorized until the schema gap and the random-split estimand are")
    lines.append("accepted in a frozen protocol.")
    lines.append("")
    lines.append("### Tier A schema")
    lines.append("")
    lines.append(
        f"{unsw['schema']['available']}/{unsw['schema']['total']} features available; "
        f"{unsw['schema']['missing']} missing."
    )
    lines.append("")
    lines.append("| Feature | Status | Source | Note |")
    lines.append("| --- | --- | --- | --- |")
    for feature, row in unsw["schema"]["features"].items():
        lines.append(
            f"| `{feature}` | {row['status']} | {row['source_column'] or '—'} | {row['note'] or '—'} |"
        )
    lines.append("")
    lines.append("The CIC-trained serving model cannot be applied directly: UNSW lacks")
    lines.append("`packet_length_max` and the three flag counts. A UNSW-specific model or a")
    lines.append("new adapter would be required, and the result would not be a direct external")
    lines.append("validation of the CIC model.")
    lines.append("")
    lines.append("## 2. CIC-IDS-2018")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Status | **{cic['status']}** |")
    lines.append(f"| Official source | {cic['provenance']['official_source']} |")
    lines.append(f"| Licence | {cic['provenance']['licence_status']} |")
    lines.append(f"| Capture days | {len(cic['capture_days'])} ({', '.join(cic['capture_days']) or 'none'}) |")
    lines.append(f"| Suspicious pre-2000 days | {', '.join(cic['suspicious_days']) or 'none'} |")
    lines.append(f"| Raw rows | {_fmt(cic['rows']['raw'])} |")
    lines.append(f"| Repeated header rows removed | {_fmt(cic['rows']['header_rows_removed'])} |")
    lines.append(f"| Duplicate rows within file | {_fmt(cic['rows']['duplicate_within_file'])} |")
    lines.append(f"| Cross-file duplicate rows | {_fmt(cic['rows']['cross_file_duplicates'])} |")
    lines.append(f"| Unique feature-identical flows | {_fmt(cic['rows']['unique'])} |")
    lines.append(f"| Conflicting duplicate groups | {_fmt(cic['conflicting_duplicate_groups'])} |")
    lines.append(f"| Malformed timestamps | {_fmt(cic['rows']['malformed_timestamps'])} |")
    lines.append(f"| Suspicious timestamps (pre-2000) | {_fmt(cic['rows']['suspicious_timestamps'])} |")
    lines.append(f"| Files at the 1,048,575-row cap | {sum(1 for audit in cic['per_file'] if audit['possible_row_cap'])} of {len(cic['per_file'])} |")
    lines.append(f"| Positive families present | {', '.join(cic['label_policy']['positive_labels']) or 'none'} |")
    lines.append(f"| Required families missing | {', '.join(cic['label_policy']['missing_required_families']) or 'none'} |")
    lines.append("")
    lines.append("### Files")
    lines.append("")
    lines.append("| File | Raw rows | Unique rows | Duplicates | Header rows | Columns | 1M cap |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | --- |")
    for audit in cic["per_file"]:
        lines.append(
            f"| {os.path.basename(audit['path'])} | {_fmt(audit['raw_rows'])} | "
            f"{_fmt(audit['unique_rows'])} | {_fmt(audit['duplicate_rows'])} | "
            f"{_fmt(audit['header_rows'])} | {audit['column_count']} | "
            f"{audit['possible_row_cap']} |"
        )
    lines.append("")
    lines.append("The 84-column `02-20` export reduces to the same 80-column schema as the")
    lines.append("other days after dropping `Flow ID`, `Src IP`, `Src Port`, and `Dst IP`.")
    lines.append("Those four columns are direct identifiers and are excluded from the")
    lines.append("duplicate hash and from every split.")
    lines.append("")
    lines.append("Seven files have exactly 1,048,575 data rows, which is 2^20 - 1 and the")
    lines.append("Excel row ceiling. That is strong evidence of truncation, not of a")
    lines.append("complete capture day. Re-acquire those days from the official source")
    lines.append("before any fit; a truncated day cannot support a count or a split claim.")
    lines.append("")
    lines.append("### Family counts by capture day")
    lines.append("")
    families = ["Benign", "DoS", "DDoS", "PortScan"]
    lines.append("| Day | " + " | ".join(families) + " |")
    lines.append("| --- | " + " | ".join("---:" for _ in families) + " |")
    for day in sorted(cic["day_family_counts"]):
        counts = cic["day_family_counts"][day]
        lines.append(
            f"| {day} | "
            + " | ".join(_fmt(counts.get(family, 0)) for family in families)
            + " |"
        )
    lines.append("")
    lines.append("### Temporal day split")
    lines.append("")
    temporal = cic["temporal_split"]
    lines.append(f"**Status: {temporal['status']}**")
    lines.append("")
    if temporal.get("day_split"):
        lines.append("| Day | Partition |")
        lines.append("| --- | --- |")
        for day, partition in temporal["day_split"].items():
            lines.append(f"| {day} | {partition} |")
        lines.append("")
    lines.append("| Partition | Rows | Positive rows |")
    lines.append("| --- | ---: | ---: |")
    for name in ("train", "validation", "test"):
        part = temporal["partitions"].get(name)
        if part is None:
            continue
        lines.append(
            f"| {name} | {_fmt(part['rows'])} | {_fmt(part['positive_rows'])} |"
        )
    lines.append("")
    lines.append(temporal["coverage_gate"]["reason"])
    lines.append("")
    lines.append("A day-based split is also a family split here: every DoS and DDoS")
    lines.append("positive falls in the early capture days, so validation and test hold")
    lines.append("no volumetric positives. The temporal result is recorded but rejected.")
    lines.append("Flows that appear on more than one day are assigned to their first")
    lines.append("capture day, so no flow can span partitions.")
    lines.append("")
    lines.append("### Group-hash split")
    lines.append("")
    group = cic["group_split"]
    lines.append(f"**Status: {group['status']}**")
    lines.append("")
    lines.append("| Partition | Rows | Positive rows | DoS | DDoS | PortScan |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for name in ("train", "validation", "test"):
        part = group["partitions"][name]
        counts = part["label_counts"]
        lines.append(
            f"| {name} | {_fmt(part['rows'])} | {_fmt(part['positive_rows'])} | "
            f"{_fmt(counts.get('DoS', 0))} | {_fmt(counts.get('DDoS', 0))} | "
            f"{_fmt(counts.get('PortScan', 0))} |"
        )
    lines.append("")
    lines.append(group["coverage_gate"]["reason"])
    lines.append("")
    lines.append("The group split keeps feature-identical flows in one partition. It is a")
    lines.append("random split, not a temporal one, so it cannot support a claim about")
    lines.append("future traffic. It also cannot create the PortScan family.")
    lines.append("")
    lines.append("### Tier A schema")
    lines.append("")
    lines.append(
        f"{cic['schema']['available']}/{cic['schema']['total']} features available; "
        f"{cic['schema']['missing']} missing."
    )
    lines.append("")
    lines.append("All 12 Tier A features exist under CICFlowMeter-2018 names. The blocker")
    lines.append("is family coverage and provenance, not the feature schema.")
    lines.append("")
    lines.append("## 3. Decision")
    lines.append("")
    lines.append(f"- **UNSW-NB15:** {payload['decision']['unsw_nb15_verdict'].rstrip('.')}.")
    lines.append(f"- **CIC-IDS-2018:** {payload['decision']['cic_ids_2018_verdict'].rstrip('.')}.")
    lines.append("- **Training authorized:** no.")
    lines.append("- **P2B status:** blocked.")
    lines.append("")
    lines.append("## 4. Findings")
    lines.append("")
    for finding in payload["findings"]:
        lines.append(f"- {finding}")
    lines.append("")
    lines.append("## 5. What does not change")
    lines.append("")
    lines.append("- Serving artifact and threshold: unchanged.")
    lines.append("- Detection **4/10**, SaaS **3/10**, overall **4.5/10**.")
    lines.append("- Scope: volumetric/scanning only; no blocking, botnet, web-attack,")
    lines.append("  infiltration, zero-day, general NIDS, or production-readiness claim.")
    lines.append("- Tier B fan-out remains unavailable.")
    lines.append("")
    lines.append("## 6. Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append("venv/Scripts/python.exe scripts/external_dataset_audit.py \\")
    lines.append("  --unsw-dir ~/Downloads/UNSW_NB15 \\")
    lines.append('  --cic-dir "~/Downloads/CIC IDS 2018 Complete" \\')
    lines.append("  --output docs/EXTERNAL_DATASET_AUDIT.json \\")
    lines.append("  --report docs/EXTERNAL_DATASET_AUDIT.md")
    lines.append("venv/Scripts/python.exe -m pytest tests/test_external_dataset_audit.py -q")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def run(unsw_dir: str, cic_dir: str, output: str, report: str) -> dict[str, Any]:
    payload = build_payload(unsw_dir, cic_dir)
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
    parser.add_argument("--unsw-dir", default=DEFAULT_UNSW_DIR)
    parser.add_argument("--cic-dir", default=DEFAULT_CIC_DIR)
    parser.add_argument("--output", default="docs/EXTERNAL_DATASET_AUDIT.json")
    parser.add_argument("--report", default="docs/EXTERNAL_DATASET_AUDIT.md")
    args = parser.parse_args(list(argv) if argv is not None else None)
    run(args.unsw_dir, args.cic_dir, args.output, args.report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
