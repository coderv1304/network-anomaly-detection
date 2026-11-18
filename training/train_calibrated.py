"""Matched-scope probability calibration and benign-FPR operating points.

This module turns the frozen volumetric/scanning scope into portable-ratio
matrices, builds a leakage-safe day protocol, fits two candidate classifiers,
and selects operating thresholds from **Wednesday benign scores only**.

Why calibration exists here
---------------------------
Tree-vote fractions from an uncalibrated Random Forest pile up at ``1.0``.
Selecting a quantile of those scores on a validation split produces a threshold
of exactly ``1.0`` and therefore zero alerts everywhere. A sigmoid calibrator
fitted on a disjoint validation partition spreads the scores, and the imposed
benign false-positive rate becomes a real operating point.

Protocol reality
----------------
The product scope contains only volumetric DoS/DDoS and scanning. In the
CIC-IDS-2017 distribution, Monday is entirely benign and Tuesday contains only
credential attacks (FTP/SSH Patator), which the frozen policy excludes. A
literal "train on Monday-Tuesday" matched-scope split therefore contains
**zero positive rows**. :func:`build_protocol_split` records that finding and,
only when it happens, falls back to a group-disjoint split of Wednesday:
Wednesday groups are assigned wholly to training or calibration, Monday-Tuesday
benign rows stay in training, and Thursday-Friday plus every external dataset
remain untouched. The fallback is reported as a deviation, never hidden.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Iterable

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

from training.portable_features import PORTABLE_FEATURE_NAMES, portable_matrix
from training.scope_filter import (
    MATCHED_LABEL_COLUMN,
    NORMALIZED_LABEL_COLUMN,
    filter_matched_scope,
    merge_audits,
)

SEED = 42
TARGET_FPRS = (0.005, 0.001)
THRESHOLD_FLOOR = 0.001
THRESHOLD_CEILING = 0.99
DAY_ORDER = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")
TRAIN_DAYS = ("Monday", "Tuesday")
CALIBRATION_DAYS = ("Wednesday",)
TEST_DAYS = ("Thursday", "Friday")
WEDNESDAY_TRAIN_BUCKETS = 70  # 70% of Wednesday groups train the base model

RF_PARAMS: dict[str, Any] = {
    "n_estimators": 200,
    "max_depth": 16,
    "min_samples_leaf": 10,
    "max_features": "sqrt",
    "random_state": SEED,
    "n_jobs": -1,
}

HGB_PARAMS: dict[str, Any] = {
    "max_iter": 200,
    "learning_rate": 0.05,
    "max_leaf_nodes": 31,
    "min_samples_leaf": 50,
    "l2_regularization": 1.0,
    "random_state": SEED,
}

# Source columns for the four portable inputs. The DistriNet corrected export
# uses singular "Packet"/"packets" spellings; the Kaggle export uses plural.
CIC_SOURCE_COLUMNS: dict[str, dict[str, str]] = {
    "cicids2017": {
        "label": "Label",
        "fwd_packets": "Total Fwd Packets",
        "bwd_packets": "Total Backward Packets",
        "fwd_bytes": "Total Length of Fwd Packets",
        "bwd_bytes": "Total Length of Bwd Packets",
        "src_ip": "Source IP",
        "dst_ip": "Destination IP",
        "src_port": "Source Port",
        "dst_port": "Destination Port",
        "protocol": "Protocol",
        "timestamp": "Timestamp",
    },
    "distrinet_cicids2017": {
        "label": "Label",
        "fwd_packets": "Total Fwd Packet",
        "bwd_packets": "Total Bwd packets",
        "fwd_bytes": "Total Length of Fwd Packet",
        "bwd_bytes": "Total Length of Bwd Packet",
        "src_ip": "Src IP",
        "dst_ip": "Dst IP",
        "src_port": "Src Port",
        "dst_port": "Dst Port",
        "protocol": "Protocol",
        "timestamp": "Timestamp",
    },
}

CIC_DAY_FILES: dict[str, dict[str, list[str]]] = {
    "cicids2017": {
        "Monday": ["Monday-WorkingHours.pcap_ISCX.csv"],
        "Tuesday": ["Tuesday-WorkingHours.pcap_ISCX.csv"],
        "Wednesday": ["Wednesday-workingHours.pcap_ISCX.csv"],
        "Thursday": [
            "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        ],
        "Friday": [
            "Friday-WorkingHours-Morning.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        ],
    },
    "distrinet_cicids2017": {
        "Monday": ["monday.csv"],
        "Tuesday": ["tuesday.csv"],
        "Wednesday": ["wednesday.csv"],
        "Thursday": ["thursday.csv"],
        "Friday": ["friday.csv"],
    },
}

CIC2018_COLUMNS = {
    "label": "Label",
    "fwd_packets": "Tot Fwd Pkts",
    "bwd_packets": "Tot Bwd Pkts",
    "fwd_bytes": "TotLen Fwd Pkts",
    "bwd_bytes": "TotLen Bwd Pkts",
}

UNSW_COLUMNS = {
    "label": "attack_cat",
    "fwd_packets": "spkts",
    "bwd_packets": "dpkts",
    "fwd_bytes": "sbytes",
    "bwd_bytes": "dbytes",
}

PORTABLE_INPUT_KEYS = ("fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes")

# Duplicate detection hashes the complete behavioural row, not the eight model
# inputs. Distinct flows can share packet and byte counts (a SYN scan is the
# extreme case), and collapsing them would fabricate a tiny, easy evaluation
# set. Only per-flow identifiers and timestamps are excluded.
CIC_HASH_EXCLUDE: dict[str, tuple[str, ...]] = {
    "cicids2017": (
        "Flow ID",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Timestamp",
    ),
    "distrinet_cicids2017": (
        "id",
        "Flow ID",
        "Src IP",
        "Src Port",
        "Dst IP",
        "Timestamp",
    ),
}
CIC2018_HASH_EXCLUDE = ("Timestamp",)
UNSW_HASH_EXCLUDE = ("id",)


# ---------------------------------------------------------------------------
# Portable dataset container
# ---------------------------------------------------------------------------
@dataclass
class PortableDataset:
    """Portable matrices plus the labels needed to audit them.

    ``source_ip_codes`` / ``source_ip_values`` / ``timestamps`` are optional
    host-and-time metadata captured only when a caller asks for it. They are
    aligned row-for-row with ``matrix`` after duplicate removal, which is why
    they travel through the same dedup index rather than being joined later.
    """

    name: str
    matrix: np.ndarray
    labels: np.ndarray
    families: np.ndarray
    audit: dict[str, Any]
    counts: dict[str, dict[str, int]]
    raw_rows: int
    kept_rows_before_dedup: int
    duplicate_rows: int
    header_rows: int = 0
    days: np.ndarray | None = None
    groups: np.ndarray | None = None
    files: list[str] = field(default_factory=list)
    source_ip_codes: np.ndarray | None = None
    source_ip_values: list[str] = field(default_factory=list)
    timestamps: np.ndarray | None = None

    def subset(self, mask: np.ndarray) -> "PortableDataset":
        return PortableDataset(
            name=self.name,
            matrix=self.matrix[mask],
            labels=self.labels[mask],
            families=self.families[mask],
            audit=self.audit,
            counts=self.counts,
            raw_rows=int(mask.sum()),
            kept_rows_before_dedup=int(mask.sum()),
            duplicate_rows=0,
            header_rows=0,
            days=None if self.days is None else self.days[mask],
            groups=None if self.groups is None else self.groups[mask],
            files=self.files,
            source_ip_codes=(
                None if self.source_ip_codes is None else self.source_ip_codes[mask]
            ),
            source_ip_values=self.source_ip_values,
            timestamps=None if self.timestamps is None else self.timestamps[mask],
        )


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------
def _normalize_column(name: Any) -> str:
    return str(name).strip().lstrip("\ufeff")


def _iter_chunks(
    path: str,
    chunksize: int,
):
    """Yield normalised whole-row chunks.

    ``utf-8-sig`` strips a possible BOM. ``encoding_errors="replace"`` keeps a
    single non-UTF-8 byte (the Kaggle exports contain Windows-1252 en dashes in
    some out-of-scope web-attack rows) from aborting a multi-gigabyte read. All
    in-scope labels are ASCII, so replacement cannot change a scope decision.
    """
    return pd.read_csv(
        path,
        chunksize=chunksize,
        low_memory=False,
        encoding="utf-8-sig",
        encoding_errors="replace",
        on_bad_lines="skip",
    )


def _strip_columns(chunk: pd.DataFrame) -> pd.DataFrame:
    chunk.columns = [_normalize_column(column) for column in chunk.columns]
    return chunk


def _require_columns(chunk: pd.DataFrame, columns: Iterable[str], path: str) -> None:
    missing = [column for column in columns if column not in chunk.columns]
    if missing:
        raise KeyError(f"{os.path.basename(path)} is missing columns: {missing}")


def _numeric(frame: pd.DataFrame, column: str) -> np.ndarray:
    return pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=np.float64)


def _portable_from_frame(frame: pd.DataFrame, mapping: dict[str, str]) -> np.ndarray:
    return portable_matrix(
        _numeric(frame, mapping["fwd_packets"]),
        _numeric(frame, mapping["bwd_packets"]),
        _numeric(frame, mapping["fwd_bytes"]),
        _numeric(frame, mapping["bwd_bytes"]),
    )


def _row_hashes(frame: pd.DataFrame, exclude: Iterable[str]) -> np.ndarray:
    """Hash the complete behavioural row, excluding per-flow identifiers."""
    excluded = {_normalize_column(column) for column in exclude}
    columns = sorted(
        column for column in frame.columns if column not in excluded
    )
    if not columns:
        return np.zeros(len(frame), dtype=np.uint64)
    return (
        pd.util.hash_pandas_object(frame[columns], index=False)
        .astype("uint64")
        .to_numpy()
    )


def _deduplicate(
    matrix: np.ndarray,
    labels: np.ndarray,
    families: np.ndarray,
    days: np.ndarray | None,
    groups: np.ndarray | None,
    row_hashes: np.ndarray,
) -> tuple[
    np.ndarray, np.ndarray, np.ndarray, np.ndarray | None, np.ndarray | None, int, np.ndarray
]:
    """Drop exact duplicate rows using the full-row hash.

    The label is part of the hash basis, so two identical feature rows with
    different labels are both kept. A 64-bit collision is astronomically
    unlikely and would only merge two identical rows, never invent a label.

    Returns the surviving arrays plus the kept indices, so optional per-row
    metadata (source IP, timestamp) can be sliced with the same decision.
    """
    if len(matrix) == 0:
        empty = np.empty(0, dtype=np.int64)
        return matrix, labels, families, days, groups, 0, empty
    _, indices = np.unique(np.asarray(row_hashes, dtype=np.uint64), return_index=True)
    indices = np.asarray(indices, dtype=np.int64)
    indices.sort()
    duplicate_rows = int(len(matrix) - len(indices))
    return (
        matrix[indices],
        labels[indices],
        families[indices],
        None if days is None else days[indices],
        None if groups is None else groups[indices],
        duplicate_rows,
        indices,
    )


def _count_payload(labels: np.ndarray) -> dict[str, int]:
    return {
        "rows": int(len(labels)),
        "benign": int(np.sum(labels == 0)),
        "positive": int(np.sum(labels == 1)),
    }


# ---------------------------------------------------------------------------
# CIC-IDS-2017 loader
# ---------------------------------------------------------------------------
def load_cic2017_portable(
    data_dir: str,
    source: str = "cicids2017",
    chunksize: int = 250_000,
    max_rows_per_file: int | None = None,
    capture_metadata: bool = False,
) -> PortableDataset:
    """Load CIC-IDS-2017 by day into the portable schema with scope filtering.

    ``capture_metadata=True`` additionally keeps the source IP and the flow
    timestamp aligned with the surviving rows. The two arrays travel through
    the *same* dedup index as the matrix, so a row's host and time always
    belong to the row that survived duplicate removal. This is what makes a
    window evaluation reproducible instead of a best-effort re-join.

    ``Source IP`` is interned into ``int32`` codes with a value table: the
    full CIC-IDS-2017 export has millions of rows and only tens of thousands
    of distinct hosts, so keeping one Python string per row would waste
    hundreds of megabytes.

    ``timestamps`` are POSIX epoch **seconds** as ``float64``, with ``NaN`` for
    unparseable values.

    Timestamps are parsed with ``dayfirst=True``. The frozen Kaggle export
    mixes ``D/M/YYYY H:MM`` and ``DD/MM/YYYY HH:MM:SS`` and stores afternoon
    captures on a 12-hour clock without an AM/PM marker, so the absolute
    wall-clock is unreliable; within a single capture file the ordering and
    the spacing between flows are preserved.
    """
    if source not in CIC_DAY_FILES:
        raise KeyError(f"unknown CIC source {source!r}")
    mapping = CIC_SOURCE_COLUMNS[source]
    day_files = CIC_DAY_FILES[source]
    group_columns = [
        mapping["src_ip"],
        mapping["dst_ip"],
        mapping["src_port"],
        mapping["dst_port"],
        mapping["protocol"],
    ]
    needed = set(mapping.values()) | set(group_columns) | {"Label"}

    matrix_parts: list[np.ndarray] = []
    label_parts: list[np.ndarray] = []
    family_parts: list[np.ndarray] = []
    day_parts: list[np.ndarray] = []
    group_parts: list[np.ndarray] = []
    hash_parts: list[np.ndarray] = []
    ip_code_parts: list[np.ndarray] = []
    timestamp_parts: list[np.ndarray] = []
    ip_code_map: dict[str, int] = {}
    audits: list[dict[str, Any]] = []
    raw_rows = kept_rows = 0
    files: list[str] = []
    header_rows = 0

    for day in DAY_ORDER:
        for filename in day_files[day]:
            path = os.path.join(data_dir, filename)
            if not os.path.isfile(path):
                raise FileNotFoundError(path)
            files.append(filename)
            rows_in_file = 0
            for chunk in _iter_chunks(path, chunksize):
                if max_rows_per_file is not None:
                    remaining = max_rows_per_file - rows_in_file
                    if remaining <= 0:
                        break
                    chunk = chunk.head(remaining)
                rows_in_file += len(chunk)
                raw_rows += len(chunk)
                chunk = _strip_columns(chunk).reset_index(drop=True)
                _require_columns(chunk, needed, path)
                row_hashes = _row_hashes(chunk, CIC_HASH_EXCLUDE[source])

                filtered, audit = filter_matched_scope(chunk, source, mapping["label"])
                audits.append(audit)
                header_rows += int(audit["dropped_label_counts"].get("Label", 0))
                if filtered.empty:
                    continue
                kept_rows += len(filtered)
                kept_positions = filtered.index.to_numpy(dtype=np.int64)

                matrix_parts.append(_portable_from_frame(filtered, mapping))
                label_parts.append(
                    filtered[MATCHED_LABEL_COLUMN].to_numpy(dtype=np.int8)
                )
                family_parts.append(
                    filtered[NORMALIZED_LABEL_COLUMN].to_numpy(dtype=object)
                )
                day_parts.append(np.full(len(filtered), day, dtype=object))
                hash_parts.append(row_hashes[kept_positions])

                if capture_metadata:
                    hosts = filtered[mapping["src_ip"]].astype(str).to_numpy(dtype=object)
                    ip_code_parts.append(
                        np.fromiter(
                            (
                                ip_code_map.setdefault(host, len(ip_code_map))
                                for host in hosts
                            ),
                            dtype=np.int32,
                            count=len(hosts),
                        )
                    )
                    parsed = pd.to_datetime(
                        filtered[mapping["timestamp"]], dayfirst=True, errors="coerce"
                    )
                    # Store POSIX epoch *seconds*, not nanoseconds. The window
                    # bucket is ``floor(seconds / 300)``, so the unit is part of
                    # the contract; a silent ns/s mix-up turns a 300 s window
                    # into a 300 ns one.
                    epoch = (
                        parsed.to_numpy(dtype="datetime64[ns]")
                        .astype(np.int64)
                        .astype(np.float64)
                        / 1e9
                    )
                    epoch[parsed.isna().to_numpy()] = np.nan
                    timestamp_parts.append(epoch)

                group_frame = filtered[group_columns].astype(str)
                group_frame["__label"] = filtered[
                    NORMALIZED_LABEL_COLUMN
                ].to_numpy(dtype=object)
                group_parts.append(
                    pd.util.hash_pandas_object(group_frame, index=False).to_numpy(
                        dtype=np.uint64
                    )
                )

    if not matrix_parts:
        raise RuntimeError(f"no in-scope rows survived for {source}")

    matrix = np.concatenate(matrix_parts)
    labels = np.concatenate(label_parts)
    families = np.concatenate(family_parts)
    days = np.concatenate(day_parts)
    groups = np.concatenate(group_parts)
    row_hashes = np.concatenate(hash_parts)
    del matrix_parts, label_parts, family_parts, day_parts, group_parts, hash_parts

    ip_codes = np.concatenate(ip_code_parts) if capture_metadata else None
    timestamps = np.concatenate(timestamp_parts) if capture_metadata else None
    del ip_code_parts, timestamp_parts

    matrix, labels, families, days, groups, duplicates, kept = _deduplicate(
        matrix, labels, families, days, groups, row_hashes
    )
    if capture_metadata:
        source_ip_values = [None] * len(ip_code_map)
        for host, code in ip_code_map.items():
            source_ip_values[code] = host
        ip_codes = ip_codes[kept]
        timestamps = timestamps[kept]
    else:
        source_ip_values = []
    counts = {
        day: _count_payload(labels[days == day]) for day in DAY_ORDER
    }
    return PortableDataset(
        name=source,
        matrix=matrix,
        labels=labels,
        families=families,
        audit=merge_audits(audits),
        counts=counts,
        raw_rows=raw_rows,
        kept_rows_before_dedup=kept_rows,
        duplicate_rows=duplicates,
        header_rows=header_rows,
        days=days,
        groups=groups,
        files=files,
        source_ip_codes=ip_codes,
        source_ip_values=source_ip_values,
        timestamps=timestamps,
    )


# ---------------------------------------------------------------------------
# External loaders
# ---------------------------------------------------------------------------
def load_cic2018_portable(
    directory: str,
    chunksize: int = 250_000,
    max_rows_per_file: int | None = None,
) -> PortableDataset:
    """Load only matched-scope CIC-IDS-2018 rows into the portable schema."""
    files = sorted(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.lower().endswith(".csv")
    )
    if not files:
        raise FileNotFoundError(f"no CSV files in {directory}")

    matrix_parts: list[np.ndarray] = []
    label_parts: list[np.ndarray] = []
    family_parts: list[np.ndarray] = []
    hash_parts: list[np.ndarray] = []
    audits: list[dict[str, Any]] = []
    raw_rows = kept_rows = 0
    header_rows = 0

    for path in files:
        rows_in_file = 0
        for chunk in _iter_chunks(path, chunksize):
            if max_rows_per_file is not None:
                remaining = max_rows_per_file - rows_in_file
                if remaining <= 0:
                    break
                chunk = chunk.head(remaining)
            rows_in_file += len(chunk)
            raw_rows += len(chunk)
            chunk = _strip_columns(chunk).reset_index(drop=True)
            _require_columns(chunk, CIC2018_COLUMNS.values(), path)
            row_hashes = _row_hashes(chunk, CIC2018_HASH_EXCLUDE)

            filtered, audit = filter_matched_scope(
                chunk, "cicids2018", CIC2018_COLUMNS["label"]
            )
            audits.append(audit)
            header_rows += int(audit["dropped_label_counts"].get("Label", 0))
            if filtered.empty:
                continue
            kept_rows += len(filtered)
            kept_positions = filtered.index.to_numpy(dtype=np.int64)
            matrix_parts.append(_portable_from_frame(filtered, CIC2018_COLUMNS))
            label_parts.append(filtered[MATCHED_LABEL_COLUMN].to_numpy(dtype=np.int8))
            family_parts.append(
                filtered[NORMALIZED_LABEL_COLUMN].to_numpy(dtype=object)
            )
            hash_parts.append(row_hashes[kept_positions])

    if not matrix_parts:
        raise RuntimeError("no CIC-IDS-2018 rows survived the matched-scope filter")

    matrix = np.concatenate(matrix_parts)
    labels = np.concatenate(label_parts)
    families = np.concatenate(family_parts)
    row_hashes = np.concatenate(hash_parts)
    del matrix_parts, label_parts, family_parts, hash_parts
    matrix, labels, families, _, _, duplicates, _ = _deduplicate(
        matrix, labels, families, None, None, row_hashes
    )
    return PortableDataset(
        name="cicids2018",
        matrix=matrix,
        labels=labels,
        families=families,
        audit=merge_audits(audits),
        counts={"cicids2018": _count_payload(labels)},
        raw_rows=raw_rows,
        kept_rows_before_dedup=kept_rows,
        duplicate_rows=duplicates,
        header_rows=header_rows,
        files=[os.path.basename(path) for path in files],
    )


def load_unsw_portable(directory: str) -> PortableDataset:
    """Load the official UNSW-NB15 test split into the portable schema."""
    path = os.path.join(directory, "unsw_test_official.csv")
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    frame = pd.read_csv(
        path,
        low_memory=False,
        encoding="utf-8-sig",
        encoding_errors="replace",
    )
    frame = _strip_columns(frame).reset_index(drop=True)
    _require_columns(frame, UNSW_COLUMNS.values(), path)
    raw_rows = int(len(frame))

    row_hashes = _row_hashes(frame, UNSW_HASH_EXCLUDE)
    filtered, audit = filter_matched_scope(frame, "unsw_nb15", UNSW_COLUMNS["label"])
    if filtered.empty:
        raise RuntimeError("no UNSW-NB15 rows survived the matched-scope filter")
    kept_positions = filtered.index.to_numpy(dtype=np.int64)
    matrix = _portable_from_frame(filtered, UNSW_COLUMNS)
    labels = filtered[MATCHED_LABEL_COLUMN].to_numpy(dtype=np.int8)
    families = filtered[NORMALIZED_LABEL_COLUMN].to_numpy(dtype=object)
    matrix, labels, families, _, _, duplicates, _ = _deduplicate(
        matrix, labels, families, None, None, row_hashes[kept_positions]
    )
    return PortableDataset(
        name="unsw_nb15",
        matrix=matrix,
        labels=labels,
        families=families,
        audit=audit,
        counts={"unsw_nb15": _count_payload(labels)},
        raw_rows=raw_rows,
        kept_rows_before_dedup=int(audit["benign_rows"] + audit["positive_rows"]),
        duplicate_rows=duplicates,
        header_rows=0,
        files=[os.path.basename(path)],
    )


# ---------------------------------------------------------------------------
# Protocol split
# ---------------------------------------------------------------------------
@dataclass
class ProtocolSplit:
    """Leakage-safe masks plus the exact provenance of the executed protocol."""

    train_mask: np.ndarray
    calibration_mask: np.ndarray
    test_mask: np.ndarray
    provenance: str
    deviation: str | None
    strict: dict[str, Any]
    executed: dict[str, Any]
    group_overlap: int

    def as_payload(self) -> dict[str, Any]:
        return {
            "provenance": self.provenance,
            "deviation": self.deviation,
            "strict_requested": self.strict,
            "executed": self.executed,
            "train_calibration_group_overlap": self.group_overlap,
        }


def strict_protocol_status(dataset: PortableDataset) -> dict[str, Any]:
    """Report whether a literal Monday-Tuesday training split is fittable."""
    if dataset.days is None:
        raise ValueError("strict protocol requires day tags")
    mask = np.isin(dataset.days, TRAIN_DAYS)
    benign = int(np.sum(dataset.labels[mask] == 0))
    positive = int(np.sum(dataset.labels[mask] == 1))
    feasible = positive > 0 and benign > 0
    if feasible:
        reason = "Monday-Tuesday contains both benign and in-scope positive rows."
    elif positive == 0:
        reason = (
            "Monday-Tuesday contains zero in-scope positive rows: Monday is "
            "benign-only and Tuesday carries only FTP/SSH Patator, which the "
            "frozen policy excludes. A supervised classifier cannot be fitted."
        )
    else:
        reason = "Monday-Tuesday contains no benign rows."
    return {
        "train_days": list(TRAIN_DAYS),
        "calibration_days": list(CALIBRATION_DAYS),
        "test_days": list(TEST_DAYS),
        "rows": int(mask.sum()),
        "benign_rows": benign,
        "positive_rows": positive,
        "feasible": bool(feasible),
        "reason": reason,
    }


def build_protocol_split(dataset: PortableDataset) -> ProtocolSplit:
    """Build the strict day split or the documented Wednesday fallback.

    The strict protocol trains on Monday-Tuesday and calibrates on Wednesday.
    When that training partition has no positives, the fallback keeps every
    Monday-Tuesday benign row and assigns whole Wednesday groups to either
    training or calibration. Groups that appear on both Monday/Tuesday and the
    Wednesday calibration side are removed from training, so no group crosses
    the boundary.
    """
    if dataset.days is None or dataset.groups is None:
        raise ValueError("protocol split requires day and group tags")

    strict = strict_protocol_status(dataset)
    test_mask = np.isin(dataset.days, TEST_DAYS)
    if not np.any(test_mask):
        raise ValueError("test partition is empty")

    if strict["feasible"]:
        calibration_mask = np.isin(dataset.days, CALIBRATION_DAYS)
        calibration_groups = np.unique(dataset.groups[calibration_mask])
        # A 5-tuple+label group can recur on another day. Remove those groups
        # from training so the boundary stays group-disjoint even when the
        # requested day split is used.
        train_mask = np.isin(dataset.days, TRAIN_DAYS) & ~np.isin(
            dataset.groups, calibration_groups
        )
        provenance = "requested_day_split"
        deviation = None
        wednesday_train = np.zeros(len(dataset.labels), dtype=bool)
    else:
        wednesday = np.isin(dataset.days, CALIBRATION_DAYS)
        bucket = (dataset.groups % 100).astype(np.int16)
        wednesday_train = wednesday & (bucket < WEDNESDAY_TRAIN_BUCKETS)
        wednesday_calibration = wednesday & ~wednesday_train

        calibration_groups = np.unique(dataset.groups[wednesday_calibration])
        leaks_into_calibration = np.isin(dataset.groups, calibration_groups)
        train_mask = (
            np.isin(dataset.days, TRAIN_DAYS) & ~leaks_into_calibration
        ) | wednesday_train
        calibration_mask = wednesday_calibration
        provenance = "wednesday_group_split_fallback"
        deviation = (
            "The literal Monday-Tuesday training split has zero in-scope "
            "positives, so it cannot fit either candidate. Wednesday groups "
            "were split 70/30 by a deterministic group hash (group key: source "
            "and destination IP/port plus transport protocol plus normalised "
            "label), 70% joined the Monday-Tuesday benign rows in training and "
            "30% formed a disjoint calibration partition. Thursday-Friday and "
            "every external dataset were never used for fitting or threshold "
            "selection."
        )

    if np.any(train_mask & test_mask) or np.any(calibration_mask & test_mask):
        raise AssertionError("test rows leaked into training or calibration")
    if np.any(train_mask & calibration_mask):
        raise AssertionError("training and calibration masks overlap")

    overlap = int(
        len(
            np.intersect1d(
                np.unique(dataset.groups[train_mask]),
                np.unique(dataset.groups[calibration_mask]),
            )
        )
    )
    if overlap:
        raise AssertionError(f"{overlap} groups cross the training/calibration boundary")

    def _summary(mask: np.ndarray) -> dict[str, int]:
        return _count_payload(dataset.labels[mask])

    train_summary = _summary(train_mask)
    calibration_summary = _summary(calibration_mask)
    test_summary = _summary(test_mask)
    if train_summary["positive"] == 0 or train_summary["benign"] == 0:
        raise RuntimeError(
            f"training partition is not fittable: {train_summary}. A small "
            "--max-rows-per-file smoke limit can truncate the positive rows."
        )
    if calibration_summary["positive"] == 0 or calibration_summary["benign"] == 0:
        raise RuntimeError(
            f"calibration partition is not fittable: {calibration_summary}. A "
            "small --max-rows-per-file smoke limit can truncate the positive rows."
        )

    executed = {
        "train": train_summary,
        "calibration": calibration_summary,
        "test": test_summary,
        "train_days": list(TRAIN_DAYS)
        + (["Wednesday (70% of groups)"] if not strict["feasible"] else []),
        "calibration_days": ["Wednesday (30% of groups)"]
        if not strict["feasible"]
        else list(CALIBRATION_DAYS),
        "test_days": list(TEST_DAYS),
        "wednesday_train_rows": int(wednesday_train.sum()),
    }
    return ProtocolSplit(
        train_mask=train_mask,
        calibration_mask=calibration_mask,
        test_mask=test_mask,
        provenance=provenance,
        deviation=deviation,
        strict=strict,
        executed=executed,
        group_overlap=overlap,
    )


# ---------------------------------------------------------------------------
# Thresholds and metrics
# ---------------------------------------------------------------------------
def benign_fpr_threshold(
    probabilities: np.ndarray,
    target_fpr: float,
    *,
    strict: bool = True,
) -> float:
    """Select the ``1 - target_fpr`` quantile of benign scores.

    A valid operating point must be strictly between 0.001 and 0.99. A value
    outside that range means the score distribution saturates and the threshold
    would silence the detector (or alert on everything). ``strict=True`` raises
    the frozen guard; callers that need to *report* saturation use
    :func:`benign_fpr_threshold_report`.
    """
    scores = np.asarray(probabilities, dtype=np.float64)
    if scores.size == 0:
        raise ValueError("cannot select a threshold without benign scores")
    if not 0.0 < float(target_fpr) < 0.5:
        raise ValueError(f"target_fpr must be in (0, 0.5), got {target_fpr}")
    threshold = float(np.quantile(scores, 1.0 - float(target_fpr)))
    if strict:
        assert (
            THRESHOLD_FLOOR < threshold < THRESHOLD_CEILING
        ), f"Threshold saturation detected: {threshold}"
    return threshold


def benign_fpr_threshold_report(
    probabilities: np.ndarray,
    target_fpr: float,
) -> dict[str, Any]:
    """Return a threshold plus saturation diagnostics without raising."""
    scores = np.asarray(probabilities, dtype=np.float64)
    threshold = benign_fpr_threshold(scores, target_fpr, strict=False)
    saturated = not (THRESHOLD_FLOOR < threshold < THRESHOLD_CEILING)
    realized = float(np.mean(scores > threshold))
    return {
        "target_fpr": float(target_fpr),
        "threshold": threshold,
        "decision": "attack_probability > threshold",
        "benign_rows": int(scores.size),
        "benign_min": float(np.min(scores)),
        "benign_max": float(np.max(scores)),
        "benign_mean": float(np.mean(scores)),
        "realized_benign_fpr": realized,
        "saturated": bool(saturated),
        "guard": f"{THRESHOLD_FLOOR} < threshold < {THRESHOLD_CEILING}",
    }


def attack_probability(
    model: Any,
    matrix: np.ndarray,
    batch_size: int = 200_000,
) -> np.ndarray:
    """Return P(attack) regardless of the estimator's class ordering.

    Prediction is batched. A single ``predict_proba`` call on an external
    dataset with more than ten million rows allocates per-tree worker buffers
    that exceed this project's 8 GB test machine, and the process dies without
    a traceback. Batching bounds the transient allocation without changing any
    score.
    """
    classes = [int(value) for value in getattr(model, "classes_", [0, 1])]
    if 1 not in classes:
        return np.zeros(len(matrix), dtype=np.float64)
    column = classes.index(1)
    rows = len(matrix)
    if rows <= batch_size:
        probabilities = model.predict_proba(matrix)
        return np.asarray(probabilities[:, column], dtype=np.float64)
    scores = np.empty(rows, dtype=np.float64)
    for start in range(0, rows, batch_size):
        stop = min(start + batch_size, rows)
        probabilities = model.predict_proba(matrix[start:stop])
        scores[start:stop] = probabilities[:, column]
    return scores


def binary_metrics(
    labels: np.ndarray,
    scores: np.ndarray,
    threshold: float,
    *,
    comparison: str = ">",
) -> dict[str, Any]:
    """Compute ranking and operating-point metrics at one threshold."""
    truth = np.asarray(labels, dtype=np.int8)
    values = np.asarray(scores, dtype=np.float64)
    if len(truth) != len(values):
        raise ValueError("labels and scores must have equal length")
    predicted = values > threshold if comparison == ">" else values >= threshold

    tp = int(np.sum(predicted & (truth == 1)))
    fp = int(np.sum(predicted & (truth == 0)))
    tn = int(np.sum(~predicted & (truth == 0)))
    fn = int(np.sum(~predicted & (truth == 1)))
    positives = int(np.sum(truth == 1))
    negatives = int(np.sum(truth == 0))
    alerts = int(np.sum(predicted))
    rows = int(len(truth))

    roc_auc = (
        float(roc_auc_score(truth, values)) if 0 < positives < rows else None
    )
    pr_auc = (
        float(average_precision_score(truth, values))
        if 0 < positives < rows
        else None
    )
    return {
        "rows": rows,
        "benign_rows": negatives,
        "positive_rows": positives,
        "prevalence": float(positives / rows) if rows else None,
        "threshold": float(threshold),
        "comparison": comparison,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "alerts": alerts,
        "alert_rate": float(alerts / rows) if rows else None,
        "alerts_per_10k": float(alerts / rows * 10_000.0) if rows else None,
        "fpr": float(fp / negatives) if negatives else None,
        "precision": float(tp / alerts) if alerts else None,
        "recall": float(tp / positives) if positives else None,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
    }


def prevalence_subsample_indices(
    labels: np.ndarray,
    target_prevalence: float = 0.001,
    seed: int = SEED,
) -> tuple[np.ndarray, dict[str, Any]]:
    """Keep every benign row and deterministically downsample positives."""
    truth = np.asarray(labels, dtype=np.int8)
    if not 0.0 < float(target_prevalence) < 1.0:
        raise ValueError("target_prevalence must be in (0, 1)")
    negatives = np.flatnonzero(truth == 0)
    positives = np.flatnonzero(truth == 1)
    desired = int(
        round((float(target_prevalence) / (1.0 - float(target_prevalence))) * len(negatives))
    )
    sampled = min(desired, len(positives))
    rng = np.random.default_rng(seed)
    chosen = rng.choice(positives, size=sampled, replace=False) if sampled else np.empty(0, dtype=np.int64)
    chosen = np.sort(np.asarray(chosen, dtype=np.int64))
    indices = np.concatenate([negatives, chosen])
    realized = sampled / (sampled + len(negatives)) if len(negatives) else 0.0
    return indices, {
        "target_prevalence": float(target_prevalence),
        "benign_rows": int(len(negatives)),
        "positives_available": int(len(positives)),
        "positives_sampled": int(sampled),
        "positives_dropped": int(len(positives) - sampled),
        "realized_prevalence": float(realized),
        "seed": int(seed),
    }


# ---------------------------------------------------------------------------
# Candidate fitting
# ---------------------------------------------------------------------------
def fit_candidate_a(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_calibration: np.ndarray,
    y_calibration: np.ndarray,
) -> tuple[Any, dict[str, Any]]:
    """Regularised Random Forest wrapped in a prefit sigmoid calibrator."""
    base = RandomForestClassifier(**RF_PARAMS)
    base.fit(x_train, y_train)
    calibrated = CalibratedClassifierCV(
        estimator=base, method="sigmoid", cv="prefit"
    )
    calibrated.fit(x_calibration, y_calibration)
    metadata = {
        "name": "Candidate A",
        "estimator": "RandomForestClassifier",
        "params": dict(RF_PARAMS),
        "calibration": "sigmoid",
        "calibration_cv": "prefit",
        "calibration_rows": int(len(y_calibration)),
        "native_probabilities": False,
    }
    return calibrated, metadata


def fit_candidate_b(
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_calibration: np.ndarray,
    y_calibration: np.ndarray,
) -> tuple[Any, dict[str, Any]]:
    """Histogram gradient boosting with native log-loss probabilities."""
    model = HistGradientBoostingClassifier(**HGB_PARAMS)
    model.fit(x_train, y_train)
    metadata = {
        "name": "Candidate B",
        "estimator": "HistGradientBoostingClassifier",
        "params": dict(HGB_PARAMS),
        "calibration": "native_log_loss",
        "calibration_cv": None,
        "calibration_rows": int(len(y_calibration)),
        "native_probabilities": True,
    }
    return model, metadata


def feature_schema() -> dict[str, Any]:
    """Stable description of the portable feature contract."""
    import hashlib

    digest = hashlib.sha256(
        "\n".join(PORTABLE_FEATURE_NAMES).encode("utf-8")
    ).hexdigest()
    return {
        "version": "portable-ratio-v1",
        "features": list(PORTABLE_FEATURE_NAMES),
        "count": len(PORTABLE_FEATURE_NAMES),
        "sha256": digest,
    }


__all__ = [
    "CALIBRATION_DAYS",
    "CIC2018_COLUMNS",
    "CIC_DAY_FILES",
    "CIC_SOURCE_COLUMNS",
    "DAY_ORDER",
    "HGB_PARAMS",
    "PORTABLE_INPUT_KEYS",
    "ProtocolSplit",
    "PortableDataset",
    "RF_PARAMS",
    "SEED",
    "TARGET_FPRS",
    "TEST_DAYS",
    "TRAIN_DAYS",
    "UNSW_COLUMNS",
    "attack_probability",
    "benign_fpr_threshold",
    "benign_fpr_threshold_report",
    "binary_metrics",
    "build_protocol_split",
    "feature_schema",
    "fit_candidate_a",
    "fit_candidate_b",
    "load_cic2017_portable",
    "load_cic2018_portable",
    "load_unsw_portable",
    "prevalence_subsample_indices",
    "strict_protocol_status",
]
