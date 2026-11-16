"""Protocol-invariant, ratio-only features for cross-dataset transfer.

The frozen Tier A schema (``docs/PORTABLE_FEATURES.md``) is portable at the
*column availability* level, but several of its columns are still raw
scale-dependent measurements: duration, packet counts, byte counts, and packet
rates. A model trained on those columns can separate attack families by
memorising capture-specific magnitudes (CICFlowMeter timing artifacts, lab
link speeds, dataset-specific flow timeouts) instead of attack behaviour.

This module derives a smaller schema from the same Tier A inputs using only
bounded ratios and log-scaled per-packet quantities. It is intentionally
computed from the four Tier A columns that are present in CIC-IDS-2017,
CIC-IDS-2018, and UNSW-NB15, so no median imputation is required and no
missing-value indicator can leak the dataset identity.

The transform is deterministic and has no fitted parameters. It does not
change the serving artifact, the frozen Tier A schema, or any existing report.
"""

from __future__ import annotations

import hashlib
from typing import Iterable

import numpy as np
import pandas as pd

PORTABLE_FEATURE_VERSION = "portable-ratio-v1"

# Eight features are ratios or log-scaled per-packet quantities. Redundant
# complements (backward packet/byte ratios) are omitted because they are exact
# functions of the forward ratios and only split tree importance arbitrarily.
PORTABLE_FEATURE_NAMES = (
    "log_bytes_per_packet",
    "log_fwd_bytes_per_packet",
    "log_bwd_bytes_per_packet",
    "fwd_packet_ratio",
    "packet_count_balance",
    "fwd_byte_ratio",
    "log_down_up_ratio",
    "packet_size_asymmetry",
)

# Inputs used by the transform. All four are available in the three datasets
# used by the P3 transfer protocol; no flag, packet-length-max, or duration
# column is required.
PORTABLE_INPUT_COLUMNS = (
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
)


def _clean(values: np.ndarray) -> np.ndarray:
    array = np.asarray(values, dtype=np.float64)
    return np.where(np.isfinite(array) & (array >= 0.0), array, 0.0)


def _safe_ratio(numerator: np.ndarray, denominator: np.ndarray) -> np.ndarray:
    result = np.divide(
        numerator,
        denominator,
        out=np.zeros_like(numerator, dtype=np.float64),
        where=denominator > 0.0,
    )
    return np.clip(np.nan_to_num(result, nan=0.0, posinf=0.0, neginf=0.0), 0.0, 1.0)


def portable_matrix(
    fwd_packets: np.ndarray,
    bwd_packets: np.ndarray,
    fwd_bytes: np.ndarray,
    bwd_bytes: np.ndarray,
) -> np.ndarray:
    """Return the eight portable features in ``PORTABLE_FEATURE_NAMES`` order."""
    fwd_packets = _clean(fwd_packets)
    bwd_packets = _clean(bwd_packets)
    fwd_bytes = _clean(fwd_bytes)
    bwd_bytes = _clean(bwd_bytes)

    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes

    total_per_packet = np.divide(
        total_bytes,
        total_packets,
        out=np.zeros_like(total_bytes),
        where=total_packets > 0.0,
    )
    fwd_per_packet = np.divide(
        fwd_bytes,
        fwd_packets,
        out=np.zeros_like(fwd_bytes),
        where=fwd_packets > 0.0,
    )
    bwd_per_packet = np.divide(
        bwd_bytes,
        bwd_packets,
        out=np.zeros_like(bwd_bytes),
        where=bwd_packets > 0.0,
    )

    packet_max = np.maximum(fwd_packets, bwd_packets)
    packet_min = np.minimum(fwd_packets, bwd_packets)
    packet_count_balance = np.divide(
        packet_min,
        packet_max,
        out=np.zeros_like(packet_max),
        where=packet_max > 0.0,
    )

    packet_sum = fwd_per_packet + bwd_per_packet
    packet_size_asymmetry = np.divide(
        np.abs(fwd_per_packet - bwd_per_packet),
        packet_sum,
        out=np.zeros_like(packet_sum),
        where=packet_sum > 0.0,
    )

    # Down/up byte ratio. The epsilon must be relative, not an absolute +1, or
    # the feature stops being scale-invariant for small flows. fwd_bytes == 0
    # is capped at 1e6 (log1p ~ 13.8) so a one-direction flow stays finite.
    down_up = np.divide(
        bwd_bytes,
        fwd_bytes,
        out=np.zeros_like(bwd_bytes),
        where=fwd_bytes > 0.0,
    )
    down_up = np.where(
        (fwd_bytes == 0.0) & (bwd_bytes > 0.0), 1e6, down_up
    )
    down_up = np.clip(np.nan_to_num(down_up, nan=0.0, posinf=1e6), 0.0, 1e6)

    matrix = np.column_stack(
        [
            np.log1p(total_per_packet),
            np.log1p(fwd_per_packet),
            np.log1p(bwd_per_packet),
            _safe_ratio(fwd_packets, total_packets),
            packet_count_balance,
            _safe_ratio(fwd_bytes, total_bytes),
            np.log1p(down_up),
            packet_size_asymmetry,
        ]
    ).astype(np.float32)
    return np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)


def portable_matrix_from_tier_a(
    matrix: np.ndarray,
    tier_a_columns: Iterable[str],
) -> np.ndarray:
    """Convert a Tier A matrix (or DataFrame) to the portable schema.

    ``tier_a_columns`` must contain the four ``PORTABLE_INPUT_COLUMNS``. Extra
    columns are ignored, so a caller can pass the frozen 12-column Tier A array
    unchanged.
    """
    columns = list(tier_a_columns)
    missing = [name for name in PORTABLE_INPUT_COLUMNS if name not in columns]
    if missing:
        raise KeyError(f"portable transform is missing Tier A columns: {missing}")
    if isinstance(matrix, pd.DataFrame):
        values = matrix[list(PORTABLE_INPUT_COLUMNS)].to_numpy(dtype=np.float64)
    else:
        array = np.asarray(matrix)
        if array.ndim != 2:
            raise ValueError("matrix must be two-dimensional")
        index = [columns.index(name) for name in PORTABLE_INPUT_COLUMNS]
        values = array[:, index].astype(np.float64)
    return portable_matrix(
        fwd_packets=values[:, 0],
        bwd_packets=values[:, 1],
        fwd_bytes=values[:, 2],
        bwd_bytes=values[:, 3],
    )


def portable_dataframe(frame: pd.DataFrame) -> pd.DataFrame:
    """Return a named portable-feature DataFrame from a Tier A-style frame."""
    matrix = portable_matrix_from_tier_a(frame, frame.columns)
    return pd.DataFrame(matrix, columns=list(PORTABLE_FEATURE_NAMES), index=frame.index)


def schema_payload() -> dict:
    """Stable description used by manifests and reports."""
    digest = hashlib.sha256("\n".join(PORTABLE_FEATURE_NAMES).encode("utf-8")).hexdigest()
    return {
        "version": PORTABLE_FEATURE_VERSION,
        "features": list(PORTABLE_FEATURE_NAMES),
        "count": len(PORTABLE_FEATURE_NAMES),
        "inputs": list(PORTABLE_INPUT_COLUMNS),
        "sha256": digest,
    }
