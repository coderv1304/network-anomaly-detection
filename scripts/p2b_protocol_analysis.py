#!/usr/bin/env python
"""P2B protocol analysis: family-day confound audit.

P2B is supposed to train on Monday-Tuesday, validate on Wednesday, and test on
Thursday-Friday. This script records two independent reasons that the
preregistered split cannot identify the requested supervised comparison:

1. Monday-Tuesday contains zero volumetric/scanning positives.
2. The volumetric families are separated by day and by time. Wednesday's
   validation positives are the four DoS families; Friday's test positives are
   DDoS and PortScan. A time-ordered Wednesday split is therefore also a family
   split, not a random or representative train/validation split.

The script does not train a model, does not write a registry row, and does not
touch the serving artifact. It produces the evidence used by
``docs/P2B_PROTOCOL_ANALYSIS.md``.

Examples:
    python scripts/p2b_protocol_analysis.py \
        --output docs/p2b_protocol_analysis.json
"""

from __future__ import annotations

import argparse
import collections
import gc
import json
import os
import sys
from typing import Any, Iterable

import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.evaluate import CIC_DAYS  # noqa: E402
from scripts.rule_baselines import (  # noqa: E402
    EXCLUDED_LABELS,
    NEGATIVE_LABELS,
    POSITIVE_LABELS,
    _read_raw_label_counts,
    _sha256_file,
)

ARTIFACT_VERSION = "p2b-protocol-analysis-v1"
P2A_ARTIFACT = os.path.join(PROJECT_ROOT, "docs", "rule_baselines.json")
P2B_AUDIT_ARTIFACT = os.path.join(PROJECT_ROOT, "docs", "VOLUMETRIC_MODEL.json")
SERVING_ARTIFACT = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_day_based_seed42.pkl"
)
WEDNESDAY_FILE = os.path.join(
    PROJECT_ROOT, "data", CIC_DAYS["Wednesday"][0]
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def _counts(labels: np.ndarray) -> dict[str, int]:
    return {
        str(label): int(count)
        for label, count in sorted(collections.Counter(labels).items())
    }


def _primary_positives(
    counts: dict[str, int],
    positive_labels: Iterable[str] | None = None,
) -> int:
    labels = POSITIVE_LABELS if positive_labels is None else positive_labels
    return int(sum(counts.get(label, 0) for label in labels))


def _positive_families(
    counts: dict[str, int],
    positive_labels: Iterable[str] | None = None,
) -> list[str]:
    labels = POSITIVE_LABELS if positive_labels is None else positive_labels
    return sorted(label for label in counts if label in labels)


def family_day_matrix(
    train_counts: dict[str, int],
    validation_counts: dict[str, int],
    test_counts: dict[str, int],
    positive_labels: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Build the partition x family matrix and flag disjoint positive families.

    ``positive_labels`` defaults to the CIC-IDS-2017 policy. External datasets
    pass their own positive-family set so the same matrix and gate can be reused.
    """
    partitions = {
        "train": train_counts,
        "validation": validation_counts,
        "test": test_counts,
    }
    positive_families = {
        name: _positive_families(counts, positive_labels)
        for name, counts in partitions.items()
    }
    train_positive = set(positive_families["train"])
    validation_positive = set(positive_families["validation"])
    test_positive = set(positive_families["test"])
    return {
        "partitions": {
            name: {
                "label_counts": dict(sorted(counts.items())),
                "primary_positives": _primary_positives(counts, positive_labels),
                "primary_positive_families": positive_families[name],
            }
            for name, counts in partitions.items()
        },
        "train_validation_overlap": sorted(train_positive & validation_positive),
        "train_test_overlap": sorted(train_positive & test_positive),
        "validation_test_overlap": sorted(validation_positive & test_positive),
        "validation_test_disjoint": not (validation_positive & test_positive),
        "train_has_primary_positives": bool(train_positive),
    }


def family_time_ranges(
    labels: np.ndarray, timestamps: np.ndarray
) -> dict[str, dict[str, Any]]:
    """Per-label count and first/last timestamp, sorted by first appearance."""
    labels = np.asarray(labels, dtype=object)
    stamps = pd.to_datetime(pd.Series(timestamps), errors="coerce")
    valid = stamps.notna().to_numpy()
    result: dict[str, dict[str, Any]] = {}
    for label in sorted(set(labels)):
        mask = (labels == label) & valid
        count = int(mask.sum())
        if count == 0:
            continue
        first = stamps[mask].min()
        last = stamps[mask].max()
        result[str(label)] = {
            "count": count,
            "first": first.isoformat(),
            "last": last.isoformat(),
            "is_primary": label in POSITIVE_LABELS,
        }
    return dict(
        sorted(result.items(), key=lambda item: (item[1]["first"], item[0]))
    )


def time_split(
    labels: np.ndarray,
    timestamps: np.ndarray,
    fraction: float = 0.5,
) -> dict[str, Any]:
    """Sort by timestamp and split the first ``fraction`` of rows from the rest."""
    if not 0.0 < fraction < 1.0:
        raise ValueError("fraction must be in (0, 1)")
    labels = np.asarray(labels, dtype=object)
    stamps = pd.to_datetime(pd.Series(timestamps), errors="coerce").to_numpy(
        dtype="datetime64[ns]"
    )
    order = np.argsort(stamps.astype("int64"), kind="mergesort")
    cut = int(len(order) * fraction)
    train_idx = order[:cut]
    validation_idx = order[cut:]
    train_counts = _counts(labels[train_idx])
    validation_counts = _counts(labels[validation_idx])
    return {
        "rule": (
            f"stable sort by Timestamp; first {fraction:.0%} of rows are train, "
            "the remainder is validation"
        ),
        "fraction": fraction,
        "cut_timestamp": pd.Timestamp(stamps[order[cut]]).isoformat()
        if cut < len(order)
        else None,
        "train": {
            "rows": int(len(train_idx)),
            "label_counts": train_counts,
            "primary_positives": _primary_positives(train_counts),
            "primary_positive_families": _positive_families(train_counts),
        },
        "validation": {
            "rows": int(len(validation_idx)),
            "label_counts": validation_counts,
            "primary_positives": _primary_positives(validation_counts),
            "primary_positive_families": _positive_families(validation_counts),
        },
    }


def expanding_folds(
    labels: np.ndarray, timestamps: np.ndarray, n_folds: int = 3
) -> dict[str, Any]:
    """Split sorted rows into contiguous time folds for expanding-window CV."""
    if n_folds < 2:
        raise ValueError("n_folds must be at least 2")
    labels = np.asarray(labels, dtype=object)
    stamps = pd.to_datetime(pd.Series(timestamps), errors="coerce").to_numpy(
        dtype="datetime64[ns]"
    )
    order = np.argsort(stamps.astype("int64"), kind="mergesort")
    ordered_labels = labels[order]
    ordered_stamps = stamps[order]
    n = len(order)
    boundaries = [(index * n) // n_folds for index in range(n_folds + 1)]
    folds = []
    for index in range(n_folds):
        start, stop = boundaries[index], boundaries[index + 1]
        counts = _counts(ordered_labels[start:stop])
        folds.append(
            {
                "fold": index + 1,
                "start": pd.Timestamp(ordered_stamps[start]).isoformat()
                if start < n
                else None,
                "end": pd.Timestamp(ordered_stamps[stop - 1]).isoformat()
                if stop > start
                else None,
                "rows": int(stop - start),
                "label_counts": counts,
                "primary_positives": _primary_positives(counts),
                "primary_positive_families": _positive_families(counts),
            }
        )
    return {
        "rule": (
            "stable sort by Timestamp; split into contiguous folds by row count; "
            "expanding-window CV fits earlier folds and validates on the next"
        ),
        "n_folds": n_folds,
        "folds": folds,
    }


def coverage_gate(
    matrix: dict[str, Any],
    minimums: dict[str, int] | None = None,
    positive_labels: Iterable[str] | None = None,
    required_families: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Check that each evaluated positive family is present in every partition.

    This is a feasibility gate, not a power gate. The default minimum is one
    positive row per partition. A separate minimum-reportable-count rule handles
    statistical precision. A family that appears only in test fails the gate.

    ``positive_labels`` defaults to the CIC-IDS-2017 policy; external datasets
    pass their own positive-family set. ``required_families`` names families that
    must be covered even if the dataset never contains them. A required family
    with zero rows in every partition is reported as unobserved and fails.
    """
    minimums = minimums or {"train": 1, "validation": 1, "test": 1}
    labels = POSITIVE_LABELS if positive_labels is None else positive_labels
    partitions = matrix["partitions"]
    observed = {
        label
        for name in ("train", "validation", "test")
        for label in partitions[name]["label_counts"]
        if label in labels
    }
    required = set(required_families or ())
    families = sorted(observed | required)
    rows: dict[str, Any] = {}
    for family in families:
        counts = {
            name: int(partitions[name]["label_counts"].get(family, 0))
            for name in ("train", "validation", "test")
        }
        passes = all(counts[name] >= minimums[name] for name in minimums)
        rows[family] = {
            **counts,
            "observed": family in observed,
            "required": family in required,
            "pass": bool(passes),
        }
    missing_required = sorted(family for family in required if family not in observed)
    overall = (
        bool(rows)
        and all(row["pass"] for row in rows.values())
        and not matrix["validation_test_disjoint"]
    )
    if overall:
        reason = (
            "Every positive family is present in train, validation, and test, "
            "and validation/test families overlap."
        )
    else:
        failures: list[str] = []
        if missing_required:
            failures.append(
                "Required families are absent from the dataset: "
                + ", ".join(missing_required)
                + "."
            )
        partition_failures = [
            family
            for family in families
            if family not in missing_required and not rows[family]["pass"]
        ]
        if partition_failures:
            failures.append(
                "Families absent from at least one partition: "
                + ", ".join(partition_failures)
                + "."
            )
        if matrix["validation_test_disjoint"]:
            failures.append(
                "Validation and test positive families do not overlap."
            )
        reason = " ".join(failures) or (
            "At least one positive family is absent from a partition, or the "
            "validation and test positive families do not overlap."
        )
    return {
        "minimums": dict(minimums),
        "families": rows,
        "missing_required": missing_required,
        "overall_pass": bool(overall),
        "reason": reason,
    }


def build_findings(payload: dict[str, Any]) -> list[str]:
    matrix = payload["family_day_matrix"]
    half = payload["half_split"]
    folds = payload["expanding_folds"]["folds"]
    validation_families = matrix["partitions"]["validation"][
        "primary_positive_families"
    ]
    test_families = matrix["partitions"]["test"]["primary_positive_families"]
    train_positives = matrix["partitions"]["train"]["primary_positives"]
    first_fold = folds[0]
    return [
        (
            f"The training partition contains {train_positives:,} primary "
            "volumetric/scanning positives. No supervised binary head can be "
            "fitted on Monday-Tuesday without changing the label policy or the split."
        ),
        (
            "Validation positives are "
            + ", ".join(validation_families)
            + "; test positives are "
            + ", ".join(test_families)
            + ". The positive-family sets are disjoint: a threshold selected on "
            "Wednesday DoS traffic is applied zero-shot to Friday DDoS/PortScan."
        ),
        (
            "Wednesday's primary families occupy disjoint time windows. A "
            "time-ordered split is therefore also a family split, not a "
            "representative sample of the target families."
        ),
        (
            "A 50/50 time split trains on "
            + ", ".join(half["train"]["primary_positive_families"])
            + " and validates on "
            + ", ".join(half["validation"]["primary_positive_families"])
            + f" ({half['train']['primary_positives']:,} train positives and "
            f"{half['validation']['primary_positives']:,} validation positives)."
        ),
        (
            f"The first expanding-window fold contains only "
            f"{first_fold['primary_positives']:,} primary positives "
            f"({', '.join(first_fold['primary_positive_families']) or 'none'}), "
            "which is too small to train or calibrate a supervised model."
        ),
        (
            "No threshold for DDoS or PortScan can be selected on Wednesday because "
            "those families do not appear there. Their test metrics are zero-shot "
            "descriptors, not validated operating points."
        ),
        (
            "A1 as originally proposed (early Wednesday train, late Wednesday "
            "validation) is rejected as a primary P2B protocol. It is a cross-family "
            "zero-shot experiment and would not answer the requested comparison."
        ),
        (
            "The proposed coverage gate fails for "
            + ", ".join(
                family
                for family, row in payload["coverage_gate"]["families"].items()
                if not row["pass"]
            )
            + ". No evaluated family is present in train, validation, and test."
        ),
    ]


def build_options() -> list[dict[str, str]]:
    return [
        {
            "id": "A1",
            "name": "Early/late Wednesday holdout",
            "verdict": "rejected as primary; family split",
            "reason": (
                "Trains on slowloris/Slowhttptest and validates on Hulk/GoldenEye; "
                "DDoS/PortScan still have no training or validation rows."
            ),
        },
        {
            "id": "A1f",
            "name": "Wednesday expanding-window CV with out-of-fold thresholds",
            "verdict": "exploratory only",
            "reason": (
                "Uses all Wednesday rows for training and threshold selection, but "
                "the first fold has few positives and the test families remain "
                "unseen. The claim must be labelled cross-family zero-shot."
            ),
        },
        {
            "id": "A2",
            "name": "Unsupervised IsolationForest on Monday-Tuesday",
            "verdict": "fallback only",
            "reason": (
                "No positives are needed, but it cannot answer rules-vs-supervised "
                "and its Friday metrics are also zero-shot."
            ),
        },
        {
            "id": "A3",
            "name": "Move Wednesday into training",
            "verdict": "rejected",
            "reason": (
                "Removes the validation partition and still leaves DDoS/PortScan "
                "test-only."
            ),
        },
        {
            "id": "A4",
            "name": "External volumetric/scanning data",
            "verdict": "preferred",
            "reason": (
                "The only option that can provide positives in train and validation "
                "for the families that are tested. Requires data, licensing, and "
                "human approval."
            ),
        },
    ]


# ---------------------------------------------------------------------------
# Audit assembly
# ---------------------------------------------------------------------------
def _load_json(path: str, label: str) -> dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"{label} is missing: {path}")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _wednesday_frame() -> tuple[np.ndarray, np.ndarray, int, int]:
    """Load the frozen Wednesday partition and return labels, timestamps, rows."""
    # ``load_partition`` only returns Tier A features, so the timestamp must be
    # read from the same frozen loader before feature extraction. Use the
    # threshold-calibration helper directly to keep the split identical.
    from training.threshold_calibration_v2 import _load_partition

    frame = _load_partition({"Wednesday": CIC_DAYS["Wednesday"]})
    labels = frame["__label"].to_numpy(dtype=object)
    timestamps = pd.to_datetime(
        frame["Timestamp"], errors="coerce", dayfirst=True
    ).to_numpy(dtype="datetime64[ns]")
    rows = int(len(frame))
    del frame
    gc.collect()
    return labels, timestamps, rows


def build_payload() -> dict[str, Any]:
    p2a = _load_json(P2A_ARTIFACT, "P2A artifact")
    p2b = _load_json(P2B_AUDIT_ARTIFACT, "P2B audit artifact")

    train_counts = p2b["partitions"]["train"]["label_counts"]
    validation_counts = p2a["partitions"]["validation"]["label_counts"]
    test_counts = p2a["partitions"]["test"]["label_counts"]

    print("loading frozen Wednesday partition", flush=True)
    labels, timestamps, frozen_rows = _wednesday_frame()
    raw_rows = sum(_read_raw_label_counts(WEDNESDAY_FILE).values())

    profile = family_time_ranges(labels, timestamps)
    half = time_split(labels, timestamps, 0.5)
    folds = expanding_folds(labels, timestamps, 3)
    matrix = family_day_matrix(train_counts, validation_counts, test_counts)

    payload: dict[str, Any] = {
        "artifact_version": ARTIFACT_VERSION,
        "method": "family_day_confound_audit",
        "status": "infeasible_under_preregistered_split",
        "scope": (
            "Flow-based detector for volumetric and scanning behavior. "
            "Not a general NIDS. Botnet, web attacks, infiltration, zero-day, "
            "and blocking are out of scope."
        ),
        "label_policy": {
            "positive_labels": sorted(POSITIVE_LABELS),
            "negative_labels": sorted(NEGATIVE_LABELS),
            "excluded_labels": dict(sorted(EXCLUDED_LABELS.items())),
        },
        "family_day_matrix": matrix,
        "coverage_gate": coverage_gate(matrix),
        "wednesday_time_profile": {
            "source_file": os.path.relpath(WEDNESDAY_FILE, PROJECT_ROOT).replace(
                "\\", "/"
            ),
            "raw_rows": int(raw_rows),
            "frozen_rows": int(frozen_rows),
            "dedup_removed_rows": int(raw_rows - frozen_rows),
            "timestamp_min": str(pd.Timestamp(timestamps.min()).isoformat()),
            "timestamp_max": str(pd.Timestamp(timestamps.max()).isoformat()),
            "families": profile,
        },
        "half_split": half,
        "expanding_folds": folds,
        "decision": {
            "p2b_status": "blocked",
            "execute_a1_as_proposed": False,
            "preferred_option": "A4",
            "conditional_exploratory_option": "A1f",
            "reason": (
                "The preregistered split cannot identify the supervised comparison: "
                "the training partition has no target positives, validation and test "
                "positive families are disjoint, and Wednesday's families are "
                "time-separated. A time-ordered amendment would be a family split."
            ),
        },
        "options": build_options(),
        "artifact_identity": {
            "p2a_artifact": os.path.relpath(P2A_ARTIFACT, PROJECT_ROOT).replace(
                "\\", "/"
            ),
            "p2a_sha256": _sha256_file(P2A_ARTIFACT),
            "p2b_audit_artifact": os.path.relpath(
                P2B_AUDIT_ARTIFACT, PROJECT_ROOT
            ).replace("\\", "/"),
            "p2b_audit_sha256": _sha256_file(P2B_AUDIT_ARTIFACT),
            "serving_artifact": os.path.relpath(SERVING_ARTIFACT, PROJECT_ROOT).replace(
                "\\", "/"
            ),
            "serving_sha256": _sha256_file(SERVING_ARTIFACT)
            if os.path.exists(SERVING_ARTIFACT)
            else None,
            "wednesday_source_sha256": _sha256_file(WEDNESDAY_FILE),
        },
        "notes": [
            "No model is trained, no registry row is written, and the serving artifact is untouched.",
            "The family-day matrix uses the frozen partition label counts from the P2A and P2B audit artifacts.",
            "The Wednesday time profile uses the frozen loader; raw and frozen row counts are both reported.",
            "A time-ordered split is a family split because the CIC-IDS-2017 campaigns are sequential.",
            "DDoS and PortScan appear only in the test partition, so their thresholds cannot be selected on Wednesday.",
            "A1f and A2 are exploratory fallbacks; they do not satisfy the preregistered P2B mission.",
        ],
    }
    payload["findings"] = build_findings(payload)
    return payload


def run(output: str) -> dict[str, Any]:
    payload = build_payload()
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, allow_nan=False)
        handle.write("\n")
    print(f"wrote {output}", flush=True)
    return payload


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", default="docs/p2b_protocol_analysis.json"
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    run(output=args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
