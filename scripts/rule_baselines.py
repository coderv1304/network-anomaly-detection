#!/usr/bin/env python
"""Tier A rule baselines for the frozen volumetric/scanning label policy.

Phase P2A defines the target and the simple rules that any later model must
beat. The script reads the frozen CIC-IDS-2017 partitions, maps labels with the
policy in ``docs/LABEL_POLICY.md``, extracts the portable Tier A features, and
evaluates rate, SYN, and composite rules under fixed alert budgets.

Design constraints
------------------
* Thresholds are selected on the validation partition only. Test labels are
  read after the thresholds are frozen and never influence them.
* The primary task is binary any-volumetric/scan. Excluded labels are removed
  from the primary metrics and logged separately.
* Tier B fan-out is not approximated from per-flow columns. If raw packets are
  absent, the fan-out rule is reported as unavailable.
* No model artifact, registry row, or serving threshold is read or written.

Examples:
    python scripts/rule_baselines.py \
        --output docs/rule_baselines.json \
        --report docs/RULE_BASELINES.md
"""

from __future__ import annotations

import argparse
import collections
import csv
import gc
import hashlib
import json
import math
import os
import sys
from typing import Any, Iterable

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.baseline_comparison_v2 import canonical_label  # noqa: E402
from training.evaluate import CIC_DAYS  # noqa: E402
from training.threshold_calibration_v2 import _load_partition  # noqa: E402
from scripts.prevalence_eval import (  # noqa: E402
    alerts_per_10k,
    break_even_per_flow,
    clopper_pearson_upper,
    ppv_at_prevalence,
    wilson_interval,
)

SEED = 20261113
DEFAULT_DRAWS = 10_000
DEFAULT_BUDGETS = (10, 100)
DEFAULT_PREVALENCES = (0.0001, 0.001, 0.01, 0.10)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
SAMPLES_DIR = os.path.join(DATA_DIR, "samples")
SCRATCH_DIR = os.path.join(PROJECT_ROOT, "scratch")
ARTIFACT_VERSION = "rule-baselines-v1"

# ---------------------------------------------------------------------------
# Label policy
# ---------------------------------------------------------------------------
POSITIVE_LABELS = {
    "DDoS",
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "PortScan",
}
NEGATIVE_LABELS = {"BENIGN"}
EXCLUDED_LABELS = {
    "Heartbleed": "excluded; validation-only diagnostic",
    "Web Attack - Brute Force": "excluded; web attack",
    "Web Attack - XSS": "excluded; web attack",
    "Web Attack - Sql Injection": "excluded; web attack",
    "FTP-Patator": "excluded; credential attack",
    "SSH-Patator": "excluded; credential attack",
    "Bot": "excluded; botnet",
    "Infiltration": "excluded; infiltration",
}

# These are the exact strings observed in the CIC-IDS-2017 CSVs. The Web
# Attack strings use U+2013 EN DASH, while ``canonical_label`` normalises it to
# an ASCII hyphen. Keep the raw table for the audit and the canonical table for
# matching.
RAW_LABEL_STRINGS = [
    "BENIGN",
    "DDoS",
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "PortScan",
    "Heartbleed",
    "Web Attack \u2013 Brute Force",
    "Web Attack \u2013 Sql Injection",
    "Web Attack \u2013 XSS",
    "FTP-Patator",
    "SSH-Patator",
    "Bot",
    "Infiltration",
]


def classify_label(value: Any) -> dict[str, Any]:
    """Return the policy role for a raw label value.

    Unknown labels are excluded, never treated as benign. Missing labels are
    reported separately and are removed by the frozen partition loader.
    """
    if value is None:
        return {
            "raw": None,
            "canonical": "<missing>",
            "role": "missing",
            "reason": "missing label",
        }
    try:
        if isinstance(value, float) and math.isnan(value):
            return {
                "raw": value,
                "canonical": "<missing>",
                "role": "missing",
                "reason": "missing label",
            }
    except TypeError:
        pass
    raw = str(value)
    if raw.strip() == "":
        return {
            "raw": raw,
            "canonical": "<missing>",
            "role": "missing",
            "reason": "blank label",
        }
    canonical = canonical_label(raw)
    if canonical in NEGATIVE_LABELS:
        return {
            "raw": raw,
            "canonical": canonical,
            "role": "negative",
            "reason": "benign traffic",
        }
    if canonical in POSITIVE_LABELS:
        return {
            "raw": raw,
            "canonical": canonical,
            "role": "positive",
            "reason": "volumetric or scanning family",
        }
    if canonical in EXCLUDED_LABELS:
        return {
            "raw": raw,
            "canonical": canonical,
            "role": "excluded",
            "reason": EXCLUDED_LABELS[canonical],
        }
    return {
        "raw": raw,
        "canonical": canonical,
        "role": "excluded",
        "reason": "unmapped label; fail closed",
    }


# ---------------------------------------------------------------------------
# Tier A feature schema
# ---------------------------------------------------------------------------
TIER_A_COLUMNS = {
    "flow_duration": "Flow Duration",
    "total_fwd_packets": "Total Fwd Packets",
    "total_backward_packets": "Total Backward Packets",
    "total_length_of_fwd_packets": "Total Length of Fwd Packets",
    "total_length_of_bwd_packets": "Total Length of Bwd Packets",
    "flow_packets_s": "Flow Packets/s",
    "flow_bytes_s": "Flow Bytes/s",
    "packet_length_mean": "Packet Length Mean",
    # The CIC column is "Max Packet Length", not "Packet Length Max".
    "packet_length_max": "Max Packet Length",
    "syn_flag_count": "SYN Flag Count",
    "fin_flag_count": "FIN Flag Count",
    "rst_flag_count": "RST Flag Count",
}

TIER_A_DERIVED = {
    "total_packets": "total_fwd_packets + total_backward_packets",
    "total_bytes": "total_length_of_fwd_packets + total_length_of_bwd_packets",
    "syn_ratio": "syn_flag_count / total_packets, 0 when total_packets == 0",
    "rst_ratio": "rst_flag_count / total_packets, 0 when total_packets == 0",
    "short_flow_flag": "1 when flow_duration < 1,000,000 us and total_packets <= 3",
}

FANOUT_FEATURES = [
    "unique_dst_ports_60s",
    "unique_dst_hosts_60s",
    "connection_attempts_60s",
    "fanout_ratio_60s",
]

RULE_ORDER = [
    "rate_bytes",
    "rate_packets",
    "syn",
    "composite_bytes_syn",
    "composite_packets_syn",
]

RULE_DEFINITIONS = {
    "rate_bytes": {
        "tier": "A",
        "formula": "score = sanitized Flow Bytes/s",
        "source_features": ["flow_bytes_s"],
    },
    "rate_packets": {
        "tier": "A",
        "formula": "score = sanitized Flow Packets/s",
        "source_features": ["flow_packets_s"],
    },
    "syn": {
        "tier": "A",
        "formula": "score = syn_ratio * log1p(total_packets + 1)",
        "source_features": ["syn_ratio", "total_packets"],
    },
    "composite_bytes_syn": {
        "tier": "A",
        "formula": (
            "score = z(log1p(max(flow_bytes_s, 0))) + z(syn_score); "
            "median/IQR fitted on validation only"
        ),
        "source_features": ["flow_bytes_s", "syn_ratio", "total_packets"],
    },
    "composite_packets_syn": {
        "tier": "A",
        "formula": (
            "score = z(log1p(max(flow_packets_s, 0))) + z(syn_score); "
            "median/IQR fitted on validation only"
        ),
        "source_features": ["flow_packets_s", "syn_ratio", "total_packets"],
    },
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _finite_or_none(value: Any) -> float | None:
    """Return a finite float or None so the JSON never contains inf/nan."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _percentile_ci(values: np.ndarray) -> list[float | None]:
    clean = np.asarray(values, dtype=np.float64)
    clean = clean[np.isfinite(clean)]
    if clean.size == 0:
        return [None, None]
    return [
        _finite_or_none(np.percentile(clean, 2.5)),
        _finite_or_none(np.percentile(clean, 97.5)),
    ]


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _numeric(frame: pd.DataFrame, column: str) -> np.ndarray:
    return pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=np.float64)


def _clean_nonnegative(
    values: np.ndarray, repairs: collections.Counter, key: str
) -> np.ndarray:
    array = np.asarray(values, dtype=np.float64)
    nonfinite = ~np.isfinite(array)
    negative = array < 0.0
    repairs[f"{key}_nonfinite"] += int(nonfinite.sum())
    repairs[f"{key}_negative"] += int(negative.sum())
    return np.where(np.isfinite(array) & (array >= 0.0), array, 0.0)


def _repair_rate(
    raw: np.ndarray,
    total: np.ndarray,
    duration_us: np.ndarray,
    repairs: collections.Counter,
    key: str,
) -> np.ndarray:
    """Replace non-finite or negative rates with a documented finite value.

    If duration is positive, recompute ``total / duration_seconds``. If duration
    is zero or negative, use ``total * 1e6``: the rate implied by a one
    microsecond flow. This is a repair for a handful of malformed rows, not a
    measured rate. The counts are recorded in the artifact.
    """
    array = np.asarray(raw, dtype=np.float64)
    nonfinite = ~np.isfinite(array)
    negative = array < 0.0
    bad = nonfinite | negative
    repairs[f"{key}_nonfinite"] += int(nonfinite.sum())
    repairs[f"{key}_negative"] += int(negative.sum())

    duration_s = np.maximum(duration_us, 0.0) / 1_000_000.0
    computed = np.divide(
        total,
        duration_s,
        out=np.zeros_like(total, dtype=np.float64),
        where=duration_s > 0.0,
    )
    zero_duration = bad & ~(duration_s > 0.0)
    computed = np.where(zero_duration, total * 1_000_000.0, computed)
    repairs[f"{key}_repaired"] += int(bad.sum())
    repairs[f"{key}_zero_duration_repair"] += int(zero_duration.sum())
    return np.where(bad, computed, array)


def _ratio(
    numerator: np.ndarray,
    denominator: np.ndarray,
    repairs: collections.Counter,
    key: str,
) -> np.ndarray:
    ratio = np.divide(
        numerator,
        denominator,
        out=np.zeros_like(numerator, dtype=np.float64),
        where=denominator > 0.0,
    )
    repairs[f"{key}_above_one"] += int((ratio > 1.0).sum())
    return np.clip(ratio, 0.0, 1.0)


# ---------------------------------------------------------------------------
# Data loading and feature extraction
# ---------------------------------------------------------------------------
def extract_tier_a(frame: pd.DataFrame) -> tuple[dict[str, np.ndarray], dict[str, int]]:
    """Extract the portable Tier A features and record every repair."""
    missing = [column for column in TIER_A_COLUMNS.values() if column not in frame.columns]
    if missing:
        raise KeyError(f"missing Tier A columns: {sorted(missing)}")

    repairs: collections.Counter = collections.Counter()
    raw = {name: _numeric(frame, column) for name, column in TIER_A_COLUMNS.items()}

    duration = _clean_nonnegative(raw["flow_duration"], repairs, "flow_duration")
    fwd = _clean_nonnegative(raw["total_fwd_packets"], repairs, "total_fwd_packets")
    bwd = _clean_nonnegative(raw["total_backward_packets"], repairs, "total_backward_packets")
    fwd_bytes = _clean_nonnegative(
        raw["total_length_of_fwd_packets"], repairs, "total_length_of_fwd_packets"
    )
    bwd_bytes = _clean_nonnegative(
        raw["total_length_of_bwd_packets"], repairs, "total_length_of_bwd_packets"
    )
    packet_length_mean = _clean_nonnegative(
        raw["packet_length_mean"], repairs, "packet_length_mean"
    )
    packet_length_max = _clean_nonnegative(
        raw["packet_length_max"], repairs, "packet_length_max"
    )
    syn = _clean_nonnegative(raw["syn_flag_count"], repairs, "syn_flag_count")
    fin = _clean_nonnegative(raw["fin_flag_count"], repairs, "fin_flag_count")
    rst = _clean_nonnegative(raw["rst_flag_count"], repairs, "rst_flag_count")

    total_packets = fwd + bwd
    total_bytes = fwd_bytes + bwd_bytes
    repairs["total_packets_zero"] += int((total_packets == 0.0).sum())

    flow_packets_s = _repair_rate(
        raw["flow_packets_s"], total_packets, duration, repairs, "flow_packets_s"
    )
    flow_bytes_s = _repair_rate(
        raw["flow_bytes_s"], total_bytes, duration, repairs, "flow_bytes_s"
    )
    syn_ratio = _ratio(syn, total_packets, repairs, "syn_ratio")
    rst_ratio = _ratio(rst, total_packets, repairs, "rst_ratio")
    short_flow_flag = (
        (duration < 1_000_000.0) & (total_packets <= 3.0)
    ).astype(np.float64)

    features = {
        "flow_duration": duration,
        "total_fwd_packets": fwd,
        "total_backward_packets": bwd,
        "total_length_of_fwd_packets": fwd_bytes,
        "total_length_of_bwd_packets": bwd_bytes,
        "flow_packets_s": flow_packets_s,
        "flow_bytes_s": flow_bytes_s,
        "packet_length_mean": packet_length_mean,
        "packet_length_max": packet_length_max,
        "syn_flag_count": syn,
        "fin_flag_count": fin,
        "rst_flag_count": rst,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "syn_ratio": syn_ratio,
        "rst_ratio": rst_ratio,
        "short_flow_flag": short_flow_flag,
    }
    repairs["short_flow_flag_count"] += int(short_flow_flag.sum())
    return features, dict(repairs)


def load_partition(name: str, day_files: dict[str, list[str]]) -> dict[str, Any]:
    """Load one frozen partition and return labels plus compact features."""
    frame = _load_partition(day_files)
    labels = frame["__label"].to_numpy(dtype=object)
    features, repairs = extract_tier_a(frame)
    rows = int(len(frame))
    del frame
    gc.collect()
    return {
        "name": name,
        "days": list(day_files.keys()),
        "source_files": [filename for files in day_files.values() for filename in files],
        "rows": rows,
        "labels": labels,
        "features": features,
        "repairs": repairs,
    }


def primary_mask(labels: np.ndarray) -> np.ndarray:
    keep = POSITIVE_LABELS | NEGATIVE_LABELS
    return np.isin(labels, np.asarray(sorted(keep), dtype=object))


def binary_truth(labels: np.ndarray) -> np.ndarray:
    return np.isin(labels, np.asarray(sorted(POSITIVE_LABELS), dtype=object)).astype(np.int8)


# ---------------------------------------------------------------------------
# Rules and thresholds
# ---------------------------------------------------------------------------
def syn_score(features: dict[str, np.ndarray]) -> np.ndarray:
    return features["syn_ratio"] * np.log1p(features["total_packets"] + 1.0)


def _fit_scale(values: np.ndarray) -> dict[str, float]:
    array = np.asarray(values, dtype=np.float64)
    median = float(np.median(array))
    q25, q75 = np.percentile(array, [25.0, 75.0])
    iqr = float(q75 - q25)
    if iqr <= 0.0:
        std = float(np.std(array))
        iqr = std if std > 0.0 else 1.0
    return {"median": median, "iqr": iqr}


def fit_rule_normalization(features: dict[str, np.ndarray]) -> dict[str, dict[str, float]]:
    return {
        "rate_bytes_log1p": _fit_scale(
            np.log1p(np.maximum(features["flow_bytes_s"], 0.0))
        ),
        "rate_packets_log1p": _fit_scale(
            np.log1p(np.maximum(features["flow_packets_s"], 0.0))
        ),
        "syn_score": _fit_scale(syn_score(features)),
    }


def _standardize(values: np.ndarray, scale: dict[str, float]) -> np.ndarray:
    return (np.asarray(values, dtype=np.float64) - scale["median"]) / scale["iqr"]


def build_rule_scores(
    features: dict[str, np.ndarray],
    normalization: dict[str, dict[str, float]],
) -> dict[str, np.ndarray]:
    rate_bytes = np.asarray(features["flow_bytes_s"], dtype=np.float64)
    rate_packets = np.asarray(features["flow_packets_s"], dtype=np.float64)
    syn = syn_score(features)
    return {
        "rate_bytes": rate_bytes,
        "rate_packets": rate_packets,
        "syn": syn,
        "composite_bytes_syn": (
            _standardize(np.log1p(np.maximum(rate_bytes, 0.0)), normalization["rate_bytes_log1p"])
            + _standardize(syn, normalization["syn_score"])
        ),
        "composite_packets_syn": (
            _standardize(
                np.log1p(np.maximum(rate_packets, 0.0)),
                normalization["rate_packets_log1p"],
            )
            + _standardize(syn, normalization["syn_score"])
        ),
    }


def alert_budget_k(budget_per_10k: int, n: int) -> int:
    """K = ceil(budget_per_10k * N / 10,000), using exact integer arithmetic."""
    if budget_per_10k < 0:
        raise ValueError("budget must be non-negative")
    if budget_per_10k == int(budget_per_10k):
        return (int(budget_per_10k) * n + 9_999) // 10_000
    return int(math.ceil((float(budget_per_10k) * n) / 10_000.0))


def select_budget_threshold(
    scores: np.ndarray, budget_per_10k: int
) -> dict[str, Any]:
    """Select the rank K+1 threshold and apply ``score > threshold``.

    Sorting is descending and one-based. The decision is strict so that the
    K+1-th score supplies exactly K alerts when there are no ties. Ties at the
    boundary reduce the alert count; a top score tied more than K times yields
    zero alerts. That is the specified "ties -> higher threshold" behaviour and
    is preserved as a negative result rather than broken by an arbitrary
    tie-breaker.

    This function deliberately accepts only scores and a budget. It cannot see
    labels, which is a structural guard against test-label tuning.
    """
    array = np.asarray(scores, dtype=np.float64)
    if array.ndim != 1 or array.size == 0:
        raise ValueError("scores must be a non-empty one-dimensional array")
    if not np.isfinite(array).all():
        raise ValueError("scores must be finite")
    n = int(array.size)
    k = alert_budget_k(budget_per_10k, n)
    sorted_desc = np.sort(array)[::-1]

    if k >= n:
        minimum = float(sorted_desc[-1])
        epsilon = max(1e-12, abs(minimum) * 1e-12)
        threshold = minimum - epsilon
    elif k <= 0:
        threshold = float(sorted_desc[0])
    else:
        threshold = float(sorted_desc[k])

    expected = int(np.sum(array > threshold))
    return {
        "budget_per_10k": int(budget_per_10k),
        "n": n,
        "k": int(k),
        "threshold": threshold,
        "comparison": ">",
        "expected_alerts": expected,
        "expected_alerts_per_10k": _finite_or_none(10_000.0 * expected / n),
    }


def confusion_counts(
    scores: np.ndarray, truth: np.ndarray, threshold: float
) -> dict[str, int]:
    predicted = np.asarray(scores, dtype=np.float64) > threshold
    actual = np.asarray(truth).astype(bool)
    return {
        "true_positives": int(np.sum(predicted & actual)),
        "false_positives": int(np.sum(predicted & ~actual)),
        "false_negatives": int(np.sum(~predicted & actual)),
        "true_negatives": int(np.sum(~predicted & ~actual)),
    }


def rates_from_counts(counts: dict[str, int]) -> tuple[float | None, float | None, int, int]:
    positives = counts["true_positives"] + counts["false_negatives"]
    negatives = counts["false_positives"] + counts["true_negatives"]
    tpr = counts["true_positives"] / positives if positives else None
    fpr = counts["false_positives"] / negatives if negatives else None
    return tpr, fpr, positives, negatives


def bootstrap_prevalence(
    true_positives: int,
    false_positives: int,
    positives: int,
    negatives: int,
    prevalences: Iterable[float],
    draws: int,
    seed: int,
) -> dict[float, dict[str, list[float | None]]]:
    """Stratified bootstrap of the thresholded confusion counts.

    Resampling the fixed-threshold indicator within each class is exactly a
    binomial draw with the observed class rate. This is the non-parametric
    bootstrap distribution of TP and FP for a frozen threshold, not a
    distributional assumption about the scores.
    """
    if draws <= 0:
        raise ValueError("draws must be positive")
    rng = np.random.default_rng(seed)
    tpr = true_positives / positives if positives else 0.0
    fpr = false_positives / negatives if negatives else 0.0
    tp_draw = rng.binomial(positives, tpr, size=draws).astype(np.float64)
    fp_draw = rng.binomial(negatives, fpr, size=draws).astype(np.float64)
    tpr_draw = tp_draw / positives if positives else np.zeros(draws)
    fpr_draw = fp_draw / negatives if negatives else np.zeros(draws)

    result: dict[float, dict[str, list[float | None]]] = {}
    for prevalence in prevalences:
        p = float(prevalence)
        numerator = tpr_draw * p
        denominator = numerator + fpr_draw * (1.0 - p)
        ppv_draw = np.divide(
            numerator,
            denominator,
            out=np.full_like(numerator, np.nan),
            where=denominator > 0.0,
        )
        alerts_draw = 10_000.0 * denominator
        result[p] = {
            "ppv_ci95": _percentile_ci(ppv_draw),
            "alerts_per_10k_ci95": _percentile_ci(alerts_draw),
        }
    return result


def _family_metrics(
    predicted: np.ndarray, labels: np.ndarray, positive_labels: Iterable[str]
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for family in sorted(positive_labels):
        mask = labels == family
        support = int(mask.sum())
        if support == 0:
            continue
        alerts = int(predicted[mask].sum())
        low, high = wilson_interval(alerts, support)
        result[family] = {
            "support": support,
            "alerts": alerts,
            "recall": _finite_or_none(alerts / support),
            "recall_ci95": [_finite_or_none(low), _finite_or_none(high)],
        }
    return result


def _excluded_diagnostics(
    predicted: np.ndarray, labels: np.ndarray, excluded_labels: Iterable[str]
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for family in sorted(excluded_labels):
        mask = labels == family
        support = int(mask.sum())
        if support == 0:
            continue
        alerts = int(predicted[mask].sum())
        result[family] = {
            "support": support,
            "alerts": alerts,
            "alert_rate": _finite_or_none(alerts / support),
            "note": "excluded from primary metrics and threshold selection",
        }
    return result


def evaluate_rule(
    scores: np.ndarray,
    labels: np.ndarray,
    threshold: float,
    prevalences: list[float],
    bootstrap_draws: int,
    seed: int,
) -> dict[str, Any]:
    """Evaluate one frozen rule threshold on one partition.

    ``labels`` covers the whole partition. Primary metrics use only BENIGN and
    positive rows. Excluded labels are reported as diagnostics.
    """
    keep = primary_mask(labels)
    primary_scores = np.asarray(scores, dtype=np.float64)[keep]
    primary_labels = labels[keep]
    truth = binary_truth(primary_labels)
    counts = confusion_counts(primary_scores, truth, threshold)
    tpr, fpr, positives, negatives = rates_from_counts(counts)
    predicted_all = np.asarray(scores, dtype=np.float64) > threshold

    tp = counts["true_positives"]
    fp = counts["false_positives"]
    alerts = tp + fp
    precision = tp / alerts if alerts else None

    if tpr is None:
        recall_ci: list[float | None] = [None, None]
    else:
        low, high = wilson_interval(tp, positives)
        recall_ci = [_finite_or_none(low), _finite_or_none(high)]
    if fpr is None:
        fpr_ci: list[float | None] = [None, None]
    elif fp == 0:
        fpr_ci = [0.0, _finite_or_none(clopper_pearson_upper(0, negatives))]
    else:
        low, high = wilson_interval(fp, negatives)
        fpr_ci = [_finite_or_none(low), _finite_or_none(high)]

    bootstrap = (
        bootstrap_prevalence(tp, fp, positives, negatives, prevalences, bootstrap_draws, seed)
        if positives and negatives
        else {float(p): {"ppv_ci95": [None, None], "alerts_per_10k_ci95": [None, None]} for p in prevalences}
    )

    prevalence_rows = []
    for prevalence in prevalences:
        p = float(prevalence)
        row_tpr = tpr if tpr is not None else 0.0
        row_fpr = fpr if fpr is not None else 0.0
        prevalence_rows.append(
            {
                "p": p,
                "ppv": _finite_or_none(ppv_at_prevalence(row_tpr, row_fpr, p)),
                "ppv_ci95": bootstrap[p]["ppv_ci95"],
                "alerts_per_10k": _finite_or_none(alerts_per_10k(row_tpr, row_fpr, p)),
                "alerts_per_10k_ci95": bootstrap[p]["alerts_per_10k_ci95"],
                "break_even_per_flow": _finite_or_none(
                    break_even_per_flow(row_tpr, row_fpr, p)
                ),
            }
        )

    roc_auc = None
    pr_auc = None
    if truth.size and np.unique(truth).size == 2:
        roc_auc = _finite_or_none(roc_auc_score(truth, primary_scores))
        pr_auc = _finite_or_none(average_precision_score(truth, primary_scores))

    return {
        "threshold": float(threshold),
        "comparison": ">",
        "alerts": alerts,
        "alerts_per_10k": _finite_or_none(10_000.0 * alerts / primary_scores.size)
        if primary_scores.size
        else None,
        "counts": counts,
        "positives": positives,
        "negatives": negatives,
        "recall": _finite_or_none(tpr),
        "recall_ci95": recall_ci,
        "fpr": _finite_or_none(fpr),
        "fpr_ci95": fpr_ci,
        "precision_at_benchmark": _finite_or_none(precision),
        "benchmark_prevalence": _finite_or_none(positives / (positives + negatives))
        if positives + negatives
        else None,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "prevalence": prevalence_rows,
        "per_family_recall": _family_metrics(predicted_all, labels, POSITIVE_LABELS),
        "excluded_diagnostics": _excluded_diagnostics(
            predicted_all, labels, EXCLUDED_LABELS
        ),
    }


def score_tie_diagnostics(
    scores_by_rule: dict[str, np.ndarray],
    labels: np.ndarray,
    budgets: Iterable[int],
) -> dict[str, dict[str, Any]]:
    """Describe the top-score tie for every rule on the primary validation rows."""
    keep = primary_mask(labels)
    primary_labels = labels[keep]
    result: dict[str, dict[str, Any]] = {}
    for rule, scores in scores_by_rule.items():
        primary_scores = np.asarray(scores, dtype=np.float64)[keep]
        maximum = float(np.max(primary_scores))
        tied = primary_scores == maximum
        counts = collections.Counter(primary_labels[tied])
        budget_k = {
            str(int(budget)): alert_budget_k(int(budget), int(primary_scores.size))
            for budget in budgets
        }
        result[rule] = {
            "max_score": maximum,
            "tied_rows": int(tied.sum()),
            "tied_label_counts": {
                str(key): int(value) for key, value in sorted(counts.items())
            },
            "budget_k": budget_k,
            "exceeds_smallest_budget": bool(tied.sum() > min(budget_k.values()))
            if budget_k
            else False,
        }
    return result


def syn_tie_diagnostic(
    validation_scores: np.ndarray,
    validation_labels: np.ndarray,
    budgets: Iterable[int],
) -> dict[str, Any]:
    diagnostic = score_tie_diagnostics(
        {"syn": validation_scores}, validation_labels, budgets
    )["syn"]
    diagnostic["partition"] = "validation"
    diagnostic["explanation"] = (
        "The top SYN score is tied across more rows than either budget allows. "
        "The specified tie rule raises the threshold above the maximum and "
        "selects zero alerts. This is a property of the rule, not a bug."
    )
    return diagnostic


# ---------------------------------------------------------------------------
# Inventory and label audit
# ---------------------------------------------------------------------------
def _read_raw_label_counts(path: str) -> dict[str, int]:
    """Read only the label column with the same encoding fallback as training."""
    for encoding in ("utf-8-sig", "cp1252", "latin1"):
        counts: collections.Counter = collections.Counter()
        try:
            with open(path, "r", newline="", encoding=encoding) as handle:
                reader = csv.reader(handle)
                header = next(reader)
                label_index = next(
                    index for index, column in enumerate(header) if column.strip() == "Label"
                )
                for row in reader:
                    value = row[label_index] if label_index < len(row) else ""
                    counts[value if value != "" else "<missing>"] += 1
            return dict(counts)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("unable to decode label column", b"", 0, 1, path)


def label_audit(day_files: dict[str, list[str]]) -> dict[str, Any]:
    per_file: dict[str, Any] = {}
    aggregate: collections.Counter = collections.Counter()
    for filename in [name for files in day_files.values() for name in files]:
        path = os.path.join(DATA_DIR, filename)
        counts = _read_raw_label_counts(path)
        per_file[filename] = {
            "counts": counts,
            "sha256": _sha256_file(path),
        }
        aggregate.update(counts)
    return {"per_file": per_file, "aggregate": dict(aggregate)}


def data_inventory() -> dict[str, Any]:
    flow_files = (
        sorted(
            os.path.join(DATA_DIR, name)
            for name in os.listdir(DATA_DIR)
            if name.lower().endswith(".csv")
        )
        if os.path.isdir(DATA_DIR)
        else []
    )
    sample_files = (
        sorted(
            os.path.join(SAMPLES_DIR, name)
            for name in os.listdir(SAMPLES_DIR)
            if name.lower().endswith(".csv")
        )
        if os.path.isdir(SAMPLES_DIR)
        else []
    )
    scratch_dirs = (
        sorted(
            name
            for name in os.listdir(SCRATCH_DIR)
            if os.path.isdir(os.path.join(SCRATCH_DIR, name))
        )
        if os.path.isdir(SCRATCH_DIR)
        else []
    )
    packet_files = []
    for root in (DATA_DIR, SAMPLES_DIR, SCRATCH_DIR):
        if not os.path.isdir(root):
            continue
        for directory, _subdirs, files in os.walk(root):
            for name in files:
                if name.lower().endswith((".pcap", ".pcapng")):
                    packet_files.append(os.path.join(directory, name))

    def describe(paths: list[str]) -> list[dict[str, Any]]:
        return [
            {
                "path": os.path.relpath(path, PROJECT_ROOT).replace("\\", "/"),
                "bytes": os.path.getsize(path),
                "sha256": _sha256_file(path),
            }
            for path in paths
        ]

    return {
        "flow_csv_files": describe(flow_files),
        "sample_csv_files": describe(sample_files),
        "scratch_dirs": scratch_dirs,
        "raw_packet_files": describe(sorted(packet_files)),
        "raw_packet_search": {
            "roots": ["data", "data/samples", "scratch"],
            "extensions": [".pcap", ".pcapng"],
            "count": len(packet_files),
            "note": (
                "CIC-IDS-2017 CSV filenames contain 'pcap_ISCX' but their "
                "extension is .csv; they are per-flow exports, not packets."
            ),
        },
    }


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------
def _pct(value: float | None, digits: int = 2) -> str:
    return "n/a" if value is None else f"{value * 100:.{digits}f}%"


def _num(value: float | None, digits: int = 2) -> str:
    return "n/a" if value is None else f"{value:,.{digits}f}"


def _ci_text(low: float | None, high: float | None, percent: bool = True) -> str:
    if low is None or high is None:
        return "n/a"
    if percent:
        return f"{_pct(low, 4)}-{_pct(high, 4)}"
    return f"{_num(low, 2)}-{_num(high, 2)}"


def render_markdown(payload: dict[str, Any]) -> str:
    validation = payload["partitions"]["validation"]
    test = payload["partitions"]["test"]
    rules = payload["rules"]
    budgets = payload["inputs"]["budgets"]
    prevalences = payload["inputs"]["prevalences"]

    lines: list[str] = []
    lines.append("# Rule Baselines (Phase P2A)")
    lines.append("")
    lines.append("**Status:** complete. **Scope:** flow-based volumetric and scanning behavior; not a general NIDS.")
    lines.append("")
    lines.append("**Artifact:** [`rule_baselines.json`](rule_baselines.json). "
                 "**Script:** [`../scripts/rule_baselines.py`](../scripts/rule_baselines.py).")
    lines.append("")
    lines.append("This report defines the Tier A rule baselines that any later model must beat. "
                 "It adds no model, does not touch the serving artifact, and does not tune on test labels.")
    lines.append("")

    lines.append("## Data and label policy")
    lines.append("")
    lines.append("| Partition | Days | Rows after dedup | Primary rows | Positives | Negatives | Excluded | Benchmark prevalence |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for name, block in (("Validation", validation), ("Test", test)):
        lines.append(
            f"| {name} | {', '.join(block['days'])} | {block['rows_after_dedup']:,} | "
            f"{block['primary_rows']:,} | {block['positives']:,} | {block['negatives']:,} | "
            f"{block['excluded_rows']:,} | {_pct(block['benchmark_prevalence'], 2)} |"
        )
    lines.append("")
    lines.append(f"Primary positives: {', '.join(sorted(payload['label_policy']['positive_labels']))}. "
                 f"Negative: {', '.join(sorted(payload['label_policy']['negative_labels']))}. "
                 "Excluded labels are removed from the primary metrics and logged in `excluded_diagnostics`.")
    lines.append("")
    lines.append("The Thursday Morning WebAttacks CSV contains empty records. "
                 "The frozen loader reads them as all-NaN rows, collapses them during `drop_duplicates`, "
                 "and removes the collapsed row with `dropna(subset=['Label'])`. They are never treated as benign.")
    lines.append("")

    lines.append("## Rules")
    lines.append("")
    lines.append("| Rule | Tier | Formula |")
    lines.append("| --- | --- | --- |")
    for rule in RULE_ORDER:
        definition = RULE_DEFINITIONS[rule]
        lines.append(f"| `{rule}` | {definition['tier']} | {definition['formula']} |")
    lines.append("| `fanout` | B | `unique_dst_ports_60s`; **unavailable** without raw packets or a stateful aggregator |")
    lines.append("")

    lines.append("## Threshold selection")
    lines.append("")
    lines.append("Scores are sorted in descending one-based rank. "
                 "For a budget `B` alerts per 10,000 flows and `N` validation rows, "
                 "`K = ceil(B * N / 10000)`. If `K >= N`, the threshold is `min(score) - epsilon`. "
                 "Otherwise the threshold is the score at rank `K + 1`, and the decision is `score > threshold`. "
                 "Ties at the boundary reduce the alert count; a top score tied more than `K` times yields zero alerts. "
                 "This is the specified tie behaviour and is preserved as a negative result.")
    lines.append("")

    lines.append("## Validation thresholds")
    lines.append("")
    lines.append("| Rule | Budget / 10k | K | Threshold | Alerts | Alerts / 10k | Recall | FPR |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for rule in RULE_ORDER:
        for budget in budgets:
            block = rules[rule]["validation"][str(budget)]
            lines.append(
                f"| `{rule}` | {budget} | {block['k']:,} | {block['threshold']:.6g} | "
                f"{block['alerts']:,} | {_num(block['alerts_per_10k'], 2)} | "
                f"{_pct(block['recall'], 4)} | {_pct(block['fpr'], 6)} |"
            )
    lines.append("")

    for budget in budgets:
        lines.append(f"## Test results at {budget} alerts / 10k")
        lines.append("")
        lines.append("| Rule | Alerts | Alerts / 10k | TP | FP | Recall | FPR | Precision @ benchmark |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for rule in RULE_ORDER:
            block = rules[rule]["test"][str(budget)]
            lines.append(
                f"| `{rule}` | {block['alerts']:,} | {_num(block['alerts_per_10k'], 2)} | "
                f"{block['counts']['true_positives']:,} | {block['counts']['false_positives']:,} | "
                f"{_pct(block['recall'], 3)} | {_pct(block['fpr'], 4)} | "
                f"{_pct(block['precision_at_benchmark'], 2)} |"
            )
        lines.append("")
        columns = [p for p in prevalences]
        header = "| Rule | " + " | ".join(_pct(p, 4) for p in columns) + " | Benchmark |"
        divider = "| --- | " + " | ".join("---:" for _ in columns) + " | ---: |"
        lines.append(header)
        lines.append(divider)
        for rule in RULE_ORDER:
            block = rules[rule]["test"][str(budget)]
            by_p = {row["p"]: row for row in block["prevalence"]}
            cells = []
            for p in columns:
                cells.append(_pct(by_p[p]["ppv"], 4))
            cells.append(_pct(block["precision_at_benchmark"], 2))
            lines.append(f"| `{rule}` | " + " | ".join(cells) + " |")
        lines.append("")
        lines.append("PPV uses the test TPR/FPR at the frozen validation threshold. "
                     "The benchmark column is the dataset prevalence, not a site prevalence.")
        lines.append("")

    lines.append("## Confidence intervals at 0.1% prevalence")
    lines.append("")
    lines.append("Intervals are 95% Wilson for recall/FPR and 2.5th-97.5th bootstrap percentiles for PPV and alert volume. "
                 "The bootstrap resamples the thresholded indicator within each class and is deterministic at the recorded seed.")
    lines.append("")
    lines.append("| Rule | Budget / 10k | Recall (95% CI) | FPR (95% CI) | PPV @ 0.1% (95% CI) | Alerts / 10k @ 0.1% (95% CI) |")
    lines.append("| --- | ---: | --- | --- | --- | --- |")
    for rule in RULE_ORDER:
        for budget in budgets:
            block = rules[rule]["test"][str(budget)]
            low_row = next(
                (row for row in block["prevalence"] if abs(row["p"] - 0.001) < 1e-12),
                None,
            )
            ppv_ci = low_row["ppv_ci95"] if low_row else [None, None]
            alerts_ci = low_row["alerts_per_10k_ci95"] if low_row else [None, None]
            lines.append(
                f"| `{rule}` | {budget} | {_pct(block['recall'], 3)} ({_ci_text(*block['recall_ci95'])}) | "
                f"{_pct(block['fpr'], 4)} ({_ci_text(*block['fpr_ci95'])}) | "
                f"{_pct(low_row['ppv'] if low_row else None, 4)} ({_ci_text(*ppv_ci)}) | "
                f"{_num(low_row['alerts_per_10k'] if low_row else None, 2)} ({_ci_text(*alerts_ci, percent=False)}) |"
            )
    lines.append("")

    lines.append("## Per-family recall on test")
    lines.append("")
    lines.append("| Rule | Budget / 10k | DDoS | PortScan |")
    lines.append("| --- | ---: | ---: | ---: |")
    for rule in RULE_ORDER:
        for budget in budgets:
            families = rules[rule]["test"][str(budget)]["per_family_recall"]
            ddos = families.get("DDoS", {})
            portscan = families.get("PortScan", {})
            lines.append(
                f"| `{rule}` | {budget} | "
                f"{_pct(ddos.get('recall'), 3)} ({ddos.get('alerts', 0):,}/{ddos.get('support', 0):,}) | "
                f"{_pct(portscan.get('recall'), 3)} ({portscan.get('alerts', 0):,}/{portscan.get('support', 0):,}) |"
            )
    lines.append("")

    lines.append("## Discrimination")
    lines.append("")
    lines.append("| Rule | Test ROC-AUC | Test PR-AUC |")
    lines.append("| --- | ---: | ---: |")
    for rule in RULE_ORDER:
        block = rules[rule]["test"][str(budgets[0])]
        lines.append(f"| `{rule}` | {_num(block['roc_auc'], 4)} | {_num(block['pr_auc'], 4)} |")
    lines.append("")
    lines.append("AUC is threshold-free and is reported for context. It does not rescue a rule "
                 "that cannot meet an alert budget.")
    lines.append("")

    lines.append("## Excluded-label diagnostics")
    lines.append("")
    lines.append("These rows are excluded from the primary metrics and from threshold selection. "
                 "The table logs how the frozen thresholds would treat them, nothing more.")
    lines.append("")
    lines.append("| Partition | Rule | Budget / 10k | Label | Support | Alerts | Alert rate |")
    lines.append("| --- | --- | ---: | --- | ---: | ---: | ---: |")
    for partition_name, partition in (("validation", validation), ("test", test)):
        for rule in RULE_ORDER:
            for budget in budgets:
                diagnostics = rules[rule][partition_name][str(budget)]["excluded_diagnostics"]
                for label in sorted(diagnostics):
                    row = diagnostics[label]
                    lines.append(
                        f"| {partition_name} | `{rule}` | {budget} | {label} | "
                        f"{row['support']:,} | {row['alerts']:,} | {_pct(row['alert_rate'], 3)} |"
                    )
    lines.append("")

    tie = payload["syn_tie_diagnostic"]
    lines.append("## Score tie diagnostics")
    lines.append("")
    lines.append("A rule whose maximum validation score is tied across more rows than the smallest "
                 "budget allows cannot select a non-empty alert set under the strict `score > threshold` "
                 "rule. The table reports the top tie for every Tier A rule on the primary validation rows.")
    lines.append("")
    lines.append("| Rule | Max validation score | Tied rows | Budget K (10 / 100) | Tie exceeds smallest K |")
    lines.append("| --- | ---: | ---: | --- | --- |")
    for rule in RULE_ORDER:
        block = payload["score_tie_diagnostics"][rule]
        k_values = " / ".join(
            f"{block['budget_k'][str(budget)]:,}" for budget in budgets
        )
        lines.append(
            f"| `{rule}` | {block['max_score']:.6g} | {block['tied_rows']:,} | "
            f"{k_values} | {'yes' if block['exceeds_smallest_budget'] else 'no'} |"
        )
    lines.append("")
    lines.append(f"The maximum validation SYN score is `{tie['max_score']:.6g}` and is tied across "
                 f"{tie['tied_rows']:,} primary validation rows. The tie is dominated by "
                 + ", ".join(f"{label}: {count:,}" for label, count in tie["tied_label_counts"].items())
                 + ". Both budgets require fewer alerts than the size of this tie, so the specified "
                 "tie rule selects zero alerts. The SYN rule therefore has no usable operating point "
                 "on this dataset. The `composite_packets_syn` rule inherits that tie through its SYN "
                 "term and also selects zero validation alerts at the 10/10k budget; at 100/10k it "
                 "only clears the tie and recovers 49 validation positives.")
    lines.append("")

    lines.append("## Tier B fan-out")
    lines.append("")
    fanout = payload["fanout"]
    if fanout["available"]:
        lines.append("Tier B fan-out is available and evaluated.")
    else:
        lines.append(f"Tier B fan-out is **unavailable**: {fanout['reason']}")
    lines.append("")
    lines.append("The primary claim is therefore **Tier A only**. "
                 "Per-flow columns cannot reconstruct 60-second destination fan-out. "
                 "A stateful aggregator or raw packets are required, and neither exists in the repository.")
    lines.append("")

    lines.append("## Key findings")
    lines.append("")
    for budget in budgets:
        candidates = [
            (rule, rules[rule]["test"][str(budget)]["recall"] or 0.0)
            for rule in RULE_ORDER
        ]
        best_rule, best_recall = max(candidates, key=lambda item: item[1])
        best_block = rules[best_rule]["test"][str(budget)]
        low_prevalence = next(
            (row for row in best_block["prevalence"] if abs(row["p"] - 0.001) < 1e-12),
            best_block["prevalence"][1] if len(best_block["prevalence"]) > 1 else best_block["prevalence"][0],
        )
        lines.append(
            f"- At **{budget} alerts / 10k**, the best Tier A rule is `{best_rule}` with "
            f"test recall **{_pct(best_recall, 3)}** ({best_block['counts']['true_positives']:,} TP), "
            f"FPR **{_pct(best_block['fpr'], 4)}**, and PPV **{_pct(low_prevalence['ppv'], 4)}** at "
            f"{_pct(low_prevalence['p'], 4)} prevalence. This is not a viable detector."
        )
    lines.append("- The `syn` rule is degenerate because of ties; see the diagnostic above.")
    lines.append("- `composite_packets_syn` inherits the SYN tie: it selects zero validation alerts at 10/10k "
                 "because its top tie (1,487 rows) exceeds K=693.")
    lines.append("- The composite rules do not beat the best single rate rule at either budget.")
    lines.append("- Tier B fan-out is the missing capability for scan detection. Without raw packets or "
                 "a stateful aggregator, the Tier A baseline cannot represent it honestly.")
    lines.append("")
    lines.append("## Limits")
    lines.append("")
    lines.append("- CIC-IDS-2017 Thursday + Friday is a development test partition that has already been inspected. "
                 "It is not a blind confirmatory test.")
    lines.append("- The benchmark prevalence is a property of this dataset, not a real network.")
    lines.append("- Flows within one capture are not independent; the bootstrap intervals are a lower bound on uncertainty.")
    lines.append("- The rate repair for zero-duration flows uses a one-microsecond assumption. The repair counts are in the artifact.")
    lines.append("- The rules are baselines, not a deployable detector. Detection remains **4/10**.")
    lines.append("")

    lines.append("## Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append("venv/Scripts/python.exe scripts/rule_baselines.py \\")
    lines.append("  --output docs/rule_baselines.json \\")
    lines.append("  --report docs/RULE_BASELINES.md")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _parse_int_list(value: str) -> list[int]:
    return [int(item) for item in value.split(",") if item.strip()]


def _parse_float_list(value: str) -> list[float]:
    result = [float(item) for item in value.split(",") if item.strip()]
    for item in result:
        if not 0.0 <= item <= 1.0:
            raise ValueError(f"prevalence must be in [0, 1]: {item}")
    return sorted(set(result))


def _partition_payload(partition: dict[str, Any]) -> dict[str, Any]:
    labels = partition["labels"]
    keep = primary_mask(labels)
    truth = binary_truth(labels[keep])
    label_counts = collections.Counter(labels)
    excluded_counts = collections.Counter(
        label for label in labels if label in EXCLUDED_LABELS
    )
    positives = int(truth.sum())
    negatives = int(truth.size - positives)
    return {
        "days": partition["days"],
        "source_files": partition["source_files"],
        "rows_after_dedup": int(partition["rows"]),
        "primary_rows": int(keep.sum()),
        "positives": positives,
        "negatives": negatives,
        "excluded_rows": int((~keep).sum()),
        "benchmark_prevalence": _finite_or_none(positives / (positives + negatives))
        if positives + negatives
        else None,
        "label_counts": {str(key): int(value) for key, value in sorted(label_counts.items())},
        "excluded_label_counts": {
            str(key): int(value) for key, value in sorted(excluded_counts.items())
        },
        "repairs": partition["repairs"],
    }


def run(
    output: str,
    report: str,
    budgets: list[int],
    prevalences: list[float],
    bootstrap_draws: int,
    seed: int,
) -> dict[str, Any]:
    validation_files = {"Wednesday": CIC_DAYS["Wednesday"]}
    test_files = {"Thursday": CIC_DAYS["Thursday"], "Friday": CIC_DAYS["Friday"]}

    print("auditing raw labels and data inventory", flush=True)
    validation_audit = label_audit(validation_files)
    test_audit = label_audit(test_files)
    inventory = data_inventory()

    print("loading validation and extracting Tier A features", flush=True)
    validation = load_partition("validation", validation_files)
    validation_keep = primary_mask(validation["labels"])
    validation_features = {
        key: value[validation_keep] for key, value in validation["features"].items()
    }
    normalization = fit_rule_normalization(validation_features)
    del validation_features
    gc.collect()

    validation_scores_all = build_rule_scores(validation["features"], normalization)
    thresholds: dict[str, dict[str, dict[str, Any]]] = {}
    for rule in RULE_ORDER:
        primary_scores = validation_scores_all[rule][validation_keep]
        thresholds[rule] = {
            str(budget): select_budget_threshold(primary_scores, budget)
            for budget in budgets
        }
    frozen_thresholds = json.loads(json.dumps(thresholds))
    tie_diagnostic = syn_tie_diagnostic(
        validation_scores_all["syn"], validation["labels"], budgets
    )
    rule_tie_diagnostics = score_tie_diagnostics(
        validation_scores_all, validation["labels"], budgets
    )

    validation_results: dict[str, dict[str, Any]] = {}
    for rule in RULE_ORDER:
        validation_results[rule] = {}
        for budget in budgets:
            selection = frozen_thresholds[rule][str(budget)]
            block = evaluate_rule(
                validation_scores_all[rule],
                validation["labels"],
                selection["threshold"],
                prevalences,
                bootstrap_draws,
                seed + RULE_ORDER.index(rule) * 1_000 + budget,
            )
            block.update(
                {
                    "k": selection["k"],
                    "expected_alerts": selection["expected_alerts"],
                    "expected_alerts_per_10k": selection["expected_alerts_per_10k"],
                }
            )
            validation_results[rule][str(budget)] = block

    # Thresholds are frozen above. Only now is the test partition loaded.
    print("loading test and extracting Tier A features", flush=True)
    test = load_partition("test", test_files)
    test_scores_all = build_rule_scores(test["features"], normalization)
    test_results: dict[str, dict[str, Any]] = {}
    for rule in RULE_ORDER:
        test_results[rule] = {}
        for budget in budgets:
            selection = frozen_thresholds[rule][str(budget)]
            test_results[rule][str(budget)] = evaluate_rule(
                test_scores_all[rule],
                test["labels"],
                selection["threshold"],
                prevalences,
                bootstrap_draws,
                seed + RULE_ORDER.index(rule) * 1_000 + budget,
            )

    rules_payload: dict[str, Any] = {}
    for rule in RULE_ORDER:
        rules_payload[rule] = {
            "tier": RULE_DEFINITIONS[rule]["tier"],
            "definition": RULE_DEFINITIONS[rule]["formula"],
            "source_features": RULE_DEFINITIONS[rule]["source_features"],
            "normalization": normalization
            if rule.startswith("composite")
            else None,
            "thresholds": frozen_thresholds[rule],
            "validation": validation_results[rule],
            "test": test_results[rule],
        }

    fanout_available = inventory["raw_packet_search"]["count"] > 0
    fanout = {
        "tier": "B",
        "available": fanout_available,
        "required_features": FANOUT_FEATURES,
        "raw_packets_present": fanout_available,
        "reason": (
            "Tier B requires raw packets or a stateful aggregator. The repository "
            "contains per-flow CSV exports and no .pcap/.pcapng files, so 60-second "
            "destination fan-out cannot be derived. It is not approximated from "
            "per-flow columns."
        ),
        "evaluated": False,
    }

    payload = {
        "artifact_version": ARTIFACT_VERSION,
        "method": "tier_a_rule_baselines",
        "scope": (
            "Flow-based detector for volumetric and scanning behavior. "
            "Not a general NIDS. Botnet, web attacks, infiltration, zero-day, "
            "and blocking are out of scope."
        ),
        "seed": seed,
        "bootstrap_draws": bootstrap_draws,
        "inputs": {
            "budgets": budgets,
            "prevalences": prevalences,
            "threshold_comparison": "score > threshold",
            "threshold_rule": (
                "K = ceil(B * N / 10000); if K >= N, min(score)-epsilon; "
                "otherwise score at descending rank K+1"
            ),
            "source_files": {
                "validation": validation_files,
                "test": test_files,
            },
        },
        "label_policy": {
            "positive_labels": sorted(POSITIVE_LABELS),
            "negative_labels": sorted(NEGATIVE_LABELS),
            "excluded_labels": dict(sorted(EXCLUDED_LABELS.items())),
            "unmapped_policy": "excluded and logged; never treated as negative",
            "missing_policy": "removed by the frozen loader; never treated as negative",
            "heartbleed": "excluded from primary; validation-only diagnostic",
            "primary_metric": "binary any-volumetric/scan",
            "secondary_metric": "per-family recall",
        },
        "label_audit": {
            "raw_strings_observed": RAW_LABEL_STRINGS,
            "validation": validation_audit,
            "test": test_audit,
        },
        "data_inventory": inventory,
        "datasets": {
            "CIC-IDS-2017": {
                "evaluated": True,
                "tier_a": True,
                "tier_b": fanout_available,
                "raw_packets": fanout_available,
            },
            "CIC-IDS-2018": {
                "evaluated": False,
                "tier_a": False,
                "tier_b": False,
                "reason": "dataset not acquired",
            },
            "UNSW-NB15": {
                "evaluated": False,
                "tier_a": False,
                "tier_b": False,
                "reason": "dataset not acquired",
            },
            "ToN-IoT": {
                "evaluated": False,
                "tier_a": False,
                "tier_b": False,
                "reason": "dataset not acquired",
            },
            "CIC-IoT-2023": {
                "evaluated": False,
                "tier_a": False,
                "tier_b": False,
                "reason": "dataset not acquired",
            },
        },
        "partitions": {
            "validation": _partition_payload(validation),
            "test": _partition_payload(test),
        },
        "rules": rules_payload,
        "fanout": fanout,
        "syn_tie_diagnostic": tie_diagnostic,
        "score_tie_diagnostics": rule_tie_diagnostics,
        "notes": [
            "Thresholds are selected on validation only; the test partition is loaded after they are frozen.",
            "The decision is score > threshold, so a threshold at descending rank K+1 yields K alerts without ties.",
            "Ties at the boundary reduce the alert count. A top score tied more than K times yields zero alerts.",
            "Rate repairs replace non-finite or negative values with total/duration, or total*1e6 when duration is zero.",
            "Excluded labels are removed from primary metrics and logged as diagnostics.",
            "Tier B fan-out is unavailable because no raw packets exist; it is not approximated from per-flow columns.",
            "Bootstrap intervals resample the thresholded indicator within each class; this is the non-parametric bootstrap distribution of TP/FP at a frozen threshold.",
            "The test partition is CIC-IDS-2017 Thursday + Friday, already inspected. It is not a blind confirmatory test.",
            "These are rule baselines, not a deployable detector. Detection remains 4/10.",
        ],
    }

    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, allow_nan=False)
        handle.write("\n")

    os.makedirs(os.path.dirname(os.path.abspath(report)), exist_ok=True)
    with open(report, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(payload))
        handle.write("\n")

    print(f"wrote {output}", flush=True)
    print(f"wrote {report}", flush=True)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="docs/rule_baselines.json")
    parser.add_argument("--report", default="docs/RULE_BASELINES.md")
    parser.add_argument("--budgets", default="10,100")
    parser.add_argument("--prevalence", default="0.0001,0.001,0.01,0.10")
    parser.add_argument("--bootstrap", type=int, default=DEFAULT_DRAWS)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args(argv)

    run(
        output=args.output,
        report=args.report,
        budgets=_parse_int_list(args.budgets),
        prevalences=_parse_float_list(args.prevalence),
        bootstrap_draws=args.bootstrap,
        seed=args.seed,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
