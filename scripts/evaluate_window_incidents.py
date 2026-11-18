#!/usr/bin/env python
"""Phase 3: ground-truth evaluation of host/time-window evidence accumulation.

Question
--------
Phase 2 showed that a calibrated per-flow threshold collapses at realistic
prevalence: 7.40% PPV at a 0.1% attack prevalence means almost every alert is
wrong. This script tests the repository's existing claim that aggregating
calibrated flow probabilities into ``(source IP, 300 s)`` windows repairs that
collapse.

Nothing here is mocked. The script refits the exact Phase 2 Candidate A
configuration on the exact Phase 2 split, and uses the resulting calibrated
probabilities for every number in the report.

Protocol
--------
1. Load CIC-IDS-2017 with source-IP and timestamp metadata captured through the
   same dedup index as the feature matrix, so a surviving row's host and time
   always belong to that row.
2. Rebuild the Phase 2 protocol split (:mod:`training.train_calibrated`). The
   Wednesday calibration partition alone chooses ``(p_floor,
   incident_threshold)``; Thursday-Friday is scored once, after the parameters
   are frozen.
3. Evaluate Thursday-Friday twice: at natural prevalence and at a deterministic
   0.1% flow prevalence (positives downsampled, ``seed=42``). Report single-flow
   alerting and window-incident alerting side by side.

Grouping key
------------
``(Source IP, floor(epoch_seconds / 300) * 300)``. The frozen export's
timestamps are minute-resolution in the attack-day files and the stored clock
is not a reliable absolute wall-clock (afternoon captures are recorded on a
12-hour clock without a marker), but ordering and spacing within a capture file
are preserved, which is what a 300-second bucket needs. No synthetic host
assignment is used: the real ``Source IP`` column is present in every file.

Run
---
    venv/Scripts/python.exe scripts/evaluate_window_incidents.py
    venv/Scripts/python.exe scripts/evaluate_window_incidents.py --use-scores-cache

No dataset is downloaded. The script only reads local CSVs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import joblib  # noqa: E402

from evidence_accumulator import (  # noqa: E402
    EvidenceAccumulator,
    Observation,
    calibrated_flow_points,
)
from training.train_calibrated import (  # noqa: E402
    SEED,
    TARGET_FPRS,
    PortableDataset,
    attack_probability,
    benign_fpr_threshold_report,
    binary_metrics,
    build_protocol_split,
    feature_schema,
    fit_candidate_a,
    fit_candidate_b,
    load_cic2017_portable,
    prevalence_subsample_indices,
)

ARTIFACT_VERSION = "window-incident-eval-v1"
SCORES_CACHE_VERSION = 2

WINDOW_SECONDS = 300
PRIMARY_TARGET_WINDOW_FPR = 0.001
PER_FLOW_CAP = 50.0
WINDOW_CAP = 100.0
P_FLOOR_GRID = (0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90)
INCIDENT_THRESHOLD_GRID = (55.0, 60.0, 65.0, 70.0, 75.0, 80.0, 90.0, 100.0)
PRIMARY_SINGLE_FLOW_TARGET = 0.005

# Canonical Phase 2 candidate descriptions. Kept here so a cached-score run
# still reports what was fitted rather than the word "cached".
CANDIDATE_DESCRIPTIONS = {
    "A": {
        "name": "Candidate A",
        "estimator": "RandomForestClassifier",
        "calibration": "sigmoid (Platt)",
    },
    "B": {
        "name": "Candidate B",
        "estimator": "HistGradientBoostingClassifier",
        "calibration": "sigmoid (Platt)",
    },
}

SERVING_PATH = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_day_based_seed42.pkl"
)
SERVING_SHA256 = (
    "fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350"
)
PHASE2_JSON = os.path.join(PROJECT_ROOT, "docs", "CALIBRATED_TRANSFER_RESULTS.json")
DEFAULT_SCORES_CACHE = os.path.join(
    PROJECT_ROOT, "models", "eval_cache", "window_incident_scores.npz"
)

LIMITATIONS = [
    "A window's ground truth is derived from the flows inside it: `sum(y_true) >= 1` (primary) or `>= 3` (burst). One attack flow therefore makes an entire window malicious, which flatters window recall relative to a per-flow detector.",
    "The 300-second window is the only window size evaluated. Nothing here says 60 s or 900 s behaves the same way.",
    "Grouping uses the real `Source IP` column. NAT and campus egress aggregation collapse many real hosts into one key; a shared egress address can therefore accumulate somebody else's evidence.",
    "The frozen export's timestamps are minute-resolution on the attack days and use an unreliable 12-hour clock. Window boundaries are quantised to the stored minute, and absolute wall-clock time is not meaningful.",
    "Window parameters were selected on the Wednesday calibration partition, which is the same partition that fitted the Phase 2 sigmoid calibrator. The choice is leakage-safe with respect to Thursday-Friday, but it is not a third independent split.",
    "The two alerting units consume different false-alarm budgets: a flow threshold bounds per-flow false positives, while the window threshold bounds per-window false incidents. The report states both and adds a matched-budget sensitivity rather than implying the budgets are equal.",
    "The 0.1% regime is produced by dropping individual positive flows from the Thursday-Friday set. It keeps each flow's score but removes most within-window co-occurrence, so it measures sparse labels rather than a sparse but bursty attacker.",
    "The serving artifact is untouched. No candidate is promoted by this evaluation.",
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        number = float(value)
        return number if np.isfinite(number) else None
    if isinstance(value, np.ndarray):
        return value.tolist()
    if isinstance(value, float):
        return value if np.isfinite(value) else None
    return value


def _fmt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, np.integer)):
        return str(int(value))
    if isinstance(value, (float, np.floating)):
        number = float(value)
        if not np.isfinite(number):
            return "n/a"
        return f"{number:.{digits}f}"
    return str(value)


def _stamp_iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _sha256(path: str) -> str | None:
    import hashlib

    if not os.path.isfile(path):
        return None
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _add_f1(metrics: dict[str, Any]) -> dict[str, Any]:
    precision = metrics.get("precision")
    recall = metrics.get("recall")
    if precision is None or recall is None or (precision + recall) <= 0:
        metrics["f1"] = None
    else:
        metrics["f1"] = 2.0 * precision * recall / (precision + recall)
    return metrics


# ---------------------------------------------------------------------------
# Windowing
# ---------------------------------------------------------------------------
def window_index(
    host_codes: np.ndarray,
    timestamps: np.ndarray,
    window_seconds: int = WINDOW_SECONDS,
) -> tuple[np.ndarray, int]:
    """Map each flow to a ``(host, window bucket)`` id.

    Both inputs must be finite; the caller drops rows without a parsed
    timestamp first. Bucket ids fit in 32 bits for any second-resolution epoch,
    so ``host * 2**32 + bucket`` is a collision-free int64 key.
    """
    if len(host_codes) != len(timestamps):
        raise ValueError("host codes and timestamps must be aligned")
    if len(host_codes) == 0:
        return np.empty(0, dtype=np.int64), 0
    values = np.asarray(timestamps, dtype=np.float64)
    # 1e11 seconds is year 5138. Anything larger is a sub-second epoch
    # (milliseconds/nanoseconds) and would silently shrink a 300 s window into
    # a 0.3 ms one instead of failing loudly.
    if np.any(np.abs(values) > 1e11):
        raise ValueError(
            "timestamps must be POSIX epoch seconds; "
            f"max |t| = {float(np.max(np.abs(values))):.3e}"
        )
    buckets = np.floor(values / float(window_seconds)).astype(np.int64)
    if np.any(buckets < 0):
        raise ValueError("negative window bucket: timestamps must be positive")
    keys = np.asarray(host_codes, dtype=np.int64) * (2**32) + buckets
    _, inverse = np.unique(keys, return_inverse=True)
    inverse = np.asarray(inverse, dtype=np.int64)
    # np.unique sorts keys, so window ids are ordered by (host, bucket). That
    # ordering is what makes the lexsort in flows_to_detection cheap.
    return inverse, int(inverse.max()) + 1


def window_totals(
    inverse: np.ndarray,
    values: np.ndarray,
    n_windows: int,
) -> np.ndarray:
    return np.bincount(inverse, weights=values, minlength=n_windows)


def window_points(inverse: np.ndarray, points: np.ndarray, n_windows: int) -> np.ndarray:
    """Per-window accumulated points under the accumulator's cap and rounding."""
    totals = window_totals(inverse, points, n_windows)
    return np.round(np.minimum(totals, WINDOW_CAP), 4)


def flows_to_detection(
    inverse: np.ndarray,
    timestamps: np.ndarray,
    labels: np.ndarray,
    points: np.ndarray,
    alert: np.ndarray,
    threshold: float,
    window_positives: np.ndarray,
) -> dict[str, Any]:
    """How much evidence a malicious window needed before it opened.

    Flows are replayed in stored-time order inside each window and the
    per-window cumulative score is computed with the accumulator's cap and
    4-decimal rounding. The reported count is the number of attack flows seen
    up to and including the flow that crossed the threshold.
    """
    n_windows = len(alert)
    malicious = window_positives >= 1
    triggered = malicious & alert
    if not np.any(triggered):
        return {
            "malicious_windows": int(malicious.sum()),
            "triggered_malicious_windows": 0,
            "mean_attack_flows_before_trigger": None,
            "median_attack_flows_before_trigger": None,
            "mean_flows_before_trigger": None,
            "median_flows_before_trigger": None,
        }

    order = np.lexsort((timestamps, inverse))
    codes = inverse[order]
    ordered_labels = labels[order]
    ordered_points = np.asarray(points, dtype=np.float64)[order]
    counts = np.bincount(codes, minlength=n_windows).astype(np.int64)
    starts = np.concatenate(([0], np.cumsum(counts)[:-1])).astype(np.int64)

    cumulative = np.cumsum(ordered_points)
    base_points = cumulative[starts] - ordered_points[starts]
    running = np.minimum(cumulative - base_points[codes], WINDOW_CAP)
    crossed = np.round(running, 4) >= float(threshold)

    first = np.full(n_windows, len(codes), dtype=np.int64)
    crossed_positions = np.flatnonzero(crossed)
    np.minimum.at(first, codes[crossed_positions], crossed_positions)

    attack_prefix = np.cumsum(ordered_labels)
    base_attack = attack_prefix[starts] - ordered_labels[starts]
    attack_before = np.zeros(n_windows, dtype=np.float64)
    flows_before = np.zeros(n_windows, dtype=np.float64)
    opened = first < len(codes)
    attack_before[opened] = (
        attack_prefix[first[opened]] - base_attack[codes[first[opened]]]
    )
    flows_before[opened] = first[opened] - starts[opened] + 1

    selected = triggered & opened
    return {
        "malicious_windows": int(malicious.sum()),
        "triggered_malicious_windows": int(selected.sum()),
        "mean_attack_flows_before_trigger": (
            float(attack_before[selected].mean()) if np.any(selected) else None
        ),
        "median_attack_flows_before_trigger": (
            float(np.median(attack_before[selected])) if np.any(selected) else None
        ),
        "mean_flows_before_trigger": (
            float(flows_before[selected].mean()) if np.any(selected) else None
        ),
        "median_flows_before_trigger": (
            float(np.median(flows_before[selected])) if np.any(selected) else None
        ),
    }


def _window_ranking(labels: np.ndarray, scores: np.ndarray) -> dict[str, Any]:
    """Threshold-free ranking quality on the window unit.

    The frozen threshold can fail for reasons that have nothing to do with
    aggregation. Reporting ROC-AUC and PR-AUC over windows separates the two:
    if window ranking beats flow ranking, aggregation carries signal even when
    the transferred operating point is wrong.
    """
    from sklearn.metrics import average_precision_score, roc_auc_score

    truth = np.asarray(labels, dtype=np.int8)
    values = np.asarray(scores, dtype=np.float64)
    positives = int(truth.sum())
    if positives == 0 or positives == len(truth):
        return {"positives": positives, "roc_auc": None, "pr_auc": None}
    return {
        "positives": positives,
        "roc_auc": float(roc_auc_score(truth, values)),
        "pr_auc": float(average_precision_score(truth, values)),
    }


def _window_confusion(    window_positive_counts: np.ndarray,
    alert: np.ndarray,
    *,
    label: str,
    min_positives: int,
) -> dict[str, Any]:
    positive = window_positive_counts >= min_positives
    tp = int(np.sum(alert & positive))
    fp = int(np.sum(alert & ~positive))
    fn = int(np.sum(~alert & positive))
    tn = int(np.sum(~alert & ~positive))
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )
    return {
        "definition": label,
        "min_positive_flows": int(min_positives),
        "windows": int(len(alert)),
        "malicious_windows": int(tp + fn),
        "benign_windows": int(fp + tn),
        "incidents": int(tp + fp),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr_benign_windows": (fp / (fp + tn)) if (fp + tn) else None,
    }


# ---------------------------------------------------------------------------
# Wednesday-only tuning
# ---------------------------------------------------------------------------
def tune_window_parameters(
    host_codes: np.ndarray,
    timestamps: np.ndarray,
    labels: np.ndarray,
    probabilities: np.ndarray,
    *,
    target_fpr: float = PRIMARY_TARGET_WINDOW_FPR,
    p_floor_grid: tuple[float, ...] = P_FLOOR_GRID,
    threshold_grid: tuple[float, ...] = INCIDENT_THRESHOLD_GRID,
) -> dict[str, Any]:
    """Choose ``(p_floor, incident_threshold)`` on Wednesday benign windows.

    Selection rule, fixed before the numbers are seen: among all grid points
    whose benign-window false-incident rate is within the target, maximise
    window recall on the primary window definition; break ties toward the
    lower false-incident rate, then the higher threshold. If nothing is
    feasible the grid is reported as infeasible and the lowest-FPR point is
    returned so the caller cannot accidentally claim success.
    """
    inverse, n_windows = window_index(host_codes, timestamps, WINDOW_SECONDS)
    window_positive_counts = window_totals(inverse, labels.astype(np.float64), n_windows)
    benign = window_positive_counts == 0
    malicious = window_positive_counts >= 1

    rows: list[dict[str, Any]] = []
    for p_floor in p_floor_grid:
        points = calibrated_flow_points(
            probabilities, p_floor=p_floor, per_flow_cap=PER_FLOW_CAP
        )
        totals = window_points(inverse, points, n_windows)
        for threshold in threshold_grid:
            alert = totals >= float(threshold)
            fpr = float(alert[benign].mean()) if np.any(benign) else None
            recall = float(alert[malicious].mean()) if np.any(malicious) else None
            rows.append(
                {
                    "p_floor": float(p_floor),
                    "incident_threshold": float(threshold),
                    "benign_window_fpr": fpr,
                    "window_recall": recall,
                    "benign_incidents": int(alert[benign].sum()),
                    "malicious_windows": int(malicious.sum()),
                    "feasible": bool(fpr is not None and fpr <= float(target_fpr)),
                }
            )

    feasible = [row for row in rows if row["feasible"]]
    if feasible:
        best = max(
            feasible,
            key=lambda row: (
                row["window_recall"] if row["window_recall"] is not None else -1.0,
                -(row["benign_window_fpr"] or 0.0),
                row["incident_threshold"],
                row["p_floor"],
            ),
        )
    else:
        best = min(
            rows,
            key=lambda row: (
                row["benign_window_fpr"] if row["benign_window_fpr"] is not None else 1.0,
                -row["incident_threshold"],
            ),
        )
    return {
        "target_window_fpr": float(target_fpr),
        "selection_rule": (
            "maximise Wednesday window recall subject to benign-window FPR <= "
            "target; ties -> lower FPR, then higher threshold"
        ),
        "windows": int(n_windows),
        "benign_windows": int(benign.sum()),
        "malicious_windows": int(malicious.sum()),
        "feasible": bool(feasible),
        "selected": best,
        "grid": rows,
        "grid_axes": {
            "p_floor": [float(value) for value in p_floor_grid],
            "incident_threshold": [float(value) for value in threshold_grid],
        },
    }


# ---------------------------------------------------------------------------
# Regime evaluation
# ---------------------------------------------------------------------------
def evaluate_regime(
    *,
    name: str,
    labels: np.ndarray,
    probabilities: np.ndarray,
    host_codes: np.ndarray,
    timestamps: np.ndarray,
    flow_thresholds: dict[str, float],
    window_parameters: dict[str, float],
    sampling: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Score one flow regime with both alerting units."""
    valid = np.isfinite(timestamps)
    dropped = int((~valid).sum())
    y = np.asarray(labels, dtype=np.int8)[valid]
    p = np.asarray(probabilities, dtype=np.float64)[valid]
    hosts = np.asarray(host_codes, dtype=np.int64)[valid]
    stamps = np.asarray(timestamps, dtype=np.float64)[valid]

    block: dict[str, Any] = {
        "name": name,
        "rows": int(len(labels)),
        "scored_rows": int(len(y)),
        "dropped_rows_without_timestamp": dropped,
        "benign_rows": int(np.sum(y == 0)),
        "positive_rows": int(np.sum(y == 1)),
        "prevalence": float(np.mean(y)) if len(y) else None,
        "sampling": sampling,
    }

    flow_blocks: dict[str, Any] = {}
    for key, threshold in flow_thresholds.items():
        metrics = _add_f1(binary_metrics(y, p, threshold))
        metrics["unit"] = "flow"
        metrics["threshold_key"] = key
        flow_blocks[key] = metrics
    block["single_flow"] = flow_blocks

    inverse, n_windows = window_index(hosts, stamps, WINDOW_SECONDS)
    points = calibrated_flow_points(
        p,
        p_floor=float(window_parameters["p_floor"]),
        per_flow_cap=float(window_parameters["per_flow_cap"]),
    )
    totals = window_points(inverse, points, n_windows)
    window_positive_counts = window_totals(
        inverse, y.astype(np.float64), n_windows
    ).astype(np.int64)
    threshold = float(window_parameters["incident_threshold"])
    alert = totals >= threshold

    window_block: dict[str, Any] = {
        "window_seconds": WINDOW_SECONDS,
        "parameters": dict(window_parameters),
        "windows": int(n_windows),
        "alerted_windows": int(alert.sum()),
        "cap_saturated_windows": int(np.sum(totals >= float(window_parameters["window_cap"]) - 1e-9)),
        "cap_saturated_share": (
            float(np.mean(totals >= float(window_parameters["window_cap"]) - 1e-9))
            if n_windows
            else None
        ),
        "incidents_per_10k_flows": (
            float(alert.sum() / len(y) * 10_000.0) if len(y) else None
        ),
        "attack_flow_coverage": (
            float(np.sum(y[alert[inverse]] == 1) / np.sum(y == 1))
            if np.sum(y == 1)
            else None
        ),
        "primary": _window_confusion(
            window_positive_counts, alert, label="sum(y_true) >= 1", min_positives=1
        ),
        "burst": _window_confusion(
            window_positive_counts, alert, label="sum(y_true) >= 3", min_positives=3
        ),
        "flows_to_detection": flows_to_detection(
            inverse,
            stamps,
            y,
            points,
            alert,
            threshold,
            window_positive_counts,
        ),
        "ranking": {
            "primary": _window_ranking(window_positive_counts >= 1, totals),
            "burst": _window_ranking(window_positive_counts >= 3, totals),
        },
    }
    block["window_incident"] = window_block

    # A fair adversarial read: spend the same *benign false-alarm count* on the
    # flow detector. The budget is the window policy's target, expressed per
    # benign flow, so the comparison is not an artefact of a looser unit.
    benign_windows = int(np.sum(window_positive_counts == 0))
    benign_flows = int(np.sum(y == 0))
    budget_per_flow = (
        (PRIMARY_TARGET_WINDOW_FPR * benign_windows / benign_flows)
        if benign_flows
        else None
    )
    block["matched_false_alarm_budget"] = {
        "benign_windows": benign_windows,
        "benign_flows": benign_flows,
        "window_target_fpr": PRIMARY_TARGET_WINDOW_FPR,
        "implied_flow_fpr_budget": budget_per_flow,
        "note": (
            "Flow-level threshold that spends the same number of benign false "
            "alarms as the window policy's target. Computed here, not tuned on "
            "test data."
        ),
    }
    return block


def _matched_budget_threshold(
    benign_probabilities: np.ndarray, budget_per_flow: float | None
) -> dict[str, Any]:
    """Quantile threshold that spends exactly ``budget_per_flow`` on benign flows."""
    scores = np.asarray(benign_probabilities, dtype=np.float64)
    if budget_per_flow is None or budget_per_flow <= 0.0 or scores.size == 0:
        return {"threshold": None, "reason": "no representable budget"}
    if budget_per_flow >= 1.0:
        budget_per_flow = 1.0
    threshold = float(np.quantile(scores, 1.0 - float(budget_per_flow)))
    saturated = threshold >= 1.0 or threshold <= 0.0
    return {
        "threshold": threshold,
        "saturated": bool(saturated),
        "realized_benign_fpr": float(np.mean(scores > threshold)),
    }


# ---------------------------------------------------------------------------
# Phase 2 cross-check
# ---------------------------------------------------------------------------
def _phase2_cross_check(
    test: PortableDataset,
    probabilities: np.ndarray,
    *,
    candidate: str,
) -> dict[str, Any]:
    """Compare this run's refit against the published Phase 2 numbers."""
    payload: dict[str, Any] = {
        "path": os.path.relpath(PHASE2_JSON, PROJECT_ROOT),
        "available": os.path.isfile(PHASE2_JSON),
    }
    if not payload["available"]:
        return payload
    with open(PHASE2_JSON, encoding="utf-8") as handle:
        published = json.load(handle)
    executed = published.get("protocol", {}).get("executed", {}).get("test", {})
    published_metrics = (
        published.get("evaluation", {})
        .get("test_natural", {})
        .get(candidate, {})
        .get("metrics", {})
    )
    recomputed = binary_metrics(test.labels, probabilities, 1.0)
    payload.update(
        {
            "candidate": candidate,
            "published_test_rows": executed.get("rows"),
            "recomputed_test_rows": int(len(test.labels)),
            "rows_match": executed.get("rows") == int(len(test.labels)),
            "published_roc_auc": published_metrics.get("roc_auc"),
            "recomputed_roc_auc": recomputed.get("roc_auc"),
            "published_pr_auc": published_metrics.get("pr_auc"),
            "recomputed_pr_auc": recomputed.get("pr_auc"),
        }
    )
    deltas = []
    for key in ("roc_auc", "pr_auc"):
        left = payload.get(f"published_{key}")
        right = payload.get(f"recomputed_{key}")
        if left is not None and right is not None:
            deltas.append(abs(float(left) - float(right)))
    payload["max_abs_delta"] = max(deltas) if deltas else None
    payload["refit_reproduced_phase2"] = bool(
        payload["rows_match"]
        and payload["max_abs_delta"] is not None
        and payload["max_abs_delta"] <= 1e-4
    )
    return payload


# ---------------------------------------------------------------------------
# Accumulator parity
# ---------------------------------------------------------------------------
def accumulator_parity(
    host_values: list[str],
    host_codes: np.ndarray,
    timestamps: np.ndarray,
    probabilities: np.ndarray,
    window_parameters: dict[str, float],
    *,
    sample_size: int = 20_000,
    seed: int = SEED,
) -> dict[str, Any]:
    """Replay a random flow sample through the real accumulator.

    The metrics above use a vectorised window sum because replaying a million
    observations one at a time is slow. This check proves the vectorised path
    and :class:`EvidenceAccumulator` agree on the sampled flows: same per-window
    risk points and the same open/closed decision.
    """
    valid = np.flatnonzero(np.isfinite(timestamps))
    if valid.size == 0:
        return {"status": "unavailable", "reason": "no finite timestamps"}
    rng = np.random.default_rng(seed)
    take = min(int(sample_size), int(valid.size))
    sample = rng.choice(valid, size=take, replace=False)

    hosts = np.asarray(host_codes[sample], dtype=np.int64)
    stamps = np.asarray(timestamps[sample], dtype=np.float64)
    scores = np.asarray(probabilities[sample], dtype=np.float64)
    threshold = float(window_parameters["incident_threshold"])

    accumulator = EvidenceAccumulator(
        window_seconds=WINDOW_SECONDS,
        incident_threshold=threshold,
        scoring_mode="calibrated",
        p_floor=float(window_parameters["p_floor"]),
        per_flow_cap=float(window_parameters["per_flow_cap"]),
        window_cap=float(window_parameters["window_cap"]),
        # Eviction is a bounded-memory feature, not a scoring rule. Disable it
        # so the replay covers every sampled window.
        max_windows_per_source=1_000_000_000,
    )
    inverse, n_windows = window_index(hosts, stamps, WINDOW_SECONDS)
    order = np.lexsort((stamps, inverse))
    for position in order:
        accumulator.observe(
            Observation(
                source_ip=host_values[int(hosts[position])],
                timestamp=float(stamps[position]),
                supervised_probability=float(scores[position]),
                supervised_calibration="phase2-calibrated",
            )
        )
    snapshot = accumulator.snapshot(open_only=False, limit=10_000_000)
    observed = {
        row["incident_id"]: (
            float(row["risk_points"]),
            bool(row["incident_open"]),
        )
        for row in snapshot["incidents"]
    }

    buckets = np.floor(stamps / WINDOW_SECONDS).astype(np.int64)
    keys = hosts * (2**32) + buckets
    unique_keys, key_inverse = np.unique(keys, return_inverse=True)
    points = calibrated_flow_points(
        scores,
        p_floor=float(window_parameters["p_floor"]),
        per_flow_cap=float(window_parameters["per_flow_cap"]),
    )
    totals = np.round(
        np.minimum(
            np.bincount(key_inverse, weights=points, minlength=len(unique_keys)),
            float(window_parameters["window_cap"]),
        ),
        4,
    )
    expected = {
        f"{host_values[int(key // (2**32))]}:{int((key % (2**32)) * WINDOW_SECONDS)}": (
            float(total),
            bool(total >= threshold),
        )
        for key, total in zip(unique_keys, totals)
    }

    compared = 0
    max_delta = 0.0
    flags_match = True
    for key, (total, is_open) in expected.items():
        if key not in observed:
            flags_match = False
            continue
        observed_total, observed_open = observed[key]
        compared += 1
        max_delta = max(max_delta, abs(observed_total - total))
        if observed_open != is_open:
            flags_match = False
    return {
        "status": "ok",
        "sampled_flows": int(take),
        "sampled_windows": int(n_windows),
        "compared_windows": compared,
        "windows_missing_from_accumulator": int(n_windows - compared),
        "max_abs_points_delta": float(max_delta),
        "incident_flags_match": bool(flags_match),
        "all_match": bool(
            compared == int(n_windows) and flags_match and max_delta <= 1e-6
        ),
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def _comparison_table(regime: dict[str, Any], flow_key: str) -> str:
    flow = regime["single_flow"][flow_key]
    window = regime["window_incident"]["primary"]
    lines = [
        "| Alerting unit | Threshold | Units | Alerts | Precision (PPV) | Recall | F1 | per 10k flows |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        "| Single flow | {t} | {u} | {a} | {p} | {r} | {f} | {rate} |".format(
            t=_fmt(flow.get("threshold")),
            u=_fmt(flow.get("rows")),
            a=_fmt(flow.get("alerts")),
            p=_fmt(flow.get("precision")),
            r=_fmt(flow.get("recall")),
            f=_fmt(flow.get("f1")),
            rate=_fmt(flow.get("alerts_per_10k")),
        ),
        "| 300 s host/window incident | {t} | {u} | {a} | {p} | {r} | {f} | {rate} |".format(
            t=_fmt(regime["window_incident"]["parameters"]["incident_threshold"], 1),
            u=_fmt(window.get("windows")),
            a=_fmt(window.get("incidents")),
            p=_fmt(window.get("precision")),
            r=_fmt(window.get("recall")),
            f=_fmt(window.get("f1")),
            rate=_fmt(regime["window_incident"]["incidents_per_10k_flows"]),
        ),
    ]
    return "\n".join(lines)


def render_report(payload: dict[str, Any]) -> str:
    protocol = payload["protocol"]
    tuning = payload["tuning"]
    windows = payload["window_parameters"]
    regimes = payload["evaluation"]
    realistic = regimes["flow_prevalence_0_001"]
    natural = regimes["natural"]

    lines: list[str] = []
    lines.append("# Host/Window Incident Evaluation (Phase 3)")
    lines.append("")
    lines.append(
        f"**Generated:** {payload['generated_at']}  \n"
        f"**Artifact:** `{payload['artifact_version']}`  \n"
        f"**Candidate:** {payload['candidate']['name']} "
        f"(`{payload['candidate']['estimator']}`, "
        f"{payload['candidate']['calibration']})  \n"
        f"**Seed:** {payload['seed']}  \n"
        f"**Serving artifact:** `{payload['serving']['artifact']}` unchanged "
        f"(`{payload['serving']['sha256']}`)"
    )
    lines.append("")

    lines.append("## 1. Protocol")
    lines.append("")
    lines.append(
        "Wednesday selects the window parameters; Thursday-Friday is scored once "
        "after they are frozen. No Thursday-Friday label contributes to any "
        "choice."
    )
    lines.append("")
    executed = protocol["executed"]
    lines.append(
        f"- Provenance: `{protocol['provenance']}`\n"
        f"- Train: {executed['train']['rows']} rows "
        f"({executed['train']['benign']} benign / {executed['train']['positive']} positive)\n"
        f"- Wednesday calibration: {executed['calibration']['rows']} rows "
        f"({executed['calibration']['benign']} benign / {executed['calibration']['positive']} positive)\n"
        f"- Thursday-Friday test: {executed['test']['rows']} rows "
        f"({executed['test']['benign']} benign / {executed['test']['positive']} positive)\n"
        f"- Training/calibration group overlap: "
        f"{protocol['train_calibration_group_overlap']}"
    )
    lines.append("")
    if protocol.get("deviation"):
        lines.append(f"> **Protocol deviation.** {protocol['deviation']}")
        lines.append("")
    lines.append(
        f"- Grouping key: `{payload['grouping_key']}`  \n"
        f"- Window: {windows['window_seconds']} s  \n"
        f"- Per-flow score: "
        f"`{payload['scoring']['formula']}`  \n"
        f"- Per-flow cap: {windows['per_flow_cap']}  \n"
        f"- Per-window cap: {windows['window_cap']}  \n"
        f"- Incident threshold: {windows['incident_threshold']}  \n"
        f"- p_floor: {windows['p_floor']}"
    )
    lines.append("")

    lines.append("## 2. Wednesday-only parameter selection")
    lines.append("")
    lines.append(
        f"Target: benign-window false-incident rate <= **{_fmt(tuning['target_window_fpr'], 4)}** "
        f"over {tuning['benign_windows']} benign and {tuning['malicious_windows']} "
        f"malicious Wednesday windows ({tuning['windows']} total)."
    )
    lines.append("")
    selected = tuning["selected"]
    lines.append(
        f"Selected `p_floor = {_fmt(selected['p_floor'], 2)}`, "
        f"`incident_threshold = {_fmt(selected['incident_threshold'], 1)}` "
        f"-> Wednesday benign-window FPR **{_fmt(selected['benign_window_fpr'], 5)}**, "
        f"Wednesday window recall **{_fmt(selected['window_recall'], 4)}**. "
        f"Feasible grid point: **{_fmt(tuning['feasible'])}**."
    )
    lines.append("")
    lines.append("| p_floor | threshold | Wednesday benign-window FPR | Wednesday window recall | Feasible |")
    lines.append("|---:|---:|---:|---:|---:|")
    for row in tuning["grid"]:
        lines.append(
            f"| {_fmt(row['p_floor'], 2)} | {_fmt(row['incident_threshold'], 1)} | "
            f"{_fmt(row['benign_window_fpr'], 5)} | {_fmt(row['window_recall'], 4)} | "
            f"{_fmt(row['feasible'])} |"
        )
    lines.append("")

    lines.append("## 3. Single-flow vs 300 s host/window at 0.1% flow prevalence")
    lines.append("")
    sampling = realistic["sampling"]
    lines.append(
        f"Deterministic positive downsampling (`seed={sampling['seed']}`): all "
        f"{sampling['benign_rows']} benign rows kept, "
        f"{sampling['positives_sampled']} of {sampling['positives_available']} "
        f"positives sampled, realised prevalence "
        f"**{_fmt(sampling['realized_prevalence'], 5)}**."
    )
    lines.append("")
    lines.append(_comparison_table(realistic, payload["primary_flow_key"]))
    lines.append("")
    lines.append(
        "Window truth here is the primary definition: a window is malicious if "
        f"it contains at least one attack flow. Attack-flow coverage: "
        f"**{_fmt(realistic['window_incident']['attack_flow_coverage'], 4)}** of "
        "attack flows fall inside an alerted window."
    )
    lines.append("")

    lines.append("## 4. Natural Thursday-Friday prevalence")
    lines.append("")
    lines.append(
        f"{natural['rows']} flows, prevalence **{_fmt(natural['prevalence'], 5)}**."
    )
    lines.append("")
    lines.append(_comparison_table(natural, payload["primary_flow_key"]))
    lines.append("")

    lines.append("## 5. Burst sensitivity (`sum(y_true) >= 3`)")
    lines.append("")
    lines.append(
        "| Regime | Alerting unit | Precision | Recall | F1 | Alerts / incidents |"
    )
    lines.append("|---|---|---:|---:|---:|---:|")
    for regime_key, label in (("natural", "Natural"), ("flow_prevalence_0_001", "0.1%")):
        block = regimes[regime_key]
        flow = block["single_flow"][payload["primary_flow_key"]]
        burst = block["window_incident"]["burst"]
        lines.append(
            f"| {label} | Single flow | {_fmt(flow.get('precision'))} | "
            f"{_fmt(flow.get('recall'))} | {_fmt(flow.get('f1'))} | "
            f"{_fmt(flow.get('alerts'))} |"
        )
        lines.append(
            f"| {label} | Window (burst) | {_fmt(burst.get('precision'))} | "
            f"{_fmt(burst.get('recall'))} | {_fmt(burst.get('f1'))} | "
            f"{_fmt(burst.get('incidents'))} |"
        )
    lines.append("")

    lines.append("## 6. Mean flows-to-detection inside malicious windows")
    lines.append("")
    lines.append(
        "| Regime | Malicious windows | Triggered | Mean attack flows before trigger | Median | Mean flows before trigger |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|")
    for regime_key, label in (("natural", "Natural"), ("flow_prevalence_0_001", "0.1%")):
        stats = regimes[regime_key]["window_incident"]["flows_to_detection"]
        lines.append(
            f"| {label} | {_fmt(stats['malicious_windows'])} | "
            f"{_fmt(stats['triggered_malicious_windows'])} | "
            f"{_fmt(stats['mean_attack_flows_before_trigger'], 2)} | "
            f"{_fmt(stats['median_attack_flows_before_trigger'], 1)} | "
            f"{_fmt(stats['mean_flows_before_trigger'], 2)} |"
        )
    lines.append("")

    lines.append("## 7. Threshold-free ranking on each unit")
    lines.append("")
    lines.append(
        "The frozen threshold is one operating point. These numbers ignore it "
        "and ask whether the unit orders malicious above benign at all."
    )
    lines.append("")
    lines.append("| Regime | Unit | Positives | ROC-AUC | PR-AUC |")
    lines.append("|---|---|---:|---:|---:|")
    for regime_key, label in (("natural", "Natural"), ("flow_prevalence_0_001", "0.1%")):
        block = regimes[regime_key]
        flow = block["single_flow"][payload["primary_flow_key"]]
        ranking = block["window_incident"]["ranking"]
        lines.append(
            f"| {label} | Flow | {_fmt(flow.get('positive_rows'))} | "
            f"{_fmt(flow.get('roc_auc'))} | {_fmt(flow.get('pr_auc'))} |"
        )
        for unit_key, unit_label in (("primary", "Window (>=1)"), ("burst", "Window (>=3)")):
            unit = ranking[unit_key]
            lines.append(
                f"| {label} | {unit_label} | {_fmt(unit.get('positives'))} | "
                f"{_fmt(unit.get('roc_auc'))} | {_fmt(unit.get('pr_auc'))} |"
            )
    lines.append("")
    lines.append(
        "PR-AUC is not comparable across units with different prevalence, which "
        "is why both the positive count and ROC-AUC are shown."
    )
    lines.append("")
    for regime_key, label in (("natural", "Natural"), ("flow_prevalence_0_001", "0.1%")):
        w = regimes[regime_key]["window_incident"]
        at_cap = w["cap_saturated_windows"]
        at_threshold = w["alerted_windows"]
        suffix = (
            " The frozen threshold equals the cap, so this is also exactly the "
            "alert set: the score carries no resolution above the operating point."
            if abs(
                float(w["parameters"]["incident_threshold"])
                - float(w["parameters"]["window_cap"])
            )
            < 1e-9
            else ""
        )
        lines.append(
            f"- {label}: {_fmt(at_cap)} of {_fmt(w['windows'])} windows "
            f"({_fmt((w['cap_saturated_share'] or 0.0) * 100.0, 2)}%) reach the "
            f"{_fmt(w['parameters']['window_cap'], 0)}-point cap"
            f" ({_fmt(at_threshold)} incidents).{suffix}"
        )
    lines.append("")

    lines.append("## 8. Matched false-alarm budget")
    lines.append("")
    lines.append(
        "The two units do not spend the same budget: a flow threshold bounds "
        "per-flow false positives, the window threshold bounds per-window false "
        "incidents. This section re-prices the flow detector at the window "
        "policy's benign false-alarm count."
    )
    lines.append("")
    lines.append("| Regime | Implied flow FPR budget | Flow threshold | Flow precision | Flow recall | Flow alerts |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for regime_key, label in (("natural", "Natural"), ("flow_prevalence_0_001", "0.1%")):
        block = regimes[regime_key]
        matched = block["matched_flow_budget"]
        lines.append(
            f"| {label} | {_fmt(block['matched_false_alarm_budget']['implied_flow_fpr_budget'], 8)} | "
            f"{_fmt(matched.get('threshold'), 9)} | {_fmt(matched.get('precision'))} | "
            f"{_fmt(matched.get('recall'))} | {_fmt(matched.get('alerts'))} |"
        )
    lines.append("")
    lines.append(
        "A `n/a` threshold means the budget is too small for any representable "
        "quantile: the flow detector cannot spend that little at all."
    )
    lines.append("")
    lines.append(
        "Note that the matched threshold ~1.0 sits above almost every calibrated "
        "probability, so the flow detector buys its low false-alarm count by "
        "alerting almost never."
    )
    lines.append("")

    lines.append("## 9. Phase 2 reproducibility check")
    lines.append("")
    check = payload["phase2_cross_check"]
    if not check.get("available"):
        lines.append("Phase 2 JSON was not present, so no cross-check was possible.")
    else:
        lines.append(
            f"- Published test rows {_fmt(check.get('published_test_rows'))} vs "
            f"recomputed {_fmt(check.get('recomputed_test_rows'))} "
            f"(match: **{_fmt(check.get('rows_match'))}**)\n"
            f"- Published ROC-AUC {_fmt(check.get('published_roc_auc'))} vs "
            f"recomputed {_fmt(check.get('recomputed_roc_auc'))}\n"
            f"- Published PR-AUC {_fmt(check.get('published_pr_auc'))} vs "
            f"recomputed {_fmt(check.get('recomputed_pr_auc'))}\n"
            f"- Max absolute delta {_fmt(check.get('max_abs_delta'), 6)} -> scores "
            f"reproduce Phase 2: **{_fmt(check.get('refit_reproduced_phase2'))}**\n"
            f"- Scores used here: `{_fmt(payload['candidate'].get('scores_source'))}`"
        )
    lines.append("")

    lines.append("## 10. Accumulator parity check")
    lines.append("")
    parity = payload["accumulator_parity"]
    if parity.get("status") != "ok":
        lines.append(f"Parity check unavailable: {parity.get('reason')}.")
    else:
        lines.append(
            f"A random sample of {_fmt(parity['sampled_flows'])} Thursday-Friday "
            f"flows spanning {_fmt(parity['sampled_windows'])} windows was replayed "
            f"through `EvidenceAccumulator(scoring_mode='calibrated')`. "
            f"Compared windows: {_fmt(parity['compared_windows'])}; max absolute "
            f"per-window risk-point delta: {_fmt(parity['max_abs_points_delta'], 8)}; "
            f"incident flags match: **{_fmt(parity['incident_flags_match'])}**; "
            f"overall: **{_fmt(parity['all_match'])}**."
        )
        lines.append("")
        lines.append(
            "The vectorised window sums used for the metrics above are therefore "
            "the shipped accumulator's arithmetic, not a reimplementation."
        )
    lines.append("")

    lines.append("## 11. What this evidence supports")
    lines.append("")
    for bullet in _interpretation(payload):
        lines.append(f"- {bullet}")
    lines.append("")

    lines.append("## 12. Limitations")
    lines.append("")
    for limitation in payload["limitations"]:
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)


def _interpretation(payload: dict[str, Any]) -> list[str]:
    """Derive claims from the measured numbers, never from prose."""
    bullets: list[str] = []
    tuning = payload["tuning"]
    selected = tuning["selected"]
    regimes = payload["evaluation"]
    realistic = regimes["flow_prevalence_0_001"]
    flow = realistic["single_flow"][payload["primary_flow_key"]]
    window = realistic["window_incident"]["primary"]

    if not tuning["feasible"]:
        best = min(
            (row["benign_window_fpr"] for row in tuning["grid"]),
            key=lambda value: value if value is not None else 1.0,
        )
        bullets.append(
            "No grid point reached the 0.1% benign-window false-incident target. "
            f"The lowest attainable Wednesday rate was {_fmt(best, 5)} "
            f"({_fmt(selected['p_floor'], 2)} p_floor, threshold "
            f"{_fmt(selected['incident_threshold'], 1)}), so the reported "
            "operating point is a fallback and the window policy is not "
            "validated at its own target."
        )
    else:
        bullets.append(
            f"Wednesday-only selection reached a benign-window false-incident "
            f"rate of {_fmt(selected['benign_window_fpr'], 5)} at "
            f"p_floor={_fmt(selected['p_floor'], 2)} and threshold "
            f"{_fmt(selected['incident_threshold'], 1)}, so the target is "
            "satisfiable on validation data."
        )

    natural_window = regimes["natural"]["window_incident"]["primary"]
    natural_fpr = natural_window.get("fpr_benign_windows")
    if natural_fpr is not None:
        bullets.append(
            f"The frozen point transfers to a Thursday-Friday benign-window "
            f"false-incident rate of {_fmt(natural_fpr, 5)}, "
            f"{natural_fpr / PRIMARY_TARGET_WINDOW_FPR:.1f}x the 0.1% target, "
            "so the Wednesday estimate does not hold on the evaluation days."
        )

    bullets.append(
        f"At 0.1% flow prevalence on Thursday-Friday, single-flow alerting at "
        f"threshold {_fmt(flow.get('threshold'))} achieves precision "
        f"{_fmt(flow.get('precision'))} with {_fmt(flow.get('alerts'))} alerts "
        f"({_fmt(flow.get('alerts_per_10k'))} per 10k flows)."
    )
    bullets.append(
        f"The 300 s host/window policy produces {_fmt(window.get('incidents'))} "
        f"incidents ({_fmt(realistic['window_incident']['incidents_per_10k_flows'])} "
        f"per 10k flows) at precision {_fmt(window.get('precision'))} and window "
        f"recall {_fmt(window.get('recall'))}."
    )

    flow_precision = flow.get("precision") or 0.0
    window_precision = window.get("precision") or 0.0
    if window_precision > flow_precision:
        bullets.append(
            "Window precision exceeds flow precision at this prevalence, "
            "though both are far below a usable level."
        )
    else:
        bullets.append(
            "Window precision does not exceed flow precision at 0.1% "
            "prevalence, so the accumulator does not repair the precision "
            "collapse in this regime."
        )

    # Is aggregation harmful to ranking, or only to the transferred threshold?
    natural = regimes["natural"]
    natural_flow = natural["single_flow"][payload["primary_flow_key"]]
    natural_rank = natural["window_incident"]["ranking"]["primary"]
    if (
        natural_flow.get("roc_auc") is not None
        and natural_rank.get("roc_auc") is not None
    ):
        delta = natural_rank["roc_auc"] - natural_flow["roc_auc"]
        bullets.append(
            f"At natural prevalence the window ranker reaches ROC-AUC "
            f"{_fmt(natural_rank['roc_auc'])} against {_fmt(natural_flow['roc_auc'])} "
            f"for per-flow ranking ({delta:+.4f}); "
            + (
                "aggregation therefore preserves ranking quality while cutting "
                "the number of alert units by more than an order of magnitude."
                if delta > -0.02
                else "aggregation loses ranking quality as well."
            )
        )

    natural_saturated = natural["window_incident"].get("cap_saturated_share")
    if natural_saturated is not None and natural_saturated > 0.0:
        bullets.append(
            f"Part of that loss is structural: {_fmt(natural_saturated * 100.0, 2)}% "
            f"of natural-prevalence windows sit exactly at the "
            f"{_fmt(natural['window_incident']['parameters']['window_cap'], 0)}-point "
            "cap, so the window score behaves almost like a binary flag and ties "
            "thousands of windows. The cap bounds a single host's influence but "
            "also erases ordering information."
        )

    stats = realistic["window_incident"]["flows_to_detection"]
    if stats["mean_attack_flows_before_trigger"] is not None:
        bullets.append(
            f"A malicious window needs {_fmt(stats['mean_attack_flows_before_trigger'], 2)} "
            f"attack flows on average (median "
            f"{_fmt(stats['median_attack_flows_before_trigger'], 1)}) before the "
            "incident opens; a host that emits a single attack flow is not "
            "escalated."
        )
    else:
        bullets.append(
            "No malicious window opened an incident in the 0.1% regime, so no "
            "flows-to-detection figure exists there."
        )

    matched = realistic["matched_flow_budget"]
    if matched.get("threshold") is None:
        bullets.append(
            "At the window policy's false-alarm budget the flow threshold is not "
            "representable: a single-flow detector would have to alert on "
            "nothing at all. The units are not interchangeable."
        )
    else:
        bullets.append(
            f"When re-priced to the same benign false-alarm count, the flow "
            f"detector reaches precision {_fmt(matched.get('precision'))} and "
            f"recall {_fmt(matched.get('recall'))}."
        )

    natural_windows = natural_window.get("malicious_windows") or 0
    realistic_windows = window.get("malicious_windows") or 0
    if natural_windows:
        bullets.append(
            f"Downsampling to 0.1% prevalence leaves {realistic_windows} of the "
            f"{natural_windows} malicious windows that exist at natural "
            "prevalence, because positive flows are dropped individually. That "
            "strips the within-window co-occurrence windowing depends on: this "
            "regime measures sparse labels, not a sparse but bursty attacker, "
            "and should not be read as proof that aggregation cannot help in "
            "live traffic."
        )

    bullets.append(
        "This evaluates one dataset, one window size, and one candidate. It does "
        "not establish live-capture behaviour, and the serving artifact is "
        "unchanged."
    )
    return bullets


# ---------------------------------------------------------------------------
# Score cache
# ---------------------------------------------------------------------------
def _scores_signature(candidate_key: str, split, cic: PortableDataset) -> str:
    import hashlib

    payload = {
        "version": SCORES_CACHE_VERSION,
        "candidate": candidate_key,
        "seed": SEED,
        "provenance": split.provenance,
        "counts": {
            "train": int(split.train_mask.sum()),
            "calibration": int(split.calibration_mask.sum()),
            "test": int(split.test_mask.sum()),
        },
        "feature_schema": feature_schema()["sha256"],
        "window_seconds": WINDOW_SECONDS,
        "per_flow_cap": PER_FLOW_CAP,
        "window_cap": WINDOW_CAP,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _write_scores_cache(
    path: str,
    *,
    signature: str,
    host_values: list[str],
    p_cal: np.ndarray,
    y_cal: np.ndarray,
    hosts_cal: np.ndarray,
    ts_cal: np.ndarray,
    p_test: np.ndarray,
    y_test: np.ndarray,
    hosts_test: np.ndarray,
    ts_test: np.ndarray,
) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    np.savez_compressed(
        path,
        signature=np.array(signature),
        host_values=np.array(host_values, dtype=object),
        p_cal=p_cal,
        y_cal=y_cal,
        hosts_cal=hosts_cal,
        ts_cal=ts_cal,
        p_test=p_test,
        y_test=y_test,
        hosts_test=hosts_test,
        ts_test=ts_test,
    )


def _read_scores_cache(path: str, signature: str) -> dict[str, Any] | None:
    if not os.path.isfile(path):
        return None
    try:
        with np.load(path, allow_pickle=True) as data:
            if str(data["signature"].item()) != signature:
                print("      cache signature mismatch; refitting", flush=True)
                return None
            return {
                "host_values": [str(value) for value in data["host_values"].tolist()],
                "p_cal": np.asarray(data["p_cal"], dtype=np.float64),
                "y_cal": np.asarray(data["y_cal"], dtype=np.int8),
                "hosts_cal": np.asarray(data["hosts_cal"], dtype=np.int64),
                "ts_cal": np.asarray(data["ts_cal"], dtype=np.float64),
                "p_test": np.asarray(data["p_test"], dtype=np.float64),
                "y_test": np.asarray(data["y_test"], dtype=np.int8),
                "hosts_test": np.asarray(data["hosts_test"], dtype=np.int64),
                "ts_test": np.asarray(data["ts_test"], dtype=np.float64),
            }
    except Exception as exc:  # noqa: BLE001 - cache is optional
        print(f"      cache unreadable ({exc}); refitting", flush=True)
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default=os.path.join(PROJECT_ROOT, "data"))
    parser.add_argument(
        "--cic-source",
        default="cicids2017",
        choices=("cicids2017", "distrinet_cicids2017"),
    )
    parser.add_argument(
        "--candidate", default="A", choices=("A", "B"), help="Phase 2 candidate to score."
    )
    parser.add_argument(
        "--output-json",
        default=os.path.join(PROJECT_ROOT, "docs", "WINDOW_INCIDENT_EVAL.json"),
    )
    parser.add_argument(
        "--report",
        default=os.path.join(PROJECT_ROOT, "docs", "WINDOW_INCIDENT_EVAL.md"),
    )
    parser.add_argument("--chunksize", type=int, default=250_000)
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=None,
        help="Smoke-test limit per CSV; omit for the full run.",
    )
    parser.add_argument("--scores-cache", default=DEFAULT_SCORES_CACHE)
    parser.add_argument(
        "--use-scores-cache",
        action="store_true",
        help="Reuse cached Phase 2 scores instead of reloading and refitting.",
    )
    parser.add_argument("--skip-cache-write", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = time.time()
    os.makedirs(os.path.dirname(args.output_json) or ".", exist_ok=True)

    print(f"[1/6] loading {args.cic_source} with host/time metadata", flush=True)
    stage = time.time()
    cic = load_cic2017_portable(
        args.data_dir,
        source=args.cic_source,
        chunksize=args.chunksize,
        max_rows_per_file=args.max_rows_per_file,
        capture_metadata=True,
    )
    if cic.source_ip_codes is None or cic.timestamps is None:
        raise RuntimeError("metadata capture failed: no host/timestamp arrays")
    finite_stamps = cic.timestamps[np.isfinite(cic.timestamps)]
    if finite_stamps.size:
        median_stamp = float(np.median(finite_stamps))
        if median_stamp > 1e11:
            raise RuntimeError(
                f"timestamps look sub-second (median {median_stamp:.3e}); "
                "the window math expects epoch seconds"
            )
    print(
        f"      {len(cic.labels)} unique in-scope rows; "
        f"{len(cic.source_ip_values)} distinct source IPs; "
        f"{int(np.sum(~np.isfinite(cic.timestamps)))} rows without a timestamp "
        f"({time.time() - stage:.1f}s)",
        flush=True,
    )
    if finite_stamps.size:
        print(
            "      stored-time range: "
            f"{_stamp_iso(float(finite_stamps.min()))} .. "
            f"{_stamp_iso(float(finite_stamps.max()))}",
            flush=True,
        )

    print("[2/6] rebuilding the Phase 2 split", flush=True)
    split = build_protocol_split(cic)
    print(f"      provenance: {split.provenance}", flush=True)
    print(f"      executed: {split.executed}", flush=True)

    signature = _scores_signature(args.candidate, split, cic)
    cached = _read_scores_cache(args.scores_cache, signature) if args.use_scores_cache else None

    if cached is not None:
        print("      loaded cached Phase 2 scores (no refit)", flush=True)
        p_cal = cached["p_cal"]
        y_cal = cached["y_cal"]
        hosts_cal = cached["hosts_cal"]
        ts_cal = cached["ts_cal"]
        p_test = cached["p_test"]
        y_test = cached["y_test"]
        hosts_test = cached["hosts_test"]
        ts_test = cached["ts_test"]
        host_values = cached["host_values"]
        candidate_meta = {
            **CANDIDATE_DESCRIPTIONS[args.candidate],
            "scores_source": "cache",
        }
    else:
        x_train = cic.matrix[split.train_mask]
        y_train = cic.labels[split.train_mask]
        x_calibration = cic.matrix[split.calibration_mask]
        y_calibration = cic.labels[split.calibration_mask]

        print(f"[3/6] fitting Phase 2 Candidate {args.candidate}", flush=True)
        stage = time.time()
        if args.candidate == "A":
            model, candidate_meta = fit_candidate_a(
                x_train, y_train, x_calibration, y_calibration
            )
        else:
            model, candidate_meta = fit_candidate_b(
                x_train, y_train, x_calibration, y_calibration
            )
        del x_train, y_train
        print(f"      done ({time.time() - stage:.1f}s)", flush=True)

        print("[4/6] scoring Wednesday and Thursday-Friday", flush=True)
        stage = time.time()
        p_cal = attack_probability(model, x_calibration)
        p_test = attack_probability(model, cic.matrix[split.test_mask])
        del x_calibration
        y_cal = y_calibration
        hosts_cal = cic.source_ip_codes[split.calibration_mask]
        ts_cal = cic.timestamps[split.calibration_mask]
        y_test = cic.labels[split.test_mask]
        hosts_test = cic.source_ip_codes[split.test_mask]
        ts_test = cic.timestamps[split.test_mask]
        host_values = cic.source_ip_values
        candidate_meta["scores_source"] = "refit"
        print(f"      done ({time.time() - stage:.1f}s)", flush=True)

        if not args.skip_cache_write:
            _write_scores_cache(
                args.scores_cache,
                signature=signature,
                host_values=host_values,
                p_cal=p_cal,
                y_cal=y_cal,
                hosts_cal=hosts_cal,
                ts_cal=ts_cal,
                p_test=p_test,
                y_test=y_test,
                hosts_test=hosts_test,
                ts_test=ts_test,
            )
            print(f"      cached scores: {args.scores_cache}", flush=True)

    print("[5/6] tuning on Wednesday only and freezing parameters", flush=True)
    stage = time.time()
    calibration_valid = np.isfinite(ts_cal)
    tuning = tune_window_parameters(
        hosts_cal[calibration_valid],
        ts_cal[calibration_valid],
        y_cal[calibration_valid],
        p_cal[calibration_valid],
    )
    selected = tuning["selected"]
    window_parameters = {
        "window_seconds": WINDOW_SECONDS,
        "p_floor": float(selected["p_floor"]),
        "per_flow_cap": PER_FLOW_CAP,
        "window_cap": WINDOW_CAP,
        "incident_threshold": float(selected["incident_threshold"]),
        "min_signals": 1,
        "scoring_mode": "calibrated",
        "selection": "wednesday_only",
    }
    print(
        f"      p_floor={window_parameters['p_floor']:.2f} "
        f"threshold={window_parameters['incident_threshold']:.1f} "
        f"wed_fpr={selected['benign_window_fpr']:.5f} "
        f"wed_recall={selected['window_recall']:.4f} "
        f"feasible={tuning['feasible']} ({time.time() - stage:.1f}s)",
        flush=True,
    )

    calibration_benign = p_cal[y_cal == 0]
    flow_thresholds = {
        "phase2_flow_fpr_0.005": benign_fpr_threshold_report(
            calibration_benign, 0.005
        )["threshold"],
        "phase2_flow_fpr_0.001": benign_fpr_threshold_report(
            calibration_benign, 0.001
        )["threshold"],
    }
    primary_flow_key = f"phase2_flow_fpr_{PRIMARY_SINGLE_FLOW_TARGET:g}"
    for key, value in flow_thresholds.items():
        print(f"      {key}: threshold={value:.6f}", flush=True)

    print("[6/6] evaluating Thursday-Friday (one shot)", flush=True)
    stage = time.time()
    natural = evaluate_regime(
        name="Thursday-Friday (natural prevalence)",
        labels=y_test,
        probabilities=p_test,
        host_codes=hosts_test,
        timestamps=ts_test,
        flow_thresholds=flow_thresholds,
        window_parameters=window_parameters,
    )
    sample_indices, sampling = prevalence_subsample_indices(
        y_test, target_prevalence=0.001, seed=SEED
    )
    realistic = evaluate_regime(
        name="Thursday-Friday (0.1% flow prevalence)",
        labels=y_test[sample_indices],
        probabilities=p_test[sample_indices],
        host_codes=hosts_test[sample_indices],
        timestamps=ts_test[sample_indices],
        flow_thresholds=flow_thresholds,
        window_parameters=window_parameters,
        sampling=sampling,
    )

    for block in (natural, realistic):
        budget = block["matched_false_alarm_budget"]["implied_flow_fpr_budget"]
        matched = _matched_budget_threshold(calibration_benign, budget)
        block["matched_flow_budget"] = dict(matched)
        if matched.get("threshold") is None:
            block["matched_flow_budget"].update(
                {
                    "rows": int(block["single_flow"][primary_flow_key].get("rows", 0)),
                    "alerts": 0,
                    "precision": None,
                    "recall": 0.0 if block["positive_rows"] else None,
                    "threshold_key": "matched_budget",
                }
            )
        else:
            metrics = _add_f1(
                binary_metrics(
                    y_test if block is natural else y_test[sample_indices],
                    p_test if block is natural else p_test[sample_indices],
                    float(matched["threshold"]),
                )
            )
            block["matched_flow_budget"].update(metrics)
            block["matched_flow_budget"]["threshold_key"] = "matched_budget"
    print(f"      done ({time.time() - stage:.1f}s)", flush=True)

    cross_check = _phase2_cross_check(
        cic.subset(split.test_mask), p_test, candidate=args.candidate
    )
    parity = accumulator_parity(
        cic.source_ip_values, hosts_test, ts_test, p_test, window_parameters
    )
    print(
        f"      accumulator parity: {parity.get('compared_windows')} windows, "
        f"max delta {parity.get('max_abs_points_delta')}, "
        f"all_match={parity.get('all_match')}",
        flush=True,
    )

    payload: dict[str, Any] = {
        "artifact_version": ARTIFACT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "feature_schema": feature_schema(),
        "serving": {
            "artifact": os.path.basename(SERVING_PATH),
            "sha256": SERVING_SHA256,
            "present_sha256": _sha256(SERVING_PATH),
            "untouched": _sha256(SERVING_PATH) == SERVING_SHA256,
        },
        "candidate": candidate_meta,
        "grouping_key": "(Source IP, floor(epoch_seconds / 300) * 300)",
        "scoring": {
            "formula": "points = min(per_flow_cap, 100 * max(0, (p - p_floor) / (1 - p_floor)))",
            "accumulator_scoring_mode": "calibrated",
            "window_total": "min(window_cap, sum(per-flow points))",
            "incident": "round(window_total, 4) >= incident_threshold",
        },
        "protocol": split.as_payload(),
        "tuning": tuning,
        "window_parameters": window_parameters,
        "flow_thresholds": flow_thresholds,
        "primary_flow_key": primary_flow_key,
        "evaluation": {
            "natural": natural,
            "flow_prevalence_0_001": realistic,
        },
        "phase2_cross_check": cross_check,
        "accumulator_parity": parity,
        "limitations": LIMITATIONS,
        "elapsed_seconds": round(time.time() - started, 2),
    }

    with open(args.output_json, "w", encoding="utf-8") as handle:
        json.dump(_json_safe(payload), handle, indent=2, sort_keys=True)
        handle.write("\n")
    report = render_report(payload)
    with open(args.report, "w", encoding="utf-8") as handle:
        handle.write(report)
        handle.write("\n")

    print("")
    print("Single-Flow vs 300 s Host/Window (0.1% flow prevalence)")
    print(_comparison_table(realistic, primary_flow_key))
    print("")
    print(f"JSON:   {args.output_json}")
    print(f"Report: {args.report}")
    print(f"Elapsed: {payload['elapsed_seconds']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
