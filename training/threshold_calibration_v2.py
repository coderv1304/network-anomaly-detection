"""Phase D4/D5: threshold-policy transfer and probability calibration.

This script uses the frozen day-based Random Forest bundles for seeds 42-46.
It does not retrain. It reloads the exact day-based partitions, scores the
validation (Wednesday) and test (Thursday + Friday) partitions, and then:

D4
  * selects one global attack-score threshold per seed on validation only;
  * applies that threshold unchanged to every test day;
  * reports FPR, recall, precision, alert volume, and per-family recall per
    day and per seed;
  * compares the global policy with a per-predicted-class policy, a label-free
    day-aware score-quantile policy, and the serving argmax policy;
  * reports the operational cost when the validation threshold does not
    transfer to later days.

D5
  * measures binary attack-score ECE and Brier score on held-out data;
  * fits temperature scaling and isotonic regression on validation only;
  * reports reliability bins overall, by day, and by family;
  * reports decision-curve analysis;
  * explains how calibration interacts with the threshold and alert budget.

Outputs
-------
docs/THRESHOLD_POLICY_V2.md
docs/threshold_policy_v2.json
docs/CALIBRATION_V2.md
docs/calibration_v2.json
docs/figures/reliability_seed42_overall.svg
docs/figures/reliability_seed42_by_day.svg
docs/figures/reliability_seed42_by_family.svg
docs/figures/decision_curve_seed42.svg
models/calibration_rf_day_based_seed42.json ... seed46.json
models/eval_cache/*.npz  (regenerable score cache; gitignored)

Run:
    python -m training.threshold_calibration_v2
    python -m training.threshold_calibration_v2 --force
"""

from __future__ import annotations

import argparse
import html
import json
import math
import os
import sys
import time
from datetime import UTC, datetime

import joblib
import numpy as np
import pandas as pd
from scipy.optimize import minimize_scalar
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import log_loss

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.baseline_comparison_v2 import (  # noqa: E402
    canonical_label,
    mean_std,
    sha256_file,
    sha256_json,
)
from training.evaluate import CIC_DAYS, select_threshold_at_max_fpr  # noqa: E402
from training.train_pipeline import _read_csv_safe  # noqa: E402

SEEDS = [42, 43, 44, 45, 46]
DATA_DIR = "data"
MODEL_DIR = "models"
CACHE_DIR = os.path.join(MODEL_DIR, "eval_cache")
DOCS_DIR = "docs"
FIGURES_DIR = os.path.join(DOCS_DIR, "figures")
MAX_FPR = 0.01
ANALYST_MINUTES_PER_ALERT = 5.0
RELIABILITY_BINS = 10
DECISION_THRESHOLDS = [0.01, 0.02, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50]
EPS = 1e-6
DAY_ORDER = ["Thursday", "Friday"]


# ---------------------------------------------------------------------------
# Data loading and scoring
# ---------------------------------------------------------------------------
def _load_partition(day_files: dict[str, list[str]]) -> pd.DataFrame:
    """Load a partition with day tags while matching ``_load_files`` exactly.

    ``train_pipeline._load_files`` concatenates the configured files and then
    calls ``drop_duplicates()`` on every source column. The tags are added
    before that step but excluded from the duplicate subset so the surviving
    row set is identical to the frozen training/evaluation loader.
    """
    frames = []
    for day, files in day_files.items():
        for filename in files:
            path = os.path.join(DATA_DIR, filename)
            frame = _read_csv_safe(path)
            if frame is None:
                raise FileNotFoundError(path)
            frame.columns = frame.columns.str.strip()
            frame["__day"] = day
            frame["__source_file"] = filename
            frames.append(frame)
    if not frames:
        raise FileNotFoundError("No files configured for partition")
    combined = pd.concat(frames, ignore_index=True)
    source_columns = [column for column in combined.columns if not column.startswith("__")]
    combined.drop_duplicates(subset=source_columns, inplace=True)
    combined.dropna(subset=["Label"], inplace=True)
    combined["__label"] = combined["Label"].map(canonical_label)
    return combined


def _score_bundle(bundle: dict, features: pd.DataFrame) -> dict[str, np.ndarray]:
    """Return attack scores and argmax labels from one frozen bundle."""
    pipeline = bundle["pipeline"]
    classes = [str(value) for value in bundle["label_encoder"].classes_]
    benign_index = classes.index("BENIGN")
    probabilities = pipeline.predict_proba(features)
    attack_scores = 1.0 - probabilities[:, benign_index]
    argmax_indices = probabilities.argmax(axis=1)
    return {
        "attack_score": attack_scores.astype(np.float32),
        "argmax_index": argmax_indices.astype(np.int8),
        "classes": np.asarray(classes),
    }


def _cache_path(seed: int, partition: str) -> str:
    return os.path.join(CACHE_DIR, f"rf_seed{seed}_{partition}.npz")


def _save_scores(
    seed: int,
    partition: str,
    frame: pd.DataFrame,
    scored: dict,
    families: list[str],
    days: list[str],
) -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    family_codes = np.asarray([families.index(value) for value in frame["__label"]], dtype=np.int16)
    day_codes = np.asarray([days.index(value) for value in frame["__day"]], dtype=np.int8)
    np.savez_compressed(
        _cache_path(seed, partition),
        attack_score=scored["attack_score"],
        argmax_index=scored["argmax_index"],
        binary_truth=(frame["__label"].to_numpy() != "BENIGN").astype(np.int8),
        family_codes=family_codes,
        day_codes=day_codes,
        families=np.asarray(families),
        days=np.asarray(days),
        classes=scored["classes"],
    )


def _load_scores(seed: int, partition: str) -> dict[str, np.ndarray] | None:
    path = _cache_path(seed, partition)
    if not os.path.isfile(path):
        return None
    with np.load(path, allow_pickle=False) as data:
        return {key: data[key] for key in data.files}


def prepare_scores(force: bool = False) -> dict:
    """Load partitions and score every frozen seed, with a regenerable cache."""
    validation_files = {"Wednesday": CIC_DAYS["Wednesday"]}
    test_files = {"Thursday": CIC_DAYS["Thursday"], "Friday": CIC_DAYS["Friday"]}

    started = time.time()
    validation = _load_partition(validation_files)
    test = _load_partition(test_files)
    load_seconds = time.time() - started

    families = sorted(set(validation["__label"]) | set(test["__label"]))
    if "BENIGN" in families:
        families.remove("BENIGN")
        families.insert(0, "BENIGN")

    metadata = {
        "validation_rows": int(len(validation)),
        "test_rows": int(len(test)),
        "test_rows_by_day": {day: int((test["__day"] == day).sum()) for day in DAY_ORDER},
        "validation_rows_by_day": {"Wednesday": int(len(validation))},
        "validation_label_counts": validation["__label"].value_counts().to_dict(),
        "test_label_counts": test["__label"].value_counts().to_dict(),
        "families": families,
        "validation_families": sorted(set(validation["__label"])),
        "test_families": sorted(set(test["__label"])),
        "load_seconds": load_seconds,
    }

    all_scores = {}
    scoring_seconds = {}
    for seed in SEEDS:
        cached_validation = None if force else _load_scores(seed, "validation")
        cached_test = None if force else _load_scores(seed, "test")
        if cached_validation is not None and cached_test is not None:
            all_scores[seed] = {"validation": cached_validation, "test": cached_test}
            scoring_seconds[seed] = 0.0
            print(f"seed {seed}: loaded score cache")
            continue

        bundle_path = os.path.join(MODEL_DIR, f"model_bundle_rf_day_based_seed{seed}.pkl")
        bundle = joblib.load(bundle_path)
        feature_names = list(bundle["feature_names"])
        seed_started = time.time()
        validation_scored = _score_bundle(bundle, validation.reindex(columns=feature_names))
        test_scored = _score_bundle(bundle, test.reindex(columns=feature_names))
        _save_scores(seed, "validation", validation, validation_scored, families, ["Wednesday"])
        _save_scores(seed, "test", test, test_scored, families, DAY_ORDER)
        all_scores[seed] = {
            "validation": _load_scores(seed, "validation"),
            "test": _load_scores(seed, "test"),
        }
        scoring_seconds[seed] = time.time() - seed_started
        print(
            f"seed {seed}: scored validation={len(validation):,} "
            f"test={len(test):,} in {scoring_seconds[seed]:.1f}s"
        )

    metadata["scoring_seconds"] = scoring_seconds
    metadata["source_sha256"] = {
        filename: sha256_file(os.path.join(DATA_DIR, filename))
        for day, files in {**validation_files, **test_files}.items()
        for filename in files
    }
    metadata["feature_schema_sha256"] = sha256_json(list(joblib.load(
        os.path.join(MODEL_DIR, "model_bundle_rf_day_based_seed42.pkl")
    )["feature_names"]))
    return {"validation": validation, "test": test, "scores": all_scores, "metadata": metadata}


# ---------------------------------------------------------------------------
# Threshold metrics and policies
# ---------------------------------------------------------------------------
def _binary_metrics(truth: np.ndarray, score: np.ndarray, threshold: float) -> dict:
    truth = np.asarray(truth, dtype=int)
    predicted = np.asarray(score, dtype=float) >= float(threshold)
    positive = truth == 1
    negative = ~positive
    tp = int(np.sum(predicted & positive))
    fp = int(np.sum(predicted & negative))
    fn = int(np.sum(~predicted & positive))
    tn = int(np.sum(~predicted & negative))
    total = int(truth.size)
    return {
        "threshold": float(threshold),
        "total_flows": total,
        "attacks": int(positive.sum()),
        "benign": int(negative.sum()),
        "alerts": int(predicted.sum()),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "recall": float(tp / (tp + fn)) if (tp + fn) else 0.0,
        "precision": float(tp / (tp + fp)) if (tp + fp) else 0.0,
        "alert_rate": float(predicted.mean()) if total else 0.0,
        "alerts_per_10k": float(predicted.mean() * 10_000.0) if total else 0.0,
    }


def _per_family_recall(family_codes: np.ndarray, families: list[str], predicted: np.ndarray) -> dict:
    result = {}
    for index, family in enumerate(families):
        if family == "BENIGN":
            continue
        mask = family_codes == index
        support = int(mask.sum())
        if support == 0:
            result[family] = {"support": 0, "detected": 0, "recall": None}
            continue
        detected = int(np.sum(mask & predicted))
        result[family] = {
            "support": support,
            "detected": detected,
            "recall": float(detected / support),
        }
    return result


def _metrics_from_prediction(
    truth: np.ndarray,
    predicted: np.ndarray,
    threshold: float | None = None,
    decision_basis: str = "threshold",
) -> dict:
    truth = np.asarray(truth, dtype=int)
    predicted = np.asarray(predicted, dtype=bool)
    positive = truth == 1
    negative = ~positive
    tp = int(np.sum(predicted & positive))
    fp = int(np.sum(predicted & negative))
    fn = int(np.sum(~predicted & positive))
    tn = int(np.sum(~predicted & negative))
    total = int(truth.size)
    return {
        "threshold": threshold,
        "decision_basis": decision_basis,
        "total_flows": total,
        "attacks": int(positive.sum()),
        "benign": int(negative.sum()),
        "alerts": int(predicted.sum()),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "recall": float(tp / (tp + fn)) if (tp + fn) else 0.0,
        "precision": float(tp / (tp + fp)) if (tp + fp) else 0.0,
        "alert_rate": float(predicted.mean()) if total else 0.0,
        "alerts_per_10k": float(predicted.mean() * 10_000.0) if total else 0.0,
    }


def _evaluate_policy(
    truth: np.ndarray,
    score: np.ndarray,
    threshold_or_scores: float | np.ndarray,
    family_codes: np.ndarray,
    families: list[str],
    day_codes: np.ndarray | None = None,
    days: list[str] | None = None,
) -> dict:
    if np.isscalar(threshold_or_scores):
        predicted = score >= float(threshold_or_scores)
        threshold_used = float(threshold_or_scores)
    else:
        predicted = score >= np.asarray(threshold_or_scores, dtype=float)
        threshold_used = None

    overall = _metrics_from_prediction(truth, predicted, threshold_used)
    overall["per_family_recall"] = _per_family_recall(family_codes, families, predicted)

    by_day = {}
    if day_codes is not None and days is not None:
        for index, day in enumerate(days):
            mask = day_codes == index
            if not np.any(mask):
                continue
            day_predicted = predicted[mask]
            day_metrics = _metrics_from_prediction(
                truth[mask], day_predicted, threshold_used
            )
            day_metrics["per_family_recall"] = _per_family_recall(
                family_codes[mask], families, day_predicted
            )
            by_day[day] = day_metrics

    return {"overall": overall, "by_day": by_day}


def _select_global_threshold(validation: dict) -> dict:
    selection = select_threshold_at_max_fpr(
        validation["binary_truth"], validation["attack_score"], MAX_FPR
    )
    if selection is None:
        raise RuntimeError("Could not select a validation threshold")
    return selection


def _per_predicted_class_thresholds(validation: dict, classes: list[str], fallback: float) -> dict:
    thresholds = {}
    details = {}
    for index, label in enumerate(classes):
        mask = validation["argmax_index"] == index
        support = int(mask.sum())
        if support == 0 or np.unique(validation["binary_truth"][mask]).size < 2:
            thresholds[label] = float(fallback)
            details[label] = {
                "support": support,
                "threshold": float(fallback),
                "source": "global fallback",
                "validation_fpr": None,
                "validation_tpr": None,
            }
            continue
        selection = select_threshold_at_max_fpr(
            validation["binary_truth"][mask], validation["attack_score"][mask], MAX_FPR
        )
        if selection is None:
            thresholds[label] = float(fallback)
            details[label] = {
                "support": support,
                "threshold": float(fallback),
                "source": "global fallback",
                "validation_fpr": None,
                "validation_tpr": None,
            }
        else:
            thresholds[label] = float(selection["threshold"])
            details[label] = {
                "support": support,
                "threshold": float(selection["threshold"]),
                "source": "validation",
                "validation_fpr": float(selection["validation_fpr"]),
                "validation_tpr": float(selection["validation_tpr"]),
            }
    return {"thresholds": thresholds, "details": details}


def _operational_cost(metrics: dict, minutes_per_alert: float = ANALYST_MINUTES_PER_ALERT) -> dict:
    alerts = int(metrics["alerts"])
    false_positives = int(metrics["false_positives"])
    benign = int(metrics["benign"])
    excess_fpr = max(0.0, float(metrics["fpr"]) - MAX_FPR)
    return {
        "alerts": alerts,
        "alerts_per_day": alerts,
        "fpr": float(metrics["fpr"]),
        "alert_rate": float(metrics["alert_rate"]),
        "false_positives": false_positives,
        "false_positives_per_day": false_positives,
        "excess_fpr_over_budget": excess_fpr,
        "excess_false_positives_per_10k_benign": excess_fpr * 10_000.0,
        "analyst_minutes_per_alert_assumption": minutes_per_alert,
        "analyst_hours_per_day": alerts * minutes_per_alert / 60.0,
        "false_positive_review_hours_per_day": false_positives * minutes_per_alert / 60.0,
        "budget_breach": bool(excess_fpr > 0),
        "benign_flows": benign,
    }


def evaluate_threshold_policies(prepared: dict) -> dict:
    metadata = prepared["metadata"]
    families = metadata["families"]
    days = [str(value) for value in prepared["scores"][SEEDS[0]]["test"]["days"]]
    results = {"seeds": {}, "summary": {}, "true_family_policy": {}}

    for seed in SEEDS:
        validation = prepared["scores"][seed]["validation"]
        test = prepared["scores"][seed]["test"]
        classes = [str(value) for value in validation["classes"]]
        global_selection = _select_global_threshold(validation)
        global_threshold = float(global_selection["threshold"])

        # The frozen bundle records the threshold selected during training. It
        # must match this recomputation; a mismatch means the reloaded data or
        # scoring path is not the frozen one.
        bundle = joblib.load(os.path.join(MODEL_DIR, f"model_bundle_rf_day_based_seed{seed}.pkl"))
        frozen_threshold = float(bundle.get("attack_threshold"))
        threshold_match = math.isclose(global_threshold, frozen_threshold, rel_tol=1e-9, abs_tol=1e-12)

        global_eval = _evaluate_policy(
            test["binary_truth"], test["attack_score"], global_threshold,
            test["family_codes"], families, test["day_codes"], days,
        )

        per_class = _per_predicted_class_thresholds(validation, classes, global_threshold)
        per_class_threshold_array = np.asarray(
            [per_class["thresholds"][classes[int(index)]] for index in test["argmax_index"]],
            dtype=float,
        )
        per_class_eval = _evaluate_policy(
            test["binary_truth"], test["attack_score"], per_class_threshold_array,
            test["family_codes"], families, test["day_codes"], days,
        )
        per_class_eval["thresholds"] = per_class["thresholds"]
        per_class_eval["selection_details"] = per_class["details"]

        # A label-free day-aware policy: use the validation-selected alert rate
        # and take that quantile of each test day's unlabeled score distribution.
        validation_alert_rate = float(np.mean(validation["attack_score"] >= global_threshold))
        day_thresholds = {}
        day_threshold_array = np.empty(test["attack_score"].shape, dtype=float)
        for day_index, day in enumerate(days):
            mask = test["day_codes"] == day_index
            if not np.any(mask):
                continue
            threshold = float(np.quantile(test["attack_score"][mask], 1.0 - validation_alert_rate))
            day_thresholds[day] = threshold
            day_threshold_array[mask] = threshold
        day_aware_eval = _evaluate_policy(
            test["binary_truth"], test["attack_score"], day_threshold_array,
            test["family_codes"], families, test["day_codes"], days,
        )
        day_aware_eval["validation_alert_rate"] = validation_alert_rate
        day_aware_eval["thresholds_by_day"] = day_thresholds
        day_aware_eval["note"] = (
            "Uses the validation-selected alert rate and each test day's unlabeled "
            "score distribution. It is label-free but not a frozen threshold."
        )

        benign_index = classes.index("BENIGN")
        argmax_predicted = test["argmax_index"] != benign_index
        argmax_eval = {
            "overall": _metrics_from_prediction(
                test["binary_truth"], argmax_predicted, None, decision_basis="argmax"
            ),
            "by_day": {},
            "decision_basis": "argmax",
        }
        for day_index, day in enumerate(days):
            mask = test["day_codes"] == day_index
            argmax_eval["by_day"][day] = _metrics_from_prediction(
                test["binary_truth"][mask], argmax_predicted[mask], None, decision_basis="argmax"
            )
            argmax_eval["by_day"][day]["per_family_recall"] = _per_family_recall(
                test["family_codes"][mask], families, argmax_predicted[mask]
            )
        argmax_eval["overall"]["per_family_recall"] = _per_family_recall(
            test["family_codes"], families, argmax_predicted
        )

        results["seeds"][str(seed)] = {
            "artifact_sha256": sha256_file(
                os.path.join(MODEL_DIR, f"model_bundle_rf_day_based_seed{seed}.pkl")
            ),
            "frozen_threshold": frozen_threshold,
            "recomputed_validation_threshold": global_threshold,
            "threshold_matches_frozen": bool(threshold_match),
            "validation_selection": {
                "threshold": global_threshold,
                "validation_fpr": float(global_selection["validation_fpr"]),
                "validation_tpr": float(global_selection["validation_tpr"]),
                "selected_on": "Wednesday validation only",
                "max_fpr": MAX_FPR,
            },
            "global": {
                **global_eval,
                "operational_cost": _operational_cost(global_eval["overall"]),
                "operational_cost_by_day": {
                    day: _operational_cost(values) for day, values in global_eval["by_day"].items()
                },
            },
            "per_predicted_class": per_class_eval,
            "day_aware_quantile": day_aware_eval,
            "argmax": argmax_eval,
        }
        print(
            f"seed {seed}: threshold={global_threshold:.8f} "
            f"test FPR={global_eval['overall']['fpr']:.4%} "
            f"recall={global_eval['overall']['recall']:.2%} "
            f"alerts={global_eval['overall']['alerts']:,}"
        )

    # True-family thresholds can only be selected for families present in
    # validation. The test families are different, so this policy cannot be
    # applied to held-out families without inventing thresholds.
    validation_families = sorted(
        set(canonical_label(value) for value in metadata["validation_label_counts"])
    )
    test_families = sorted(
        set(canonical_label(value) for value in metadata["test_label_counts"])
    )
    validation_attack_families = [value for value in validation_families if value != "BENIGN"]
    test_attack_families = [value for value in test_families if value != "BENIGN"]
    results["true_family_policy"] = {
        "applicable": False,
        "validation_families": validation_families,
        "test_families": test_families,
        "overlap": sorted(set(validation_families) & set(test_families)),
        "validation_attack_families": validation_attack_families,
        "test_attack_families": test_attack_families,
        "reason": (
            "A per-true-family threshold can only be selected for a family that "
            "appears in validation with both benign and attack rows. None of the "
            "held-out test attack families has a validation-selected threshold. "
            "Applying a fallback threshold to unseen families would not be a "
            "per-family policy."
        ),
    }

    # Summaries across seeds.
    def _collect(path: list[str]) -> list[float]:
        values = []
        for seed in SEEDS:
            node = results["seeds"][str(seed)]
            for key in path:
                node = node[key]
            if node is not None:
                values.append(float(node))
        return values

    summary = {}
    for policy in ["global", "per_predicted_class", "day_aware_quantile", "argmax"]:
        summary[policy] = {}
        for metric in ["fpr", "recall", "precision", "alert_rate", "alerts"]:
            summary[policy][metric] = mean_std(_collect([policy, "overall", metric]))
        summary[policy]["by_day"] = {}
        for day in days:
            summary[policy]["by_day"][day] = {}
            for metric in ["fpr", "recall", "precision", "alert_rate", "alerts"]:
                summary[policy]["by_day"][day][metric] = mean_std(
                    _collect([policy, "by_day", day, metric])
                )
    results["summary"] = summary
    results["metadata"] = metadata
    return results


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------
def _sigmoid(value: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-value))


def _logit(probability: np.ndarray) -> np.ndarray:
    clipped = np.clip(np.asarray(probability, dtype=float), EPS, 1.0 - EPS)
    return np.log(clipped / (1.0 - clipped))


def _brier(truth: np.ndarray, probability: np.ndarray) -> float:
    return float(np.mean((np.asarray(probability, dtype=float) - np.asarray(truth, dtype=float)) ** 2))


def _reliability_bins(truth: np.ndarray, probability: np.ndarray, bins: int = RELIABILITY_BINS) -> dict:
    truth = np.asarray(truth, dtype=int)
    probability = np.asarray(probability, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    rows = []
    ece = 0.0
    for index in range(bins):
        lower, upper = float(edges[index]), float(edges[index + 1])
        if index == bins - 1:
            mask = (probability >= lower) & (probability <= upper)
        else:
            mask = (probability >= lower) & (probability < upper)
        count = int(mask.sum())
        if count == 0:
            rows.append({
                "lower": lower,
                "upper": upper,
                "count": 0,
                "mean_predicted": None,
                "observed_frequency": None,
                "absolute_gap": None,
            })
            continue
        mean_predicted = float(probability[mask].mean())
        observed = float(truth[mask].mean())
        gap = abs(observed - mean_predicted)
        ece += (count / truth.size) * gap
        rows.append({
            "lower": lower,
            "upper": upper,
            "count": count,
            "mean_predicted": mean_predicted,
            "observed_frequency": observed,
            "absolute_gap": gap,
        })
    return {"bins": rows, "ece": float(ece)}


def _calibration_metrics(truth: np.ndarray, probability: np.ndarray) -> dict:
    truth = np.asarray(truth, dtype=int)
    probability = np.asarray(probability, dtype=float)
    reliability = _reliability_bins(truth, probability)
    return {
        "rows": int(truth.size),
        "attack_prevalence": float(truth.mean()) if truth.size else None,
        "brier_score": _brier(truth, probability),
        "log_loss": float(log_loss(truth, np.clip(probability, EPS, 1.0 - EPS), labels=[0, 1])),
        "ece_10_bins": reliability["ece"],
        "reliability": reliability,
    }


def _fit_temperature(truth: np.ndarray, probability: np.ndarray) -> float:
    logits = _logit(probability)

    def objective(log_temperature: float) -> float:
        temperature = math.exp(float(log_temperature))
        calibrated = _sigmoid(logits / temperature)
        return float(log_loss(truth, np.clip(calibrated, EPS, 1.0 - EPS), labels=[0, 1]))

    result = minimize_scalar(objective, bounds=(math.log(0.05), math.log(20.0)), method="bounded")
    return float(math.exp(result.x))


def _apply_temperature(probability: np.ndarray, temperature: float) -> np.ndarray:
    return _sigmoid(_logit(probability) / temperature)


def _fit_isotonic(truth: np.ndarray, probability: np.ndarray) -> IsotonicRegression:
    model = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    model.fit(probability, truth)
    return model


def _decision_curve(truth: np.ndarray, probability: np.ndarray) -> list[dict]:
    truth = np.asarray(truth, dtype=int)
    probability = np.asarray(probability, dtype=float)
    total = truth.size
    prevalence = float(truth.mean()) if total else 0.0
    rows = []
    for threshold in DECISION_THRESHOLDS:
        predicted = probability >= threshold
        tp = int(np.sum(predicted & (truth == 1)))
        fp = int(np.sum(predicted & (truth == 0)))
        net_benefit = (tp / total) - (fp / total) * (threshold / (1.0 - threshold))
        treat_all = prevalence - (1.0 - prevalence) * (threshold / (1.0 - threshold))
        rows.append({
            "threshold_probability": threshold,
            "net_benefit": float(net_benefit),
            "treat_all_net_benefit": float(treat_all),
            "treat_none_net_benefit": 0.0,
            "alerts": int(predicted.sum()),
        })
    return rows


def evaluate_calibration(prepared: dict) -> dict:
    metadata = prepared["metadata"]
    families = metadata["families"]
    days = [str(value) for value in prepared["scores"][SEEDS[0]]["test"]["days"]]
    results = {"seeds": {}, "summary": {}, "target": "binary_attack_score"}
    for seed in SEEDS:
        validation = prepared["scores"][seed]["validation"]
        test = prepared["scores"][seed]["test"]
        truth = test["binary_truth"]
        uncalibrated = test["attack_score"]

        temperature = _fit_temperature(validation["binary_truth"], validation["attack_score"])
        temperature_scores = _apply_temperature(uncalibrated, temperature)
        isotonic = _fit_isotonic(validation["binary_truth"], validation["attack_score"])
        isotonic_scores = isotonic.predict(uncalibrated)

        methods = {
            "uncalibrated": uncalibrated,
            "temperature": temperature_scores,
            "isotonic": isotonic_scores,
        }
        seed_result = {
            "artifact_sha256": sha256_file(
                os.path.join(MODEL_DIR, f"model_bundle_rf_day_based_seed{seed}.pkl")
            ),
            "parameters": {
                "temperature": temperature,
                "isotonic_x": [float(value) for value in isotonic.X_thresholds_],
                "isotonic_y": [float(value) for value in isotonic.y_thresholds_],
                "fit_partition": "Wednesday validation only",
                "target": "binary attack score (1 - P(BENIGN))",
            },
            "methods": {},
            "threshold_interaction": {},
            "decision_curve": {},
        }

        for method, scores in methods.items():
            method_result = {
                "overall": _calibration_metrics(truth, scores),
                "by_day": {},
                "by_family": {},
            }
            for day_index, day in enumerate(days):
                mask = test["day_codes"] == day_index
                method_result["by_day"][day] = _calibration_metrics(truth[mask], scores[mask])
            for family_index in sorted(set(int(value) for value in test["family_codes"])):
                family = families[family_index]
                mask = test["family_codes"] == family_index
                method_result["by_family"][family] = _calibration_metrics(truth[mask], scores[mask])
            method_result["decision_curve"] = _decision_curve(truth, scores)
            seed_result["methods"][method] = method_result

        # Threshold interaction. Reselect the threshold on calibrated
        # validation scores, then apply it to calibrated test scores. Also show
        # the common mistake of keeping the uncalibrated threshold after
        # calibration.
        for method, scores in methods.items():
            if method == "uncalibrated":
                validation_scores = validation["attack_score"]
            elif method == "temperature":
                validation_scores = _apply_temperature(validation["attack_score"], temperature)
            else:
                validation_scores = isotonic.predict(validation["attack_score"])
            selection = select_threshold_at_max_fpr(
                validation["binary_truth"], validation_scores, MAX_FPR
            )
            calibrated_threshold = float(selection["threshold"])
            reselected_metrics = _binary_metrics(truth, scores, calibrated_threshold)
            seed_result["threshold_interaction"][method] = {
                "validation_selected_threshold": calibrated_threshold,
                "validation_fpr": float(selection["validation_fpr"]),
                "validation_tpr": float(selection["validation_tpr"]),
                "test_at_reselected_threshold": reselected_metrics,
            }

        uncalibrated_selection = select_threshold_at_max_fpr(
            validation["binary_truth"], validation["attack_score"], MAX_FPR
        )
        uncalibrated_threshold = float(uncalibrated_selection["threshold"])
        for method, scores in methods.items():
            if method == "uncalibrated":
                continue
            seed_result["threshold_interaction"][method]["test_with_uncalibrated_threshold"] = _binary_metrics(
                truth, scores, uncalibrated_threshold
            )
            seed_result["threshold_interaction"][method]["threshold_value_changed"] = (
                not math.isclose(
                    seed_result["threshold_interaction"][method]["validation_selected_threshold"],
                    uncalibrated_threshold,
                    rel_tol=1e-9,
                    abs_tol=1e-12,
                )
            )

        # Ranking invariance: temperature scaling and isotonic regression are
        # monotonic, so a rank-based alert budget is unchanged. Spearman is
        # computed on a deterministic sample to keep the evaluation bounded.
        rng = np.random.default_rng(seed)
        sample_size = min(int(uncalibrated.size), 50_000)
        sample_index = rng.choice(int(uncalibrated.size), size=sample_size, replace=False)
        seed_result["ranking_invariance"] = {
            "temperature_spearman": float(
                pd.Series(uncalibrated[sample_index]).corr(
                    pd.Series(temperature_scores[sample_index]), method="spearman"
                )
            ),
            "isotonic_spearman": float(
                pd.Series(uncalibrated[sample_index]).corr(
                    pd.Series(isotonic_scores[sample_index]), method="spearman"
                )
            ),
            "sample_rows": sample_size,
            "note": (
                "Calibration is monotonic in theory, so it preserves the ordering up "
                "to ties and isotonic plateaus. A top-K alert budget therefore selects "
                "the same set except for tie-breaking at the cut point; a "
                "probability-threshold policy must reselect its threshold."
            ),
        }

        # Save the calibration artifact for this seed. The serving path is a
        # different artifact and remains explicitly uncalibrated.
        calibration_version = f"rf-day-based-seed{seed}-isotonic-v1"
        calibration_path = os.path.join(MODEL_DIR, f"calibration_rf_day_based_seed{seed}.json")
        with open(calibration_path, "w", encoding="utf-8") as handle:
            json.dump({
                "calibration_version": calibration_version,
                "method": "isotonic",
                "target": "binary_attack_score",
                "fit_partition": "validation (Wednesday)",
                "seed": seed,
                "artifact_sha256": seed_result["artifact_sha256"],
                "feature_schema_sha256": metadata["feature_schema_sha256"],
                "parameters": seed_result["parameters"],
                "validation_rows": int(validation["binary_truth"].size),
                "validation_attack_prevalence": float(validation["binary_truth"].mean()),
                "metrics": seed_result["methods"]["isotonic"]["overall"],
            }, handle, indent=2, sort_keys=True)
        seed_result["calibration_artifact"] = calibration_path
        seed_result["calibration_version"] = calibration_version
        results["seeds"][str(seed)] = seed_result

    for method in ["uncalibrated", "temperature", "isotonic"]:
        results["summary"][method] = {
            "ece_10_bins": mean_std([
                results["seeds"][str(seed)]["methods"][method]["overall"]["ece_10_bins"]
                for seed in SEEDS
            ]),
            "brier_score": mean_std([
                results["seeds"][str(seed)]["methods"][method]["overall"]["brier_score"]
                for seed in SEEDS
            ]),
            "log_loss": mean_std([
                results["seeds"][str(seed)]["methods"][method]["overall"]["log_loss"]
                for seed in SEEDS
            ]),
        }
    results["metadata"] = metadata
    return results


# ---------------------------------------------------------------------------
# SVG figures (no matplotlib dependency)
# ---------------------------------------------------------------------------
def _svg_text(x, y, text, size=12, anchor="start", color="#1f2937", weight="normal"):
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-family="Inter, Arial, sans-serif" '
        f'font-size="{size}" text-anchor="{anchor}" fill="{color}" font-weight="{weight}">'
        f'{html.escape(str(text))}</text>'
    )


def _svg_panel(series, title, x0, y0, width, height):
    left, top = x0 + 48, y0 + 30
    plot_w, plot_h = width - 70, height - 66
    parts = [
        f'<rect x="{x0}" y="{y0}" width="{width}" height="{height}" fill="#ffffff" stroke="#d1d5db"/>',
        _svg_text(x0 + width / 2, y0 + 20, title, size=13, anchor="middle", weight="600"),
    ]
    # grid
    for step in range(5):
        value = step / 4
        gx = left + value * plot_w
        gy = top + plot_h - value * plot_h
        parts.append(f'<line x1="{left}" y1="{gy:.1f}" x2="{left + plot_w}" y2="{gy:.1f}" stroke="#e5e7eb"/>')
        parts.append(f'<line x1="{gx:.1f}" y1="{top}" x2="{gx:.1f}" y2="{top + plot_h}" stroke="#e5e7eb"/>')
        parts.append(_svg_text(left - 6, gy + 4, f"{value:.1f}", size=10, anchor="end", color="#6b7280"))
        parts.append(_svg_text(gx, top + plot_h + 16, f"{value:.1f}", size=10, anchor="middle", color="#6b7280"))
    parts.append(f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top}" stroke="#9ca3af" stroke-dasharray="4 4"/>')
    parts.append(_svg_text(left + plot_w / 2, top + plot_h + 34, "Mean predicted probability", size=10, anchor="middle", color="#4b5563"))
    parts.append(f'<text x="{x0 + 14}" y="{top + plot_h / 2}" font-family="Inter, Arial, sans-serif" font-size="10" fill="#4b5563" text-anchor="middle" transform="rotate(-90 {x0 + 14} {top + plot_h / 2})">Observed frequency</text>')
    for item in series:
        color = item["color"]
        points = []
        for row in item["bins"]:
            if row["count"] == 0 or row["mean_predicted"] is None:
                continue
            px = left + row["mean_predicted"] * plot_w
            py = top + plot_h - row["observed_frequency"] * plot_h
            radius = max(2.5, min(9.0, 2.5 + math.sqrt(row["count"]) / 18.0))
            points.append((px, py, radius, row))
        if len(points) >= 2:
            path = " ".join(f"{px:.1f},{py:.1f}" for px, py, _, _ in points)
            parts.append(f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="2"/>')
        for px, py, radius, row in points:
            parts.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{radius:.1f}" fill="{color}" fill-opacity="0.75" stroke="#ffffff"/>')
    # legend
    legend_x = left
    legend_y = y0 + height - 12
    for index, item in enumerate(series):
        x = legend_x + index * 150
        parts.append(f'<rect x="{x}" y="{legend_y - 9}" width="12" height="12" fill="{item["color"]}"/>')
        parts.append(_svg_text(x + 17, legend_y, item["name"], size=10, color="#374151"))
    return "\n".join(parts)


def write_reliability_svg(path: str, title: str, panels: list[dict]) -> None:
    """Write a simple multi-panel reliability diagram as standalone SVG."""
    columns = min(2, len(panels))
    rows = math.ceil(len(panels) / columns)
    panel_w, panel_h = 520, 360
    width = columns * panel_w + 20
    height = rows * panel_h + 30
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" fill="#f9fafb"/>',
        _svg_text(width / 2, 22, title, size=16, anchor="middle", weight="700"),
    ]
    for index, panel in enumerate(panels):
        column = index % columns
        row = index // columns
        parts.append(_svg_panel(
            panel["series"], panel["title"],
            10 + column * panel_w, 34 + row * panel_h, panel_w - 10, panel_h - 10,
        ))
    parts.append("</svg>")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(parts))


def write_decision_curve_svg(path: str, title: str, curves: dict) -> None:
    width, height = 720, 460
    left, top, plot_w, plot_h = 70, 50, 610, 350
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        _svg_text(width / 2, 26, title, size=16, anchor="middle", weight="700"),
    ]
    for step in range(6):
        value = step / 5
        gx = left + value * plot_w
        gy = top + plot_h - value * plot_h
        parts.append(f'<line x1="{left}" y1="{gy:.1f}" x2="{left + plot_w}" y2="{gy:.1f}" stroke="#e5e7eb"/>')
        parts.append(f'<line x1="{gx:.1f}" y1="{top}" x2="{gx:.1f}" y2="{top + plot_h}" stroke="#e5e7eb"/>')
        parts.append(_svg_text(left - 8, gy + 4, f"{value:.2f}", size=10, anchor="end", color="#6b7280"))
        parts.append(_svg_text(gx, top + plot_h + 16, f"{value:.2f}", size=10, anchor="middle", color="#6b7280"))
    parts.append(_svg_text(left + plot_w / 2, top + plot_h + 38, "Threshold probability", size=11, anchor="middle", color="#4b5563"))
    parts.append(f'<text x="{left - 48}" y="{top + plot_h / 2}" font-family="Inter, Arial, sans-serif" font-size="11" fill="#4b5563" text-anchor="middle" transform="rotate(-90 {left - 48} {top + plot_h / 2})">Net benefit</text>')
    all_values = []
    for curve in curves.values():
        all_values.extend(row["net_benefit"] for row in curve)
        all_values.extend(row["treat_all_net_benefit"] for row in curve)
    y_min = min(all_values + [0.0]) - 0.02
    y_max = max(all_values + [0.0]) + 0.02
    span = max(y_max - y_min, 1e-6)

    def sx(value):
        return left + (value - DECISION_THRESHOLDS[0]) / (DECISION_THRESHOLDS[-1] - DECISION_THRESHOLDS[0]) * plot_w

    def sy(value):
        return top + plot_h - (value - y_min) / span * plot_h

    colors = {"uncalibrated": "#6b7280", "temperature": "#2563eb", "isotonic": "#059669", "treat_all": "#dc2626"}
    for name, curve in curves.items():
        color = colors.get(name, "#111827")
        points = " ".join(f"{sx(row['threshold_probability']):.1f},{sy(row['net_benefit']):.1f}" for row in curve)
        parts.append(f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2"/>')
        for row in curve:
            parts.append(f'<circle cx="{sx(row["threshold_probability"]):.1f}" cy="{sy(row["net_benefit"]):.1f}" r="2.5" fill="{color}"/>')
    treat_all = next(iter(curves.values()), None)
    if treat_all:
        points = " ".join(f"{sx(row['threshold_probability']):.1f},{sy(row['treat_all_net_benefit']):.1f}" for row in treat_all)
        parts.append(f'<polyline points="{points}" fill="none" stroke="{colors["treat_all"]}" stroke-width="1.5" stroke-dasharray="5 4"/>')
    legend_y = height - 20
    for index, (name, color) in enumerate([
        ("Uncalibrated", colors["uncalibrated"]),
        ("Temperature", colors["temperature"]),
        ("Isotonic", colors["isotonic"]),
        ("Treat all", colors["treat_all"]),
    ]):
        x = left + index * 150
        parts.append(f'<rect x="{x}" y="{legend_y - 10}" width="12" height="12" fill="{color}"/>')
        parts.append(_svg_text(x + 17, legend_y, name, size=10, color="#374151"))
    parts.append("</svg>")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(parts))


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------
def _pct(value) -> str:
    return "n/a" if value is None else f"{100.0 * float(value):.2f}%"


def _num(value, digits=4) -> str:
    return "n/a" if value is None else f"{float(value):.{digits}f}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def render_threshold_markdown(results: dict, output_path: str) -> None:
    metadata = results["metadata"]
    lines = [
        "# Threshold Policy Across Day Shift (D4)",
        "",
        f"Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## What was measured",
        "",
        "One attack-score threshold per seed was selected on the Wednesday validation partition at a maximum false-positive rate of 1%. The threshold was then applied unchanged to Thursday and Friday. No test label was used to choose a threshold.",
        "",
        f"- Validation rows: {metadata['validation_rows']:,} (Wednesday)",
        f"- Test rows: {metadata['test_rows']:,} (Thursday {metadata['test_rows_by_day']['Thursday']:,}; Friday {metadata['test_rows_by_day']['Friday']:,})",
        f"- Seeds: {', '.join(str(seed) for seed in SEEDS)}",
        "- Attack score: `1 - P(BENIGN)` from the frozen Random Forest bundle.",
        "",
        "The primary policy is the global validation threshold. The per-predicted-class and day-aware policies are comparisons, not replacements selected on test.",
        "",
        "## Primary global policy",
        "",
        _table(
            ["Seed", "Validation FPR", "Validation TPR", "Test FPR", "Recall", "Precision", "Alert rate", "Alerts"],
            [
                [
                    str(seed),
                    _pct(results["seeds"][str(seed)]["validation_selection"]["validation_fpr"]),
                    _pct(results["seeds"][str(seed)]["validation_selection"]["validation_tpr"]),
                    _pct(results["seeds"][str(seed)]["global"]["overall"]["fpr"]),
                    _pct(results["seeds"][str(seed)]["global"]["overall"]["recall"]),
                    _pct(results["seeds"][str(seed)]["global"]["overall"]["precision"]),
                    _pct(results["seeds"][str(seed)]["global"]["overall"]["alert_rate"]),
                    f"{results['seeds'][str(seed)]['global']['overall']['alerts']:,}",
                ]
                for seed in SEEDS
            ],
        ),
        "",
        "The validation target does not transfer. The five-seed mean test FPR is "
        f"{_pct(results['summary']['global']['fpr']['mean'])} with a standard deviation of "
        f"{_pct(results['summary']['global']['fpr']['std'])}. The worst seed is "
        f"{_pct(max(results['seeds'][str(seed)]['global']['overall']['fpr'] for seed in SEEDS))}.",
        "",
        "Per-family recall at the frozen threshold, by seed:",
        "",
        _table(
            ["Family"] + [f"Seed {seed}" for seed in SEEDS],
            [
                [
                    family,
                    *[
                        _pct(results["seeds"][str(seed)]["global"]["overall"]["per_family_recall"].get(family, {}).get("recall"))
                        for seed in SEEDS
                    ],
                ]
                for family in metadata["test_families"]
                if family != "BENIGN"
            ],
        ),
        "",
        "## Per-day results at the frozen threshold",
        "",
        "The aggregate test FPR hides day-level breaches. For seed 42 the aggregate FPR is "
        f"{_pct(results['seeds']['42']['global']['overall']['fpr'])}, but Thursday alone is "
        f"{_pct(results['seeds']['42']['global']['by_day']['Thursday']['fpr'])}. The threshold "
        "is not stable within the held-out period, let alone across seeds.",
        "",
    ]
    for seed in SEEDS:
        lines.append(f"### Seed {seed}")
        lines.append("")
        rows = []
        for day in DAY_ORDER:
            day_metrics = results["seeds"][str(seed)]["global"]["by_day"].get(day)
            if not day_metrics:
                continue
            rows.append([
                day,
                f"{day_metrics['total_flows']:,}",
                _pct(day_metrics["fpr"]),
                _pct(day_metrics["recall"]),
                _pct(day_metrics["precision"]),
                _pct(day_metrics["alert_rate"]),
                f"{day_metrics['alerts']:,}",
            ])
        lines.append(_table(
            ["Day", "Flows", "FPR", "Recall", "Precision", "Alert rate", "Alerts"],
            rows,
        ))
        lines.append("")
        lines.append("Per-family recall by day:")
        lines.append("")
        family_rows = []
        for day in DAY_ORDER:
            day_metrics = results["seeds"][str(seed)]["global"]["by_day"].get(day)
            if not day_metrics:
                continue
            for family, values in day_metrics["per_family_recall"].items():
                if values["support"] == 0:
                    continue
                family_rows.append([
                    day,
                    family,
                    f"{values['support']:,}",
                    f"{values['detected']:,}",
                    _pct(values["recall"]),
                ])
        lines.append(_table(["Day", "Family", "Support", "Detected", "Recall"], family_rows))
        lines.append("")

    lines.extend([
        "## Policy comparison",
        "",
        "The table reports the five-seed mean and standard deviation of test FPR, recall, precision, and alert rate. The global policy is the only policy selected entirely on validation and applied unchanged to every test day.",
        "",
        _table(
            ["Policy", "FPR", "Recall", "Precision", "Alert rate"],
            [
                [
                    policy,
                    f"{_pct(values['fpr']['mean'])} ± {_pct(values['fpr']['std'])}",
                    f"{_pct(values['recall']['mean'])} ± {_pct(values['recall']['std'])}",
                    f"{_pct(values['precision']['mean'])} ± {_pct(values['precision']['std'])}",
                    f"{_pct(values['alert_rate']['mean'])} ± {_pct(values['alert_rate']['std'])}",
                ]
                for policy, values in [
                    ("Global validation threshold", results["summary"]["global"]),
                    ("Per-predicted-class threshold", results["summary"]["per_predicted_class"]),
                    ("Day-aware score quantile", results["summary"]["day_aware_quantile"]),
                    ("RF argmax (no threshold)", results["summary"]["argmax"]),
                ]
            ],
        ),
        "",
        "### Per-predicted-class policy",
        "",
        "This policy selects a threshold for each predicted class (BENIGN, FTP-Patator, SSH-Patator) on validation. It is label-free at serving time because the predicted class is available. It is not a per-true-family policy: the test attack families are unseen.",
        "",
    ])
    for seed in SEEDS:
        details = results["seeds"][str(seed)]["per_predicted_class"]["selection_details"]
        lines.append(f"Seed {seed}: " + "; ".join(
            f"`{label}` = {value['threshold']:.8f} ({value['source']})"
            for label, value in details.items()
        ))
    lines.extend([
        "",
        "In this split the policy collapses to the global policy: the Wednesday validation partition contains BENIGN and DoS families, so the model never predicts FTP-Patator or SSH-Patator there. Both class-specific thresholds therefore fall back to the global threshold. A genuine per-predicted-class policy would need validation data that exercises those predicted classes.",
    ])
    lines.extend([
        "",
        "### Per-true-family policy",
        "",
        "Not applicable. A per-family threshold can only be selected for a family that appears in validation with both benign and attack rows. The held-out test attack families are different from the validation attack families, so there is no validation-selected threshold to apply.",
        "",
        f"- Validation families: {', '.join(results['true_family_policy']['validation_families'])}",
        f"- Test families: {', '.join(results['true_family_policy']['test_families'])}",
        f"- Overlap: {', '.join(results['true_family_policy']['overlap']) or 'none'}",
        "",
        "### Day-aware score-quantile policy",
        "",
        "This policy uses the validation-selected alert rate and takes that quantile of each test day's unlabeled score distribution. It is label-free but not a frozen threshold: it adapts to the test day's score distribution. It is reported as an operational alternative, not as a validation-selected policy.",
        "",
        _table(
            ["Seed", "Validation alert rate", "Thursday threshold", "Friday threshold", "Test FPR", "Recall", "Alerts"],
            [
                [
                    str(seed),
                    _pct(results["seeds"][str(seed)]["day_aware_quantile"]["validation_alert_rate"]),
                    _num(results["seeds"][str(seed)]["day_aware_quantile"]["thresholds_by_day"].get("Thursday"), 8),
                    _num(results["seeds"][str(seed)]["day_aware_quantile"]["thresholds_by_day"].get("Friday"), 8),
                    _pct(results["seeds"][str(seed)]["day_aware_quantile"]["overall"]["fpr"]),
                    _pct(results["seeds"][str(seed)]["day_aware_quantile"]["overall"]["recall"]),
                    f"{results['seeds'][str(seed)]['day_aware_quantile']['overall']['alerts']:,}",
                ]
                for seed in SEEDS
            ],
        ),
        "",
        "The day-aware policy keeps the alert rate near the validation rate, but it does not hold the false-positive rate: seed 44 still reaches 6.59% FPR. It also gives up most recall because it spends the budget on the highest-scoring flows, which are dominated by DDoS and PortScan. It is a label-free operational control, not a fix for threshold transfer.",
        "",
        "## Operational cost when the threshold does not transfer",
        "",
        f"Assumption: {ANALYST_MINUTES_PER_ALERT:.0f} analyst minutes per alert. The cost below is the measured alert volume and false-positive volume at the frozen threshold, not a staffing recommendation.",
        "",
        _table(
            ["Seed", "Day", "Alerts", "False positives", "FPR", "Excess FPR over 1%", "Alert review hours", "FP review hours"],
            [
                [
                    str(seed),
                    day,
                    f"{values['alerts']:,}",
                    f"{values['false_positives']:,}",
                    _pct(values["fpr"]),
                    _pct(values["excess_fpr_over_budget"]),
                    f"{values['analyst_hours_per_day']:.1f}",
                    f"{values['false_positive_review_hours_per_day']:.1f}",
                ]
                for seed in SEEDS
                for day, values in results["seeds"][str(seed)]["global"]["operational_cost_by_day"].items()
            ],
        ),
        "",
        "The highest measured cost is not a small calibration error. At the worst seed and day, the frozen threshold generates tens of thousands of false positives, which is thousands of analyst hours at five minutes per alert. That is the operating cost of claiming a 1% FPR bound without a policy that transfers.",
        "",
        "False-positive rate is not the whole cost. On Friday the attack prevalence is high, so the same threshold produces more than 160,000 alerts for every seed even when the measured FPR is below 1%. At five minutes per alert that is over 13,000 review hours per day. The operating cost includes alert volume, not only false positives.",
        "",
        "## Serving-path decision",
        "",
        "The serving bundle is the evaluated seed 42 Random Forest `models/model_bundle_rf_day_based_seed42.pkl`. It contains `attack_threshold=0.002515048908954043` and `threshold_selection_max_fpr=0.01`. The serving path applies that attack-score threshold and records the decision basis, threshold, artifact hash, feature-schema version, model version, and calibration version on every stored prediction. The raw argmax label is stored separately so the threshold decision is auditable.",
        "",
        "## Honest conclusion",
        "",
        "- A threshold selected on Wednesday validation does not preserve a 1% FPR on Thursday and Friday.",
        "- Seed 42 is not representative. Reporting only seed 42 hides the five-seed spread and the worst-case operating cost.",
        "- Per-predicted-class thresholds are implementable but do not solve the unseen-family problem.",
        "- A day-aware quantile policy can hold an alert-rate budget, but it is not a validation-selected threshold and it uses each day's unlabeled score distribution.",
        "- The serving artifact is not the evaluated artifact. The threshold policy is applied, but the serving model remains a different, weaker model with only three output classes.",
        "",
        "## Reproduction",
        "",
        "```bash",
        "python -m training.threshold_calibration_v2 --force",
        "pytest tests -q",
        "```",
        "",
        f"Artifacts: `{output_path}` and `docs/threshold_policy_v2.json`.",
    ])
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def render_calibration_markdown(results: dict, output_path: str) -> None:
    metadata = results["metadata"]
    lines = [
        "# Probability Calibration on Held-Out Days (D5)",
        "",
        f"Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## Scope",
        "",
        "Calibration is evaluated for the binary attack score `1 - P(BENIGN)` from the frozen Random Forest bundles for seeds 42-46. Temperature scaling and isotonic regression are fitted on the Wednesday validation partition only and applied unchanged to Thursday and Friday.",
        "",
        "Multiclass calibration is not attempted. The model has three output classes (BENIGN, FTP-Patator, SSH-Patator), while the validation partition contains BENIGN and DoS families and the test partition contains seven unseen attack families. A multiclass calibration target is not identifiable across those partitions. The binary attack score is the score used by the threshold policy, so it is the relevant calibration target.",
        "",
        f"- Validation rows: {metadata['validation_rows']:,} (Wednesday)",
        f"- Test rows: {metadata['test_rows']:,} (Thursday {metadata['test_rows_by_day']['Thursday']:,}; Friday {metadata['test_rows_by_day']['Friday']:,})",
        "- ECE: 10 equal-width bins, weighted by bin population.",
        "- Brier score: mean squared error of the binary attack probability.",
        "",
        "## Overall calibration",
        "",
        _table(
            ["Method", "ECE (mean ± sd)", "Brier (mean ± sd)", "Log loss (mean ± sd)"],
            [
                [
                    method,
                    f"{_num(values['ece_10_bins']['mean'])} ± {_num(values['ece_10_bins']['std'])}",
                    f"{_num(values['brier_score']['mean'])} ± {_num(values['brier_score']['std'])}",
                    f"{_num(values['log_loss']['mean'])} ± {_num(values['log_loss']['std'])}",
                ]
                for method, values in results["summary"].items()
            ],
        ),
        "",
        "The uncalibrated score is already a poor probability: its ECE is far above the 0.05 gate in the evaluation protocol. Temperature scaling and isotonic regression improve the probability scale on validation, but they only preserve the ordering up to ties. The held-out ECE and Brier values below show whether the improvement transfers.",
        "",
        "## Per-seed calibration",
        "",
        _table(
            ["Seed", "Method", "ECE", "Brier", "Log loss"],
            [
                [
                    str(seed),
                    method,
                    _num(results["seeds"][str(seed)]["methods"][method]["overall"]["ece_10_bins"]),
                    _num(results["seeds"][str(seed)]["methods"][method]["overall"]["brier_score"]),
                    _num(results["seeds"][str(seed)]["methods"][method]["overall"]["log_loss"]),
                ]
                for seed in SEEDS
                for method in ["uncalibrated", "temperature", "isotonic"]
            ],
        ),
        "",
        "## Reliability by day (seed 42)",
        "",
        _table(
            ["Day", "Method", "ECE", "Brier", "Rows"],
            [
                [
                    day,
                    method,
                    _num(results["seeds"]["42"]["methods"][method]["by_day"][day]["ece_10_bins"]),
                    _num(results["seeds"]["42"]["methods"][method]["by_day"][day]["brier_score"]),
                    f"{results['seeds']['42']['methods'][method]['by_day'][day]['rows']:,}",
                ]
                for day in DAY_ORDER
                for method in ["uncalibrated", "temperature", "isotonic"]
            ],
        ),
        "",
        "Thursday's uncalibrated ECE is low because Thursday is dominated by BENIGN flows and the attack prevalence is very low; a low ECE there does not mean the score is calibrated on Friday. Friday's uncalibrated ECE is 0.4066. The day-level split is the relevant comparison, not the pooled number.",
        "",
        "Reliability diagrams:",
        "",
        "- [Overall reliability, seed 42](figures/reliability_seed42_overall.svg)",
        "- [Reliability by day, seed 42](figures/reliability_seed42_by_day.svg)",
        "- [Reliability by family, seed 42](figures/reliability_seed42_by_family.svg)",
        "",
        "## Reliability by family (seed 42)",
        "",
        _table(
            ["Family", "Rows", "Uncalibrated ECE", "Isotonic ECE", "Uncalibrated Brier", "Isotonic Brier"],
            [
                [
                    family,
                    f"{results['seeds']['42']['methods']['uncalibrated']['by_family'][family]['rows']:,}",
                    _num(results["seeds"]["42"]["methods"]["uncalibrated"]["by_family"][family]["ece_10_bins"]),
                    _num(results["seeds"]["42"]["methods"]["isotonic"]["by_family"][family]["ece_10_bins"]),
                    _num(results["seeds"]["42"]["methods"]["uncalibrated"]["by_family"][family]["brier_score"]),
                    _num(results["seeds"]["42"]["methods"]["isotonic"]["by_family"][family]["brier_score"]),
                ]
                for family in metadata["test_families"]
            ],
        ),
        "",
        "Small families (Infiltration, SQL Injection) have unstable estimates. Their ECE can look good or bad because a handful of rows changes the observed frequency. Do not treat those rows as a family-level calibration guarantee.",
        "",
        "The family table also exposes a failure that the aggregate Brier score hides: isotonic calibration fitted on Wednesday lowers overall Brier but makes BENIGN calibration much worse (ECE 0.3576) because the validation day contains DoS attacks that the model scores in the same range as benign test flows. Aggregate calibration is not family-level calibration. Do not present a single calibrated confidence number as if it were valid for every family.",
        "",
        "## Decision-curve analysis (seed 42)",
        "",
        _table(
            ["Threshold probability", "Uncalibrated net benefit", "Temperature net benefit", "Isotonic net benefit", "Treat all"],
            [
                [
                    f"{row['threshold_probability']:.2f}",
                    _num(results["seeds"]["42"]["methods"]["uncalibrated"]["decision_curve"][index]["net_benefit"]),
                    _num(results["seeds"]["42"]["methods"]["temperature"]["decision_curve"][index]["net_benefit"]),
                    _num(results["seeds"]["42"]["methods"]["isotonic"]["decision_curve"][index]["net_benefit"]),
                    _num(row["treat_all_net_benefit"]),
                ]
                for index, row in enumerate(results["seeds"]["42"]["methods"]["uncalibrated"]["decision_curve"])
            ],
        ),
        "",
        "The decision curve is a net-benefit view, not a deployment policy. It assumes the stated threshold probability is the clinically or operationally relevant trade-off. For a security queue, the more useful operational control is the alert budget, which is rank-based and therefore unchanged by monotonic calibration.",
        "",
        "## Interaction with the threshold and alert budget",
        "",
        "Temperature scaling and isotonic regression are monotonic transformations. They change the probability values and the numeric threshold, but not the ordering of flows. Consequences:",
        "",
        "1. A top-K alert budget selects the same flows before and after calibration. Calibration does not fix the alert-volume problem.",
        "2. A probability-threshold policy must reselect its threshold on calibrated validation scores. Keeping the uncalibrated threshold after calibration changes the operating point.",
        "3. A calibrated probability is only meaningful if the calibration artifact is versioned and linked to the model artifact and feature schema. The serving path must not display a confidence value unless that link exists.",
        "",
        "Threshold interaction by seed:",
        "",
        _table(
            ["Seed", "Method", "Uncalibrated threshold", "Reselected threshold", "Test FPR at reselected", "Test FPR with uncalibrated threshold"],
            [
                [
                    str(seed),
                    method,
                    _num(results["seeds"][str(seed)]["threshold_interaction"]["uncalibrated"]["validation_selected_threshold"], 8),
                    _num(results["seeds"][str(seed)]["threshold_interaction"][method]["validation_selected_threshold"], 8),
                    _pct(results["seeds"][str(seed)]["threshold_interaction"][method]["test_at_reselected_threshold"]["fpr"]),
                    _pct(results["seeds"][str(seed)]["threshold_interaction"][method]["test_with_uncalibrated_threshold"]["fpr"]),
                ]
                for seed in SEEDS
                for method in ["temperature", "isotonic"]
            ],
        ),
        "",
        "The reselected thresholds preserve the decisions because the transformations are monotonic. The last column shows what happens when the uncalibrated threshold is left in place: the operating point changes. That is a versioning failure, not a calibration improvement.",
        "",
        "Ranking invariance (Spearman correlation with the uncalibrated score):",
        "",
        _table(
            ["Seed", "Temperature", "Isotonic"],
            [
                [
                    str(seed),
                    _num(results["seeds"][str(seed)]["ranking_invariance"]["temperature_spearman"], 6),
                    _num(results["seeds"][str(seed)]["ranking_invariance"]["isotonic_spearman"], 6),
                ]
                for seed in SEEDS
            ],
        ),
        "",
        "Spearman is below 1.0 where the transformation creates ties or isotonic plateaus; the ordering is preserved up to those ties. A top-K budget selects the same set except for tie-breaking at the cut point. Calibration does not create new separability.",
        "",
        "## Serving path and UI",
        "",
        "The serving artifact is the evaluated Random Forest bundle `models/model_bundle_rf_day_based_seed42.pkl`, registered as `uncalibrated` because the available isotonic artifact fails the 0.05 ECE gate. The console therefore does not show a confidence percentage. It may show the thresholded decision, the threshold policy, and the model/artifact provenance. The D5 calibration artifacts describe this RF configuration; their held-out results still fail the gate.",
        "",
        "## Honest conclusion",
        "",
        "- The uncalibrated attack score is not a probability an analyst should trust.",
        "- Temperature scaling and isotonic regression improve validation calibration, but their held-out ECE must be read from the tables above; they do not solve the day shift.",
        "- Calibration preserves the ordering up to ties, so it does not create separability or fix the alert budget. It changes the probability scale and the numeric threshold.",
        "- The UI must not show a confidence value until the serving artifact has its own calibration artifact linked to its hash and feature schema.",
        "",
        "## Reproduction",
        "",
        "```bash",
        "python -m training.threshold_calibration_v2 --force",
        "pytest tests -q",
        "```",
        "",
        f"Artifacts: `{output_path}`, `docs/calibration_v2.json`, and `models/calibration_rf_day_based_seed*.json`.",
    ]
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Ignore and rebuild the score cache")
    args = parser.parse_args()

    os.makedirs(DOCS_DIR, exist_ok=True)
    os.makedirs(FIGURES_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

    prepared = prepare_scores(force=args.force)
    threshold_results = evaluate_threshold_policies(prepared)
    calibration_results = evaluate_calibration(prepared)

    threshold_json = os.path.join(DOCS_DIR, "threshold_policy_v2.json")
    calibration_json = os.path.join(DOCS_DIR, "calibration_v2.json")
    with open(threshold_json, "w", encoding="utf-8") as handle:
        json.dump(threshold_results, handle, indent=2, sort_keys=True)
    with open(calibration_json, "w", encoding="utf-8") as handle:
        json.dump(calibration_results, handle, indent=2, sort_keys=True)

    render_threshold_markdown(threshold_results, os.path.join(DOCS_DIR, "THRESHOLD_POLICY_V2.md"))
    render_calibration_markdown(calibration_results, os.path.join(DOCS_DIR, "CALIBRATION_V2.md"))

    seed = "42"
    methods = calibration_results["seeds"][seed]["methods"]
    colors = {"uncalibrated": "#6b7280", "temperature": "#2563eb", "isotonic": "#059669"}
    write_reliability_svg(
        os.path.join(FIGURES_DIR, "reliability_seed42_overall.svg"),
        "Reliability diagram: seed 42, held-out test",
        [{
            "title": "Overall (Thursday + Friday)",
            "series": [
                {"name": method.title(), "color": colors[method], "bins": methods[method]["overall"]["reliability"]["bins"]}
                for method in ["uncalibrated", "temperature", "isotonic"]
            ],
        }],
    )
    write_reliability_svg(
        os.path.join(FIGURES_DIR, "reliability_seed42_by_day.svg"),
        "Reliability by day: seed 42",
        [{
            "title": day,
            "series": [
                {"name": method.title(), "color": colors[method], "bins": methods[method]["by_day"][day]["reliability"]["bins"]}
                for method in ["uncalibrated", "temperature", "isotonic"]
            ],
        } for day in DAY_ORDER],
    )
    write_reliability_svg(
        os.path.join(FIGURES_DIR, "reliability_seed42_by_family.svg"),
        "Reliability by family: seed 42 (uncalibrated vs isotonic)",
        [{
            "title": family,
            "series": [
                {"name": "Uncalibrated", "color": colors["uncalibrated"], "bins": methods["uncalibrated"]["by_family"][family]["reliability"]["bins"]},
                {"name": "Isotonic", "color": colors["isotonic"], "bins": methods["isotonic"]["by_family"][family]["reliability"]["bins"]},
            ],
        } for family in calibration_results["metadata"]["test_families"]],
    )
    curves = {
        "uncalibrated": methods["uncalibrated"]["decision_curve"],
        "temperature": methods["temperature"]["decision_curve"],
        "isotonic": methods["isotonic"]["decision_curve"],
    }
    write_decision_curve_svg(
        os.path.join(FIGURES_DIR, "decision_curve_seed42.svg"),
        "Decision-curve analysis: seed 42",
        curves,
    )

    print("Wrote:")
    for path in [
        threshold_json,
        calibration_json,
        os.path.join(DOCS_DIR, "THRESHOLD_POLICY_V2.md"),
        os.path.join(DOCS_DIR, "CALIBRATION_V2.md"),
        os.path.join(FIGURES_DIR, "reliability_seed42_overall.svg"),
        os.path.join(FIGURES_DIR, "reliability_seed42_by_day.svg"),
        os.path.join(FIGURES_DIR, "reliability_seed42_by_family.svg"),
        os.path.join(FIGURES_DIR, "decision_curve_seed42.svg"),
    ]:
        print(" ", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
