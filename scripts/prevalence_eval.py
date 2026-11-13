#!/usr/bin/env python
"""Prevalence and alert-budget evaluation for the frozen NetShield model.

This script converts a frozen operating point (TPR/FPR) and per-flow held-out
scores into prevalence-aware precision and alert-volume estimates. It never
trains, retunes, or changes a threshold.

Examples:
    python scripts/prevalence_eval.py \
        --metrics models/metrics_rf_day_based_seed42.json \
        --prevalence 0.0001,0.001,0.01,0.10 --benchmark \
        --flows-per-day 1000000 --review-cost-ratio 0.0 \
        --output docs/PREVALENCE_EVAL.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from typing import Any

import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DEFAULT_SEED = 20261113
DEFAULT_BOOTSTRAP = 10_000
Z95 = 1.959963984540054


# ---------------------------------------------------------------------------
# Metric primitives
# ---------------------------------------------------------------------------

def confusion_at_threshold(scores: np.ndarray, truth: np.ndarray, threshold: float) -> dict[str, int]:
    """Return TP/FP/FN/TN for ``score >= threshold`` where truth is 1 for attack."""
    predicted = np.asarray(scores) >= threshold
    actual = np.asarray(truth).astype(bool)
    return {
        "true_positives": int(np.sum(predicted & actual)),
        "false_positives": int(np.sum(predicted & ~actual)),
        "false_negatives": int(np.sum(~predicted & actual)),
        "true_negatives": int(np.sum(~predicted & ~actual)),
    }


def rates_from_counts(counts: dict[str, int]) -> tuple[float, float, int, int]:
    """Return TPR, FPR, positives, negatives. Never divide by zero."""
    positives = counts["true_positives"] + counts["false_negatives"]
    negatives = counts["false_positives"] + counts["true_negatives"]
    tpr = counts["true_positives"] / positives if positives else float("nan")
    fpr = counts["false_positives"] / negatives if negatives else float("nan")
    return tpr, fpr, positives, negatives


def ppv_at_prevalence(tpr: float, fpr: float, prevalence: float) -> float:
    """Positive predictive value at an attack prevalence."""
    numerator = tpr * prevalence
    denominator = numerator + fpr * (1.0 - prevalence)
    if denominator <= 0:
        return float("nan")
    return numerator / denominator


def alerts_per_10k(tpr: float, fpr: float, prevalence: float) -> float:
    """Expected alerts per 10,000 flows, including false positives."""
    return 10_000.0 * (tpr * prevalence + fpr * (1.0 - prevalence))


def alerts_per_day(tpr: float, fpr: float, prevalence: float, flows_per_day: float) -> float:
    """Expected alerts per day for an explicitly illustrative flow volume."""
    return flows_per_day * (tpr * prevalence + fpr * (1.0 - prevalence))


def break_even_per_flow(tpr: float, fpr: float, prevalence: float) -> float:
    """C_FN/C_FP at which the detector ties 'do nothing', per-flow costs only."""
    denominator = tpr * prevalence
    if denominator <= 0:
        return float("inf")
    return fpr * (1.0 - prevalence) / denominator


def break_even_with_review(
    tpr: float, fpr: float, prevalence: float, review_cost_ratio: float
) -> float:
    """C_FN/C_FP break-even with a review cost per alert.

    ``review_cost_ratio`` (r) is c_r / C_FP: review cost per alert divided by
    the cost of one false positive. ``r=0`` reduces to the per-flow model.
    """
    denominator = tpr * prevalence
    if denominator <= 0:
        return float("inf")
    false_positive_cost = fpr * (1.0 - prevalence)
    alert_cost = tpr * prevalence + false_positive_cost
    return (false_positive_cost + review_cost_ratio * alert_cost) / denominator


def wilson_interval(successes: int, trials: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if trials <= 0:
        return float("nan"), float("nan")
    phat = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (phat + z * z / (2.0 * trials)) / denominator
    margin = z * math.sqrt(phat * (1.0 - phat) / trials + z * z / (4.0 * trials * trials)) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def clopper_pearson_upper(successes: int, trials: int, alpha: float = 0.05) -> float:
    """Clopper-Pearson upper bound. Used when FPR is zero."""
    if trials <= 0:
        return float("nan")
    try:
        from scipy.stats import beta

        return float(beta.ppf(1.0 - alpha / 2.0, successes + 1, trials - successes))
    except Exception:  # pragma: no cover - scipy is a test/runtime dependency
        # Conservative fallback: rule of three for zero successes.
        if successes == 0:
            return 1.0 - (alpha / 2.0) ** (1.0 / trials)
        return 1.0


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def _class_score_counts(scores: np.ndarray, truth: np.ndarray, positive: bool) -> tuple[np.ndarray, np.ndarray]:
    mask = np.asarray(truth).astype(bool) == positive
    values = np.asarray(scores)[mask]
    unique, counts = np.unique(values, return_counts=True)
    return unique, counts


def bootstrap_confusion(
    scores: np.ndarray,
    truth: np.ndarray,
    threshold: float,
    draws: int,
    seed: int,
) -> dict[str, np.ndarray]:
    """Stratified non-parametric bootstrap over held-out per-flow scores.

    Positives and negatives are resampled separately, preserving class counts.
    Because the decision rule is a fixed threshold, resampling scores is
    represented as multinomial draws over the unique score values in each
    class. This is exact for the thresholded decision and far cheaper than
    materialising 10,000 copies of a million-row score vector.
    """
    rng = np.random.default_rng(seed)
    pos_values, pos_counts = _class_score_counts(scores, truth, positive=True)
    neg_values, neg_counts = _class_score_counts(scores, truth, positive=False)

    pos_probs = pos_counts / pos_counts.sum()
    neg_probs = neg_counts / neg_counts.sum()
    pos_above = pos_values >= threshold
    neg_above = neg_values >= threshold

    tp = np.empty(draws, dtype=np.int64)
    fp = np.empty(draws, dtype=np.int64)
    for index in range(draws):
        pos_draw = rng.multinomial(pos_counts.sum(), pos_probs)
        neg_draw = rng.multinomial(neg_counts.sum(), neg_probs)
        tp[index] = int(pos_draw[pos_above].sum())
        fp[index] = int(neg_draw[neg_above].sum())
    return {"tp": tp, "fp": fp}


def _intervals_from_boot(
    boot: dict[str, np.ndarray],
    positives: int,
    negatives: int,
    prevalences: list[float],
) -> dict[float, dict[str, list[float]]]:
    tpr_draw = boot["tp"] / positives
    fpr_draw = boot["fp"] / negatives
    result: dict[float, dict[str, list[float]]] = {}
    for prevalence in prevalences:
        ppv_draw = np.where(
            tpr_draw * prevalence + fpr_draw * (1.0 - prevalence) > 0,
            (tpr_draw * prevalence)
            / (tpr_draw * prevalence + fpr_draw * (1.0 - prevalence)),
            np.nan,
        )
        alerts_draw = 10_000.0 * (tpr_draw * prevalence + fpr_draw * (1.0 - prevalence))
        result[prevalence] = {
            "ppv": _percentile_ci(ppv_draw),
            "alerts_per_10k": _percentile_ci(alerts_draw),
        }
    return result


def _percentile_ci(values: np.ndarray) -> list[float]:
    clean = values[np.isfinite(values)]
    if clean.size == 0:
        return [float("nan"), float("nan")]
    return [float(np.percentile(clean, 2.5)), float(np.percentile(clean, 97.5))]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _load_json(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _parse_prevalences(raw: str) -> list[float]:
    values = [float(value) for value in raw.split(",") if value.strip()]
    for value in values:
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"prevalence must be in [0, 1]: {value}")
    return sorted(set(values))


def evaluate_seed(
    score_cache: str,
    threshold: float,
    prevalences: list[float],
    flows_per_day: float,
    review_cost_ratio: float,
    draws: int,
    seed: int,
) -> dict[str, Any]:
    cache = np.load(score_cache)
    scores = cache["attack_score"]
    truth = cache["binary_truth"]
    counts = confusion_at_threshold(scores, truth, threshold)
    tpr, fpr, positives, negatives = rates_from_counts(counts)

    # Exact score bootstrap for the primary seed.
    boot = bootstrap_confusion(scores, truth, threshold, draws, seed)
    intervals = _intervals_from_boot(boot, positives, negatives, prevalences)

    tpr_ci = wilson_interval(counts["true_positives"], positives)
    fpr_ci = (
        wilson_interval(counts["false_positives"], negatives)
        if counts["false_positives"] > 0
        else (0.0, clopper_pearson_upper(0, negatives))
    )

    rows = []
    for prevalence in prevalences:
        per_flow = break_even_per_flow(tpr, fpr, prevalence)
        rows.append({
            "p": prevalence,
            "tpr": tpr,
            "fpr": fpr,
            "ppv": ppv_at_prevalence(tpr, fpr, prevalence),
            "ppv_ci95": intervals[prevalence]["ppv"],
            "alerts_per_10k": alerts_per_10k(tpr, fpr, prevalence),
            "alerts_per_10k_ci95": intervals[prevalence]["alerts_per_10k"],
            "alerts_per_day": alerts_per_day(tpr, fpr, prevalence, flows_per_day),
            "break_even_per_flow": per_flow,
            "break_even_with_review": break_even_with_review(
                tpr, fpr, prevalence, review_cost_ratio
            ),
            # D9 charges a review for every alert, true or false, so its
            # break-even is alerts/TP = 1 + FP/TP.
            "break_even_all_alerts": 1.0 + per_flow,
        })

    return {
        "partition": "test",
        "score_cache": score_cache,
        "threshold": threshold,
        "counts": counts,
        "tpr": tpr,
        "fpr": fpr,
        "tpr_ci95": list(tpr_ci),
        "fpr_ci95": list(fpr_ci),
        "positives": positives,
        "negatives": negatives,
        "benchmark_prevalence": positives / (positives + negatives) if positives + negatives else None,
        "prevalence": rows,
    }


def evaluate_seeds(
    cache_dir: str,
    model: str,
    seeds: list[int],
    threshold: float | None,
    metrics_pattern: str,
    prevalences: list[float],
    flows_per_day: float,
    review_cost_ratio: float,
    draws: int,
    seed: int,
) -> dict[str, Any]:
    per_seed: dict[str, Any] = {}
    for model_seed in seeds:
        path = os.path.join(cache_dir, f"{model}_seed{model_seed}_test.npz")
        if not os.path.isfile(path):
            per_seed[str(model_seed)] = {"error": f"missing score cache: {path}"}
            continue
        if threshold is not None:
            seed_threshold = threshold
            threshold_source = "CLI override"
        else:
            metrics_path = metrics_pattern.format(seed=model_seed)
            if not os.path.isfile(metrics_path):
                per_seed[str(model_seed)] = {
                    "error": f"missing per-seed metrics: {metrics_path}"
                }
                continue
            seed_threshold = (
                (_load_json(metrics_path).get("operating_threshold") or {}).get("threshold")
            )
            threshold_source = metrics_path
            if seed_threshold is None:
                per_seed[str(model_seed)] = {
                    "error": f"missing operating threshold in {metrics_path}"
                }
                continue
        result = evaluate_seed(
            path, seed_threshold, prevalences, flows_per_day,
            review_cost_ratio, draws, seed,
        )
        result["threshold_source"] = threshold_source
        per_seed[str(model_seed)] = result

    valid = [value for value in per_seed.values() if "prevalence" in value]
    five_seed = []
    for index, prevalence in enumerate(prevalences):
        ppvs = [value["prevalence"][index]["ppv"] for value in valid]
        alerts = [value["prevalence"][index]["alerts_per_10k"] for value in valid]
        break_even = [value["prevalence"][index]["break_even_per_flow"] for value in valid]
        break_even_all = [value["prevalence"][index]["break_even_all_alerts"] for value in valid]
        tprs = [value["tpr"] for value in valid]
        fprs = [value["fpr"] for value in valid]
        mean_tpr = float(np.mean(tprs)) if tprs else None
        mean_fpr = float(np.mean(fprs)) if fprs else None
        five_seed.append({
            "p": prevalence,
            "ppv_mean": float(np.mean(ppvs)) if ppvs else None,
            "ppv_sd": float(np.std(ppvs, ddof=1)) if len(ppvs) > 1 else 0.0,
            "ppv_from_mean_rates": (
                ppv_at_prevalence(mean_tpr, mean_fpr, prevalence)
                if mean_tpr is not None and mean_fpr is not None else None
            ),
            "mean_tpr": mean_tpr,
            "mean_fpr": mean_fpr,
            "alerts_per_10k_mean": float(np.mean(alerts)) if alerts else None,
            "alerts_per_10k_sd": float(np.std(alerts, ddof=1)) if len(alerts) > 1 else 0.0,
            "break_even_per_flow_mean": float(np.mean(break_even)) if break_even else None,
            "break_even_per_flow_sd": float(np.std(break_even, ddof=1)) if len(break_even) > 1 else 0.0,
            "break_even_all_alerts_mean": float(np.mean(break_even_all)) if break_even_all else None,
            "break_even_all_alerts_sd": float(np.std(break_even_all, ddof=1)) if len(break_even_all) > 1 else 0.0,
            "seeds_used": [int(key) for key, value in per_seed.items() if "prevalence" in value],
        })

    return {"per_seed": per_seed, "five_seed": five_seed}


def _d9_provenance(cost_results_path: str) -> dict[str, Any] | None:
    if not os.path.isfile(cost_results_path):
        return None
    data = _load_json(cost_results_path)
    values = []
    for seed_key, row in (data.get("cache_results", {}).get("rf", {})).items():
        ratio = (row.get("threshold") or {}).get("break_even_ratio")
        if ratio is not None:
            values.append(float(ratio))
    if not values:
        return None
    attacks = data.get("data", {}).get("test_attacks")
    rows = data.get("data", {}).get("test_rows")
    prevalence = attacks / rows if attacks and rows else None
    return {
        "value": float(np.mean(values)),
        "sd": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
        "seeds": sorted(int(seed) for seed in data.get("cache_results", {}).get("rf", {})),
        "source": cost_results_path,
        "prevalence_assumption": prevalence,
        "note": (
            "Five-seed mean at the benchmark test prevalence. D9 charges a review "
            "for every alert, so its break-even is alerts/TP = 1 + FP/TP. It is "
            "not prevalence-free and not the same as the per-flow false-positive model."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", default="models/metrics_rf_day_based_seed42.json")
    parser.add_argument("--prevalence", default="0.0001,0.001,0.01,0.10")
    parser.add_argument("--benchmark", action="store_true",
                        help="Append the exact test-partition prevalence to the grid.")
    parser.add_argument("--flows-per-day", type=float, default=1_000_000.0,
                        help="Illustrative daily flow volume; not a measured site value.")
    parser.add_argument("--review-cost-ratio", type=float, default=0.0,
                        help="c_r / C_FP: review cost per alert over false-positive cost.")
    parser.add_argument("--output", default="docs/PREVALENCE_EVAL.json")
    parser.add_argument("--score-cache-dir", default="models/eval_cache")
    parser.add_argument("--model", default="rf")
    parser.add_argument("--seeds", default="42,43,44,45,46")
    parser.add_argument("--metrics-pattern", default="models/metrics_{model}_day_based_seed{seed}.json",
                        help="Per-seed metrics path; {model} and {seed} are substituted.")
    parser.add_argument("--threshold", type=float, default=None,
                        help="Override the metrics operating threshold (recorded in output).")
    parser.add_argument("--bootstrap", type=int, default=DEFAULT_BOOTSTRAP)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--cost-results", default="docs/COST_SENSITIVE_RESULTS.json")
    args = parser.parse_args(argv)

    metrics = _load_json(args.metrics)
    operating = metrics.get("operating_threshold") or {}
    threshold = args.threshold if args.threshold is not None else operating.get("threshold")
    if threshold is None:
        print("BLOCKED: no operating threshold in metrics and none supplied", file=sys.stderr)
        return 2

    prevalences = _parse_prevalences(args.prevalence)
    seeds = [int(value) for value in args.seeds.split(",") if value.strip()]

    seed42 = evaluate_seed(
        os.path.join(args.score_cache_dir, f"{args.model}_seed{seeds[0]}_test.npz"),
        threshold, prevalences, args.flows_per_day, args.review_cost_ratio,
        args.bootstrap, args.seed,
    )
    benchmark = seed42["benchmark_prevalence"]
    if args.benchmark and benchmark is not None and benchmark not in prevalences:
        prevalences = sorted(set(prevalences + [benchmark]))
        seed42 = evaluate_seed(
            os.path.join(args.score_cache_dir, f"{args.model}_seed{seeds[0]}_test.npz"),
            threshold, prevalences, args.flows_per_day, args.review_cost_ratio,
            args.bootstrap, args.seed,
        )

    five = evaluate_seeds(
        args.score_cache_dir, args.model, seeds, args.threshold,
        args.metrics_pattern.replace("{model}", args.model),
        prevalences, args.flows_per_day, args.review_cost_ratio,
        args.bootstrap, args.seed,
    )

    output = {
        "method": "bootstrap_scores",
        "seed": args.seed,
        "bootstrap_draws": args.bootstrap,
        "inputs": {
            "metrics": args.metrics,
            "partition": "test (Thursday + Friday)",
            "operating_point": f"score >= {threshold}",
            "threshold": threshold,
            "threshold_source": "metrics operating_threshold" if args.threshold is None else "CLI override",
            "model": args.model,
            "seeds": seeds,
            "review_cost_ratio": args.review_cost_ratio,
            "flows_per_day": args.flows_per_day,
            "flows_per_day_note": "Illustrative volume, not a measured site value.",
        },
        "benchmark_prevalence": benchmark,
        "prevalence": seed42["prevalence"],
        "seed42": {
            "counts": seed42["counts"],
            "tpr": seed42["tpr"],
            "fpr": seed42["fpr"],
            "tpr_ci95": seed42["tpr_ci95"],
            "fpr_ci95": seed42["fpr_ci95"],
            "positives": seed42["positives"],
            "negatives": seed42["negatives"],
        },
        "five_seed": five["five_seed"],
        "per_seed": five["per_seed"],
        "d9_break_even_1_21": _d9_provenance(args.cost_results),
        "notes": [
            "Bootstrap resamples held-out positive and negative scores separately and preserves class counts.",
            "PPV and alert intervals are 2.5th-97.5th percentiles of 10,000 draws.",
            "TPR/FPR Wilson intervals are a sanity check on the point estimate.",
            "Costs are per flow; review cost is per alert; no blocking cost is modeled.",
            "break_even_per_flow = FP/TP. break_even_all_alerts = alerts/TP = 1 + FP/TP, matching D9.",
            "alerts/day uses an explicitly illustrative flow volume unless a site value is supplied.",
            "Five-seed rows use each seed's own validation-selected threshold.",
            "ppv_mean averages per-seed PPV; ppv_from_mean_rates plugs mean TPR and mean FPR into the formula. They differ because PPV is nonlinear.",
            "1.21 in D9 is a five-seed mean at the benchmark prevalence, not a prevalence-free constant.",
        ],
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)
        handle.write("\n")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
