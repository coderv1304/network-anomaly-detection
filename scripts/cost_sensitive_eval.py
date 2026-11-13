#!/usr/bin/env python
"""D9: cost-sensitive evaluation and detection release gate.

The detector is not scored in the abstract. This script applies one declared
cost model to the frozen evaluation artifacts:

* ``C_FP``  — cost of one analyst review. Every alert (true or false positive)
  is reviewed under the threshold policy, so the review load is ``alerts``.
* ``C_FN``  — cost of one missed attack.
* ``r``     — the cost ratio ``C_FN / C_FP``. Absolute currency values are not
  established by this project, so results are reported as a curve over ``r``
  rather than as a single dollar figure.

Expected cost per 10,000 flows:

    cost(r) = (alerts + r * false_negatives) * 10,000 / n_flows

The no-detector baseline misses every attack:

    cost_none(r) = r * attacks * 10,000 / n_flows

The detector beats doing nothing only when ``r > alerts / true_positives``,
i.e. ``r > 1 / precision``. That break-even ratio is reported for every model.

Policies evaluated:

1. the frozen threshold (validation-selected at <=1% validation FPR);
2. a fixed analyst budget of 50 and 100 alerts per 10,000 flows, ranking by the
   model's attack score.

Sources:

* ``models/metrics_{lr,rf,if}_day_based_seed{seed}.json`` — threshold results;
* ``models/eval_cache/{prefix}_seed{seed}_{partition}.npz`` — raw scores, used
  for the alert-budget policy and family breakdown;
* ``docs/d6_unseen_family_results.json`` — D6 arms, if the run has completed.

The script never retunes a threshold and never uses test labels to choose a
policy. It writes machine-readable output and prints a markdown summary.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.evaluate import evaluate_alert_budgets  # noqa: E402

SEEDS = (42, 43, 44, 45, 46)
BUDGETS_PER_10K = (50, 100)
COST_RATIOS = (1, 2, 3, 5, 10, 30, 100, 300, 1000)
ANALYST_MINUTES_PER_ALERT = 5.0
TEST_ROWS = 1_162_065
TEST_ATTACKS = 291_139
TEST_BENIGN = TEST_ROWS - TEST_ATTACKS
MODELS = {
    "lr": "Logistic Regression (legacy comparison; no longer served)",
    "rf": "Random Forest (evaluated model and registry-active serving artifact; D6 reference)",
    "if": "Isolation Forest (benign-only baseline)",
}


def load_json(path: str) -> dict[str, Any] | None:
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def threshold_from_metrics(document: dict[str, Any]) -> dict[str, Any] | None:
    operating = document.get("operating_threshold") or {}
    test = operating.get("test") or {}
    if "fpr" not in test or "recall" not in test:
        return None
    return {
        "threshold": float(operating.get("threshold", test.get("threshold", 0.0))),
        "fpr": float(test["fpr"]),
        "recall": float(test["recall"]),
        "precision": float(test.get("precision", 0.0)),
        "alert_rate": float(test.get("alert_rate", 0.0)),
        "validation_fpr": float(operating.get("validation_fpr", 0.0)),
        "validation_recall": float(operating.get("validation_tpr", 0.0)),
    }


def counts_from_rates(fpr: float, recall: float) -> dict[str, int]:
    false_positives = int(round(fpr * TEST_BENIGN))
    true_positives = int(round(recall * TEST_ATTACKS))
    false_negatives = TEST_ATTACKS - true_positives
    true_negatives = TEST_BENIGN - false_positives
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "alerts": true_positives + false_positives,
    }


def cost_per_10k(alerts: int, false_negatives: int, ratio: float) -> float:
    return (alerts + ratio * false_negatives) * 10_000.0 / TEST_ROWS


def no_detector_cost_per_10k(ratio: float) -> float:
    return ratio * TEST_ATTACKS * 10_000.0 / TEST_ROWS


def break_even_ratio(true_positives: int, alerts: int) -> float | None:
    if true_positives <= 0 or alerts <= 0:
        return None
    return alerts / true_positives


def cost_curve(alerts: int, false_negatives: int, true_positives: int) -> dict[str, Any]:
    curve = {}
    for ratio in COST_RATIOS:
        detector = cost_per_10k(alerts, false_negatives, ratio)
        none = no_detector_cost_per_10k(ratio)
        curve[str(ratio)] = {
            "detector": round(detector, 3),
            "no_detector": round(none, 3),
            "delta": round(detector - none, 3),
            "beats_no_detector": detector < none,
        }
    return {
        "curve": curve,
        "break_even_ratio": (
            round(break_even_ratio(true_positives, alerts), 4)
            if break_even_ratio(true_positives, alerts) is not None
            else None
        ),
    }


def analyst_hours(alerts: int) -> float:
    return alerts * ANALYST_MINUTES_PER_ALERT / 60.0


def analyst_hours_per_10k(alerts: int) -> float:
    return analyst_hours(alerts) * 10_000.0 / TEST_ROWS


def summarise_threshold(model: str, threshold: dict[str, Any]) -> dict[str, Any]:
    counts = counts_from_rates(threshold["fpr"], threshold["recall"])
    summary = {
        "threshold": threshold["threshold"],
        "validation_fpr": threshold["validation_fpr"],
        "validation_recall": threshold["validation_recall"],
        "test_fpr": threshold["fpr"],
        "test_recall": threshold["recall"],
        "test_precision": threshold["precision"],
        "alert_rate": threshold["alert_rate"],
        **counts,
        "review_hours_per_10k_flows": round(analyst_hours_per_10k(counts["alerts"]), 3),
        **cost_curve(counts["alerts"], counts["false_negatives"], counts["true_positives"]),
    }
    return summary


def budget_from_cache(path: str, threshold: float) -> dict[str, Any] | None:
    if not os.path.isfile(path):
        return None
    with np.load(path, allow_pickle=True) as data:
        scores = data["attack_score"].astype(np.float32)
        truth = data["binary_truth"].astype(np.int8)
        families = np.asarray([str(value) for value in data["families"]], dtype=object)
        codes = data["family_codes"].astype(np.int16)
        family_labels = np.asarray([families[code] for code in codes], dtype=object)
        day_vocabulary = [str(value) for value in data["days"]]
        day_codes = data["day_codes"].astype(np.int16) if "day_codes" in data else None
        day_labels = (
            np.asarray([day_vocabulary[code] for code in day_codes], dtype=object)
            if day_codes is not None
            else None
        )

    selected = scores >= threshold
    tp = int(np.sum(selected & (truth == 1)))
    fp = int(np.sum(selected & (truth == 0)))
    fn = int(np.sum(~selected & (truth == 1)))
    threshold_counts = {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": int(np.sum(~selected & (truth == 0))),
        "alerts": tp + fp,
    }
    budgets = evaluate_alert_budgets(
        truth,
        scores,
        y_true_families=family_labels,
        budgets_per_10k=list(BUDGETS_PER_10K),
        fixed_counts=[],
    )
    per_day: dict[str, Any] = {}
    if day_labels is not None:
        for day in sorted(set(day_labels)):
            mask = day_labels == day
            day_benign = int(np.sum(mask & (truth == 0)))
            day_attack = int(np.sum(mask & (truth == 1)))
            day_alerts = int(np.sum(selected & mask))
            per_day[day] = {
                "threshold": {
                    "fpr": float(np.sum(selected & mask & (truth == 0)) / day_benign) if day_benign else None,
                    "recall": float(np.sum(selected & mask & (truth == 1)) / day_attack) if day_attack else None,
                    "alerts": day_alerts,
                }
            }
    return {
        "threshold": {
            **threshold_counts,
            "alert_rate": threshold_counts["alerts"] / len(truth),
            **cost_curve(threshold_counts["alerts"], threshold_counts["false_negatives"], threshold_counts["true_positives"]),
        },
        "budgets": budgets,
        "per_day": per_day,
    }


def budget_summary(budgets: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in (budgets.get("budgets_per_10k") or {}).items():
        tp = int(value["true_positives"])
        fp = int(value["false_positives"])
        fn = int(budgets["total_attacks"]) - tp
        alerts = int(value["alerts_generated"])
        output[key] = {
            "alerts": alerts,
            "alert_rate": value["alert_rate"],
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": value["precision"],
            "recall": value["recall"],
            "review_hours_per_10k_flows": round(analyst_hours_per_10k(alerts), 3),
            "per_family_recall": value.get("per_family_recall", {}),
            **cost_curve(alerts, fn, tp),
        }
    return output


def inspect_artifact_identity() -> dict[str, Any]:
    """Compare the registry-active serving artifact to the evaluated RF seed.

    The comparison is by SHA-256, not by name. A different artifact path or
    model_id is fine as long as the served bytes are the evaluated bytes.
    """
    registry = load_json("models/registry/registry.json") or {}
    models = registry.get("models") or {}
    active = registry.get("active") or {}
    entry = None
    model = models.get(active.get("model_id")) if isinstance(models, dict) else None
    if isinstance(model, dict):
        entry = (model.get("versions") or {}).get(active.get("version"))
    manifest = load_json("models/model_manifest_rf_day_based_seed42.json") or {}
    evaluated_hash = str(manifest.get("model_sha256") or "").lower() or None
    serving_hash = str((entry or {}).get("artifact_sha256") or "").lower() or None
    matches = bool(serving_hash and evaluated_hash and serving_hash == evaluated_hash)
    serving_label = (
        f"{entry.get('model_id')}/{entry.get('version')}" if entry else "no active registry entry"
    )
    if matches:
        reason = (
            "The registry-active serving artifact has the same SHA-256 as the "
            "evaluated and gated Random Forest seed42 bundle."
        )
    elif serving_hash and evaluated_hash:
        reason = (
            "The registry-active serving artifact hash differs from the evaluated "
            "Random Forest seed42 bundle."
        )
    else:
        reason = "The registry-active artifact or the evaluated manifest is unavailable."
    return {
        "serving_model_id": serving_label,
        "serving_artifact_sha256": serving_hash,
        "serving_artifact_path": (entry or {}).get("artifact_path"),
        "evaluated_model": "rf-day-based-seed42",
        "evaluated_artifact_sha256": evaluated_hash,
        "identity_matches": matches,
        "reason": reason,
    }


def d6_gate_metrics() -> dict[str, Any] | None:
    document = load_json("docs/d6_unseen_family_results.json")
    if not document:
        return None
    reference = (document.get("arms") or {}).get("R_full_data_rf_reference", {})
    aggregate = reference.get("aggregate") or {}
    bot = (aggregate.get("per_family") or {}).get("Bot") or {}
    return {
        "fpr_mean": (aggregate.get("fpr") or {}).get("mean"),
        "fpr_values": (aggregate.get("fpr") or {}).get("values"),
        "recall_mean": (aggregate.get("recall") or {}).get("mean"),
        "alert_rate_mean": (aggregate.get("alert_rate") or {}).get("mean"),
        "bot_recall_mean": bot.get("recall_mean"),
        "bot_recall_values": bot.get("recall_values"),
        "ece_mean": (aggregate.get("ece_10_bins") or {}).get("mean"),
        "seeds": document.get("seeds"),
    }


def release_gate(metrics: dict[str, Any] | None, identity: dict[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(check_id: str, requirement: str, observed: Any, passed: bool, detail: str = "") -> None:
        checks.append(
            {
                "id": check_id,
                "requirement": requirement,
                "observed": observed,
                "pass": bool(passed),
                "detail": detail,
            }
        )

    add(
        "artifact_identity",
        "The served artifact must be the artifact that was evaluated and gated.",
        f"served={identity['serving_model_id']}; evaluated={identity['evaluated_model']}",
        identity["identity_matches"],
        identity["reason"],
    )
    fpr_values = (metrics or {}).get("fpr_values") or []
    add(
        "fpr_every_day_seed",
        "Test FPR <= 1% on every day and every seed.",
        f"max={max(fpr_values):.4f}" if fpr_values else "no D6 result",
        bool(fpr_values) and max(fpr_values) <= 0.01,
        "The Wednesday-frozen threshold does not transfer to Thursday/Friday.",
    )
    alert_rate = (metrics or {}).get("alert_rate_mean")
    add(
        "alert_rate",
        "Alert rate <= 2% of flows at the frozen threshold.",
        round(alert_rate, 4) if alert_rate is not None else "no D6 result",
        alert_rate is not None and alert_rate <= 0.02,
        "A 15% alert rate is not an operating budget.",
    )
    bot_values = (metrics or {}).get("bot_recall_values") or []
    bot_min = min(bot_values) if bot_values else None
    add(
        "bot_recall",
        "Bot recall >= 0.50 minimum (0.70 desired) at <= 1% FPR.",
        round(bot_min, 4) if bot_min is not None else "no D6 result",
        bot_min is not None and bot_min >= 0.50,
        "Unseen-family recall is the core detection gap.",
    )
    ece = (metrics or {}).get("ece_mean")
    add(
        "calibration",
        "ECE <= 0.05 on the held-out test partition.",
        round(ece, 4) if ece is not None else "no D6 result",
        ece is not None and ece <= 0.05,
        "The serving artifact is explicitly uncalibrated.",
    )
    add(
        "external_dataset",
        "Pass the same gate on at least one independent external dataset.",
        "blocked: no independent dataset on disk",
        False,
        "See docs/EXTERNAL_VALIDATION.md.",
    )
    add(
        "prospective_pilot",
        "Complete the D8/S7 prospective human-review pilot with predeclared criteria.",
        "not run: no design partner",
        False,
        "See docs/D8_PROSPECTIVE_PILOT_PROTOCOL.md.",
    )
    add(
        "site_cost_model",
        "Use a site-supplied C_FP, C_FN, and review budget, not an illustrative ratio.",
        "not supplied: results are a r = C_FN/C_FP sensitivity curve",
        False,
        "No organization has supplied its costs.",
    )
    add(
        "seeds",
        "Report at least five estimator seeds for the exact served artifact.",
        f"RF configuration: {len((metrics or {}).get('seeds') or [])} seeds; served artifact: seed42",
        bool(metrics and len(metrics.get("seeds") or []) >= 5),
        "Five seed runs exist for the served Random Forest configuration; the served bytes are the seed42 artifact.",
    )
    passed = all(check["pass"] for check in checks)
    return {
        "gate": "9/10 detection claim",
        "passed": passed,
        "checks": checks,
        "verdict": "PASS" if passed else "FAIL",
        "consequence": (
            "No 9/10 detection claim is allowed. Detection remains 4/10."
            if not passed
            else "All checks pass; a scoped, cost-based claim may be considered."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="docs/COST_SENSITIVE_RESULTS.json")
    parser.add_argument("--cache-prefixes", default="rf,lr")
    args = parser.parse_args()

    generated = datetime.now(UTC).isoformat()
    threshold_results: dict[str, Any] = {}
    cache_results: dict[str, Any] = {}

    for model in MODELS:
        threshold_results[model] = {}
        for seed in SEEDS:
            document = load_json(f"models/metrics_{model}_day_based_seed{seed}.json")
            if not document:
                continue
            threshold = threshold_from_metrics(document)
            if threshold is None:
                continue
            threshold_results[model][str(seed)] = summarise_threshold(model, threshold)

    for prefix in [item.strip() for item in args.cache_prefixes.split(",") if item.strip()]:
        cache_results[prefix] = {}
        for seed in SEEDS:
            test_path = f"models/eval_cache/{prefix}_seed{seed}_test.npz"
            metrics = load_json(f"models/metrics_{prefix}_day_based_seed{seed}.json")
            if not os.path.isfile(test_path) or not metrics:
                continue
            threshold = threshold_from_metrics(metrics)
            if threshold is None:
                continue
            cached = budget_from_cache(test_path, threshold["threshold"])
            if cached is None:
                continue
            cache_results[prefix][str(seed)] = {
                **cached,
                "budget_summary": budget_summary(cached["budgets"]) if cached.get("budgets") else {},
                "threshold_metrics": threshold,
            }

    d6 = d6_gate_metrics()
    identity = inspect_artifact_identity()
    gate = release_gate(d6, identity)

    report = {
        "phase": "D9",
        "generated_at_utc": generated,
        "cost_model": {
            "definition": "cost_per_10k = (alerts + r * false_negatives) * 10000 / n_flows",
            "no_detector": "cost_per_10k = r * attacks * 10000 / n_flows",
            "C_FP": "one analyst review of one alert (all alerts are reviewed under the threshold policy)",
            "C_FN": "one missed attack",
            "r": "C_FN / C_FP; absolute currency not established",
            "analyst_minutes_per_alert": ANALYST_MINUTES_PER_ALERT,
            "cost_ratios": list(COST_RATIOS),
            "break_even": "detector beats no detector iff r > alerts / true_positives = 1 / precision",
        },
        "data": {
            "test_rows": TEST_ROWS,
            "test_attacks": TEST_ATTACKS,
            "test_benign": TEST_BENIGN,
            "partition": "Thursday + Friday (frozen final test)",
            "thresholds_selected_on": "Wednesday validation only",
        },
        "models": MODELS,
        "threshold_results": threshold_results,
        "cache_results": cache_results,
        "d6_reference": d6,
        "serving_artifact_identity": identity,
        "release_gate": gate,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output}")
    print(f"Release gate: {gate['verdict']}")
    for check in gate["checks"]:
        print(f"  [{'PASS' if check['pass'] else 'FAIL'}] {check['id']}: {check['observed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
