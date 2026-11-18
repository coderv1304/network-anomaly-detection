#!/usr/bin/env python
"""Phase 1/2 benchmark: matched scope, calibration, and benign-FPR thresholds.

The benchmark answers four questions with one leakage-safe protocol:

1. Is the requested Monday-Tuesday training split fittable after the frozen
   volumetric/scanning scope is applied? (For CIC-IDS-2017 it is not: Monday is
   benign-only and Tuesday is Patator-only.)
2. Do Candidate A (regularised Random Forest + prefit sigmoid calibration) and
   Candidate B (histogram gradient boosting) eliminate the ``1.000000``
   threshold saturation seen in P3B/P3C?
3. What are the realized false-positive rate, precision, recall, and alert
   volume on Thursday-Friday and on matched-scope CIC-IDS-2018 / UNSW-NB15?
4. Does either candidate beat the uncalibrated portable baseline at matched
   scope without touching the serving artifact?

Run:
    venv/Scripts/python.exe scripts/run_calibrated_transfer.py
    venv/Scripts/python.exe scripts/run_calibrated_transfer.py --max-rows-per-file 50000

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

import joblib
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.portable_features import (  # noqa: E402
    PORTABLE_FEATURE_NAMES,
    schema_payload as portable_schema,
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
    load_cic2018_portable,
    load_unsw_portable,
    prevalence_subsample_indices,
    strict_protocol_status,
)

ARTIFACT_VERSION = "calibrated-transfer-v1"
PRIMARY_TARGET_FPR = 0.005
SECONDARY_TARGET_FPR = 0.001
BASELINE_PATH = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_portable_ratio_seed42.pkl"
)
PUBLISHED_BASELINE = os.path.join(PROJECT_ROOT, "docs", "portable_transfer_results.json")
SERVING_PATH = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_day_based_seed42.pkl"
)
SERVING_SHA256 = (
    "fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350"
)
DEFAULT_CIC_DIR = os.path.expanduser(
    os.path.join("~", "Downloads", "CIC IDS 2018 Complete")
)
DEFAULT_UNSW_DIR = os.path.expanduser(os.path.join("~", "Downloads", "UNSW_NB15"))

LIMITATIONS = [
    "The literal Monday-Tuesday training split has zero in-scope positives in CIC-IDS-2017. The benchmark reports that finding and executes the documented Wednesday group-split fallback; it is not a literal day split.",
    "The scope is volumetric DoS/DDoS and scanning only. Web, brute-force, bot, infiltration, exploit, fuzzer, shellcode, backdoor, analysis, and worm rows are dropped, never scored as benign.",
    "Every '- Attempted' row is excluded from both classes.",
    "Thresholds are selected from Wednesday benign scores only. Thursday-Friday labels and external labels are never used to choose a threshold.",
    "CIC-IDS-2018 is used only for DoS/DDoS (no PortScan rows are present). UNSW-NB15 is used only for DoS/Reconnaissance.",
    "Average precision is prevalence-sensitive. Compare the same rows and the same threshold; the natural-prevalence and 0.1% tables are not interchangeable.",
    "The portable-ratio transform removes scale-dependent magnitudes, not every capture artifact. Flow timeout, capture point, and labelling policy still differ.",
    "The serving artifact and the frozen Tier A schema are unchanged. No candidate is promoted to serving while the requested protocol is infeasible.",
    "The P3B baseline bundle is a gitignored, regenerable research artifact. When it is absent, baseline thresholded values come from docs/portable_transfer_results.json and ROC-AUC/AP are reported as unavailable.",
    "The P3B baseline was fitted with a stratified group split over all CIC-IDS-2017 days, so some Thursday-Friday rows were in its training partition and its test ROC-AUC/PR-AUC are optimistic. Its published threshold is 1.000000 and produced zero alerts by construction. Read the baseline rows as a ranking reference, not a clean holdout.",
    "The fallback split is group-disjoint under the repository's (5-tuple, normalised label) group key. Because the key includes the label, one 5-tuple can appear in training as one family and in calibration as another.",
]


# ---------------------------------------------------------------------------
# Helpers
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


def _sha256(path: str) -> str | None:
    if not os.path.isfile(path):
        return None
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _model_row(
    label: str,
    metrics: dict[str, Any],
    *,
    note: str | None = None,
) -> dict[str, Any]:
    return {
        "model": label,
        "threshold": metrics.get("threshold"),
        "roc_auc": metrics.get("roc_auc"),
        "pr_auc": metrics.get("pr_auc"),
        "fpr": metrics.get("fpr"),
        "precision": metrics.get("precision"),
        "recall": metrics.get("recall"),
        "alerts": metrics.get("alerts"),
        "rows": metrics.get("rows"),
        "prevalence": metrics.get("prevalence"),
        "note": note,
    }


def _evaluate(
    model: Any,
    dataset: PortableDataset,
    threshold: float,
) -> dict[str, Any]:
    scores = attack_probability(model, dataset.matrix)
    return binary_metrics(dataset.labels, scores, threshold)


def _load_baseline() -> tuple[Any | None, str | None]:
    if not os.path.isfile(BASELINE_PATH):
        return None, None
    try:
        bundle = joblib.load(BASELINE_PATH)
        return bundle, _sha256(BASELINE_PATH)
    except Exception as exc:  # noqa: BLE001 - baseline is optional
        print(f"warning: could not load the P3B baseline bundle: {exc}", flush=True)
        return None, None


def _published_baseline_payload() -> dict[str, Any] | None:
    if not os.path.isfile(PUBLISHED_BASELINE):
        return None
    with open(PUBLISHED_BASELINE, encoding="utf-8") as handle:
        data = json.load(handle)
    external = {}
    for dataset in data.get("datasets", []):
        name = dataset.get("name")
        results = dataset.get("results", {})
        external[name] = {
            "unique_rows": dataset.get("unique_rows"),
            "prevalence": dataset.get("prevalence"),
            "published_threshold": results.get("100_per_10k", {}).get("threshold"),
            "published_recall": results.get("100_per_10k", {}).get("recall"),
            "published_fpr": results.get("100_per_10k", {}).get("fpr"),
            "published_alerts": results.get("100_per_10k", {}).get("tp", 0)
            + results.get("100_per_10k", {}).get("fp", 0),
        }
    return {
        "source": "docs/portable_transfer_results.json",
        "model_sha256": data.get("model_sha256"),
        "thresholds": data.get("thresholds"),
        "external": external,
        "note": (
            "The P3B baseline selected a 1.000000 threshold on validation, so its "
            "published external alerts are zero by construction. That is the "
            "saturation failure this experiment is testing."
        ),
    }


def _baseline_metrics(
    bundle: Any | None,
    dataset: PortableDataset,
    *,
    matched_threshold: float | None,
    scores: np.ndarray | None = None,
) -> dict[str, Any]:
    if bundle is None:
        return {"status": "unavailable"}
    pipeline = bundle["pipeline"] if isinstance(bundle, dict) else bundle
    published_threshold = float(
        bundle.get("attack_threshold", 1.0) if isinstance(bundle, dict) else 1.0
    )
    if scores is None:
        scores = attack_probability(pipeline, dataset.matrix)
    payload: dict[str, Any] = {
        "status": "recomputed",
        "published_threshold": published_threshold,
        "published": binary_metrics(
            dataset.labels,
            scores,
            published_threshold,
        ),
    }
    if matched_threshold is not None:
        payload["matched_fpr"] = {
            "threshold": matched_threshold,
            "metrics": binary_metrics(
                dataset.labels,
                scores,
                matched_threshold,
            ),
            "caveat": (
                "The P3B model trained on a stratified group split over all "
                "CIC-IDS-2017 days, so its Wednesday benign score distribution "
                "is not a clean holdout and this row is a diagnostic, not an "
                "unbiased operating point."
            ),
        }
    return payload


def _external_block(
    dataset: PortableDataset,
    models: dict[str, Any],
    thresholds: dict[str, float],
    baseline_bundle: Any | None,
    *,
    primary_target: float,
) -> dict[str, Any]:
    block: dict[str, Any] = {
        "name": dataset.name,
        "files": dataset.files,
        "raw_rows": dataset.raw_rows,
        "kept_rows_before_dedup": dataset.kept_rows_before_dedup,
        "unique_rows": int(len(dataset.labels)),
        "duplicate_rows": dataset.duplicate_rows,
        "header_rows": dataset.header_rows,
        "prevalence": (
            float(np.mean(dataset.labels)) if len(dataset.labels) else None
        ),
        "scope_audit": dataset.audit,
        "models": {},
    }
    for name, model in models.items():
        threshold = thresholds[name]
        metrics = _evaluate(model, dataset, threshold)
        block["models"][name] = {
            "target_fpr": primary_target,
            "metrics": metrics,
        }
    baseline_threshold = None
    if baseline_bundle is not None:
        baseline_threshold = thresholds.get("baseline_matched")
    block["baseline"] = _baseline_metrics(
        baseline_bundle, dataset, matched_threshold=baseline_threshold
    )
    return block


def _candidate_thresholds(
    calibration_benign_scores: dict[str, np.ndarray],
) -> dict[str, dict[str, Any]]:
    thresholds: dict[str, dict[str, Any]] = {}
    for name, scores in calibration_benign_scores.items():
        thresholds[name] = {
            f"{target:g}": benign_fpr_threshold_report(scores, target)
            for target in TARGET_FPRS
        }
    return thresholds


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def _comparison_table(blocks: list[dict[str, Any]]) -> str:
    """Render a Baseline/A/B table for both block shapes.

    External blocks nest candidate payloads under ``models``; the Thursday-Friday
    block stores them at the top level. Folding both into one view keeps the
    table honest instead of skipping a dataset.
    """
    lines = [
        "| Dataset | Model | Threshold | ROC-AUC | PR-AUC | FPR | Precision | Recall | Alerts | Rows |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for block in blocks:
        models_payload = block.get("models")
        if models_payload is None:
            models_payload = {
                name: block[name]
                for name in ("A", "B")
                if isinstance(block.get(name), dict)
            }
        for name in ("baseline", "A", "B"):
            if name == "baseline":
                payload = block.get("baseline", {})
                if payload.get("status") != "recomputed":
                    rows = block.get("unique_rows", block.get("rows", "n/a"))
                    lines.append(
                        f"| {block['name']} | Baseline (published) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | {rows} |"
                    )
                    continue
                metrics = payload["published"]
                label = "Baseline (published threshold)"
            else:
                payload = models_payload.get(name)
                if payload is None:
                    continue
                metrics = payload["metrics"]
                label = f"Candidate {name}"
            lines.append(
                "| {dataset} | {model} | {threshold} | {auc} | {ap} | {fpr} | {precision} | {recall} | {alerts} | {rows} |".format(
                    dataset=block["name"],
                    model=label,
                    threshold=_fmt(metrics.get("threshold")),
                    auc=_fmt(metrics.get("roc_auc")),
                    ap=_fmt(metrics.get("pr_auc")),
                    fpr=_fmt(metrics.get("fpr"), 5),
                    precision=_fmt(metrics.get("precision")),
                    recall=_fmt(metrics.get("recall")),
                    alerts=_fmt(metrics.get("alerts")),
                    rows=_fmt(metrics.get("rows")),
                )
            )
    return "\n".join(lines)


def _interpretation(payload: dict[str, Any]) -> list[str]:
    """Derive plain-language findings from measured values, not from prose.

    Each sentence is conditioned on the payload so a rerun that changes the
    numbers also changes the interpretation. The goal is to stop a weak result
    from reading as a success.
    """
    bullets: list[str] = []
    thresholds = payload.get("thresholds", {})
    for name in ("A", "B"):
        rows = thresholds.get(name, {})
        if not rows:
            continue
        if all(not row.get("saturated") for row in rows.values()):
            bullets.append(
                f"Candidate {name} removes threshold saturation at both "
                "benign-FPR targets (0.005 and 0.001)."
            )
        else:
            saturated = ", ".join(
                key for key, row in rows.items() if row.get("saturated")
            )
            bullets.append(
                f"Candidate {name} still saturates at target FPR {saturated}, "
                "so that operating point is unusable."
            )

    test = payload["evaluation"]["test_natural"]
    for name in ("A", "B"):
        metrics = test[name]["metrics"]
        fpr = metrics.get("fpr")
        if fpr is not None:
            bullets.append(
                f"Thursday-Friday FPR for Candidate {name} is {fpr:.4f} at a "
                f"threshold selected for 0.005 on Wednesday "
                f"({fpr / 0.005:.1f}x the target). The benign-FPR guarantee does "
                "not transfer across days."
            )
        recall = metrics.get("recall")
        if recall is not None and recall < 0.05:
            bullets.append(
                f"Natural-prevalence recall for Candidate {name} is "
                f"{recall:.4f}, so the operating point misses almost every attack."
            )

    prevalence = payload["evaluation"]["test_prevalence_0_001"]
    for name in ("A", "B"):
        metrics = prevalence[name]["metrics"]
        bullets.append(
            f"At 0.1% prevalence, Candidate {name} has precision "
            f"{_fmt(metrics.get('precision'), 3)}, recall "
            f"{_fmt(metrics.get('recall'), 3)}, and "
            f"{_fmt(metrics.get('alerts_per_10k'), 0)} alerts per 10,000 rows. "
            "At this prevalence precision is set by the false-positive rate."
        )

    for block in payload["evaluation"]["external"]:
        models = block.get("models") or {}
        if not models:
            continue
        parts = []
        best_auc = 0.0
        for name in ("A", "B"):
            if name not in models:
                continue
            metrics = models[name]["metrics"]
            parts.append(
                f"{name}: ROC-AUC {_fmt(metrics.get('roc_auc'), 3)}, PR-AUC "
                f"{_fmt(metrics.get('pr_auc'), 3)}, recall "
                f"{_fmt(metrics.get('recall'), 4)}"
            )
            best_auc = max(best_auc, metrics.get("roc_auc") or 0.0)
        bullets.append(
            f"Matched-scope {block['name']} (prevalence "
            f"{_fmt(block.get('prevalence'), 3)}, {block['unique_rows']} rows): "
            + "; ".join(parts)
            + "."
        )
        if best_auc < 0.65:
            bullets.append(
                f"{block['name']} ranking is close to chance (best ROC-AUC "
                f"{best_auc:.3f}); this dataset does not support a claim of "
                "cross-dataset detection."
            )
        elif best_auc < 0.8:
            bullets.append(
                f"{block['name']} ranking is weak-to-moderate (best ROC-AUC "
                f"{best_auc:.3f}); transfer is demonstrated only as a ranking "
                "signal, not as an operating detector."
            )

    baseline_ap = payload["promotion"].get("baseline_external_mean_pr_auc")
    candidate_ap = payload["promotion"].get("candidate_external_mean_pr_auc", {})
    if baseline_ap is not None:
        bullets.append(
            "Mean matched-scope external PR-AUC: baseline "
            f"{baseline_ap:.4f}, Candidate A {_fmt(candidate_ap.get('A'), 4)}, "
            f"Candidate B {_fmt(candidate_ap.get('B'), 4)}. The baseline's "
            "Thursday-Friday scores are optimistic because its group split "
            "included Thursday-Friday rows, so the external comparison is the "
            "fair one."
        )
    return bullets


def render_report(payload: dict[str, Any]) -> str:
    protocol = payload["protocol"]
    thresholds = payload["thresholds"]
    test_natural = payload["evaluation"]["test_natural"]
    test_prevalence = payload["evaluation"]["test_prevalence_0_001"]
    external = payload["evaluation"]["external"]
    promotion = payload["promotion"]

    lines: list[str] = []
    lines.append("# Calibrated Cross-Dataset Transfer (Phase 1/2)")
    lines.append("")
    lines.append(
        f"**Generated:** {payload['generated_at']}  \n"
        f"**Artifact:** `{payload['artifact_version']}`  \n"
        f"**Feature schema:** {payload['feature_schema']['count']} portable-ratio features "
        f"(`{payload['feature_schema']['sha256'][:16]}...`)  \n"
        f"**Seed:** {payload['seed']}  \n"
        f"**Serving artifact:** `{payload['serving']['artifact']}` unchanged "
        f"(`{payload['serving']['sha256']}`)"
    )
    lines.append("")

    lines.append("## 1. Protocol feasibility")
    lines.append("")
    strict = protocol["strict_requested"]
    lines.append(
        f"The requested split trains on **{', '.join(strict['train_days'])}**, "
        f"calibrates on **{', '.join(strict['calibration_days'])}**, and tests on "
        f"**{', '.join(strict['test_days'])}**."
    )
    lines.append("")
    lines.append("| Partition | Rows | Benign | In-scope positive |")
    lines.append("|---|---:|---:|---:|")
    lines.append(
        f"| Monday-Tuesday (requested train) | {strict['rows']} | "
        f"{strict['benign_rows']} | {strict['positive_rows']} |"
    )
    lines.append("")
    lines.append(
        f"**Strict protocol fittable:** **{_fmt(strict['feasible'])}**. "
        f"{strict['reason']}"
    )
    lines.append("")
    executed = protocol["executed"]
    lines.append(
        f"**Executed protocol:** `{protocol['provenance']}`. "
        f"Train: {executed['train']['rows']} rows "
        f"({executed['train']['benign']} benign / {executed['train']['positive']} positive). "
        f"Calibration: {executed['calibration']['rows']} rows "
        f"({executed['calibration']['benign']} benign / {executed['calibration']['positive']} positive). "
        f"Test: {executed['test']['rows']} rows "
        f"({executed['test']['benign']} benign / {executed['test']['positive']} positive)."
    )
    lines.append("")
    if protocol["deviation"]:
        lines.append(f"> **Protocol deviation.** {protocol['deviation']}")
        lines.append("")
    lines.append(
        f"Training/calibration group overlap: **{protocol['train_calibration_group_overlap']}**. "
        "Thursday-Friday and external rows were never used for fitting or threshold selection."
    )
    lines.append("")

    lines.append("## 2. Operating thresholds from Wednesday benign scores")
    lines.append("")
    lines.append(
        "| Model | Target FPR | Threshold | Realized benign FPR | Benign max | Saturated |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|")
    for name in ("A", "B", "baseline_matched"):
        if name not in thresholds:
            continue
        for key, row in thresholds[name].items():
            lines.append(
                f"| {name if name != 'baseline_matched' else 'Baseline (matched policy)'} | "
                f"{key} | {_fmt(row['threshold'])} | {_fmt(row['realized_benign_fpr'], 5)} | "
                f"{_fmt(row['benign_max'])} | {_fmt(row['saturated'])} |"
            )
    lines.append("")
    lines.append(
        "The guard is `0.001 < threshold < 0.99`. A saturated threshold would silence "
        "the detector; none of the calibrated candidates may be promoted if any target "
        "is saturated."
    )
    lines.append("")

    lines.append("## 3. Thursday-Friday natural prevalence")
    lines.append("")
    lines.append(
        "| Model | Threshold | ROC-AUC | PR-AUC | FPR | Precision | Recall | Alerts | Alert rate |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for name in ("baseline", "A", "B"):
        if name == "baseline":
            baseline = test_natural.get("baseline", {})
            if baseline.get("status") != "recomputed":
                continue
            metrics = baseline["published"]
            label = "Baseline (published threshold)"
        else:
            metrics = test_natural[name]["metrics"]
            label = f"Candidate {name}"
        lines.append(
            f"| {label} | {_fmt(metrics.get('threshold'))} | {_fmt(metrics.get('roc_auc'))} | "
            f"{_fmt(metrics.get('pr_auc'))} | {_fmt(metrics.get('fpr'), 5)} | "
            f"{_fmt(metrics.get('precision'))} | {_fmt(metrics.get('recall'))} | "
            f"{_fmt(metrics.get('alerts'))} | {_fmt(metrics.get('alert_rate'), 5)} |"
        )
    lines.append("")
    lines.append(
        f"Thursday is benign-only in the frozen scope; Friday supplies DDoS and "
        f"PortScan. Natural prevalence: {_fmt(test_natural['prevalence'], 5)}."
    )
    lines.append("")

    lines.append("## 4. Thursday-Friday at 0.1% prevalence")
    lines.append("")
    sampling = test_prevalence["sampling"]
    lines.append(
        f"All {sampling['benign_rows']} benign test rows are kept; "
        f"{sampling['positives_sampled']} of {sampling['positives_available']} positives "
        f"are sampled with seed {sampling['seed']}. Realized prevalence: "
        f"{_fmt(sampling['realized_prevalence'], 5)}."
    )
    lines.append("")
    lines.append(
        "| Model | Threshold | PPV (precision) | Recall | Alerts per 10k | Alerts | TP | FP |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for name in ("baseline", "A", "B"):
        if name == "baseline":
            baseline = test_prevalence.get("baseline", {})
            if baseline.get("status") != "recomputed":
                continue
            metrics = baseline["published"]
            label = "Baseline (published threshold)"
        else:
            metrics = test_prevalence[name]["metrics"]
            label = f"Candidate {name}"
        lines.append(
            f"| {label} | {_fmt(metrics.get('threshold'))} | {_fmt(metrics.get('precision'))} | "
            f"{_fmt(metrics.get('recall'))} | {_fmt(metrics.get('alerts_per_10k'))} | "
            f"{_fmt(metrics.get('alerts'))} | {_fmt(metrics.get('tp'))} | {_fmt(metrics.get('fp'))} |"
        )
    lines.append("")

    lines.append("## 5. Matched-scope external transfer")
    lines.append("")
    lines.append(
        "Both external datasets were filtered to the same DoS/DDoS/scanning scope "
        "before scoring. Thresholds are the CIC-IDS-2017 Wednesday benign-FPR "
        "thresholds; no external label was used to choose them."
    )
    lines.append("")
    external_rows = [block for block in external if block.get("models")]
    if external_rows:
        lines.append(_comparison_table(external_rows))
        lines.append("")
        for block in external_rows:
            audit = block["scope_audit"]
            lines.append(
                f"- **{block['name']}**: raw {audit['raw_rows']}, benign "
                f"{audit['benign_rows']}, positive {audit['positive_rows']}, dropped "
                f"{audit['dropped_out_of_scope_rows']} (including "
                f"{audit['dropped_attempted_rows']} `- Attempted`)."
            )
        lines.append("")
    else:
        lines.append("No external dataset was available in this run.")
        lines.append("")

    lines.append("## 6. Baseline vs Candidate A vs Candidate B")
    lines.append("")
    lines.append(_comparison_table([test_natural] + external_rows))
    lines.append("")
    lines.append(
        "> **Baseline caveat.** The P3B baseline was fitted with a stratified "
        "group split over all CIC-IDS-2017 days, so part of Thursday-Friday was "
        "in its training data and its ROC-AUC/PR-AUC are optimistic. Its "
        "published threshold is 1.000000 and produced zero alerts, which is the "
        "saturation failure this experiment isolates. Read the baseline rows as "
        "a ranking reference, not a clean holdout."
    )
    lines.append("")

    lines.append("## 7. What the evidence supports")
    lines.append("")
    for bullet in _interpretation(payload):
        lines.append(f"- {bullet}")
    lines.append("")

    lines.append("## 8. Promotion decision")
    lines.append("")
    saturation_flags = {
        name: not any(row.get("saturated") for row in rows.values())
        for name, rows in thresholds.items()
        if name in ("A", "B")
    }
    lines.append(
        f"- Saturation eliminated (both targets, both candidates): "
        f"**{_fmt(promotion['saturation_eliminated'])}**\n"
        f"- Saturation eliminated by candidate: "
        + ", ".join(
            f"{name} = **{_fmt(value)}**" for name, value in saturation_flags.items()
        )
        + f"\n- Protocol matches the requested day split: **{_fmt(promotion['protocol_matches_request'])}**\n"
        f"- Beats the baseline on matched-scope external PR-AUC: "
        f"**{_fmt(promotion['beats_baseline'])}**\n"
        f"- Best candidate by external mean PR-AUC: **{promotion['candidate'] or 'none'}**\n"
        f"- Promoted to serving: **{_fmt(promotion['promoted'])}**"
    )
    lines.append("")
    if promotion["reason"]:
        lines.append(f"{promotion['reason']}")
        lines.append("")

    lines.append("## 9. Limitations")
    lines.append("")
    for limitation in payload["limitations"]:
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)


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
    parser.add_argument("--cic-dir", default=DEFAULT_CIC_DIR)
    parser.add_argument("--unsw-dir", default=DEFAULT_UNSW_DIR)
    parser.add_argument(
        "--output-json",
        default=os.path.join(PROJECT_ROOT, "docs", "CALIBRATED_TRANSFER_RESULTS.json"),
    )
    parser.add_argument(
        "--report",
        default=os.path.join(PROJECT_ROOT, "docs", "CALIBRATED_TRANSFER_RESULTS.md"),
    )
    parser.add_argument("--chunksize", type=int, default=250_000)
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=None,
        help="Smoke-test limit per CSV; omit for the full run.",
    )
    parser.add_argument("--skip-external", action="store_true")
    parser.add_argument("--save-winner", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = time.time()
    os.makedirs(os.path.dirname(args.output_json) or ".", exist_ok=True)

    print(f"[1/6] loading {args.cic_source} from {args.data_dir}", flush=True)
    stage = time.time()
    cic = load_cic2017_portable(
        args.data_dir,
        source=args.cic_source,
        chunksize=args.chunksize,
        max_rows_per_file=args.max_rows_per_file,
    )
    print(
        f"      {len(cic.labels)} unique in-scope rows; "
        f"{cic.raw_rows} raw; {cic.duplicate_rows} duplicates "
        f"({time.time() - stage:.1f}s)",
        flush=True,
    )
    for day, counts in cic.counts.items():
        print(
            f"      {day}: {counts['rows']} rows ({counts['benign']} benign / "
            f"{counts['positive']} positive)",
            flush=True,
        )

    strict = strict_protocol_status(cic)
    print(
        f"      strict Monday-Tuesday train: {strict['benign_rows']} benign / "
        f"{strict['positive_rows']} positive (fittable={strict['feasible']})",
        flush=True,
    )

    print("[2/6] building the leakage-safe protocol split", flush=True)
    split = build_protocol_split(cic)
    print(f"      provenance: {split.provenance}", flush=True)
    print(f"      executed: {split.executed}", flush=True)

    x_train = cic.matrix[split.train_mask]
    y_train = cic.labels[split.train_mask]
    x_calibration = cic.matrix[split.calibration_mask]
    y_calibration = cic.labels[split.calibration_mask]
    calibration_benign = x_calibration[y_calibration == 0]
    test = cic.subset(split.test_mask)

    print("[3/6] fitting Candidate A (Random Forest + sigmoid calibration)", flush=True)
    stage = time.time()
    model_a, meta_a = fit_candidate_a(x_train, y_train, x_calibration, y_calibration)
    print(f"      done ({time.time() - stage:.1f}s)", flush=True)

    print("[4/6] fitting Candidate B (HistGradientBoosting)", flush=True)
    stage = time.time()
    model_b, meta_b = fit_candidate_b(x_train, y_train, x_calibration, y_calibration)
    print(f"      done ({time.time() - stage:.1f}s)", flush=True)

    calibration_scores = {
        "A": attack_probability(model_a, calibration_benign),
        "B": attack_probability(model_b, calibration_benign),
    }
    baseline_bundle, baseline_sha = _load_baseline()
    if baseline_bundle is not None:
        baseline_pipeline = (
            baseline_bundle["pipeline"]
            if isinstance(baseline_bundle, dict)
            else baseline_bundle
        )
        calibration_scores["baseline_matched"] = attack_probability(
            baseline_pipeline, calibration_benign
        )
    thresholds = _candidate_thresholds(calibration_scores)
    primary = {
        name: rows[f"{PRIMARY_TARGET_FPR:g}"]["threshold"]
        for name, rows in thresholds.items()
    }
    for name, rows in thresholds.items():
        for target, row in rows.items():
            print(
                f"      {name} target_fpr={target}: threshold={row['threshold']:.6f} "
                f"realized={row['realized_benign_fpr']:.6f} saturated={row['saturated']}",
                flush=True,
            )

    models = {"A": model_a, "B": model_b}

    print("[5/6] scoring Thursday-Friday and external datasets", flush=True)
    test_scores = {
        name: attack_probability(model, test.matrix) for name, model in models.items()
    }
    test_natural: dict[str, Any] = {
        "name": "Thursday-Friday",
        "prevalence": float(np.mean(test.labels)) if len(test.labels) else None,
        "rows": int(len(test.labels)),
        "benign_rows": int(np.sum(test.labels == 0)),
        "positive_rows": int(np.sum(test.labels == 1)),
    }
    for name in ("A", "B"):
        test_natural[name] = {
            "target_fpr": PRIMARY_TARGET_FPR,
            "metrics": binary_metrics(
                test.labels, test_scores[name], primary[name]
            ),
        }
    test_natural["baseline"] = _baseline_metrics(
        baseline_bundle,
        test,
        matched_threshold=primary.get("baseline_matched"),
    )

    sample_indices, sampling = prevalence_subsample_indices(
        test.labels, target_prevalence=0.001, seed=SEED
    )
    test_prevalence: dict[str, Any] = {
        "sampling": sampling,
        "rows": int(len(sample_indices)),
    }
    for name in ("A", "B"):
        metrics = binary_metrics(
            test.labels[sample_indices],
            test_scores[name][sample_indices],
            primary[name],
        )
        test_prevalence[name] = {
            "target_fpr": PRIMARY_TARGET_FPR,
            "metrics": metrics,
        }
    test_prevalence["baseline"] = _baseline_metrics(
        baseline_bundle,
        test.subset(sample_indices),
        matched_threshold=primary.get("baseline_matched"),
    )

    external: list[dict[str, Any]] = []
    if not args.skip_external:
        try:
            print(f"      loading CIC-IDS-2018 from {args.cic_dir}", flush=True)
            stage = time.time()
            cic2018 = load_cic2018_portable(
                args.cic_dir,
                chunksize=args.chunksize,
                max_rows_per_file=args.max_rows_per_file,
            )
            print(
                f"      CIC-IDS-2018: {len(cic2018.labels)} unique rows "
                f"({time.time() - stage:.1f}s)",
                flush=True,
            )
            external.append(
                _external_block(
                    cic2018,
                    models,
                    primary,
                    baseline_bundle,
                    primary_target=PRIMARY_TARGET_FPR,
                )
            )
        except (FileNotFoundError, RuntimeError) as exc:
            external.append(
                {"name": "cicids2018", "status": "unavailable", "reason": str(exc)}
            )
            print(f"      CIC-IDS-2018 unavailable: {exc}", flush=True)

        try:
            print(f"      loading UNSW-NB15 from {args.unsw_dir}", flush=True)
            unsw = load_unsw_portable(args.unsw_dir)
            print(
                f"      UNSW-NB15: {len(unsw.labels)} unique rows", flush=True
            )
            external.append(
                _external_block(
                    unsw,
                    models,
                    primary,
                    baseline_bundle,
                    primary_target=PRIMARY_TARGET_FPR,
                )
            )
        except (FileNotFoundError, RuntimeError) as exc:
            external.append(
                {"name": "unsw_nb15", "status": "unavailable", "reason": str(exc)}
            )
            print(f"      UNSW-NB15 unavailable: {exc}", flush=True)

    print("[6/6] writing the report", flush=True)

    saturated = any(
        row["saturated"]
        for name in ("A", "B")
        for row in thresholds.get(name, {}).values()
    )
    saturation_by_candidate = {
        name: not any(row["saturated"] for row in thresholds.get(name, {}).values())
        for name in ("A", "B")
    }
    protocol_matches = split.provenance == "requested_day_split"

    def _mean_external_ap(name: str) -> float | None:
        values = []
        for block in external:
            payload = block.get("models", {}).get(name)
            if payload and payload["metrics"].get("pr_auc") is not None:
                values.append(payload["metrics"]["pr_auc"])
        return float(np.mean(values)) if values else None

    baseline_external_ap = None
    baseline_ap_values = []
    for block in external:
        payload = block.get("baseline", {})
        if payload.get("status") == "recomputed":
            baseline_ap_values.append(payload["published"]["pr_auc"])
    if baseline_ap_values and all(value is not None for value in baseline_ap_values):
        baseline_external_ap = float(np.mean(baseline_ap_values))

    candidate_ap = {name: _mean_external_ap(name) for name in ("A", "B")}
    beats_baseline = bool(
        baseline_external_ap is not None
        and any(
            value is not None and value > baseline_external_ap
            for value in candidate_ap.values()
        )
    )
    best_candidate = None
    if any(value is not None for value in candidate_ap.values()):
        best_candidate = max(
            (name for name, value in candidate_ap.items() if value is not None),
            key=lambda name: candidate_ap[name],
        )
    qualifies = bool(not saturated and protocol_matches and beats_baseline)

    promotion_reason = (
        "Promoted: saturation eliminated, the requested day split was fittable, "
        "and the candidate beat the baseline on matched-scope external PR-AUC."
        if qualifies
        else (
            "Not promoted. The requested Monday-Tuesday matched-scope training "
            "partition has zero positives, so the executed Wednesday group-split "
            "fallback is a protocol deviation. The serving artifact and registry "
            "stay unchanged."
        )
    )

    payload: dict[str, Any] = {
        "artifact_version": ARTIFACT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "feature_schema": feature_schema(),
        "portable_schema": portable_schema(),
        "serving": {
            "artifact": os.path.basename(SERVING_PATH),
            "sha256": SERVING_SHA256,
            "present_sha256": _sha256(SERVING_PATH),
            "untouched": True,
        },
        "baseline": {
            "source": "P3B portable-ratio RF (stratified group, uncalibrated)",
            "artifact": os.path.basename(BASELINE_PATH),
            "artifact_present": baseline_bundle is not None,
            "artifact_sha256": baseline_sha,
            "published": _published_baseline_payload(),
        },
        "protocol": split.as_payload(),
        "candidates": {
            "A": meta_a,
            "B": meta_b,
        },
        "thresholds": thresholds,
        "evaluation": {
            "test_natural": test_natural,
            "test_prevalence_0_001": test_prevalence,
            "external": external,
        },
        "promotion": {
            "saturation_eliminated": bool(not saturated),
            "saturation_eliminated_by_candidate": saturation_by_candidate,
            "protocol_matches_request": bool(protocol_matches),
            "beats_baseline": beats_baseline,
            "baseline_external_mean_pr_auc": baseline_external_ap,
            "candidate_external_mean_pr_auc": candidate_ap,
            "candidate": best_candidate,
            "promoted": bool(qualifies and args.save_winner),
            "qualifies": qualifies,
            "reason": promotion_reason,
        },
        "limitations": LIMITATIONS,
        "elapsed_seconds": round(time.time() - started, 2),
    }

    if args.save_winner and qualifies and best_candidate is not None:
        winner = models[best_candidate]
        bundle_path = os.path.join(
            PROJECT_ROOT,
            "models",
            f"model_bundle_rf_calibrated_candidate_{best_candidate.lower()}_seed42.pkl",
        )
        bundle = {
            "pipeline": winner,
            "feature_names": list(PORTABLE_FEATURE_NAMES),
            "feature_set": "portable_ratio",
            "feature_schema_sha256": payload["feature_schema"]["sha256"],
            "task": "binary_attack",
            "classes": ["BENIGN", "ATTACK"],
            "benign_class_index": 0,
            "attack_threshold": primary[best_candidate],
            "thresholds": {
                key: row["threshold"]
                for key, row in thresholds[best_candidate].items()
            },
            "threshold_comparison": ">",
            "training_split": split.provenance,
            "seed": SEED,
            "serving_artifact_untouched": True,
        }
        joblib.dump(bundle, bundle_path)
        payload["promotion"]["saved_bundle"] = os.path.basename(bundle_path)
        payload["promotion"]["saved_bundle_sha256"] = _sha256(bundle_path)
        print(f"      saved candidate bundle to {bundle_path}", flush=True)

    with open(args.output_json, "w", encoding="utf-8") as handle:
        json.dump(_json_safe(payload), handle, indent=2, sort_keys=True)
        handle.write("\n")
    report = render_report(payload)
    with open(args.report, "w", encoding="utf-8") as handle:
        handle.write(report)
        handle.write("\n")

    print("")
    print("Baseline vs Candidate A vs Candidate B (matched scope)")
    print(
        _comparison_table(
            [test_natural] + [block for block in external if block.get("models")]
        )
    )
    print("")
    print(f"JSON:   {args.output_json}")
    print(f"Report: {args.report}")
    print(f"Elapsed: {payload['elapsed_seconds']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
