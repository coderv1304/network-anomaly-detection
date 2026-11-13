"""Phase D3: re-establish baselines under the frozen evaluation protocol.

The Random Forest, Logistic Regression, and Isolation Forest artifacts were
already trained and evaluated on the day-based split (train = Mon+Tue,
validation = Wed, test = Thu+Fri) for seeds 42-46.  This script does not
retrain them.  It aggregates their frozen per-seed metrics, verifies that the
data and feature-schema hashes agree, and adds cheap reference baselines that
are computed directly from the final-test partition:

* majority class (always BENIGN);
* a port-memorisation rule that flags the destination ports used by attacks
  in the training partition (FTP 21, SSH 22);
* an ephemeral-destination heuristic that flags destination ports above 1023.

All methods are reported against the same predeclared gates.  No model is
selected on weighted F1 or accuracy.

Outputs:
    docs/BASELINE_RESULTS_V2.md
    docs/baseline_results_v2.json
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import statistics
import sys
import time
import unicodedata
from datetime import UTC, datetime

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.evaluate import CIC_DAYS  # noqa: E402

SEEDS = [42, 43, 44, 45, 46]
MODELS = ["rf", "lr", "if"]
MODEL_DISPLAY = {
    "rf": "Random Forest (multiclass)",
    "lr": "Logistic Regression (multiclass)",
    "if": "Isolation Forest (binary anomaly)",
}
CHUNK_ROWS = 200_000

# Predeclared per-family recall targets from docs/EVALUATION_PROTOCOL_V2.md.
FAMILY_RECALL_TARGETS = {
    "Bot": 0.70,
    "DDoS": 0.85,
    "PortScan": 0.85,
    "Web Attack - Brute Force": 0.85,
    "Infiltration": 0.60,
    "Web Attack - Sql Injection": 0.70,
    "Web Attack - XSS": 0.85,
}
CROSS_CUTTING = {
    "max_test_fpr": 0.01,
    "max_alert_rate": 0.02,
    "max_ece": 0.05,
}

# Training attacks in the day-based split are FTP-Patator and SSH-Patator,
# whose destination ports are 21 and 22.  The rule uses only that training
# knowledge, never test labels.
TRAINING_ATTACK_PORTS = {21, 22}


def canonical_label(value) -> str:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return "<missing>"
    text = unicodedata.normalize("NFKC", str(value)).strip()
    for dash in ("\u2013", "\u2014", "\u2212"):
        text = text.replace(dash, "-")
    return " ".join(text.split())


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def mean_std(values: list[float]) -> dict:
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return {"mean": None, "std": None, "n": 0}
    return {
        "mean": statistics.fmean(clean),
        "std": statistics.stdev(clean) if len(clean) > 1 else 0.0,
        "n": len(clean),
    }


def load_metrics(model: str, seed: int) -> dict:
    path = f"models/metrics_{model}_day_based_seed{seed}.json"
    with open(path, encoding="utf-8") as handle:
        metrics = json.load(handle)
    manifest_path = f"models/model_manifest_{model}_day_based_seed{seed}.json"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    return {"metrics": metrics, "manifest": manifest, "metrics_path": path, "manifest_path": manifest_path}


def extract_run(model: str, seed: int) -> dict:
    loaded = load_metrics(model, seed)
    metrics = loaded["metrics"]
    manifest = loaded["manifest"]

    pr_auc = metrics.get("binary_pr_auc", metrics.get("pr_auc"))
    roc_auc = metrics.get("binary_roc_auc", metrics.get("roc_auc"))
    operating = metrics.get("operating_threshold", {}).get("test", {})
    calibration = metrics.get("calibration") or {}
    evaluation = metrics.get("evaluation") or {}

    family_recall = {}
    family_support = {}
    for raw_label, values in (metrics.get("attack_family_detection") or {}).items():
        label = canonical_label(raw_label)
        family_recall[label] = values.get("recall")
        family_support[label] = values.get("support")

    fit_seconds = evaluation.get("fit_seconds", metrics.get("fit_seconds"))
    inference_seconds = evaluation.get("batch_inference_mean_seconds_per_flow")

    config = {
        "model_type": manifest.get("model_type"),
        "task": manifest.get("task"),
        "split_mode": manifest.get("split_mode"),
        "seed": manifest.get("seed"),
        "class_weight": manifest.get("class_weight"),
        "feature_count": manifest.get("feature_count"),
        "features": manifest.get("features"),
        "python_version": manifest.get("python_version"),
        "scikit_learn_version": manifest.get("scikit_learn_version"),
    }

    return {
        "model": model,
        "seed": seed,
        "task": manifest.get("task"),
        "split_mode": manifest.get("split_mode"),
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "threshold": operating.get("threshold"),
        "test_fpr": operating.get("fpr"),
        "test_recall": operating.get("recall"),
        "test_precision": operating.get("precision"),
        "alert_rate": operating.get("alert_rate"),
        "family_recall": family_recall,
        "family_support": family_support,
        "brier": calibration.get("multiclass_brier_score"),
        "ece": calibration.get("expected_calibration_error_10_bins"),
        "fit_seconds": fit_seconds,
        "inference_seconds_per_flow": inference_seconds,
        "test_rows": metrics.get("test_rows") or evaluation.get("test_rows"),
        "train_rows": metrics.get("train_rows") or evaluation.get("train_rows"),
        "validation_rows": metrics.get("validation_rows") or evaluation.get("validation_rows"),
        "config_hash": sha256_json(config),
        "artifact_sha256": manifest.get("model_sha256"),
        "metrics_sha256": sha256_file(loaded["metrics_path"]),
        "dataset_sha256": manifest.get("dataset_sha256"),
        "feature_schema_sha256": sha256_json(manifest.get("features")),
        "config": {
            "task": manifest.get("task"),
            "split_mode": manifest.get("split_mode"),
            "class_weight": manifest.get("class_weight"),
            "feature_count": manifest.get("feature_count"),
            "python_version": manifest.get("python_version"),
            "scikit_learn_version": manifest.get("scikit_learn_version"),
        },
    }


def brier_and_ece(y_true: np.ndarray, scores: np.ndarray, bins: int = 10) -> tuple[float, float]:
    brier = float(np.mean((scores.astype(np.float64) - y_true.astype(np.float64)) ** 2))
    edges = np.linspace(0.0, 1.0, bins + 1)
    ece = 0.0
    total = len(scores)
    for index in range(bins):
        lower, upper = edges[index], edges[index + 1]
        if index == bins - 1:
            mask = (scores >= lower) & (scores <= upper)
        else:
            mask = (scores >= lower) & (scores < upper)
        count = int(mask.sum())
        if count == 0:
            continue
        confidence = float(np.mean(scores[mask]))
        accuracy = float(np.mean(y_true[mask]))
        ece += (count / total) * abs(confidence - accuracy)
    return brier, float(ece)


def read_test_labels_and_ports() -> dict:
    """Stream the final-test partition once and return labels and ports."""
    names = CIC_DAYS["Thursday"] + CIC_DAYS["Friday"]
    labels: list[np.ndarray] = []
    ports: list[np.ndarray] = []
    for name in names:
        path = os.path.join("data", name)
        encoding = "cp1252" if "WebAttacks" in name else "utf-8-sig"
        for chunk in pd.read_csv(
            path,
            usecols=[" Destination Port", " Label"],
            chunksize=CHUNK_ROWS,
            encoding=encoding,
            low_memory=False,
        ):
            chunk.columns = [column.strip() for column in chunk.columns]
            valid = chunk["Label"].notna()
            if not valid.any():
                continue
            labels.append(chunk.loc[valid, "Label"].astype(str).to_numpy())
            ports.append(
                pd.to_numeric(chunk.loc[valid, "Destination Port"], errors="coerce")
                .fillna(-1)
                .astype(np.int64)
                .to_numpy()
            )
    return {
        "labels": np.concatenate(labels),
        "ports": np.concatenate(ports),
        "files": names,
    }


def evaluate_rule(name: str, description: str, y_true: np.ndarray, scores: np.ndarray, labels: np.ndarray) -> dict:
    started = time.perf_counter()
    predictions = scores >= 0.5
    elapsed = time.perf_counter() - started

    tp = int(np.sum(predictions & (y_true == 1)))
    fp = int(np.sum(predictions & (y_true == 0)))
    fn = int(np.sum(~predictions & (y_true == 1)))
    tn = int(np.sum(~predictions & (y_true == 0)))
    benign = int((y_true == 0).sum())
    attacks = int((y_true == 1).sum())

    recall = tp / attacks if attacks else None
    precision = tp / (tp + fp) if (tp + fp) else None
    fpr = fp / benign if benign else None
    alert_rate = int(predictions.sum()) / len(predictions)
    alerts_per_10k_benign = fp / benign * 10_000 if benign else None

    # A constant score has no ranking information: AP equals prevalence and
    # ROC-AUC is 0.5 by definition.  sklearn would warn or be undefined.
    if float(np.ptp(scores)) == 0.0:
        pr_auc = float(attacks / len(y_true))
        roc_auc = 0.5
    else:
        pr_auc = float(average_precision_score(y_true, scores))
        roc_auc = float(roc_auc_score(y_true, scores))

    brier, ece = brier_and_ece(y_true, scores)

    family_counts = collections.Counter(labels.tolist())
    family_recall = {}
    family_support = {}
    for family, support in family_counts.items():
        if family == "BENIGN":
            continue
        mask = labels == family
        family_support[family] = int(support)
        family_recall[family] = float(np.mean(predictions[mask]))

    return {
        "model": name,
        "description": description,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "threshold": 0.5,
        "test_fpr": fpr,
        "test_recall": recall,
        "test_precision": precision,
        "alert_rate": alert_rate,
        "alerts_per_10k_benign": alerts_per_10k_benign,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "brier": brier,
        "ece": ece,
        "runtime_seconds": elapsed,
        "family_recall": family_recall,
        "family_support": family_support,
        "support": {"benign": benign, "attacks": attacks, "rows": int(len(y_true))},
    }


def aggregate_model(runs: list[dict]) -> dict:
    first = runs[0]
    families = sorted(
        {family for run in runs for family in run["family_recall"]},
        key=lambda family: (-(first["family_support"].get(family) or 0), family),
    )
    family_stats = {}
    for family in families:
        family_stats[family] = {
            "support": first["family_support"].get(family),
            "recall": mean_std([run["family_recall"].get(family) for run in runs]),
            "per_seed": {
                str(run["seed"]): run["family_recall"].get(family) for run in runs
            },
        }

    return {
        "model": first["model"],
        "display": MODEL_DISPLAY[first["model"]],
        "task": first["task"],
        "pr_auc": mean_std([run["pr_auc"] for run in runs]),
        "roc_auc": mean_std([run["roc_auc"] for run in runs]),
        "threshold": mean_std([run["threshold"] for run in runs]),
        "test_fpr": mean_std([run["test_fpr"] for run in runs]),
        "test_recall": mean_std([run["test_recall"] for run in runs]),
        "test_precision": mean_std([run["test_precision"] for run in runs]),
        "alert_rate": mean_std([run["alert_rate"] for run in runs]),
        "brier": mean_std([run["brier"] for run in runs]),
        "ece": mean_std([run["ece"] for run in runs]),
        "fit_seconds": mean_std([run["fit_seconds"] for run in runs]),
        "inference_seconds_per_flow": mean_std(
            [run["inference_seconds_per_flow"] for run in runs]
        ),
        "family_recall": family_stats,
        "per_seed": [
            {
                "seed": run["seed"],
                "pr_auc": run["pr_auc"],
                "roc_auc": run["roc_auc"],
                "threshold": run["threshold"],
                "test_fpr": run["test_fpr"],
                "test_recall": run["test_recall"],
                "test_precision": run["test_precision"],
                "alert_rate": run["alert_rate"],
                "brier": run["brier"],
                "ece": run["ece"],
                "bot_recall": run["family_recall"].get("Bot"),
            }
            for run in runs
        ],
        "config_hashes": sorted({run["config_hash"] for run in runs}),
        "artifact_hashes": {str(run["seed"]): run["artifact_sha256"] for run in runs},
        "metrics_hashes": {str(run["seed"]): run["metrics_sha256"] for run in runs},
        "feature_schema_sha256": first["feature_schema_sha256"],
        "config": first["config"],
        "rows": {
            "train": first["train_rows"],
            "validation": first["validation_rows"],
            "test": first["test_rows"],
        },
    }


def dataset_provenance(runs: list[dict]) -> dict:
    mappings = [run["dataset_sha256"] for run in runs]
    canonical = json.dumps(mappings[0], sort_keys=True, separators=(",", ":"))
    identical = all(
        json.dumps(mapping, sort_keys=True, separators=(",", ":")) == canonical
        for mapping in mappings
    )
    combined = hashlib.sha256()
    for name, digest in sorted(mappings[0].items()):
        combined.update(f"{name}:{digest}\n".encode("utf-8"))
    return {
        "files": mappings[0],
        "combined_sha256": combined.hexdigest(),
        "identical_across_runs": identical,
    }


def gate_results(models: list[dict], rules: list[dict]) -> dict:
    results = {}
    for model in models:
        bot = model["family_recall"].get("Bot", {}).get("recall", {})
        bot_mean = bot.get("mean")
        bot_seeds = [
            run["bot_recall"] for run in model["per_seed"] if run["bot_recall"] is not None
        ]
        results[model["model"]] = {
            "botnet_gate_target": FAMILY_RECALL_TARGETS["Bot"],
            "botnet_recall_mean": bot_mean,
            "botnet_recall_per_seed": bot_seeds,
            "botnet_gate_pass": bool(bot_mean is not None and bot_mean >= FAMILY_RECALL_TARGETS["Bot"]),
            "fpr_gate_target": CROSS_CUTTING["max_test_fpr"],
            "fpr_max_seed": max(
                (run["test_fpr"] for run in model["per_seed"] if run["test_fpr"] is not None),
                default=None,
            ),
            "fpr_gate_pass": bool(
                all(
                    run["test_fpr"] is not None
                    and run["test_fpr"] <= CROSS_CUTTING["max_test_fpr"]
                    for run in model["per_seed"]
                )
            ),
            "alert_rate_gate_target": CROSS_CUTTING["max_alert_rate"],
            "alert_rate_max_seed": max(
                (run["alert_rate"] for run in model["per_seed"] if run["alert_rate"] is not None),
                default=None,
            ),
            "alert_rate_gate_pass": bool(
                all(
                    run["alert_rate"] is not None
                    and run["alert_rate"] <= CROSS_CUTTING["max_alert_rate"]
                    for run in model["per_seed"]
                )
            ),
            "calibration_gate_target": CROSS_CUTTING["max_ece"],
            "ece_mean": model["ece"]["mean"],
            "calibration_gate_pass": bool(
                model["ece"]["mean"] is not None
                and model["ece"]["mean"] <= CROSS_CUTTING["max_ece"]
            ),
        }
    for rule in rules:
        bot = rule["family_recall"].get("Bot")
        results[rule["model"]] = {
            "botnet_gate_target": FAMILY_RECALL_TARGETS["Bot"],
            "botnet_recall_mean": bot,
            "botnet_recall_per_seed": [bot],
            "botnet_gate_pass": bool(bot is not None and bot >= FAMILY_RECALL_TARGETS["Bot"]),
            "fpr_gate_target": CROSS_CUTTING["max_test_fpr"],
            "fpr_max_seed": rule["test_fpr"],
            "fpr_gate_pass": bool(
                rule["test_fpr"] is not None and rule["test_fpr"] <= CROSS_CUTTING["max_test_fpr"]
            ),
            "alert_rate_gate_target": CROSS_CUTTING["max_alert_rate"],
            "alert_rate_max_seed": rule["alert_rate"],
            "alert_rate_gate_pass": bool(rule["alert_rate"] <= CROSS_CUTTING["max_alert_rate"]),
            "calibration_gate_target": CROSS_CUTTING["max_ece"],
            "ece_mean": rule["ece"],
            "calibration_gate_pass": bool(rule["ece"] <= CROSS_CUTTING["max_ece"]),
        }
    return results


def fmt(value, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def fmt_mean_std(stat: dict, digits: int = 4, percent: bool = False) -> str:
    if stat.get("mean") is None:
        return "n/a"
    if percent:
        return f"{stat['mean'] * 100:.2f}% ± {stat['std'] * 100:.2f}%"
    return f"{stat['mean']:.{digits}f} ± {stat['std']:.{digits}f}"


def fmt_pct(value, digits: int = 2) -> str:
    if value is None:
        return "n/a"
    return f"{value * 100:.{digits}f}%"


def write_markdown(report: dict, path: str) -> None:
    lines = [
        "# Controlled Baseline Comparison Under the Frozen Protocol (Phase D3)",
        "",
        f"*Generated: {report['generated_at']}*",
        "",
        "## 1. Scope and rules",
        "",
        "- Split: train = Monday + Tuesday, validation = Wednesday, final test = Thursday + Friday.",
        "- Threshold: selected on validation only by maximising attack recall subject to validation FPR <= 1%, then frozen before test.",
        "- Seeds: 42, 43, 44, 45, 46. Variation across seeds on one fixed split is estimator variation, not independent replication.",
        "- No model is selected using weighted F1 or accuracy. Model rows come from the frozen per-seed artifacts; rule rows are recomputed directly from the final-test partition.",
        "- Per-family precision is not available from the frozen binary attack-flag artifacts. Only per-family recall and support are reported; this is a known gap.",
        "",
        "## 2. Provenance",
        "",
        f"- Data combined SHA-256: `{report['provenance']['data']['combined_sha256']}`",
        f"- Data hashes identical across all runs: `{report['provenance']['data']['identical_across_runs']}`",
        f"- Feature schema SHA-256: `{report['provenance']['feature_schema_sha256']}`",
        f"- Evaluation protocol SHA-256: `{report['provenance']['protocol_sha256']}`",
        f"- Rows: train {report['provenance']['rows']['train']:,}, validation {report['provenance']['rows']['validation']:,}, test {report['provenance']['rows']['test']:,}",
        "",
        "| Model | Configuration hash | Artifact hashes (seed: SHA-256) |",
        "| --- | --- | --- |",
    ]
    for model in report["models"]:
        artifacts = "<br>".join(
            f"{seed}: `{digest}`" for seed, digest in sorted(model["artifact_hashes"].items())
        )
        lines.append(
            f"| {model['display']} | `{model['config_hashes'][0]}` | {artifacts} |"
        )

    lines.extend([
        "",
        "## 3. Aggregate results (mean ± sample std across seeds 42-46)",
        "",
        "| Method | PR-AUC | ROC-AUC | Frozen threshold | Test FPR | Recall | Precision | Alert rate | Alerts / 10k benign | Brier | ECE | Fit (s) | Inference (ms/flow) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for model in report["models"]:
        inference = model["inference_seconds_per_flow"]
        inference_ms = (
            f"{inference['mean'] * 1000:.4f} ± {inference['std'] * 1000:.4f}"
            if inference.get("mean") is not None
            else "n/a"
        )
        benign = report["test_support"]["benign"]
        total = report["test_support"]["rows"]
        per_10k_mean = (
            model["alert_rate"]["mean"] * total / benign * 10_000
            if model["alert_rate"]["mean"] is not None
            else None
        )
        per_10k_std = (
            model["alert_rate"]["std"] * total / benign * 10_000
            if model["alert_rate"]["std"] is not None
            else 0.0
        )
        lines.append(
            f"| {model['display']} | {fmt_mean_std(model['pr_auc'])} | "
            f"{fmt_mean_std(model['roc_auc'])} | {fmt_mean_std(model['threshold'], 6)} | "
            f"{fmt_mean_std(model['test_fpr'], percent=True)} | "
            f"{fmt_mean_std(model['test_recall'], percent=True)} | "
            f"{fmt_mean_std(model['test_precision'], percent=True)} | "
            f"{fmt_mean_std(model['alert_rate'], percent=True)} | "
            f"{fmt(per_10k_mean, 1)} ± {fmt(per_10k_std, 1)} | "
            f"{fmt_mean_std(model['brier'])} | {fmt_mean_std(model['ece'])} | "
            f"{fmt_mean_std(model['fit_seconds'], 2)} | {inference_ms} |"
        )
    for rule in report["rules"]:
        lines.append(
            f"| {rule['display']} | {fmt(rule['pr_auc'])} | {fmt(rule['roc_auc'])} | "
            f"{fmt(rule['threshold'], 2)} | {fmt_pct(rule['test_fpr'])} | "
            f"{fmt_pct(rule['test_recall'])} | {fmt_pct(rule['test_precision'])} | "
            f"{fmt_pct(rule['alert_rate'])} | {fmt(rule['alerts_per_10k_benign'], 1)} | "
            f"{fmt(rule['brier'])} | {fmt(rule['ece'])} | {fmt(rule['runtime_seconds'], 4)} | n/a |"
        )

    lines.extend([
        "",
        "## 4. Per-family recall at the frozen threshold",
        "",
        "Mean ± sample std across seeds for learned models; point estimate for rules. Support is the final-test count.",
        "",
        "| Family | Support | " + " | ".join(model["display"] for model in report["models"]) + " | " + " | ".join(rule["display"] for rule in report["rules"]) + " |",
        "| --- | ---: | " + " | ".join("---:" for _ in report["models"]) + " | " + " | ".join("---:" for _ in report["rules"]) + " |",
    ])
    families = sorted(
        {family for model in report["models"] for family in model["family_recall"]}
        | {family for rule in report["rules"] for family in rule["family_recall"]},
        key=lambda family: -(report["models"][0]["family_recall"].get(family, {}).get("support") or 0),
    )
    for family in families:
        support = (
            report["models"][0]["family_recall"].get(family, {}).get("support")
            or next(
                (
                    rule["family_support"].get(family)
                    for rule in report["rules"]
                    if family in rule["family_support"]
                ),
                0,
            )
        )
        model_cells = []
        for model in report["models"]:
            stat = model["family_recall"].get(family, {}).get("recall", {})
            model_cells.append(fmt_mean_std(stat, percent=True))
        rule_cells = [
            f"{fmt(rule['family_recall'].get(family) * 100, 2)}%" if family in rule["family_recall"] else "n/a"
            for rule in report["rules"]
        ]
        lines.append(
            f"| {family} | {support:,} | " + " | ".join(model_cells) + " | " + " | ".join(rule_cells) + " |"
        )

    lines.extend([
        "",
        "## 5. Gate results",
        "",
        "| Method | Bot recall (target >= 0.70) | Botnet gate | Max seed FPR (target <= 1%) | FPR gate | Max alert rate (target <= 2%) | Alert-rate gate | ECE (target <= 0.05) | Calibration gate |",
        "| --- | ---: | :---: | ---: | :---: | ---: | :---: | ---: | :---: |",
    ])
    for name, gate in report["gates"].items():
        display = next(
            (model["display"] for model in report["models"] if model["model"] == name),
            next((rule["display"] for rule in report["rules"] if rule["model"] == name), name),
        )
        lines.append(
            f"| {display} | {fmt_pct(gate['botnet_recall_mean'])} | "
            f"{'PASS' if gate['botnet_gate_pass'] else 'FAIL'} | "
            f"{fmt_pct(gate['fpr_max_seed'])} | "
            f"{'PASS' if gate['fpr_gate_pass'] else 'FAIL'} | "
            f"{fmt_pct(gate['alert_rate_max_seed'])} | "
            f"{'PASS' if gate['alert_rate_gate_pass'] else 'FAIL'} | "
            f"{fmt(gate['ece_mean'])} | "
            f"{'PASS' if gate['calibration_gate_pass'] else 'FAIL'} |"
        )

    lines.extend([
        "",
        "## 6. Rule baseline definitions",
        "",
    ])
    for rule in report["rules"]:
        lines.append(f"- **{rule['display']}**: {rule['description']}")

    lines.extend([
        "",
        "## 7. Per-seed results for learned models",
        "",
        "| Model | Seed | PR-AUC | ROC-AUC | Threshold | Test FPR | Recall | Precision | Alert rate | Bot recall |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for model in report["models"]:
        for run in model["per_seed"]:
            lines.append(
                f"| {model['display']} | {run['seed']} | {fmt(run['pr_auc'])} | "
                f"{fmt(run['roc_auc'])} | {fmt(run['threshold'], 6)} | "
                f"{fmt_pct(run['test_fpr'])} | {fmt_pct(run['test_recall'])} | "
                f"{fmt_pct(run['test_precision'])} | {fmt_pct(run['alert_rate'])} | "
                f"{fmt_pct(run['bot_recall'])} |"
            )

    lines.extend([
        "",
        "## 8. Interpretation",
        "",
        "- The Random Forest is the strongest learned baseline on PR-AUC, but its frozen-threshold FPR varies from below 1% to roughly 7.8% across seeds, so it fails the cross-cutting FPR gate on at least one seed.",
        "- Every learned model fails the Botnet recall gate: Bot recall is near zero for Logistic Regression and Isolation Forest and about 1% for the Random Forest.",
        "- The majority baseline fails the Botnet gate and has no ranking ability.",
        "- The port-memorisation rule fails the Botnet gate because the final-test attacks do not reuse the FTP/SSH training ports.",
        "- The ephemeral-destination rule reaches high Bot recall by flagging every Bot flow, but it also flags roughly a quarter of benign flows. It therefore fails the FPR and alert-rate gates. This shows why the Botnet gate must never be evaluated alone.",
        "- Calibration is poor for every learned model (ECE about 0.24-0.25), far above the 0.05 target.",
        "- No baseline passes all predeclared gates. The 9/10 detection claim remains unsupported.",
        "",
        "## 9. Reproduce",
        "",
        "```bash",
        "venv/Scripts/python.exe training/baseline_comparison_v2.py",
        "```",
        "",
    ])

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate frozen baselines and rule baselines.")
    parser.add_argument("--output-dir", default="docs")
    args = parser.parse_args()

    runs = []
    for model in MODELS:
        for seed in SEEDS:
            runs.append(extract_run(model, seed))

    models = []
    for model in MODELS:
        model_runs = [run for run in runs if run["model"] == model]
        models.append(aggregate_model(model_runs))

    print("[baselines] streaming final-test labels and destination ports ...", flush=True)
    test = read_test_labels_and_ports()
    labels = test["labels"]
    y_true = (np.array([canonical_label(label) for label in labels]) != "BENIGN").astype(np.int8)
    ports = test["ports"]
    canonical_labels = np.array([canonical_label(label) for label in labels])

    rule_specs = [
        (
            "majority",
            "Majority class",
            "Always predict BENIGN. This is the trivial reference for class imbalance.",
            np.zeros(len(y_true), dtype=np.float32),
        ),
        (
            "port_memorisation",
            "Port memorisation (21/22)",
            "Flag a flow when its destination port is one of the attack ports seen in the training partition (FTP 21, SSH 22). Uses no test labels.",
            np.isin(ports, sorted(TRAINING_ATTACK_PORTS)).astype(np.float32),
        ),
        (
            "ephemeral_destination",
            "Ephemeral destination heuristic",
            "Flag a flow when its destination port is above 1023. This is a crude anomaly heuristic: server-side attacks are expected to target well-known service ports.",
            (ports > 1023).astype(np.float32),
        ),
    ]
    rules = [
        evaluate_rule(name, description, y_true, scores, canonical_labels)
        for name, display, description, scores in rule_specs
    ]
    for rule, (_, display, _, _) in zip(rules, rule_specs):
        rule["display"] = display

    provenance = {
        "data": dataset_provenance(runs),
        "feature_schema_sha256": models[0]["feature_schema_sha256"],
        "protocol_sha256": sha256_file("docs/EVALUATION_PROTOCOL_V2.md"),
        "rows": models[0]["rows"],
    }

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "seeds": SEEDS,
        "split_rule": {
            "train": CIC_DAYS["Monday"] + CIC_DAYS["Tuesday"],
            "validation": CIC_DAYS["Wednesday"],
            "test": CIC_DAYS["Thursday"] + CIC_DAYS["Friday"],
        },
        "threshold_rule": "max validation attack recall subject to validation FPR <= 0.01; frozen before test",
        "family_recall_targets": FAMILY_RECALL_TARGETS,
        "cross_cutting_gates": CROSS_CUTTING,
        "provenance": provenance,
        "models": models,
        "rules": rules,
        "gates": gate_results(models, rules),
        "test_support": rules[0]["support"],
        "notes": [
            "Per-family precision is not available from the frozen binary artifacts.",
            "Seed variation on one fixed split is not independent replication.",
            "Rule baselines are evaluated once on the final-test partition; they have no seed variation.",
        ],
    }

    os.makedirs(args.output_dir, exist_ok=True)
    json_path = os.path.join(args.output_dir, "baseline_results_v2.json")
    md_path = os.path.join(args.output_dir, "BASELINE_RESULTS_V2.md")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    write_markdown(report, md_path)
    print(f"[baselines] wrote {json_path}")
    print(f"[baselines] wrote {md_path}")


if __name__ == "__main__":
    main()
