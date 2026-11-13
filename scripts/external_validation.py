#!/usr/bin/env python
"""Evaluate the frozen serving artifact on an external CSV.

This harness is deliberately strict about comparability:

- the feature schema is reported before scoring;
- missing features are not silently invented;
- the threshold is the frozen serving threshold, never retuned;
- the label mapping is reported and coarse by default;
- the output states whether the result is comparable to CIC-IDS-2017.

It does **not** download a dataset and it does not claim that a compatible
second dataset exists. See ``docs/EXTERNAL_VALIDATION.md``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import joblib  # noqa: E402
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score  # noqa: E402

from training.model_registry import resolve_serving_path  # noqa: E402

ENCODINGS = ("utf-8-sig", "cp1252", "latin1")
BENIGN_NAMES = {"benign", "normal", "background", "0"}


def normalize_label(value: object) -> str:
    text = str(value).strip()
    text = text.replace("\ufffd", "-").replace("�", "-")
    return " ".join(text.split())


def read_header(path: Path) -> pd.DataFrame:
    for encoding in ENCODINGS:
        try:
            return pd.read_csv(path, nrows=0, encoding=encoding)
        except UnicodeDecodeError:
            continue
    raise RuntimeError(f"Could not decode header for {path}")


def find_label_column(header: pd.DataFrame, requested: str) -> str:
    for column in header.columns:
        if str(column).strip().lower() == requested.strip().lower():
            return column
    raise KeyError(f"Label column {requested!r} not found; columns are {list(header.columns)[:20]}")


def binary_ece(truth: np.ndarray, probability: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    error = 0.0
    for index in range(bins):
        if index == bins - 1:
            mask = (probability >= edges[index]) & (probability <= edges[index + 1])
        else:
            mask = (probability >= edges[index]) & (probability < edges[index + 1])
        if np.any(mask):
            error += float(mask.mean()) * abs(float(truth[mask].mean()) - float(probability[mask].mean()))
    return float(error)


def wilson(successes: int, total: int, z: float = 1.96) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * np.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return [max(0.0, float(center - margin)), min(1.0, float(center + margin))]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--label-column", default="Label")
    parser.add_argument("--model-bundle", default=None, help="Defaults to the registry-active serving artifact.")
    parser.add_argument("--output", default="docs/external_validation_results.json")
    parser.add_argument("--max-rows", type=int, default=None)
    parser.add_argument("--chunksize", type=int, default=100_000)
    parser.add_argument(
        "--allow-missing-features",
        action="store_true",
        help="Score anyway and mark the result non-comparable. Missing values are left as NaN.",
    )
    args = parser.parse_args()

    dataset = Path(args.dataset)
    if not dataset.exists():
        raise SystemExit(f"Dataset not found: {dataset}")
    model_bundle = resolve_serving_path(explicit_path=args.model_bundle)
    bundle = joblib.load(model_bundle)
    expected_features = list(bundle["feature_names"])
    label_encoder = bundle["label_encoder"]
    threshold = float(bundle["attack_threshold"])

    header = read_header(dataset)
    clean_to_original = {str(column).strip(): column for column in header.columns}
    missing = [name for name in expected_features if name not in clean_to_original]
    extra = [str(column) for column in header.columns if str(column).strip() not in set(expected_features)]
    label_original = find_label_column(header, args.label_column)

    mapping = {
        "expected_feature_count": len(expected_features),
        "matched_feature_count": len(expected_features) - len(missing),
        "missing_features": missing,
        "extra_columns": extra,
        "label_column": str(label_original).strip(),
        "feature_schema": "cic-ids-2017-80f-45cd75ce849b",
        "model_bundle": model_bundle,
        "frozen_threshold": threshold,
        "threshold_retuned": False,
    }
    comparable = not missing
    if missing and not args.allow_missing_features:
        report = {
            "dataset": str(dataset),
            "status": "not_comparable",
            "reason": "missing required features; no score computed",
            "schema": mapping,
            "note": "Rerun with --allow-missing-features only to document a non-comparable stress result.",
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 2

    usecols = [clean_to_original[name] for name in expected_features if name in clean_to_original]
    usecols.append(label_original)
    rename = {clean_to_original[name]: name for name in expected_features if name in clean_to_original}
    rename[label_original] = "Label"

    scores: list[np.ndarray] = []
    truths: list[np.ndarray] = []
    families: list[np.ndarray] = []
    rows = 0
    last_error = None
    for encoding in ENCODINGS:
        try:
            reader = pd.read_csv(
                dataset,
                usecols=usecols,
                dtype={column: np.float32 for column in usecols if column != label_original},
                encoding=encoding,
                chunksize=args.chunksize,
                low_memory=False,
            )
            for chunk in reader:
                if args.max_rows is not None and rows >= args.max_rows:
                    break
                if args.max_rows is not None:
                    chunk = chunk.iloc[: args.max_rows - rows]
                chunk = chunk.rename(columns=rename)
                labels = chunk.pop("Label").map(normalize_label)
                for name in expected_features:
                    if name not in chunk.columns:
                        chunk[name] = np.nan
                X = chunk[expected_features].replace([np.inf, -np.inf], np.nan)
                probabilities = bundle["pipeline"].predict_proba(X)
                benign_column = list(label_encoder.classes_).index("BENIGN")
                attack_score = 1.0 - probabilities[:, benign_column]
                scores.append(np.asarray(attack_score, dtype=np.float32))
                truths.append((~labels.str.lower().isin(BENIGN_NAMES)).to_numpy(dtype=np.int8))
                families.append(labels.to_numpy(dtype=object))
                rows += len(chunk)
            break
        except UnicodeDecodeError as exc:
            last_error = exc
            continue
    if not scores:
        raise SystemExit(f"No rows scored: {last_error}")

    score = np.concatenate(scores)
    truth = np.concatenate(truths)
    family = np.concatenate(families)
    selected = score >= threshold
    benign = truth == 0
    attack = truth == 1
    tp = int(np.sum(selected & attack))
    fp = int(np.sum(selected & benign))
    fn = int(np.sum(~selected & attack))
    tn = int(np.sum(~selected & benign))
    per_family: dict[str, dict] = {}
    for name in sorted(set(family) - {item for item in family if item.lower() in BENIGN_NAMES}):
        mask = family == name
        support = int(mask.sum())
        detected = int(np.sum(selected & mask))
        per_family[name] = {
            "support": support,
            "detected": detected,
            "recall": detected / support if support else 0.0,
            "recall_wilson_95": wilson(detected, support),
        }
    metrics = {
        "rows": int(len(truth)),
        "benign_rows": int(benign.sum()),
        "attack_rows": int(attack.sum()),
        "attack_rate": float(attack.mean()),
        "frozen_threshold": threshold,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "alert_rate": float(selected.mean()),
        "alerts": int(selected.sum()),
        "pr_auc": float(average_precision_score(truth, score)) if len(set(truth)) == 2 else None,
        "roc_auc": float(roc_auc_score(truth, score)) if len(set(truth)) == 2 else None,
        "calibration_uncalibrated": {
            "brier": float(brier_score_loss(truth, np.clip(score, 0, 1))),
            "ece_10_bins": binary_ece(truth, np.clip(score, 0, 1)),
        },
        "per_family": per_family,
    }
    report = {
        "dataset": str(dataset),
        "status": "scored" if comparable else "scored_not_comparable",
        "schema": mapping,
        "comparability": {
            "comparable_to_cic_ids_2017": comparable,
            "reason": (
                "all expected feature names are present"
                if comparable
                else "one or more required feature names are missing; predictions are not comparable"
            ),
            "feature_mapping": "stripped column names matched exactly; case is not changed",
            "label_mapping": "BENIGN/Normal/background/0 -> benign; all other labels -> attack",
            "threshold_policy": "frozen serving threshold; not retuned on this dataset",
            "calibration": "serving artifact is uncalibrated; Brier/ECE are diagnostics, not calibrated probabilities",
        },
        "metrics": metrics,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if comparable else 2


if __name__ == "__main__":
    raise SystemExit(main())
