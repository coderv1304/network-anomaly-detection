#!/usr/bin/env python
"""Build the regenerable score cache for D9 cost-sensitive evaluation.

The cache stores frozen model scores on the day-based validation (Wednesday)
and test (Thursday + Friday) partitions, so cost and alert-budget analysis does
not need to reload the raw CSVs or rescore the model every time.

This script never trains, never retunes, and never reads test labels to choose
a threshold. It preserves the exact deduplicated partition and feature schema
used by ``training/threshold_calibration_v2.py``.

Examples:
    python scripts/build_score_cache.py --model lr --seeds 42
    python scripts/build_score_cache.py --model if --seeds 42,43,44,45,46
"""

from __future__ import annotations

import argparse
import os
import sys

import joblib
import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
# The legacy Isolation Forest bundle was pickled with a top-level module name.
TRAINING_DIR = os.path.join(PROJECT_ROOT, "training")
if TRAINING_DIR not in sys.path:
    sys.path.insert(0, TRAINING_DIR)

from training.evaluate import CIC_DAYS  # noqa: E402
from training.threshold_calibration_v2 import (  # noqa: E402
    CACHE_DIR,
    _load_partition,
    _score_bundle,
)

PARTITIONS = {
    "validation": {"Wednesday": CIC_DAYS["Wednesday"]},
    "test": {"Thursday": CIC_DAYS["Thursday"], "Friday": CIC_DAYS["Friday"]},
}
DAY_ORDER = {"validation": ["Wednesday"], "test": ["Thursday", "Friday"]}


def score(model: str, bundle: dict, frame):
    pipeline = bundle["pipeline"]
    feature_names = list(bundle["feature_names"])
    features = frame.reindex(columns=feature_names)

    if model in {"lr", "rf"}:
        scored = _score_bundle(bundle, features)
        return scored["attack_score"], scored["classes"]
    if model == "if":
        steps = pipeline.named_steps
        preprocessor = steps["preprocessor"]
        classifier = steps["classifier"]
        # IsolationForest.decision_function is lower for anomalies; negate it
        # so higher always means "more attack-like", matching the other models.
        scores = -classifier.decision_function(preprocessor.transform(features))
        return scores.astype(np.float32), np.asarray(["BENIGN", "ANOMALY"])
    raise ValueError(f"unsupported model: {model}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", choices=["lr", "rf", "if"], required=True)
    parser.add_argument("--seeds", default="42")
    args = parser.parse_args()

    seeds = [int(value) for value in args.seeds.split(",") if value.strip()]
    frames = {
        partition: _load_partition(files) for partition, files in PARTITIONS.items()
    }

    families = sorted(set(frames["validation"]["__label"]) | set(frames["test"]["__label"]))
    if "BENIGN" in families:
        families.remove("BENIGN")
        families.insert(0, "BENIGN")

    os.makedirs(CACHE_DIR, exist_ok=True)
    for seed in seeds:
        bundle_path = os.path.join("models", f"model_bundle_{args.model}_day_based_seed{seed}.pkl")
        bundle = joblib.load(bundle_path)
        for partition, frame in frames.items():
            attack_score, classes = score(args.model, bundle, frame)
            day_labels = DAY_ORDER[partition]
            family_codes = np.asarray(
                [families.index(value) for value in frame["__label"]], dtype=np.int16
            )
            day_codes = np.asarray(
                [day_labels.index(value) for value in frame["__day"]], dtype=np.int8
            )
            output = os.path.join(CACHE_DIR, f"{args.model}_seed{seed}_{partition}.npz")
            np.savez_compressed(
                output,
                attack_score=attack_score,
                argmax_index=np.zeros(len(frame), dtype=np.int8),
                binary_truth=(frame["__label"].to_numpy() != "BENIGN").astype(np.int8),
                family_codes=family_codes,
                day_codes=day_codes,
                families=np.asarray(families),
                days=np.asarray(day_labels),
                classes=classes,
            )
            print(f"wrote {output}: {len(frame):,} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
