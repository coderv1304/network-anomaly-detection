"""Export the sensor's flow classifier to ONNX with a pure-Go fallback.

The Go sensor consumes a frozen 24-feature vector (``capture/internal/flow``)
whose values are derived from a bidirectional five-tuple. This script trains
the same classifier family on the held-out CIC-style fixture, exports it to
``models/netshield_flow.onnx``, and records enough metadata for the sensor's
non-CGo build to keep scoring:

* ``models/netshield_flow_manifest.json`` pins the ONNX SHA-256, the feature
  order, the calibrated threshold, and a logistic fallback expressed in the
  sensor's raw feature space. The Go sensor validates the SHA-256 before it
  swaps a live model.
* ``models/netshield_flow_parity.json`` stores 1,000 deterministic feature rows
  with the reference probabilities so ``tests/test_export_onnx.py`` can assert
  ONNX/sklearn parity without re-training.

Run from the repository root:

    python training/export_onnx.py

The script is deterministic: the split, model seeds, parity sample, and output
ordering all use ``SEED``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_FIXTURE = os.path.join(
    PROJECT_ROOT, "tests", "fixtures", "sample_flows_500.csv"
)
DEFAULT_MODEL = os.path.join(PROJECT_ROOT, "models", "netshield_flow.onnx")
DEFAULT_MANIFEST = os.path.join(
    PROJECT_ROOT, "models", "netshield_flow_manifest.json"
)
DEFAULT_PARITY = os.path.join(PROJECT_ROOT, "models", "netshield_flow_parity.json")

SEED = 42
PARITY_ROWS = 1000
PARITY_TOLERANCE = 1e-5
RATIO_EPSILON = 1e-6

# This order is part of the Go sensor's wire contract. Changing it requires a
# matching change in capture/internal/flow/features.go and a new manifest.
FEATURE_NAMES = (
    "duration_sec",
    "fwd_pkts",
    "bwd_pkts",
    "fwd_bytes",
    "bwd_bytes",
    "fwd_hdr_bytes",
    "bwd_hdr_bytes",
    "pkt_len_mean",
    "pkt_len_std",
    "iat_mean",
    "iat_std",
    "fin_cnt",
    "syn_cnt",
    "rst_cnt",
    "psh_cnt",
    "ack_cnt",
    "bytes_per_sec",
    "pkts_per_sec",
    "fwd_bwd_pkt_ratio",
    "fwd_bwd_byte_ratio",
    "syn_ack_ratio",
    "fin_rst_ratio",
    "mean_pkt_size",
    "iat_cv",
)


def _numeric(frame: pd.DataFrame, column: str) -> np.ndarray:
    if column not in frame.columns:
        raise KeyError(f"fixture is missing required column {column!r}")
    return pd.to_numeric(frame[column], errors="coerce").fillna(0.0).to_numpy(
        dtype=np.float64
    )


def derive_features(frame: pd.DataFrame) -> np.ndarray:
    """Derive the Go sensor's 24 features from CIC-style fixture columns.

    The arithmetic mirrors ``flow.Snapshot.FeatureValues`` exactly, including
    the epsilon floors and the ``max(denominator, 1)`` guards, so a model
    trained here sees the same scale the sensor emits at inference time.
    """

    duration_us = np.maximum(_numeric(frame, "Flow Duration"), 0.0)
    duration_sec = np.maximum(duration_us / 1e6, RATIO_EPSILON)

    fwd_pkts = np.maximum(_numeric(frame, "Total Fwd Packets"), 0.0)
    bwd_pkts = np.maximum(_numeric(frame, "Total Backward Packets"), 0.0)
    fwd_bytes = np.maximum(_numeric(frame, "Total Length of Fwd Packets"), 0.0)
    bwd_bytes = np.maximum(_numeric(frame, "Total Length of Bwd Packets"), 0.0)
    fwd_hdr = np.maximum(_numeric(frame, "Fwd Header Length"), 0.0)
    bwd_hdr = np.maximum(_numeric(frame, "Bwd Header Length"), 0.0)

    pkt_len_mean = _numeric(frame, "Packet Length Mean")
    pkt_len_std = _numeric(frame, "Packet Length Std")
    iat_mean = _numeric(frame, "Flow IAT Mean")
    iat_std = _numeric(frame, "Flow IAT Std")

    fin = _numeric(frame, "FIN Flag Count")
    syn = _numeric(frame, "SYN Flag Count")
    rst = _numeric(frame, "RST Flag Count")
    psh = _numeric(frame, "PSH Flag Count")
    ack = _numeric(frame, "ACK Flag Count")

    total_pkts = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes
    packet_floor = np.maximum(total_pkts, 1.0)
    bwd_pkt_floor = np.maximum(bwd_pkts, 1.0)
    bwd_byte_floor = np.maximum(bwd_bytes, 1.0)
    ack_floor = np.maximum(ack, 1.0)

    values = np.column_stack(
        [
            duration_sec,  # duration_sec
            fwd_pkts,  # fwd_pkts
            bwd_pkts,  # bwd_pkts
            fwd_bytes,  # fwd_bytes
            bwd_bytes,  # bwd_bytes
            fwd_hdr,  # fwd_hdr_bytes
            bwd_hdr,  # bwd_hdr_bytes
            pkt_len_mean,  # pkt_len_mean
            pkt_len_std,  # pkt_len_std
            iat_mean,  # iat_mean
            iat_std,  # iat_std
            fin,  # fin_cnt
            syn,  # syn_cnt
            rst,  # rst_cnt
            psh,  # psh_cnt
            ack,  # ack_cnt
            total_bytes / duration_sec,  # bytes_per_sec
            total_pkts / duration_sec,  # pkts_per_sec
            fwd_pkts / bwd_pkt_floor,  # fwd_bwd_pkt_ratio
            fwd_bytes / bwd_byte_floor,  # fwd_bwd_byte_ratio
            syn / ack_floor,  # syn_ack_ratio
            (fin + rst) / packet_floor,  # fin_rst_ratio
            total_bytes / packet_floor,  # mean_pkt_size
            iat_std / np.maximum(iat_mean, RATIO_EPSILON),  # iat_cv
        ]
    )
    # The sensor never emits NaN or Infinity. Mirror that guarantee here so the
    # training matrix and ONNX inputs stay identical.
    values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)
    return np.ascontiguousarray(values, dtype=np.float32)


def build_labels(frame: pd.DataFrame) -> np.ndarray:
    labels = frame["Label"].astype(str).str.strip().str.upper()
    return (labels != "BENIGN").astype(np.int64).to_numpy()


def calibrate_threshold(probabilities: np.ndarray, labels: np.ndarray) -> float:
    """Pick the validation threshold with the best F1, then highest recall."""

    candidates = np.unique(np.round(probabilities, 6))
    best_threshold = 0.5
    best_key = (-1.0, -1.0, -1.0)
    for threshold in candidates:
        predictions = (probabilities >= threshold).astype(np.int64)
        f1 = f1_score(labels, predictions, zero_division=0)
        recall = recall_score(labels, predictions, zero_division=0)
        precision = precision_score(labels, predictions, zero_division=0)
        key = (float(f1), float(recall), float(precision))
        if key > best_key:
            best_key = key
            best_threshold = float(threshold)
    return round(min(max(best_threshold, 0.01), 0.99), 6)


def raw_logistic_coefficients(pipeline) -> tuple[list[float], float]:
    """Express a standardized logistic model in the sensor's raw space.

    Go's fallback scorer only multiplies raw features by weights and adds a
    bias. If ``z = (x - mean) / scale`` and ``logit = w_z * z + b_z``, then the
    equivalent raw-space coefficients are ``w = w_z / scale`` and
    ``b = b_z - sum(w_z * mean / scale)``.
    """

    scaler = pipeline.named_steps["standardscaler"]
    model = pipeline.named_steps["logisticregression"]
    coefficient = np.asarray(model.coef_, dtype=np.float64).reshape(-1)
    intercept = float(np.asarray(model.intercept_, dtype=np.float64).reshape(-1)[0])
    mean = np.asarray(scaler.mean_, dtype=np.float64)
    scale = np.asarray(scaler.scale_, dtype=np.float64)
    scale = np.where(np.abs(scale) < 1e-12, 1.0, scale)
    weights = coefficient / scale
    bias = intercept - float(np.sum(coefficient * mean / scale))
    return [float(value) for value in weights], float(bias)


def export_onnx(model, sample: np.ndarray):
    """Convert an HGB classifier to ONNX with probabilities and a label output.

    skl2onnx 1.17 writes ``nodes_missing_value_tracks_true`` as Python/numpy
    booleans, which ONNX 1.16 rejects because the attribute is an int list.
    The wrapper normalizes that one attribute and leaves every other converter
    path untouched.
    """

    import skl2onnx.common.tree_ensemble as tree_ensemble
    from skl2onnx import to_onnx

    original_add_node = tree_ensemble.add_node

    def add_node_with_int_missing_flag(*args, **kwargs):
        if "nodes_missing_value_tracks_true" in kwargs:
            kwargs["nodes_missing_value_tracks_true"] = int(
                bool(kwargs["nodes_missing_value_tracks_true"])
            )
        return original_add_node(*args, **kwargs)

    tree_ensemble.add_node = add_node_with_int_missing_flag
    try:
        return to_onnx(
            model,
            sample,
            options={id(model): {"zipmap": False}},
        )
    finally:
        tree_ensemble.add_node = original_add_node


def validate_onnx(onnx_model, sample: np.ndarray, expected: np.ndarray) -> list[dict]:
    import onnxruntime as ort

    serialized = onnx_model.SerializeToString()
    session = ort.InferenceSession(
        serialized, providers=["CPUExecutionProvider"]
    )
    input_name = session.get_inputs()[0].name
    output_names = [output.name for output in session.get_outputs()]
    if "probabilities" not in output_names:
        raise AssertionError(
            f"ONNX graph must expose a 'probabilities' output, got {output_names}"
        )
    raw = session.run(
        ["probabilities"], {input_name: sample}
    )[0]
    probabilities = np.asarray(raw, dtype=np.float64)[:, 1]
    expected = np.asarray(expected, dtype=np.float64)
    differences = np.abs(probabilities - expected)
    maximum = float(np.max(differences))
    if not math.isfinite(maximum) or maximum >= PARITY_TOLERANCE:
        index = int(np.argmax(differences))
        raise AssertionError(
            "ONNX/sklearn parity failed: "
            f"max|delta|={maximum:.3e} at row {index} "
            f"(onnx={probabilities[index]!r}, sklearn={expected[index]!r})"
        )
    return [
        {
            "features": [round(float(value), 6) for value in row],
            "onnx_probability": round(float(onnx_probability), 8),
            "sklearn_probability": round(float(expected_probability), 8),
        }
        for row, onnx_probability, expected_probability in zip(
            sample, probabilities, expected
        )
    ]


def write_json(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", default=DEFAULT_FIXTURE)
    parser.add_argument("--model-out", default=DEFAULT_MODEL)
    parser.add_argument("--manifest-out", default=DEFAULT_MANIFEST)
    parser.add_argument("--parity-out", default=DEFAULT_PARITY)
    parser.add_argument("--parity-rows", type=int, default=PARITY_ROWS)
    args = parser.parse_args()

    frame = pd.read_csv(args.fixture)
    features = derive_features(frame)
    labels = build_labels(frame)
    if features.shape[0] != labels.shape[0]:
        raise AssertionError("feature and label row counts diverged")
    if features.shape[1] != len(FEATURE_NAMES):
        raise AssertionError(
            f"expected {len(FEATURE_NAMES)} features, got {features.shape[1]}"
        )

    x_train, x_valid, y_train, y_valid = train_test_split(
        features,
        labels,
        test_size=0.3,
        random_state=SEED,
        stratify=labels,
    )

    classifier = HistGradientBoostingClassifier(
        max_iter=250,
        learning_rate=0.08,
        max_depth=3,
        l2_regularization=0.1,
        min_samples_leaf=5,
        early_stopping=False,
        random_state=SEED,
    )
    classifier.fit(x_train, y_train)
    valid_probabilities = classifier.predict_proba(x_valid)[:, 1]
    threshold = calibrate_threshold(valid_probabilities, y_valid)

    predictions = (valid_probabilities >= threshold).astype(np.int64)
    metrics = {
        "rows_train": int(x_train.shape[0]),
        "rows_validation": int(x_valid.shape[0]),
        "accuracy": round(float(accuracy_score(y_valid, predictions)), 6),
        "precision": round(float(precision_score(y_valid, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(y_valid, predictions, zero_division=0)), 6),
        "f1": round(float(f1_score(y_valid, predictions, zero_division=0)), 6),
        "roc_auc": round(float(roc_auc_score(y_valid, valid_probabilities)), 6),
        "threshold": threshold,
    }

    onnx_model = export_onnx(classifier, x_train[:1])
    serialized = onnx_model.SerializeToString()
    model_sha256 = hashlib.sha256(serialized).hexdigest()

    # Parity uses 1,000 deterministic draws from the full fixture, so the check
    # covers every attack family and not only the validation split.
    rng = np.random.default_rng(SEED)
    parity_indices = rng.integers(0, features.shape[0], size=args.parity_rows)
    parity_features = np.ascontiguousarray(features[parity_indices], dtype=np.float32)
    parity_expected = classifier.predict_proba(parity_features)[:, 1]
    parity_rows = validate_onnx(onnx_model, parity_features, parity_expected)

    fallback = make_pipeline(
        StandardScaler(),
        LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=SEED,
        ),
    )
    fallback.fit(x_train, y_train)
    weights, bias = raw_logistic_coefficients(fallback)
    fallback_probabilities = fallback.predict_proba(x_valid)[:, 1]
    fallback_metrics = {
        "precision": round(float(precision_score(y_valid, fallback_probabilities >= threshold, zero_division=0)), 6),
        "recall": round(float(recall_score(y_valid, fallback_probabilities >= threshold, zero_division=0)), 6),
        "roc_auc": round(float(roc_auc_score(y_valid, fallback_probabilities)), 6),
    }

    os.makedirs(os.path.dirname(args.model_out), exist_ok=True)
    with open(args.model_out, "wb") as handle:
        handle.write(serialized)

    manifest = {
        "model_id": "netshield-flow-hgb",
        "model_version": "hgb-portable-v1-seed42",
        "created_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "feature_names": list(FEATURE_NAMES),
        "classes": ["BENIGN", "ATTACK"],
        "threshold": threshold,
        "calibration_method": "validation_f1_sweep",
        "sha256": model_sha256,
        "onnx_input": "X",
        "onnx_output": "probabilities",
        "fallback": {
            "type": "logistic",
            "weights": weights,
            "bias": bias,
            "activation": "sigmoid",
        },
        "validation_metrics": {
            "onnx": metrics,
            "fallback": fallback_metrics,
            "parity_rows": len(parity_rows),
            "parity_max_abs_delta": max(
                abs(row["onnx_probability"] - row["sklearn_probability"])
                for row in parity_rows
            ),
        },
    }
    write_json(args.manifest_out, manifest)

    parity = {
        "feature_names": list(FEATURE_NAMES),
        "onnx_sha256": model_sha256,
        "threshold": threshold,
        "tolerance": PARITY_TOLERANCE,
        "rows": parity_rows,
    }
    write_json(args.parity_out, parity)

    print(
        "exported "
        f"{args.model_out} sha256={model_sha256} "
        f"threshold={threshold:.6f} "
        f"f1={metrics['f1']:.4f} auc={metrics['roc_auc']:.4f}"
    )
    print(
        "parity rows="
        f"{len(parity_rows)} max|delta|={manifest['validation_metrics']['parity_max_abs_delta']:.3e}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
