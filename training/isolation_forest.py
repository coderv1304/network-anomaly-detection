# training/isolation_forest.py
"""
IsolationForest baseline that follows the frozen evaluation protocol and
day-based split logic from `train_pipeline.py`.

Usage:
    python training/isolation_forest.py \
        --data-dir data \
        --output-dir models \
        --seed 42
"""

import sys
import os

# Ensure both repo root and training directory are in sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
TRAINING_DIR = os.path.abspath(os.path.dirname(__file__))
if TRAINING_DIR not in sys.path:
    sys.path.insert(0, TRAINING_DIR)

import argparse
import json
import time
import hashlib
import platform
import sklearn
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import precision_recall_curve, auc, roc_auc_score
from sklearn.pipeline import Pipeline

from preprocessor import IDENTIFIER_COLUMNS, FlowSanitizer
from evaluate import select_threshold_at_max_fpr, evaluate_binary_threshold, evaluate_alert_budgets
from train_pipeline import load_split_data


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_isolation_forest(data_dir: str, output_dir: str, seed: int):
    print(f"\nStarting IsolationForest training (seed={seed}, split=day_based)")
    
    # Load splits matching train_pipeline exactly:
    # Monday-Tuesday (train), Wednesday (validation), Thursday-Friday (test)
    train_df, test_df, val_df = load_split_data(
        data_dir, split_mode="day_based", seed=seed, include_validation=True
    )
    print(f"Train samples: {len(train_df):,} | Validation samples: {len(val_df):,} | Test samples: {len(test_df):,}")

    train_labels = train_df["Label"].astype(str)
    val_labels = val_df["Label"].astype(str)
    test_labels = test_df["Label"].astype(str)

    y_val_bin = (val_labels != "BENIGN").astype(int).to_numpy()
    y_test_bin = (test_labels != "BENIGN").astype(int).to_numpy()

    # Features = all columns except non-feature identifiers and label
    feature_cols = [c for c in train_df.columns if c not in IDENTIFIER_COLUMNS]
    X_train = train_df[feature_cols]
    X_val = val_df.reindex(columns=feature_cols)
    X_test = test_df.reindex(columns=feature_cols)

    # Build leak-free preprocessing pipeline:
    # FlowSanitizer strips identifiers, normalizes column names, converts Inf/-Inf to NaN
    # SimpleImputer fits median strictly on training split
    preprocessor = Pipeline([
        ("sanitizer", FlowSanitizer(expected_features=feature_cols)),
        ("imputer", SimpleImputer(strategy="median")),
    ])

    print("Fitting leak-free preprocessor strictly on training split...")
    X_train_proc = preprocessor.fit_transform(X_train)
    X_val_proc = preprocessor.transform(X_val)
    X_test_proc = preprocessor.transform(X_test)

    # Configure IsolationForest
    model = IsolationForest(
        n_estimators=100,
        max_samples="auto",
        contamination="auto",
        random_state=seed,
        n_jobs=-1,
    )

    print("Fitting IsolationForest on training split...")
    start = time.perf_counter()
    model.fit(X_train_proc)
    fit_seconds = time.perf_counter() - start

    # Anomaly score: higher means more anomalous (more likely an attack)
    # decision_function returns negative values for anomalies, positive for normal
    print("Evaluating scores on validation and test splits...")
    val_scores = -model.decision_function(X_val_proc)
    test_scores = -model.decision_function(X_test_proc)

    # ---- Threshold selection (validation split only) ----
    max_fpr = 0.01
    thresh_info = select_threshold_at_max_fpr(
        y_val_bin, val_scores, max_fpr=max_fpr
    )
    if thresh_info is None:
        benign_val_scores = val_scores[y_val_bin == 0]
        fallback_threshold = float(np.percentile(benign_val_scores, 99)) if len(benign_val_scores) > 0 else 0.0
        thresh_info = {
            "threshold": fallback_threshold,
            "max_fpr": float(max_fpr),
            "validation_fpr": 0.01,
            "validation_tpr": float(np.mean(val_scores[y_val_bin == 1] >= fallback_threshold)) if (y_val_bin == 1).any() else 0.0,
        }

    selected_threshold = thresh_info["threshold"]

    # ---- Evaluation on test split ----
    binary_metrics = evaluate_binary_threshold(
        y_test_bin, test_scores, selected_threshold
    )

    pr_curve_precision, pr_curve_recall, _ = precision_recall_curve(y_test_bin, test_scores)
    pr_auc = float(auc(pr_curve_recall, pr_curve_precision))
    roc_auc = float(roc_auc_score(y_test_bin, test_scores))

    # Per-family detection metrics
    unseen_test_labels = sorted(set(test_labels) - set(train_labels))
    attack_family_detection = {
        str(family): {
            "support": int((test_labels == family).sum()),
            "detected": int(((test_labels == family).to_numpy() & (test_scores >= selected_threshold)).sum()),
            "recall": float(((test_labels == family).to_numpy() & (test_scores >= selected_threshold)).sum() / max(1, (test_labels == family).sum())),
            "seen_in_training": bool(family in set(train_labels)),
        }
        for family in sorted(set(test_labels) - {"BENIGN"})
    }

    # Combined full inference pipeline for saving
    full_pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", model),
    ])

    # ---- Save artifacts ----
    os.makedirs(output_dir, exist_ok=True)
    
    # Save versioned pipeline
    pipeline_filename = f"pipeline_if_day_based_seed{seed}.pkl"
    pipeline_path = os.path.join(output_dir, pipeline_filename)
    joblib.dump(full_pipeline, pipeline_path)

    # Save model bundle
    bundle_filename = f"model_bundle_if_day_based_seed{seed}.pkl"
    bundle_path = os.path.join(output_dir, bundle_filename)
    model_bundle = {
        "pipeline": full_pipeline,
        "feature_names": feature_cols,
        "threshold": selected_threshold,
        "task": "binary_attack",
    }
    joblib.dump(model_bundle, bundle_path)

    # Phase 4: Alert-budget evaluation
    alert_budgets = evaluate_alert_budgets(
        y_true_binary=y_test_bin,
        scores=test_scores,
        y_true_families=test_labels.to_numpy(),
        budgets_per_10k=[10, 50, 100],
        fixed_counts=[50, 100, 250, 500, 1000],
    )

    # Metrics dictionary
    metrics = {
        "model_type": "if",
        "task": "binary_attack",
        "seed": seed,
        "split_mode": "day_based",
        "threshold_selection": thresh_info,
        "binary_metrics": binary_metrics,
        "alert_budget_evaluation": alert_budgets,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "operating_threshold": {
            **thresh_info,
            "test": binary_metrics,
            "selected_on": "validation partition only",
        },
        "attack_family_detection": attack_family_detection,
        "fit_seconds": fit_seconds,
        "feature_count": len(feature_cols),
        "train_rows": len(train_df),
        "validation_rows": len(val_df),
        "test_rows": len(test_df),
        "unseen_test_labels": unseen_test_labels,
    }

    metrics_filename = f"metrics_if_day_based_seed{seed}.json"
    metrics_path = os.path.join(output_dir, metrics_filename)
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    # Model manifest
    source_files = sorted(set(train_df.attrs.get("source_files", [])) | 
                          set(val_df.attrs.get("source_files", [])) | 
                          set(test_df.attrs.get("source_files", [])))
    dataset_hashes = {os.path.basename(p): compute_sha256(p) for p in source_files if os.path.isfile(p)}

    manifest = {
        "model_type": "if",
        "task": "binary_attack",
        "split_mode": "day_based",
        "seed": seed,
        "model_file": bundle_filename,
        "model_sha256": compute_sha256(bundle_path),
        "dataset_sha256": dataset_hashes,
        "feature_count": len(feature_cols),
        "features": feature_cols,
        "trained_classes": ["BENIGN", "ANOMALY"],
        "unseen_test_labels": unseen_test_labels,
        "metrics_file": metrics_filename,
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
    }

    manifest_filename = f"model_manifest_if_day_based_seed{seed}.json"
    manifest_path = os.path.join(output_dir, manifest_filename)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n=== IsolationForest Run Summary ===")
    print(f"Seed                : {seed}")
    print(f"Fit time (s)        : {fit_seconds:.2f}")
    print(f"Test PR-AUC         : {pr_auc:.4f}")
    print(f"Test ROC-AUC        : {roc_auc:.4f}")
    print(f"Frozen Threshold    : {selected_threshold:.6f}")
    if binary_metrics:
        print(f"Test Recall @ 1% FPR: {binary_metrics['recall']:.4f}")
        print(f"Test Alert Rate     : {binary_metrics['alert_rate']:.4f}")
    print(f"Saved pipeline      : {pipeline_path}")
    print(f"Saved manifest      : {manifest_path}")
    print(f"Saved metrics       : {metrics_path}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IsolationForest baseline following the frozen evaluation protocol."
    )
    parser.add_argument(
        "--data-dir",
        default="data",
        help="Root folder containing the raw CSV files (default: data)",
    )
    parser.add_argument(
        "--output-dir",
        default="models",
        help="Directory where model bundle and metrics JSON will be stored",
    )
    parser.add_argument(
        "--seed",
        type=int,
        required=True,
        help="Random seed",
    )
    args = parser.parse_args()
    run_isolation_forest(args.data_dir, args.output_dir, args.seed)
