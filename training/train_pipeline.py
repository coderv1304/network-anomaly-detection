"""
training/train_pipeline.py

Leak-Free, Day-Based / Temporal Training Pipeline for CIC-IDS-2017.

Features:
1. Uses sklearn.pipeline.Pipeline with SimpleImputer + StandardScaler + Model.
2. Strictly fits transformations on X_train only.
3. Supports Day-based splits (e.g. Train on Mon-Wed, Test on Thu-Fri) or chronological splits.
4. Evaluates with Macro-F1, per-class PR-AUC, FPR @ 95% TPR, and confusion matrices.
5. Saves unified pipeline (models/pipeline.pkl) and exports legacy components for app.py compatibility.
"""

import argparse
import hashlib
import glob
import json
import os
import platform
import sys
import time

import joblib
import pandas as pd
import sklearn

# Ensure project root is in sys.path when executed directly as python training/train_pipeline.py
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402
from sklearn.preprocessing import LabelEncoder  # noqa: E402

try:
    from training.evaluate import (
        CIC_DAYS,
        evaluate_alert_budgets,
        evaluate_binary_threshold,
        evaluate_predictions,
        format_evaluation_summary,
        select_threshold_at_max_fpr,
    )
    from training.preprocessor import IDENTIFIER_COLUMNS, build_leak_free_pipeline
except ImportError:
    from evaluate import (
        CIC_DAYS,
        evaluate_alert_budgets,
        evaluate_binary_threshold,
        evaluate_predictions,
        format_evaluation_summary,
        select_threshold_at_max_fpr,
    )
    from preprocessor import IDENTIFIER_COLUMNS, build_leak_free_pipeline

DEFAULT_DATA_DIR = "data"
DEFAULT_OUTPUT_DIR = "models"
ENCODINGS = ["utf-8-sig", "cp1252", "latin1"]

def load_split_data(data_dir: str, split_mode: str = "random", test_size: float = 0.2, seed: int = 42,
                    include_validation: bool = False):
    """
    Load CIC-IDS-2017 datasets according to the requested split strategy.
    split_mode:
        - 'random': stratified random split (with leakage warning)
        - 'day_based': Train Monday-Tuesday, validate Wednesday, test Thursday-Friday
    """
    if split_mode == "day_based":
        print("Executing temporal split: train=Monday-Tuesday, validation=Wednesday, test=Thursday-Friday")
        train_files = CIC_DAYS["Monday"] + CIC_DAYS["Tuesday"]
        validation_files = CIC_DAYS["Wednesday"]
        test_files = CIC_DAYS["Thursday"] + CIC_DAYS["Friday"]

        missing_files = [name for name in train_files + validation_files + test_files if not os.path.isfile(os.path.join(data_dir, name))]
        if missing_files:
            raise FileNotFoundError(
                "Day-based evaluation requires every configured day file; missing: "
                + ", ".join(missing_files)
            )

        df_train = _load_files(train_files, data_dir)
        df_validation = _load_files(validation_files, data_dir)
        df_test = _load_files(test_files, data_dir)
        return (df_train, df_test, df_validation) if include_validation else (pd.concat([df_train, df_validation], ignore_index=True), df_test)
    else:
        # Load available CSVs in data_dir (or data/samples if fallback)
        csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
        if not csv_files:
            fallback = os.path.join("data", "samples", "*.csv")
            csv_files = glob.glob(fallback)
            print(f"Loading from samples fallback: {fallback}")

        df_list = []
        for f in csv_files:
            d = _read_csv_safe(f)
            if d is not None and not d.empty and "Label" in d.columns:
                print(f"Loaded {os.path.basename(f)}: {len(d):,} rows")
                df_list.append(d)

        if not df_list:
            raise FileNotFoundError(f"No CSV datasets found in {data_dir} or data/samples/")

        full_df = pd.concat(df_list, ignore_index=True)
        full_df.attrs["source_files"] = csv_files
        initial_count = len(full_df)
        full_df.drop_duplicates(inplace=True)
        full_df.dropna(subset=["Label"], inplace=True)
        print(f"Total dataset after deduplication: {len(full_df):,} rows (removed {initial_count - len(full_df):,} duplicates/nulls)")

        class_counts = full_df["Label"].value_counts()
        can_stratify = (class_counts.min() >= 2)
        stratify_target = full_df["Label"] if can_stratify else None

        train_df, test_df = train_test_split(
            full_df, test_size=test_size, random_state=seed, stratify=stratify_target
        )
        return (train_df, test_df, None) if include_validation else (train_df, test_df)

def _read_csv_safe(filepath: str) -> pd.DataFrame | None:
    if not os.path.exists(filepath):
        return None
    for enc in ENCODINGS:
        try:
            df = pd.read_csv(filepath, encoding=enc, low_memory=False)
            df.columns = df.columns.str.strip()
            return df
        except UnicodeDecodeError:
            # CIC-IDS-2017 source exports can be Windows-1252. Encoding
            # fallback is expected; do not print a scary error for it.
            continue
        except Exception as e:  # noqa: BLE001
            print(f"CSV read error: {e}")
            continue
    return None

def _load_files(file_list: list, data_dir: str) -> pd.DataFrame:
    frames = []
    loaded_paths = []
    for fname in file_list:
        path = os.path.join(data_dir, fname)
        df = _read_csv_safe(path)
        if df is not None:
            df.columns = df.columns.str.strip()
            frames.append(df)
            loaded_paths.append(path)
        else:
            print(f"Warning: {fname} not found in {data_dir}; skipping.")

    if not frames:
        raise FileNotFoundError(f"None of {file_list} found in {data_dir}")
    combined = pd.concat(frames, ignore_index=True)
    combined.drop_duplicates(inplace=True)
    combined.dropna(subset=["Label"], inplace=True)
    combined.attrs["source_files"] = loaded_paths
    return combined

def run_training(
    data_dir: str = DEFAULT_DATA_DIR,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    split_mode: str = "random",
    model_type: str = "rf",
    n_estimators: int = 100,
    seed: int = 42,
    max_fpr: float = 0.01,
    class_weight: str | None = None,
    task: str = "multiclass",
):
    if task not in {"multiclass", "binary_attack"}:
        raise ValueError("task must be 'multiclass' or 'binary_attack'")
    if not 0 <= max_fpr <= 1:
        raise ValueError("max_fpr must be between zero and one")
    if model_type == "lr" and class_weight == "balanced_subsample":
        raise ValueError("LogisticRegression supports class_weight='balanced', not 'balanced_subsample'")
    os.makedirs(output_dir, exist_ok=True)
    print(f"\nStarting training pipeline (model={model_type.upper()}, split={split_mode})")

    train_df, test_df, validation_df = load_split_data(
        data_dir, split_mode=split_mode, seed=seed, include_validation=True
    )
    if validation_df is None:
        stratify_target = train_df["Label"] if train_df["Label"].value_counts().min() >= 2 else None
        train_df, validation_df = train_test_split(
            train_df, test_size=0.2, random_state=seed + 10_000, stratify=stratify_target
        )
        test_df.attrs["source_files"] = test_df.attrs.get("source_files", [])
    print(f"Train samples: {len(train_df):,} | Validation samples: {len(validation_df):,} | Test samples: {len(test_df):,}")

    # Fit the label vocabulary on training labels only. Test-only classes must
    # remain unseen and be reported as such, never included in model metadata.
    label_encoder = LabelEncoder()
    train_labels = train_df["Label"].astype(str)
    test_labels = test_df["Label"].astype(str)
    validation_labels = validation_df["Label"].astype(str)
    train_targets = train_labels if task == "multiclass" else train_labels.where(train_labels == "BENIGN", "ATTACK")
    test_targets = test_labels if task == "multiclass" else test_labels.where(test_labels == "BENIGN", "ATTACK")
    label_encoder.fit(train_targets)
    y_train = label_encoder.transform(train_targets)
    unseen_validation_labels = sorted(set(validation_labels) - set(train_labels))

    feature_cols = [c for c in train_df.columns if c not in IDENTIFIER_COLUMNS]
    X_train = train_df[feature_cols]
    X_test = test_df.reindex(columns=feature_cols)

    # Select base estimator
    if model_type == "rf":
        base_estimator = RandomForestClassifier(
            n_estimators=n_estimators, random_state=seed, n_jobs=-1,
            class_weight=class_weight,
        )
    elif model_type == "lr":
        base_estimator = LogisticRegression(max_iter=1000, random_state=seed, class_weight=class_weight)
    else:
        raise ValueError(f"Unknown model_type: {model_type}")

    # Build leak-free pipeline
    pipeline = build_leak_free_pipeline(
        classifier=base_estimator,
        expected_features=feature_cols
    )

    print("Fitting pipeline (Imputer -> Scaler -> Classifier) STRICTLY on training split...")
    fit_start = time.perf_counter()
    pipeline.fit(X_train, y_train)
    fit_seconds = time.perf_counter() - fit_start

    print("Evaluating on test split...")
    validation_features = validation_df.reindex(columns=feature_cols)
    validation_attack_scores = None
    if hasattr(pipeline, "predict_proba") and "BENIGN" in label_encoder.classes_:
        probabilities = pipeline.predict_proba(validation_features)
        benign_column = list(label_encoder.classes_).index("BENIGN")
        validation_attack_scores = 1.0 - probabilities[:, benign_column]
    validation_binary_truth = (validation_labels != "BENIGN").astype(int).to_numpy()
    operating_point = (
        select_threshold_at_max_fpr(validation_binary_truth, validation_attack_scores, max_fpr)
        if validation_attack_scores is not None else None
    )
    inference_start = time.perf_counter()
    y_pred_ids = pipeline.predict(X_test)
    inference_seconds = time.perf_counter() - inference_start
    y_pred = label_encoder.inverse_transform(y_pred_ids.astype(int))
    y_prob = None
    if hasattr(pipeline, "predict_proba"):
        try:
            y_prob = pipeline.predict_proba(X_test)
        except Exception as e:  # noqa: BLE001
            print(f"Warning: Prediction probability computation failed: {e}")

    metrics = evaluate_predictions(
        y_true=test_targets.to_numpy(),
        y_pred=y_pred,
        y_prob=y_prob,
        classes=sorted(set(train_targets) | set(test_targets)),
        probability_classes=label_encoder.classes_.tolist(),
    )
    if operating_point and "BENIGN" in label_encoder.classes_:
        benign_column = list(label_encoder.classes_).index("BENIGN")
        test_attack_scores = 1.0 - y_prob[:, benign_column]
        binary_truth = (test_labels != "BENIGN").astype(int).to_numpy()
        metrics["operating_threshold"] = {
            **operating_point,
            "test": evaluate_binary_threshold(binary_truth, test_attack_scores, operating_point["threshold"]),
            "selected_on": "validation partition only",
        }
        metrics["attack_family_detection"] = {
            str(family): {
                "support": int((test_labels == family).sum()),
                "detected": int(((test_labels == family).to_numpy() & (test_attack_scores >= operating_point["threshold"])).sum()),
                "recall": float(((test_labels == family).to_numpy() & (test_attack_scores >= operating_point["threshold"])).sum() / max(1, (test_labels == family).sum())),
                "seen_in_training": bool(family in set(train_labels)),
            }
            for family in sorted(set(test_labels) - {"BENIGN"})
        }
        # Phase 4: Analyst Alert Burden Evaluation (predeclared budgets)
        metrics["alert_budget_evaluation"] = evaluate_alert_budgets(
            y_true_binary=binary_truth,
            scores=test_attack_scores,
            y_true_families=test_labels.to_numpy(),
            budgets_per_10k=[10, 50, 100],
            fixed_counts=[50, 100, 250, 500, 1000],
        )
    else:
        metrics["operating_threshold"] = None
    train_label_counts = {str(k): int(v) for k, v in train_labels.value_counts().items()}
    test_label_counts = {str(k): int(v) for k, v in test_labels.value_counts().items()}
    unseen_test_labels = sorted(set(test_labels) - set(train_labels))
    metrics["evaluation"] = {
        "split_mode": split_mode,
        "class_weight": class_weight,
        "task": task,
        "seed": seed,
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "validation_rows": int(len(validation_df)),
        "feature_count": int(len(feature_cols)),
        "train_label_counts": train_label_counts,
        "test_label_counts": test_label_counts,
        "unseen_test_labels": unseen_test_labels,
        "unseen_test_rows": int(test_labels.isin(unseen_test_labels).sum()),
        "unseen_validation_labels": unseen_validation_labels,
        "label_vocabulary_fit_on": "training partition only",
        "source_files": sorted(set(train_df.attrs.get("source_files", [])) | set(validation_df.attrs.get("source_files", [])) | set(test_df.attrs.get("source_files", []))),
        "fit_seconds": fit_seconds,
        "batch_inference_seconds": inference_seconds,
        "batch_inference_mean_seconds_per_flow": inference_seconds / max(1, len(test_df)),
    }

    print("\n" + format_evaluation_summary(metrics))

    # Save artifacts
    variant_suffix = ("_binary_attack" if task == "binary_attack" else "") + (f"_{class_weight}" if class_weight else "")
    versioned_pipeline_name = f"pipeline_{model_type}_{split_mode}{variant_suffix}_seed{seed}.pkl"
    pipeline_path = os.path.join(output_dir, versioned_pipeline_name)
    joblib.dump(pipeline, pipeline_path)
    # Keep experimental binary artifacts out of the app's stable multiclass path.
    if task == "multiclass":
        joblib.dump(pipeline, os.path.join(output_dir, "pipeline.pkl"))
    print(f"\nSaved versioned pipeline: {pipeline_path}")

    model_bundle = {
        "pipeline": pipeline,
        "label_encoder": label_encoder,
        "feature_names": feature_cols,
        "attack_threshold": operating_point["threshold"] if operating_point else None,
        "threshold_selection_max_fpr": max_fpr if operating_point else None,
        "task": task,
    }
    versioned_bundle_name = f"model_bundle_{model_type}_{split_mode}{variant_suffix}_seed{seed}.pkl"
    bundle_path = os.path.join(output_dir, versioned_bundle_name)
    joblib.dump(model_bundle, bundle_path)
    if task == "multiclass":
        joblib.dump(model_bundle, os.path.join(output_dir, "model_bundle.pkl"))

    # Keep the separate encoder/features synchronized with the selected pipeline.
    if task == "multiclass":
        joblib.dump(label_encoder, os.path.join(output_dir, "label_encoder.pkl"))
        joblib.dump(feature_cols, os.path.join(output_dir, "feature_names.pkl"))
    if model_type == "rf" and task == "multiclass":
        joblib.dump(pipeline.named_steps["classifier"], os.path.join(output_dir, "random_forest.pkl"))
        joblib.dump(pipeline.named_steps["scaler"], os.path.join(output_dir, "scaler.pkl"))

    # Save metrics JSON
    metrics_path = os.path.join(output_dir, f"metrics_{model_type}_{split_mode}{variant_suffix}_seed{seed}.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, allow_nan=False)

    artifact_hash = hashlib.sha256()
    with open(bundle_path, "rb") as artifact_file:
        for chunk in iter(lambda: artifact_file.read(1024 * 1024), b""):
            artifact_hash.update(chunk)
    model_sha256 = artifact_hash.hexdigest()
    dataset_hashes = {}
    for source_path in metrics["evaluation"]["source_files"]:
        source_hash = hashlib.sha256()
        with open(source_path, "rb") as source_file:
            for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
                source_hash.update(chunk)
        dataset_hashes[os.path.basename(source_path)] = source_hash.hexdigest()
    manifest = {
        "model_type": model_type,
        "class_weight": class_weight,
        "task": task,
        "split_mode": split_mode,
        "seed": seed,
        "model_file": os.path.basename(bundle_path),
        "model_sha256": model_sha256,
        "dataset_sha256": dataset_hashes,
        "feature_count": len(feature_cols),
        "features": feature_cols,
        "trained_classes": label_encoder.classes_.tolist(),
        "unseen_test_labels": unseen_test_labels,
        "metrics_file": os.path.basename(metrics_path),
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
    }
    manifest_path = os.path.join(output_dir, f"model_manifest_{model_type}_{split_mode}{variant_suffix}_seed{seed}.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, allow_nan=False)
    print(f"Saved artifact manifest: {manifest_path}")

    return metrics

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train leak-free intrusion detection models.")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="Path to CSV folder")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Where to save model artifacts")
    parser.add_argument("--split-mode", choices=["random", "day_based"], default="random")
    parser.add_argument("--model", choices=["rf", "lr"], default="rf")
    parser.add_argument("--n-trees", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-fpr", type=float, default=0.01, help="Validation false-positive budget for attack threshold selection")
    parser.add_argument("--class-weight", choices=["balanced", "balanced_subsample"], default=None)
    parser.add_argument("--task", choices=["multiclass", "binary_attack"], default="multiclass", help="Classify attack families or group all non-benign labels as ATTACK")
    args = parser.parse_args()

    run_training(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        split_mode=args.split_mode,
        model_type=args.model,
        n_estimators=args.n_trees,
        seed=args.seed,
        max_fpr=args.max_fpr,
        class_weight=args.class_weight,
        task=args.task,
    )
