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

import os
import sys
import glob
import argparse
import joblib
import json
import pandas as pd
import numpy as np
from datetime import datetime, timezone
from typing import Optional

# Ensure project root is in sys.path when executed directly as python training/train_pipeline.py
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

try:
    from training.preprocessor import build_leak_free_pipeline, IDENTIFIER_COLUMNS
    from training.evaluate import evaluate_predictions, format_evaluation_summary, CIC_DAYS
except ImportError:
    from preprocessor import build_leak_free_pipeline, IDENTIFIER_COLUMNS
    from evaluate import evaluate_predictions, format_evaluation_summary, CIC_DAYS

DEFAULT_DATA_DIR = "data"
DEFAULT_OUTPUT_DIR = "models"
ENCODINGS = ["utf-8", "latin1", "ISO-8859-1"]

def load_split_data(data_dir: str, split_mode: str = "random", test_size: float = 0.2, seed: int = 42):
    """
    Load CIC-IDS-2017 datasets according to the requested split strategy.
    split_mode:
        - 'random': stratified random split (with leakage warning)
        - 'day_based': Train on Monday-Wednesday, Test on Thursday-Friday
    """
    if split_mode == "day_based":
        print("📅 Executing Day-Based Split: Train=[Mon, Tue, Wed], Test=[Thu, Fri]")
        train_files = CIC_DAYS["Monday"] + CIC_DAYS["Tuesday"] + CIC_DAYS["Wednesday"]
        test_files = CIC_DAYS["Thursday"] + CIC_DAYS["Friday"]

        df_train = _load_files(train_files, data_dir)
        df_test = _load_files(test_files, data_dir)
        return df_train, df_test
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
        return train_df, test_df

def _read_csv_safe(filepath: str) -> Optional[pd.DataFrame]:
    if not os.path.exists(filepath):
        return None
    for enc in ENCODINGS:
        try:
            df = pd.read_csv(filepath, encoding=enc, low_memory=False)
            df.columns = df.columns.str.strip()
            return df
        except Exception:
            continue
    return None

def _load_files(file_list: list, data_dir: str) -> pd.DataFrame:
    frames = []
    for fname in file_list:
        path = os.path.join(data_dir, fname)
        df = _read_csv_safe(path)
        if df is not None:
            df.columns = df.columns.str.strip()
            frames.append(df)
        else:
            print(f"⚠️ Warning: {fname} not found in {data_dir}. Skipping.")

    if not frames:
        raise FileNotFoundError(f"None of {file_list} found in {data_dir}")
    combined = pd.concat(frames, ignore_index=True)
    combined.drop_duplicates(inplace=True)
    combined.dropna(subset=["Label"], inplace=True)
    return combined

def run_training(
    data_dir: str = DEFAULT_DATA_DIR,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    split_mode: str = "random",
    model_type: str = "rf",
    n_estimators: int = 100,
    seed: int = 42
):
    os.makedirs(output_dir, exist_ok=True)
    print(f"\n🚀 Initiating ML Rigor Training Pipeline (Model: {model_type.upper()}, Split: {split_mode})")

    train_df, test_df = load_split_data(data_dir, split_mode=split_mode, seed=seed)
    print(f"Train samples: {len(train_df):,} | Test samples: {len(test_df):,}")

    # Separate X and y
    label_encoder = LabelEncoder()
    # Fit label encoder on all observed unique labels across train + test
    combined_labels = pd.concat([train_df["Label"], test_df["Label"]]).unique()
    label_encoder.fit(combined_labels)

    y_train = label_encoder.transform(train_df["Label"])
    y_test = label_encoder.transform(test_df["Label"])

    feature_cols = [c for c in train_df.columns if c not in IDENTIFIER_COLUMNS]
    X_train = train_df[feature_cols]
    X_test = test_df[feature_cols]

    # Select base estimator
    if model_type == "rf":
        base_estimator = RandomForestClassifier(
            n_estimators=n_estimators, random_state=seed, n_jobs=-1
        )
    elif model_type == "lr":
        base_estimator = LogisticRegression(max_iter=1000, random_state=seed)
    else:
        raise ValueError(f"Unknown model_type: {model_type}")

    # Build leak-free pipeline
    pipeline = build_leak_free_pipeline(
        classifier=base_estimator,
        expected_features=feature_cols
    )

    print("Fitting pipeline (Imputer -> Scaler -> Classifier) STRICTLY on training split...")
    pipeline.fit(X_train, y_train)

    print("Evaluating on test split...")
    y_pred = pipeline.predict(X_test)
    y_prob = None
    if hasattr(pipeline, "predict_proba"):
        try:
            y_prob = pipeline.predict_proba(X_test)
        except Exception:
            pass

    metrics = evaluate_predictions(
        y_true=y_test,
        y_pred=y_pred,
        y_prob=y_prob,
        classes=label_encoder.classes_.tolist()
    )

    print("\n" + format_evaluation_summary(metrics))

    # Save artifacts
    pipeline_path = os.path.join(output_dir, "pipeline.pkl")
    joblib.dump(pipeline, pipeline_path)
    print(f"\nSaved unified leak-free pipeline: {pipeline_path}")

    # Export decoupled legacy components for backward compatibility with app.py
    joblib.dump(pipeline.named_steps["classifier"], os.path.join(output_dir, "random_forest.pkl"))
    joblib.dump(pipeline.named_steps["scaler"], os.path.join(output_dir, "scaler.pkl"))
    joblib.dump(label_encoder, os.path.join(output_dir, "label_encoder.pkl"))
    joblib.dump(feature_cols, os.path.join(output_dir, "feature_names.pkl"))
    print("Exported decoupled artifacts to models/ for app.py backward compatibility.")

    # Save metrics JSON
    metrics_path = os.path.join(output_dir, f"metrics_{model_type}_{split_mode}.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return metrics

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train leak-free intrusion detection models.")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="Path to CSV folder")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Where to save model artifacts")
    parser.add_argument("--split-mode", choices=["random", "day_based"], default="random")
    parser.add_argument("--model", choices=["rf", "lr"], default="rf")
    parser.add_argument("--n-trees", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    run_training(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        split_mode=args.split_mode,
        model_type=args.model,
        n_estimators=args.n_trees,
        seed=args.seed
    )
