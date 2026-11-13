"""
training/benchmark_baselines.py

Multi-model baseline benchmark for Network Anomaly Detection:
1. Evaluates Logistic Regression, Random Forest, LightGBM, and Isolation Forest.
2. Supports multi-seed runs with confidence intervals (mean +/- std).
3. Measures training duration and per-sample inference latency.
4. Reports Macro-F1, Weighted-F1, and FPR @ 95% TPR.
5. Saves comparative results to docs/BENCHMARK_RESULTS.md.
"""

import argparse
import hashlib
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from training.evaluate import evaluate_predictions
    from training.preprocessor import IDENTIFIER_COLUMNS, build_leak_free_pipeline
    from training.train_pipeline import load_split_data
except ImportError:
    from evaluate import evaluate_predictions
    from preprocessor import IDENTIFIER_COLUMNS, build_leak_free_pipeline
    from train_pipeline import load_split_data

DEFAULT_DATA_DIR = "data/samples"
DEFAULT_OUTPUT = "docs/BENCHMARK_RESULTS.md"

def evaluate_model_seed(
    model_name: str,
    X_train,
    y_train,
    X_test,
    y_test_labels,
    seed: int,
    train_classes: list[str],
) -> dict[str, Any]:
    start_train = time.perf_counter()

    if model_name == "Logistic Regression":
        estimator = LogisticRegression(max_iter=1000, random_state=seed)
        pipeline = build_leak_free_pipeline(estimator, expected_features=X_train.columns.tolist())
        pipeline.fit(X_train, y_train)

    elif model_name == "Random Forest":
        estimator = RandomForestClassifier(n_estimators=100, random_state=seed, n_jobs=-1)
        pipeline = build_leak_free_pipeline(estimator, expected_features=X_train.columns.tolist())
        pipeline.fit(X_train, y_train)

    elif model_name == "LightGBM":
        if not HAS_LIGHTGBM:
            raise ImportError("lightgbm is not installed. Run: pip install lightgbm")
        estimator = lgb.LGBMClassifier(random_state=seed, n_jobs=-1, verbose=-1)
        pipeline = build_leak_free_pipeline(estimator, expected_features=X_train.columns.tolist())
        pipeline.fit(X_train, y_train)

    elif model_name == "Isolation Forest (Unsupervised)":
        # Unsupervised: Train only on benign traffic (class index 0 / BENIGN)
        benign_mask = y_train == train_classes.index("BENIGN")
        estimator = IsolationForest(contamination=0.05, random_state=seed, n_jobs=-1)
        pipeline = build_leak_free_pipeline(estimator, expected_features=X_train.columns.tolist())
        pipeline.fit(X_train[benign_mask])

    train_time = time.perf_counter() - start_train

    # Inference Latency Benchmark
    start_infer = time.perf_counter()
    if model_name == "Isolation Forest (Unsupervised)":
        raw_preds = pipeline.predict(X_test)
        infer_time = time.perf_counter() - start_infer
        # Isolation Forest outputs 1 (normal) and -1 (anomaly)
        y_pred = np.where(raw_preds == 1, "BENIGN", "ATTACK")
        y_true = np.where(y_test_labels == "BENIGN", "BENIGN", "ATTACK")
        y_prob = None
        metrics = evaluate_predictions(y_true, y_pred, classes=["BENIGN", "ATTACK"])
        task = "binary"
    else:
        predicted_ids = pipeline.predict(X_test).astype(int)
        y_pred = np.asarray(train_classes)[predicted_ids]
        y_true = y_test_labels
        infer_time = time.perf_counter() - start_infer
        y_prob = pipeline.predict_proba(X_test) if hasattr(pipeline, "predict_proba") else None
        report_classes = sorted(set(train_classes) | set(y_test_labels))
        metrics = evaluate_predictions(
            y_true,
            y_pred,
            y_prob,
            classes=report_classes,
            probability_classes=train_classes,
        )
        task = "multiclass"

    latency_per_sample_us = (infer_time / len(X_test)) * 1_000_000

    fpr_at_95 = metrics.get("fpr_at_95_tpr")
    return {
        "task": task,
        "macro_f1": metrics["macro_f1"],
        "weighted_f1": metrics["weighted_f1"],
        "fpr_at_95": fpr_at_95 if fpr_at_95 is not None and np.isfinite(fpr_at_95) else None,
        "binary_pr_auc": metrics.get("binary_pr_auc"),
        "classification_report": metrics["classification_report"],
        "per_class_pr_auc": metrics["per_class_pr_auc"],
        "calibration": metrics["calibration"],
        "train_time_sec": train_time,
        "latency_us": latency_per_sample_us
    }


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def run_benchmarks(data_dir: str = DEFAULT_DATA_DIR, output_path: str = DEFAULT_OUTPUT, n_seeds: int = 3):
    if n_seeds < 2:
        raise ValueError("At least two seeds are required to report mean and standard deviation")
    print(f"\nStarting multi-model baseline benchmark ({n_seeds} seeds)...")
    
    models = ["Random Forest", "Logistic Regression"]
    if HAS_LIGHTGBM:
        models.append("LightGBM")
    else:
        print("Notice: lightgbm not installed. Install via pip install lightgbm to include in benchmark.")
    models.append("Isolation Forest (Unsupervised)")

    results_by_model = {m: [] for m in models}

    for seed in range(42, 42 + n_seeds):
        print(f"\n--- Seed {seed} ---")
        train_df, test_df = load_split_data(data_dir, split_mode="random", seed=seed)
        if seed == 42:
            dataset_files = sorted(set(train_df.attrs.get("source_files", [])) | set(test_df.attrs.get("source_files", [])))
            dataset_hashes = {os.path.basename(path): _sha256_file(path) for path in dataset_files}

        label_encoder = LabelEncoder()
        train_labels = train_df["Label"].astype(str)
        test_labels = test_df["Label"].astype(str).to_numpy()
        label_encoder.fit(train_labels)
        classes = label_encoder.classes_.tolist()

        y_train = label_encoder.transform(train_labels)

        feature_cols = [c for c in train_df.columns if c not in IDENTIFIER_COLUMNS]
        X_train = train_df[feature_cols]
        X_test = test_df.reindex(columns=feature_cols)

        for model_name in models:
            print(f"Running {model_name}...")
            res = evaluate_model_seed(model_name, X_train, y_train, X_test, test_labels, seed, classes)
            results_by_model[model_name].append(res)
            print(f"  Macro-F1: {res['macro_f1']:.4f} | Weighted-F1: {res['weighted_f1']:.4f} | Latency: {res['latency_us']:.1f} us/sample")

    # Generate Markdown Summary
    lines = [
        "# Model Baseline Benchmark Results",
        "",
        f"*Generated on: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}*",
        f"*Mean ± sample standard deviation across {n_seeds} random seeds; this is not a confidence interval.*",
        f"*Data directory: `{data_dir}`. Split: stratified random row holdout.*",
        f"*Seeds: {', '.join(str(seed) for seed in range(42, 42 + n_seeds))}.*",
        "*Input SHA-256: " + "; ".join(f"`{name}` `{digest}`" for name, digest in dataset_hashes.items()) + "*",
        "",
        "## 1. Summary Comparison Table",
        "",
        "| Model | Task | Macro-F1 (Mean ± Std) | Weighted-F1 | Attack PR-AUC | FPR @ 95% TPR | Multiclass Brier | ECE (10 bins) | Train Time (s) | Latency (µs / flow) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
    ]
    per_class_rows = []

    for model_name, runs in results_by_model.items():
        macro_f1s = [r["macro_f1"] for r in runs]
        weighted_f1s = [r["weighted_f1"] for r in runs]
        train_times = [r["train_time_sec"] for r in runs]
        latencies = [r["latency_us"] for r in runs]
        fprs = [r["fpr_at_95"] for r in runs if r["fpr_at_95"] is not None and np.isfinite(r["fpr_at_95"])]

        macro_mean = np.mean(macro_f1s)
        macro_std = np.std(macro_f1s, ddof=1)
        weighted_mean = np.mean(weighted_f1s)
        train_mean = np.mean(train_times)
        latency_mean = np.mean(latencies)
        fpr_str = f"{np.mean(fprs)*100:.2f}%" if fprs else "N/A"
        attack_pr_values = [r["binary_pr_auc"] for r in runs if r["binary_pr_auc"] is not None]
        attack_pr_str = f"{np.mean(attack_pr_values):.4f}" if attack_pr_values else "N/A"
        calibration_runs = [r["calibration"] for r in runs if r["calibration"] is not None]
        brier_str = f"{np.mean([m['multiclass_brier_score'] for m in calibration_runs]):.4f}" if calibration_runs else "N/A"
        ece_str = f"{np.mean([m['expected_calibration_error_10_bins'] for m in calibration_runs]):.4f}" if calibration_runs else "N/A"

        lines.append(
            f"| **{model_name}** | {runs[0]['task']} | {macro_mean:.4f} ± {macro_std:.4f} | {weighted_mean:.4f} | {attack_pr_str} | {fpr_str} | {brier_str} | {ece_str} | {train_mean:.2f}s | {latency_mean:.1f} µs |"
        )

        label_names = sorted({
            label
            for run in runs
            for label in run["classification_report"]
            if label not in {"accuracy", "macro avg", "weighted avg"}
        })
        for label in label_names:
            reports = [run["classification_report"][label] for run in runs if label in run["classification_report"]]
            supports = [report["support"] for report in reports]
            aps = [run["per_class_pr_auc"].get(label) for run in runs if run["per_class_pr_auc"].get(label) is not None]
            per_class_rows.append(
                f"| {model_name} | {runs[0]['task']} | {label} | "
                f"{np.mean([m['precision'] for m in reports]):.4f} | "
                f"{np.mean([m['recall'] for m in reports]):.4f} | "
                f"{np.mean([m['f1-score'] for m in reports]):.4f} | "
                f"{np.mean(supports):.1f} | {np.mean(aps):.4f} |" if aps else
                f"| {model_name} | {runs[0]['task']} | {label} | "
                f"{np.mean([m['precision'] for m in reports]):.4f} | "
                f"{np.mean([m['recall'] for m in reports]):.4f} | "
                f"{np.mean([m['f1-score'] for m in reports]):.4f} | "
                f"{np.mean(supports):.1f} | N/A |"
            )

    lines.extend([
        "",
        "## Per-class Results",
        "",
        "Precision, recall, F1, support, and PR-AUC are means across seeds. PR-AUC is N/A when the fitted model has no output column for that class.",
        "",
        "| Model | Task | Class | Precision | Recall | F1 | Mean support | PR-AUC |",
        "| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: |",
        *per_class_rows,
        "",
        "## 2. Methodology & Findings",
        "- Preprocessing statistics and label vocabularies are fitted on the training partition only.",
        "- Random row splits can put related flows from the same capture days on both sides; these results do not establish temporal or environment generalization.",
        "- Attack PR-AUC scores benign versus any non-benign row; it does not measure which attack family was identified. The per-class table shows the multi-class failure modes.",
        "- Brier score and ECE are uncalibrated test-set diagnostics. No probability calibration method or operational threshold has been selected.",
        "- The Isolation Forest row is a binary benign-versus-anomaly task. Its macro-F1 is not directly comparable to the supervised multi-class rows.",
        "- FPR at 95% TPR is computed from supervised model scores; the Isolation Forest row reports N/A because calibrated probability was not evaluated.",
        "- Latency is batch inference elapsed time divided by test rows on this host; it is not a production throughput guarantee."
    ])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nBenchmark results saved to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run multi-model baselines.")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="Path to evaluation data")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output markdown path")
    parser.add_argument("--seeds", type=int, default=3, help="Number of random seeds")
    args = parser.parse_args()

    run_benchmarks(args.data_dir, args.output, args.seeds)
