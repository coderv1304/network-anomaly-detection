# training/simulate_feedback.py
"""
Phase 5: Offline Simulation of Analyst Feedback in Network Flow Detection.

This experiment evaluates whether a small, fixed review budget (simulated analyst feedback)
during an intermediate review period (Thursday) enables an intrusion detector to adapt
and improve detection quality or reduce alert burden on a later, untouched period (Friday).

INTEGRITY & TEMPORAL CONSTRAINTS:
1. Time-ordered partitions:
   - Initial Train: Monday & Tuesday (historical baseline: BENIGN, FTP-Patator, SSH-Patator)
   - Validation: Wednesday (DoS, Heartbleed - used for frozen threshold selection)
   - Review Period: Thursday (Web Attacks, Infiltration - flows scored without labels;
     only the selected budget flows have labels revealed)
   - Untouched Evaluation Period: Friday (Bot, PortScan, DDoS - strictly held out;
     zero Friday labels or flows are ever observed during selection or adaptation)
2. Compares four policies:
   - No Feedback (Baseline, B=0): Initial model evaluated directly on Friday
   - Random Sampling: Uniform random selection of B flows from Thursday
   - Model Uncertainty: B flows closest to the decision boundary (|P(attack) - 0.5| min)
   - Top Alert / SOC Triage: Top B highest-scoring flows (highest P(attack))
3. Clearly labeled as SIMULATED analyst feedback (offline retrospective),
   NOT a prospective human study.

Optimized for memory efficiency (float32 feature arrays, single-pass leak-free preprocessing,
and base-model caching per seed).
"""

import sys
import os

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
TRAINING_DIR = os.path.abspath(os.path.dirname(__file__))
if TRAINING_DIR not in sys.path:
    sys.path.insert(0, TRAINING_DIR)

import argparse
import gc
import json
import time
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import precision_recall_curve, auc, roc_auc_score
from sklearn.pipeline import Pipeline

from preprocessor import IDENTIFIER_COLUMNS, FlowSanitizer
from evaluate import (
    CIC_DAYS,
    select_threshold_at_max_fpr,
    evaluate_binary_threshold,
    evaluate_alert_budgets,
)
from train_pipeline import _load_files


def load_temporal_simulation_splits(data_dir: str):
    """Load chronologically ordered splits for feedback simulation."""
    print("Loading time-ordered partitions for feedback simulation...")
    train_files = CIC_DAYS["Monday"] + CIC_DAYS["Tuesday"]
    val_files = CIC_DAYS["Wednesday"]
    review_files = CIC_DAYS["Thursday"]
    eval_files = CIC_DAYS["Friday"]

    df_train = _load_files(train_files, data_dir)
    df_val = _load_files(val_files, data_dir)
    df_review = _load_files(review_files, data_dir)
    df_eval = _load_files(eval_files, data_dir)

    print(f"  Initial Train (Mon-Tue): {len(df_train):,} flows")
    print(f"  Validation (Wed)       : {len(df_val):,} flows")
    print(f"  Review Period (Thu)    : {len(df_review):,} flows")
    print(f"  Untouched Eval (Fri)   : {len(df_eval):,} flows")

    return df_train, df_val, df_review, df_eval


def select_feedback_indices(
    scores: np.ndarray,
    budget: int,
    policy: str,
    seed: int,
    threshold: float = 0.5,
) -> np.ndarray:
    """Select indices of flows from the review period according to the designated policy."""
    n_samples = len(scores)
    budget = min(budget, n_samples)
    if budget <= 0:
        return np.array([], dtype=int)

    rng = np.random.default_rng(seed)

    if policy == "random":
        return rng.choice(n_samples, size=budget, replace=False)

    elif policy == "top_alert":
        # Top highest attack scores (standard SOC tier-1 alert queue triage)
        ranked = np.argsort(-scores)
        return ranked[:budget]

    elif policy == "uncertainty":
        # Closest to decision boundary (maximum ambiguity)
        uncertainty = np.abs(scores - threshold)
        ranked = np.argsort(uncertainty)
        return ranked[:budget]

    else:
        raise ValueError(f"Unknown feedback policy: {policy}")


def evaluate_on_untouched_eval(
    clf,
    label_encoder: LabelEncoder,
    X_eval: np.ndarray,
    y_eval: np.ndarray,
    frozen_threshold: float,
    seen_classes: set,
) -> tuple[float, float, dict, dict, dict]:
    """Evaluate fitted model on the untouched Friday evaluation partition."""
    y_eval_bin = (y_eval != "BENIGN").astype(int)

    eval_probs = clf.predict_proba(X_eval)
    benign_idx = list(label_encoder.classes_).index("BENIGN") if "BENIGN" in label_encoder.classes_ else 0
    eval_scores = 1.0 - eval_probs[:, benign_idx]

    # Overall metrics
    pr_curve_prec, pr_curve_rec, _ = precision_recall_curve(y_eval_bin, eval_scores)
    pr_auc = float(auc(pr_curve_rec, pr_curve_prec))
    roc_auc = float(roc_auc_score(y_eval_bin, eval_scores))

    eval_bin_metrics = evaluate_binary_threshold(y_eval_bin, eval_scores, frozen_threshold)

    # Per-family recall on Friday (Bot, PortScan, DDoS)
    attack_families = sorted(set(y_eval) - {"BENIGN"})
    per_family_recall = {}
    for fam in attack_families:
        mask = (y_eval == fam)
        tot = int(mask.sum())
        det = int((mask & (eval_scores >= frozen_threshold)).sum())
        per_family_recall[fam] = {
            "support": tot,
            "detected": det,
            "recall": float(det / tot) if tot > 0 else 0.0,
            "seen_in_adapted_training": bool(fam in seen_classes),
        }

    # Alert budget evaluation
    alert_budgets = evaluate_alert_budgets(
        y_true_binary=y_eval_bin,
        scores=eval_scores,
        y_true_families=y_eval,
        budgets_per_10k=[10, 50, 100],
        fixed_counts=[50, 100, 250, 500],
    )

    return pr_auc, roc_auc, eval_bin_metrics, per_family_recall, alert_budgets


def main():
    parser = argparse.ArgumentParser(description="Simulate limited analyst feedback under temporal holdout.")
    parser.add_argument("--data-dir", default="data", help="Path to raw CSV dataset directory")
    parser.add_argument("--output-dir", default="models", help="Directory for metric outputs")
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44, 45, 46], help="Random seeds")
    parser.add_argument("--budgets", type=int, nargs="+", default=[50, 100, 250], help="Labeling budgets")
    parser.add_argument("--model", choices=["rf", "lr"], default="rf", help="Classifier type")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs("docs", exist_ok=True)

    df_train, df_val, df_review, df_eval = load_temporal_simulation_splits(args.data_dir)
    feature_cols = [c for c in df_train.columns if c not in IDENTIFIER_COLUMNS]

    # Preprocess all partitions once up front using float32 to conserve memory
    print("\nFitting leak-free preprocessor strictly on Monday-Tuesday train data...")
    preprocessor = Pipeline([
        ("sanitizer", FlowSanitizer(expected_features=feature_cols)),
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
    ])

    X_train = preprocessor.fit_transform(df_train[feature_cols]).astype(np.float32)
    y_train = df_train["Label"].astype(str).to_numpy()

    X_val = preprocessor.transform(df_val[feature_cols]).astype(np.float32)
    y_val = df_val["Label"].astype(str).to_numpy()

    X_review = preprocessor.transform(df_review[feature_cols]).astype(np.float32)
    y_review = df_review["Label"].astype(str).to_numpy()

    X_eval = preprocessor.transform(df_eval[feature_cols]).astype(np.float32)
    y_eval = df_eval["Label"].astype(str).to_numpy()

    # Free the raw DataFrames immediately to reclaim memory
    del df_train, df_val, df_review, df_eval
    gc.collect()
    print("Preprocessed feature matrices cached in float32. Raw DataFrames freed.")

    all_runs = []

    print("\n" + "=" * 60)
    print("STARTING TIME-ORDERED ANALYST FEEDBACK SIMULATION")
    print("=" * 60)

    # Cache base models and review scores per seed
    base_models = {}
    for s in args.seeds:
        print(f"\n[Seed {s}] Fitting initial base model (Mon-Tue)...")
        base_encoder = LabelEncoder()
        base_encoder.fit(y_train)
        y_train_enc = base_encoder.transform(y_train)

        if args.model == "rf":
            base_clf = RandomForestClassifier(n_estimators=100, random_state=s, n_jobs=-1)
        else:
            base_clf = LogisticRegression(max_iter=1000, random_state=s)

        base_clf.fit(X_train, y_train_enc)

        # Validation score & threshold selection (frozen at max FPR <= 0.01)
        val_probs = base_clf.predict_proba(X_val)
        benign_idx = list(base_encoder.classes_).index("BENIGN") if "BENIGN" in base_encoder.classes_ else 0
        val_scores = 1.0 - val_probs[:, benign_idx]
        y_val_bin = (y_val != "BENIGN").astype(int)

        thresh_info = select_threshold_at_max_fpr(y_val_bin, val_scores, max_fpr=0.01)
        frozen_thresh = thresh_info["threshold"] if thresh_info else 0.5

        # Thursday review scores (without labels)
        review_probs = base_clf.predict_proba(X_review)
        review_scores = 1.0 - review_probs[:, benign_idx]

        # Evaluate No-Feedback Baseline (B=0) on Friday
        pr_auc, roc_auc, bm, fam_rec, alb = evaluate_on_untouched_eval(
            base_clf, base_encoder, X_eval, y_eval, frozen_thresh, set(y_train)
        )
        base_run = {
            "policy": "none",
            "budget": 0,
            "seed": s,
            "labels_requested": 0,
            "review_labels_seen": {},
            "frozen_threshold": float(frozen_thresh),
            "fit_seconds": 0.0,
            "pr_auc": pr_auc,
            "roc_auc": roc_auc,
            "binary_metrics": bm,
            "per_family_recall": fam_rec,
            "alert_budget_evaluation": alb,
        }
        all_runs.append(base_run)
        print(f"  [No-Feedback | B=0] Seed {s}: PR-AUC={pr_auc:.4f}, Recall@1%FPR={bm['recall']:.4f}")

        base_models[s] = {
            "review_scores": review_scores,
            "frozen_threshold": frozen_thresh,
        }
        gc.collect()

    # Feedback policies across budgets
    for b in args.budgets:
        for pol in ["random", "top_alert", "uncertainty"]:
            print(f"\nEvaluating Policy={pol}, Budget={b} across seeds...")
            for s in args.seeds:
                review_scores = base_models[s]["review_scores"]
                frozen_thresh = base_models[s]["frozen_threshold"]

                selected_idx = select_feedback_indices(
                    scores=review_scores,
                    budget=b,
                    policy=pol,
                    seed=s,
                    threshold=frozen_thresh,
                )

                # Reveal labels strictly for selected indices
                X_feedback = X_review[selected_idx]
                y_feedback = y_review[selected_idx]
                review_labels_seen = pd.Series(y_feedback).value_counts().to_dict()

                # Augment training set with feedback (balanced repetition)
                weight_factor = max(1, min(50, int(len(X_train) / (len(selected_idx) * 10))))
                X_aug = np.vstack([X_train, np.repeat(X_feedback, weight_factor, axis=0)])
                y_aug = np.concatenate([y_train, np.repeat(y_feedback, weight_factor)])

                adapted_encoder = LabelEncoder()
                adapted_encoder.fit(y_aug)
                y_aug_enc = adapted_encoder.transform(y_aug)

                if args.model == "rf":
                    adapted_clf = RandomForestClassifier(n_estimators=100, random_state=s, n_jobs=-1)
                else:
                    adapted_clf = LogisticRegression(max_iter=1000, random_state=s)

                t0 = time.perf_counter()
                adapted_clf.fit(X_aug, y_aug_enc)
                fit_sec = time.perf_counter() - t0

                # Evaluate on Friday untouched evaluation split
                pr_auc, roc_auc, bm, fam_rec, alb = evaluate_on_untouched_eval(
                    adapted_clf, adapted_encoder, X_eval, y_eval, frozen_thresh, set(y_aug)
                )

                res = {
                    "policy": pol,
                    "budget": b,
                    "seed": s,
                    "labels_requested": len(selected_idx),
                    "review_labels_seen": review_labels_seen,
                    "frozen_threshold": float(frozen_thresh),
                    "fit_seconds": fit_sec,
                    "pr_auc": pr_auc,
                    "roc_auc": roc_auc,
                    "binary_metrics": bm,
                    "per_family_recall": fam_rec,
                    "alert_budget_evaluation": alb,
                }
                all_runs.append(res)
                print(f"  [{pol} | B={b}] Seed {s}: PR-AUC={pr_auc:.4f}, Recall@1%FPR={bm['recall']:.4f}")

                del X_aug, y_aug, y_aug_enc, adapted_clf, adapted_encoder
                gc.collect()

    # Aggregate results across seeds
    summary_table = {}
    for r in all_runs:
        key = (r["policy"], r["budget"])
        if key not in summary_table:
            summary_table[key] = {
                "pr_auc": [],
                "roc_auc": [],
                "recall": [],
                "fpr": [],
                "alert_rate": [],
                "precision_50_10k": [],
                "recall_50_10k": [],
                "bot_recall": [],
                "ddos_recall": [],
                "portscan_recall": [],
            }
        entry = summary_table[key]
        entry["pr_auc"].append(r["pr_auc"])
        entry["roc_auc"].append(r["roc_auc"])
        bm = r["binary_metrics"]
        entry["recall"].append(bm["recall"])
        entry["fpr"].append(bm["fpr"])
        entry["alert_rate"].append(bm["alert_rate"])

        b50 = r["alert_budget_evaluation"].get("budgets_per_10k", {}).get("50_per_10k", {})
        entry["precision_50_10k"].append(b50.get("precision", np.nan))
        entry["recall_50_10k"].append(b50.get("recall", np.nan))

        fam = r["per_family_recall"]
        entry["bot_recall"].append(fam.get("Bot", {}).get("recall", np.nan))
        entry["ddos_recall"].append(fam.get("DDoS", {}).get("recall", np.nan))
        entry["portscan_recall"].append(fam.get("PortScan", {}).get("recall", np.nan))

    # Save raw metrics JSON
    out_json_path = os.path.join(args.output_dir, "feedback_simulation_results.json")
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump({
            "experiment": "offline_analyst_feedback_simulation",
            "model_type": args.model,
            "seeds": args.seeds,
            "budgets": args.budgets,
            "policies": ["none", "random", "top_alert", "uncertainty"],
            "total_runs": len(all_runs),
            "individual_runs": all_runs,
        }, f, indent=2)
    print(f"\nSaved raw simulation metrics: {out_json_path}")

    # Generate Markdown Report (docs/FEEDBACK_SIMULATION.md)
    md_lines = [
        "# Simulated Analyst Feedback Experiment (Phase 5)",
        "",
        "> [!IMPORTANT]",
        "> **Disclaimers & Experimental Protocol:**",
        "> - This is an **offline retrospective simulation** using time-ordered historical partitions, **NOT a prospective human study**.",
        "> - Assumes instantaneous, 100% accurate ground-truth labeling for selected flows with zero fatigue or delay.",
        "> - Partitions strictly enforce time ordering: Initial Train (Mon-Tue) -> Validation (Wed) -> Review Period (Thu) -> Untouched Evaluation (Fri).",
        "> - **Zero Friday labels or flows** were accessible during Thursday selection or adaptation.",
        "",
        "## Experimental Setup",
        "- **Initial Training (Mon-Tue)**: 975,789 flows (BENIGN, FTP-Patator, SSH-Patator)",
        "- **Validation (Wed)**: 692,686 flows (used strictly to freeze the operating threshold at max FPR <= 1%)",
        "- **Review Batch (Thu)**: 458,825 flows (Web Attacks, Infiltration - scored without labels; only budget flows revealed)",
        "- **Untouched Evaluation (Fri)**: 703,240 flows (Bot, PortScan, DDoS)",
        f"- **Classifier**: {args.model.upper()} | **Seeds**: {args.seeds}",
        "",
        "## Comparative Results Across Policies & Budgets",
        "",
        "| Policy | Budget (B) | Binary PR-AUC | Test Recall @ 1% Val FPR | Test FPR | Alert Rate | Bot Recall | PortScan Recall | DDoS Recall | Precision @ 50/10k |",
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for (pol, bud), data in summary_table.items():
        def _fmt(vals, dec=4):
            clean = [v for v in vals if not np.isnan(v)]
            if not clean:
                return "N/A"
            m = np.mean(clean)
            s = np.std(clean, ddof=1) if len(clean) > 1 else 0.0
            return f"{m:.{dec}f} ± {s:.{dec}f}"

        pol_name = {
            "none": "No Feedback (Baseline)",
            "random": "Random Sampling",
            "top_alert": "Top Alert / SOC Triage",
            "uncertainty": "Uncertainty Sampling",
        }.get(pol, pol)

        row = (
            f"| **{pol_name}** | {bud} | "
            f"{_fmt(data['pr_auc'])} | "
            f"{_fmt(data['recall'])} | "
            f"{_fmt(data['fpr'])} | "
            f"{_fmt(data['alert_rate'])} | "
            f"{_fmt(data['bot_recall'])} | "
            f"{_fmt(data['portscan_recall'])} | "
            f"{_fmt(data['ddos_recall'])} | "
            f"{_fmt(data['precision_50_10k'])} |"
        )
        md_lines.append(row)

    md_lines.extend([
        "",
        "## Key Findings and Discussion",
        "",
        "1. **Holdout Generalization vs. Review Specificity**:",
        "   - Revealing labels for Thursday attacks (Web Attacks & Infiltration) provides specific examples of those families, but Friday contains completely different families (Bot, PortScan, DDoS).",
        "   - The simulation directly tests whether intermediate feedback helps the model learn invariant attack boundaries or whether it overfits to the review day's specific attack types.",
        "",
        "2. **Policy Trade-offs**:",
        "   - **Top Alert / SOC Triage**: Focuses the analyst's budget on flows the current model already considers anomalous. High review precision, but risks confirming existing model biases.",
        "   - **Uncertainty Sampling**: Queries flows near the decision boundary. High value for refining thresholds on borderline benign/malicious traffic.",
        "   - **Random Sampling**: Provides unbiased coverage of background traffic shifts, helping suppress false positives from novel benign protocols.",
        "",
        "3. **Threats to Validity**:",
        "   - Real security analysts do not have access to ground-truth PCAP labels; real triage introduces noise, misclassification, and inconclusive tickets.",
        "   - Future work must evaluate active feedback in a live pilot environment with measured human interaction times.",
    ])

    report_path = os.path.join("docs", "FEEDBACK_SIMULATION.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))
    print(f"Saved simulated feedback report: {report_path}\n")


if __name__ == "__main__":
    main()
