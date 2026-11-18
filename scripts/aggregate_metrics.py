# scripts/aggregate_metrics.py
"""
Aggregates baseline metrics across seeds 42-46 for Random Forest,
Logistic Regression, and Isolation Forest.

Computes Mean ± SD for:
- Macro-F1
- Weighted-F1
- PR-AUC
- ROC-AUC
- Frozen-Threshold Recall (at max validation FPR <= 1%)
- Frozen-Threshold FPR
- Alert Rate (alerts per flow)
- Fit Time (seconds)

Outputs:
- docs/summary_metrics.json
- docs/BASELINE_RESULTS.md
"""

import json
import os
import numpy as np

MODELS_DIR = "models"
DOCS_DIR = "docs"
SEEDS = [42, 43, 44, 45, 46]
MODEL_TYPES = [
    ("rf", "Random Forest"),
    ("lr", "Logistic Regression"),
    ("if", "Isolation Forest"),
]


def load_seed_metrics(model_code: str, seed: int):
    path = os.path.join(MODELS_DIR, f"metrics_{model_code}_day_based_seed{seed}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_metrics(data: dict):
    # Macro / Weighted F1
    macro_f1 = data.get("macro_f1", np.nan)
    weighted_f1 = data.get("weighted_f1", np.nan)

    # PR-AUC & ROC-AUC
    pr_auc = data.get("binary_pr_auc", data.get("pr_auc", np.nan))
    roc_auc = data.get("binary_roc_auc", data.get("roc_auc", np.nan))

    # Frozen threshold test metrics
    op_thresh = data.get("operating_threshold") or {}
    test_metrics = op_thresh.get("test") or data.get("binary_metrics") or {}

    recall = test_metrics.get("recall", np.nan)
    fpr = test_metrics.get("fpr", np.nan)
    alert_rate = test_metrics.get("alert_rate", np.nan)

    # Fit time
    eval_info = data.get("evaluation") or {}
    fit_sec = eval_info.get("fit_seconds", data.get("fit_seconds", np.nan))

    # Alert budget evaluation (Phase 4)
    alert_budgets = data.get("alert_budget_evaluation") or {}
    b10k = alert_budgets.get("budgets_per_10k") or {}
    b_50 = b10k.get("50_per_10k") or {}
    b_100 = b10k.get("100_per_10k") or {}
    fb = alert_budgets.get("fixed_budgets") or {}
    top_100 = fb.get("top_100") or {}
    top_500 = fb.get("top_500") or {}

    return {
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "recall_at_frozen_threshold": recall,
        "fpr_at_frozen_threshold": fpr,
        "alert_rate": alert_rate,
        "fit_seconds": fit_sec,
        "precision_at_50_per_10k": b_50.get("precision", np.nan),
        "recall_at_50_per_10k": b_50.get("recall", np.nan),
        "fp_per_10k_at_50_budget": b_50.get("fp_per_10k_benign", np.nan),
        "precision_at_100_per_10k": b_100.get("precision", np.nan),
        "recall_at_100_per_10k": b_100.get("recall", np.nan),
        "precision_top_100": top_100.get("precision", np.nan),
        "recall_top_100": top_100.get("recall", np.nan),
        "precision_top_500": top_500.get("precision", np.nan),
        "recall_top_500": top_500.get("recall", np.nan),
    }


def main():
    os.makedirs(DOCS_DIR, exist_ok=True)
    results = {}

    for code, name in MODEL_TYPES:
        seed_records = []
        for s in SEEDS:
            m = load_seed_metrics(code, s)
            if m is not None:
                seed_records.append(extract_metrics(m))

        if not seed_records:
            print(f"Notice: No metric files found for {name} ({code})")
            continue

        keys = seed_records[0].keys()
        summary = {"n_seeds": len(seed_records)}

        for k in keys:
            vals = [r[k] for r in seed_records if not np.isnan(r.get(k, np.nan))]
            if vals:
                mean_val = float(np.mean(vals))
                std_val = float(np.std(vals, ddof=1)) if len(vals) > 1 else 0.0
                summary[k] = {
                    "mean": mean_val,
                    "std": std_val,
                    "values": vals,
                }
            else:
                summary[k] = {"mean": None, "std": None, "values": []}

        results[code] = {
            "name": name,
            "summary": summary,
        }

    # Save JSON summary
    summary_path = os.path.join(DOCS_DIR, "summary_metrics.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Saved aggregated JSON: {summary_path}")

    # Generate Markdown Table
    md_lines = [
        "# Controlled Baseline Comparison (Day-Based Split)",
        "",
        "Evaluation across 5 random seeds (42-46) following the frozen evaluation protocol.",
        "Split rule: Train = Monday-Tuesday, Validation = Wednesday (threshold freeze at max FPR <= 1%), Test = Thursday-Friday.",
        "",
        "| Baseline Model | Macro-F1 | Weighted-F1 | Binary PR-AUC | Binary ROC-AUC | Test Recall @ 1% Val FPR | Test FPR | Alert Rate | Fit Time (s) |",
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for code, name in MODEL_TYPES:
        if code not in results:
            continue
        s = results[code]["summary"]

        def fmt(metric_name, dec=4):
            item = s.get(metric_name)
            if not item or item["mean"] is None:
                return "N/A"
            return f"{item['mean']:.{dec}f} ± {item['std']:.{dec}f}"

        row = (
            f"| **{name}** | "
            f"{fmt('macro_f1')} | "
            f"{fmt('weighted_f1')} | "
            f"{fmt('pr_auc')} | "
            f"{fmt('roc_auc')} | "
            f"{fmt('recall_at_frozen_threshold')} | "
            f"{fmt('fpr_at_frozen_threshold')} | "
            f"{fmt('alert_rate')} | "
            f"{fmt('fit_seconds', dec=1)} |"
        )
        md_lines.append(row)

    # Phase 4 Alert Burden Table
    md_lines.append("")
    md_lines.append("## Analyst Alert Burden Comparison (Phase 4)")
    md_lines.append("")
    md_lines.append("Predeclared alert budgets: Top-50 alerts per 10,000 flows and Fixed Top-100/500 alerts.")
    md_lines.append("")
    md_lines.append("| Baseline Model | Precision @ 50/10k | Recall @ 50/10k | FP / 10k Benign @ 50/10k | Precision @ Top-100 | Recall @ Top-100 | Precision @ Top-500 | Recall @ Top-500 |")
    md_lines.append("|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|")

    for code, name in MODEL_TYPES:
        if code not in results:
            continue
        s = results[code]["summary"]

        def fmt(metric_name, dec=4):
            item = s.get(metric_name)
            if not item or item["mean"] is None:
                return "N/A"
            return f"{item['mean']:.{dec}f} ± {item['std']:.{dec}f}"

        b_row = (
            f"| **{name}** | "
            f"{fmt('precision_at_50_per_10k')} | "
            f"{fmt('recall_at_50_per_10k')} | "
            f"{fmt('fp_per_10k_at_50_budget', dec=1)} | "
            f"{fmt('precision_top_100')} | "
            f"{fmt('recall_top_100')} | "
            f"{fmt('precision_top_500')} | "
            f"{fmt('recall_top_500')} |"
        )
        md_lines.append(b_row)

    md_lines.append("")
    md_lines.append("### Key Observations")
    md_lines.append("- **Class Imbalance & Unseen Families**: Multiclass models evaluate with low Macro-F1 because test-only attack families (e.g. DDoS, PortScan, Web Attacks) have zero training examples in the temporal split.")
    md_lines.append("- **Frozen Threshold Operating Point**: Thresholds are frozen on Wednesday validation traffic strictly at max FPR <= 0.01 before evaluating on Thursday-Friday traffic.")
    md_lines.append("")

    table_path = os.path.join(DOCS_DIR, "BASELINE_RESULTS.md")
    with open(table_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))
    print(f"Saved Markdown baseline results: {table_path}")


if __name__ == "__main__":
    main()

