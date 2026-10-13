"""
training/evaluate.py

Evaluation engine for Intrusion Detection:
1. Computes Macro-F1, per-class Precision/Recall/F1.
2. Computes PR-AUC and ROC-AUC.
3. Computes False Positive Rate (FPR) at a fixed Detection Rate (e.g., 95% TPR).
4. Generates confusion matrices (raw counts and row-normalized).
5. Supports Day-based evaluation splits for CIC-IDS-2017.
"""

import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    confusion_matrix,
    precision_recall_curve,
    roc_curve,
    auc,
    roc_auc_score
)

# CIC-IDS-2017 Day Groupings
CIC_DAYS = {
    "Monday": ["Monday-WorkingHours.pcap_ISCX.csv"],
    "Tuesday": ["Tuesday-WorkingHours.pcap_ISCX.csv"],
    "Wednesday": ["Wednesday-workingHours.pcap_ISCX.csv"],
    "Thursday": [
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
    ],
    "Friday": [
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    ]
}

def calculate_fpr_at_fixed_tpr(y_true_binary: np.ndarray, y_score: np.ndarray, target_tpr: float = 0.95) -> float:
    """
    Computes the False Positive Rate (FPR) at a fixed True Positive Rate (target_tpr, e.g. 0.95).
    FPR = FP / (FP + TN)
    """
    fpr, tpr, thresholds = roc_curve(y_true_binary, y_score)
    # Find the smallest FPR where TPR >= target_tpr
    eligible_indices = np.where(tpr >= target_tpr)[0]
    if len(eligible_indices) == 0:
        return 1.0
    idx = eligible_indices[0]
    return float(fpr[idx])

def evaluate_predictions(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
    classes: Optional[List[str]] = None,
    benign_label: str = "BENIGN"
) -> Dict[str, Any]:
    """
    Compute comprehensive IDS evaluation metrics.
    """
    # 1. Macro and Weighted F1
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)

    # 2. Per-class report
    clf_report = classification_report(
        y_true, y_pred, target_names=classes, output_dict=True, zero_division=0
    )

    # 3. Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    cm_norm = confusion_matrix(y_true, y_pred, normalize="true")

    # 4. Binary Attack vs Benign metrics & FPR @ 95% TPR
    binary_metrics = {}
    if y_prob is not None and classes is not None and benign_label in classes:
        benign_idx = list(classes).index(benign_label)
        # Any attack is positive (1), benign is negative (0)
        y_true_binary = (y_true != benign_idx).astype(int)
        # Probability of being ANY attack = 1.0 - prob(benign)
        attack_prob = 1.0 - y_prob[:, benign_idx]

        fpr_at_95 = calculate_fpr_at_fixed_tpr(y_true_binary, attack_prob, target_tpr=0.95)
        fpr_at_99 = calculate_fpr_at_fixed_tpr(y_true_binary, attack_prob, target_tpr=0.99)

        precision_curve, recall_curve, _ = precision_recall_curve(y_true_binary, attack_prob)
        pr_auc = auc(recall_curve, precision_curve)
        roc_auc = roc_auc_score(y_true_binary, attack_prob)

        binary_metrics = {
            "binary_pr_auc": float(pr_auc),
            "binary_roc_auc": float(roc_auc),
            "fpr_at_95_tpr": float(fpr_at_95),
            "fpr_at_99_tpr": float(fpr_at_99)
        }

    return {
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "classification_report": clf_report,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_normalized": cm_norm.tolist(),
        **binary_metrics
    }

def format_evaluation_summary(metrics: Dict[str, Any]) -> str:
    """Format metrics into a clean markdown summary."""
    lines = [
        "### 📊 Evaluation Summary",
        f"- **Macro-F1:** {metrics['macro_f1']:.4f}",
        f"- **Weighted-F1:** {metrics['weighted_f1']:.4f}",
    ]
    if "fpr_at_95_tpr" in metrics:
        lines.extend([
            f"- **Binary PR-AUC:** {metrics['binary_pr_auc']:.4f}",
            f"- **Binary ROC-AUC:** {metrics['binary_roc_auc']:.4f}",
            f"- **FPR @ 95% Detection Rate (TPR):** {metrics['fpr_at_95_tpr'] * 100:.2f}%",
            f"- **FPR @ 99% Detection Rate (TPR):** {metrics['fpr_at_99_tpr'] * 100:.2f}%",
        ])
    return "\n".join(lines)
