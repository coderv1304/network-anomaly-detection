"""Evaluation helpers for repeatable network-flow classifier experiments."""

from typing import Any

import numpy as np
from sklearn.metrics import (
    auc,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

CIC_DAYS = {
    "Monday": ["Monday-WorkingHours.pcap_ISCX.csv"],
    "Tuesday": ["Tuesday-WorkingHours.pcap_ISCX.csv"],
    "Wednesday": ["Wednesday-workingHours.pcap_ISCX.csv"],
    "Thursday": [
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    ],
    "Friday": [
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ],
}


def calculate_fpr_at_fixed_tpr(
    y_true_binary: np.ndarray,
    y_score: np.ndarray,
    target_tpr: float = 0.95,
) -> float | None:
    """Return the lowest observed FPR that reaches target TPR, or None if undefined."""
    truth = np.asarray(y_true_binary, dtype=int)
    scores = np.asarray(y_score, dtype=float)
    if truth.size == 0 or np.unique(truth).size != 2:
        return None
    fpr, tpr, _ = roc_curve(truth, scores)
    eligible = np.flatnonzero(tpr >= target_tpr)
    return float(fpr[eligible[0]]) if eligible.size else 1.0


def select_threshold_at_max_fpr(
    y_true_binary: np.ndarray, scores: np.ndarray, max_fpr: float = 0.01
) -> dict[str, float] | None:
    """Select the highest validation TPR under an FPR budget.

    This threshold is selected from validation data only. The caller must apply
    it unchanged to the held-out test set and report that result separately.
    """
    truth = np.asarray(y_true_binary, dtype=int)
    score = np.asarray(scores, dtype=float)
    if not 0 <= max_fpr <= 1:
        raise ValueError("max_fpr must be between zero and one")
    if truth.ndim != 1 or score.ndim != 1 or truth.size != score.size:
        raise ValueError("binary labels and scores must be equal-length one-dimensional arrays")
    if truth.size == 0 or np.unique(truth).size != 2 or not np.isfinite(score).all():
        return None
    fpr, tpr, thresholds = roc_curve(truth, score)
    eligible = np.flatnonzero(fpr <= max_fpr)
    if not eligible.size:
        return None
    best_tpr = np.max(tpr[eligible])
    best_candidates = eligible[tpr[eligible] == best_tpr]
    selected = int(best_candidates[np.argmax(thresholds[best_candidates])])
    threshold = float(thresholds[selected])
    if not np.isfinite(threshold):
        threshold = float(np.nextafter(np.max(score), np.inf))
    return {
        "threshold": threshold,
        "max_fpr": float(max_fpr),
        "validation_fpr": float(fpr[selected]),
        "validation_tpr": float(tpr[selected]),
    }


def evaluate_binary_threshold(y_true_binary: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float] | None:
    """Measure a frozen score threshold on a separate evaluation partition."""
    truth = np.asarray(y_true_binary, dtype=int)
    score = np.asarray(scores, dtype=float)
    if truth.ndim != 1 or score.ndim != 1 or truth.size != score.size:
        raise ValueError("binary labels and scores must be equal-length one-dimensional arrays")
    if truth.size == 0 or np.unique(truth).size != 2 or not np.isfinite(score).all():
        return None
    predicted = score >= threshold
    positive = truth == 1
    negative = ~positive
    tp = int(np.sum(predicted & positive))
    fp = int(np.sum(predicted & negative))
    fn = int(np.sum(~predicted & positive))
    tn = int(np.sum(~predicted & negative))
    return {
        "threshold": float(threshold),
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "tpr": tp / (tp + fn) if tp + fn else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "alert_rate": float(np.mean(predicted)),
    }


def evaluate_alert_budgets(
    y_true_binary: np.ndarray,
    scores: np.ndarray,
    y_true_families: np.ndarray | None = None,
    budgets_per_10k: list[int] | None = None,
    fixed_counts: list[int] | None = None,
) -> dict[str, Any]:
    """Measure detection metrics under predeclared analyst alert budgets (Phase 4).

    Separates fixed rate budgets (e.g. 10, 50, 100 alerts per 10,000 flows)
    and fixed volume budgets (e.g. 50, 100, 250, 500 alerts) from score thresholds.
    """
    truth = np.asarray(y_true_binary, dtype=int)
    score_arr = np.asarray(scores, dtype=float)
    n_flows = truth.shape[0]
    if n_flows == 0 or truth.ndim != 1 or score_arr.ndim != 1:
        return {}

    total_attacks = int(np.sum(truth == 1))
    total_benign = int(np.sum(truth == 0))

    if budgets_per_10k is None:
        budgets_per_10k = [10, 50, 100]
    if fixed_counts is None:
        fixed_counts = [50, 100, 250, 500, 1000]

    # Pre-sort indices by descending anomaly/attack score
    ranked_indices = np.argsort(-score_arr)

    results: dict[str, Any] = {
        "total_flows": n_flows,
        "total_attacks": total_attacks,
        "total_benign": total_benign,
        "budgets_per_10k": {},
        "fixed_budgets": {},
    }

    def _eval_top_k(k: int) -> dict[str, Any]:
        k = max(1, min(k, n_flows))
        selected = ranked_indices[:k]
        tp = int(np.sum(truth[selected] == 1))
        fp = int(k - tp)
        precision = float(tp / k) if k > 0 else 0.0
        recall = float(tp / total_attacks) if total_attacks > 0 else 0.0
        fp_per_10k_benign = float((fp / total_benign) * 10_000.0) if total_benign > 0 else 0.0
        alert_rate = float(k / n_flows)
        effective_threshold = float(score_arr[ranked_indices[k - 1]])

        per_family_recall: dict[str, float] = {}
        if y_true_families is not None:
            families_arr = np.asarray(y_true_families, dtype=str)
            unique_families = sorted(set(families_arr) - {"BENIGN"})
            selected_families = families_arr[selected]
            for fam in unique_families:
                fam_total = int(np.sum(families_arr == fam))
                fam_detected = int(np.sum(selected_families == fam))
                per_family_recall[fam] = float(fam_detected / fam_total) if fam_total > 0 else 0.0

        return {
            "budget_k": k,
            "alerts_generated": k,
            "alert_rate": alert_rate,
            "effective_threshold": effective_threshold,
            "true_positives": tp,
            "false_positives": fp,
            "precision": precision,
            "recall": recall,
            "fp_per_10k_benign": fp_per_10k_benign,
            "per_family_recall": per_family_recall,
        }

    for b in budgets_per_10k:
        k = int(round((b / 10_000.0) * n_flows))
        results["budgets_per_10k"][f"{b}_per_10k"] = _eval_top_k(k)

    for k in fixed_counts:
        results["fixed_budgets"][f"top_{k}"] = _eval_top_k(k)

    return results


def _label_values(classes: list[Any], observed: np.ndarray) -> list[Any]:
    """Resolve display classes to the values used in y_true/y_pred.

    Older callers pass encoded integers plus display names. Newer callers can
    pass original string labels directly, which is preferred for temporal splits.
    """
    values = set(observed.tolist())
    if values.issubset(set(range(len(classes)))):
        return list(range(len(classes)))
    return list(classes)


def _expected_calibration_error(
    truth: np.ndarray, predicted: np.ndarray, confidence: np.ndarray, bins: int = 10
) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    error = 0.0
    for index in range(bins):
        # Include confidence=1.0 in the final bin.
        mask = (confidence >= edges[index]) & (
            confidence <= edges[index + 1] if index == bins - 1 else confidence < edges[index + 1]
        )
        if np.any(mask):
            error += float(mask.mean()) * abs(float((predicted[mask] == truth[mask]).mean()) - float(confidence[mask].mean()))
    return error


def evaluate_predictions(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None = None,
    classes: list[Any] | None = None,
    benign_label: Any = "BENIGN",
    probability_classes: list[Any] | None = None,
) -> dict[str, Any]:
    """Compute fixed-label metrics while preserving explicitly unseen classes.

    ``classes`` is the full reporting vocabulary (train ∪ test). Probability
    columns must be described separately when the fitted model did not learn
    every reported class. An unseen test class remains in the confusion matrix
    and report but has no invented probability score or per-class PR-AUC.
    """
    truth = np.asarray(y_true)
    predicted = np.asarray(y_pred)
    if truth.ndim != 1 or predicted.ndim != 1 or truth.shape != predicted.shape:
        raise ValueError("y_true and y_pred must be one-dimensional arrays of equal length")
    if truth.size == 0:
        raise ValueError("Cannot evaluate an empty test set")

    observed = np.concatenate([truth, predicted])
    if classes is None:
        report_classes = list(dict.fromkeys(observed.tolist()))
        report_classes.sort(key=str)
    else:
        report_classes = list(classes)
    values = _label_values(report_classes, observed)
    display_names = [str(name) for name in report_classes]
    report = classification_report(
        truth,
        predicted,
        labels=values,
        target_names=display_names,
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(truth, predicted, labels=values)
    normalized = confusion_matrix(truth, predicted, labels=values, normalize="true")
    metrics: dict[str, Any] = {
        "macro_f1": float(f1_score(truth, predicted, labels=values, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(truth, predicted, labels=values, average="weighted", zero_division=0)),
        "classes": display_names,
        "class_support": {str(label): int(np.sum(truth == value)) for label, value in zip(report_classes, values)},
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_normalized": np.nan_to_num(normalized).tolist(),
        "per_class_average_precision": {},
        "per_class_pr_auc": {},
        "probability_classes": [],
        "calibration": None,
        "binary_metrics": None,
    }

    if y_prob is None:
        return metrics

    probabilities = np.asarray(y_prob, dtype=float)
    probability_labels = list(probability_classes or report_classes)
    if probabilities.ndim != 2 or probabilities.shape != (truth.size, len(probability_labels)):
        raise ValueError("y_prob shape must match rows and probability_classes")
    if not np.isfinite(probabilities).all() or np.any(probabilities < 0):
        raise ValueError("y_prob must contain finite, non-negative values")
    row_sums = probabilities.sum(axis=1)
    if not np.allclose(row_sums, 1.0, atol=1e-5):
        raise ValueError("Each y_prob row must sum to 1")
    metrics["probability_classes"] = [str(label) for label in probability_labels]

    # Map model output columns into the full reporting vocabulary. Classes
    # absent from training receive no fabricated class-specific probability.
    class_to_column = {label: index for index, label in enumerate(probability_labels)}
    per_class_ap: dict[str, float | None] = {}
    per_class_pr_auc: dict[str, float | None] = {}
    for name, value in zip(report_classes, values):
        column_label = name if name in class_to_column else value
        if column_label not in class_to_column:
            per_class_ap[str(name)] = None
            per_class_pr_auc[str(name)] = None
            continue
        binary_truth = (truth == value).astype(int)
        if binary_truth.sum() == 0:
            per_class_ap[str(name)] = None
            per_class_pr_auc[str(name)] = None
        else:
            class_scores = probabilities[:, class_to_column[column_label]]
            per_class_ap[str(name)] = float(average_precision_score(binary_truth, class_scores))
            precision, recall, _ = precision_recall_curve(binary_truth, class_scores)
            per_class_pr_auc[str(name)] = float(auc(recall, precision))
    metrics["per_class_average_precision"] = per_class_ap
    metrics["per_class_pr_auc"] = per_class_pr_auc

    # Multiclass Brier score includes unseen test labels as unassigned mass,
    # making the failure visible instead of silently dropping those examples.
    aligned = np.zeros((truth.size, len(values)), dtype=float)
    for class_index, (name, value) in enumerate(zip(report_classes, values)):
        source_label = name if name in class_to_column else value
        if source_label in class_to_column:
            aligned[:, class_index] = probabilities[:, class_to_column[source_label]]
    one_hot = np.column_stack([(truth == value).astype(float) for value in values])
    brier = float(np.mean(np.sum((aligned - one_hot) ** 2, axis=1)))

    predicted_columns = probabilities.argmax(axis=1)
    predicted_values = np.asarray([probability_labels[column] for column in predicted_columns])
    confidence = probabilities.max(axis=1)
    metrics["calibration"] = {
        "multiclass_brier_score": brier,
        "expected_calibration_error_10_bins": _expected_calibration_error(truth, predicted_values, confidence),
    }

    benign_value = benign_label
    if benign_label not in set(values) and isinstance(benign_label, str) and benign_label in report_classes:
        benign_value = values[report_classes.index(benign_label)]
    benign_column_label = benign_label if benign_label in class_to_column else benign_value
    if benign_column_label in class_to_column:
        binary_truth = (truth != benign_value).astype(int)
        attack_score = 1.0 - probabilities[:, class_to_column[benign_column_label]]
        if np.unique(binary_truth).size == 2:
            metrics["binary_metrics"] = {
                "binary_pr_auc": float(auc(*precision_recall_curve(binary_truth, attack_score)[1::-1])),
                "binary_average_precision": float(average_precision_score(binary_truth, attack_score)),
                "binary_roc_auc": float(roc_auc_score(binary_truth, attack_score)),
                "fpr_at_95_tpr": calculate_fpr_at_fixed_tpr(binary_truth, attack_score, 0.95),
                "fpr_at_99_tpr": calculate_fpr_at_fixed_tpr(binary_truth, attack_score, 0.99),
            }
            # Keep aliases for existing benchmark consumers.
            metrics["binary_pr_auc"] = metrics["binary_metrics"]["binary_pr_auc"]
            metrics["binary_roc_auc"] = metrics["binary_metrics"]["binary_roc_auc"]
            metrics["fpr_at_95_tpr"] = metrics["binary_metrics"]["fpr_at_95_tpr"]
            metrics["fpr_at_99_tpr"] = metrics["binary_metrics"]["fpr_at_99_tpr"]
    return metrics


def format_evaluation_summary(metrics: dict[str, Any]) -> str:
    """Format a concise text summary without hiding missing evaluation fields."""
    lines = [
        "Evaluation Summary",
        f"- Macro-F1: {metrics['macro_f1']:.4f}",
        f"- Weighted-F1: {metrics['weighted_f1']:.4f}",
    ]
    binary = metrics.get("binary_metrics")
    if binary:
        lines.extend([
            f"- Binary average precision: {binary['binary_average_precision']:.4f}",
            f"- Binary PR-AUC: {binary['binary_pr_auc']:.4f}",
            f"- Binary ROC-AUC: {binary['binary_roc_auc']:.4f}",
            f"- FPR at 95% TPR: {binary['fpr_at_95_tpr']:.4f}",
            f"- FPR at 99% TPR: {binary['fpr_at_99_tpr']:.4f}",
        ])
    calibration = metrics.get("calibration")
    if calibration:
        lines.append(f"- Multiclass Brier score: {calibration['multiclass_brier_score']:.4f}")
        lines.append(f"- Expected calibration error (10 bins): {calibration['expected_calibration_error_10_bins']:.4f}")
    alert_budgets = metrics.get("alert_budget_evaluation")
    if alert_budgets:
        lines.append("- Alert Budget Evaluation:")
        budgets_10k = alert_budgets.get("budgets_per_10k", {})
        for name, info in budgets_10k.items():
            lines.append(f"  * {name} ({info['budget_k']} alerts): Precision={info['precision']:.4f}, Recall={info['recall']:.4f}, FP/10k benign={info['fp_per_10k_benign']:.1f}")
        fixed_b = alert_budgets.get("fixed_budgets", {})
        for name, info in list(fixed_b.items())[:2]:
            lines.append(f"  * {name} alerts: Precision={info['precision']:.4f}, Recall={info['recall']:.4f}, FP/10k benign={info['fp_per_10k_benign']:.1f}")
    return "\n".join(lines)
