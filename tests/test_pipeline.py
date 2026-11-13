"""
tests/test_pipeline.py

Unit tests for leak-free sklearn pipeline construction,
FlowSanitizer transformer, and evaluation metrics.
"""

import numpy as np
import pandas as pd
import pytest
from sklearn.dummy import DummyClassifier

from training.evaluate import (
    CIC_DAYS,
    calculate_fpr_at_fixed_tpr,
    evaluate_binary_threshold,
    evaluate_predictions,
    select_threshold_at_max_fpr,
)
from training.preprocessor import FlowSanitizer, build_leak_free_pipeline
from training.benchmark_baselines import evaluate_model_seed
from training.train_pipeline import _read_csv_safe, load_split_data, run_training
from training.feature_parity import compare_feature_tables


def test_flow_sanitizer_drops_identifiers():
    df = pd.DataFrame({
        "Flow ID": ["192.168.1.1-10.0.0.1-80-443-6"],
        "Source IP": ["192.168.1.1"],
        "Destination IP": ["10.0.0.1"],
        "Timestamp": ["04/07/2017 08:55:00"],
        " Destination Port ": [80],
        " Flow Duration ": [5000.0],
        "Label": ["BENIGN"]
    })
    sanitizer = FlowSanitizer()
    sanitizer.fit(df)
    transformed = sanitizer.transform(df)

    assert "Flow ID" not in transformed.columns
    assert "Source IP" not in transformed.columns
    assert "Destination IP" not in transformed.columns
    assert "Timestamp" not in transformed.columns
    assert "Destination Port" in transformed.columns
    assert "Flow Duration" in transformed.columns

def test_leak_free_pipeline_fit_predict():
    X = pd.DataFrame({
        "Destination Port": [80, 443, 22, 8080, 53],
        "Flow Duration": [100.0, np.inf, 50.0, -np.inf, 20.0],
        "Total Fwd Packets": [5, 10, np.nan, 2, 4]
    })
    y = np.array([0, 1, 0, 1, 0])

    pipeline = build_leak_free_pipeline(DummyClassifier(strategy="most_frequent"))
    pipeline.fit(X, y)
    preds = pipeline.predict(X)

    assert len(preds) == 5
    assert set(preds).issubset({0, 1})

def test_fpr_at_fixed_tpr_calculation():
    # Synthetic binary predictions: perfect separation
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    y_scores = np.array([0.1, 0.2, 0.15, 0.05, 0.8, 0.9, 0.85, 0.95])
    
    fpr_95 = calculate_fpr_at_fixed_tpr(y_true, y_scores, target_tpr=0.95)
    assert fpr_95 == 0.0


def test_operating_threshold_is_selected_on_validation_and_frozen_for_test():
    validation_truth = np.array([0, 0, 0, 1, 1, 1])
    validation_scores = np.array([0.1, 0.2, 0.3, 0.4, 0.8, 0.9])
    point = select_threshold_at_max_fpr(validation_truth, validation_scores, max_fpr=0.0)
    assert point is not None
    assert point["validation_fpr"] == 0.0
    assert point["validation_tpr"] > 0

    test_result = evaluate_binary_threshold(
        np.array([0, 0, 1, 1]), np.array([0.35, 0.45, 0.5, 0.95]), point["threshold"]
    )
    assert test_result is not None
    assert test_result["threshold"] == point["threshold"]
    assert test_result["fpr"] == 0.5
    assert test_result["tpr"] == 1.0

def test_evaluate_predictions_metrics():
    y_true = np.array([0, 1, 0, 1, 0, 1])
    y_pred = np.array([0, 1, 0, 0, 0, 1])
    y_prob = np.array([
        [0.9, 0.1],
        [0.2, 0.8],
        [0.85, 0.15],
        [0.6, 0.4],
        [0.95, 0.05],
        [0.1, 0.9]
    ])
    classes = ["BENIGN", "PortScan"]

    metrics = evaluate_predictions(y_true, y_pred, y_prob, classes, benign_label="BENIGN")
    assert "macro_f1" in metrics
    assert "fpr_at_95_tpr" in metrics
    assert "binary_pr_auc" in metrics
    assert metrics["macro_f1"] > 0.0


def test_evaluation_keeps_unseen_test_class_explicit():
    y_true = np.array(["BENIGN", "PortScan", "NovelAttack"])
    y_pred = np.array(["BENIGN", "BENIGN", "PortScan"])
    y_prob = np.array([[0.9, 0.1], [0.7, 0.3], [0.2, 0.8]])

    metrics = evaluate_predictions(
        y_true,
        y_pred,
        y_prob,
        classes=["BENIGN", "PortScan", "NovelAttack"],
        probability_classes=["BENIGN", "PortScan"],
    )

    assert len(metrics["confusion_matrix"]) == 3
    assert metrics["class_support"]["NovelAttack"] == 1
    assert metrics["per_class_average_precision"]["NovelAttack"] is None
    assert metrics["per_class_pr_auc"]["NovelAttack"] is None
    assert "NovelAttack" not in metrics["probability_classes"]
    assert metrics["calibration"]["multiclass_brier_score"] > 0


def test_day_based_split_refuses_partial_dataset(tmp_path):
    with pytest.raises(FileNotFoundError, match="requires every configured day file"):
        load_split_data(str(tmp_path), split_mode="day_based")


def test_day_based_split_returns_disjoint_train_validation_and_test_days(tmp_path):
    labels = {
        "Monday": "BENIGN",
        "Tuesday": "FTP-Patator",
        "Wednesday": "PortScan",
        "Thursday": "DDoS",
        "Friday": "Bot",
    }
    row_number = 0
    for day, filenames in CIC_DAYS.items():
        for filename in filenames:
            (tmp_path / filename).write_text(
                f"Flow Duration,Label\n{row_number},{labels[day]}\n", encoding="utf-8"
            )
            row_number += 1

    train, test, validation = load_split_data(
        str(tmp_path), split_mode="day_based", include_validation=True
    )
    assert set(train["Label"]) == {"BENIGN", "FTP-Patator"}
    assert set(validation["Label"]) == {"PortScan"}
    assert set(test["Label"]) == {"DDoS", "Bot"}
    assert len(train) + len(validation) + len(test) == row_number


def test_csv_fallback_preserves_cic_en_dash_labels(tmp_path):
    source = tmp_path / "cp1252.csv"
    source.write_bytes("Label\nWeb Attack – Brute Force\n".encode("cp1252"))
    frame = _read_csv_safe(str(source))
    assert frame is not None
    assert frame.loc[0, "Label"] == "Web Attack – Brute Force"


def test_logistic_regression_rejects_random_forest_only_class_weight(tmp_path):
    with pytest.raises(ValueError, match="not 'balanced_subsample'"):
        run_training(
            data_dir=str(tmp_path / "missing"),
            output_dir=str(tmp_path / "output"),
            split_mode="day_based",
            model_type="lr",
            class_weight="balanced_subsample",
        )


def test_baseline_benchmark_preserves_unseen_class_and_binary_task():
    X_train = pd.DataFrame({"feature": [0, 1, 0.1, 0.9, 0.2, 0.8]})
    y_train = np.array([0, 1, 0, 1, 0, 1])
    X_test = pd.DataFrame({"feature": [0.05, 0.95, 1.1]})
    y_test = np.array(["BENIGN", "PortScan", "NovelAttack"])
    classes = ["BENIGN", "PortScan"]

    supervised = evaluate_model_seed(
        "Random Forest", X_train, y_train, X_test, y_test, 42, classes
    )
    unsupervised = evaluate_model_seed(
        "Isolation Forest (Unsupervised)", X_train, y_train, X_test, y_test, 42, classes
    )

    assert supervised["task"] == "multiclass"
    assert unsupervised["task"] == "binary"
    assert supervised["fpr_at_95"] is None or 0 <= supervised["fpr_at_95"] <= 1
    assert unsupervised["fpr_at_95"] is None


def test_feature_parity_compares_unique_flow_keys_and_marks_ambiguous():
    reference = pd.DataFrame({
        "Source IP": ["192.0.2.1"],
        "Destination IP": ["198.51.100.2"],
        "Source Port": [12345],
        "Destination Port": [443],
        "Protocol": [6],
        "Flow Duration": [100.0],
    })
    parsed = reference.copy()
    parsed.loc[0, "Flow Duration"] = 110.0

    result = compare_feature_tables(reference, parsed)
    assert result["matched_unique_flows"] == 1
    assert result["features_compared"]["Flow Duration"]["median_absolute_error"] == 10.0

    duplicate_reference = pd.concat([reference, reference], ignore_index=True)
    ambiguous = compare_feature_tables(duplicate_reference, parsed)
    assert ambiguous["matched_unique_flows"] == 0
    assert ambiguous["ambiguous_reference_keys"] == 1
