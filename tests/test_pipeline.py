"""
tests/test_pipeline.py

Unit tests for leak-free sklearn pipeline construction,
FlowSanitizer transformer, and evaluation metrics.
"""

import pytest
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression

from training.preprocessor import FlowSanitizer, build_leak_free_pipeline
from training.evaluate import evaluate_predictions, calculate_fpr_at_fixed_tpr

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
