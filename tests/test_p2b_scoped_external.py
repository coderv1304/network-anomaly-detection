"""Tests for the scoped P2B external comparison.

These tests use synthetic arrays only. They do not load CIC-IDS-2018.
"""

from __future__ import annotations

import numpy as np

from scripts.p2b_scoped_external import (
    coverage_gate,
    evaluate_scores,
    expected_calibration_error,
    fit_models,
    group_split,
    holm_adjust,
    mcnemar_exact,
    partition_counts,
    rule_feature_dict,
    score_models,
    stratified_train_sample,
)


def _labels() -> np.ndarray:
    return np.asarray(
        ["Benign"] * 5 + ["DoS"] * 3 + ["DDoS"] * 2,
        dtype=object,
    )


def test_group_split_is_deterministic_and_covers_all_partitions():
    hashes = np.arange(10_000, dtype=np.uint64)
    first = group_split(hashes)
    second = group_split(hashes)
    assert np.array_equal(first, second)
    assert set(np.unique(first)) == {0, 1, 2}
    assert np.all(first[hashes % 100 < 70] == 0)
    assert np.all(first[(hashes % 100 >= 70) & (hashes % 100 < 85)] == 1)
    assert np.all(first[hashes % 100 >= 85] == 2)


def test_partition_counts_and_coverage_gate_pass():
    partition = np.asarray([0, 0, 1, 1, 2, 2], dtype=np.int8)
    families = np.asarray([1, 2, 1, 2, 1, 2], dtype=np.int8)
    names = np.asarray(["Benign", "DoS", "DDoS"], dtype=object)
    counts = partition_counts(partition, families, names)
    gate = coverage_gate(counts)
    assert gate["overall_pass"] is True
    assert gate["families"]["DoS"]["pass"] is True
    assert gate["families"]["DDoS"]["pass"] is True
    assert gate["validation_test_overlap"] == ["DDoS", "DoS"]


def test_coverage_gate_fails_when_a_family_is_missing():
    counts = {
        "train": {"DoS": 10, "DDoS": 0, "Benign": 100},
        "validation": {"DoS": 5, "DDoS": 0, "Benign": 50},
        "test": {"DoS": 5, "DDoS": 0, "Benign": 50},
    }
    gate = coverage_gate(counts)
    assert gate["overall_pass"] is False
    assert gate["missing_required"] == ["DDoS"]


def test_evaluate_scores_reports_counts_and_per_family_recall():
    scores = np.asarray([0.1, 0.2, 0.3, 0.4, 0.45, 0.8, 0.9, 0.95, 0.85, 0.7])
    labels = _labels()
    result = evaluate_scores(
        scores,
        labels,
        threshold=0.5,
        prevalences=(0.01,),
        bootstrap_draws=100,
        seed=42,
        probabilistic=True,
    )
    assert result["counts"]["true_positives"] == 5
    assert result["counts"]["false_positives"] == 0
    assert result["counts"]["false_negatives"] == 0
    assert result["recall"] == 1.0
    assert result["per_family_recall"]["DoS"]["alerts"] == 3
    assert result["per_family_recall"]["DDoS"]["alerts"] == 2
    assert result["per_family_recall"]["DoS"]["recall"] == 1.0


def test_evaluate_scores_marks_isolation_metrics_unavailable():
    scores = np.asarray([0.1, 0.2, 0.3, 0.4, 0.45, 0.8, 0.9, 0.95, 0.85, 0.7])
    result = evaluate_scores(
        scores,
        _labels(),
        threshold=0.5,
        prevalences=(0.01,),
        bootstrap_draws=100,
        seed=42,
        probabilistic=False,
    )
    assert result["brier"] is None
    assert result["ece_10_bins"] is None


def test_mcnemar_exact_matches_a_known_discordant_case():
    truth = np.asarray([1, 1, 0, 0])
    a = np.asarray([1, 1, 0, 0])
    b = np.asarray([1, 0, 0, 0])
    result = mcnemar_exact(a, b, truth)
    assert result["b"] == 1
    assert result["c"] == 0
    assert 0.0 <= result["p_value"] <= 1.0


def test_holm_adjust_is_monotonic_and_bounded():
    adjusted = holm_adjust([0.01, 0.04, 0.03])
    assert adjusted == [0.03, 0.06, 0.06]
    assert all(0.0 <= value <= 1.0 for value in adjusted)


def test_expected_calibration_error_is_zero_for_perfect_bins():
    truth = np.asarray([0, 0, 1, 1])
    scores = np.asarray([0.0, 0.0, 1.0, 1.0])
    assert expected_calibration_error(truth, scores) == 0.0


def test_rule_feature_dict_rebuilds_rates_and_syn_ratio():
    from scripts.external_dataset_audit import TIER_A_FEATURES

    matrix = np.zeros((2, len(TIER_A_FEATURES)), dtype=np.float32)
    matrix[0, TIER_A_FEATURES.index("total_fwd_packets")] = 3.0
    matrix[0, TIER_A_FEATURES.index("total_backward_packets")] = 1.0
    matrix[0, TIER_A_FEATURES.index("syn_flag_count")] = 2.0
    matrix[0, TIER_A_FEATURES.index("flow_bytes_s")] = 100.0
    matrix[0, TIER_A_FEATURES.index("flow_packets_s")] = 4.0
    features = rule_feature_dict(matrix)
    assert features["total_packets"][0] == 4.0
    assert features["syn_ratio"][0] == 0.5
    assert features["flow_bytes_s"][0] == 100.0
    assert features["flow_packets_s"][0] == 4.0


def test_stratified_train_sample_respects_cap_and_is_deterministic():
    partition = np.asarray([0] * 100 + [1] * 10 + [2] * 10, dtype=np.int8)
    truth = np.asarray([0, 1] * 50 + [0] * 10 + [1] * 10, dtype=np.int8)
    families = np.asarray([0, 1] * 50 + [0] * 10 + [1] * 10, dtype=np.int8)
    first = stratified_train_sample(partition, truth, families, cap=40, seed=42)
    second = stratified_train_sample(partition, truth, families, cap=40, seed=42)
    assert len(first) == 40
    assert np.array_equal(first, second)
    assert np.all(partition[first] == 0)


def test_fit_and_score_models_on_synthetic_features():
    rng = np.random.default_rng(42)
    matrix = rng.normal(size=(240, 12)).astype(np.float32)
    truth = np.asarray([0, 1] * 120, dtype=np.int8)
    train = np.arange(0, 160)
    validation = np.arange(160, 200)
    test = np.arange(200, 240)
    models = fit_models(matrix, truth, train, validation, seed=42)
    assert set(models) == {
        "logistic_regression",
        "random_forest",
        "isolation_forest",
    }
    for entry in models.values():
        assert entry["validation_scores"].shape == (40,)
    scores = score_models(models, matrix[test])
    assert set(scores) == set(models)
    for values in scores.values():
        assert values.shape == (40,)
        assert np.isfinite(values).all()
