"""Hand-computed tests for the prevalence evaluation harness.

These tests use a synthetic confusion matrix. They never read the production
metrics or score-cache artifacts.
"""

import json

import numpy as np
import pytest

from scripts.prevalence_eval import (
    alerts_per_10k,
    break_even_per_flow,
    break_even_with_review,
    clopper_pearson_upper,
    confusion_at_threshold,
    evaluate_seed,
    main,
    ppv_at_prevalence,
    rates_from_counts,
    wilson_interval,
)


def synthetic_scores():
    """200 attacks (120 detected) and 19,800 benign (198 flagged)."""
    positives = np.concatenate([
        np.full(120, 0.9, dtype=np.float64),
        np.full(80, 0.1, dtype=np.float64),
    ])
    negatives = np.concatenate([
        np.full(198, 0.9, dtype=np.float64),
        np.full(19_602, 0.1, dtype=np.float64),
    ])
    scores = np.concatenate([positives, negatives])
    truth = np.concatenate([
        np.ones(len(positives), dtype=np.int8),
        np.zeros(len(negatives), dtype=np.int8),
    ])
    return scores, truth


def test_confusion_and_rates_are_hand_computable():
    scores, truth = synthetic_scores()
    counts = confusion_at_threshold(scores, truth, 0.5)

    assert counts == {
        "true_positives": 120,
        "false_positives": 198,
        "false_negatives": 80,
        "true_negatives": 19_602,
    }
    tpr, fpr, positives, negatives = rates_from_counts(counts)
    assert tpr == pytest.approx(0.6)
    assert fpr == pytest.approx(0.01)
    assert positives == 200
    assert negatives == 19_800


@pytest.mark.parametrize(
    "prevalence, expected_ppv, expected_alerts",
    [
        (0.0001, 0.00006 / 0.010059, 100.59),
        (0.001, 0.0006 / 0.01059, 105.9),
        (0.01, 0.006 / 0.0159, 159.0),
    ],
)
def test_prevalence_formulas_match_hand_values(prevalence, expected_ppv, expected_alerts):
    assert ppv_at_prevalence(0.6, 0.01, prevalence) == pytest.approx(expected_ppv, rel=1e-12)
    assert alerts_per_10k(0.6, 0.01, prevalence) == pytest.approx(expected_alerts, rel=1e-12)


def test_break_even_models_match_hand_values():
    # FP/TP at p=0.001: 0.01 * 0.999 / (0.6 * 0.001) = 16.65
    assert break_even_per_flow(0.6, 0.01, 0.001) == pytest.approx(16.65)
    # With review ratio 0.5: (0.00999 + 0.5 * 0.01059) / 0.0006 = 25.475
    assert break_even_with_review(0.6, 0.01, 0.001, 0.5) == pytest.approx(25.475)


def test_wilson_interval_brackets_the_point_estimate():
    low, high = wilson_interval(60, 100)
    assert low < 0.6 < high
    assert 0.0 <= low <= high <= 1.0


def test_zero_false_positive_rate_uses_clopper_pearson_upper():
    upper = clopper_pearson_upper(0, 1_000)
    assert 0.0 < upper < 0.01


def test_bootstrap_is_deterministic_and_brackets_the_point_estimate(tmp_path):
    scores, truth = synthetic_scores()
    cache = tmp_path / "rf_seed42_test.npz"
    np.savez_compressed(
        cache,
        attack_score=scores,
        binary_truth=truth,
    )
    prevalences = [0.0001, 0.001, 0.01]

    first = evaluate_seed(str(cache), 0.5, prevalences, 1_000_000, 0.0, 500, 7)
    second = evaluate_seed(str(cache), 0.5, prevalences, 1_000_000, 0.0, 500, 7)

    assert first["tpr"] == pytest.approx(0.6)
    assert first["fpr"] == pytest.approx(0.01)
    assert first["benchmark_prevalence"] == pytest.approx(200 / 20_000)
    for first_row, second_row in zip(first["prevalence"], second["prevalence"]):
        assert first_row["ppv"] == pytest.approx(second_row["ppv"])
        assert first_row["ppv_ci95"] == pytest.approx(second_row["ppv_ci95"])
        low, high = first_row["ppv_ci95"]
        assert low <= first_row["ppv"] <= high


def test_cli_writes_deterministic_artifact_without_production_inputs(tmp_path):
    scores, truth = synthetic_scores()
    cache_dir = tmp_path / "eval_cache"
    cache_dir.mkdir()
    np.savez_compressed(cache_dir / "rf_seed42_test.npz", attack_score=scores, binary_truth=truth)

    metrics = tmp_path / "metrics_rf_day_based_seed42.json"
    metrics.write_text(json.dumps({"operating_threshold": {"threshold": 0.5}}), encoding="utf-8")
    output = tmp_path / "prevalence.json"

    exit_code = main([
        "--metrics", str(metrics),
        "--prevalence", "0.0001,0.001,0.01",
        "--benchmark",
        "--flows-per-day", "1000000",
        "--review-cost-ratio", "0.5",
        "--output", str(output),
        "--score-cache-dir", str(cache_dir),
        "--model", "rf",
        "--seeds", "42",
        "--metrics-pattern", str(tmp_path / "metrics_rf_day_based_seed{seed}.json"),
        "--bootstrap", "200",
        "--seed", "20261113",
        "--cost-results", str(tmp_path / "missing.json"),
    ])

    assert exit_code == 0
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["method"] == "bootstrap_scores"
    assert document["seed"] == 20261113
    assert document["benchmark_prevalence"] == pytest.approx(0.01)
    assert [row["p"] for row in document["prevalence"]] == [0.0001, 0.001, 0.01]
    assert document["prevalence"][1]["ppv"] == pytest.approx(0.0006 / 0.01059)
    assert document["prevalence"][1]["break_even_per_flow"] == pytest.approx(16.65)
    assert document["prevalence"][1]["break_even_with_review"] == pytest.approx(25.475)
    assert document["prevalence"][1]["break_even_all_alerts"] == pytest.approx(17.65)
    assert document["prevalence"][1]["alerts_per_10k"] == pytest.approx(105.9)
