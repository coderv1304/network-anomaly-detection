"""Hand-computed tests for the Tier A rule baselines.

These tests use synthetic frames and arrays. They never read the production
metrics, score caches, or raw CIC-IDS-2017 CSVs.
"""

from __future__ import annotations

import inspect
import json
import math

import numpy as np
import pandas as pd
import pytest

from scripts.rule_baselines import (
    FANOUT_FEATURES,
    NEGATIVE_LABELS,
    POSITIVE_LABELS,
    RULE_ORDER,
    _finite_or_none,
    alert_budget_k,
    binary_truth,
    bootstrap_prevalence,
    build_rule_scores,
    classify_label,
    evaluate_rule,
    extract_tier_a,
    fit_rule_normalization,
    primary_mask,
    select_budget_threshold,
    score_tie_diagnostics,
    syn_score,
    syn_tie_diagnostic,
)


def tier_a_frame(**overrides) -> pd.DataFrame:
    base = {
        "Flow Duration": [500_000.0, 2_000_000.0],
        "Total Fwd Packets": [1.0, 10.0],
        "Total Backward Packets": [1.0, 10.0],
        "Total Length of Fwd Packets": [60.0, 6000.0],
        "Total Length of Bwd Packets": [60.0, 6000.0],
        "Flow Packets/s": [4000.0, 10.0],
        "Flow Bytes/s": [240_000.0, 6000.0],
        "Packet Length Mean": [60.0, 300.0],
        "Max Packet Length": [60.0, 1500.0],
        "SYN Flag Count": [1.0, 0.0],
        "FIN Flag Count": [0.0, 1.0],
        "RST Flag Count": [0.0, 0.0],
        "Label": ["BENIGN", "DDoS"],
    }
    base.update(overrides)
    lengths = [
        len(value)
        for value in base.values()
        if isinstance(value, (list, tuple, np.ndarray))
    ]
    length = max(lengths) if lengths else 1
    for key, value in list(base.items()):
        if isinstance(value, (list, tuple, np.ndarray)):
            base[key] = [value[index % len(value)] for index in range(length)]
        else:
            base[key] = [value] * length
    return pd.DataFrame(base)


# ---------------------------------------------------------------------------
# Label policy
# ---------------------------------------------------------------------------
def test_exact_cic_label_strings_map_to_the_policy():
    positive = [
        "DDoS",
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest",
        "PortScan",
    ]
    negative = ["BENIGN"]
    excluded = [
        "Heartbleed",
        "Web Attack \u2013 Brute Force",
        "Web Attack \u2013 XSS",
        "Web Attack \u2013 Sql Injection",
        "FTP-Patator",
        "SSH-Patator",
        "Bot",
        "Infiltration",
    ]

    for raw in positive:
        info = classify_label(raw)
        assert info["role"] == "positive"
        assert info["canonical"] == raw

    for raw in negative:
        info = classify_label(raw)
        assert info["role"] == "negative"
        assert info["canonical"] == raw

    for raw in excluded:
        info = classify_label(raw)
        assert info["role"] == "excluded"
        assert info["canonical"] == raw.replace("\u2013", "-")


def test_web_attack_en_dash_is_canonicalised_not_silently_dropped():
    info = classify_label("Web Attack \u2013 Brute Force")

    assert info["raw"] == "Web Attack \u2013 Brute Force"
    assert info["canonical"] == "Web Attack - Brute Force"
    assert info["role"] == "excluded"


def test_heartbleed_is_excluded_and_marked_validation_only():
    info = classify_label("Heartbleed")

    assert info["role"] == "excluded"
    assert "validation-only" in info["reason"]


def test_unknown_labels_are_excluded_not_treated_as_benign():
    info = classify_label("Some Future Attack")

    assert info["role"] == "excluded"
    assert "unmapped" in info["reason"]


@pytest.mark.parametrize("value", [None, float("nan"), "", "   "])
def test_missing_labels_are_reported_separately(value):
    info = classify_label(value)

    assert info["role"] == "missing"
    assert info["canonical"] == "<missing>"


def test_primary_mask_and_binary_truth_exclude_non_target_labels():
    labels = np.array(
        ["BENIGN", "DDoS", "Heartbleed", "Web Attack - XSS", "PortScan"],
        dtype=object,
    )

    keep = primary_mask(labels)
    truth = binary_truth(labels[keep])

    assert keep.tolist() == [True, True, False, False, True]
    assert truth.tolist() == [0, 1, 1]
    assert POSITIVE_LABELS.isdisjoint(NEGATIVE_LABELS)


# ---------------------------------------------------------------------------
# Threshold selection and budgets
# ---------------------------------------------------------------------------
def test_alert_budget_uses_exact_integer_ceiling():
    assert alert_budget_k(10, 692_675) == 693
    assert alert_budget_k(100, 692_675) == 6_927
    assert alert_budget_k(10, 10_000) == 10
    assert alert_budget_k(0, 100) == 0
    assert alert_budget_k(10, 1) == 1


def test_threshold_at_rank_k_plus_one_yields_k_alerts_without_ties():
    scores = np.array([10.0, 9.0, 8.0, 7.0, 6.0])

    selection = select_budget_threshold(scores, 4_000)  # K = 2

    assert selection["k"] == 2
    assert selection["threshold"] == 8.0
    assert selection["expected_alerts"] == 2
    assert selection["comparison"] == ">"


def test_boundary_ties_reduce_alerts_instead_of_exceeding_the_budget():
    scores = np.array([10.0, 9.0, 9.0, 9.0, 8.0])

    selection = select_budget_threshold(scores, 4_000)  # K = 2

    assert selection["threshold"] == 9.0
    assert selection["expected_alerts"] == 1
    assert selection["expected_alerts"] <= selection["k"]


def test_top_tie_larger_than_budget_yields_zero_alerts():
    scores = np.array([10.0, 10.0, 10.0, 8.0])

    selection = select_budget_threshold(scores, 5_000)  # K = 2

    assert selection["threshold"] == 10.0
    assert selection["expected_alerts"] == 0


def test_budget_larger_than_population_selects_everything():
    scores = np.array([10.0, 9.0, 8.0, 7.0])

    selection = select_budget_threshold(scores, 10_000)  # K >= N

    assert selection["threshold"] < 7.0
    assert selection["expected_alerts"] == 4


def test_zero_budget_selects_nothing():
    scores = np.array([3.0, 2.0, 1.0])

    selection = select_budget_threshold(scores, 0)

    assert selection["threshold"] == 3.0
    assert selection["expected_alerts"] == 0


def test_threshold_selection_cannot_see_labels():
    parameters = inspect.signature(select_budget_threshold).parameters

    assert "labels" not in parameters
    assert "truth" not in parameters


def test_budget_k_rejects_negative_budget():
    with pytest.raises(ValueError):
        alert_budget_k(-1, 100)


# ---------------------------------------------------------------------------
# Feature extraction and rule formulas
# ---------------------------------------------------------------------------
def test_syn_score_uses_the_exact_prompt_formula():
    features = {
        "syn_ratio": np.array([1.0, 0.5, 0.0]),
        "total_packets": np.array([1.0, 2.0, 0.0]),
    }

    expected = np.array(
        [
            1.0 * math.log1p(2.0),
            0.5 * math.log1p(3.0),
            0.0 * math.log1p(1.0),
        ]
    )

    assert np.allclose(syn_score(features), expected)


def test_short_flow_flag_matches_the_one_second_three_packet_definition():
    frame = tier_a_frame(
        **{
            "Flow Duration": [999_999.0, 1_000_000.0, 500_000.0],
            "Total Fwd Packets": [2.0, 2.0, 3.0],
            "Total Backward Packets": [1.0, 1.0, 2.0],
        }
    )

    features, _ = extract_tier_a(frame)

    assert features["short_flow_flag"].tolist() == [1.0, 0.0, 0.0]
    assert features["total_packets"].tolist() == [3.0, 3.0, 5.0]


def test_rate_repair_is_finite_and_documented():
    frame = tier_a_frame(
        **{
            "Flow Duration": [1_000_000.0, 0.0, 2_000_000.0, 1_000_000.0],
            "Total Fwd Packets": [10.0, 5.0, 10.0, 10.0],
            "Total Backward Packets": [0.0, 0.0, 0.0, 0.0],
            "Total Length of Fwd Packets": [1000.0, 500.0, 1000.0, 1000.0],
            "Total Length of Bwd Packets": [0.0, 0.0, 0.0, 0.0],
            "Flow Packets/s": [np.inf, np.nan, -1.0, 10.0],
            "Flow Bytes/s": [np.inf, np.nan, np.nan, 1000.0],
        }
    )

    features, repairs = extract_tier_a(frame)

    assert features["flow_packets_s"].tolist() == pytest.approx(
        [10.0, 5_000_000.0, 5.0, 10.0]
    )
    assert features["flow_bytes_s"].tolist() == pytest.approx(
        [1000.0, 500_000_000.0, 500.0, 1000.0]
    )
    assert repairs["flow_packets_s_repaired"] == 3
    assert repairs["flow_packets_s_zero_duration_repair"] == 1
    assert repairs["flow_bytes_s_repaired"] == 3
    assert repairs["flow_bytes_s_zero_duration_repair"] == 1
    assert np.isfinite(features["flow_packets_s"]).all()
    assert np.isfinite(features["flow_bytes_s"]).all()


def test_syn_and_rst_ratios_are_bounded_and_zero_safe():
    frame = tier_a_frame(
        **{
            "Total Fwd Packets": [0.0, 2.0],
            "Total Backward Packets": [0.0, 0.0],
            "SYN Flag Count": [1.0, 1.0],
            "RST Flag Count": [1.0, 1.0],
        }
    )

    features, repairs = extract_tier_a(frame)

    assert features["syn_ratio"].tolist() == [0.0, 0.5]
    assert features["rst_ratio"].tolist() == [0.0, 0.5]
    assert repairs["total_packets_zero"] == 1


def test_composite_uses_the_supplied_validation_normalisation():
    frame = tier_a_frame()
    features, _ = extract_tier_a(frame)
    normalization = fit_rule_normalization(features)

    first = build_rule_scores(features, normalization)
    shifted = {
        key: {"median": value["median"] + 1.0, "iqr": value["iqr"]}
        for key, value in normalization.items()
    }
    second = build_rule_scores(features, shifted)

    assert np.allclose(first["rate_bytes"], second["rate_bytes"])
    assert np.allclose(first["syn"], second["syn"])
    assert not np.allclose(
        first["composite_bytes_syn"], second["composite_bytes_syn"]
    )


# ---------------------------------------------------------------------------
# Metrics and bootstrap
# ---------------------------------------------------------------------------
def test_confusion_and_prevalence_metrics_are_hand_computable():
    labels = np.array(["BENIGN", "DDoS", "PortScan", "BENIGN"], dtype=object)
    scores = np.array([0.9, 0.8, 0.2, 0.1])

    block = evaluate_rule(
        scores,
        labels,
        threshold=0.5,
        prevalences=[0.001],
        bootstrap_draws=200,
        seed=7,
    )

    assert block["counts"] == {
        "true_positives": 1,
        "false_positives": 1,
        "false_negatives": 1,
        "true_negatives": 1,
    }
    assert block["recall"] == pytest.approx(0.5)
    assert block["fpr"] == pytest.approx(0.5)
    assert block["alerts"] == 2
    assert block["alerts_per_10k"] == pytest.approx(5_000.0)
    assert block["precision_at_benchmark"] == pytest.approx(0.5)
    assert block["benchmark_prevalence"] == pytest.approx(0.5)
    assert block["prevalence"][0]["ppv"] == pytest.approx(0.001)
    assert block["prevalence"][0]["alerts_per_10k"] == pytest.approx(5_000.0)
    assert block["per_family_recall"]["DDoS"]["recall"] == pytest.approx(1.0)
    assert block["per_family_recall"]["PortScan"]["recall"] == pytest.approx(0.0)


def test_bootstrap_is_deterministic_and_brackets_the_point_estimate():
    first = bootstrap_prevalence(50, 50, 100, 100, [0.001], 2_000, 7)
    second = bootstrap_prevalence(50, 50, 100, 100, [0.001], 2_000, 7)

    assert first == second
    ppv_low, ppv_high = first[0.001]["ppv_ci95"]
    alerts_low, alerts_high = first[0.001]["alerts_per_10k_ci95"]
    assert ppv_low < 0.001 < ppv_high
    assert alerts_low < 5_000.0 < alerts_high


def test_non_finite_values_become_none_and_serialise_as_strict_json():
    assert _finite_or_none(float("inf")) is None
    assert _finite_or_none(float("-inf")) is None
    assert _finite_or_none(float("nan")) is None
    assert _finite_or_none(1.5) == 1.5

    payload = {"value": _finite_or_none(float("inf"))}
    assert json.loads(json.dumps(payload, allow_nan=False)) == {"value": None}


# ---------------------------------------------------------------------------
# Tier B and SYN diagnostics
# ---------------------------------------------------------------------------
def test_fanout_is_tier_b_only_and_not_in_the_tier_a_rule_list():
    assert "fanout" not in RULE_ORDER
    assert set(FANOUT_FEATURES) == {
        "unique_dst_ports_60s",
        "unique_dst_hosts_60s",
        "connection_attempts_60s",
        "fanout_ratio_60s",
    }


def test_syn_tie_diagnostic_reports_the_top_tie():
    scores = np.array([0.693, 0.693, 0.693, 0.1])
    labels = np.array(["BENIGN", "BENIGN", "DoS Hulk", "PortScan"], dtype=object)

    diagnostic = syn_tie_diagnostic(scores, labels, [10])

    assert diagnostic["tied_rows"] == 3
    assert diagnostic["tied_label_counts"] == {"BENIGN": 2, "DoS Hulk": 1}
    assert diagnostic["budget_k"]["10"] == 1


def test_score_tie_diagnostics_covers_every_rule_and_flags_budget_breach():
    labels = np.array(["BENIGN", "BENIGN", "DDoS", "PortScan"], dtype=object)
    scores_by_rule = {
        "syn": np.array([0.693, 0.693, 0.693, 0.1]),
        "rate_bytes": np.array([9.0, 5.0, 4.0, 1.0]),
    }

    diagnostics = score_tie_diagnostics(scores_by_rule, labels, [10, 100])

    assert set(diagnostics) == {"syn", "rate_bytes"}
    assert diagnostics["syn"]["tied_rows"] == 3
    assert diagnostics["syn"]["exceeds_smallest_budget"] is True
    assert diagnostics["rate_bytes"]["tied_rows"] == 1
    assert diagnostics["rate_bytes"]["exceeds_smallest_budget"] is False
    assert diagnostics["syn"]["budget_k"] == {"10": 1, "100": 1}
