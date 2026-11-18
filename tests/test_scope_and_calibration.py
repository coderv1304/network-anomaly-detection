"""Matched-scope filtering, calibration, and benign-FPR threshold tests."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from training.scope_filter import (
    MATCHED_LABEL_COLUMN,
    NORMALIZED_LABEL_COLUMN,
    filter_matched_scope,
    merge_audits,
    normalize_label,
)
from training.train_calibrated import (
    PortableDataset,
    attack_probability,
    benign_fpr_threshold,
    benign_fpr_threshold_report,
    binary_metrics,
    build_protocol_split,
    fit_candidate_a,
    fit_candidate_b,
    prevalence_subsample_indices,
    strict_protocol_status,
)


# ---------------------------------------------------------------------------
# Scope filter
# ---------------------------------------------------------------------------
def test_cicids2017_scope_drops_out_of_scope_and_attempted_rows():
    labels = [
        "BENIGN",
        "DoS Hulk",
        "PortScan",
        "DDoS",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest",
        "Web Attack \u2013 Brute Force",
        "Bot",
        "Infiltration",
        "Heartbleed",
        "FTP-Patator",
        "SSH-Patator",
        "DoS Hulk - Attempted",
        "DoS Slowhttptest - Attempted",
        "Exploits",
        "Shellcode",
        "Fuzzers",
        "Normal",
        "Reconnaissance",
    ]
    frame = pd.DataFrame({"Label": labels, "marker": range(len(labels))})

    filtered, audit = filter_matched_scope(frame, "cicids2017", "Label")

    kept = set(filtered[NORMALIZED_LABEL_COLUMN])
    assert kept == {
        "BENIGN",
        "DoS Hulk",
        "PortScan",
        "DDoS",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest",
    }
    assert "DoS Hulk - Attempted" not in kept
    assert "Web Attack - Brute Force" not in kept
    assert "Exploits" not in kept
    assert "Shellcode" not in kept

    assert audit["raw_rows"] == len(labels)
    assert audit["benign_rows"] == 1
    assert audit["positive_rows"] == 6
    assert audit["dropped_out_of_scope_rows"] == len(labels) - 7
    assert audit["dropped_attempted_rows"] == 2
    assert (
        audit["benign_rows"]
        + audit["positive_rows"]
        + audit["dropped_out_of_scope_rows"]
        == audit["raw_rows"]
    )
    # The dropped rows are absent, not silently relabelled benign.
    assert set(filtered[MATCHED_LABEL_COLUMN]) == {0, 1}
    assert int((filtered[MATCHED_LABEL_COLUMN] == 0).sum()) == 1


def test_unsw_scope_keeps_only_dos_and_reconnaissance():
    frame = pd.DataFrame(
        {
            "attack_cat": [
                "Normal",
                "DoS",
                "Reconnaissance",
                "Exploits",
                "Fuzzers",
                "Generic",
                "Analysis",
                "Backdoor",
                "Shellcode",
                "Worms",
            ]
        }
    )
    filtered, audit = filter_matched_scope(frame, "unsw_nb15", "attack_cat")
    assert set(filtered[NORMALIZED_LABEL_COLUMN]) == {
        "Normal",
        "DoS",
        "Reconnaissance",
    }
    assert audit["benign_rows"] == 1
    assert audit["positive_rows"] == 2
    assert audit["dropped_out_of_scope_rows"] == 7
    assert audit["dropped_label_counts"]["Shellcode"] == 1


def test_cicids2018_scope_keeps_only_dos_and_ddos():
    frame = pd.DataFrame(
        {
            "Label": [
                "Benign",
                "DoS attacks-Hulk",
                "DoS attacks-SlowHTTPTest",
                "DoS attacks-GoldenEye",
                "DoS attacks-Slowloris",
                "DDOS attack-HOIC",
                "DDOS attack-LOIC-UDP",
                "DDoS attacks-LOIC-HTTP",
                "Brute Force -Web",
                "Brute Force -XSS",
                "SQL Injection",
                "Infilteration",
                "Bot",
            ]
        }
    )
    filtered, audit = filter_matched_scope(frame, "cicids2018", "Label")
    assert audit["benign_rows"] == 1
    assert audit["positive_rows"] == 7
    assert audit["dropped_out_of_scope_rows"] == 5
    assert "Bot" not in set(filtered[NORMALIZED_LABEL_COLUMN])


def test_scope_normalizes_dashes_whitespace_case_and_distrinet_alias():
    assert normalize_label("  DoS\t  Hulk ") == "DoS Hulk"
    assert normalize_label("Web Attack \u2013 XSS") == "Web Attack - XSS"
    assert normalize_label("Web Attack \u2014 XSS") == "Web Attack - XSS"

    frame = pd.DataFrame(
        {
            "Label": [
                "DoS   Hulk",
                "Portscan",
                "BENIGN",
                "Web Attack \u2013 Brute Force",
            ]
        }
    )
    filtered, _ = filter_matched_scope(frame, "distrinet_cicids2017", "Label")
    assert set(filtered[NORMALIZED_LABEL_COLUMN]) == {
        "DoS Hulk",
        "Portscan",
        "BENIGN",
    }
    assert int(filtered[MATCHED_LABEL_COLUMN].sum()) == 2


def test_missing_and_unknown_labels_are_dropped_never_benign():
    frame = pd.DataFrame({"Label": [None, np.nan, "", "mystery", "BENIGN"]})
    filtered, audit = filter_matched_scope(frame, "cicids2017", "Label")
    assert len(filtered) == 1
    assert filtered.iloc[0][MATCHED_LABEL_COLUMN] == 0
    assert audit["dropped_missing_label_rows"] == 3
    assert audit["dropped_label_counts"]["mystery"] == 1


def test_merge_audits_reconciles_counts():
    frame = pd.DataFrame({"Label": ["BENIGN", "DoS Hulk", "Bot"]})
    _, first = filter_matched_scope(frame, "cicids2017", "Label")
    _, second = filter_matched_scope(frame.iloc[:1], "cicids2017", "Label")
    merged = merge_audits([first, second])
    assert merged["raw_rows"] == 4
    assert merged["benign_rows"] == 2
    assert merged["positive_rows"] == 1
    assert (
        merged["benign_rows"]
        + merged["positive_rows"]
        + merged["dropped_out_of_scope_rows"]
        == merged["raw_rows"]
    )


# ---------------------------------------------------------------------------
# Benign-FPR thresholds
# ---------------------------------------------------------------------------
def test_benign_fpr_quantile_is_not_saturated_and_matches_target():
    rng = np.random.default_rng(7)
    benign = rng.beta(2.0, 8.0, size=50_000)

    for target in (0.005, 0.001):
        threshold = benign_fpr_threshold(benign, target)
        assert 0.001 < threshold < 0.99
        realized = float(np.mean(benign > threshold))
        assert abs(realized - target) <= 0.001


def test_benign_fpr_quantile_raises_on_saturation():
    saturated = np.ones(10_000, dtype=np.float64)
    with pytest.raises(AssertionError, match="Threshold saturation detected"):
        benign_fpr_threshold(saturated, 0.005)

    report = benign_fpr_threshold_report(saturated, 0.005)
    assert report["threshold"] == 1.0
    assert report["saturated"] is True


def test_benign_fpr_quantile_rejects_an_empty_benign_partition():
    with pytest.raises(ValueError):
        benign_fpr_threshold(np.empty(0), 0.005)


# ---------------------------------------------------------------------------
# Metrics and prevalence sampling
# ---------------------------------------------------------------------------
def test_binary_metrics_at_one_threshold():
    labels = np.array([1, 1, 0, 0], dtype=np.int8)
    scores = np.array([0.9, 0.4, 0.6, 0.1])
    metrics = binary_metrics(labels, scores, 0.5)
    assert metrics["tp"] == 1
    assert metrics["fn"] == 1
    assert metrics["fp"] == 1
    assert metrics["tn"] == 1
    assert metrics["precision"] == pytest.approx(0.5)
    assert metrics["recall"] == pytest.approx(0.5)
    assert metrics["fpr"] == pytest.approx(0.5)
    assert metrics["roc_auc"] == pytest.approx(0.75)


def test_prevalence_subsample_is_deterministic_and_keeps_all_benign():
    labels = np.concatenate(
        [np.zeros(10_000, dtype=np.int8), np.ones(5_000, dtype=np.int8)]
    )
    first, payload = prevalence_subsample_indices(labels, 0.001, seed=42)
    second, _ = prevalence_subsample_indices(labels, 0.001, seed=42)
    other, _ = prevalence_subsample_indices(labels, 0.001, seed=43)

    assert np.array_equal(first, second)
    assert not np.array_equal(first, other)
    assert payload["benign_rows"] == 10_000
    assert payload["positives_sampled"] == 10
    assert abs(payload["realized_prevalence"] - 0.001) < 1e-6
    sampled = labels[first]
    assert int(np.sum(sampled == 0)) == 10_000
    assert int(np.sum(sampled == 1)) == 10


# ---------------------------------------------------------------------------
# Candidate fitting
# ---------------------------------------------------------------------------
def test_candidates_learn_and_produce_spread_probabilities():
    rng = np.random.default_rng(11)
    features = rng.normal(size=(4_000, 8)).astype(np.float32)
    labels = (features[:, 0] + features[:, 1] > 0.9).astype(np.int8)
    assert 0 < labels.sum() < len(labels)

    x_train, y_train = features[:3_000], labels[:3_000]
    x_calibration, y_calibration = features[3_000:], labels[3_000:]
    assert 0 < y_train.sum() < len(y_train)
    assert 0 < y_calibration.sum() < len(y_calibration)

    model_a, meta_a = fit_candidate_a(
        x_train, y_train, x_calibration, y_calibration
    )
    model_b, meta_b = fit_candidate_b(
        x_train, y_train, x_calibration, y_calibration
    )

    probabilities_a = attack_probability(model_a, x_calibration)
    probabilities_b = attack_probability(model_b, x_calibration)

    for probabilities in (probabilities_a, probabilities_b):
        assert probabilities.shape == (len(x_calibration),)
        assert float(probabilities.min()) >= 0.0
        assert float(probabilities.max()) <= 1.0
        assert len(np.unique(np.round(probabilities, 6))) > 10

    assert meta_a["calibration"] == "sigmoid"
    assert meta_a["calibration_cv"] == "prefit"
    assert meta_b["native_probabilities"] is True


def test_batched_attack_probability_matches_single_pass():
    rng = np.random.default_rng(17)
    features = rng.normal(size=(2_000, 8)).astype(np.float32)
    labels = (features[:, 0] > 0).astype(np.int8)
    model, _ = fit_candidate_b(features, labels, features, labels)

    full = attack_probability(model, features)
    batched = attack_probability(model, features, batch_size=137)

    # Batching must not change a single score; both paths use the same model.
    assert np.array_equal(full, batched)


# ---------------------------------------------------------------------------
# Protocol feasibility
# ---------------------------------------------------------------------------
def _synthetic_dataset() -> PortableDataset:
    rng = np.random.default_rng(13)
    days = np.concatenate(
        [
            np.full(1_000, "Monday", dtype=object),
            np.full(1_000, "Tuesday", dtype=object),
            np.full(1_500, "Wednesday", dtype=object),
            np.full(750, "Thursday", dtype=object),
            np.full(750, "Friday", dtype=object),
        ]
    )
    labels = np.zeros(len(days), dtype=np.int8)
    labels[2_000:2_500] = 1  # Wednesday only
    groups = rng.integers(0, 20_000, size=len(days), dtype=np.uint64)
    matrix = rng.normal(size=(len(days), 8)).astype(np.float32)
    families = np.where(labels == 1, "DoS Hulk", "BENIGN").astype(object)
    return PortableDataset(
        name="synthetic",
        matrix=matrix,
        labels=labels,
        families=families,
        audit={"raw_rows": len(days)},
        counts={},
        raw_rows=len(days),
        kept_rows_before_dedup=len(days),
        duplicate_rows=0,
        days=days,
        groups=groups,
    )


def test_strict_monday_tuesday_split_is_reported_infeasible():
    dataset = _synthetic_dataset()
    status = strict_protocol_status(dataset)
    assert status["feasible"] is False
    assert status["positive_rows"] == 0
    assert status["benign_rows"] == 2_000
    assert "zero in-scope positive" in status["reason"]


def test_fallback_split_is_group_disjoint_and_never_touches_test_days():
    dataset = _synthetic_dataset()
    split = build_protocol_split(dataset)

    assert split.provenance == "wednesday_group_split_fallback"
    assert split.deviation is not None
    assert split.group_overlap == 0
    assert split.executed["train"]["positive"] > 0
    assert split.executed["calibration"]["positive"] > 0
    assert split.executed["calibration"]["benign"] > 0
    assert not np.any(dataset.days[split.train_mask] == "Thursday")
    assert not np.any(dataset.days[split.train_mask] == "Friday")
    assert not np.any(dataset.days[split.calibration_mask] == "Thursday")
    assert not np.any(dataset.days[split.calibration_mask] == "Friday")
    assert set(dataset.days[split.test_mask]) <= {"Thursday", "Friday"}


def test_requested_split_is_used_when_monday_tuesday_has_positives():
    dataset = _synthetic_dataset()
    dataset.labels[1_000:1_100] = 1  # Tuesday positives
    split = build_protocol_split(dataset)
    assert strict_protocol_status(dataset)["feasible"] is True
    assert split.provenance == "requested_day_split"
    assert split.deviation is None
    assert np.all(np.isin(dataset.days[split.train_mask], ["Monday", "Tuesday"]))
    assert np.all(dataset.days[split.calibration_mask] == "Wednesday")
