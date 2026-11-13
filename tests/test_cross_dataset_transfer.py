"""Tests for the P3 cross-dataset transfer mapping and metrics.

These tests use synthetic frames. They never read the external downloads or
score a model. They do check that the serving artifact hash is unchanged when
the artifact is present.
"""

from __future__ import annotations

import json
import os

import numpy as np
import pandas as pd
import pytest

from scripts.cross_dataset_transfer import (
    CIC2018_FAMILY_CODES,
    CIC2018_TIER_A_MAP,
    SERVING_ARTIFACT,
    SERVING_SHA256,
    TIER_A_FEATURES,
    TRANSFER_MODEL,
    UNSW_TIER_A_MAP,
    apply_missing_policy,
    coverage_gate,
    external_budget_threshold,
    external_label,
    feature_status,
    ks_statistic,
    metrics_at_threshold,
    partition_counts,
    psi,
    render_report,
    schema_payload,
    serializable_split,
    stratified_group_split,
    tie_aware_metrics,
    _dataset_payload,
    _full_feature_hashes,
    _negative_transfer_text,
)
from scripts.rule_baselines import _sha256_file
from training.model_registry import feature_schema_sha256


def test_schema_is_frozen_at_twelve_tier_a_features():
    schema = schema_payload()
    assert schema["count"] == 12
    assert schema["features"] == TIER_A_FEATURES
    assert schema["sha256"] == feature_schema_sha256(TIER_A_FEATURES)


def test_cic2018_label_mapping_never_guesses_benign():
    assert external_label("Benign", "cic_ids_2018") == 0
    assert external_label("DDoS attacks-LOIC-HTTP", "cic_ids_2018") == 1
    assert external_label("DDOS attack-HOIC", "cic_ids_2018") == 1
    assert external_label("DoS attacks-Hulk", "cic_ids_2018") == 1
    assert external_label("DoS attacks-Slowloris", "cic_ids_2018") == 1
    assert external_label("Bot", "cic_ids_2018") == -1
    assert external_label("FTP-BruteForce", "cic_ids_2018") == -1
    assert external_label("SQL Injection", "cic_ids_2018") == -1
    assert external_label("something-new", "cic_ids_2018") == -1


def test_unsw_label_mapping_never_guesses_normal():
    assert external_label("Normal", "unsw_nb15") == 0
    assert external_label("DoS", "unsw_nb15") == 1
    assert external_label("Reconnaissance", "unsw_nb15") == 1
    assert external_label("Exploits", "unsw_nb15") == -1
    assert external_label("Fuzzers", "unsw_nb15") == -1
    assert external_label("something-new", "unsw_nb15") == -1


def test_cic2018_feature_mapping_is_complete():
    status = feature_status(CIC2018_TIER_A_MAP)
    assert status["available"] == 12
    assert status["missing"] == 0
    assert all(row["present"] for row in status["features"].values())


def test_cic2018_family_codes_keep_portscan_separate():
    assert CIC2018_FAMILY_CODES["PortScan"] == 3
    assert len(set(CIC2018_FAMILY_CODES.values())) == len(CIC2018_FAMILY_CODES)


def test_unsw_feature_mapping_is_partial_and_names_the_gaps():
    status = feature_status(UNSW_TIER_A_MAP)
    assert status["available"] == 8
    assert status["missing"] == 4
    missing = {
        name for name, row in status["features"].items() if not row["present"]
    }
    assert missing == {
        "packet_length_max",
        "syn_flag_count",
        "fin_flag_count",
        "rst_flag_count",
    }


def test_missing_policy_fills_only_the_absent_columns():
    frame = pd.DataFrame(
        {
            "flow_duration": [1.0, 2.0],
            "total_fwd_packets": [3.0, 4.0],
            "total_backward_packets": [5.0, 6.0],
            "total_length_of_fwd_packets": [7.0, 8.0],
            "total_length_of_bwd_packets": [9.0, 10.0],
            "flow_packets_s": [11.0, 12.0],
            "flow_bytes_s": [13.0, 14.0],
            "packet_length_mean": [15.0, 16.0],
        }
    )
    medians = {feature: 100.0 + index for index, feature in enumerate(TIER_A_FEATURES)}
    result = apply_missing_policy(frame, medians)
    assert list(result.columns) == TIER_A_FEATURES
    for feature in (
        "packet_length_max",
        "syn_flag_count",
        "fin_flag_count",
        "rst_flag_count",
    ):
        assert result[feature].tolist() == [medians[feature], medians[feature]]
    assert result["flow_duration"].tolist() == [1.0, 2.0]


def test_psi_is_zero_for_an_identical_distribution():
    values = np.linspace(0.0, 100.0, 5000)
    assert psi(values, values) == pytest.approx(0.0, abs=1e-9)


def test_psi_grows_when_the_distribution_shifts():
    reference = np.linspace(0.0, 100.0, 5000)
    shifted = reference + 50.0
    assert psi(reference, shifted) > psi(reference, reference)


def test_ks_is_zero_for_an_identical_distribution():
    values = np.linspace(0.0, 100.0, 5000)
    assert ks_statistic(values, values) == pytest.approx(0.0, abs=1e-12)


def test_metrics_report_ppv_at_the_observed_prevalence():
    scores = np.array([0.9, 0.8, 0.2, 0.1])
    truth = np.array([1, 0, 1, 0], dtype=np.int8)
    family_codes = np.array([1, 0, 1, 0], dtype=np.int8)
    families = ("Normal", "DoS", "Excluded")
    row = metrics_at_threshold(scores, truth, family_codes, families, 0.85)
    assert (row["tp"], row["fp"], row["tn"], row["fn"]) == (1, 0, 2, 1)
    assert row["prevalence"] == pytest.approx(0.5)
    assert row["recall"] == pytest.approx(0.5)
    assert row["fpr"] == pytest.approx(0.0)
    assert row["ppv"] == pytest.approx(1.0)
    assert row["ppv_at_1_percent_prevalence"] == pytest.approx(1.0)


def test_external_budget_threshold_spends_the_budget():
    scores = np.array([0.9] * 10 + [0.1] * 90)
    threshold = external_budget_threshold(scores, 100)
    assert threshold == pytest.approx(0.9)
    row = tie_aware_metrics(
        scores,
        np.array([1] * 10 + [0] * 90, dtype=np.int8),
        np.zeros(100, dtype=np.int8),
        ("Normal",),
        threshold,
        100,
    )
    assert row["expected_alerts"] == pytest.approx(1.0)


def test_tie_aware_metrics_fill_the_budget_from_ties():
    scores = np.array([1.0] * 10 + [0.0] * 90)
    truth = np.array([1] * 3 + [0] * 7 + [0] * 90, dtype=np.int8)
    family_codes = np.array([1] * 3 + [0] * 97, dtype=np.int8)
    families = ("Normal", "DoS", "Excluded")
    row = tie_aware_metrics(scores, truth, family_codes, families, 1.0, 100)
    assert row["strict_alerts"] == 0
    assert row["tie_count"] == 10
    assert row["tie_positive_rate"] == pytest.approx(0.3)
    assert row["k"] == 1
    assert row["expected_alerts"] == pytest.approx(1.0)
    assert row["expected_tp"] == pytest.approx(0.3)
    assert row["expected_fp"] == pytest.approx(0.7)
    assert row["expected_recall"] == pytest.approx(0.1)
    assert row["expected_ppv"] == pytest.approx(0.3)


def test_tie_aware_metrics_cap_at_the_tie_pool():
    scores = np.array([1.0] * 2 + [0.0] * 98)
    truth = np.array([1, 0] + [0] * 98, dtype=np.int8)
    row = tie_aware_metrics(scores, truth, np.zeros(100, dtype=np.int8), ("Normal",), 1.0, 1000)
    assert row["selected_from_ties"] == 2
    assert row["expected_alerts"] == pytest.approx(2.0)


def test_full_feature_hash_uses_columns_outside_tier_a():
    base = pd.DataFrame(
        {
            "flow_duration": [1.0, 1.0],
            "total_fwd_packets": [2.0, 2.0],
            "unused_extra": [10.0, 20.0],
        }
    )
    hashes = _full_feature_hashes(base, exclude=("label",))
    assert hashes[0] != hashes[1]


def test_split_metadata_is_json_serializable():
    families = np.repeat(["BENIGN", "PortScan"], 50).astype(object)
    groups = np.arange(len(families), dtype=np.uint64)
    split = stratified_group_split(groups, families)
    payload = serializable_split(split)
    assert "partition" not in payload
    json.dumps(payload)  # must not raise


def test_report_and_results_payload_are_json_serializable():
    rng = np.random.default_rng(7)
    reference = rng.random((200, 12)).astype(np.float32)
    matrix = rng.random((60, 12)).astype(np.float32)
    truth = np.array([1, 0] * 30, dtype=np.int8)
    family_codes = np.array([1, 0] * 30, dtype=np.int8)
    scores = rng.random(60)
    result = {
        "dataset": "unsw_nb15",
        "files": ["synthetic.csv"],
        "raw_rows": 60,
        "header_rows": 0,
        "unique_rows": 60,
        "duplicate_rows": 0,
        "scores": scores,
        "truth": truth,
        "family_codes": family_codes,
        "matrix": matrix,
        "families": ("Normal", "DoS", "Reconnaissance", "Excluded"),
        "available_features": list(TIER_A_FEATURES),
    }
    thresholds = {"100_per_10k": {"threshold": 0.5}}
    dataset = _dataset_payload(result, reference, thresholds, {})
    payload = {
        "status": "PARTIAL",
        "schema": schema_payload(),
        "model_sha256": "0" * 64,
        "serving_sha256": "1" * 64,
        "training": {
            "coverage_gate": {
                "families": {"DoS": {"train": 1, "validation": 1, "test": 1}},
                "reason": "synthetic",
            }
        },
        "datasets": [dataset],
        "negative_transfer": _negative_transfer_text([dataset]),
    }
    json.dumps(payload, allow_nan=False)
    report = render_report(payload)
    assert "UNSW-NB15" not in report or "unsw_nb15" in report
    assert "PPV @ 1%" in report


def test_group_split_is_deterministic_and_covers_every_family():
    families = np.repeat(
        [
            "BENIGN",
            "DDoS",
            "DoS Hulk",
            "DoS GoldenEye",
            "DoS slowloris",
            "DoS Slowhttptest",
            "PortScan",
        ],
        100,
    ).astype(object)
    groups = np.arange(len(families), dtype=np.uint64)

    first = stratified_group_split(groups, families)
    second = stratified_group_split(groups, families)
    assert np.array_equal(first["partition"], second["partition"])
    assert first["mixed_groups_dropped"] == 0

    counts = partition_counts(first["partition"], families)
    gate = coverage_gate(counts)
    assert gate["overall_pass"] is True
    for family in (
        "DDoS",
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest",
        "PortScan",
    ):
        for partition in ("train", "validation", "test"):
            assert counts[partition][family] > 0


def test_coverage_gate_fails_when_a_required_family_is_absent():
    counts = {
        "train": {"BENIGN": 10, "DDoS": 2, "DoS Hulk": 2, "PortScan": 2},
        "validation": {"BENIGN": 10, "DDoS": 2, "DoS Hulk": 2, "PortScan": 2},
        "test": {"BENIGN": 10, "DDoS": 2, "DoS Hulk": 2, "PortScan": 2},
    }
    gate = coverage_gate(counts)
    assert gate["overall_pass"] is False
    assert "DoS GoldenEye" in gate["missing_required"]


def test_serving_artifact_hash_is_unchanged():
    if not os.path.exists(SERVING_ARTIFACT):
        pytest.skip("serving artifact is not present in this checkout")
    assert _sha256_file(SERVING_ARTIFACT) == SERVING_SHA256


def test_transfer_artifact_is_not_the_serving_artifact():
    assert os.path.abspath(TRANSFER_MODEL) != os.path.abspath(SERVING_ARTIFACT)
    if os.path.exists(TRANSFER_MODEL):
        assert _sha256_file(TRANSFER_MODEL) != SERVING_SHA256
