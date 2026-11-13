"""Hand-computed tests for the P2B family-day confound analysis.

These tests use synthetic labels and timestamps. They never read the
production CSVs, the score caches, or the serving artifact.
"""

from __future__ import annotations

import numpy as np
import pytest

from scripts.p2b_protocol_analysis import (
    coverage_gate,
    expanding_folds,
    family_day_matrix,
    family_time_ranges,
    time_split,
)


def stamps(values: list[str]) -> np.ndarray:
    return np.array(values, dtype="datetime64[ns]")


def test_family_day_matrix_flags_disjoint_validation_and_test_families():
    matrix = family_day_matrix(
        train_counts={"BENIGN": 10, "FTP-Patator": 2},
        validation_counts={"BENIGN": 5, "DoS Hulk": 3},
        test_counts={"BENIGN": 7, "DDoS": 4, "PortScan": 2},
    )

    assert matrix["train_has_primary_positives"] is False
    assert matrix["partitions"]["train"]["primary_positives"] == 0
    assert matrix["partitions"]["validation"]["primary_positive_families"] == [
        "DoS Hulk"
    ]
    assert matrix["partitions"]["test"]["primary_positive_families"] == [
        "DDoS",
        "PortScan",
    ]
    assert matrix["validation_test_disjoint"] is True
    assert matrix["validation_test_overlap"] == []


def test_family_day_matrix_detects_overlap_when_present():
    matrix = family_day_matrix(
        train_counts={"BENIGN": 1, "DDoS": 1},
        validation_counts={"BENIGN": 1, "DDoS": 1},
        test_counts={"BENIGN": 1, "DDoS": 1},
    )

    assert matrix["train_has_primary_positives"] is True
    assert matrix["train_validation_overlap"] == ["DDoS"]
    assert matrix["validation_test_disjoint"] is False


def test_family_time_ranges_reports_first_last_and_primary_flag():
    labels = np.array(["BENIGN", "DoS Hulk", "BENIGN", "DDoS"], dtype=object)
    timestamps = stamps(
        [
            "2020-01-01T00:00:00",
            "2020-01-01T01:00:00",
            "2020-01-01T02:00:00",
            "2020-01-01T03:00:00",
        ]
    )

    ranges = family_time_ranges(labels, timestamps)

    assert ranges["BENIGN"]["count"] == 2
    assert ranges["BENIGN"]["first"] == "2020-01-01T00:00:00"
    assert ranges["BENIGN"]["last"] == "2020-01-01T02:00:00"
    assert ranges["BENIGN"]["is_primary"] is False
    assert ranges["DoS Hulk"]["is_primary"] is True
    assert ranges["DDoS"]["count"] == 1


def test_time_split_is_a_family_split_on_a_sequential_timeline():
    labels = np.array(["DoS Hulk"] * 5 + ["DDoS"] * 5, dtype=object)
    timestamps = stamps([f"2020-01-01T{hour:02d}:00:00" for hour in range(10)])

    split = time_split(labels, timestamps, 0.5)

    assert split["train"]["primary_positive_families"] == ["DoS Hulk"]
    assert split["validation"]["primary_positive_families"] == ["DDoS"]
    assert split["train"]["primary_positives"] == 5
    assert split["validation"]["primary_positives"] == 5
    assert split["cut_timestamp"] == "2020-01-01T05:00:00"


def test_time_split_stable_sort_keeps_original_order_for_equal_timestamps():
    labels = np.array(["BENIGN", "DDoS", "BENIGN", "PortScan"], dtype=object)
    timestamps = stamps(["2020-01-01T00:00:00"] * 4)

    split = time_split(labels, timestamps, 0.5)

    assert split["train"]["rows"] == 2
    assert split["validation"]["rows"] == 2
    assert split["train"]["label_counts"] == {"BENIGN": 1, "DDoS": 1}
    assert split["validation"]["label_counts"] == {"BENIGN": 1, "PortScan": 1}


def test_expanding_folds_can_show_a_degenerate_first_fold():
    labels = np.array(
        ["BENIGN"] * 3 + ["DoS Hulk"] * 3 + ["DDoS"] * 3, dtype=object
    )
    timestamps = stamps([f"2020-01-01T{hour:02d}:00:00" for hour in range(9)])

    folds = expanding_folds(labels, timestamps, 3)

    assert [fold["fold"] for fold in folds["folds"]] == [1, 2, 3]
    assert [fold["primary_positives"] for fold in folds["folds"]] == [0, 3, 3]
    assert folds["folds"][0]["primary_positive_families"] == []
    assert folds["folds"][1]["primary_positive_families"] == ["DoS Hulk"]
    assert folds["folds"][2]["primary_positive_families"] == ["DDoS"]


def test_invalid_split_parameters_are_rejected():
    labels = np.array(["BENIGN"], dtype=object)
    timestamps = stamps(["2020-01-01T00:00:00"])

    with pytest.raises(ValueError):
        time_split(labels, timestamps, 0.0)
    with pytest.raises(ValueError):
        time_split(labels, timestamps, 1.0)
    with pytest.raises(ValueError):
        expanding_folds(labels, timestamps, 1)


def test_coverage_gate_passes_when_every_partition_has_the_family():
    matrix = family_day_matrix(
        train_counts={"BENIGN": 1, "DDoS": 2},
        validation_counts={"BENIGN": 1, "DDoS": 2},
        test_counts={"BENIGN": 1, "DDoS": 2},
    )

    gate = coverage_gate(matrix)

    assert gate["overall_pass"] is True
    assert gate["families"]["DDoS"]["pass"] is True


def test_coverage_gate_fails_when_a_family_is_test_only():
    matrix = family_day_matrix(
        train_counts={"BENIGN": 1},
        validation_counts={"BENIGN": 1, "DoS Hulk": 2},
        test_counts={"BENIGN": 1, "DDoS": 2},
    )

    gate = coverage_gate(matrix)

    assert gate["overall_pass"] is False
    assert gate["families"]["DDoS"]["train"] == 0
    assert gate["families"]["DDoS"]["pass"] is False
    assert gate["families"]["DoS Hulk"]["test"] == 0


def test_coverage_gate_fails_on_disjoint_validation_and_test_families():
    matrix = family_day_matrix(
        train_counts={"BENIGN": 1, "DDoS": 1, "DoS Hulk": 1},
        validation_counts={"BENIGN": 1, "DoS Hulk": 1},
        test_counts={"BENIGN": 1, "DDoS": 1},
    )

    gate = coverage_gate(matrix)

    assert gate["overall_pass"] is False
    assert gate["families"]["DDoS"]["validation"] == 0
    assert gate["families"]["DoS Hulk"]["test"] == 0


def test_coverage_gate_fails_closed_on_an_empty_matrix():
    matrix = family_day_matrix({}, {}, {})

    gate = coverage_gate(matrix)

    assert gate["overall_pass"] is False
    assert gate["families"] == {}
