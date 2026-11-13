"""Hand-computed tests for the P2B protocol audit.

These tests use synthetic labels and payload fixtures. They never read the
production CSVs, the score caches, or the serving artifact.
"""

from __future__ import annotations

import numpy as np

from scripts.volumetric_model import (
    amendment_options,
    assess_feasibility,
    build_blocker,
    partition_summary,
    render_markdown,
)


def synthetic_labels() -> np.ndarray:
    return np.array(
        [
            "BENIGN",
            "BENIGN",
            "DDoS",
            "PortScan",
            "Heartbleed",
            "FTP-Patator",
            "Some Future Attack",
        ],
        dtype=object,
    )


def test_partition_summary_splits_primary_and_excluded_rows():
    summary = partition_summary(synthetic_labels())

    assert summary["rows"] == 7
    assert summary["primary_rows"] == 4
    assert summary["positives"] == 2
    assert summary["negatives"] == 2
    assert summary["excluded_rows"] == 3
    assert summary["benchmark_prevalence"] == 0.5
    assert summary["label_counts"]["BENIGN"] == 2
    assert summary["excluded_label_counts"] == {
        "FTP-Patator": 1,
        "Heartbleed": 1,
    }


def test_partition_summary_is_empty_safe():
    summary = partition_summary(np.array([], dtype=object))

    assert summary["rows"] == 0
    assert summary["primary_rows"] == 0
    assert summary["positives"] == 0
    assert summary["benchmark_prevalence"] is None


def test_zero_training_positives_blocks_supervised_families():
    feasibility = assess_feasibility(0)

    assert feasibility["supervised_binary_heads"] is False
    assert feasibility["logistic_regression"] is False
    assert feasibility["random_forest"] is False
    assert feasibility["isolation_forest"] is True
    assert feasibility["full_p2b_comparison"] is False
    assert "zero" in feasibility["reason"]


def test_positive_training_rows_allow_the_full_comparison():
    feasibility = assess_feasibility(25)

    assert feasibility["supervised_binary_heads"] is True
    assert feasibility["logistic_regression"] is True
    assert feasibility["random_forest"] is True
    assert feasibility["full_p2b_comparison"] is True


def test_blocker_is_none_when_training_positives_exist():
    summary = partition_summary(np.array(["BENIGN", "DDoS"], dtype=object))

    assert build_blocker(summary) is None


def test_blocker_records_the_zero_positive_evidence():
    summary = partition_summary(
        np.array(["BENIGN", "FTP-Patator", "SSH-Patator"], dtype=object)
    )

    blocker = build_blocker(summary)

    assert blocker["code"] == "training_partition_has_no_target_positives"
    assert blocker["evidence"]["train_positives"] == 0
    assert blocker["evidence"]["train_negatives"] == 1
    assert blocker["evidence"]["train_excluded_rows"] == 2
    assert "FTP-Patator" in blocker["evidence"]["train_excluded_labels"]


def test_amendments_are_logged_and_never_executed_here():
    options = amendment_options()

    assert {option["id"] for option in options} == {"A1", "A2", "A3", "A4"}
    assert all(option["requires"] for option in options)
    assert all(option["recommended"] for option in options)
    assert next(option for option in options if option["id"] == "A1")["recommended"].startswith(
        "yes"
    )


def _fixture_payload() -> dict:
    train = partition_summary(np.array(["BENIGN", "FTP-Patator"], dtype=object))
    train["days"] = ["Monday", "Tuesday"]
    train["rows_after_dedup"] = train["rows"]
    train["raw_rows"] = train["rows"]
    train["dedup_removed_rows"] = 0
    validation = partition_summary(np.array(["BENIGN", "DDoS"], dtype=object))
    validation["days"] = ["Wednesday"]
    validation["rows_after_dedup"] = validation["rows"]
    test = partition_summary(np.array(["BENIGN", "PortScan"], dtype=object))
    test["days"] = ["Thursday", "Friday"]
    test["rows_after_dedup"] = test["rows"]
    feasibility = assess_feasibility(train["positives"])
    return {
        "status": "blocked",
        "partitions": {
            "train": train,
            "validation": validation,
            "test": test,
        },
        "protocol": {
            "train_days": ["Monday", "Tuesday"],
            "validation_days": ["Wednesday"],
            "test_days": ["Thursday", "Friday"],
            "seeds": [42, 43, 44, 45, 46],
            "budgets_per_10k": [10, 100],
        },
        "blocker": build_blocker(train),
        "feasibility": feasibility,
        "amendments": amendment_options(),
    }


def test_render_markdown_reports_the_blocker_without_metrics():
    report = render_markdown(_fixture_payload())

    assert "# Volumetric Detector (Phase P2B)" in report
    assert "**Status:** BLOCKED" in report
    assert "training_partition_has_no_target_positives" in report
    assert "Rules remain the only evaluated Tier A baseline." in report
    assert "No Logistic Regression" in report
