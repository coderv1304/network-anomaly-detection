"""Tests for the S7 pilot analysis harness."""

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.pilot_analysis import analyze, write_selftest_inputs  # noqa: E402


def test_selftest_is_labelled_synthetic_and_computes_every_gate():
    directory = Path(tempfile.mkdtemp(prefix="s7_test_"))
    write_selftest_inputs(directory)

    result = analyze(directory, synthetic=True)

    assert result["verdict"] == "SELFTEST_ONLY"
    assert "SYNTHETIC" in result["evidence_status"]
    assert result["summary"]["reviewed_alerts"] == 440
    assert result["summary"]["analysts"] == 2
    assert result["onboarding"]["participants"] == 2
    assert result["support"]["tickets"] == 3
    assert {item["id"] for item in result["checks"]} == {
        "data_integrity",
        "sample_size",
        "onboarding",
        "alert_budget",
        "analyst_time",
        "yield",
        "false_positive_cost",
        "support_load",
        "model_stability",
        "pilot_status",
    }
    assert all(item["pass"] for item in result["checks"])


def test_overridden_criterion_can_fail_a_gate_without_relabelling_the_evidence():
    directory = Path(tempfile.mkdtemp(prefix="s7_test_"))
    write_selftest_inputs(directory)
    (directory / "criteria.json").write_text(
        json.dumps({"yield_min": 0.99}), encoding="utf-8"
    )

    result = analyze(directory, synthetic=True)

    yield_check = next(item for item in result["checks"] if item["id"] == "yield")
    assert yield_check["pass"] is False
    assert result["verdict"] == "SELFTEST_ONLY"


def test_missing_required_export_is_rejected():
    directory = Path(tempfile.mkdtemp(prefix="s7_test_"))
    write_selftest_inputs(directory)
    (directory / "daily.csv").unlink()

    with pytest.raises(SystemExit):
        analyze(directory, synthetic=True)


def test_missing_required_column_aborts_instead_of_crashing():
    directory = Path(tempfile.mkdtemp(prefix="s7_test_"))
    write_selftest_inputs(directory)
    reviews_path = directory / "reviews.csv"
    lines = reviews_path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split(",")
    keep = [index for index, name in enumerate(header) if name != "disposition"]
    trimmed = [",".join(row.split(",")[index] for index in keep) for row in lines]
    reviews_path.write_text("\n".join(trimmed) + "\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="disposition"):
        analyze(directory, synthetic=True)


def test_duplicate_alert_ids_fail_data_integrity():
    directory = Path(tempfile.mkdtemp(prefix="s7_test_"))
    write_selftest_inputs(directory)
    reviews_path = directory / "reviews.csv"
    reviews = reviews_path.read_text(encoding="utf-8").splitlines()
    reviews.insert(2, reviews[1])
    reviews_path.write_text("\n".join(reviews) + "\n", encoding="utf-8")

    result = analyze(directory, synthetic=True)

    integrity = next(item for item in result["checks"] if item["id"] == "data_integrity")
    assert integrity["pass"] is False
    assert any("duplicate alert_id" in issue for issue in integrity["observed"])
