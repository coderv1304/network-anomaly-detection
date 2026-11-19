"""Tests for the Phase 3 host/window incident evaluation.

Two layers are covered:

1. The accumulator's calibrated scoring mode, which is what the evaluation
   actually measures (benign fan-out must not open incidents, corroborating
   attack flows must consolidate into one incident).
2. The batch helpers used to score a million flows, including the a-priori
   claim that the vectorised points equal the scalar accumulator path and that
   Wednesday-only tuning respects its false-incident target.
"""

from __future__ import annotations

import numpy as np
import pytest

from domain.evidence_accumulator import (
    DEFAULT_PER_FLOW_CAP,
    DEFAULT_P_FLOOR,
    EvidenceAccumulator,
    Observation,
    calibrated_flow_points,
)
from scripts.evaluate_window_incidents import (
    WINDOW_SECONDS,
    flows_to_detection,
    tune_window_parameters,
    window_index,
    window_points,
    window_totals,
)

THRESHOLD = 70.0
CAP = DEFAULT_PER_FLOW_CAP


def _observation(source_ip: str, timestamp: float, probability: float) -> Observation:
    return Observation(
        source_ip=source_ip,
        timestamp=timestamp,
        supervised_probability=probability,
        supervised_calibration="phase2-sigmoid",
    )


def _calibrated_accumulator(**overrides) -> EvidenceAccumulator:
    values = {
        "window_seconds": WINDOW_SECONDS,
        "incident_threshold": THRESHOLD,
        "scoring_mode": "calibrated",
        "p_floor": DEFAULT_P_FLOOR,
        "per_flow_cap": CAP,
    }
    values.update(overrides)
    return EvidenceAccumulator(**values)


# ---------------------------------------------------------------------------
# Required behaviour: benign fan-out and attack consolidation
# ---------------------------------------------------------------------------
def test_high_volume_benign_client_produces_no_incident():
    """50 low-probability flows from one host must not open an incident.

    A DNS resolver or CDN egress address emits far more than 50 flows per five
    minutes. If volume alone were evidence, those hosts would dominate the
    incident queue.
    """
    accumulator = _calibrated_accumulator()
    result = None
    for index in range(50):
        result = accumulator.observe(
            _observation("203.0.113.10", 1_700_000_000.0 + index, 0.2)
        )

    assert result is not None
    assert result["flow_count"] == 50
    assert result["risk_points"] == 0.0
    assert result["active_signals"] == 0
    assert result["incident_open"] is False
    assert accumulator.snapshot(open_only=True)["count"] == 0


def test_just_below_floor_also_contributes_nothing():
    """The floor, not the cap, is what suppresses a borderline benign host."""
    accumulator = _calibrated_accumulator()
    for index in range(50):
        accumulator.observe(
            _observation("203.0.113.11", 1_700_000_000.0 + index, DEFAULT_P_FLOOR - 0.05)
        )
    assert accumulator.snapshot(open_only=True)["count"] == 0


def test_five_attack_flows_collapse_to_one_incident():
    """5 flows -> 1 incident, i.e. a 5x reduction in alert units."""
    accumulator = _calibrated_accumulator()
    for index in range(5):
        accumulator.observe(
            _observation("198.51.100.7", 1_700_000_000.0 + index, 0.95)
        )

    snapshot = accumulator.snapshot(open_only=True)
    assert snapshot["count"] == 1
    incident = snapshot["incidents"][0]
    assert incident["flow_count"] == 5
    assert incident["incident_open"] is True
    # The per-window cap is reached, so extra flows cannot inflate the score.
    assert incident["risk_points"] == pytest.approx(100.0)
    assert incident["signal_hits"]["supervised"] == 2


def test_single_high_confidence_flow_cannot_open_an_incident():
    """One flow is capped below the threshold by construction."""
    accumulator = _calibrated_accumulator()
    result = accumulator.observe(
        _observation("198.51.100.8", 1_700_000_000.0, 0.999999)
    )
    assert result["risk_points"] == pytest.approx(CAP)
    assert result["risk_points"] < THRESHOLD
    assert result["incident_open"] is False


def test_two_corroborating_flows_open_exactly_one_incident():
    accumulator = _calibrated_accumulator()
    accumulator.observe(_observation("198.51.100.9", 1_700_000_000.0, 0.95))
    second = accumulator.observe(_observation("198.51.100.9", 1_700_000_060.0, 0.95))
    assert second["incident_open"] is True
    assert accumulator.snapshot(open_only=True)["count"] == 1


def test_window_rollover_starts_a_new_incident():
    accumulator = _calibrated_accumulator()
    for index in range(5):
        accumulator.observe(
            _observation("198.51.100.10", 1_700_000_000.0 + index, 0.95)
        )
    for index in range(5):
        accumulator.observe(
            _observation("198.51.100.10", 1_700_000_400.0 + index, 0.95)
        )
    assert accumulator.snapshot(open_only=True)["count"] == 2


def test_reset_clears_state_between_batch_runs():
    accumulator = _calibrated_accumulator()
    for index in range(5):
        accumulator.observe(
            _observation("198.51.100.11", 1_700_000_000.0 + index, 0.95)
        )
    assert accumulator.snapshot(open_only=True)["count"] == 1

    accumulator.reset()
    assert accumulator.snapshot(open_only=True)["count"] == 0

    # The same observations must reopen exactly the same single incident, not
    # a second one, which would mean state leaked across runs.
    for index in range(5):
        accumulator.observe(
            _observation("198.51.100.11", 1_700_000_000.0 + index, 0.95)
        )
    assert accumulator.snapshot(open_only=True)["count"] == 1


def test_calibrated_mode_rejects_a_cap_that_allows_single_flow_incidents():
    with pytest.raises(ValueError, match="per_flow_cap < incident_threshold"):
        _calibrated_accumulator(incident_threshold=40.0)
    with pytest.raises(ValueError, match="window_cap >= incident_threshold"):
        _calibrated_accumulator(window_cap=50.0, incident_threshold=70.0)


def test_default_mode_is_unchanged_by_the_calibrated_addition():
    """A single supervised signal must still be unable to open an incident."""
    accumulator = EvidenceAccumulator()
    result = accumulator.observe(_observation("203.0.113.12", 1_700_000_000.0, 1.0))
    assert accumulator.scoring_mode == "multi_signal"
    assert result["risk_points"] == pytest.approx(50.0)
    assert result["incident_open"] is False


# ---------------------------------------------------------------------------
# Batch arithmetic must equal the shipped accumulator
# ---------------------------------------------------------------------------
def test_vectorised_points_match_the_scalar_accumulator():
    probabilities = np.array(
        [0.0, 0.1, DEFAULT_P_FLOOR, 0.51, 0.6, 0.75, 0.9, 0.99, 1.0]
    )
    vectorised = calibrated_flow_points(
        probabilities, p_floor=DEFAULT_P_FLOOR, per_flow_cap=CAP
    )
    accumulator = _calibrated_accumulator()
    scalar = np.array(
        [accumulator._supervised_points(float(value)) for value in probabilities]
    )
    assert np.allclose(vectorised, scalar, atol=0.0, rtol=0.0)
    assert vectorised[2] == 0.0  # exactly at the floor contributes nothing
    assert vectorised[-1] == pytest.approx(CAP)


def test_window_index_groups_by_host_and_bucket():
    hosts = np.array([1, 1, 1, 1, 2], dtype=np.int64)
    timestamps = np.array([0.0, 10.0, 299.0, 300.0, 10.0])
    inverse, n_windows = window_index(hosts, timestamps, WINDOW_SECONDS)
    assert n_windows == 3
    assert inverse[0] == inverse[1] == inverse[2]
    assert inverse[3] != inverse[0]
    assert inverse[4] != inverse[0]


def test_window_points_apply_the_window_cap():
    inverse = np.array([0, 0, 0, 1])
    points = np.array([CAP, CAP, CAP, 10.0])
    totals = window_points(inverse, points, 2)
    assert totals[0] == pytest.approx(100.0)
    assert totals[1] == pytest.approx(10.0)


def test_flows_to_detection_counts_attack_flows_until_the_trigger():
    # One window, five flows ordered in time: benign, then four attacks.
    inverse = np.array([0, 0, 0, 0, 0])
    timestamps = np.array([0.0, 1.0, 2.0, 3.0, 4.0])
    labels = np.array([0, 1, 1, 1, 1], dtype=np.int8)
    probabilities = np.full(5, 0.95)
    points = calibrated_flow_points(
        probabilities, p_floor=DEFAULT_P_FLOOR, per_flow_cap=CAP
    )
    totals = window_points(inverse, points, 1)
    alert = totals >= THRESHOLD
    assert alert[0]

    stats = flows_to_detection(
        inverse,
        timestamps,
        labels,
        points,
        alert,
        THRESHOLD,
        window_positives=np.array([4]),
    )
    # 70 points are reached after the second flow (50 + 50 capped), which is
    # one attack flow plus the benign preamble.
    assert stats["triggered_malicious_windows"] == 1
    assert stats["mean_attack_flows_before_trigger"] == pytest.approx(1.0)
    assert stats["mean_flows_before_trigger"] == pytest.approx(2.0)


def test_wednesday_tuning_respects_the_false_incident_target():
    # 40 benign hosts, one window each, no evidence.
    benign_hosts = np.repeat(np.arange(40, dtype=np.int64), 2)
    benign_times = np.tile(np.array([0.0, 60.0]), 40)
    benign_labels = np.zeros(len(benign_hosts), dtype=np.int8)
    benign_scores = np.full(len(benign_hosts), 0.2)

    # 10 malicious hosts with three corroborating flows each.
    attack_hosts = np.repeat(np.arange(100, 110, dtype=np.int64), 3)
    attack_times = np.tile(np.array([0.0, 1.0, 2.0]), 10)
    attack_labels = np.ones(len(attack_hosts), dtype=np.int8)
    attack_scores = np.full(len(attack_hosts), 0.95)

    tuning = tune_window_parameters(
        np.concatenate([benign_hosts, attack_hosts]),
        np.concatenate([benign_times, attack_times]),
        np.concatenate([benign_labels, attack_labels]),
        np.concatenate([benign_scores, attack_scores]),
    )

    assert tuning["feasible"] is True
    assert tuning["selected"]["benign_window_fpr"] <= tuning["target_window_fpr"]
    assert tuning["selected"]["window_recall"] == pytest.approx(1.0)
    assert tuning["benign_windows"] == 40
    assert tuning["malicious_windows"] == 10


def test_burst_definition_needs_three_attack_flows():
    from scripts.evaluate_window_incidents import _window_confusion

    positives = np.array([0, 1, 2, 3, 5])
    alert = np.array([True, True, True, True, False])
    primary = _window_confusion(positives, alert, label="p", min_positives=1)
    burst = _window_confusion(positives, alert, label="b", min_positives=3)
    assert primary["tp"] == 3
    assert primary["fn"] == 1
    assert primary["fp"] == 1
    assert burst["tp"] == 1
    assert burst["fn"] == 1


def test_window_totals_sum_flow_evidence():
    inverse = np.array([0, 0, 1], dtype=np.int64)
    totals = window_totals(inverse, np.array([1.0, 2.0, 3.0]), 2)
    assert totals.tolist() == [3.0, 3.0]


def test_timestamps_are_seconds_such_that_a_300s_window_spans_five_minutes():
    """Guard against the ns/s mix-up that silently shrinks every window.

    A window boundary is ``floor(seconds / 300)``. Two flows five minutes apart
    must land in different windows, and two flows 60 s apart in the same one.
    """
    hosts = np.array([1, 1, 1], dtype=np.int64)
    base = 1_499_043_601.0  # 2017-07-03T08:55:01Z, a plausible capture epoch
    timestamps = np.array([base, base + 60.0, base + 300.0])
    inverse, n_windows = window_index(hosts, timestamps, WINDOW_SECONDS)
    assert n_windows == 2
    assert inverse[0] == inverse[1]
    assert inverse[2] != inverse[0]

    # A nanosecond epoch would overflow the int64 window key.
    with pytest.raises(Exception):
        window_index(hosts, timestamps * 1e9, WINDOW_SECONDS)

