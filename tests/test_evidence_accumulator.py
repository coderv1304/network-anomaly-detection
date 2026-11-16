"""Tests for Slips-style host/window evidence accumulation and calibration."""

from __future__ import annotations

import json
import math

import pytest

from evidence_accumulator import (
    EvidenceAccumulator,
    Observation,
    isolation_confidence,
    load_calibrator,
)


def _observation(**overrides):
    values = {
        "source_ip": "203.0.113.9",
        "timestamp": 1_700_000_000.0,
        "supervised_probability": 1.0,
        "unsupervised_confidence": None,
        "reputation_score": None,
        "supervised_calibration": "isotonic-v1",
        "tenant_id": 1,
    }
    values.update(overrides)
    return Observation(**values)


def test_one_signal_cannot_open_an_incident():
    accumulator = EvidenceAccumulator()
    result = accumulator.observe(_observation(supervised_probability=1.0))
    assert result["risk_points"] == pytest.approx(50.0)
    assert result["active_signals"] == 1
    assert result["incident_open"] is False
    assert accumulator.snapshot(tenant_id=1)["count"] == 0


def test_two_independent_signals_open_an_incident():
    accumulator = EvidenceAccumulator()
    first = accumulator.observe(
        _observation(supervised_probability=1.0, unsupervised_confidence=None)
    )
    assert first["incident_open"] is False
    second = accumulator.observe(
        _observation(supervised_probability=1.0, unsupervised_confidence=1.0)
    )
    assert second["risk_points"] == pytest.approx(85.0)
    assert second["active_signals"] == 2
    assert second["incident_open"] is True
    snapshot = accumulator.snapshot(tenant_id=1)
    assert snapshot["count"] == 1
    assert snapshot["incidents"][0]["incident_id"] == "203.0.113.9:1699999800"
    assert snapshot["incidents"][0]["flow_count"] == 2


def test_reputation_and_supervised_signal_open_an_incident():
    accumulator = EvidenceAccumulator()
    result = accumulator.observe(
        _observation(supervised_probability=1.0, reputation_score=100.0)
    )
    assert result["risk_points"] == pytest.approx(95.0)
    assert result["incident_open"] is True
    assert any("reputation" in item for item in result["evidence"])


def test_points_are_capped_per_signal_per_window():
    accumulator = EvidenceAccumulator()
    for _ in range(100):
        accumulator.observe(
            _observation(supervised_probability=1.0, unsupervised_confidence=1.0)
        )
    snapshot = accumulator.snapshot(tenant_id=1)
    incident = snapshot["incidents"][0]
    assert incident["flow_count"] == 100
    assert incident["points"]["supervised"] == pytest.approx(50.0)
    assert incident["points"]["unsupervised"] == pytest.approx(35.0)
    assert incident["risk_points"] == pytest.approx(85.0)


def test_low_confidence_signals_contribute_nothing():
    accumulator = EvidenceAccumulator()
    result = accumulator.observe(
        _observation(
            supervised_probability=0.2,
            unsupervised_confidence=0.2,
            reputation_score=10.0,
        )
    )
    assert result["risk_points"] == 0.0
    assert result["active_signals"] == 0
    assert result["incident_open"] is False


def test_window_rollover_creates_a_new_window():
    accumulator = EvidenceAccumulator(window_seconds=300)
    accumulator.observe(
        _observation(timestamp=1_700_000_000.0, supervised_probability=1.0, unsupervised_confidence=1.0)
    )
    later = accumulator.observe(
        _observation(timestamp=1_700_000_400.0, supervised_probability=1.0, unsupervised_confidence=1.0)
    )
    assert later["incident_id"] != "203.0.113.9:1699999800"
    assert later["risk_points"] == pytest.approx(85.0)
    assert accumulator.snapshot(tenant_id=1)["count"] == 2


def test_tenants_are_isolated():
    accumulator = EvidenceAccumulator()
    accumulator.observe(
        _observation(tenant_id=1, supervised_probability=1.0, unsupervised_confidence=1.0)
    )
    accumulator.observe(
        _observation(
            tenant_id=2,
            source_ip="198.51.100.4",
            supervised_probability=1.0,
            unsupervised_confidence=1.0,
        )
    )
    assert accumulator.snapshot(tenant_id=1)["count"] == 1
    assert accumulator.snapshot(tenant_id=2)["count"] == 1
    assert accumulator.snapshot(tenant_id=999)["count"] == 0


def test_snapshot_is_json_serializable():
    accumulator = EvidenceAccumulator()
    accumulator.observe(
        _observation(supervised_probability=1.0, unsupervised_confidence=1.0)
    )
    json.dumps(accumulator.snapshot(tenant_id=1), allow_nan=False)


def test_window_tracks_destination_fanout():
    accumulator = EvidenceAccumulator()
    for port in range(1, 31):
        accumulator.observe(
            _observation(
                supervised_probability=0.9,
                unsupervised_confidence=1.0,
                destination_ip=f"198.51.100.{port}",
                destination_port=port,
            )
        )
    incident = accumulator.snapshot(tenant_id=1)["incidents"][0]
    assert incident["distinct_destination_ports"] == 30
    assert incident["distinct_destination_ips"] == 30


def test_source_ip_is_required():
    accumulator = EvidenceAccumulator()
    with pytest.raises(ValueError):
        accumulator.observe(_observation(source_ip=""))


def test_isotonic_calibrator_is_monotone(tmp_path):
    path = tmp_path / "calibration.json"
    path.write_text(
        json.dumps(
            {
                "method": "isotonic",
                "parameters": {
                    "isotonic_x": [0.0, 0.5, 1.0],
                    "isotonic_y": [0.1, 0.6, 0.9],
                },
            }
        ),
        encoding="utf-8",
    )
    calibrate, metadata = load_calibrator(str(path))
    assert metadata["method"] == "isotonic"
    assert calibrate(0.0) == pytest.approx(0.1)
    assert calibrate(0.25) == pytest.approx(0.1)
    assert calibrate(0.5) == pytest.approx(0.6)
    assert calibrate(1.0) == pytest.approx(0.9)
    assert calibrate(2.0) == pytest.approx(0.9)


def test_platt_calibrator_loads(tmp_path):
    path = tmp_path / "platt.json"
    path.write_text(
        json.dumps({"method": "platt", "parameters": {"platt_a": 2.0, "platt_b": 0.0}}),
        encoding="utf-8",
    )
    calibrate, _ = load_calibrator(str(path))
    assert calibrate(0.0) == pytest.approx(0.5)
    assert calibrate(10.0) == pytest.approx(1.0, abs=1e-6)


def test_unknown_calibrator_fails_loudly(tmp_path):
    path = tmp_path / "calibration.json"
    path.write_text(json.dumps({"method": "magic"}), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported calibration"):
        load_calibrator(str(path))


def test_isolation_confidence_is_centred_on_the_threshold():
    assert isolation_confidence(0.1, threshold=0.1) == pytest.approx(0.5)
    assert isolation_confidence(0.2, threshold=0.1) > 0.5
    assert isolation_confidence(0.0, threshold=0.1) < 0.5
    assert isolation_confidence(None, threshold=0.1) is None
    assert isolation_confidence(float("nan"), threshold=0.1) is None
    assert math.isfinite(isolation_confidence(1e9, threshold=0.1))
