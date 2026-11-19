"""Collector heartbeat validation and fleet-state tests."""

from datetime import datetime, timedelta, timezone

import pytest

from domain.sensor_fleet import (
    SensorReportError,
    fleet_entry,
    merge_fleet,
    parse_report,
)


def test_parse_report_keeps_missing_metrics_missing():
    report = parse_report(
        {
            "sensor_id": "probe-a",
            "interface": "eth0",
            "capture_driver": "AF_PACKET",
            "rx_bytes": 1024,
        }
    )
    assert report["sensor_id"] == "probe-a"
    assert report["vector"] == "ethernet"
    assert report["vector_basis"] == "name_heuristic"
    assert report["capture_driver"] == "AF_PACKET"
    assert report["rx_bytes"] == 1024
    assert report["rx_dropped"] is None
    assert report["link_speed_mbps"] is None


def test_parse_report_accepts_collector_reported_vector():
    report = parse_report({"sensor_id": "probe-b", "interface": "en0", "vector": "wlan"})
    assert report["vector"] == "wlan"
    assert report["vector_basis"] == "collector_reported"


@pytest.mark.parametrize(
    "payload,message",
    [
        ({}, "sensor_id is required"),
        ({"sensor_id": "x", "rx_dropped": -1}, "finite, non-negative"),
        ({"sensor_id": "x", "rx_dropped": "many"}, "must be numeric"),
        ({"sensor_id": "x", "vector": "satellite"}, "not a supported"),
        ({"sensor_id": "x", "reported_at": "yesterday"}, "ISO-8601"),
        ({"sensor_id": "x" * 81}, "at most 80"),
        ({"sensor_id": "bad\nname"}, "control characters"),
    ],
)
def test_parse_report_rejects_invalid_values(payload, message):
    with pytest.raises(SensorReportError, match=message):
        parse_report(payload)


def _report(**overrides):
    base = {
        "sensor_id": "probe-a",
        "interface": "eth0",
        "vector": "ethernet",
        "vector_basis": "name_heuristic",
        "rx_packets": 1000,
        "rx_dropped": 2,
        "reported_at": datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
        "received_at": datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
    }
    base.update(overrides)
    return base


def test_fleet_status_is_derived_from_the_last_heartbeat():
    now = datetime(2026, 1, 1, 12, 1, tzinfo=timezone.utc)
    online = fleet_entry(_report(), now=now, offline_after_seconds=90)
    assert online["status"] == "online"
    assert online["heartbeat_source"] == "collector"
    assert online["rx_drop_rate"] == pytest.approx(0.002)

    stale = fleet_entry(
        _report(received_at=now - timedelta(minutes=10)),
        now=now,
        offline_after_seconds=90,
    )
    assert stale["status"] == "stale"

    never = fleet_entry(
        None,
        now=now,
        offline_after_seconds=90,
        flow_stats={"sensor_id": "probe-c", "interface": "wlan0", "total": 4},
    )
    assert never["status"] == "never_reported"
    assert never["heartbeat_source"] == "flow records only"
    assert never["flows_total"] == 4
    assert never["rx_drop_rate"] is None


def test_merge_fleet_does_not_invent_missing_metrics():
    now = datetime(2026, 1, 1, 12, 1, tzinfo=timezone.utc)
    payload = merge_fleet(
        [_report()],
        [{"sensor_id": "probe-a", "interface": "eth0", "total": 9, "attacks": 2}],
        now=now,
    )
    assert payload["sensor_count"] == 1
    assert payload["online_count"] == 1
    assert payload["stale_count"] == 0
    assert payload["sensors"][0]["flows_total"] == 9
    assert payload["sensors"][0]["link_speed_mbps"] is None
    assert payload["heartbeat_source"] == "collector-reported metrics only"

