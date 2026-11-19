"""Collector heartbeat validation and fleet presentation.

The fleet grid is only as honest as the data collectors send. There is no
synthetic bandwidth, no invented packet-drop percentage, and no "DPDK" label
unless the collector explicitly reports that driver. A sensor that has never
reported is shown as ``never_reported``; a sensor whose last heartbeat is older
than ``SENSOR_OFFLINE_SECONDS`` is shown as ``stale``.
"""

from __future__ import annotations

import math
import os
from datetime import datetime, timezone

from .capture_metadata import classify_ingestion_vector

DEFAULT_OFFLINE_SECONDS = 90
MAX_INTERFACE_LENGTH = 120
MAX_SENSOR_LENGTH = 80
MAX_DRIVER_LENGTH = 40
MAX_LINK_TYPE_LENGTH = 40

_NON_NEGATIVE_NUMBERS = (
    "rx_bytes",
    "tx_bytes",
    "rx_packets",
    "tx_packets",
    "rx_dropped",
    "tx_dropped",
    "uptime_seconds",
)


class SensorReportError(ValueError):
    """Raised when a heartbeat contains an invalid or unsafe value."""


def offline_seconds() -> int:
    try:
        value = int(os.environ.get("SENSOR_OFFLINE_SECONDS", DEFAULT_OFFLINE_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_OFFLINE_SECONDS
    return max(30, min(value, 3600))


def _clean_text(value, field: str, maximum: int, *, required: bool = False) -> str:
    text = "" if value is None else str(value).strip()
    if required and not text:
        raise SensorReportError(f"{field} is required")
    if len(text) > maximum:
        raise SensorReportError(f"{field} must be at most {maximum} characters")
    if any(ord(char) < 32 for char in text):
        raise SensorReportError(f"{field} contains control characters")
    return text


def _number(value, field: str) -> float | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise SensorReportError(f"{field} must be numeric") from exc
    if not math.isfinite(number) or number < 0:
        raise SensorReportError(f"{field} must be a finite, non-negative number")
    return number


def parse_report(payload: dict) -> dict:
    """Validate a collector heartbeat. Unknown fields are rejected by the route."""
    if not isinstance(payload, dict):
        raise SensorReportError("A JSON object is required")
    sensor_id = _clean_text(
        payload.get("sensor_id"), "sensor_id", MAX_SENSOR_LENGTH, required=True
    )
    interface = _clean_text(payload.get("interface"), "interface", MAX_INTERFACE_LENGTH)
    description = _clean_text(
        payload.get("interface_description"), "interface_description", 200
    )
    vector_info = classify_ingestion_vector(interface, description)
    reported_vector = _clean_text(payload.get("vector"), "vector", 24).lower()
    if reported_vector:
        if reported_vector not in {
            "ethernet",
            "wlan",
            "wwan",
            "vpn",
            "virtual",
            "loopback",
            "unknown",
        }:
            raise SensorReportError("vector is not a supported ingestion vector")
        vector = reported_vector
        vector_basis = "collector_reported"
    else:
        vector = vector_info["vector"]
        vector_basis = vector_info["basis"]

    report = {
        "sensor_id": sensor_id,
        "interface": interface,
        "interface_description": description,
        "vector": vector,
        "vector_basis": vector_basis,
        "capture_driver": _clean_text(
            payload.get("capture_driver"), "capture_driver", MAX_DRIVER_LENGTH
        ),
        "link_type": _clean_text(payload.get("link_type"), "link_type", MAX_LINK_TYPE_LENGTH),
        "link_speed_mbps": _number(payload.get("link_speed_mbps"), "link_speed_mbps"),
    }
    for field in _NON_NEGATIVE_NUMBERS:
        report[field] = _number(payload.get(field), field)

    collector_time = payload.get("reported_at")
    if collector_time in (None, ""):
        report["reported_at"] = datetime.now(timezone.utc)
    else:
        try:
            parsed = datetime.fromisoformat(str(collector_time).replace("Z", "+00:00"))
        except ValueError as exc:
            raise SensorReportError("reported_at must be an ISO-8601 timestamp") from exc
        report["reported_at"] = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return report


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def fleet_entry(
    report: dict | None,
    *,
    now: datetime,
    offline_after_seconds: int,
    flow_stats: dict | None = None,
) -> dict:
    """Build one fleet row from a stored heartbeat and optional flow counts."""
    flows = flow_stats or {}
    base = {
        "sensor_id": (report or {}).get("sensor_id") or flows.get("sensor_id"),
        "interface": (report or {}).get("interface") or flows.get("interface") or "",
        "vector": (report or {}).get("vector") or "unknown",
        "vector_basis": (report or {}).get("vector_basis") or "unknown",
        "capture_driver": (report or {}).get("capture_driver") or None,
        "link_type": (report or {}).get("link_type") or None,
        "link_speed_mbps": (report or {}).get("link_speed_mbps"),
        "rx_bytes": (report or {}).get("rx_bytes"),
        "tx_bytes": (report or {}).get("tx_bytes"),
        "rx_packets": (report or {}).get("rx_packets"),
        "tx_packets": (report or {}).get("tx_packets"),
        "rx_dropped": (report or {}).get("rx_dropped"),
        "tx_dropped": (report or {}).get("tx_dropped"),
        "uptime_seconds": (report or {}).get("uptime_seconds"),
        "reported_at": _iso((report or {}).get("reported_at")),
        "flows_total": flows.get("total"),
        "flows_attacks": flows.get("attacks"),
        "flows_last_seen": flows.get("last_seen"),
    }
    received = (report or {}).get("received_at") or (report or {}).get("reported_at")
    if received is None:
        base["status"] = "never_reported"
        base["age_seconds"] = None
        base["heartbeat_source"] = "flow records only"
        base["rx_drop_rate"] = None
        return base
    if received.tzinfo is None:
        received = received.replace(tzinfo=timezone.utc)
    age = max(0.0, (now - received.astimezone(timezone.utc)).total_seconds())
    base["age_seconds"] = round(age, 1)
    base["status"] = "online" if age <= offline_after_seconds else "stale"
    base["heartbeat_source"] = "collector"
    dropped = base["rx_dropped"]
    packets = base["rx_packets"]
    base["rx_drop_rate"] = (
        round(dropped / packets, 8)
        if dropped is not None and packets
        else None
    )
    return base


def merge_fleet(reports: list[dict], flow_rows: list[dict], *, now: datetime | None = None) -> dict:
    """Merge heartbeats and flow-derived sensors without inventing either."""
    now = now or datetime.now(timezone.utc)
    offline = offline_seconds()
    flow_by_key = {
        (row.get("sensor_id"), row.get("interface") or ""): row
        for row in flow_rows
        if row.get("sensor_id")
    }
    by_key: dict[tuple, dict] = {
        key: fleet_entry(
            None,
            now=now,
            offline_after_seconds=offline,
            flow_stats=row,
        )
        for key, row in flow_by_key.items()
    }
    for report in reports:
        key = (report.get("sensor_id"), report.get("interface") or "")
        by_key[key] = fleet_entry(
            report,
            now=now,
            offline_after_seconds=offline,
            flow_stats=flow_by_key.get(key),
        )

    entries = sorted(
        by_key.values(),
        key=lambda row: (
            0 if row["status"] == "online" else 1,
            str(row.get("sensor_id") or ""),
            str(row.get("interface") or ""),
        ),
    )
    return {
        "sensors": entries,
        "sensor_count": len({row["sensor_id"] for row in entries if row.get("sensor_id")}),
        "online_count": sum(1 for row in entries if row["status"] == "online"),
        "stale_count": sum(1 for row in entries if row["status"] == "stale"),
        "never_reported_count": sum(
            1 for row in entries if row["status"] == "never_reported"
        ),
        "offline_after_seconds": offline,
        "heartbeat_source": "collector-reported metrics only",
        "note": (
            "Bandwidth, packet drops and capture driver are displayed only when a "
            "collector reports them. Missing values stay null; none are synthesised."
        ),
    }

