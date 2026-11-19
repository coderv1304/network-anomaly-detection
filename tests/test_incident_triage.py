"""Incident severity, SLA, and triage validation."""

from datetime import datetime, timedelta, timezone

import pytest

from domain.incident_triage import (
    SEVERITY_POLICY,
    severity_for,
    sla_payload,
    triage_payload,
    validate_status,
)


def test_severity_is_internal_risk_points_not_cvss():
    p1 = severity_for(130, 3)
    assert p1["id"] == "P1"
    assert p1["basis"] == "internal_risk_points"
    assert "Not CVSS" in p1["note"] or "not CVSS" in p1["note"]
    assert p1["ack_minutes"] == 15

    assert severity_for(100, 2)["id"] == "P2"
    assert severity_for(70, 2)["id"] == "P3"
    assert severity_for(10, 1)["id"] == "P4"


def test_severity_requires_both_points_and_signals():
    # High points from one signal never reach P1/P2.
    assert severity_for(130, 1)["id"] == "P4"


def test_sla_counts_down_and_flags_overdue():
    opened = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    incident = {"incident_opened_at": opened.isoformat()}
    severity = severity_for(130, 3)

    early = sla_payload(
        incident, severity, now=opened + timedelta(minutes=5)
    )
    assert early["state"] == "open"
    assert early["remaining_seconds"] == 600

    late = sla_payload(
        incident, severity, now=opened + timedelta(minutes=30)
    )
    assert late["state"] == "overdue"
    assert late["remaining_seconds"] < 0

    acked = sla_payload(
        incident,
        severity,
        acknowledged_at=opened + timedelta(minutes=3),
        now=opened + timedelta(minutes=30),
    )
    assert acked["state"] == "acknowledged"
    assert acked["late"] is False


def test_triage_payload_closes_sla_for_suppressed_state():
    opened = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    incident = {
        "incident_opened_at": opened.isoformat(),
        "max_risk_points": 100,
        "active_signals": 2,
    }
    payload = triage_payload(
        incident,
        {"status": "suppressed", "updated_by": "analyst", "acknowledged_at": opened},
        now=opened + timedelta(hours=2),
    )
    assert payload["status"] == "suppressed"
    assert payload["persisted"] is True
    assert payload["severity"]["id"] == "P2"
    assert payload["sla"]["state"] == "closed"


def test_invalid_status_is_rejected():
    assert validate_status("Investigating") == "investigating"
    with pytest.raises(ValueError, match="status must be one of"):
        validate_status("deleted")


def test_policy_ids_are_stable():
    assert [rule["id"] for rule in SEVERITY_POLICY] == ["P1", "P2", "P3", "P4"]

