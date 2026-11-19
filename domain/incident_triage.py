"""Incident severity, SLA, and triage-state helpers.

This is an internal SOC workflow policy, not CVSS. CVSS scores a *vulnerability*
from a vector string; it cannot be computed from a flow risk score. Presenting a
flow incident as "CVSS 8.4" would be fabricated. NetShield instead maps its own
explainable risk points and independent-signal count to P1-P4, and records the
mapping in every response.

The accumulator owns detection. This module owns workflow state and deadlines
that survive a restart because they are stored in the database.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

TRIAGE_STATUSES = ("new", "investigating", "suppressed", "remediated")
ACKNOWLEDGED_STATUSES = {"investigating", "suppressed", "remediated"}

# Internal severity policy. Thresholds are risk points from
# evidence_accumulator.EvidenceAccumulator (weights: 50/35/45, incident at 70).
SEVERITY_POLICY = (
    {"id": "P1", "minimum_points": 100.0, "minimum_signals": 3, "ack_minutes": 15},
    {"id": "P2", "minimum_points": 85.0, "minimum_signals": 2, "ack_minutes": 60},
    {"id": "P3", "minimum_points": 70.0, "minimum_signals": 2, "ack_minutes": 240},
    {"id": "P4", "minimum_points": 0.0, "minimum_signals": 1, "ack_minutes": 1440},
)

SEVERITY_LABELS = {
    "P1": "P1 · critical risk",
    "P2": "P2 · high risk",
    "P3": "P3 · elevated risk",
    "P4": "P4 · low risk",
}


def severity_for(risk_points: float, active_signals: int) -> dict:
    """Map accumulator risk to an internal priority. Never a CVSS score."""
    try:
        points = float(risk_points)
    except (TypeError, ValueError):
        points = 0.0
    try:
        signals = int(active_signals)
    except (TypeError, ValueError):
        signals = 0
    for rule in SEVERITY_POLICY:
        if points >= rule["minimum_points"] and signals >= rule["minimum_signals"]:
            return {
                "id": rule["id"],
                "label": SEVERITY_LABELS[rule["id"]],
                "basis": "internal_risk_points",
                "risk_points": round(points, 4),
                "active_signals": signals,
                "ack_minutes": rule["ack_minutes"],
                "note": (
                    "Internal NetShield priority derived from explainable risk "
                    "points and independent signal count. Not CVSS, not a "
                    "probability, and not a site severity policy."
                ),
            }
    return {
        "id": "P4",
        "label": SEVERITY_LABELS["P4"],
        "basis": "internal_risk_points",
        "risk_points": round(points, 4),
        "active_signals": signals,
        "ack_minutes": 1440,
        "note": "Internal NetShield priority; not CVSS.",
    }


def _parse(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def sla_payload(
    incident: dict,
    severity: dict,
    *,
    acknowledged_at=None,
    now: datetime | None = None,
) -> dict:
    """Compute the acknowledgment deadline and its current state."""
    now = now or datetime.now(timezone.utc)
    opened = _parse(incident.get("incident_opened_at") or incident.get("first_seen"))
    if opened is None:
        return {
            "state": "unknown",
            "deadline": None,
            "remaining_seconds": None,
            "ack_minutes": severity["ack_minutes"],
            "note": "No incident open time was recorded.",
        }
    deadline = opened + timedelta(minutes=severity["ack_minutes"])
    acknowledged = _parse(acknowledged_at)
    remaining = (deadline - now).total_seconds()
    if acknowledged is not None:
        state = "acknowledged"
    elif not incident.get("incident_open", True):
        state = "closed"
    elif remaining < 0:
        state = "overdue"
    elif remaining <= max(60, severity["ack_minutes"] * 60 * 0.25):
        state = "due_soon"
    else:
        state = "open"
    return {
        "state": state,
        "deadline": _iso(deadline),
        "remaining_seconds": int(round(remaining)),
        "ack_minutes": severity["ack_minutes"],
        "acknowledged_at": _iso(acknowledged),
        "late": bool(acknowledged is not None and acknowledged > deadline),
        "note": (
            "Acknowledgment target for this local prototype. It is not a "
            "contracted SLA and no paging integration is implied."
        ),
    }


def triage_payload(incident: dict, record: dict | None, *, now: datetime | None = None) -> dict:
    """Merge stored triage state with the derived incident."""
    severity = severity_for(
        incident.get("max_risk_points", incident.get("risk_points", 0)),
        incident.get("active_signals", 0),
    )
    status = (record or {}).get("status") or "new"
    if status not in TRIAGE_STATUSES:
        status = "new"
    payload = {
        "status": status,
        "assignee": (record or {}).get("assignee") or None,
        "note": (record or {}).get("note") or "",
        "updated_by": (record or {}).get("updated_by") or None,
        "updated_at": _iso((record or {}).get("updated_at")),
        "acknowledged_at": _iso((record or {}).get("acknowledged_at")),
        "persisted": record is not None,
        "allowed_statuses": list(TRIAGE_STATUSES),
    }
    payload["severity"] = severity
    payload["sla"] = sla_payload(
        incident, severity, acknowledged_at=(record or {}).get("acknowledged_at"), now=now
    )
    if status in {"suppressed", "remediated"}:
        payload["sla"]["state"] = "closed"
    return payload


def validate_status(status: str) -> str:
    value = str(status or "").strip().lower()
    if value not in TRIAGE_STATUSES:
        raise ValueError(
            "status must be one of: " + ", ".join(TRIAGE_STATUSES)
        )
    return value
