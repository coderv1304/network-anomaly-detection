"""Response playbooks that do not pretend to be an enforcement plane.

NetShield is a research prototype. It has no privileged agent, no firewall
credential, and no cloud control-plane token. This module therefore provides:

* a **dry-run containment plan** with exact nftables/iptables commands that an
  operator can review and apply outside the app;
* a **STIX 2.1 bundle** with an indicator derived from the incident;
* an **opt-in webhook dispatch** that only sends when both
  ``NETSHIELD_SOAR_ENABLED=true`` and ``NETSHIELD_SOAR_WEBHOOK_URL`` are set,
  and only to a host in ``NETSHIELD_SOAR_WEBHOOK_ALLOWLIST``.

No call here executes a firewall change. The response says ``executed: false``
for containment plans. A webhook failure is returned as a failure, never
converted into a simulated success.
"""

from __future__ import annotations

import ipaddress
import os
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

STIX_SPEC_VERSION = "2.1"
_STIX_NAMESPACE = uuid.UUID("46a6f2c9-7f8e-4b1f-9d4a-4f2a2f0c3b7d")
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"


class PlaybookError(ValueError):
    """Raised for an unsafe or unsupported playbook request."""


def _iso(value: datetime | str | None) -> str:
    if value is None:
        value = datetime.now(timezone.utc)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        parsed = value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _public_ip(value: str) -> ipaddress._BaseAddress:
    try:
        parsed = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise PlaybookError("source IP is not a valid address") from exc
    if not parsed.is_global:
        raise PlaybookError(
            "refusing to generate a containment plan for a non-public source address"
        )
    return parsed


def containment_plan(incident: dict) -> dict:
    """Return reviewable firewall commands; never execute them."""
    source_ip = str(incident.get("source_ip") or "")
    parsed = _public_ip(source_ip)
    address = parsed.compressed
    incident_id = str(incident.get("incident_id") or "unknown")
    risk = incident.get("max_risk_points", incident.get("risk_points", 0))
    return {
        "playbook": "containment_plan",
        "mode": "dry_run",
        "executed": False,
        "target": {"ip": address, "incident_id": incident_id, "risk_points": risk},
        "commands": [
            {
                "platform": "linux-nftables",
                "description": "Drop new inbound traffic from the source (review table/chain names first).",
                "command": f"nft add rule inet filter input ip saddr {address} counter drop",
            },
            {
                "platform": "linux-iptables",
                "description": "Insert a DROP rule at the top of INPUT.",
                "command": f"iptables -I INPUT -s {address}/32 -j DROP",
            },
            {
                "platform": "cloud-waf",
                "description": "Conceptual edge rule; apply it in the WAF console. NetShield has no cloud credential.",
                "command": f"block source {address}/32 at the edge WAF",
            },
        ],
        "warning": (
            "NetShield does not execute these commands and has no privileged "
            "agent or cloud credential. Review the rule, scope, and rollback "
            "before applying it. Blocking a source can affect shared NAT egress."
        ),
        "rollback": [
            f"nft delete rule inet filter input ip saddr {address} counter drop",
            f"iptables -D INPUT -s {address}/32 -j DROP",
        ],
    }


def _indicator_pattern(source_ip: str) -> str:
    parsed = _public_ip(source_ip)
    if parsed.version == 6:
        return f"[ipv6-addr:value = '{parsed.compressed}']"
    return f"[ipv4-addr:value = '{parsed.compressed}']"


def stix_bundle(incident: dict, *, tenant_slug: str | None = None) -> dict:
    """Build a deterministic STIX 2.1 bundle for one incident.

    The indicator carries the internal risk points as STIX ``confidence`` and a
    description that states it is an uncalibrated model/accumulator signal, not
    a confirmed malicious indicator.
    """
    source_ip = str(incident.get("source_ip") or "")
    pattern = _indicator_pattern(source_ip)
    incident_id = str(incident.get("incident_id") or "unknown")
    created = _iso(incident.get("incident_opened_at") or incident.get("first_seen"))
    risk = incident.get("max_risk_points", incident.get("risk_points", 0)) or 0
    try:
        confidence = max(0, min(100, int(round(float(risk)))))
    except (TypeError, ValueError):
        confidence = 0

    identity_id = "identity--" + str(
        uuid.uuid5(_STIX_NAMESPACE, f"netshield:{tenant_slug or 'default'}")
    )
    indicator_id = "indicator--" + str(
        uuid.uuid5(_STIX_NAMESPACE, f"indicator:{tenant_slug or 'default'}:{incident_id}")
    )
    bundle_id = "bundle--" + str(
        uuid.uuid5(_STIX_NAMESPACE, f"bundle:{tenant_slug or 'default'}:{incident_id}:{created}")
    )
    indicator = {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": indicator_id,
        "created": created,
        "modified": created,
        "created_by_ref": identity_id,
        "name": f"NetShield host/window incident for {source_ip}",
        "description": (
            "Source address accumulated independent NetShield signals in one "
            f"{incident.get('window_seconds', 'unknown')}-second window. "
            "Confidence is the internal risk-point total, not a calibrated "
            "probability and not a confirmed malicious indicator. Verify before "
            "blocking."
        ),
        "indicator_types": ["anomalous-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": created,
        "confidence": confidence,
        "labels": ["netshield", "flow-anomaly"],
        "external_references": [
            {
                "source_name": "NetShield incident",
                "description": f"incident_id={incident_id}",
            }
        ],
    }
    identity = {
        "type": "identity",
        "spec_version": STIX_SPEC_VERSION,
        "id": identity_id,
        "created": created,
        "modified": created,
        "name": "NetShield",
        "identity_class": "system",
        "description": "Research prototype export; not a threat-intelligence feed.",
    }
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": STIX_SPEC_VERSION,
        "objects": [identity, indicator],
    }


def webhook_config() -> dict:
    return {
        "enabled": os.environ.get("NETSHIELD_SOAR_ENABLED", "false").strip().lower()
        == "true",
        "url": os.environ.get("NETSHIELD_SOAR_WEBHOOK_URL", "").strip(),
        "allowlist": [
            item.strip().lower()
            for item in os.environ.get("NETSHIELD_SOAR_WEBHOOK_ALLOWLIST", "").split(",")
            if item.strip()
        ],
    }


def dispatch_webhook(incident: dict, *, timeout: float = 5.0) -> dict:
    """Send an incident summary only to an explicitly allowlisted destination.

    Returns a failure result instead of pretending delivery happened. Redirects
    are disabled to avoid an allowlisted host redirecting to an arbitrary target.
    """
    config = webhook_config()
    if not config["enabled"]:
        return {
            "playbook": "notify_webhook",
            "mode": "disabled",
            "executed": False,
            "delivered": False,
            "status": "disabled",
            "message": "NETSHIELD_SOAR_ENABLED is not true; no webhook was sent.",
        }
    if not config["url"]:
        return {
            "playbook": "notify_webhook",
            "mode": "not_configured",
            "executed": False,
            "delivered": False,
            "status": "not_configured",
            "message": "NETSHIELD_SOAR_WEBHOOK_URL is not set; no webhook was sent.",
        }

    parsed = urlparse(config["url"])
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"https", "http"} or not host:
        return {
            "playbook": "notify_webhook",
            "mode": "error",
            "executed": False,
            "delivered": False,
            "status": "invalid_url",
            "message": "Webhook URL must be an absolute http(s) URL.",
        }
    if parsed.username or parsed.password or parsed.fragment:
        return {
            "playbook": "notify_webhook",
            "mode": "error",
            "executed": False,
            "delivered": False,
            "status": "invalid_url",
            "message": "Webhook URL must not contain credentials or a fragment.",
        }
    if host not in config["allowlist"]:
        return {
            "playbook": "notify_webhook",
            "mode": "blocked",
            "executed": False,
            "delivered": False,
            "status": "host_not_allowlisted",
            "message": (
                "The webhook host is not in NETSHIELD_SOAR_WEBHOOK_ALLOWLIST. "
                "Add the exact host to opt in."
            ),
        }

    payload = {
        "source": "NetShield",
        "event": "flow_incident",
        "incident_id": incident.get("incident_id"),
        "source_ip": incident.get("source_ip"),
        "risk_points": incident.get("max_risk_points", incident.get("risk_points")),
        "window_start": incident.get("window_start"),
        "window_seconds": incident.get("window_seconds"),
        "note": "Detection is an uncalibrated prototype signal; verify before acting.",
    }
    try:
        response = requests.post(
            config["url"], json=payload, timeout=timeout, allow_redirects=False
        )
    except requests.RequestException as exc:
        return {
            "playbook": "notify_webhook",
            "mode": "live",
            "executed": True,
            "delivered": False,
            "status": "request_failed",
            "message": f"Webhook request failed: {type(exc).__name__}",
        }
    delivered = 200 <= response.status_code < 300
    return {
        "playbook": "notify_webhook",
        "mode": "live",
        "executed": True,
        "delivered": delivered,
        "status": "delivered" if delivered else "http_error",
        "http_status": response.status_code,
        "destination_host": host,
    }
