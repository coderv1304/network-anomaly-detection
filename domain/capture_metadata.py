"""Capture provenance and ingestion-vector classification.

Enterprise NDR products talk about *capture vectors* (a mirrored 10/25 GbE
backbone, a corporate WLAN controller feed, a cellular gateway, a cloud VPC
flow-log export), not about consumer connectivity modes. This module keeps that
distinction honest:

* A capture is described by what the file or adapter actually reports (PCAP link
  type, adapter name/description, directional counters). Missing data stays
  missing.
* Wi-Fi, cellular, Ethernet and VPN are Layer-1/2 or deployment contexts. They
  are **not** model features. Once packets reach IP, the flow statistics are the
  same regardless of the radio or fibre underneath.
* The interface classifier is a name/description heuristic. It is labelled as
  such in every response and is never presented as an operating-system fact.

No function here sends traffic, opens a socket, or invents a measurement.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

INGESTION_VECTORS = (
    "ethernet",
    "wlan",
    "wwan",
    "vpn",
    "virtual",
    "loopback",
    "unknown",
)

VECTOR_LABELS = {
    "ethernet": "Wired Ethernet",
    "wlan": "802.11 wireless",
    "wwan": "Cellular / WWAN",
    "vpn": "VPN / tunnel",
    "virtual": "Virtual / container",
    "loopback": "Loopback",
    "unknown": "Unclassified",
}

# Values are libpcap DLT_* numbers. This is the link-layer framing, not the
# physical medium; radiotap is the one case where the framing proves 802.11.
LINK_TYPES = {
    0: {"name": "NULL / loopback", "vector": "loopback", "layer": "loopback"},
    1: {"name": "Ethernet (DLT_EN10MB)", "vector": "ethernet", "layer": "ethernet"},
    9: {"name": "PPP", "vector": "vpn", "layer": "ppp"},
    12: {"name": "Raw IP", "vector": "unknown", "layer": "raw_ip"},
    50: {"name": "PPP in HDLC", "vector": "vpn", "layer": "ppp"},
    51: {"name": "PPP over Ethernet", "vector": "vpn", "layer": "pppoe"},
    101: {"name": "Raw IP (DLT_RAW)", "vector": "unknown", "layer": "raw_ip"},
    105: {"name": "IEEE 802.11", "vector": "wlan", "layer": "ieee802_11"},
    108: {"name": "Loopback (DLT_LOOP)", "vector": "loopback", "layer": "loopback"},
    113: {"name": "Linux cooked capture (SLL)", "vector": "unknown", "layer": "linux_sll"},
    127: {"name": "Radiotap / 802.11", "vector": "wlan", "layer": "radiotap"},
    228: {"name": "IPv4", "vector": "unknown", "layer": "ipv4"},
    229: {"name": "IPv6", "vector": "unknown", "layer": "ipv6"},
    276: {"name": "Linux cooked capture v2 (SLL2)", "vector": "unknown", "layer": "linux_sll2"},
}

_VECTOR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("loopback", re.compile(r"(^|[^a-z])(lo|lo0|loopback)([^a-z]|$)")),
    ("wlan", re.compile(r"(wi[- ]?fi|wlan|wireless|802\.11|airport)")),
    (
        "wwan",
        re.compile(r"(wwan|wwlan|rmnet|cellular|lte|5g|modem|mobile broadband|mobile data)"),
    ),
    (
        "vpn",
        re.compile(r"(vpn|wireguard|tailscale|zerotier|openvpn|ipsec|(^|[^a-z])(tun|tap|wg)\d*([^a-z]|$)|ppp)"),
    ),
    (
        "virtual",
        re.compile(
            r"(vethernet|hyper[- ]?v|vmware|virtualbox|virtual|docker|podman|"
            r"veth|virbr|br-|bridge|cni|flannel|cali|tap|tun)"
        ),
    ),
    (
        "ethernet",
        re.compile(
            r"(ethernet|(^|[^a-z])(eth|enp|eno|ens|em|en|gbe)\d*([^a-z]|$)|"
            r"local area connection|10gbe|25gbe|40gbe|100gbe)"
        ),
    ),
)


def classify_ingestion_vector(name: Any, description: Any = "") -> dict[str, Any]:
    """Classify an adapter name/description into a capture vector.

    The result includes ``basis`` so callers can display that this is a name
    heuristic. An unrecognised adapter returns ``unknown``; it is never guessed
    into Ethernet or Wi-Fi.
    """
    label = f"{name or ''} {description or ''}".strip().lower()
    if not label:
        return {
            "vector": "unknown",
            "label": VECTOR_LABELS["unknown"],
            "basis": "no_adapter_metadata",
            "matched": None,
        }
    for vector, pattern in _VECTOR_PATTERNS:
        match = pattern.search(label)
        if match:
            return {
                "vector": vector,
                "label": VECTOR_LABELS[vector],
                "basis": "name_heuristic",
                "matched": match.group(0).strip(),
            }
    return {
        "vector": "unknown",
        "label": VECTOR_LABELS["unknown"],
        "basis": "name_heuristic_no_match",
        "matched": None,
    }


def link_type_metadata(value: Any) -> dict[str, Any]:
    """Return link-layer metadata for a libpcap DLT value without guessing."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return {
            "value": value,
            "name": "Not reported",
            "layer": "unknown",
            "vector": "unknown",
        }
    entry = LINK_TYPES.get(number)
    if entry is None:
        return {
            "value": number,
            "name": f"Unrecognised DLT {number}",
            "layer": "unknown",
            "vector": "unknown",
        }
    return {"value": number, **entry}


def ingestion_label(filename: str | None, columns: Iterable[Any]) -> str:
    """Describe a tabular upload by its actual schema, not a marketing name.

    NetFlow/IPFIX are binary template protocols and are not parsed by the CSV
    path. Zeek ``conn.log`` has its own parser and its own limitations, so a
    Zeek-shaped CSV is described as a flow export rather than silently claimed
    as a native Zeek stream.
    """
    names = {str(column).strip().lower() for column in columns}
    lowered = (filename or "").lower()
    if {"id.orig_h", "id.resp_h"} & names or {"uid", "conn_state"} <= names:
        return "Zeek-like conn.log flow export (CSV)"
    if {"destination port", "flow duration", "total fwd packets"} <= names:
        return "CICFlowMeter-style flow CSV"
    if {"src_ip", "dst_ip"} <= names and ({"bytes", "packets"} & names):
        return "Generic flow CSV"
    if lowered.endswith((".log", ".tsv")):
        return "Tabular flow export"
    return "CSV flow export"


def describe_pcap_link_type(format_name: str | None, link_type: Any) -> dict[str, Any]:
    """Combine container format and link type into a provenance record."""
    meta = link_type_metadata(link_type)
    return {
        "format": (format_name or "unknown").lower(),
        "link_type": meta,
        "note": (
            "PCAP records the link-layer framing. It does not prove the physical "
            "medium; a mirrored Ethernet port and a VM tap both appear as Ethernet."
        ),
    }
