"""Cross-platform live-capture interface resolution.

NetShield's live capture must work on any connectivity: Wi-Fi, Ethernet,
mobile-hotspot / USB-tethering adapters, VPNs, virtual bridges, and loopback.
Operating systems name adapters differently (Npcap friendly names and GUIDs on
Windows, ``eth0``/``wlan0`` on Linux, ``en0`` on macOS), so this module
resolves adapters through Scapy, which normalises them per platform.

Selection modes for ``NETSHIELD_CAPTURE_INTERFACE``:

- ``auto`` (default): the adapter that currently owns the OS default route.
  This is whatever the machine is actually using - Wi-Fi today, Ethernet or a
  tethered phone tomorrow. No code change or restart configuration is needed
  when connectivity changes; restart the collector and it re-resolves.
- ``all``: every adapter that has an IP address, captured simultaneously.
  Loopback is included so locally generated traffic is also scored.
- ``loopback``: the loopback adapter only.
- A comma-separated list of names, descriptions, IPs, or Npcap GUIDs,
  matched case-insensitively. Unknown entries are reported, not silently
  dropped.

This module never sends traffic; the UDP connect used for default-route
detection only asks the OS routing table for the source address.
"""

from __future__ import annotations

import socket

INTERFACE_ENV = "NETSHIELD_CAPTURE_INTERFACE"
DEFAULT_SPEC = "auto"


def _scapy_ifaces():
    """Return the list of Scapy NetworkInterface objects for this host."""
    # Importing scapy.all (not scapy.config) is required: it initialises the
    # platform interface provider that populates conf.ifaces.
    import scapy.all as sa  # noqa: F401  (side-effectful import)

    return list(sa.conf.ifaces.values())


def _iface_ip(iface) -> str | None:
    ip = getattr(iface, "ip", None)
    return ip or None


def _is_loopback(iface) -> bool:
    name = (getattr(iface, "name", "") or "").lower()
    if name in ("lo", "lo0", "loopback") or name.startswith("loopback"):
        return True
    ip = _iface_ip(iface)
    return bool(ip and ip.startswith("127."))


def list_capture_interfaces() -> list[dict]:
    """Enumerate capture-capable adapters with their addresses.

    Returns a list of dicts: name, description, ip, mac, loopback. Adapter
    "up/down" state is platform-specific in Scapy, so it is not reported;
    adapters without an IP address are excluded because a capture on them
    cannot carry the demo traffic this collector is for.
    """
    interfaces = []
    for iface in _scapy_ifaces():
        ip = _iface_ip(iface)
        if not ip:
            continue
        interfaces.append(
            {
                "name": getattr(iface, "name", ""),
                "description": getattr(iface, "description", "") or "",
                "ip": ip,
                "mac": getattr(iface, "mac", "") or "",
                "loopback": _is_loopback(iface),
            }
        )
    interfaces.sort(key=lambda entry: (entry["loopback"], entry["name"].lower()))
    return interfaces


def _default_route_ip() -> str | None:
    """Local source IP the OS would use for internet traffic (no packets sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1)
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def resolve_capture_interfaces(spec: str | None = None) -> tuple[list[str], list[str]]:
    """Resolve a selection spec into concrete Scapy interface names.

    Returns ``(resolved_names, unknown_entries)``. Unknown entries are
    reported so operators can see typos instead of capturing nothing.
    """
    spec = (spec or DEFAULT_SPEC).strip()
    if not spec:
        spec = DEFAULT_SPEC
    mode = spec.lower()

    interfaces = list_capture_interfaces()
    by_name = {entry["name"].lower(): entry for entry in interfaces}
    by_description = {entry["description"].lower(): entry for entry in interfaces}
    by_ip = {entry["ip"]: entry for entry in interfaces}

    if mode == "auto":
        route_ip = _default_route_ip()
        if route_ip and route_ip in by_ip:
            return [by_ip[route_ip]["name"]], []
        # No default route (offline): fall back to the first non-loopback
        # adapter that has an address, then to any adapter at all.
        non_loopback = [entry for entry in interfaces if not entry["loopback"]]
        pool = non_loopback or interfaces
        return ([pool[0]["name"]], []) if pool else ([], ["no adapter with an IP address was found"])

    if mode == "loopback":
        loopback = [entry for entry in interfaces if entry["loopback"]]
        if loopback:
            return [entry["name"] for entry in loopback], []
        return [], ["no loopback adapter was found"]

    if mode == "all":
        return [entry["name"] for entry in interfaces], []

    resolved: list[str] = []
    unknown: list[str] = []
    for raw in spec.split(","):
        wanted = raw.strip()
        if not wanted:
            continue
        key = wanted.lower()
        match = by_name.get(key) or by_description.get(key) or by_ip.get(wanted)
        if match is None:
            # Not in the enumerated adapter list. Windows Npcap accepts raw
            # device GUIDs that Scapy does not enumerate, so the entry is
            # still attempted, but it is also reported as unknown so a typo
            # cannot silently reduce coverage.
            resolved.append(wanted)
            unknown.append(wanted)
            continue
        if match["name"] not in resolved:
            resolved.append(match["name"])
    return resolved, unknown


def format_capture_interfaces() -> str:
    """Human-readable adapter table for CLI help and diagnostics."""
    rows = list_capture_interfaces()
    if not rows:
        return "No capture-capable adapters with an IP address were found."
    lines = ["Capture-capable adapters (name | ip | description):"]
    for row in rows:
        marker = " [loopback]" if row["loopback"] else ""
        lines.append(f"  {row['name']} | {row['ip']} | {row['description']}{marker}")
    route_ip = _default_route_ip()
    lines.append(f"Default-route source IP: {route_ip or 'unknown (offline?)'}")
    return "\n".join(lines)
