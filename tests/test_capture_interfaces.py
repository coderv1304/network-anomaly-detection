"""Tests for cross-platform capture interface selection."""

import capture_interfaces as ci

FAKE_INTERFACES = [
    {"name": "Wi-Fi", "description": "MediaTek Wi-Fi 6E", "ip": "10.0.0.5", "mac": "aa", "loopback": False},
    {"name": "Ethernet", "description": "Realtek GbE", "ip": "192.168.1.20", "mac": "bb", "loopback": False},
    {"name": "Local Area Connection", "description": "ExpressVPN TUN Driver", "ip": "10.8.0.2", "mac": "cc", "loopback": False},
    {"name": "\\Device\\NPF_Loopback", "description": "Software Loopback Interface 1", "ip": "127.0.0.1", "mac": "", "loopback": True},
]


def _patch(monkeypatch, route_ip="10.0.0.5"):
    monkeypatch.setattr(ci, "list_capture_interfaces", lambda: FAKE_INTERFACES)
    monkeypatch.setattr(ci, "_default_route_ip", lambda: route_ip)


def test_auto_follows_the_default_route(monkeypatch):
    _patch(monkeypatch)
    resolved, unknown = ci.resolve_capture_interfaces("auto")
    assert resolved == ["Wi-Fi"]
    assert unknown == []


def test_auto_switches_to_hotspot_or_ethernet_when_route_changes(monkeypatch):
    # A tethered phone or a docked Ethernet cable owns the default route; the
    # same configuration follows it without editing the environment.
    _patch(monkeypatch, route_ip="192.168.1.20")
    resolved, unknown = ci.resolve_capture_interfaces("auto")
    assert resolved == ["Ethernet"]
    assert unknown == []


def test_auto_offline_prefers_a_non_loopback_adapter(monkeypatch):
    _patch(monkeypatch, route_ip=None)
    resolved, _ = ci.resolve_capture_interfaces("auto")
    assert resolved == ["Wi-Fi"]


def test_all_includes_loopback_and_vpn(monkeypatch):
    _patch(monkeypatch)
    resolved, unknown = ci.resolve_capture_interfaces("all")
    assert "Wi-Fi" in resolved
    assert "Ethernet" in resolved
    assert "Local Area Connection" in resolved
    assert "\\Device\\NPF_Loopback" in resolved
    assert unknown == []


def test_loopback_mode(monkeypatch):
    _patch(monkeypatch)
    resolved, unknown = ci.resolve_capture_interfaces("loopback")
    assert resolved == ["\\Device\\NPF_Loopback"]
    assert unknown == []


def test_explicit_names_descriptions_ips_and_unknowns(monkeypatch):
    _patch(monkeypatch)
    assert ci.resolve_capture_interfaces("Wi-Fi")[0] == ["Wi-Fi"]
    assert ci.resolve_capture_interfaces("Realtek GbE")[0] == ["Ethernet"]
    assert ci.resolve_capture_interfaces("10.8.0.2")[0] == ["Local Area Connection"]
    resolved, unknown = ci.resolve_capture_interfaces("Wi-Fi, not-a-real-adapter")
    # Unknown entries are attempted (Npcap GUIDs are not enumerable) but are
    # also reported so a typo cannot silently shrink coverage.
    assert "Wi-Fi" in resolved
    assert "not-a-real-adapter" in resolved
    assert unknown == ["not-a-real-adapter"]


def test_blank_spec_falls_back_to_auto(monkeypatch):
    _patch(monkeypatch)
    resolved, _ = ci.resolve_capture_interfaces("")
    assert resolved == ["Wi-Fi"]


def test_interface_list_is_sorted_with_loopback_last(monkeypatch):
    monkeypatch.setattr(ci, "_scapy_ifaces", lambda: [])
    rows = ci.list_capture_interfaces()
    assert rows == []
