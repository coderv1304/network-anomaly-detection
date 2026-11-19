"""SOAR plans are reviewable and never claim execution."""

import json

import pytest

from domain.soar import (
    PlaybookError,
    containment_plan,
    dispatch_webhook,
    stix_bundle,
    webhook_config,
)


def _incident(**overrides):
    base = {
        "incident_id": "8.8.8.8:1700000000",
        "source_ip": "8.8.8.8",
        "window_start": "2026-01-01T12:00:00Z",
        "window_seconds": 300,
        "incident_opened_at": "2026-01-01T12:00:00Z",
        "first_seen": "2026-01-01T12:00:01Z",
        "risk_points": 130,
        "max_risk_points": 130,
    }
    base.update(overrides)
    return base


def test_containment_plan_is_dry_run_with_rollback():
    plan = containment_plan(_incident())
    assert plan["mode"] == "dry_run"
    assert plan["executed"] is False
    assert any("8.8.8.8" in item["command"] for item in plan["commands"])
    assert any("iptables -D" in command for command in plan["rollback"])
    assert "does not execute" in plan["warning"].lower()


@pytest.mark.parametrize("address", ["192.168.1.10", "127.0.0.1", "203.0.113.7", "not-an-ip"])
def test_containment_refuses_non_public_or_invalid_sources(address):
    with pytest.raises(PlaybookError):
        containment_plan(_incident(source_ip=address))


def test_stix_bundle_is_deterministic_and_marks_confidence():
    first = stix_bundle(_incident(), tenant_slug="default")
    second = stix_bundle(_incident(), tenant_slug="default")
    assert first == second
    assert first["spec_version"] == "2.1"
    indicator = next(item for item in first["objects"] if item["type"] == "indicator")
    assert indicator["confidence"] == 100
    assert indicator["pattern"] == "[ipv4-addr:value = '8.8.8.8']"
    assert indicator["indicator_types"] == ["anomalous-activity"]
    assert "not a calibrated" in indicator["description"]
    json.dumps(first)


def test_webhook_is_disabled_without_explicit_configuration(monkeypatch):
    monkeypatch.delenv("NETSHIELD_SOAR_ENABLED", raising=False)
    monkeypatch.delenv("NETSHIELD_SOAR_WEBHOOK_URL", raising=False)
    result = dispatch_webhook(_incident())
    assert result["executed"] is False
    assert result["delivered"] is False
    assert result["status"] == "disabled"


def test_webhook_requires_allowlisted_host(monkeypatch):
    monkeypatch.setenv("NETSHIELD_SOAR_ENABLED", "true")
    monkeypatch.setenv("NETSHIELD_SOAR_WEBHOOK_URL", "https://hooks.example.test/incident")
    monkeypatch.setenv("NETSHIELD_SOAR_WEBHOOK_ALLOWLIST", "other.example.test")
    result = dispatch_webhook(_incident())
    assert result["status"] == "host_not_allowlisted"
    assert result["delivered"] is False


def test_webhook_delivers_only_to_allowlisted_host(monkeypatch):
    monkeypatch.setenv("NETSHIELD_SOAR_ENABLED", "true")
    monkeypatch.setenv("NETSHIELD_SOAR_WEBHOOK_URL", "https://hooks.example.test/incident")
    monkeypatch.setenv("NETSHIELD_SOAR_WEBHOOK_ALLOWLIST", "hooks.example.test")

    class FakeResponse:
        status_code = 204

    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setattr("soar.requests.post", fake_post)
    result = dispatch_webhook(_incident())
    assert result["status"] == "delivered"
    assert result["delivered"] is True
    assert result["http_status"] == 204
    assert calls and calls[0][1]["allow_redirects"] is False
    assert calls[0][1]["json"]["source_ip"] == "8.8.8.8"


def test_webhook_config_does_not_leak_credentials(monkeypatch):
    monkeypatch.setenv("NETSHIELD_SOAR_ENABLED", "true")
    monkeypatch.setenv("NETSHIELD_SOAR_WEBHOOK_URL", "https://user:pass@hooks.example.test/x")
    monkeypatch.setenv("NETSHIELD_SOAR_WEBHOOK_ALLOWLIST", "hooks.example.test")
    result = dispatch_webhook(_incident())
    assert result["status"] == "invalid_url"


def test_webhook_config_shape(monkeypatch):
    monkeypatch.delenv("NETSHIELD_SOAR_ENABLED", raising=False)
    config = webhook_config()
    assert config["enabled"] is False
    assert config["allowlist"] == []

