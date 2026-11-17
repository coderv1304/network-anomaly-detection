import threat_intel


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "data": {
                "abuseConfidenceScore": 87,
                "totalReports": 14,
                "isp": "Example Transit",
                "countryCode": "US",
                "usageType": "Data Center/Web Hosting/Transit",
                "isTor": False,
            }
        }


class FakeRedis:
    def __init__(self):
        self.value = None
        self.ttl = None

    def get(self, key):
        return self.value

    def setex(self, key, ttl, value):
        self.ttl = ttl
        self.value = value


def test_abuseipdb_returns_live_score_and_reuses_one_hour_cache(monkeypatch):
    calls = []
    cache = FakeRedis()
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(threat_intel, "_redis_cache", cache)
    monkeypatch.setattr(threat_intel.requests, "get", lambda *args, **kwargs: calls.append((args, kwargs)) or FakeResponse())
    threat_intel._abuse_cache.clear()

    first = threat_intel.lookup_abuseipdb("8.8.8.8")
    second = threat_intel.lookup_abuseipdb("8.8.8.8")

    assert first["status"] == "live"
    assert first["abuse_score"] == 87
    assert first["total_reports"] == 14
    assert second == first
    assert len(calls) == 1
    assert calls[0][1]["timeout"] == 4
    assert cache.ttl == 3600


def test_reputation_stats_count_real_requests_only(monkeypatch):
    calls = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(threat_intel, "_redis_cache", None)
    monkeypatch.setattr(
        threat_intel.requests,
        "get",
        lambda *args, **kwargs: calls.append(args) or FakeResponse(),
    )
    monkeypatch.setattr(threat_intel, "_abuse_stats", {"queries": 0, "live": 0, "errors": 0})
    threat_intel._abuse_cache.clear()

    threat_intel.lookup_abuseipdb("8.8.8.8")
    threat_intel.lookup_abuseipdb("8.8.8.8")  # served from the in-memory cache
    stats = threat_intel.reputation_stats()

    assert len(calls) == 1
    assert stats == {"queries": 1, "live": 1, "errors": 0}


def test_abuseipdb_never_queries_private_or_invalid_addresses(monkeypatch):
    calls = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key")
    monkeypatch.setattr(threat_intel.requests, "get", lambda *args, **kwargs: calls.append(args))

    assert threat_intel.lookup_abuseipdb("192.168.1.10")["status"] == "private_address"
    assert threat_intel.lookup_abuseipdb("not-an-ip")["status"] == "invalid_address"
    assert calls == []