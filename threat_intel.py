"""AbuseIPDB lookup with public-IP validation and one-hour caching."""

import ipaddress
import json
import os
import threading
import time

import requests

try:
    import redis
except ImportError:
    redis = None

_abuse_cache = {}
_abuse_cache_lock = threading.Lock()
_redis_cache = None
if redis is not None and os.environ.get("REDIS_URL"):
    _redis_cache = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)


def lookup_abuseipdb(ip_address):
    """Return a cached reputation result without transmitting private IPs."""
    try:
        parsed_ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return {"status": "invalid_address", "abuse_score": None}

    if not parsed_ip.is_global:
        return {"status": "private_address", "abuse_score": None}

    cache_key = f"abuseipdb:v1:{parsed_ip.compressed}"
    if _redis_cache is not None:
        try:
            cached = _redis_cache.get(cache_key)
            if cached:
                return json.loads(cached)
        except Exception:
            pass
    with _abuse_cache_lock:
        cached_entry = _abuse_cache.get(cache_key)
        if cached_entry and cached_entry[0] > time.monotonic():
            return cached_entry[1]

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"status": "not_configured", "abuse_score": None}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": parsed_ip.compressed, "maxAgeInDays": 90, "verbose": ""},
            timeout=4,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        result = {
            "status": "live",
            "abuse_score": int(data.get("abuseConfidenceScore", 0)),
            "total_reports": int(data.get("totalReports", 0)),
            "isp": data.get("isp") or "Unknown ISP",
            "country": data.get("countryCode") or "Unknown",
            "usage_type": data.get("usageType") or "Unknown",
            "is_tor": bool(data.get("isTor", False)),
        }
        if _redis_cache is not None:
            try:
                _redis_cache.setex(cache_key, 3600, json.dumps(result))
            except Exception:
                pass
        with _abuse_cache_lock:
            _abuse_cache[cache_key] = (time.monotonic() + 3600, result)
        return result
    except (requests.RequestException, ValueError, TypeError):
        return {"status": "unavailable", "abuse_score": None}