"""Optional IP attribution and reputation enrichment.

Two independent sources are supported:

* **AbuseIPDB** reputation (requires ``ABUSEIPDB_API_KEY``). Private, loopback
  and invalid addresses are never transmitted.
* **MaxMind GeoLite2** local databases for country/city and ASN. These require
  a licensed ``GeoLite2-City.mmdb`` and/or ``GeoLite2-ASN.mmdb`` downloaded by
  the operator. No database is bundled, and no lookup is fabricated when one is
  absent.

Unknown is not clean. Every result carries an explicit ``status`` and the API
renders ``Unknown``/``Not configured`` instead of a green "clean" badge. This
module never invents an ASN, a country flag, or an abuse score.
"""

from __future__ import annotations

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
_abuse_stats = {"queries": 0, "live": 0, "errors": 0}
_abuse_stats_lock = threading.Lock()
_redis_cache = None
if redis is not None and os.environ.get("REDIS_URL"):
    _redis_cache = redis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

_geo_cache: dict[str, tuple[float, dict]] = {}
_geo_cache_lock = threading.Lock()
_geo_readers: dict[str, object] = {}
_geo_reader_lock = threading.Lock()

_GEO_CACHE_SECONDS = 3600


def _scope(ip_address: str) -> tuple[str, ipaddress._BaseAddress | None]:
    try:
        parsed = ipaddress.ip_address(str(ip_address).strip())
    except ValueError:
        return "invalid", None
    if parsed.is_loopback:
        return "loopback", parsed
    if parsed.is_private or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast:
        return "private", parsed
    if parsed.is_global:
        return "public", parsed
    return "non_global", parsed


def lookup_abuseipdb(ip_address):
    """Return a cached reputation result without transmitting private IPs."""
    scope, parsed_ip = _scope(ip_address)
    if scope == "invalid":
        return {"status": "invalid_address", "abuse_score": None}
    if scope != "public":
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
        with _abuse_stats_lock:
            _abuse_stats["queries"] += 1
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
            "source": "AbuseIPDB",
        }
        with _abuse_stats_lock:
            _abuse_stats["live"] += 1
        if _redis_cache is not None:
            try:
                _redis_cache.setex(cache_key, 3600, json.dumps(result))
            except Exception:
                pass
        with _abuse_cache_lock:
            _abuse_cache[cache_key] = (time.monotonic() + 3600, result)
        return result
    except (requests.RequestException, ValueError, TypeError):
        with _abuse_stats_lock:
            _abuse_stats["errors"] += 1
        return {"status": "unavailable", "abuse_score": None}


def reputation_stats() -> dict:
    """Return this process's real AbuseIPDB request counters.

    Cached answers are not counted again; only actual HTTP attempts are.
    """
    with _abuse_stats_lock:
        return dict(_abuse_stats)


def _geo_paths() -> tuple[str | None, str | None]:
    city = os.environ.get("NETSHIELD_GEOIP_CITY_DB") or os.environ.get("MAXMIND_CITY_DB")
    asn = os.environ.get("NETSHIELD_GEOIP_ASN_DB") or os.environ.get("MAXMIND_ASN_DB")
    default_city = os.path.join("data", "GeoLite2-City.mmdb")
    default_asn = os.path.join("data", "GeoLite2-ASN.mmdb")
    if city is None and os.path.exists(default_city):
        city = default_city
    if asn is None and os.path.exists(default_asn):
        asn = default_asn
    return city, asn


def _geo_reader(path: str):
    """Open and cache a MaxMind reader. Import failure is reported, not hidden."""
    with _geo_reader_lock:
        if path in _geo_readers:
            return _geo_readers[path]
        try:
            import geoip2.database  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "geoip2 is required to read MaxMind databases; install the optional 'geoip2' package"
            ) from exc
        reader = geoip2.database.Reader(path)
        _geo_readers[path] = reader
        return reader


def lookup_geolocation(ip_address: str) -> dict:
    """Look up country/city and ASN from operator-supplied MaxMind databases.

    Returns ``status='not_configured'`` when no database exists. A city database
    and an ASN database are independent; one can be live while the other is
    unavailable, and the response says which.
    """
    scope, parsed = _scope(ip_address)
    if scope == "invalid":
        return {"status": "invalid_address", "city": None, "asn": None}
    if scope != "public":
        return {"status": "private_address", "city": None, "asn": None}

    cache_key = parsed.compressed
    with _geo_cache_lock:
        cached = _geo_cache.get(cache_key)
        if cached and cached[0] > time.monotonic():
            return cached[1]

    city_path, asn_path = _geo_paths()
    if not city_path and not asn_path:
        return {
            "status": "not_configured",
            "city": None,
            "asn": None,
            "note": (
                "Set NETSHIELD_GEOIP_CITY_DB and/or NETSHIELD_GEOIP_ASN_DB to a "
                "licensed MaxMind GeoLite2 database. No attribution is inferred."
            ),
        }

    result: dict = {"status": "live", "city": None, "asn": None, "sources": []}
    errors: list[str] = []

    if city_path:
        try:
            reader = _geo_reader(city_path)
            record = reader.city(parsed.compressed)
            result["city"] = {
                "country_code": record.country.iso_code,
                "country_name": record.country.name,
                "subdivision": record.subdivisions.most_specific.name if record.subdivisions else None,
                "city": record.city.name,
                "latitude": record.location.latitude,
                "longitude": record.location.longitude,
                "network": str(record.traits.network) if record.traits.network else None,
            }
            result["sources"].append("GeoLite2-City")
        except RuntimeError as exc:
            errors.append(str(exc))
            result["status"] = "dependency_missing" if not asn_path else "partial"
        except Exception as exc:  # noqa: BLE001 - database-specific errors
            errors.append(f"city lookup failed: {type(exc).__name__}")
            result["status"] = "partial" if asn_path else "unavailable"

    if asn_path:
        try:
            reader = _geo_reader(asn_path)
            record = reader.asn(parsed.compressed)
            result["asn"] = {
                "number": record.autonomous_system_number,
                "organization": record.autonomous_system_organization,
                "network": str(record.network) if record.network else None,
            }
            result["sources"].append("GeoLite2-ASN")
            if result["status"] != "live":
                result["status"] = "partial" if result.get("city") else result["status"]
        except RuntimeError as exc:
            errors.append(str(exc))
            result["status"] = "dependency_missing" if not city_path else "partial"
        except Exception as exc:  # noqa: BLE001 - database-specific errors
            errors.append(f"ASN lookup failed: {type(exc).__name__}")
            result["status"] = "partial" if result.get("city") else "unavailable"

    if errors:
        result["errors"] = errors[:3]
    with _geo_cache_lock:
        _geo_cache[cache_key] = (time.monotonic() + _GEO_CACHE_SECONDS, result)
    return result


def enrich_ip(ip_address: str, *, include_reputation: bool = False) -> dict:
    """Return attribution for one IP without pretending missing data is clean."""
    scope, parsed = _scope(ip_address)
    payload = {
        "ip": parsed.compressed if parsed is not None else str(ip_address)[:64],
        "scope": scope,
        "geo": {"status": "invalid_address" if scope == "invalid" else "private_address"},
        "asn": {"status": "invalid_address" if scope == "invalid" else "private_address"},
        "reputation": {
            "status": "invalid_address" if scope == "invalid" else "private_address",
            "abuse_score": None,
        },
        "sources": [],
        "note": "",
    }
    if scope in {"invalid", "loopback", "private", "non_global"}:
        payload["note"] = (
            "No external lookup was made for a non-public address. "
            "Private addresses are not transmitted to third parties."
        )
        return payload

    geo = lookup_geolocation(parsed.compressed)
    payload["geo"] = {
        "status": geo.get("status"),
        "country_code": (geo.get("city") or {}).get("country_code"),
        "country_name": (geo.get("city") or {}).get("country_name"),
        "city": (geo.get("city") or {}).get("city"),
        "subdivision": (geo.get("city") or {}).get("subdivision"),
        "network": (geo.get("city") or {}).get("network"),
        "sources": geo.get("sources", []),
    }
    payload["asn"] = {
        "status": geo.get("status"),
        "number": (geo.get("asn") or {}).get("number"),
        "organization": (geo.get("asn") or {}).get("organization"),
        "network": (geo.get("asn") or {}).get("network"),
    }
    if geo.get("note"):
        payload["note"] = geo["note"]
    if geo.get("errors"):
        payload["errors"] = geo["errors"]

    if include_reputation:
        reputation = lookup_abuseipdb(parsed.compressed)
        payload["reputation"] = {
            "status": reputation.get("status"),
            "abuse_score": reputation.get("abuse_score"),
            "total_reports": reputation.get("total_reports"),
            "usage_type": reputation.get("usage_type"),
            "is_tor": reputation.get("is_tor"),
            "source": "AbuseIPDB",
        }
    else:
        payload["reputation"] = {
            "status": "not_queried",
            "abuse_score": None,
            "note": "Reputation lookups are opt-in; this response contains attribution only.",
        }
    return payload
