"""
nvd_client.py

Optional live lookup against the real NIST NVD CVE API 2.0, with a local
on-disk cache so repeated scans don't re-hit the (rate-limited) API.

Get a free API key here (recommended, raises your rate limit from 5 to 50
requests per rolling 30-second window): https://nvd.nist.gov/developers/request-an-api-key

Usage:
    export NVD_API_KEY="your-key-here"      # optional but recommended
    from nvd_client import find_cves_live
    cves = find_cves_live("vsftpd", "2.3.4")

NOTE: I can't test the live HTTP calls to nvd.nist.gov from the sandbox this
was built in (it's outside my network allowlist) -- please verify this works
end-to-end on your own machine before relying on it for your assignment demo.
"""

import os
import json
import time
import pathlib

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = pathlib.Path(__file__).parent / "nvd_cache.json"
CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours

# Without a key: 1 request per 6s is safe. With a key: 1 per 0.6s is safe.
API_KEY = os.environ.get("NVD_API_KEY")
REQUEST_DELAY = 0.7 if API_KEY else 6.5


def _load_cache():
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache):
    try:
        CACHE_FILE.write_text(json.dumps(cache, indent=2))
    except OSError:
        pass  # non-fatal -- caching is a nice-to-have, not required


def _severity_from_cve_item(cve_item):
    """Pull a CVSS severity label out of an NVD CVE item, preferring v3.1 > v3.0 > v2."""
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            severity = entries[0].get("baseSeverity") or data.get("baseSeverity")
            if severity:
                return severity.capitalize()
    return "Unknown"


def _summary_from_cve_item(cve_item):
    for desc in cve_item.get("descriptions", []):
        if desc.get("lang") == "en":
            text = desc.get("value", "")
            return (text[:220] + "...") if len(text) > 220 else text
    return "No description available."


def _query_nvd(keyword: str):
    """Hit the live NVD API for a keyword search. Returns a list of parsed CVE dicts."""
    params = {"keywordSearch": keyword, "resultsPerPage": 20}
    headers = {"apiKey": API_KEY} if API_KEY else {}

    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve_item = vuln.get("cve", {})
        cve_id = cve_item.get("id")
        if not cve_id:
            continue
        results.append({
            "cve_id": cve_id,
            "severity": _severity_from_cve_item(cve_item),
            "summary": _summary_from_cve_item(cve_item),
        })
    return results


def find_cves_live(product: str, version: str, use_cache: bool = True):
    """
    Query the live NVD API for CVEs matching a product (+ version appended to
    the keyword search for better precision). Falls back to cache when
    available and fresh; writes to cache after a successful live call.

    Returns [] on any failure (network error, rate limit, no results) rather
    than raising -- callers should treat this as "best effort enrichment".
    """
    if not product:
        return []

    keyword = f"{product} {version}".strip()
    cache = _load_cache() if use_cache else {}
    cache_key = keyword.lower()

    cached_entry = cache.get(cache_key)
    if cached_entry and (time.time() - cached_entry["fetched_at"]) < CACHE_TTL_SECONDS:
        return cached_entry["cves"]

    try:
        time.sleep(REQUEST_DELAY)  # basic client-side rate limiting
        results = _query_nvd(keyword)
    except requests.exceptions.RequestException:
        # Network error, rate limit (HTTP 403/429), timeout, etc.
        # Fall back to stale cache if we have one, else empty.
        return cached_entry["cves"] if cached_entry else []

    if use_cache:
        cache[cache_key] = {"cves": results, "fetched_at": time.time()}
        _save_cache(cache)

    return results
