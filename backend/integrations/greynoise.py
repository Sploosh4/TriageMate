"""
GreyNoise Community API client for internet scan detection.

Returns whether a CVE is being actively scanned on the public internet.
1-hour TTL in-memory cache. TRIAGEMATE_GREYNOISE_API_KEY env var is optional.
"""

import os
import time
import logging

import requests

logger = logging.getLogger("triagemate.greynoise")

_CACHE: dict[str, tuple[float, dict]] = {}
CACHE_TTL = 3600
API_KEY = os.getenv("TRIAGEMATE_GREYNOISE_API_KEY", "").strip()


def query_greynoise(cve_id: str) -> dict:
    """Query GreyNoise Community API for internet scan activity on a CVE.

    Returns:
        dict with keys: seen, classification, last_seen, scanning_ips, queried
    """
    now = time.time()

    if not API_KEY:
        return {
            "seen": False,
            "classification": "",
            "last_seen": "",
            "scanning_ips": 0,
            "queried": False,
        }

    if cve_id in _CACHE:
        ts, data = _CACHE[cve_id]
        if now - ts < CACHE_TTL:
            return dict(data)

    start = time.time()
    try:
        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{cve_id}",
            headers={"key": API_KEY},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()

        seen = data.get("seen", False)
        classification = data.get("classification", "")
        last_seen = data.get("last_seen", "")
        scanning_ips = data.get("scan_count", 0)
        if not scanning_ips:
            scanning_ips = len(data.get("actors", []))

        result = {
            "seen": seen,
            "classification": classification,
            "last_seen": last_seen,
            "scanning_ips": scanning_ips,
            "queried": True,
        }

        duration_ms = int((time.time() - start) * 1000)
        logger.info(
            "GreyNoise query for %s: seen=%s, duration=%dms",
            cve_id,
            seen,
            duration_ms,
            extra={
                "event": "greynoise_call",
                "cve_id": cve_id,
                "seen": seen,
                "duration_ms": duration_ms,
            },
        )

        _CACHE[cve_id] = (now, result)
        return dict(result)

    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        logger.warning(
            "GreyNoise query failed for %s: %s",
            cve_id,
            e,
            extra={
                "event": "greynoise_call",
                "cve_id": cve_id,
                "duration_ms": duration_ms,
            },
        )
        result = {
            "seen": False,
            "classification": "error",
            "last_seen": "",
            "scanning_ips": 0,
            "queried": True,
        }
        _CACHE[cve_id] = (now, result)
        return dict(result)
