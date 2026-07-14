"""
AlienVault OTX (LevelBlue) client for threat pulse enrichment.

Returns how many threat pulses reference a given CVE, plus associated IoCs.
1-hour TTL in-memory cache. TRIAGEMATE_OTX_API_KEY env var is optional.
"""

import os
import time
import logging

import requests

logger = logging.getLogger("triagemate.otx")

_CACHE: dict[str, tuple[float, dict]] = {}
CACHE_TTL = 3600
API_KEY = os.getenv("TRIAGEMATE_OTX_API_KEY", "").strip()
MAX_RATE_LIMIT_RETRIES = 3
RATE_LIMIT_BACKOFF_SECONDS = 1.0


def _empty_result(*, queried: bool) -> dict:
    """Return the safe, shape-stable result used when OTX has no data."""
    return {
        "pulse_count": 0,
        "indicators": 0,
        "targeted_countries": [],
        "pulse_names": [],
        "queried": queried,
    }


def query_otx_pulses(cve_id: str) -> dict:
    """Query AlienVault OTX API for threat pulses referencing a CVE.

    Returns:
        dict with keys: pulse_count, indicators, targeted_countries,
                        pulse_names, queried
    """
    now = time.time()

    if not API_KEY:
        return _empty_result(queried=False)

    if cve_id in _CACHE:
        ts, data = _CACHE[cve_id]
        if now - ts < CACHE_TTL:
            return dict(data)

    start = time.time()
    try:
        for attempt in range(MAX_RATE_LIMIT_RETRIES + 1):
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}/general",
                headers={"X-OTX-API-KEY": API_KEY},
                timeout=10,
            )
            if resp.status_code != 429:
                break

            if attempt == MAX_RATE_LIMIT_RETRIES:
                logger.warning(
                    "OTX rate limit persisted for %s after %d retries",
                    cve_id,
                    MAX_RATE_LIMIT_RETRIES,
                    extra={"event": "otx_rate_limit", "cve_id": cve_id},
                )
                result = _empty_result(queried=True)
                _CACHE[cve_id] = (now, result)
                return dict(result)

            retry_after = resp.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after is not None else 0.0
            except ValueError:
                delay = 0.0
            delay = max(delay, RATE_LIMIT_BACKOFF_SECONDS * (2**attempt))
            logger.info(
                "OTX rate limited for %s; retrying in %.1fs (attempt %d/%d)",
                cve_id,
                delay,
                attempt + 1,
                MAX_RATE_LIMIT_RETRIES,
                extra={"event": "otx_rate_limit", "cve_id": cve_id},
            )
            time.sleep(delay)

        resp.raise_for_status()
        data = resp.json()

        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        pulse_count = len(pulses)
        raw_indicator_count = data.get("indicator_count")
        indicators = (
            raw_indicator_count
            if raw_indicator_count is not None
            else pulse_info.get("count", 0)
        )

        targeted_countries = list(
            set(
                c
                for p in pulses
                for t in p.get("targeted_countries", [])
                for c in (t if isinstance(t, list) else [t])
            )
        )

        pulse_names = [p.get("name", "") for p in pulses[:5] if p.get("name")]

        result = {
            "pulse_count": pulse_count,
            "indicators": indicators,
            "targeted_countries": targeted_countries[:20],
            "pulse_names": pulse_names,
            "queried": True,
        }

        duration_ms = int((time.time() - start) * 1000)
        logger.info(
            "OTX query for %s: pulses=%d, duration=%dms",
            cve_id,
            pulse_count,
            duration_ms,
            extra={
                "event": "otx_call",
                "cve_id": cve_id,
                "pulse_count": pulse_count,
                "duration_ms": duration_ms,
            },
        )

        _CACHE[cve_id] = (now, result)
        return dict(result)

    except (requests.RequestException, ValueError) as e:
        duration_ms = int((time.time() - start) * 1000)
        logger.warning(
            "OTX query failed for %s: %s",
            cve_id,
            e,
            extra={
                "event": "otx_call",
                "cve_id": cve_id,
                "duration_ms": duration_ms,
            },
        )
        result = _empty_result(queried=True)
        _CACHE[cve_id] = (now, result)
        return dict(result)
