"""
Cache freshness health check utilities for KEV and EPSS data sources.

Reads cache file modification times as a proxy for last-refresh timestamp.
Avoids modifying cache file structure (backward compatible).
"""

import json
import os
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("triagemate.cache_health")

DATA_DIR = Path(__file__).parent.parent / "data"


def get_kev_health() -> dict:
    """Return KEV cache freshness info for the health endpoint.

    Returns:
        dict with keys: kev_last_refresh (ISO 8601 str or ''),
                        kev_entry_count (int)
    """
    path = DATA_DIR / "kev_cache.json"
    return _read_cache_file_health(path, "kev_last_refresh", "kev_entry_count")


def get_epss_health() -> dict:
    """Return EPSS cache freshness info for the health endpoint.

    Returns:
        dict with keys: epss_last_refresh (ISO 8601 str or ''),
                        epss_entry_count (int)
    """
    path = DATA_DIR / "epss_cache.json"
    return _read_cache_file_health(path, "epss_last_refresh", "epss_entry_count")


def _read_cache_file_health(path: Path, key_last: str, key_count: str) -> dict:
    """Read a cache JSON file and return health metadata.

    Uses file mtime for last-refresh timestamp. Returns empty strings
    on any error (missing, corrupt, unreadable).
    """
    result = {key_last: "", key_count: 0}
    try:
        if not path.exists():
            return result
        mtime = os.path.getmtime(path)
        last_refresh = (
            datetime.fromtimestamp(mtime, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        result[key_last] = last_refresh
        with open(path, "r") as f:
            data = json.load(f)
        result[key_count] = len(data)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read cache health from %s: %s", path, exc)
    return result
