"""
CWE identifier lookup for the ingest pipeline.

Uses NVD API for CWE mapping, with regex fallback from description.
This is NOT an ML classifier — it delegates to backend/integrations/nvd.py for NVD API lookup.

See nvd.py for cache strategy and rate-limit handling.
"""

import re
import logging
from integrations.nvd import get_nvd_data

logger = logging.getLogger("triagemate.cwe")

_CACHE: dict[str, str] = {}
_CACHE_HITS = 0
_CACHE_MISSES = 0


def _regex_fallback(text: str) -> str:
    r"""Extract first CWE-\d+ pattern from text."""
    match = re.search(r"CWE-(\d+)", text)
    if match:
        return f"CWE-{match.group(1)}"
    return ""


def get_cwe(cve_id: str, description: str = "") -> dict:
    """Get CWE classification for a CVE.

    Uses NVD API lookup via nvd.py (which has its own TTL cache).
    Falls back to regex extraction from description if NVD fails.

    Returns:
        dict with 'cwe_class' key (e.g. 'CWE-89') or empty string.
    """
    global _CACHE, _CACHE_HITS, _CACHE_MISSES

    if cve_id in _CACHE:
        _CACHE_HITS += 1
        return {"cwe_class": _CACHE[cve_id]}

    _CACHE_MISSES += 1
    nvd_data = get_nvd_data(cve_id)
    cwe = nvd_data.get("cwe_class", "")
    if not cwe:
        cwe = _regex_fallback(description)
    if not cwe:
        cwe = _regex_fallback(cve_id)
    if not cwe:
        logger.warning("No CWE found for %s via NVD or regex fallback", cve_id)

    _CACHE[cve_id] = cwe
    if _CACHE_MISSES % 10 == 0 and _CACHE_HITS > 0:
        logger.debug("CWE cache: %d hits, %d misses", _CACHE_HITS, _CACHE_MISSES)
    return {"cwe_class": cwe}
