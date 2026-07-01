"""
NVD API 2.0 client for CVE metadata enrichment.

Returns CWE class, reference count, age, and CVSS sub-scores.
24h TTL in-memory cache. NVD_API_KEY env var is optional.
"""

import os
import json
import time
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone

logger = logging.getLogger("triagemate.nvd")

_CACHE: dict[str, tuple[float, dict]] = {}
_TTL_SECONDS = 86400  # 24 hours


def _fetch_cve_data(cve_id: str) -> dict:
    """Query NVD API 2.0 for a single CVE. Returns raw JSON dict or empty dict."""
    api_key = os.getenv("NVD_API_KEY", "")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "TriageMate/0.2.0"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        OSError,
    ) as e:
        logger.warning("NVD fetch failed for %s: %s", cve_id, e)
        return {}


def _parse_cwe(raw: dict) -> str:
    """Extract first CWE-ID from NVD weaknesses array."""
    for vuln in raw.get("vulnerabilities", []):
        for w in vuln.get("cve", {}).get("weaknesses", []):
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    return val
    return ""


def _parse_publish_date(raw: dict) -> str:
    """Extract ISO-8601 publish date from NVD response."""
    for vuln in raw.get("vulnerabilities", []):
        published = vuln.get("cve", {}).get("published", "")
        if published:
            return published
    return ""


def _parse_reference_count(raw: dict) -> int:
    """Count reference links in NVD response."""
    for vuln in raw.get("vulnerabilities", []):
        refs = vuln.get("cve", {}).get("references", [])
        return len(refs)
    return 0


def _parse_cvss_scores(raw: dict) -> tuple[float, float]:
    """Extract exploitability sub-score and impact sub-score from NVD response.

    NVD API 2.0 places these at the metric entry level, not inside cvssData.
    """
    for vuln in raw.get("vulnerabilities", []):
        metrics = vuln.get("cve", {}).get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key, [])
            if entries:
                entry = entries[0]
                e_score = entry.get("exploitabilityScore") or 0.0
                i_score = entry.get("impactScore") or 0.0
                return float(e_score), float(i_score)
    return 0.0, 0.0


def get_nvd_data(cve_id: str) -> dict:
    """Fetch NVD enrichment data for a CVE with 24h in-memory TTL cache.

    Returns:
        dict with keys: cwe_class, nvd_reference_count, vulnerability_age_days,
                        cvss_exploitability_sub, cvss_impact_sub
    """
    now = time.time()
    if cve_id in _CACHE:
        ts, data = _CACHE[cve_id]
        if now - ts < _TTL_SECONDS:
            return dict(data)

    raw = _fetch_cve_data(cve_id)
    if not raw:
        logger.warning("NVD returned no data for %s — enrichment will be empty", cve_id)
        result = {
            "cwe_class": "",
            "nvd_reference_count": 0,
            "vulnerability_age_days": 0,
            "cvss_exploitability_sub": 0.0,
            "cvss_impact_sub": 0.0,
        }
        _CACHE[cve_id] = (now, result)
        return dict(result)

    cwe = _parse_cwe(raw)
    published = _parse_publish_date(raw)
    age = 0
    if published:
        try:
            pub = published.replace("Z", "+00:00")
            pub_dt = datetime.fromisoformat(pub)
            if pub_dt.tzinfo is None:
                from datetime import timezone as tz_mod

                pub_dt = pub_dt.replace(tzinfo=tz_mod.utc)
            age = (datetime.now(timezone.utc) - pub_dt).days
        except (ValueError, TypeError):
            age = 0

    ref_count = _parse_reference_count(raw)
    exploit_sub, impact_sub = _parse_cvss_scores(raw)

    result = {
        "cwe_class": cwe,
        "nvd_reference_count": ref_count,
        "vulnerability_age_days": age,
        "cvss_exploitability_sub": exploit_sub,
        "cvss_impact_sub": impact_sub,
    }
    _CACHE[cve_id] = (now, result)
    return dict(result)
