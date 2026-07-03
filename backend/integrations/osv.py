"""
OSV.dev client for precise patch/fix version data.

Free, no API key required. Returns fixed-in-version data for open-source
packages. 1-hour TTL in-memory cache.
"""

import time
import logging

import requests

logger = logging.getLogger("triagemate.osv")

_CACHE: dict[str, tuple[float, dict]] = {}
CACHE_TTL = 3600


def query_osv(cve_id: str) -> dict:
    """Query OSV.dev for fix version data for a CVE.

    GET /v1/vulns/{cve_id} — the correct endpoint for looking up by CVE ID.
    Returns safe defaults on any error.

    Returns:
        dict with keys: fixed_available, fixed_versions, package_name,
                        package_ecosystem, queried
    """
    now = time.time()

    if cve_id in _CACHE:
        ts, data = _CACHE[cve_id]
        if now - ts < CACHE_TTL:
            return dict(data)

    start = time.time()
    try:
        resp = requests.get(
            f"https://api.osv.dev/v1/vulns/{cve_id}",
            timeout=10,
        )
        if resp.status_code == 404:
            result = {
                "fixed_available": False,
                "fixed_versions": [],
                "package_name": "",
                "package_ecosystem": "",
                "osv_published": "",
                "queried": True,
            }
            _CACHE[cve_id] = (now, result)
            return dict(result)

        resp.raise_for_status()
        data = resp.json()
        published_date = data.get("published", "")

        affected = data.get("affected", [])
        if not affected:
            result = {
                "fixed_available": False,
                "fixed_versions": [],
                "package_name": "",
                "package_ecosystem": "",
                "osv_published": "",
                "queried": True,
            }
            _CACHE[cve_id] = (now, result)
            return dict(result)

        result = _parse_osv_response([{"affected": affected}])
        result["osv_published"] = published_date

        duration_ms = int((time.time() - start) * 1000)
        logger.info(
            "OSV query for %s: fixed=%s, packages=%d, duration=%dms",
            cve_id,
            result["fixed_available"],
            len(result.get("fixed_versions", [])),
            duration_ms,
            extra={
                "event": "osv_call",
                "cve_id": cve_id,
                "fixed_available": result["fixed_available"],
                "duration_ms": duration_ms,
            },
        )

        _CACHE[cve_id] = (now, result)
        return dict(result)

    except requests.RequestException as e:
        duration_ms = int((time.time() - start) * 1000)
        logger.warning(
            "OSV GET query failed for %s: %s",
            cve_id,
            e,
            extra={"event": "osv_call", "cve_id": cve_id, "duration_ms": duration_ms},
        )
        result = {
            "fixed_available": False,
            "fixed_versions": [],
            "package_name": "",
            "package_ecosystem": "",
            "osv_published": "",
            "queried": False,
        }
        _CACHE[cve_id] = (now, result)
        return dict(result)


def _parse_osv_response(vulns: list) -> dict:
    """Parse OSV response for fixed version data across all affected packages.

    Scans all vulnerable version ranges for "fixed" events and collects
    package names and ecosystems.
    """
    fixed_versions = []
    package_name = ""
    package_ecosystem = ""

    for vuln in vulns:
        affected_list = vuln.get("affected", []) if isinstance(vuln, dict) else []
        for affected in affected_list:
            pkg = affected.get("package", {})
            pkg_name = pkg.get("name", "")
            pkg_eco = pkg.get("ecosystem", "")

            if pkg_name and not package_name:
                package_name = pkg_name
            if pkg_eco and not package_ecosystem:
                package_ecosystem = pkg_eco

            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed", "")
                    if fixed and fixed not in fixed_versions:
                        fixed_versions.append(fixed)

    return {
        "fixed_available": len(fixed_versions) > 0,
        "fixed_versions": fixed_versions,
        "package_name": package_name,
        "package_ecosystem": package_ecosystem,
        "osv_published": "",
        "queried": True,
    }
