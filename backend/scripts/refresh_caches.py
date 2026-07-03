"""
Refresh demo data caches for TriageMate.

Fetches CISA KEV, NVD, and EPSS data into local JSON caches
under backend/data/.

Usage:
    python -m scripts.refresh_caches              # All sources
    python -m scripts.refresh_caches --source nvd  # NVD only
    python -m scripts.refresh_caches --source kev  # KEV only
    python -m scripts.refresh_caches --source epss # EPSS only
"""

import argparse
import csv
import gzip
import io
import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Bulletproof: find .env relative to this script, not CWD
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=str(_env_path))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)

logger = logging.getLogger("triagemate.refresh_caches")

DATA_DIR = Path(__file__).parent.parent / "data"

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# Hardcoded "greatest hits" list of 50 well-known CVEs spanning
# the last several years — used as baseline when mock_cmdb.json
# is not yet available (Phase 1.1 prerequisite).
_GREATEST_HITS = [
    "CVE-2023-34362",
    "CVE-2024-3094",
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2023-44487",
    "CVE-2021-26855",
    "CVE-2022-41040",
    "CVE-2023-23397",
    "CVE-2021-34523",
    "CVE-2022-30190",
    "CVE-2023-21716",
    "CVE-2023-23396",
    "CVE-2021-40444",
    "CVE-2022-26925",
    "CVE-2023-28252",
    "CVE-2021-1675",
    "CVE-2022-21907",
    "CVE-2023-21554",
    "CVE-2021-42287",
    "CVE-2022-34689",
    "CVE-2023-29360",
    "CVE-2021-31207",
    "CVE-2022-23277",
    "CVE-2023-32031",
    "CVE-2021-31196",
    "CVE-2022-24516",
    "CVE-2023-28219",
    "CVE-2021-43890",
    "CVE-2022-37958",
    "CVE-2023-36884",
    "CVE-2021-28437",
    "CVE-2022-21882",
    "CVE-2023-24871",
    "CVE-2021-26414",
    "CVE-2022-37969",
    "CVE-2023-36761",
    "CVE-2021-31955",
    "CVE-2022-30136",
    "CVE-2023-21552",
    "CVE-2021-40450",
    "CVE-2022-44666",
    "CVE-2023-36025",
    "CVE-2021-42278",
    "CVE-2022-38023",
    "CVE-2023-36036",
    "CVE-2021-27065",
    "CVE-2022-21970",
    "CVE-2023-35311",
    "CVE-2021-31962",
    "CVE-2022-24521",
    # Phase 3 scenarios (Intel-approved)
    "CVE-2024-0204",
    "CVE-2020-0796",
    "CVE-2023-3519",
    "CVE-2019-19781",
    "CVE-2021-41063",
    "CVE-2024-47534",
    "CVE-2023-50164",
    "CVE-2024-4317",
    "CVE-2022-0333",
    "CVE-2019-10134",
    "CVE-2024-43427",
]


# ---------------------------------------------------------------------------
# Low-level HTTP helpers (urllib only — matching integrations/nvd.py pattern)
# ---------------------------------------------------------------------------


def _fetch_json(
    url: str, headers: Optional[dict] = None, timeout: int = 30
) -> Optional[dict]:
    """Fetch a URL and parse the response as JSON using ``urllib.request``.

    Returns ``None`` on any HTTP error, network failure, or JSON decode
    error — never raises.
    """
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# NVD response parsing helpers
# ---------------------------------------------------------------------------


def _parse_cvss_v3_score(raw: dict) -> tuple[float, str]:
    """Extract CVSS v3 base score and vector string from an NVD response.

    Tries V31 → V30 → V2 in order; returns ``(0.0, "")`` when none found.
    """
    for vuln in raw.get("vulnerabilities", []):
        metrics = vuln.get("cve", {}).get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                vector = cvss_data.get("vectorString", "")
                return float(score), vector
    return 0.0, ""


def _parse_cwe(raw: dict) -> str:
    """Extract the first CWE-ID from the weaknesses array."""
    for vuln in raw.get("vulnerabilities", []):
        for w in vuln.get("cve", {}).get("weaknesses", []):
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    return val
    return ""


def _parse_description(raw: dict) -> str:
    """Extract the English-language description."""
    for vuln in raw.get("vulnerabilities", []):
        for desc in vuln.get("cve", {}).get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value", "")
    return ""


def _parse_vulnerability_age(raw: dict) -> int:
    """Return days since the CVE was published (0 on parse failure)."""
    for vuln in raw.get("vulnerabilities", []):
        published = vuln.get("cve", {}).get("published", "")
        if published:
            try:
                pub = published.replace("Z", "+00:00")
                pub_dt = datetime.fromisoformat(pub)
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                return (datetime.now(timezone.utc) - pub_dt).days
            except (ValueError, TypeError):
                pass
    return 0


def _parse_references(raw: dict) -> list[dict]:
    """Extract the reference list from the NVD response."""
    for vuln in raw.get("vulnerabilities", []):
        return [
            {"url": r.get("url", ""), "tags": r.get("tags", [])}
            for r in vuln.get("cve", {}).get("references", [])
        ]
    return []


def _has_reference_tag(refs: list[dict], tag_keywords: set) -> bool:
    """Check whether any NVD reference tag contains one of *tag_keywords*."""
    for r in refs:
        for tag in r.get("tags", []):
            for keyword in tag_keywords:
                if keyword.lower() in tag.lower():
                    return True
    return False


def _parse_cvss_subscores(raw: dict) -> tuple[float, float]:
    """Extract exploitability and impact sub-scores from the first metric entry."""
    for vuln in raw.get("vulnerabilities", []):
        metrics = vuln.get("cve", {}).get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key, [])
            if entries:
                e_score = entries[0].get("exploitabilityScore") or 0.0
                i_score = entries[0].get("impactScore") or 0.0
                return float(e_score), float(i_score)
    return 0.0, 0.0


def _parse_vendor_product(raw: dict) -> tuple[str, str]:
    """Parse vendor / product from the first CPE criteria that has both values.

    CPE format: ``cpe:2.3:a:vendor:product:version:...``
    Vendor is field index 3, product is field index 4.
    """
    for vuln in raw.get("vulnerabilities", []):
        for config in vuln.get("cve", {}).get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        if vendor and product and vendor != "*" and product != "*":
                            return vendor, product
    return "", ""


def _extract_nvd_entry(raw: dict) -> dict:
    """Build a structured record from a raw NVD API 2.0 response.

    Returns a dict with all fields required by the NVD cache schema.
    """
    cvss_score, cvss_vector = _parse_cvss_v3_score(raw)
    cwe = _parse_cwe(raw)
    description = _parse_description(raw)
    age = _parse_vulnerability_age(raw)
    refs = _parse_references(raw)
    exploitability_sub, impact_sub = _parse_cvss_subscores(raw)
    vendor, product = _parse_vendor_product(raw)

    return {
        "cvss_v3_score": cvss_score,
        "cvss_v3_vector": cvss_vector,
        "cwe_class": cwe,
        "description": description,
        "vulnerability_age_days": age,
        "patch_available": _has_reference_tag(
            refs, {"Patch", "Vendor Advisory", "vendor-advisory"}
        ),
        "exploitdb_has_poc": _has_reference_tag(refs, {"Exploit"}),
        "metasploit_has_payload": _has_reference_tag(refs, {"Metasploit"}),
        "nvd_reference_count": len(refs),
        "cvss_exploitability_sub": exploitability_sub,
        "cvss_impact_sub": impact_sub,
        "vendor": vendor,
        "product": product,
    }


# ---------------------------------------------------------------------------
# NVD cache refresh
# ---------------------------------------------------------------------------


def refresh_nvd_cache(cve_ids: Optional[list[str]] = None, api_key: str = "") -> dict:
    """Fetch NVD API 2.0 for *cve_ids* and write ``nvd_cache.json``.

    When *cve_ids* is ``None`` it is resolved via :func:`_resolve_cve_list`.

    Rate limiting (via ``time.sleep``):
        - 5  req/s without *api_key*  (0.2 s between requests)
        - 50 req/s with    *api_key*  (0.02 s between requests)

    Returns the full cache dict (also written to disk).
    """
    if cve_ids is None:
        cve_ids = _resolve_cve_list()

    if not cve_ids:
        logger.warning("No CVE IDs provided — skipping NVD cache refresh")
        return {}

    # Load existing cache so we preserve entries for CVEs that error out
    nvd_cache_path = DATA_DIR / "nvd_cache.json"
    nvd_cache: dict = {}
    if nvd_cache_path.exists():
        try:
            with open(nvd_cache_path, "r") as f:
                nvd_cache = json.load(f)
        except (json.JSONDecodeError, OSError):
            logger.warning("Existing nvd_cache.json is corrupt — starting fresh")

    # Public NVD API 2.0 rate limit: 5 requests per 30 s window
    # With API key: 50 requests per 30 s window
    rate_delay = 6.0 if not api_key else 0.6
    total = len(cve_ids)
    logger.info(
        "Refreshing NVD cache for %d CVEs (%.2fs delay between requests)",
        total,
        rate_delay,
    )

    for i, cve_id in enumerate(cve_ids):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"User-Agent": "TriageMate/0.2.0"}
        if api_key:
            headers["apiKey"] = api_key
        # Note: sleep before the request so the first request doesn't wait
        if i > 0:
            time.sleep(rate_delay)
        raw = _fetch_json(url, headers=headers)
        if raw is not None:
            nvd_cache[cve_id] = _extract_nvd_entry(raw)
        else:
            logger.debug("No NVD data for %s — keeping previous entry if any", cve_id)

        if (i + 1) % 50 == 0:
            logger.info("NVD cache progress: %d / %d", i + 1, total)

    # Write to disk
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(nvd_cache_path, "w") as f:
        json.dump(nvd_cache, f, indent=2)

    logger.info("NVD cache written to %s (%d entries)", nvd_cache_path, len(nvd_cache))
    return nvd_cache


# ---------------------------------------------------------------------------
# KEV cache refresh
# ---------------------------------------------------------------------------


def refresh_kev_cache(filter_by_nvd: bool = False) -> dict:
    """Fetch the CISA Known Exploited Vulnerabilities feed and write
    ``kev_cache.json``.

    When *filter_by_nvd* is True and ``nvd_corpus.json`` or ``nvd_cache.json``
    exists, only KEV entries whose CVE is present in the NVD data are kept.
    """
    logger.info("Fetching CISA KEV feed from %s", KEV_URL)
    raw = _fetch_json(KEV_URL, headers={"User-Agent": "TriageMate/0.3.0"}, timeout=30)
    if raw is None:
        logger.error("Failed to fetch KEV feed — KEV cache not updated")
        return {}

    vulnerabilities = raw.get("vulnerabilities", [])
    logger.info("Fetched %d KEV entries from CISA", len(vulnerabilities))

    nvd_cve_ids: set[str] = set()
    if filter_by_nvd:
        for path in [DATA_DIR / "nvd_corpus.json", DATA_DIR / "nvd_cache.json"]:
            if path.exists():
                try:
                    with open(path) as f:
                        nvd_cache = json.load(f)
                    nvd_cve_ids = set(nvd_cache.keys())
                    logger.info(
                        "Loaded %d CVE IDs from %s for filtering",
                        len(nvd_cve_ids),
                        path.name,
                    )
                    break
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning(
                        "Could not read %s: %s — proceeding without filtering",
                        path,
                        exc,
                    )

    kev_cache: dict = {}
    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID")
        if not cve_id:
            continue
        if filter_by_nvd and nvd_cve_ids and cve_id not in nvd_cve_ids:
            continue
        kev_cache[cve_id] = {
            "known_exploited": True,
            "date_added": vuln.get("dateAdded", ""),
            "action": vuln.get("requiredAction", ""),
            "note": vuln.get("notes", ""),
        }

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    kev_cache_path = DATA_DIR / "kev_cache.json"
    try:
        with open(kev_cache_path, "w") as f:
            json.dump(kev_cache, f, indent=2)
        logger.info("Wrote %d KEV entries to %s", len(kev_cache), kev_cache_path)
    except OSError as exc:
        logger.error("Failed to write %s: %s", kev_cache_path, exc)

    return kev_cache


# ---------------------------------------------------------------------------
# EPSS cache refresh
# ---------------------------------------------------------------------------


def refresh_epss_cache() -> dict:
    """Download EPSS scores CSV.gz, parse, and write epss_cache.json.

    Downloads from https://epss.cyentia.com/epss_scores-current.csv.gz,
    decompresses in memory, parses (cve, epss, percentile) columns.

    Returns {cve_id: {epss: float, percentile: float}, ...} (~344K entries).
    """
    EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    logger.info("Downloading EPSS scores from %s", EPSS_URL)

    req = urllib.request.Request(EPSS_URL, headers={"User-Agent": "TriageMate/0.3.0"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            compressed = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        logger.error("Failed to download EPSS CSV: %s", e)
        return {}

    logger.info("Decompressing EPSS CSV (%d bytes)...", len(compressed))
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as gz:
            text = gz.read().decode("utf-8")
    except (OSError, IOError) as e:
        logger.error("Failed to decompress EPSS CSV: %s", e)
        return {}

    reader = csv.reader(io.StringIO(text))
    result: dict = {}
    line_count = 0
    for row in reader:
        line_count += 1
        if line_count == 1:
            continue
        if len(row) < 3:
            continue
        cve = row[0].strip()
        try:
            epss = float(row[1].strip())
            percentile = float(row[2].strip())
        except (ValueError, IndexError):
            continue
        if not cve.startswith("CVE-"):
            continue
        result[cve] = {"epss": epss, "percentile": percentile}

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    epss_path = DATA_DIR / "epss_cache.json"
    try:
        with open(epss_path, "w") as f:
            json.dump(result, f)
        logger.info("Wrote %d EPSS scores to %s", len(result), epss_path)
    except OSError as exc:
        logger.error("Failed to write %s: %s", epss_path, exc)

    return result


# ---------------------------------------------------------------------------
# CVE list resolution
# ---------------------------------------------------------------------------


def _resolve_cve_list() -> list[str]:
    """Assemble a list of CVE IDs that should be fetched for the NVD cache.

    Strategy:
        1. Start with the 50 *greatest hits* CVEs.
        2. If ``mock_cmdb.json`` exists, extract product names from
           registered applications (Phase 1.1 data).  Currently we only
           log the count; full product-to-CVE mapping is deferred to a
           later phase.
        3. Query the NVD API for the top 500 CRITICAL-severity CVEs
           (paginated at 100 per request) and add those IDs.
        4. Return the deduplicated, sorted list.

    The function is deliberately defensive — all external calls are
    wrapped in try/except so a failure never blocks the cache refresh.
    """
    cve_set: set[str] = set(_GREATEST_HITS)

    # ------------------------------------------------------------------
    # Phase 1.1 integration — mock_cmdb.json (graceful if absent)
    # ------------------------------------------------------------------
    mock_cmdb_path = DATA_DIR / "mock_cmdb.json"
    if mock_cmdb_path.exists():
        try:
            with open(mock_cmdb_path, "r") as f:
                cmdb = json.load(f)
            products: set[str] = set()
            if isinstance(cmdb, dict):
                for host_key, host_data in cmdb.items():
                    apps = (
                        host_data.get("registered_applications", [])
                        if isinstance(host_data, dict)
                        else []
                    )
                    if isinstance(apps, list):
                        for app in apps:
                            if isinstance(app, str) and app.strip():
                                # Strip version suffix: "Apache 2.4" -> "Apache"
                                name = app.strip().split()[0]
                                products.add(name.lower())
            if products:
                logger.info(
                    "Extracted %d product names from mock_cmdb.json: %s",
                    len(products),
                    sorted(products)[:10],
                )
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to parse mock_cmdb.json: %s", exc)
    else:
        logger.warning(
            "mock_cmdb.json not found at %s — "
            "using greatest-hits CVEs only (Phase 1.1 not yet done)",
            mock_cmdb_path,
        )

    # ------------------------------------------------------------------
    # Fetch top-500 critical CVEs from NVD
    # ------------------------------------------------------------------
    logger.info("Querying NVD for top-500 CRITICAL CVEs...")
    for offset in range(0, 500, 100):
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?cvssV3Severity=CRITICAL&resultsPerPage=100"
            f"&startIndex={offset}"
        )
        try:
            raw = _fetch_json(
                url, headers={"User-Agent": "TriageMate/0.2.0"}, timeout=30
            )
            if raw is None:
                logger.warning(
                    "Critical CVEs query returned no data at offset %d "
                    "(NVD may be rate-limiting or unavailable)",
                    offset,
                )
                break
            vulns = raw.get("vulnerabilities", [])
            page_count = 0
            for vuln in vulns:
                cve_id = vuln.get("cve", {}).get("id", "")
                if cve_id:
                    cve_set.add(cve_id)
                    page_count += 1
            logger.info(
                "  offset %d: added %d critical CVEs (total unique: %d)",
                offset,
                page_count,
                len(cve_set),
            )
            # Public NVD endpoint: 5 req per 30 s window
            time.sleep(6.0)
        except Exception as exc:
            logger.warning(
                "Error querying NVD critical CVEs at offset %d: %s", offset, exc
            )
            break

    result = sorted(cve_set)
    logger.info("Resolved %d CVE IDs for NVD cache refresh", len(result))
    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse CLI arguments and dispatch to one or all cache refreshers."""
    parser = argparse.ArgumentParser(
        description="Cache refresh CLI for TriageMate demo data sources.",
    )
    parser.add_argument(
        "--source",
        choices=["nvd", "kev", "epss"],
        default=None,
        help="Source to refresh. If omitted, refreshes all.",
    )
    parser.add_argument(
        "--api-key",
        default="",
        help="NVD API 2.0 key (or set NVD_API_KEY env var).",
    )
    args = parser.parse_args()

    api_key = args.api_key or os.getenv("NVD_API_KEY", "")

    # Determine which sources to run
    sources = ["nvd", "kev", "epss"] if args.source is None else [args.source]

    logger.info("Cache refresh starting — sources=%s", sources)

    if "nvd" in sources:
        logger.info("--- NVD cache refresh ---")
        cve_ids = _resolve_cve_list()
        refresh_nvd_cache(cve_ids, api_key=api_key)

    if "kev" in sources:
        logger.info("--- KEV cache refresh ---")
        refresh_kev_cache()

    if "epss" in sources:
        logger.info("--- EPSS cache refresh ---")
        refresh_epss_cache()

    logger.info("Cache refresh complete.")


if __name__ == "__main__":
    main()
