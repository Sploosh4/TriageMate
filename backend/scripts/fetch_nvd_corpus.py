"""
Bulk NVD API 2.0 corpus builder — fetch 200K+ CVEs with full metadata.

Date range: 2019-01-01 to 2025-12-31, 3-month chunks.
Output: backend/data/nvd_corpus.json — {cve_id: {13 fields}, ...}

Usage:
    python -m scripts.fetch_nvd_corpus
        [--start 2019-01-01] [--end 2025-12-31]
        [--limit 1000]       -- test mode, stop after N CVEs
        [--resume]           -- continue from checkpoint
"""

import argparse
import gzip
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import urllib.error
import urllib.request
from dotenv import load_dotenv

# Bulletproof: find .env relative to this script, not CWD
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=str(_env_path))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("triagemate.fetch_nvd_corpus")

DATA_DIR = Path(__file__).parent.parent / "data"
CHECKPOINT_FILE = DATA_DIR / "nvd_fetch_checkpoint.json"
OUTPUT_FILE = DATA_DIR / "nvd_corpus.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
SLEEP_WITH_KEY = 0.2
SLEEP_WITHOUT_KEY = 1.2


def _date_chunks(start_date: str, end_date: str) -> list[tuple[str, str]]:
    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")
    chunks = []
    while start < end:
        chunk_end = start.replace(day=1) + timedelta(days=93)
        chunk_end = chunk_end.replace(day=1) - timedelta(days=1)
        if chunk_end > end:
            chunk_end = end
        if chunk_end <= start:
            chunk_end = end
        chunks.append((start.strftime("%Y-%m-%d"), chunk_end.strftime("%Y-%m-%d")))
        start = chunk_end + timedelta(days=1)
    return chunks


def _fetch_json(
    url: str, headers: dict | None = None, timeout: int = 120
) -> dict | None:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        OSError,
    ) as e:
        logger.warning("HTTP error fetching %s: %s", url, e)
        return None


def _extract_cve_entry(vuln: dict) -> dict | None:
    cve = vuln.get("cve", {})

    # CVSS v3.1 score (required); fall back to v3.0
    cvss_data = None
    for metric in (cve.get("metrics", {}) or {}).get("cvssMetricV31", []):
        cvss_data = metric.get("cvssData")
        break
    if not cvss_data:
        for metric in (cve.get("metrics", {}) or {}).get("cvssMetricV30", []):
            cvss_data = metric.get("cvssData")
            break
    if not cvss_data:
        return None

    cvss_score = cvss_data.get("baseScore", 0)
    if cvss_score <= 0:
        return None

    cvss_vector = cvss_data.get("vectorString", "")

    cwe_class = ""
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_class = val
                break
        if cwe_class:
            break

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    if not description:
        return None

    published = cve.get("published", "")
    age = 0
    if published:
        try:
            pub = published.replace("Z", "+00:00")
            pub_dt = datetime.fromisoformat(pub)
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - pub_dt).days
        except (ValueError, TypeError):
            pass

    refs = cve.get("references", [])
    patch_tags = {"Patch", "Vendor Advisory", "vendor-advisory"}
    patch_available = any(
        any(tag in ref_tags for tag in patch_tags)
        for r in refs
        for ref_tags in [r.get("tags", [])]
    )

    # Metrics for sub-scores (prefer v3.1, fall back to v3.0)
    metrics = cve.get("metrics", {})
    cvss_entries = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if cvss_entries:
        exploit_sub = cvss_entries[0].get("exploitabilityScore") or 0.0
        impact_sub = cvss_entries[0].get("impactScore") or 0.0
    else:
        exploit_sub = 0.0
        impact_sub = 0.0

    vendor = ""
    product = ""
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    v = parts[3]
                    p = parts[4]
                    if v and p and v != "*" and p != "*":
                        vendor = v.lower()
                        product = p.lower()
                        break
            if vendor:
                break
        if vendor:
            break

    return {
        "cvss_v3_score": cvss_score,
        "cvss_v3_vector": cvss_vector,
        "cwe_class": cwe_class,
        "description": description,
        "vulnerability_age_days": age,
        "patch_available": patch_available,
        "exploitdb_has_poc": False,
        "metasploit_has_payload": False,
        "nvd_reference_count": len(refs),
        "cvss_exploitability_sub": float(exploit_sub),
        "cvss_impact_sub": float(impact_sub),
        "vendor": vendor,
        "product": product,
        "osv_published": "",
    }


def _load_checkpoint() -> tuple[dict, set[str], str, int]:
    corpus = {}
    completed: set[str] = set()
    resume_chunk = ""
    resume_page = 0

    if OUTPUT_FILE.exists():
        try:
            with open(OUTPUT_FILE) as f:
                corpus = json.load(f)
            logger.info(
                "Loaded %d existing CVEs from %s", len(corpus), OUTPUT_FILE.name
            )
        except (json.JSONDecodeError, OSError):
            corpus = {}

    if CHECKPOINT_FILE.exists():
        try:
            with open(CHECKPOINT_FILE) as f:
                cp = json.load(f)
            completed = set(cp.get("completed_chunks", []))
            resume_chunk = cp.get("resume_chunk", "")
            resume_page = cp.get("resume_page", 0)
            logger.info(
                "Checkpoint found: completed=%d chunks resume=%s page=%d count=%d",
                len(completed),
                resume_chunk,
                resume_page,
                len(corpus),
            )
        except (json.JSONDecodeError, OSError):
            pass

    return corpus, completed, resume_chunk, resume_page


def _save_checkpoint(corpus: dict, completed: set, resume_chunk: str, resume_page: int):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        cp_tmp = CHECKPOINT_FILE.with_suffix(".tmp")
        with open(cp_tmp, "w") as f:
            json.dump(
                {
                    "completed_chunks": sorted(completed),
                    "resume_chunk": resume_chunk,
                    "resume_page": resume_page,
                    "count": len(corpus),
                },
                f,
            )
        cp_tmp.replace(CHECKPOINT_FILE)

        corpus_tmp = OUTPUT_FILE.with_suffix(".tmp")
        with open(corpus_tmp, "w") as f:
            json.dump(corpus, f, indent=2)
        corpus_tmp.replace(OUTPUT_FILE)
    except OSError:
        pass


def fetch_nvd_corpus(
    start_date: str = "2019-01-01",
    end_date: str = "2025-12-31",
    limit: int = 0,
    resume: bool = False,
) -> dict:
    api_key = os.getenv("NVD_API_KEY", "")
    sleep_time = SLEEP_WITH_KEY if api_key else SLEEP_WITHOUT_KEY

    if resume:
        corpus, completed, resume_chunk, resume_page = _load_checkpoint()
    else:
        corpus, completed, resume_chunk, resume_page = {}, set(), "", 0

    chunks = _date_chunks(start_date, end_date)

    for chunk_start, chunk_end in chunks:
        chunk_key = f"{chunk_start}_{chunk_end}"

        # Skip fully completed chunks
        if chunk_key in completed:
            continue

        # Resume: set page_start if this is the in-progress chunk
        page_start = resume_page if resume and chunk_key == resume_chunk else 0
        chunk_total = 0

        while True:
            if limit > 0 and len(corpus) >= limit:
                logger.info("Reached --limit %d, stopping", limit)
                _save_checkpoint(corpus, completed, chunk_key, page_start)
                return corpus

            params = (
                f"pubStartDate={chunk_start}T00:00:00.000"
                f"&pubEndDate={chunk_end}T23:59:59.999"
                f"&startIndex={page_start}"
                f"&resultsPerPage={RESULTS_PER_PAGE}"
            )
            url = f"{NVD_API}?{params}"
            headers = {"User-Agent": "TriageMate/0.3.0"}
            if api_key:
                headers["apiKey"] = api_key

            logger.info(
                "Fetching %s..%s page at index %d (total: %d)",
                chunk_start,
                chunk_end,
                page_start,
                len(corpus),
            )

            resp = None
            for attempt in range(5):
                resp = _fetch_json(url, headers=headers)
                if resp is not None:
                    break
                wait = (attempt + 1) * 15
                logger.warning("Retrying in %ds (attempt %d/5)...", wait, attempt + 1)
                time.sleep(wait)
            else:
                logger.error(
                    "NVD API unavailable after 5 attempts at %s..%s page %d. "
                    "Saved %d CVEs. Run with --resume to continue when NVD recovers.",
                    chunk_start,
                    chunk_end,
                    page_start,
                    len(corpus),
                )
                _save_checkpoint(corpus, completed, chunk_key, page_start)
                return corpus

            vulns = resp.get("vulnerabilities", [])
            for vuln in vulns:
                if limit > 0 and len(corpus) >= limit:
                    break
                entry = _extract_cve_entry(vuln)
                if entry is not None:
                    cve_id = vuln.get("cve", {}).get("id", "")
                    if cve_id:
                        corpus[cve_id] = entry
                        chunk_total += 1

            page_start += RESULTS_PER_PAGE

            if len(vulns) < RESULTS_PER_PAGE:
                completed.add(chunk_key)
                logger.info(
                    "Chunk %s done: %d CVEs in chunk, %d total, %d chunks complete",
                    chunk_key,
                    chunk_total,
                    len(corpus),
                    len(completed),
                )
                _save_checkpoint(corpus, completed, chunk_key, 0)
                break

            time.sleep(sleep_time)

    logger.info(
        "Fetch complete: %d CVEs in corpus across %d chunks",
        len(corpus),
        len(completed),
    )
    _save_checkpoint(corpus, completed, "COMPLETE", 0)
    return corpus


def fetch_from_feeds(
    start_date: str = "2019-01-01",
    end_date: str = "2025-12-31",
    limit: int = 0,
    existing: dict | None = None,
) -> dict:
    """Fallback: download NVD 2.0 yearly gzipped JSON feeds.

    URL: nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{YEAR}.json.gz
    Same response format as API 2.0 — reuses _extract_cve_entry().
    No API key needed. Each year is ~25MB gzipped.
    """
    start_year = int(start_date[:4])
    end_year = int(end_date[:4])
    corpus: dict[str, dict] = existing if existing is not None else {}
    total_available = 0

    for year in range(start_year, end_year + 1):
        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
        logger.info("Downloading feed: %d", year)
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "TriageMate/0.3.0"}
            )
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(gzip.decompress(resp.read()))
        except Exception as e:
            logger.warning("Feed download failed for %d: %s", year, e)
            continue

        vulns = data.get("vulnerabilities", [])
        total_available += data.get("totalResults", len(vulns))
        logger.info(
            "  %d CVEs in %d feed (total available: %d)",
            len(vulns),
            year,
            total_available,
        )
        year_total = 0
        for vuln in vulns:
            if limit > 0 and len(corpus) >= limit:
                break
            entry = _extract_cve_entry(vuln)
            if entry is not None:
                cve_id = vuln.get("cve", {}).get("id", "")
                if cve_id:
                    corpus[cve_id] = entry
                    year_total += 1

        logger.info(
            "  Extracted %d CVEs from %d feed (%d total)", year_total, year, len(corpus)
        )
        if limit > 0 and len(corpus) >= limit:
            break

    logger.info(
        "Feed fetch complete: %d CVEs across %d-%d", len(corpus), start_year, end_year
    )
    return corpus


def main():
    parser = argparse.ArgumentParser(description="Bulk NVD corpus builder")
    parser.add_argument("--start", default="2019-01-01")
    parser.add_argument("--end", default="2025-12-31")
    parser.add_argument(
        "--limit", type=int, default=0, help="Stop after N CVEs (test mode)"
    )
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument(
        "--use-feeds",
        action="store_true",
        help="Use NVD yearly feeds instead of API (more reliable)",
    )
    parser.add_argument(
        "--kev-ids",
        type=str,
        default="",
        help="Path to kev_cache.json — fetch any KEV CVEs still missing from corpus",
    )
    args = parser.parse_args()

    logger.info("Starting NVD corpus fetch: %s to %s", args.start, args.end)
    if args.limit:
        logger.info("Test mode: limit=%d CVEs", args.limit)
    if args.resume:
        logger.info("Resume mode: will skip completed chunks")

    # When --kev-ids is the primary mode, skip date-range fetch and
    # load existing corpus directly (unless explicit start/end given)
    skip_fetch = (
        args.kev_ids and args.start == "2019-01-01" and args.end == "2025-12-31"
    )

    if args.use_feeds:
        existing_corpus = {}
        if OUTPUT_FILE.exists():
            try:
                with open(OUTPUT_FILE) as f:
                    existing_corpus = json.load(f)
                logger.info("Loaded existing corpus: %d CVEs", len(existing_corpus))
            except (json.JSONDecodeError, OSError):
                pass
        corpus = fetch_from_feeds(
            start_date=args.start,
            end_date=args.end,
            limit=args.limit,
            existing=existing_corpus,
        )
    elif skip_fetch:
        if OUTPUT_FILE.exists():
            try:
                with open(OUTPUT_FILE) as f:
                    corpus = json.load(f)
                logger.info("Loaded existing corpus: %d CVEs", len(corpus))
            except (json.JSONDecodeError, OSError):
                corpus = {}
        else:
            corpus = {}
    else:
        corpus = fetch_nvd_corpus(
            start_date=args.start,
            end_date=args.end,
            limit=args.limit,
            resume=args.resume,
        )

    if args.kev_ids:
        kev_path = Path(args.kev_ids)
        if not kev_path.exists():
            logger.error("KEV cache not found: %s", kev_path)
        else:
            with open(kev_path) as f:
                kev_cache = json.load(f)
            missing_ids = [cid for cid in kev_cache if cid not in corpus]
            if missing_ids:
                logger.info(
                    "Missing %d KEV CVEs — fetching individually by CVE ID",
                    len(missing_ids),
                )
                api_key = os.getenv("NVD_API_KEY", "")
                sleep_time = SLEEP_WITH_KEY if api_key else SLEEP_WITHOUT_KEY
                for idx, cve_id in enumerate(missing_ids):
                    url = f"{NVD_API}?cveId={cve_id}"
                    headers = {"User-Agent": "TriageMate/0.3.0"}
                    if api_key:
                        headers["apiKey"] = api_key
                    resp = _fetch_json(url, headers=headers)
                    if resp:
                        vulns = resp.get("vulnerabilities", [])
                        for vuln in vulns:
                            entry = _extract_cve_entry(vuln)
                            if entry is not None:
                                cid = vuln.get("cve", {}).get("id", "")
                                if cid:
                                    corpus[cid] = entry
                    if (idx + 1) % 10 == 0:
                        logger.info("  KEV backfill: %d/%d", idx + 1, len(missing_ids))
                    time.sleep(sleep_time)
                logger.info(
                    "KEV backfill complete: corpus now has %d CVEs", len(corpus)
                )
            else:
                logger.info("All KEV CVEs already in corpus — nothing to backfill")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(corpus, f, indent=2)
    logger.info("Corpus saved with %d CVEs", len(corpus))


if __name__ == "__main__":
    main()
