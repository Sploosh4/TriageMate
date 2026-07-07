"""
Fetch real EPSS scores from FIRST.org and cache them locally.
Usage: python -m ml.fetch_epss_data [--update]

Downloads the current EPSS score CSV from Cyentia/FIRST.org, parses it,
and caches to backend/data/epss_cache.json for use by the training pipeline.
"""

import csv
import json
import os
import logging
import urllib.request
from datetime import datetime, date

logger = logging.getLogger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "epss_cache.json")


def fetch_epss_data(force_update: bool = False) -> dict:
    """Download and parse the current EPSS data from FIRST.org.

    Returns dict of {cve_id: {"epss": float, "percentile": float, "date": str}}
    """
    cache_dir = os.path.dirname(CACHE_FILE)
    os.makedirs(cache_dir, exist_ok=True)

    # Check cache age — refresh if older than 7 days
    if not force_update and os.path.isfile(CACHE_FILE):
        age = (
            datetime.now() - datetime.fromtimestamp(os.path.getmtime(CACHE_FILE))
        ).days
        if age < 7:
            logger.info("Using cached EPSS data (%d days old)", age)
            with open(CACHE_FILE) as f:
                return json.load(f)
        else:
            logger.info("Cache is %d days old, refreshing...", age)

    import gzip
    import io

    logger.info("Downloading EPSS data from %s ...", EPSS_URL)
    req = urllib.request.Request(EPSS_URL, headers={"User-Agent": "TriageMate/2.5.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = io.BytesIO(resp.read())
        with gzip.GzipFile(fileobj=raw) as gz:
            text = gz.read().decode("utf-8")

    # Parse CSV (skip comment lines starting with #)
    reader = csv.reader(text.splitlines())
    result = {}
    today = date.today().isoformat()
    skipped = 0
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) >= 3:
            cve = row[0].strip()
            try:
                epss = float(row[1])
                pct = float(row[2])
                result[cve] = {"epss": epss, "percentile": pct, "date": today}
            except ValueError:
                skipped += 1
                continue

    with open(CACHE_FILE, "w") as f:
        json.dump(result, f)

    logger.info(
        "Cached %d CVE records to %s (skipped %d unparseable rows)",
        len(result),
        CACHE_FILE,
        skipped,
    )
    return result


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    force = "--update" in sys.argv
    data = fetch_epss_data(force_update=force)

    vals = [v["epss"] for v in data.values()]
    pcts = [v["percentile"] for v in data.values()]

    print(f"\n{'=' * 50}")
    print("  EPSS Data Fetch Complete")
    print(f"{'=' * 50}")
    print(f"  Records fetched:  {len(data):,}")
    print(f"  EPSS range:       {min(vals):.6f} - {max(vals):.6f}")
    print(f"  EPSS mean:        {sum(vals) / len(vals):.6f}")
    print(f"  EPSS median:      {sorted(vals)[len(vals) // 2]:.6f}")
    print(f"  >0.9:             {sum(1 for v in vals if v > 0.9):,} records")
    print(f"  >0.5:             {sum(1 for v in vals if v > 0.5):,} records")
    print(f"  >0.1:             {sum(1 for v in vals if v > 0.1):,} records")
    print(f"  Percentile range: {min(pcts):.2f} - {max(pcts):.2f}")
    print(f"  Cached at:        {CACHE_FILE}")
    print(f"{'=' * 50}")
