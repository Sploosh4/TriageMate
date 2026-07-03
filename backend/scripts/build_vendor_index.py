"""
Build vendor_popularity.json from NVD corpus vendor frequency.

Counts vendor occurrences across all CVEs, normalizes to 0.0-1.0,
most common vendor = 0.95.

Input: backend/data/nvd_corpus.json (or nvd_cache.json as fallback)
Output: backend/data/vendor_popularity.json

Usage:
    python -m scripts.build_vendor_index
"""

import json
import logging
from collections import Counter
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("triagemate.build_vendor_index")

DATA_DIR = Path(__file__).parent.parent / "data"


def load_nvd_corpus() -> dict:
    for path in [DATA_DIR / "nvd_corpus.json", DATA_DIR / "nvd_cache.json"]:
        if path.exists():
            try:
                with open(path) as f:
                    data = json.load(f)
                logger.info("Loaded %d entries from %s", len(data), path.name)
                return data
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load %s: %s", path, e)
    logger.error("No NVD corpus found. Run fetch_nvd_corpus.py first.")
    return {}


def count_vendors(corpus: dict) -> Counter:
    counter: Counter = Counter()
    for cve_id, entry in corpus.items():
        vendor = entry.get("vendor", "")
        if vendor:
            counter[vendor.lower()] += 1
    logger.info("Found %d unique vendors across %d CVEs", len(counter), len(corpus))
    return counter


def normalize_frequencies(counts: Counter, max_val: float = 0.95) -> dict[str, float]:
    if not counts:
        return {}
    max_count = counts.most_common(1)[0][1]
    result = {}
    for vendor, count in counts.most_common():
        score = min(count / max_count, max_val)
        score = max(score, 0.05)
        result[vendor] = round(score, 4)
    logger.info(
        "Top 5 vendors: %s",
        {k: result[k] for k in list(result.keys())[:5]},
    )
    return result


def save_index(index: dict):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / "vendor_popularity.json"
    with open(path, "w") as f:
        json.dump(index, f, indent=2)
    logger.info("Saved %d vendors to %s", len(index), path)


def main():
    corpus = load_nvd_corpus()
    if not corpus:
        return
    counts = count_vendors(corpus)
    if not counts:
        logger.warning("No vendors found in corpus.")
        return
    index = normalize_frequencies(counts)
    save_index(index)


if __name__ == "__main__":
    main()
