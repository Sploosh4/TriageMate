"""
Compute reference distributions for Pre-Tier drift monitoring.

Reads from KNOWN_TAGS hostnames in pipeline/pre_tier.py and optionally
from the synthetic_assets table in the database. Extracts the 60-dim
feature vector via ml.pretier_features.extract_features(), bins each
feature's values, and computes expected proportions.

Saves to backend/ml/pre_tier_reference_distributions.json.

Idempotent — running multiple times produces the same output (provided
the input data hasn't changed).
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("triagemate.compute_pretier_reference")

NUM_BINS = 10

# Add backend dir to sys.path so we can import project modules
_backend_dir = str(Path(__file__).resolve().parent.parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

ML_DIR = Path(__file__).resolve().parent.parent / "ml"
OUTPUT_PATH = ML_DIR / "pre_tier_reference_distributions.json"


def _collect_hostnames() -> list[str]:
    """Collect all available hostnames for reference distribution generation.

    Priority order:
    1. KNOWN_TAGS from pipeline/pre_tier.py (31 demo hosts + any extras)
    2. synthetic_assets table from the database (if available)
    """
    hostnames: set[str] = set()

    # 1. KNOWN_TAGS
    try:
        from pipeline.pre_tier import KNOWN_TAGS

        hostnames.update(KNOWN_TAGS.keys())
        logger.info("Loaded %d hostnames from KNOWN_TAGS", len(KNOWN_TAGS))
    except ImportError as e:
        logger.warning("Could not import KNOWN_TAGS: %s", e)

    # 2. synthetic_assets table
    try:
        from database import get_db

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT hostname FROM synthetic_assets")
            for row in cursor.fetchall():
                hostnames.add(row["hostname"])
            logger.info("Loaded %d hostnames from synthetic_assets", cursor.rowcount)
        except Exception as e:
            logger.warning("Could not query synthetic_assets table: %s", e)
        conn.close()
    except ImportError as e:
        logger.warning("Could not import database module: %s", e)

    return list(hostnames)


def _is_binary(values: list) -> bool:
    """Check if a feature appears to be binary (all values are 0 or 1)."""
    return all(v in (0, 1) for v in values if v is not None)


def _is_ordinal_integer(values: list) -> bool:
    """Check if a feature appears to be ordinal integer (small integer range)."""
    non_none = [v for v in values if v is not None]
    if not non_none:
        return False
    return all(isinstance(v, int) for v in non_none)


def _compute_feature_distribution(values: list) -> dict:
    """Compute bin boundaries and expected proportions for one feature.

    Handles binary, ordinal integer, and continuous features differently:
    - Binary: bins = [0.0, 0.5, 1.0]
    - Ordinal integer with small range: one bin per unique value
    - Continuous: 10 equal-width bins from min to max
    """
    non_none = [v for v in values if v is not None]
    if not non_none:
        return {
            "min": 0.0,
            "max": 0.0,
            "bins": [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
            "expected": [1.0] + [0.0] * 9,
        }

    col_min = float(min(non_none))
    col_max = float(max(non_none))

    # Binary case
    if _is_binary(non_none):
        count_0 = sum(1 for v in non_none if v == 0)
        count_1 = sum(1 for v in non_none if v == 1)
        total = count_0 + count_1
        bins = [0.0, 0.5, 1.0]
        expected = [count_0 / total, count_1 / total]
        return {
            "min": col_min,
            "max": col_max,
            "bins": bins,
            "expected": [round(p, 6) for p in expected],
        }

    # Ordinal integer with small range (<= 10 unique values)
    if _is_ordinal_integer(non_none):
        unique_vals = sorted(set(non_none))
        if len(unique_vals) <= 10:
            bins = list(range(int(col_min), int(col_max) + 2))  # +1 for last bin upper
            if len(bins) < 2:
                bins = [col_min, col_max + 1]
            counts = [0] * (len(bins) - 1)
            for v in non_none:
                idx = unique_vals.index(v)
                counts[idx] += 1
            total = sum(counts)
            expected = [c / total for c in counts]
            return {
                "min": col_min,
                "max": col_max,
                "bins": [float(b) for b in bins],
                "expected": [round(p, 6) for p in expected],
            }

    # Continuous: 10 equal-width bins
    bin_width = (col_max - col_min) / NUM_BINS if col_max > col_min else 1.0
    bins = [col_min + j * bin_width for j in range(NUM_BINS + 1)]

    counts = [0] * NUM_BINS
    for val in non_none:
        v = float(val)
        idx = min(int((v - col_min) / bin_width), NUM_BINS - 1) if bin_width > 0 else 0
        if idx < 0:
            idx = 0
        if idx >= NUM_BINS:
            idx = NUM_BINS - 1
        counts[idx] += 1

    total = sum(counts)
    expected = [c / total for c in counts] if total > 0 else [1.0 / NUM_BINS] * NUM_BINS

    bins_rounded = [round(b, 6) for b in bins]
    expected_rounded = [round(p, 6) for p in expected]

    return {
        "min": col_min,
        "max": col_max,
        "bins": bins_rounded,
        "expected": expected_rounded,
    }


def main():
    logger.info("Collecting hostnames for Pre-Tier reference distributions...")
    hostnames = _collect_hostnames()
    logger.info("Total unique hostnames: %d", len(hostnames))

    if not hostnames:
        logger.error("No hostnames available. Run synthetic data generation first.")
        sys.exit(1)

    from ml.pretier_features import extract_features, get_feature_names

    feature_names = get_feature_names()
    logger.info("Feature vector has %d dimensions", len(feature_names))

    # Collect feature values for each hostname
    feature_values: dict[str, list] = {name: [] for name in feature_names}
    success_count = 0
    for hostname in hostnames:
        try:
            features = extract_features(hostname)
            if features is None:
                continue
            for name in feature_names:
                val = features.get(name)
                feature_values[name].append(val)
            success_count += 1
        except Exception as e:
            logger.debug("Failed to extract features for %s: %s", hostname, e)

    logger.info(
        "Successfully extracted features for %d / %d hostnames",
        success_count,
        len(hostnames),
    )

    if success_count == 0:
        logger.error("No features could be extracted. Aborting.")
        sys.exit(1)

    # Compute distributions
    features_output = {}
    for name in feature_names:
        dist = _compute_feature_distribution(feature_values[name])
        features_output[name] = dist

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": f"KNOWN_TAGS ({len(hostnames)} hostnames)",
        "num_samples": success_count,
        "features": features_output,
    }

    logger.info("Writing Pre-Tier reference distributions to %s", OUTPUT_PATH)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    logger.info(
        "Done — %d features written, %d samples",
        len(features_output),
        success_count,
    )


if __name__ == "__main__":
    main()
