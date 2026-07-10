"""
Compute EPSS reference distributions for drift monitoring.

Generates synthetic EPSS feature vectors (37-dim v2 format) and computes
per-feature bin distributions (min, max, bins, expected proportions).

Usage:
    python -m scripts.compute_epss_reference

Output:
    backend/ml/epss_reference_distributions.json
"""

import json
import logging
from datetime import datetime, timezone
from itertools import product
from pathlib import Path

logger = logging.getLogger("compute_epss_reference")

# Feature names matching V2_FEATURE_NAMES in epss_substitutor.py
V2_FEATURE_NAMES = [
    "raw_epss",  # 0
    "cvss_score",  # 1
    "exploit_maturity",  # 2
    "cisa_kev",  # 3
    "has_public_poc",  # 4
    "vendor_patch_status",  # 5
    # 11 agency OHE
    "agency_health",
    "agency_transport",
    "agency_education",
    "agency_sharedservices",
    "agency_communities",
    "agency_police",
    "agency_finance",
    "agency_watercorporation",
    "agency_dpird",
    "agency_justice",
    "agency_unknown",
    # 20 CWE OHE
    "cwe_CWE-78",
    "cwe_CWE-89",
    "cwe_CWE-79",
    "cwe_CWE-22",
    "cwe_CWE-434",
    "cwe_CWE-862",
    "cwe_CWE-787",
    "cwe_CWE-125",
    "cwe_CWE-20",
    "cwe_CWE-200",
    "cwe_CWE-287",
    "cwe_CWE-306",
    "cwe_CWE-269",
    "cwe_CWE-295",
    "cwe_CWE-611",
    "cwe_CWE-918",
    "cwe_CWE-190",
    "cwe_CWE-416",
    "cwe_CWE-476",
    "cwe_CWE-352",
]

AGENCIES = [
    "health",
    "transport",
    "education",
    "sharedservices",
    "communities",
    "police",
    "finance",
    "watercorporation",
    "dpird",
    "justice",
    "unknown",
]

CWES = [
    "CWE-78",
    "CWE-89",
    "CWE-79",
    "CWE-22",
    "CWE-434",
    "CWE-862",
    "CWE-787",
    "CWE-125",
    "CWE-20",
    "CWE-200",
    "CWE-287",
    "CWE-306",
    "CWE-269",
    "CWE-295",
    "CWE-611",
    "CWE-918",
    "CWE-190",
    "CWE-416",
    "CWE-476",
    "CWE-352",
]

OUTPUT_PATH = (
    Path(__file__).resolve().parent.parent / "ml" / "epss_reference_distributions.json"
)


def generate_sample_vectors() -> list[dict]:
    """Generate synthetic EPSS feature vectors for reference distribution."""
    samples = []

    # Continuous/ordinal value combinations
    raw_epss_values = [0.001, 0.01, 0.05, 0.1, 0.3, 0.5, 0.7, 0.9, 0.99]
    cvss_values = [3.0, 5.0, 7.0, 9.0]
    exploit_maturity_values = [0, 1, 2, 3]
    kev_values = [False, True]
    poc_values = [False, True]
    patch_status_values = [0, 1, 2]

    # Generate combinations
    for raw_epss, cvss, maturity, kev, poc, patch in product(
        raw_epss_values,
        cvss_values,
        exploit_maturity_values,
        kev_values,
        poc_values,
        patch_status_values,
    ):
        # Start with a base vector
        vector = {
            "raw_epss": raw_epss,
            "cvss_score": cvss,
            "exploit_maturity": float(maturity),
            "cisa_kev": 1.0 if kev else 0.0,
            "has_public_poc": 1.0 if poc else 0.0,
            "vendor_patch_status": float(patch),
        }

        # Add agency OHE (one hot per agency)
        for agency in AGENCIES:
            vector[f"agency_{agency}"] = 0.0

        # Add CWE OHE
        for cwe in CWES:
            vector[f"cwe_{cwe}"] = 0.0

        # Distribute across agencies evenly — each sample gets one agency
        agency_idx = hash((raw_epss, cvss, maturity, kev, poc, patch)) % len(AGENCIES)
        vector[f"agency_{AGENCIES[agency_idx]}"] = 1.0

        # Distribute across CWEs evenly
        cwe_idx = hash((raw_epss, cvss, maturity, kev, poc, patch, "cwe")) % len(CWES)
        vector[f"cwe_{CWES[cwe_idx]}"] = 1.0

        samples.append(vector)

    logger.info("Generated %d synthetic EPSS feature vectors", len(samples))
    return samples


def compute_bin_distribution(values: list[float], num_bins: int = 10) -> dict:
    """Compute bin boundaries and expected proportions for a feature.

    For binary features (0/1), uses 2 bins: [0, 0.5, 1.0].
    For continuous features, uses equally-spaced bins.
    """
    if not values:
        return {
            "min": 0.0,
            "max": 0.0,
            "bins": [0.0, 1.0],
            "expected": [1.0],
        }

    min_val = min(values)
    max_val = max(values)

    # Detect binary features
    unique_vals = set(values)
    if unique_vals <= {0.0, 1.0}:
        bins = [0.0, 0.5, 1.0]
        counts = [0, 0]
        for v in values:
            if v < 0.5:
                counts[0] += 1
            else:
                counts[1] += 1
        total = sum(counts)
        expected = [c / total for c in counts] if total > 0 else [0.5, 0.5]
        return {
            "min": min_val,
            "max": max_val,
            "bins": bins,
            "expected": expected,
        }

    # Continuous/ordinal: use equally-spaced bins
    if max_val == min_val:
        # All same value — single bin
        bins = [min_val, min_val + 1.0]
        expected = [1.0]
    else:
        bins = [
            min_val + i * (max_val - min_val) / num_bins for i in range(num_bins + 1)
        ]
        counts = [0] * num_bins
        for v in values:
            for i in range(num_bins):
                low = bins[i]
                high = bins[i + 1]
                if i == num_bins - 1:
                    if low <= v <= high:
                        counts[i] += 1
                        break
                else:
                    if low <= v < high:
                        counts[i] += 1
                        break
        total = sum(counts)
        expected = (
            [c / total for c in counts] if total > 0 else [1.0 / num_bins] * num_bins
        )

    return {
        "min": min_val,
        "max": max_val,
        "bins": bins,
        "expected": expected,
    }


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    samples = generate_sample_vectors()
    num_samples = len(samples)

    # Compute per-feature distributions
    features = {}
    for fname in V2_FEATURE_NAMES:
        values = [s[fname] for s in samples]
        features[fname] = compute_bin_distribution(values)

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "synthetic_epss_combinations",
        "num_samples": num_samples,
        "features": features,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(result, f, indent=2)

    n_features = len(features)
    logger.info(
        "Wrote %d feature distributions to %s (%d samples)",
        n_features,
        OUTPUT_PATH,
        num_samples,
    )

    # Verify
    with open(OUTPUT_PATH) as f:
        loaded = json.load(f)
    assert loaded["num_samples"] == num_samples
    assert len(loaded["features"]) == len(V2_FEATURE_NAMES)
    logger.info(
        "Verification passed: %d features, %d samples",
        len(loaded["features"]),
        loaded["num_samples"],
    )


if __name__ == "__main__":
    main()
