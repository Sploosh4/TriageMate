"""
Aggregate Tenable vulnerability scan findings by (CVE, sector) for EPSS
substitution model training data.

Reads a raw Tenable batch JSON export (list of dicts with ``asset`` and
``plugin`` keys) and produces a grouped count per (CVE, sector) pair.

Usage:
    python -m scripts.aggregate_tenable_sectors --input findings.json
    python -m scripts.aggregate_tenable_sectors --test
    python -m scripts.aggregate_tenable_sectors --input findings.json --output out.json
    python -m scripts.aggregate_tenable_sectors --input findings.json --min-frequency 3

Input format (matches ``parse_tenable_batch()`` in
``backend/integrations/tenable.py``):
    [
      {
        "asset": {"fqdn": "per-PRD-MOVEIT-WEB01.health.wa.gov.au", "ipv4": "10.0.0.1"},
        "plugin": {"cve": ["CVE-2023-34362"], "cvss3_base_score": 9.8}
      },
      ...
    ]

Output format:
    {
      "CVE-2023-34362": {"health": 3, "transport": 1},
      "CVE-2023-4966": {"transport": 2},
      "_metadata": {
        "total_findings": 7,
        "unique_cves": 2,
        "unique_sectors": 2,
        "generated_at": "2026-07-08T14:00:00"
      }
    }
"""

import argparse
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from ml.epss_substitutor import _extract_agency

logger = logging.getLogger("triagemate.aggregate_tenable_sectors")

# ═════════════════════════════════════════════════════════════════════════════
# Core aggregation logic
# ═════════════════════════════════════════════════════════════════════════════


def _extract_hostname(asset: dict) -> str:
    """Extract FQDN from asset, falling back to hostname then ``"unknown"``."""
    fqdn = asset.get("fqdn")
    if fqdn and isinstance(fqdn, str):
        return fqdn
    hostname = asset.get("hostname")
    if hostname and isinstance(hostname, str):
        return hostname
    return "unknown"


def aggregate_findings(
    findings: list[dict],
    min_frequency: int = 1,
) -> dict[str, Any]:
    """Group Tenable findings by (CVE, sector) and count occurrences.

    Args:
        findings: A list of Tenable finding dicts, each containing
            ``asset`` and ``plugin`` keys.
        min_frequency: Minimum count threshold for a (CVE, sector) pair
            to be included in the result.

    Returns:
        A dict mapping CVE IDs to sector-count dicts, plus a ``_metadata``
        key with summary statistics.
    """
    counter: dict[tuple[str, str], int] = defaultdict(int)

    for idx, finding in enumerate(findings):
        plugin = finding.get("plugin", {})
        if not isinstance(plugin, dict):
            logger.warning("Finding at index %d has no plugin dict — skipping", idx)
            continue

        cve_list = plugin.get("cve", [])
        if not cve_list or not isinstance(cve_list, list) or not cve_list[0]:
            logger.warning(
                "Finding at index %d has no CVE in plugin.cve — skipping", idx
            )
            continue

        cve_id = cve_list[0].strip()

        asset = finding.get("asset", {})
        if not isinstance(asset, dict):
            logger.warning("Finding at index %d has no asset dict — skipping", idx)
            continue

        hostname = _extract_hostname(asset)
        sector = _extract_agency(hostname)

        counter[(cve_id, sector)] += 1

    # Build the output dict, filtering by min_frequency
    result: dict[str, Any] = {}
    cve_sectors: dict[str, set[str]] = defaultdict(set)

    for (cve_id, sector), count in counter.items():
        if count < min_frequency:
            continue
        if cve_id not in result:
            result[cve_id] = {}
        result[cve_id][sector] = count
        cve_sectors[cve_id].add(sector)

    # Attach metadata
    all_sectors: set[str] = {
        sector for sectors in cve_sectors.values() for sector in sectors
    }
    result["_metadata"] = {
        "total_findings": sum(counter.values()),
        "unique_cves": len(cve_sectors),
        "unique_sectors": len(all_sectors),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
    }

    return result


# ═════════════════════════════════════════════════════════════════════════════
# Test data and CLI
# ═════════════════════════════════════════════════════════════════════════════

_TEST_FINDINGS = [
    {
        "asset": {"fqdn": "per-PRD-MOVEIT-WEB01.health.wa.gov.au", "ipv4": "10.0.0.1"},
        "plugin": {"cve": ["CVE-2023-34362"], "cvss3_base_score": 9.8},
    },
    {
        "asset": {
            "fqdn": "prd-hris-app01.transport.wa.gov.au",
            "ipv4": "10.0.0.2",
        },
        "plugin": {"cve": ["CVE-2023-34362"], "cvss3_base_score": 9.8},
    },
    {
        "asset": {
            "fqdn": "edu-sis-db01.education.wa.gov.au",
            "ipv4": "10.0.0.3",
        },
        "plugin": {"cve": ["CVE-2023-34362"], "cvss3_base_score": 9.8},
    },
    {
        "asset": {
            "fqdn": "fin-ess-app01.sharedservices.wa.gov.au",
            "ipv4": "10.0.0.4",
        },
        "plugin": {"cve": ["CVE-2023-4966"], "cvss3_base_score": 7.5},
    },
    {
        "asset": {
            "fqdn": "prd-gateway01.transport.wa.gov.au",
            "ipv4": "10.0.0.5",
        },
        "plugin": {"cve": ["CVE-2023-4966"], "cvss3_base_score": 7.5},
    },
]


def _run_test() -> None:
    """Run the aggregation pipeline against inline test data."""
    print("=" * 60)
    print("TriageMate — Tenable Sector Aggregation (Test Mode)")
    print("=" * 60)
    print()
    print(f"Test findings: {len(_TEST_FINDINGS)}")
    for f in _TEST_FINDINGS:
        host = f["asset"]["fqdn"]
        cve = f["plugin"]["cve"][0]
        sector = _extract_agency(host)
        print(f"  {host:55s} → {sector:20s} {cve}")
    print()

    result = aggregate_findings(_TEST_FINDINGS)

    print("Aggregation result:")
    print(json.dumps(result, indent=2))

    # Basic sanity assertions
    meta = result["_metadata"]
    assert meta["total_findings"] == 5, f"Expected 5, got {meta['total_findings']}"
    assert meta["unique_cves"] == 2, f"Expected 2 CVEs, got {meta['unique_cves']}"
    assert "generated_at" in meta, "Missing generated_at"

    # CVE-2023-34362 should appear in 3 sectors
    assert "CVE-2023-34362" in result
    assert result["CVE-2023-34362"]["health"] == 1
    assert result["CVE-2023-34362"]["transport"] == 1
    assert result["CVE-2023-34362"]["education"] == 1

    # CVE-2023-4966 should appear in 2 sectors
    assert "CVE-2023-4966" in result
    assert result["CVE-2023-4966"]["transport"] == 1
    assert result["CVE-2023-4966"]["sharedservices"] == 1

    print()
    print("✓ All test assertions passed.")


# ═════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ═════════════════════════════════════════════════════════════════════════════


def main() -> None:
    """Parse CLI arguments, aggregate findings, and write output."""
    parser = argparse.ArgumentParser(
        description="Aggregate Tenable findings by (CVE, sector) for EPSS "
        "training data.",
    )
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Path to a JSON file containing a list of Tenable findings.",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run with inline hardcoded test data (4-5 findings).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to write the aggregation JSON (default: stdout).",
    )
    parser.add_argument(
        "--min-frequency",
        type=int,
        default=1,
        help="Minimum count to include a (CVE, sector) pair (default: 1).",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.test:
        _run_test()
        return

    if args.input:
        with open(args.input, "r") as f:
            findings = json.load(f)
    else:
        parser.print_help()
        sys.exit(1)

    result = aggregate_findings(findings, min_frequency=args.min_frequency)

    output = json.dumps(result, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        logger.info("Wrote aggregation to %s", args.output)
    else:
        sys.stdout.write(output)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
