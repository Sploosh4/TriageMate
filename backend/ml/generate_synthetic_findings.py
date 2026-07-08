"""
Generate synthetic Tenable-style vulnerability findings for EPSS v4 training.

Reads CVE patterns from research_references table and synthetic hostnames from
synthetic_assets, cross-references with the real EPSS cache, and produces
sector-specific vulnerability findings with realistic exploitation rates.

Outputs:
  - JSON backup to backend/ml/synthetic_findings_v4.json
  - Inserts into synthetic_findings DB table (via ingest_synthetic_to_db pattern)

Target: 550+ findings across 23 agencies.
"""

import json
import logging
import os
import random
import sys

import numpy as np

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from database import get_db, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("triagemate.gen_synthetic_findings")

random.seed(42)
np.random.seed(42)

# ── Paths ───────────────────────────────────────────────────────────────────
EPSS_CACHE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "epss_cache.json"
)
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "synthetic_findings_v4.json")

# ── Agency → Model agency mapping ───────────────────────────────────────────
# Maps the 23 synthetic_assets agency names to the 10 model agencies
AGENCY_TO_MODEL = {
    "health": "health",
    "wachs": "health",
    "transport": "transport",
    "mrwa": "transport",
    "pta": "transport",
    "education": "education",
    "police": "police",
    "finance": "finance",
    "sharedservices": "sharedservices",
    "justice": "justice",
    "communities": "communities",
    "dpird": "dpird",
    "dwer": "dpird",
    "dbca": "dpird",
    "watercorp": "watercorporation",
    "dfes": "health",
    "dhw": "sharedservices",
    "cits": "communities",
    "deed": "finance",
    "oag": "finance",
    "ccc": "justice",
    "parliament": "education",
    "elections": "finance",
}

# ── Sector risk profiles ─────────────────────────────────────────────────────
# Higher values = higher exploitation rates for that sector
SECTOR_RISK = {
    "health": 0.25,
    "police": 0.25,
    "justice": 0.25,
    "transport": 0.15,
    "finance": 0.15,
    "sharedservices": 0.15,
    "communities": 0.15,
    "education": 0.10,
    "dpird": 0.05,
    "watercorporation": 0.05,
}

# ── CVE definitions from research report Sections 5.1-5.5 ────────────────────
# Each entry: (CVE_ID, CWE, CVSS, is_KEV, software, relevant_agencies)
# relevant_agencies: list of model agency names, or "ALL" for all 10
CVE_DEFINITIONS = [
    # ── MOVEit Transfer ──
    (
        "CVE-2023-34362",
        "CWE-89",
        9.8,
        True,
        "MOVEit Transfer",
        ["health", "justice", "transport"],
    ),
    (
        "CVE-2024-0204",
        "CWE-306",
        9.1,
        True,
        "MOVEit Transfer",
        ["health", "justice", "transport"],
    ),
    (
        "CVE-2024-5806",
        "CWE-306",
        9.8,
        True,
        "MOVEit Transfer",
        ["health", "justice", "transport"],
    ),
    # ── Citrix ADC / NetScaler (perimeter — all agencies) ──
    ("CVE-2023-3519", "CWE-78", 9.8, True, "Citrix ADC", "ALL"),
    ("CVE-2019-19781", "CWE-78", 9.8, True, "Citrix ADC", "ALL"),
    ("CVE-2023-4966", "CWE-200", 8.2, True, "Citrix ADC", "ALL"),
    # ── Atlassian Confluence ──
    (
        "CVE-2023-22515",
        "CWE-306",
        9.8,
        True,
        "Confluence",
        ["police", "health", "transport", "finance"],
    ),
    (
        "CVE-2023-22518",
        "CWE-862",
        9.8,
        True,
        "Confluence",
        ["police", "health", "transport", "finance"],
    ),
    (
        "CVE-2022-26134",
        "CWE-78",
        9.8,
        True,
        "Confluence",
        ["police", "health", "transport", "finance"],
    ),
    # ── ManageEngine ──
    (
        "CVE-2022-47966",
        "CWE-306",
        9.8,
        True,
        "ManageEngine",
        ["sharedservices", "finance", "health", "transport"],
    ),
    (
        "CVE-2024-4317",
        "CWE-306",
        8.7,
        True,
        "ManageEngine",
        ["sharedservices", "finance", "health", "transport"],
    ),
    # ── Microsoft Exchange (ALL agencies) ──
    ("CVE-2023-23397", "CWE-287", 9.8, True, "Exchange", "ALL"),
    ("CVE-2021-26855", "CWE-918", 9.8, True, "Exchange", "ALL"),
    # ── PaperCut ──
    (
        "CVE-2023-27350",
        "CWE-434",
        9.8,
        True,
        "PaperCut MF",
        ["education", "health", "justice"],
    ),
    # ── ScreenConnect ──
    (
        "CVE-2024-1708",
        "CWE-306",
        9.8,
        True,
        "ScreenConnect",
        ["sharedservices", "health"],
    ),
    # ── Microsoft Office / Windows ──
    ("CVE-2023-36884", "CWE-78", 8.3, True, "Office/Windows", "ALL"),
    # ── Oracle ──
    (
        "CVE-2020-14750",
        "CWE-306",
        9.8,
        True,
        "Oracle WebLogic",
        ["finance", "health", "dpird"],
    ),
    ("CVE-2026-35273", "CWE-287", 9.8, True, "Oracle", ["finance", "health"]),
    (
        "CVE-2024-21182",
        "CWE-89",
        8.3,
        False,
        "Oracle EBS",
        ["finance", "health", "dpird"],
    ),
    # ── SharePoint ──
    (
        "CVE-2023-24955",
        "CWE-287",
        9.8,
        True,
        "SharePoint",
        ["education", "health", "finance", "dpird"],
    ),
    # ── Infrastructure / Cross-platform ──
    ("CVE-2022-0492", "CWE-269", 7.8, True, "Linux kernel", "ALL"),
    ("CVE-2008-4250", "CWE-94", 9.8, True, "Windows MS08-067", "ALL"),
    ("CVE-2020-0796", "CWE-787", 10.0, True, "Windows SMBGhost", "ALL"),
]


def _get_agency_list(cve_agencies: list | str) -> list:
    """Return the list of model agency names for a CVE."""
    if cve_agencies == "ALL":
        return list(AGENCY_TO_MODEL.values())
    # Deduplicate while preserving order; map through AGENCY_TO_MODEL
    seen = set()
    result = []
    for a in cve_agencies:
        mapped = AGENCY_TO_MODEL.get(a, a)
        if mapped not in seen:
            seen.add(mapped)
            result.append(mapped)
    return result


def _load_epss_cache() -> dict:
    """Load real EPSS scores from cache."""
    if not os.path.isfile(EPSS_CACHE_PATH):
        logger.warning("No EPSS cache at %s — using fallback", EPSS_CACHE_PATH)
        return {}
    with open(EPSS_CACHE_PATH) as f:
        return json.load(f)


def _load_hosts_by_agency() -> dict[str, list[dict]]:
    """Load synthetic_assets and group by agency."""
    init_db()
    db = get_db()
    try:
        rows = db.execute("SELECT hostname, agency FROM synthetic_assets").fetchall()
    finally:
        db.close()

    hosts_by_agency: dict[str, list[dict]] = {}
    for row in rows:
        agency_name = row["agency"]
        model_agency = AGENCY_TO_MODEL.get(agency_name, "unknown")
        hosts_by_agency.setdefault(model_agency, []).append(
            {"hostname": row["hostname"], "agency": agency_name}
        )
    logger.info(
        "Loaded %d hosts across %d model agencies",
        sum(len(v) for v in hosts_by_agency.values()),
        len(hosts_by_agency),
    )
    for agency, hosts in sorted(hosts_by_agency.items()):
        logger.info("  %s: %d hosts", agency, len(hosts))
    return hosts_by_agency


def compute_sector_exploitation_rate(
    raw_epss: float,
    cvss_score: float,
    cisa_kev: bool,
    model_agency: str,
    exploit_maturity: int,
    has_public_poc: bool,
    vendor_patch_status: int,
) -> float:
    """Compute the ground-truth training target: sector-specific exploitation rate.

    This is grounded in the real EPSS score but modulated by sector risk,
    KEV membership, CVSS severity, exploit maturity, PoC availability, and
    patch status. The result is a realistic exploitation probability [0-1]
    that reflects how likely a CVE is to be exploited AGAINST A SPECIFIC
    SECTOR.
    """
    # ── EPSS foundation (35% weight) ──
    base = raw_epss * 0.35

    # ── CVSS severity band (0-0.25) ──
    if cvss_score >= 9.0:
        cvss_contrib = 0.25
    elif cvss_score >= 7.0:
        cvss_contrib = 0.15
    elif cvss_score >= 4.0:
        cvss_contrib = 0.08
    else:
        cvss_contrib = 0.02

    # ── KEV boost (0 or 0.20) ──
    kev_boost = 0.20 if cisa_kev else 0.0

    # ── Sector risk premium (0.05-0.25) ──
    sector_boost = SECTOR_RISK.get(model_agency, 0.05)

    # ── Exploit maturity (0-3 → 0-0.12) ──
    maturity_boost = exploit_maturity * 0.04

    # ── PoC availability (0 or 0.04) ──
    poc_boost = 0.04 if has_public_poc else 0.0

    # ── Patch status penalty ──
    if vendor_patch_status == 2:  # No patch available
        patch_penalty = 0.0
    elif vendor_patch_status == 1:  # Temporary fix
        patch_penalty = 0.03
    else:  # Official fix available
        patch_penalty = 0.06

    target = (
        base
        + cvss_contrib
        + kev_boost
        + sector_boost
        + maturity_boost
        + poc_boost
        - patch_penalty
    )

    # Small Gaussian noise for realism
    target += np.random.normal(0, 0.02)

    return round(max(0.001, min(0.99, target)), 4)


def generate_findings() -> list[dict]:
    """Generate synthetic findings and return list of row dicts."""
    # Load data
    epss_cache = _load_epss_cache()
    hosts_by_agency = _load_hosts_by_agency()

    logger.info("Loaded %d CVE definitions from research", len(CVE_DEFINITIONS))
    logger.info("EPSS cache has %d entries", len(epss_cache))

    findings = []
    finding_id = 0

    for (
        cve_id,
        cwe_class,
        cvss_score,
        cisa_kev,
        software,
        target_agencies,
    ) in CVE_DEFINITIONS:
        # Get real EPSS score from cache
        cached: dict = epss_cache.get(cve_id, {})
        epss_score: float = cached.get("epss", 0.5) if isinstance(cached, dict) else 0.5

        # Determine which agencies this CVE affects
        agencies = _get_agency_list(target_agencies)

        # Generate multiple findings per agency
        for model_agency in agencies:
            # Get available hosts for this agency
            hosts = hosts_by_agency.get(model_agency, [])
            if not hosts:
                continue

            # Generate 2-4 findings per agency (more for high-risk)
            if model_agency in ("health", "police", "justice"):
                n_per_agency = min(4, len(hosts))
            elif model_agency in (
                "transport",
                "finance",
                "sharedservices",
                "education",
            ):
                n_per_agency = min(3, len(hosts))
            else:
                n_per_agency = min(2, len(hosts))

            sampled_hosts = random.sample(hosts, min(n_per_agency, len(hosts)))

            for host_entry in sampled_hosts:
                finding_id += 1

                # Realistic exploit maturity based on KEV and CVSS
                if cisa_kev and cvss_score >= 9.0:
                    exploit_maturity = random.choices(
                        [2, 3, 3, 3], weights=[1, 2, 3, 4]
                    )[0]
                elif cisa_kev:
                    exploit_maturity = random.choices(
                        [1, 2, 2, 3], weights=[1, 2, 3, 2]
                    )[0]
                else:
                    exploit_maturity = random.choices(
                        [0, 0, 1, 1, 2], weights=[3, 3, 2, 1, 1]
                    )[0]

                # PoC availability — high for KEV, moderate otherwise
                if cisa_kev:
                    has_public_poc = random.random() < 0.85
                elif exploit_maturity >= 2:
                    has_public_poc = random.random() < 0.60
                else:
                    has_public_poc = random.random() < 0.15

                # Vendor patch status — KEV CVEs often have no patch initially
                if cisa_kev:
                    vendor_patch_status = random.choices([0, 1, 2], weights=[2, 3, 5])[
                        0
                    ]
                else:
                    vendor_patch_status = random.choices([0, 1, 2], weights=[6, 3, 1])[
                        0
                    ]

                # Compute training target
                target = compute_sector_exploitation_rate(
                    raw_epss=epss_score,
                    cvss_score=cvss_score,
                    cisa_kev=cisa_kev,
                    model_agency=model_agency,
                    exploit_maturity=exploit_maturity,
                    has_public_poc=has_public_poc,
                    vendor_patch_status=vendor_patch_status,
                )

                # Determine sector name
                sector_name = f"wa_gov_{model_agency}"

                finding = {
                    "cve_id": cve_id,
                    "hostname": host_entry["hostname"],
                    "cvss_score": cvss_score,
                    "epss_score": epss_score,
                    "cisa_kev": 1 if cisa_kev else 0,
                    "cwe_class": cwe_class,
                    "sector": sector_name,
                    "agency": model_agency,
                    "exploit_maturity": exploit_maturity,
                    "has_public_poc": 1 if has_public_poc else 0,
                    "vendor_patch_status": vendor_patch_status,
                    "source_research_ref": f"v4_synthetic_{cve_id}",
                    "sector_exploitation_rate": target,
                }
                findings.append(finding)

    logger.info("Generated %d synthetic findings", len(findings))
    return findings


def write_json_backup(findings: list[dict], path: str):
    """Write findings as JSON backup."""
    with open(path, "w") as f:
        json.dump(findings, f, indent=2)
    size_kb = os.path.getsize(path) / 1024
    logger.info("Wrote JSON backup to %s (%.1f KB)", path, size_kb)


def insert_into_db(findings: list[dict]):
    """Insert findings into synthetic_findings table."""
    init_db()
    db = get_db()
    cols = [
        "cve_id",
        "hostname",
        "cvss_score",
        "epss_score",
        "cisa_kev",
        "cwe_class",
        "sector",
        "agency",
        "exploit_maturity",
        "has_public_poc",
        "vendor_patch_status",
        "source_research_ref",
    ]
    placeholders = ", ".join("?" for _ in cols)
    col_list = ", ".join(cols)
    sql = f"INSERT INTO synthetic_findings ({col_list}) VALUES ({placeholders})"

    inserted = 0
    for f in findings:
        values = [f.get(c) for c in cols]
        try:
            db.execute(sql, values)
            inserted += 1
        except Exception as exc:
            logger.warning("Insert failed: %s — %s", f.get("cve_id"), exc)
    db.commit()
    db.close()
    logger.info("Inserted %d rows into synthetic_findings", inserted)

    # Show stats
    cve_count = len(set(f["cve_id"] for f in findings))
    agency_count = len(set(f["agency"] for f in findings))
    rates = [f["sector_exploitation_rate"] for f in findings]
    logger.info(
        "Coverage: %d CVEs x %d agencies. Target: [%.4f, %.4f], mean=%.4f",
        cve_count,
        agency_count,
        min(rates),
        max(rates),
        sum(rates) / len(rates),
    )


def main():
    logger.info("=" * 60)
    logger.info("  EPSS v4 — Synthetic Findings Generator")
    logger.info("  (sector-aware, grounded in real EPSS data)")
    logger.info("=" * 60)

    findings = generate_findings()

    if not findings:
        logger.warning("No findings generated — aborting.")
        return

    # Output JSON backup
    write_json_backup(findings, OUTPUT_PATH)

    # Insert into DB
    insert_into_db(findings)

    # Distribution summary
    rates = [f["sector_exploitation_rate"] for f in findings]
    logger.info("─" * 60)
    logger.info("Target (sector_exploitation_rate) distribution:")
    logger.info("  Min:    %.4f", min(rates))
    logger.info("  Max:    %.4f", max(rates))
    logger.info("  Mean:   %.4f", sum(rates) / len(rates))
    logger.info("  Median: %.4f", sorted(rates)[len(rates) // 2])

    # Per-sector stats
    sector_rates: dict[str, list] = {}
    for f in findings:
        sector_rates.setdefault(f["agency"], []).append(f["sector_exploitation_rate"])
    logger.info("Per-agency mean target:")
    for agency in sorted(sector_rates.keys()):
        vals = sector_rates[agency]
        logger.info(
            "  %-20s: mean=%.4f (n=%d)", agency, sum(vals) / len(vals), len(vals)
        )

    logger.info("=" * 60)
    logger.info("Done. Generated %d synthetic findings.", len(findings))


if __name__ == "__main__":
    main()
