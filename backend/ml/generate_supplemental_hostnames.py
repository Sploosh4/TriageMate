"""
Generate 300+ supplemental WA Government hostname records with diverse,
realistic naming patterns for Pre-Tier classifier training.

Patterns added beyond the original 242 records:
  - Real system names (B2G, CHARS, DCPIMS, GARS, HSM, iPHIS, WebPAS, etc.)
  - Network zone suffixes (.dmz., .restricted., .protected., .mgmt.)
  - DC indicators (pdc1, pdc2, bdc1 as subdomain segments)
  - Extended lifecycle prefixes (EOL-, SUN-, MIG-, ACT-)
  - OS platform indicators (-WIN-, -LNX-, -SOL-)
  - Role suffixes (-AP01, -DB01, -WEB01, -FE01, -BE01, -RPT01)

Output: pretier_supplemental.json
"""

import json
import random
from collections import Counter
from pathlib import Path

random.seed(42)

HERE = Path(__file__).parent

# ─── AGENCIES AND THEIR DOMAINS ──────────────────────────────────────────────

AGENCY_DOMAINS = {
    "health": "health.wa.gov.au",
    "transport": "transport.wa.gov.au",
    "education": "education.wa.edu.au",
    "communities": "communities.wa.gov.au",
    "police": "police.wa.gov.au",
    "finance": "finance.wa.gov.au",
    "sharedservices": "sharedservices.wa.gov.au",
    "justice": "justice.wa.gov.au",
    "dfes": "dfes.wa.gov.au",
    "watercorporation": "watercorporation.wa.gov.au",
    "elections": "elections.wa.gov.au",
    "dpird": "dpird.wa.gov.au",
    "countryhealth": "countryhealth.wa.gov.au",
    "parliament": "parliament.wa.gov.au",
}

AGENCY_ABBREV = {
    "health": "WAHEALTH",
    "transport": "WATRANSPORT",
    "education": "WAEDUCATION",
    "communities": "WACOMMUNITIES",
    "police": "WAPOLICE",
    "finance": "WAFINANCE",
    "sharedservices": "WASHARED",
    "justice": "WAJUSTICE",
    "dfes": "WADFES",
    "watercorporation": "WAWATER",
    "elections": "WAELECTIONS",
    "dpird": "WADPIRD",
    "countryhealth": "WACOUNTRYHTH",
    "parliament": "WAPARLIAMENT",
}

# ─── REAL WA GOVERNMENT SYSTEM NAMES ─────────────────────────────────────────

SYSTEM_NAMES = {
    "health": [
        "B2G",
        "CHARS",
        "DCPIMS",
        "GARS",
        "HSM",
        "iPHIS",
        "WebPAS",
        "PCD",
        "RAMPS",
        "SHIELD",
        "SOH",
        "WAeMC",
    ],
    "transport": ["DVS", "SCATS", "TEMIS", "MRS", "TAMS"],
    "education": ["SIS", "SAER", "HRMIS", "TRENT", "SEQTA"],
    "communities": ["HOMES", "CIMS", "ICMS"],
    "justice": ["eCourts", "Boab", "SJIS", "ROGS"],
    "police": ["LEO", "eWitness"],
    "watercorporation": ["SCADA", "WIMS"],
    "sharedservices": ["GovNext", "Okta", "ServiceNow"],
    "dfes": ["CAD", "EmergencyAlert"],
    "dpird": ["Biosecurity", "Stockman"],
    "finance": ["SAP", "OracleFinancials"],
    "countryhealth": ["RuralEMR", "TelehealthHub"],
}

# ─── LABEL RULES ─────────────────────────────────────────────────────────────

# Core + Severe: patient data, child protection, police ops, emergency mgmt, SCADA
CRITICAL_SYSTEMS = {
    "B2G",
    "CHARS",
    "DCPIMS",
    "GARS",
    "HSM",
    "iPHIS",
    "WebPAS",
    "PCD",
    "RAMPS",
    "SHIELD",
    "SOH",
    "WAeMC",
    "RuralEMR",
    "TelehealthHub",
    "HOMES",
    "CIMS",
    "ICMS",
    "eCourts",
    "Boab",
    "SJIS",
    "ROGS",
    "LEO",
    "eWitness",
    "CAD",
    "EmergencyAlert",
    "Biosecurity",
    "SCADA",
    "WIMS",
}

# Agencies that are Core+Severe by default
CORE_SEVERE_AGENCIES = {"countryhealth", "elections"}

# Core+Moderate: schools, transport, licensing, parliament dept
CORE_MODERATE_AGENCIES = {"education", "transport", "parliament", "dpird"}


def get_labels(
    agency: str, system_name: str | None, lifecycle: str, hostname_str: str
) -> tuple[str, str]:
    """Determine mission_prevalence and public_wellbeing_impact labels."""
    h = hostname_str.lower()

    # EOL/SUN → Support + Minimal (decommissioning)
    if lifecycle in ("EOL", "SUN"):
        return "Support", "Minimal"

    # MIG → Support + Minimal
    if lifecycle == "MIG":
        return "Support", "Minimal"

    # ACT → Support + Moderate
    if lifecycle == "ACT":
        return "Support", "Moderate"

    # DEV/TST/STG → Peripheral + Minimal
    if lifecycle in ("DEV", "TST", "STG"):
        return "Peripheral", "Minimal"

    # PRD systems
    # Core + Severe
    if system_name and system_name in CRITICAL_SYSTEMS:
        return "Core", "Severe"
    if agency in CORE_SEVERE_AGENCIES:
        return "Core", "Severe"
    # Water corp with SCADA system
    if agency == "watercorporation" and system_name in {"SCADA", "WIMS"}:
        return "Core", "Severe"

    # Core + Moderate
    if agency in CORE_MODERATE_AGENCIES:
        return "Core", "Moderate"
    # Finance core systems
    if agency == "finance" and system_name in {"SAP", "OracleFinancials"}:
        return "Core", "Moderate"

    # Support + Moderate: infrastructure roles
    infra_triggers = [
        "file",
        "backup",
        "monitor",
        "log",
        "splunk",
        "dns",
        "ntp",
        "print",
        "proxy",
        "gw",
        "hr",
        "pay",
        "finance",
    ]
    if any(t in h for t in infra_triggers):
        return "Support", "Moderate"

    # Default PRD: Support + Moderate
    return "Support", "Moderate"


# ─── HOSTNAME BUILDER ────────────────────────────────────────────────────────


def build_hostname(
    agency: str,
    lifecycle: str,
    system_name: str | None,
    os_plat: str | None,
    role_suffix: str | None,
    zone: str | None,
    dc: str | None,
) -> str:
    """Assemble full hostname from parts."""
    parts = [lifecycle, AGENCY_ABBREV[agency]]
    if system_name:
        parts.append(system_name)
    if os_plat:
        parts.append(os_plat)
    if role_suffix:
        parts.append(role_suffix)
    machine_part = "-".join(parts)

    subdomain_parts = []
    if dc:
        subdomain_parts.append(dc)
    if zone:
        subdomain_parts.append(zone)

    if subdomain_parts:
        subdomain = ".".join(subdomain_parts)
        return f"{machine_part}.{subdomain}.{AGENCY_DOMAINS[agency]}"
    else:
        return f"{machine_part}.{AGENCY_DOMAINS[agency]}"


# ─── GENERATORS ──────────────────────────────────────────────────────────────


def generate_records() -> list[dict]:
    """Generate 300+ supplemental training records with diverse patterns."""
    records = []
    seen = set()

    OS_PLATFORMS = ["WIN", "LNX", "SOL"]
    ROLE_SUFFIXES = ["AP01", "DB01", "WEB01", "FE01", "BE01", "RPT01"]
    ZONES = ["dmz", "restricted", "protected", "mgmt"]
    DC_INDS = ["pdc1", "pdc2", "bdc1"]

    # ── Strategy 1: Real system names (PRD) with new patterns ──────────
    # For each (agency, system), generate 3-6 hosts with diverse zone/OS/role combos
    for agency, systems in SYSTEM_NAMES.items():
        for sys_name in systems:
            # Vary zone, OS, role suffix
            variants = [
                ("dmz", "WIN", "WEB01"),
                ("restricted", "LNX", "DB01"),
                ("protected", "WIN", "AP01"),
                ("mgmt", "LNX", "BE01"),
                (None, "WIN", "FE01"),
                (None, "SOL", "RPT01"),
            ]
            for zone, os_plat, role_sfx in variants:
                hostname = build_hostname(
                    agency, "PRD", sys_name, os_plat, role_sfx, zone, None
                )
                if hostname not in seen:
                    seen.add(hostname)
                    mp, pwi = get_labels(agency, sys_name, "PRD", hostname)
                    records.append(
                        {
                            "hostname": hostname,
                            "mission_prevalence": mp,
                            "public_wellbeing_impact": pwi,
                        }
                    )

    # ── Strategy 2: Lifecycle variants (DEV/TST/STG/EOL/SUN/MIG/ACT) ──
    generic_names = [
        "APP",
        "WEB",
        "API",
        "DB",
        "FILE",
        "BACKUP",
        "LOG",
        "PRINT",
        "DNS",
        "NTP",
        "HR",
        "PAYROLL",
        "MONITOR",
        "PROXY",
    ]
    lifecycle_rules = {
        "DEV": ("Peripheral", "Minimal"),
        "TST": ("Peripheral", "Minimal"),
        "STG": ("Peripheral", "Minimal"),
        "EOL": ("Support", "Minimal"),
        "SUN": ("Support", "Minimal"),
        "MIG": ("Support", "Minimal"),
        "ACT": ("Support", "Moderate"),
    }

    for agency in AGENCY_DOMAINS:
        for lifecycle, (mp, pwi) in lifecycle_rules.items():
            # Pick 4 random generic names per agency per lifecycle
            chosen_names = random.sample(generic_names, min(4, len(generic_names)))
            for name in chosen_names:
                os_plat = random.choice(OS_PLATFORMS)
                role_sfx = random.choice(ROLE_SUFFIXES)
                zone = random.choice([None] + ZONES)
                hostname = build_hostname(
                    agency, lifecycle, name, os_plat, role_sfx, zone, None
                )
                if hostname not in seen:
                    seen.add(hostname)
                    records.append(
                        {
                            "hostname": hostname,
                            "mission_prevalence": mp,
                            "public_wellbeing_impact": pwi,
                        }
                    )

    # ── Strategy 3: DC hosts with DC indicators ────────────────────────
    for agency in AGENCY_DOMAINS:
        for dc_ind in DC_INDS:
            for zone in [None, "protected", "mgmt"]:
                for os_plat in ["WIN", "LNX"]:
                    for dc_role in ["DC01", "ADC01"]:
                        hostname = build_hostname(
                            agency, "PRD", "ACTIVEDIR", os_plat, dc_role, zone, dc_ind
                        )
                        if hostname not in seen:
                            seen.add(hostname)
                            records.append(
                                {
                                    "hostname": hostname,
                                    "mission_prevalence": "Support",
                                    "public_wellbeing_impact": "Minimal",
                                }
                            )

    # ── Strategy 4: Hosts with BOTH system name AND DC indicator ─────
    special_systems = [
        ("justice", "eCourts"),
        ("police", "LEO"),
        ("health", "WebPAS"),
        ("health", "iPHIS"),
        ("communities", "CIMS"),
        ("watercorporation", "SCADA"),
    ]
    for agency, sys_name in special_systems:
        for dc_ind in ["pdc1", "pdc2"]:
            hostname = build_hostname(
                agency, "PRD", sys_name, "WIN", "DB01", "restricted", dc_ind
            )
            if hostname not in seen:
                seen.add(hostname)
                mp, pwi = get_labels(agency, sys_name, "PRD", hostname)
                records.append(
                    {
                        "hostname": hostname,
                        "mission_prevalence": mp,
                        "public_wellbeing_impact": pwi,
                    }
                )

    # ── Strategy 5: System name + non-PRD lifecycle ────────────────────
    for agency, systems in SYSTEM_NAMES.items():
        for sys_name in systems[:3]:  # limit per agency
            non_prd_lifecycles = [
                ("DEV", "Peripheral", "Minimal"),
                ("TST", "Peripheral", "Minimal"),
                ("EOL", "Support", "Minimal"),
            ]
            for lifecycle, mp, pwi in non_prd_lifecycles:
                hostname = build_hostname(
                    agency,
                    lifecycle,
                    sys_name,
                    random.choice(OS_PLATFORMS),
                    random.choice(ROLE_SUFFIXES),
                    random.choice([None] + ZONES),
                    None,
                )
                if hostname not in seen:
                    seen.add(hostname)
                    records.append(
                        {
                            "hostname": hostname,
                            "mission_prevalence": mp,
                            "public_wellbeing_impact": pwi,
                        }
                    )

    random.shuffle(records)
    return records


# ─── MAIN ────────────────────────────────────────────────────────────────────


def main():
    records = generate_records()
    output_path = HERE / "pretier_supplemental.json"
    with open(output_path, "w") as f:
        json.dump(records, f, indent=2)
    print(f"Generated {len(records)} supplemental records → {output_path}")

    mp_counts = Counter(r["mission_prevalence"] for r in records)
    pwi_counts = Counter(r["public_wellbeing_impact"] for r in records)
    agency_counts = Counter()
    for r in records:
        for a in AGENCY_DOMAINS:
            if a in r["hostname"]:
                agency_counts[a] += 1
                break

    print("\nSupplemental dataset distribution:")
    print(f"  Mission Prevalence: {dict(mp_counts)}")
    print(f"  Wellbeing Impact:   {dict(pwi_counts)}")
    print(f"  Agencies:           {dict(sorted(agency_counts.items()))}")
    print(f"  Total records:      {len(records)}")


if __name__ == "__main__":
    main()
