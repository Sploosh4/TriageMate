"""
Synthetic Data Generator v2 — Research-Backed WA Government Hostname Generation.

Generates 1,500-2,000 hostnames with probabilistic labels, blind holdout,
and confidence scores, then inserts into synthetic_assets via SQLite.

Usage:
    cd backend
    python -m ml.generate_synthetic_data_v2

Outputs:
    backend/ml/synthetic_data_v2.json       — full generated dataset (backup)
    backend/ml/synthetic_holdout_v2.json    — holdout subset (for blind eval)
    Inserts rows into synthetic_assets table

Design:
    - Reads research_references table for agency, system, hostname patterns
    - Probabilistic label assignment (NOT deterministic if/else)
    - Blind holdout via random 80/20 split (seed=42)
    - Confidence scores reflect label assignment probabilities
"""

import json
import logging
import random
from collections import Counter
from datetime import datetime
from pathlib import Path

from database import get_db

random.seed(42)
HERE = Path(__file__).parent
OUTPUT_JSON = HERE / "synthetic_data_v2.json"
OUTPUT_HOLDOUT = HERE / "synthetic_holdout_v2.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
#  AGENCY DEFINITIONS (from research_references)
# ═══════════════════════════════════════════════════════════════════════════

AGENCY_INFO = {
    "health": {
        "abbrev": "WAHEALTH",
        "domain": "health.wa.gov.au",
        "weight": 15,
        "ref": "AGENCY-001",
    },
    "justice": {
        "abbrev": "WAJUSTICE",
        "domain": "justice.wa.gov.au",
        "weight": 8,
        "ref": "AGENCY-002",
    },
    "transport": {
        "abbrev": "WATRANSPORT",
        "domain": "transport.wa.gov.au",
        "weight": 12,
        "ref": "AGENCY-003",
    },
    "education": {
        "abbrev": "WAEDUCATION",
        "domain": "education.wa.edu.au",
        "weight": 14,
        "ref": "AGENCY-004",
    },
    "police": {
        "abbrev": "WAPOLICE",
        "domain": "police.wa.gov.au",
        "weight": 9,
        "ref": "AGENCY-005",
    },
    "finance": {
        "abbrev": "WAFINANCE",
        "domain": "finance.wa.gov.au",
        "weight": 8,
        "ref": "AGENCY-006",
    },
    "dpird": {
        "abbrev": "WADPIRD",
        "domain": "dpird.wa.gov.au",
        "weight": 5,
        "ref": "AGENCY-007",
    },
    "communities": {
        "abbrev": "WACOMMUNITIES",
        "domain": "communities.wa.gov.au",
        "weight": 6,
        "ref": "AGENCY-008",
    },
    "parliament": {
        "abbrev": "WAPARLIAMENT",
        "domain": "parliament.wa.gov.au",
        "weight": 1,
        "ref": "AGENCY-009",
    },
    "elections": {
        "abbrev": "WAELECTIONS",
        "domain": "elections.wa.gov.au",
        "weight": 1,
        "ref": "AGENCY-010",
    },
    "wachs": {
        "abbrev": "WACOUNTRYHTH",
        "domain": "wacountry.health.wa.gov.au",
        "weight": 3,
        "ref": "AGENCY-011",
    },
    "dfes": {
        "abbrev": "WADFES",
        "domain": "dfes.wa.gov.au",
        "weight": 5,
        "ref": "AGENCY-012",
    },
    "dbca": {
        "abbrev": "WADBCA",
        "domain": "dbca.wa.gov.au",
        "weight": 2,
        "ref": "AGENCY-013",
    },
    "dwer": {
        "abbrev": "WADWER",
        "domain": "dwer.wa.gov.au",
        "weight": 2,
        "ref": "AGENCY-014",
    },
    "dhw": {
        "abbrev": "WADHW",
        "domain": "dohw.wa.gov.au",
        "weight": 3,
        "ref": "AGENCY-015",
    },
    "deed": {
        "abbrev": "WADEED",
        "domain": "deed.wa.gov.au",
        "weight": 2,
        "ref": "AGENCY-016",
    },
    "cits": {
        "abbrev": "WACITS",
        "domain": "cits.wa.gov.au",
        "weight": 2,
        "ref": "AGENCY-017",
    },
    "watercorp": {
        "abbrev": "WAWATER",
        "domain": "watercorporation.com.au",
        "weight": 3,
        "ref": "AGENCY-018",
    },
    "mrwa": {
        "abbrev": "WAMRWA",
        "domain": "mainroads.wa.gov.au",
        "weight": 2,
        "ref": "AGENCY-019",
    },
    "pta": {
        "abbrev": "WAPTA",
        "domain": "pta.wa.gov.au",
        "weight": 2,
        "ref": "AGENCY-020",
    },
    "sharedservices": {
        "abbrev": "WASHARED",
        "domain": "sharedservices.wa.gov.au",
        "weight": 5,
        "ref": "AGENCY-021",
    },
    "oag": {
        "abbrev": "WAOAG",
        "domain": "audit.wa.gov.au",
        "weight": 1,
        "ref": "AGENCY-022",
    },
    "ccc": {
        "abbrev": "WACCC",
        "domain": "ccc.wa.gov.au",
        "weight": 1,
        "ref": "AGENCY-023",
    },
}

# Map agency_key -> list of (system_name, software_ref) from research
AGENCY_SYSTEMS = {
    "health": [
        ("MOVEIT", "SOFTWARE-002"),
        ("WEBPAS", "SOFTWARE-011"),
        ("IPHIS", "SOFTWARE-011"),
        ("EXCHANGE", "SOFTWARE-004"),
        ("SHAREPOINT", "SOFTWARE-005"),
        ("SAP", "SOFTWARE-001"),
        ("ORACLEEBS", "SOFTWARE-009"),
        ("PAPERCUT", "SOFTWARE-013"),
        ("SCREENCONNECT", "SOFTWARE-012"),
        ("CITRIX", "SOFTWARE-003"),
    ],
    "wachs": [
        ("MOVEIT", "SOFTWARE-002"),
        ("WEBPAS", "SOFTWARE-011"),
        ("EXCHANGE", "SOFTWARE-004"),
        ("TELEHEALTH", "SOFTWARE-011"),
    ],
    "justice": [
        ("ECOURTS", "SOFTWARE-016"),
        ("BOAB", "SOFTWARE-016"),
        ("SJIS", "SOFTWARE-018"),
        ("ROGS", "SOFTWARE-018"),
        ("EXCHANGE", "SOFTWARE-004"),
        ("CITRIX", "SOFTWARE-003"),
        ("PAPERCUT", "SOFTWARE-013"),
    ],
    "transport": [
        ("CITRIX", "SOFTWARE-003"),
        ("TEMIS", "SOFTWARE-021"),
        ("GEOVIEW", "SOFTWARE-015"),
        ("EXCHANGE", "SOFTWARE-004"),
        ("SAP", "SOFTWARE-001"),
    ],
    "education": [
        ("SHAREPOINT", "SOFTWARE-005"),
        ("MOODLE", "SOFTWARE-008"),
        ("SIS", "SOFTWARE-010"),
        ("PAPERCUT", "SOFTWARE-013"),
        ("SHIBBOLETH", "SOFTWARE-019"),
        ("EXCHANGE", "SOFTWARE-004"),
        ("CITRIX", "SOFTWARE-003"),
    ],
    "police": [
        ("LEO", "SOFTWARE-014"),
        ("EWITNESS", "SOFTWARE-014"),
        ("CONFLUENCE", "SOFTWARE-006"),
        ("CAD", "SOFTWARE-014"),
        ("EXCHANGE", "SOFTWARE-004"),
        ("CITRIX", "SOFTWARE-003"),
    ],
    "finance": [
        ("SAP", "SOFTWARE-001"),
        ("ORACLEEBS", "SOFTWARE-009"),
        ("MANAGEENGINE", "SOFTWARE-007"),
        ("EXCHANGE", "SOFTWARE-004"),
        ("CITRIX", "SOFTWARE-003"),
    ],
    "dpird": [
        ("SAP", "SOFTWARE-001"),
        ("BIOSECURITY", "SOFTWARE-016"),
        ("STOCKMAN", "SOFTWARE-016"),
        ("SHAREPOINT", "SOFTWARE-005"),
    ],
    "communities": [
        ("CIMS", "SOFTWARE-016"),
        ("ICMS", "SOFTWARE-016"),
        ("HOMES", "SOFTWARE-016"),
        ("SHAREPOINT", "SOFTWARE-005"),
        ("EXCHANGE", "SOFTWARE-004"),
    ],
    "parliament": [
        ("SHAREPOINT", "SOFTWARE-005"),
        ("EXCHANGE", "SOFTWARE-004"),
    ],
    "elections": [
        ("EXCHANGE", "SOFTWARE-004"),
        ("SHAREPOINT", "SOFTWARE-005"),
    ],
    "dfes": [
        ("CAD", "SOFTWARE-014"),
        ("EMERGENCYALERT", "SOFTWARE-014"),
        ("EXCHANGE", "SOFTWARE-004"),
        ("CITRIX", "SOFTWARE-003"),
    ],
    "dbca": [
        ("SHAREPOINT", "SOFTWARE-005"),
        ("EXCHANGE", "SOFTWARE-004"),
    ],
    "dwer": [
        ("EXCHANGE", "SOFTWARE-004"),
        ("SHAREPOINT", "SOFTWARE-005"),
    ],
    "dhw": [
        ("SAP", "SOFTWARE-001"),
        ("SHAREPOINT", "SOFTWARE-005"),
        ("EXCHANGE", "SOFTWARE-004"),
    ],
    "deed": [
        ("SHAREPOINT", "SOFTWARE-005"),
        ("EXCHANGE", "SOFTWARE-004"),
    ],
    "cits": [
        ("SHAREPOINT", "SOFTWARE-005"),
        ("EXCHANGE", "SOFTWARE-004"),
    ],
    "watercorp": [
        ("SCADA", "SOFTWARE-020"),
        ("WIMS", "SOFTWARE-020"),
        ("EXCHANGE", "SOFTWARE-004"),
        ("SAP", "SOFTWARE-001"),
    ],
    "mrwa": [
        ("EXCHANGE", "SOFTWARE-004"),
        ("TEMIS", "SOFTWARE-021"),
    ],
    "pta": [
        ("CITRIX", "SOFTWARE-003"),
        ("EXCHANGE", "SOFTWARE-004"),
    ],
    "sharedservices": [
        ("SCREENCONNECT", "SOFTWARE-012"),
        ("MANAGEENGINE", "SOFTWARE-007"),
        ("EXCHANGE", "SOFTWARE-004"),
        ("CITRIX", "SOFTWARE-003"),
        ("SAP", "SOFTWARE-001"),
    ],
    "oag": [
        ("EXCHANGE", "SOFTWARE-004"),
        ("SHAREPOINT", "SOFTWARE-005"),
    ],
    "ccc": [
        ("SHAREPOINT", "SOFTWARE-005"),
        ("EXCHANGE", "SOFTWARE-004"),
    ],
}

# ═══════════════════════════════════════════════════════════════════════════
#  DISTRIBUTIONS
# ═══════════════════════════════════════════════════════════════════════════

ENV_DIST = {
    "PRD": 0.60,
    "DEV": 0.12,
    "TST": 0.10,
    "STG": 0.08,
    "UAT": 0.05,
    "DR": 0.03,
    "EOL": 0.01,
    "MIG": 0.01,
}

OS_DIST = {
    "WIN": 0.70,
    "LNX": 0.25,
    "SOL": 0.03,
    "N/A": 0.02,
}

ROLE_SUFFIXES = ["01", "02", "03"]

# Infrastructure roles (typically low criticality)
INFRA_ROLES = {"FILE", "PRINT", "BACKUP", "MONITOR", "SCAN"}

# Domain controller roles
DC_ROLES = {"DC", "ADC"}

# DMZ-friendly roles (internet-facing)
DMZ_ROLES = {"WEB", "API", "PROXY", "ADC", "VPN", "MAIL"}

ZONE_DIST = {
    "internal": 0.55,
    "dmz": 0.15,
    "restricted": 0.15,
    "protected": 0.10,
    "mgmt": 0.05,
}

LOCATION_PREFIXES = [
    ("per-", 0.70),
    ("sea-", 0.05),
    ("ue1-", 0.05),
    ("", 0.20),
]

# ═══════════════════════════════════════════════════════════════════════════
#  SYSTEM CRITICALITY
# ═══════════════════════════════════════════════════════════════════════════

HIGH_CRITICALITY_SYSTEMS = {
    "SAP",
    "MOVEIT",
    "EXCHANGE",
    "SCADA",
    "CAD",
    "WEBPAS",
    "IPHIS",
    "LEO",
    "EWITNESS",
    "EMERGENCYALERT",
    "BIOSECURITY",
    "SCREENCONNECT",
    "CIMS",
    "ICMS",
    "HOMES",
    "ECOURTS",
    "BOAB",
    "SJIS",
    "ROGS",
    "TELEHEALTH",
    "SIS",
    "MANAGEENGINE",
}

MEDIUM_CRITICALITY_SYSTEMS = {
    "SHAREPOINT",
    "CONFLUENCE",
    "CITRIX",
    "MOODLE",
    "ORACLEEBS",
    "PAPERCUT",
    "GEOVIEW",
    "TEMIS",
    "SHIBBOLETH",
    "STOCKMAN",
    "ORACLEFINANCIALS",
    "WIMS",
}

HIGH_CRITICALITY_AGENCIES = {
    "elections",
    "police",
    "health",
    "wachs",
    "communities",
    "justice",
    "ccc",
}

MEDIUM_CRITICALITY_AGENCIES = {
    "transport",
    "education",
    "finance",
    "dfes",
    "watercorp",
    "sharedservices",
    "dpird",
}

# ═══════════════════════════════════════════════════════════════════════════
#  PROBABILISTIC LABEL PROFILES
# ═══════════════════════════════════════════════════════════════════════════

# Profile 1: PRD + critical system + critical agency
PROFILE_CRITICAL_SYS_CRITICAL_AGENCY = [
    (("Core", "Severe"), 0.85),
    (("Core", "Moderate"), 0.12),
    (("Support", "Moderate"), 0.03),
]

# Profile 2: PRD + critical system + normal agency
PROFILE_CRITICAL_SYS_NORMAL_AGENCY = [
    (("Core", "Severe"), 0.75),
    (("Core", "Moderate"), 0.20),
    (("Support", "Moderate"), 0.05),
]

# Profile 3: PRD + DMZ zone (internet-facing)
PROFILE_DMZ_PRODUCTION = [
    (("Core", "Severe"), 0.60),
    (("Core", "Moderate"), 0.25),
    (("Support", "Moderate"), 0.10),
    (("Support", "Minimal"), 0.05),
]

# Profile 4: PRD + internal app server
PROFILE_INTERNAL_APP = [
    (("Core", "Moderate"), 0.30),
    (("Support", "Moderate"), 0.40),
    (("Support", "Minimal"), 0.20),
    (("Core", "Severe"), 0.10),
]

# Profile 5: PRD + Domain Controller
PROFILE_DOMAIN_CONTROLLER = [
    (("Core", "Severe"), 0.90),
    (("Core", "Moderate"), 0.08),
    (("Support", "Moderate"), 0.02),
]

# Profile 6: PRD + Infrastructure roles
PROFILE_INFRASTRUCTURE = [
    (("Support", "Minimal"), 0.80),
    (("Support", "Moderate"), 0.15),
    (("Peripheral", "Minimal"), 0.05),
]

# Profile 7: DEV/TST
PROFILE_DEV_TEST = [
    (("Peripheral", "Minimal"), 0.70),
    (("Support", "Minimal"), 0.20),
    (("Peripheral", "Moderate"), 0.10),
]

# Profile 8: STG
PROFILE_STAGING = [
    (("Support", "Moderate"), 0.20),
    (("Support", "Minimal"), 0.40),
    (("Peripheral", "Minimal"), 0.30),
    (("Core", "Moderate"), 0.10),
]

# Profile 9: EOL/SUN/MIG
PROFILE_EOL_MIG = [
    (("Support", "Minimal"), 0.70),
    (("Peripheral", "Minimal"), 0.20),
    (("Support", "Moderate"), 0.10),
]

# Profile 10: PRD + critical agency general
PROFILE_CRITICAL_AGENCY_GENERAL = [
    (("Core", "Severe"), 0.70),
    (("Core", "Moderate"), 0.25),
    (("Support", "Moderate"), 0.05),
]

# Profile 11: PRD + medium-criticality system + medium agency
PROFILE_MEDIUM_SYS_MEDIUM_AGENCY = [
    (("Core", "Moderate"), 0.40),
    (("Support", "Moderate"), 0.40),
    (("Support", "Minimal"), 0.15),
    (("Core", "Severe"), 0.05),
]

# Profile 12: PRD + medium system + critical agency
PROFILE_MEDIUM_SYS_CRITICAL_AGENCY = [
    (("Core", "Severe"), 0.50),
    (("Core", "Moderate"), 0.35),
    (("Support", "Moderate"), 0.15),
]

# Profile 13: DR
PROFILE_DR = [
    (("Support", "Moderate"), 0.40),
    (("Support", "Minimal"), 0.40),
    (("Core", "Moderate"), 0.15),
    (("Peripheral", "Minimal"), 0.05),
]

# Profile 14: UAT
PROFILE_UAT = [
    (("Support", "Moderate"), 0.30),
    (("Support", "Minimal"), 0.40),
    (("Peripheral", "Minimal"), 0.20),
    (("Core", "Moderate"), 0.10),
]


def weighted_choice(profile: list) -> tuple:
    """Pick a (mp, wi) label from a weighted profile distribution.

    Returns (mission_prevalence, wellbeing_impact, probability_of_chosen).
    The probability reflects the weight of the exact (mp, wi) pair chosen.
    """
    items, weights = zip(*profile)
    total = sum(weights)
    norm_weights = [w / total for w in weights]
    chosen = random.choices(items, weights=norm_weights, k=1)[0]
    idx = items.index(chosen)
    return chosen[0], chosen[1], norm_weights[idx]


def select_profile(
    env: str,
    system_name: str | None,
    agency_key: str,
    zone: str,
    role: str | None,
) -> list:
    """Select the appropriate label profile for a hostname."""
    # EOL/SUN/MIG
    if env in ("EOL", "MIG"):
        return PROFILE_EOL_MIG

    # DR
    if env == "DR":
        return PROFILE_DR

    # DEV/TST
    if env in ("DEV", "TST"):
        return PROFILE_DEV_TEST

    # UAT
    if env == "UAT":
        return PROFILE_UAT

    # STG
    if env == "STG":
        return PROFILE_STAGING

    # PRD (and anything else treated as PRD-like)
    if role in DC_ROLES:
        return PROFILE_DOMAIN_CONTROLLER

    if role in INFRA_ROLES:
        return PROFILE_INFRASTRUCTURE

    is_high_sys = system_name in HIGH_CRITICALITY_SYSTEMS if system_name else False
    is_medium_sys = system_name in MEDIUM_CRITICALITY_SYSTEMS if system_name else False
    is_critical_agency = agency_key in HIGH_CRITICALITY_AGENCIES
    is_medium_agency = agency_key in MEDIUM_CRITICALITY_AGENCIES

    if zone == "dmz":
        if is_high_sys or is_critical_agency:
            return PROFILE_CRITICAL_SYS_CRITICAL_AGENCY
        return PROFILE_DMZ_PRODUCTION

    if is_high_sys and is_critical_agency:
        return PROFILE_CRITICAL_SYS_CRITICAL_AGENCY

    if is_high_sys:
        return PROFILE_CRITICAL_SYS_NORMAL_AGENCY

    if is_medium_sys and is_critical_agency:
        return PROFILE_MEDIUM_SYS_CRITICAL_AGENCY

    if is_medium_sys and is_medium_agency:
        return PROFILE_MEDIUM_SYS_MEDIUM_AGENCY

    if is_critical_agency:
        return PROFILE_CRITICAL_AGENCY_GENERAL

    return PROFILE_INTERNAL_APP


# ═══════════════════════════════════════════════════════════════════════════
#  HOSTNAME BUILDER
# ═══════════════════════════════════════════════════════════════════════════


def build_hostname(
    location: str,
    env: str,
    agency_key: str,
    system_name: str | None,
    os_plat: str | None,
    role: str | None,
    role_num: str | None,
    zone: str | None,
    dc_prefix: str | None,
) -> str:
    """Assemble a WA government hostname from components.

    Format: {LOCATION}{ENV}-{AGENCY_ABBREV}-{SYSTEM_NAME}[-{OS}][-{ROLE}][.{DC}][.{ZONE}].{domain}
    """
    info = AGENCY_INFO[agency_key]
    machine = f"{location}{env}-{info['abbrev']}"
    if system_name:
        machine += f"-{system_name}"
    if os_plat and os_plat != "N/A":
        machine += f"-{os_plat}"
    if role:
        suffix = role_num or "01"
        machine += f"-{role}{suffix}"

    sub_parts = []
    if dc_prefix:
        sub_parts.append(dc_prefix)
    if zone:
        sub_parts.append(zone)

    if sub_parts:
        return f"{machine}.{'.'.join(sub_parts)}.{info['domain']}"
    return f"{machine}.{info['domain']}"


# ═══════════════════════════════════════════════════════════════════════════
#  GENERATOR
# ═══════════════════════════════════════════════════════════════════════════


def pick_role(env: str, zone: str, system_name: str | None) -> tuple:
    """Pick a role and number suffix based on context."""
    if random.random() < 0.08:
        return "DC", "01"

    if env == "PRD" and system_name:
        if system_name in ("MOVEIT", "SHAREPOINT", "MOODLE", "GEOVIEW", "TEMIS"):
            role = random.choice(["WEB", "APP", "DB"])
        elif system_name in ("EXCHANGE",):
            role = random.choice(["CAS", "MTA", "MAIL"])
        elif system_name in ("SAP", "ORACLEEBS", "ORACLEFINANCIALS"):
            role = random.choice(["APP", "DB", "FIN"])
        elif system_name in ("CITRIX",):
            role = random.choice(["ADC", "GW"])
        elif system_name in ("SCADA",):
            role = random.choice(["SCADA", "WTR"])
        elif system_name in ("CAD", "EMERGENCYALERT"):
            role = random.choice(["DISPATCH", "CAD", "COMMS"])
        elif system_name in ("MANAGEENGINE", "SCREENCONNECT"):
            role = random.choice(["RMM", "TOOL", "GW"])
        elif system_name in ("WEBPAS", "IPHIS", "TELEHEALTH"):
            role = random.choice(["APP", "DB", "WEB"])
        elif system_name in (
            "CIMS",
            "ICMS",
            "HOMES",
            "ECOURTS",
            "BOAB",
            "SJIS",
            "ROGS",
        ):
            role = random.choice(["APP", "DB"])
        elif system_name in ("LEO", "EWITNESS"):
            role = random.choice(["APP", "DB", "WEB"])
        elif system_name in ("PAPERCUT",):
            role = random.choice(["PRINT", "SVR"])
        elif system_name in ("SHIBBOLETH",):
            role = "IDM"
        else:
            role = random.choice(["WEB", "APP", "DB"])
    elif env in ("DEV", "TST", "STG", "UAT"):
        role = random.choice(["APP", "DB", "WEB"])
    else:
        role = random.choice(["WEB", "APP", "DB", "FE", "BE"])

    if role in (
        "CAS",
        "MTA",
        "MAIL",
        "RMM",
        "TOOL",
        "FIN",
        "IDM",
        "SCADA",
        "WTR",
        "DISPATCH",
        "ADC",
        "GW",
    ):
        role_num = "01"
    elif role in ("ADC", "GW"):
        role_num = random.choice(["01", "02"])
    else:
        role_num = random.choice(ROLE_SUFFIXES)

    return role, role_num


def generate_records(target_count: int = 1800) -> list[dict]:
    """Generate N records with probabilistic labels and holdout marking."""
    records = []
    seen_hostnames = set()
    agency_keys = list(AGENCY_INFO.keys())
    agency_weights = [AGENCY_INFO[k]["weight"] for k in agency_keys]

    envs = list(ENV_DIST.keys())
    env_probs = list(ENV_DIST.values())
    oss = list(OS_DIST.keys())
    os_probs = list(OS_DIST.values())
    zones = list(ZONE_DIST.keys())
    zone_probs = list(ZONE_DIST.values())

    max_attempts = target_count * 5
    attempts = 0

    while len(records) < target_count and attempts < max_attempts:
        attempts += 1

        agency_key = random.choices(agency_keys, weights=agency_weights, k=1)[0]
        info = AGENCY_INFO[agency_key]
        env = random.choices(envs, weights=env_probs, k=1)[0]
        os_plat = random.choices(oss, weights=os_probs, k=1)[0]
        zone = random.choices(zones, weights=zone_probs, k=1)[0]

        loc_tuple = random.choices(
            LOCATION_PREFIXES, weights=[w for _, w in LOCATION_PREFIXES], k=1
        )[0]
        location = loc_tuple[0]

        systems = AGENCY_SYSTEMS.get(agency_key, [])
        if systems and random.random() < 0.85:
            system_name, sw_ref = random.choice(systems)
        else:
            system_name = None
            sw_ref = None

        role, role_num = pick_role(env, zone, system_name)

        dc_prefix = None
        if role == "DC":
            dc_prefix = random.choice(["pdc1", "pdc2", "bdc1"])
        elif random.random() < 0.05:
            dc_prefix = random.choice(["pdc1", "pdc2"])

        if zone == "dmz" and role not in DMZ_ROLES and role is not None:
            role = random.choice(list(DMZ_ROLES))

        hostname = build_hostname(
            location,
            env,
            agency_key,
            system_name,
            os_plat,
            role,
            role_num,
            zone,
            dc_prefix,
        )
        hostname_lower = hostname.lower()

        if hostname_lower in seen_hostnames:
            continue
        seen_hostnames.add(hostname_lower)

        # Probabilistic label assignment
        profile = select_profile(env, system_name, agency_key, zone, role)
        mp, wi, confidence = weighted_choice(profile)

        is_holdout = 1 if random.random() < 0.20 else 0
        is_internet_facing = 1 if (env == "PRD" and zone == "dmz") else 0
        is_dc = 1 if role == "DC" else 0

        ref_parts = [info["ref"]]
        if sw_ref:
            ref_parts.append(sw_ref)
        source_ref = ", ".join(ref_parts)

        record = {
            "hostname": hostname,
            "ip": "",
            "agency": agency_key,
            "agency_domain": info["domain"],
            "system_name": system_name or "",
            "environment": env,
            "os_platform": os_plat if os_plat != "N/A" else "",
            "role": role or "",
            "network_zone": zone,
            "is_internet_facing": is_internet_facing,
            "is_dc": is_dc,
            "in_holdout": is_holdout,
            "mission_prevalence": mp,
            "public_wellbeing_impact": wi,
            "confidence_mp": round(confidence, 4),
            "confidence_wi": round(confidence, 4),
            "source_research_ref": source_ref,
            "generated_at": datetime.now().isoformat(),
            "validation_status": "pending",
            "validation_errors": "",
        }
        records.append(record)

        if len(records) % 500 == 0:
            logger.info("Generated %d records...", len(records))

    logger.info("Generated %d records in %d attempts", len(records), attempts)
    return records


# ═══════════════════════════════════════════════════════════════════════════
#  DATABASE INSERTION
# ═══════════════════════════════════════════════════════════════════════════


def insert_records(records: list[dict]):
    """Insert records into synthetic_assets table via ON CONFLICT SKIP."""
    db = get_db()
    try:
        cols = [
            "hostname",
            "ip",
            "agency",
            "agency_domain",
            "system_name",
            "environment",
            "os_platform",
            "role",
            "network_zone",
            "is_internet_facing",
            "is_dc",
            "in_holdout",
            "mission_prevalence",
            "public_wellbeing_impact",
            "confidence_mp",
            "confidence_wi",
            "source_research_ref",
            "generated_at",
            "validation_status",
            "validation_errors",
        ]
        placeholders = ", ".join("?" for _ in cols)
        col_list = ", ".join(cols)
        sql = (
            f"INSERT INTO synthetic_assets ({col_list}) "
            f"VALUES ({placeholders}) "
            f"ON CONFLICT (hostname) DO NOTHING"
        )

        inserted = 0
        skipped = 0
        for rec in records:
            values = [rec.get(c) for c in cols]
            cur = db.execute(sql, values)
            if cur.rowcount and cur.rowcount > 0:
                inserted += 1
            else:
                skipped += 1

        db.commit()
        logger.info("Inserted %d rows, skipped %d duplicates", inserted, skipped)
    finally:
        db.close()


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════


def main():
    logger.info("=" * 60)
    logger.info("Synthetic Data Generator v2 — WA Government Hostnames")
    logger.info("=" * 60)

    target = random.randint(1500, 2000)
    logger.info("Target record count: %d", target)
    records = generate_records(target)
    logger.info("Generated %d records total", len(records))

    mp_counts = Counter(r["mission_prevalence"] for r in records)
    wi_counts = Counter(r["public_wellbeing_impact"] for r in records)
    agency_counts = Counter(r["agency"] for r in records)
    env_counts = Counter(r["environment"] for r in records)
    holdout_count = sum(1 for r in records if r["in_holdout"])
    hostname_systems = Counter(r["system_name"] for r in records if r["system_name"])

    logger.info("Distribution stats:")
    logger.info("  Mission Prevalence:  %s", dict(mp_counts))
    logger.info("  Wellbeing Impact:    %s", dict(wi_counts))
    logger.info("  Agencies:            %s", dict(sorted(agency_counts.items())))
    logger.info("  Environments:        %s", dict(env_counts))
    logger.info("  System names:        %s", dict(hostname_systems.most_common(15)))
    logger.info(
        "  Holdout count:       %d (%.1f%%)",
        holdout_count,
        holdout_count / len(records) * 100,
    )

    holdout_records = [r for r in records if r["in_holdout"]]
    logger.info("  Training records:    %d", len(records) - holdout_count)
    logger.info("  Holdout records:     %d", len(holdout_records))

    # Write JSON
    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, "w") as f:
        json.dump(records, f, indent=2)
    logger.info("Full dataset written to %s", OUTPUT_JSON)

    with open(OUTPUT_HOLDOUT, "w") as f:
        json.dump(holdout_records, f, indent=2)
    logger.info("Holdout subset written to %s", OUTPUT_HOLDOUT)

    # Insert into SQLite
    logger.info("Inserting into synthetic_assets table...")
    insert_records(records)

    # Verify
    db = get_db()
    try:
        cnt = db.execute("SELECT COUNT(*) FROM synthetic_assets").fetchone()[0]
        hold_cnt = db.execute(
            "SELECT COUNT(*) FROM synthetic_assets WHERE in_holdout = 1"
        ).fetchone()[0]
        logger.info("Verification: %d total assets, %d holdout", cnt, hold_cnt)
    finally:
        db.close()

    logger.info("Done.")


if __name__ == "__main__":
    main()
