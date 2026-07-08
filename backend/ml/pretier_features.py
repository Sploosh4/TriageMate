"""
Shared feature extraction for the Pre-Tier multi-label classifier.

Parses WA Government hostnames (e.g., PRD-PATIENT-EMR01.health.wa.gov.au)
into a consistent numeric feature vector used by both the training pipeline
(train_pre_tier.py) and the inference endpoint (pipeline/pre_tier.py).

Feature vector (60 dimensions):
  Index   0: env_code (ordinal: PRD=1, STG=2, DEV=3, TST=4, other=0)
  Index  1-14: one-hot agency (14 WA Government departments)
  Index 15-38: binary role keyword indicators (24 roles)
  Index    39: data_classification_code (ordinal 1-4)
  Index    40: internet_facing (binary 0/1)
  Index 41-44: network zone one-hot (dmz, restricted, protected, mgmt)
  Index    45: has_dc_indicator (binary 0/1 — pdc1/pdc2/bdc1 in subdomain)
  Index 46-49: extended lifecycle (eol, sun, mig, act — binary)
  Index 50-52: OS platform (win, lnx, sol — binary)
  Index 53-58: role suffix detected (ap, db, web, fe, be, rpt — binary)
  Index    59: system_category (ordinal 0-8 — functional category of system name)

Must be kept in sync between training and inference.
"""

# ─── AGENCY DEFINITIONS ─────────────────────────────────────────────────────

AGENCIES = [
    "health",
    "transport",
    "education",
    "communities",
    "police",
    "finance",
    "sharedservices",
    "justice",
    "dfes",
    "watercorporation",
    "elections",
    "dpird",
    "countryhealth",
    "parliament",
]

AGENCY_ALIASES = {
    "wapol": "police",
}

# ─── ROLE KEYWORD PATTERNS ──────────────────────────────────────────────────

ROLE_PATTERNS = {
    "web": ["web", "portal", "dvs"],
    "app": ["app", "application", "temis", "dvs", "mrs", "tams", "transport"],
    "api": ["api"],
    "gw": ["gw", "gateway", "proxy", "adc"],
    "db": ["db", "database", "cluster", "sql"],
    "dc": ["dc", "activedir", "domain"],
    "file": ["file", "store", "san", "moveit", "mft", "filetransfer", "goanywhere"],
    "print": ["print", "papercut", "printserver"],
    "backup": ["backup", "bkup", "veeam"],
    "log": ["log", "splunk", "siem", "mon"],
    "mail": ["mail", "email", "exc"],
    "dns": ["dns"],
    "infra": [
        "sccm",
        "wsus",
        "nms",
        "network",
        "screenconnect",
        "connectwise",
        "teamviewer",
        "anydesk",
        "bomgar",
        "beyondtrust",
        "manageengine",
        "servicedesk",
        "patching",
    ],
    "security": ["sentinel", "crowdstrike", "sentinelone", "edr", "cyberark", "pam"],
    "vmware": ["vmware", "vcen"],
    "citrix": ["citrix"],
    "wiki": ["wiki", "confluence", "sharepoint"],
    "pacs": ["pacs", "imaging", "radiology"],
    "emr": ["emr", "ehr", "patient", "myrhr"],
    "identity": ["identity", "idm", "okta"],
    "itsm": ["itsm", "servicenow"],
    "sap": ["sap"],
    "scheduling": ["schedule", "sched", "roster"],
    "cad": ["cad", "dispatch"],
}

# ─── REAL WA GOVERNMENT SYSTEM NAMES ────────────────────────────────────────

KNOWN_SYSTEM_NAMES = [
    "b2g",
    "chars",
    "confluence",
    "dcpims",
    "gars",
    "hsm",
    "iphis",
    "webpas",
    "moveit",
    "pcd",
    "papercut",
    "ramps",
    "shield",
    "soh",
    "waemc",
    "dvs",
    "scats",
    "screenconnect",
    "temis",
    "mrs",
    "tams",
    "sis",
    "saer",
    "hrmis",
    "trent",
    "seqta",
    "homes",
    "cims",
    "icms",
    "manageengine",
    "ecourts",
    "oracleebs",
    "boab",
    "sjis",
    "rogs",
    "leo",
    "ewitness",
    "scada",
    "wims",
    "govnext",
    "okta",
    "servicenow",
    "cad",
    "emergencyalert",
    "biosecurity",
    "stockman",
    "sap",
    "oraclefinancials",
    "ruralemr",
    "telehealthhub",
]

# ─── DATA CLASSIFICATION KEYWORDS ───────────────────────────────────────────

CATEGORY_4_KEYWORDS = [
    "patient",
    "emr",
    "ehr",
    "pacs",
    "imaging",
    "radiology",
    "pharmacy",
    "bloodbank",
    "surgery",
    "ambulance",
    "lab",
    "immunisation",
    "mentalhealth",
    "myrhr",
    "hie",
    "medevac",
    "telehealth",
    "police",
    "cad",
    "crime",
    "offender",
    "victim",
    "bail",
    "correction",
    "youthjustice",
    "familycourt",
    "sentence",
    "courtroom",
    "witness",
    "firearms",
    "forensics",
    "intelligence",
    "bodycam",
    "cctv",
    "emergency",
    "fire",
    "hazmat",
    "bushfire",
    "ses",
    "dispatch",
    "water",
    "scada",
    "dam",
    "desalination",
    "pipeline",
    "wastewater",
    "election",
    "voter",
    "voting",
    "roll",
    "biosecurity",
    "pest",
    "livestock",
    "childprotect",
    "fostercare",
    "casemgt",
    "homeless",
    "disability",
]

CATEGORY_2_KEYWORDS = [
    "hr",
    "pay",
    "payroll",
    "finance",
    "budget",
    "procurement",
    "sap",
    "revenue",
    "tax",
    "treasury",
    "billing",
    "customer",
    "supplier",
    "donation",
    "itsm",
    "servicenow",
]

CATEGORY_1_KEYWORDS = [
    "print",
    "dns",
    "nms",
    "wsus",
]


# ─── SYSTEM CATEGORY MAPPING ────────────────────────────────────────────────


def get_system_category(system_name: str | None) -> int:
    """
    Map a system name to a functional category for better generalization.

    0 = No system name extracted
    1 = Infrastructure/utility (backup, file, print, dns, scan, log, nms, wsus, monitor, store, san, veeam, splunk, siem, patching, network)
    2 = Productivity/collaboration (exchange, mail, email, sharepoint, wiki, confluence, staffportal, exc)
    3 = Enterprise/line-of-business (sap, oracle, moveit, manageengine, servicenow, temis, oracleebs, oraclefinancials, mft, goanywhere)
    4 = Access/security (citrix, vpn, proxy, gateway, screenconnect, firewall, edr, crowdstrike, sentinel, cyberark, pam, beyondtrust, bomgar)
    5 = Application server (web, app, api, application, portal)
    6 = Database (db, sql, cluster, database)
    7 = Other known system (exists in KNOWN_SYSTEM_NAMES but doesn't match above)
    8 = Unknown system name (not in KNOWN_SYSTEM_NAMES and doesn't match above)

    This replaces the binary has_known_system with a multi-level ordinal
    that lets the model learn "category 3 systems are usually critical"
    vs "category 1 systems are usually low priority."
    """
    if not system_name:
        return 0

    name_lower = system_name.lower()

    # Category 1: Infrastructure/utility
    if any(
        kw in name_lower
        for kw in [
            "backup",
            "file",
            "print",
            "dns",
            "scan",
            "log",
            "nms",
            "wsus",
            "splunk",
            "siem",
            "monitor",
            "patching",
            "network",
            "store",
            "san",
            "veeam",
        ]
    ):
        return 1

    # Category 2: Productivity/collaboration
    if any(
        kw in name_lower
        for kw in [
            "exchange",
            "mail",
            "email",
            "sharepoint",
            "wiki",
            "confluence",
            "staffportal",
            "exc",
        ]
    ):
        return 2

    # Category 3: Enterprise/line-of-business
    if any(
        kw in name_lower
        for kw in [
            "sap",
            "oracle",
            "moveit",
            "manageengine",
            "servicenow",
            "temis",
            "oracleebs",
            "oraclefinancials",
            "mft",
            "goanywhere",
        ]
    ):
        return 3

    # Category 4: Access/security
    if any(
        kw in name_lower
        for kw in [
            "citrix",
            "vpn",
            "proxy",
            "gateway",
            "screenconnect",
            "firewall",
            "edr",
            "crowdstrike",
            "sentinel",
            "cyberark",
            "pam",
            "beyondtrust",
            "bomgar",
            "connectwise",
            "teamviewer",
            "anydesk",
        ]
    ):
        return 4

    # Category 5: Application server
    if any(kw in name_lower for kw in ["web", "app", "api", "application", "portal"]):
        return 5

    # Category 6: Database
    if any(kw in name_lower for kw in ["db", "sql", "cluster", "database"]):
        return 6

    # Check KNOWN_SYSTEM_NAMES
    if name_lower in [s.lower() for s in KNOWN_SYSTEM_NAMES]:
        return 7

    return 8


# ─── FEATURE EXTRACTION ─────────────────────────────────────────────────────


def extract_features(hostname: str) -> dict:
    """Extract a dict of numeric features from a WA Government hostname.

    Args:
        hostname: Fully-qualified hostname, e.g.
                  "per-PRD-PATIENT-EMR01.health.wa.gov.au"

    Returns:
        dict mapping feature name → numeric value.  Use feature_vector_to_array()
        to convert to a fixed-order list suitable for model input.
    """
    hostname_lower = hostname.lower().strip()
    domain_parts = hostname_lower.split(".")
    machine_part = domain_parts[0] if domain_parts else ""
    parts = machine_part.split("-")

    features: dict = {}

    # 1. Environment encoding (ordinal: PROD closer to 1, non-prod further)
    env = parts[0] if parts else ""
    features["env_code"] = {"prd": 1, "stg": 2, "dev": 3, "tst": 4}.get(env, 0)

    # 2. Agency one-hot (extract from domain)
    agency_raw = domain_parts[1] if len(domain_parts) > 1 else ""
    agency = AGENCY_ALIASES.get(agency_raw, agency_raw)
    # Also check deeper subdomain parts for agency
    if agency not in AGENCIES:
        for dp in domain_parts[1:]:
            resolved = AGENCY_ALIASES.get(dp, dp)
            if resolved in AGENCIES:
                agency = resolved
                break
    for a in AGENCIES:
        features[f"agency_{a}"] = 1 if agency == a else 0

    # 3. Role keyword binary features
    all_parts_str = machine_part.lower()
    for role_name, triggers in ROLE_PATTERNS.items():
        features[f"role_{role_name}"] = (
            1 if any(t in all_parts_str for t in triggers) else 0
        )

    # 4. Data classification code (ordinal 1-4, heuristic from keywords)
    features["data_classification_code"] = _derive_classification_code(
        agency, all_parts_str
    )

    # 5. Internet-facing flag (binary, heuristic)
    features["internet_facing"] = _is_internet_facing(env, all_parts_str)

    # ── NEW FEATURES ───────────────────────────────────────────────────

    # 6. Network zone (from subdomain)
    subdomain_str = ".".join(domain_parts[1:-2]) if len(domain_parts) > 3 else ""
    features["zone_dmz"] = 1 if "dmz" in subdomain_str else 0
    features["zone_restricted"] = 1 if "restricted" in subdomain_str else 0
    features["zone_protected"] = 1 if "protected" in subdomain_str else 0
    features["zone_mgmt"] = 1 if "mgmt" in subdomain_str else 0

    # 7. DC indicator (pdc1, pdc2, bdc1 in subdomain)
    features["has_dc_indicator"] = (
        1 if any(dc in subdomain_str for dc in ["pdc1", "pdc2", "bdc1"]) else 0
    )

    # 8. Extended lifecycle (EOL, SUN, MIG, ACT)
    features["is_eol"] = 1 if env == "eol" else 0
    features["is_sun"] = 1 if env == "sun" else 0
    features["is_mig"] = 1 if env == "mig" else 0
    features["is_act"] = 1 if env == "act" else 0

    # 9. OS platform indicators
    features["os_windows"] = 1 if any(p == "win" for p in parts) else 0
    features["os_linux"] = 1 if any(p == "lnx" for p in parts) else 0
    features["os_solaris"] = 1 if any(p == "sol" for p in parts) else 0

    # 10. Role suffix detection
    features["has_suffix_ap"] = 1 if any(p.endswith("ap01") for p in parts) else 0
    features["has_suffix_db"] = 1 if any(p.endswith("db01") for p in parts) else 0
    features["has_suffix_web"] = 1 if any(p.endswith("web01") for p in parts) else 0
    features["has_suffix_fe"] = 1 if any(p.endswith("fe01") for p in parts) else 0
    features["has_suffix_be"] = 1 if any(p.endswith("be01") for p in parts) else 0
    features["has_suffix_rpt"] = 1 if any(p.endswith("rpt01") for p in parts) else 0

    # 11. System category detection (replaces binary has_known_system)
    # Step 1: Check for KNOWN_SYSTEM_NAMES in the hostname
    known_match = None
    for sys_name in KNOWN_SYSTEM_NAMES:
        if sys_name in all_parts_str:
            known_match = sys_name
            break

    if known_match:
        features["system_category"] = get_system_category(known_match)
    else:
        # Step 2: Fallback — check hostname for category keywords that
        # won't false-positive on role suffixes (web, app, db, etc.)
        # Only checking system-level keywords here.
        _h = all_parts_str.lower()
        if any(
            kw in _h
            for kw in [
                "backup",
                "file",
                "print",
                "dns",
                "scan",
                "log",
                "monitor",
                "nms",
                "wsus",
                "splunk",
                "siem",
                "patching",
                "store",
                "san",
                "veeam",
            ]
        ):
            features["system_category"] = 1
        elif any(
            kw in _h
            for kw in [
                "exchange",
                "mail",
                "email",
                "sharepoint",
                "wiki",
                "confluence",
                "staffportal",
                "exc",
            ]
        ):
            features["system_category"] = 2
        elif any(
            kw in _h
            for kw in [
                "sap",
                "oracle",
                "moveit",
                "manageengine",
                "servicenow",
                "temis",
                "mft",
                "goanywhere",
            ]
        ):
            features["system_category"] = 3
        elif any(
            kw in _h
            for kw in [
                "citrix",
                "vpn",
                "proxy",
                "gateway",
                "screenconnect",
                "firewall",
                "edr",
                "crowdstrike",
                "sentinel",
                "cyberark",
                "pam",
            ]
        ):
            features["system_category"] = 4
        else:
            features["system_category"] = 8

    return features


def _derive_classification_code(agency: str, hostname_str: str) -> int:
    """Derive a WAICP data classification from hostname keywords.

    Returns ordinal: 4=Sensitive, 3=Protected, 2=Official, 1=Unclassified.

    This is a heuristic feature, not ground truth.  The model will learn
    the relationship between this signal and the target labels.
    """
    if any(kw in hostname_str for kw in CATEGORY_4_KEYWORDS):
        return 4
    if any(kw in hostname_str for kw in CATEGORY_2_KEYWORDS):
        return 2
    if any(kw in hostname_str for kw in CATEGORY_1_KEYWORDS):
        return 1
    return 3


def _is_internet_facing(env: str, hostname_str: str) -> int:
    """Determine if an asset is likely internet-facing based on hostname.

    Returns 1 (yes) or 0 (no).
    """
    if env != "prd":
        return 0

    internet_indicators = [
        "web",
        "api",
        "gw",
        "gateway",
        "portal",
        "proxy",
        "citrix",
        "adc",
    ]
    if any(ind in hostname_str for ind in internet_indicators):
        return 1

    internal_indicators = [
        "dc",
        "activedir",
        "db",
        "database",
        "sql",
        "cluster",
        "file",
        "store",
        "san",
        "print",
        "backup",
        "veeam",
        "splunk",
        "sccm",
        "wsus",
        "dns",
        "email",
        "exc",
        "log",
        "mon",
        "nms",
        "edr",
    ]
    if any(ind in hostname_str for ind in internal_indicators):
        return 0

    return 0


# ─── ARRAY CONVERSION ───────────────────────────────────────────────────────


def feature_vector_to_array(features: dict) -> list:
    """Convert a feature dict to a fixed-order list for model input.

    The order must exactly match the order used during training.

    Args:
        features: dict returned by extract_features()

    Returns:
        list of float/int feature values in fixed order
    """
    order = _get_feature_order()
    return [features.get(name, 0) for name in order]


def _get_feature_order() -> list:
    """Return the canonical ordered list of feature names."""
    names = ["env_code"]
    names += [f"agency_{a}" for a in AGENCIES]
    names += [f"role_{r}" for r in ROLE_PATTERNS]
    names += ["data_classification_code", "internet_facing"]
    # New features
    names += ["zone_dmz", "zone_restricted", "zone_protected", "zone_mgmt"]
    names += ["has_dc_indicator"]
    names += ["is_eol", "is_sun", "is_mig", "is_act"]
    names += ["os_windows", "os_linux", "os_solaris"]
    names += [
        "has_suffix_ap",
        "has_suffix_db",
        "has_suffix_web",
        "has_suffix_fe",
        "has_suffix_be",
        "has_suffix_rpt",
    ]
    names += ["system_category"]
    return names


def get_feature_names() -> list:
    """Return the list of feature names in canonical order (metadata)."""
    return _get_feature_order()


def get_feature_count() -> int:
    """Return the total number of features in the vector."""
    return len(_get_feature_order())
