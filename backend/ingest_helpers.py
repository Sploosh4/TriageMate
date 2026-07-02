"""
Delegates to the configured CMDB adapter for asset context lookups.

Each function is independently replaceable when real integrations are built.
The ingest router calls these functions — it never contains lookup tables
or CMDB stubs itself.
"""

import re
from integrations.cmdb import get_asset_context as _cmdb_context
from integrations.cmdb import lookup_data_classification as _cmdb_classification
from integrations.cmdb import is_internet_facing as _cmdb_internet_facing
from integrations.nvd import get_nvd_data
from integrations.exploitdb import has_poc as _has_exploitdb_poc
from integrations.metasploit import has_payload as _has_metasploit_payload
from integrations.otx import query_otx_pulses


def lookup_data_classification(hostname: str) -> str:
    """Look up the WAICP data classification for an asset.

    Delegates to the CMDB adapter. Defaults to Category 1 for unknowns.
    """
    return _cmdb_classification(hostname)


def is_internet_facing(hostname: str) -> bool:
    """Determine if an asset is exposed to the public internet.

    Delegates to the CMDB adapter. Defaults to False for unknowns.
    """
    return _cmdb_internet_facing(hostname)


def _parse_cvss_vector(vector: str) -> dict:
    """Parse a CVSS v3.1 vector string into component dict."""
    if not vector:
        return {}
    try:
        return {p.split(":")[0]: p.split(":")[1] for p in vector.split("/")}
    except Exception:
        return {}


def _cvss_av(v):
    return {"N": 3, "A": 2, "L": 1, "P": 0}.get(str(v), 3)


def _cvss_ac(v):
    return {"L": 1, "H": 0}.get(str(v), 1)


def _cvss_pr(v):
    return {"N": 2, "L": 1, "H": 0}.get(str(v), 2)


def _cvss_ui(v):
    return {"N": 1, "R": 0}.get(str(v), 1)


def _cvss_s(v):
    return {"C": 1, "U": 0}.get(str(v), 0)


def _cvss_cia(v):
    return {"H": 2, "L": 1, "N": 0}.get(str(v), 2)


def _encode_classification(klass: str) -> int:
    mapping = {"OFFICIAL Sensitive": 4, "OFFICIAL": 2, "Category 1": 1}
    try:
        return mapping.get(klass, 1)
    except Exception:
        return 1


def _derive_domain_joined(hostname: str) -> bool:
    """Derive domain-joined status from hostname conventions.

    FQDN hostnames with internal-only suffixes are assumed domain-joined.
    Operational-technology suffixes are treated as standalone.
    Default False for unknown/OT patterns.
    """
    ot_suffixes = {".ot", ".scada", ".ics", ".plc", ".rtu", ".mtu"}
    host_lower = hostname.lower()
    if any(host_lower.endswith(s) for s in ot_suffixes):
        return False
    if "." in hostname:
        return True
    return False


def _parse_cmdb_date(date_str: str):
    """Parse a CMDB date string like '14 May 2026' into a datetime.date or None."""
    if not date_str:
        return None
    try:
        from datetime import datetime

        return datetime.strptime(date_str, "%d %B %Y").date()
    except (ValueError, TypeError):
        return None


def _compute_patch_lag(last_patch_date: str, vulnerability_age_days: int) -> int:
    """Compute patch lag in days.

    Returns how many days the CVE has existed on an unpatched system.
    Missing last_patch_date defaults to 90 days.
    """
    if not last_patch_date:
        return 90
    if vulnerability_age_days <= 0:
        return 0
    parsed = _parse_cmdb_date(last_patch_date)
    if parsed is None:
        return 90
    from datetime import date

    days_since_patch = (date.today() - parsed).days
    if days_since_patch > vulnerability_age_days:
        return vulnerability_age_days
    return max(0, vulnerability_age_days - days_since_patch)


_VENDOR_POPULARITY = {
    "microsoft": 0.95,
    "windows": 0.95,
    "citrix": 0.85,
    "vmware": 0.80,
    "oracle": 0.75,
    "adobe": 0.70,
    "apache": 0.65,
    "linux": 0.60,
    "ubuntu": 0.60,
    "cisco": 0.80,
    "apple": 0.55,
    "google": 0.50,
    "progress": 0.65,
    "atlassian": 0.60,
    "zoho": 0.45,
    "manageengine": 0.45,
    "papercut": 0.40,
    "connectwise": 0.50,
    "screenconnect": 0.50,
    "freebsd": 0.40,
}


def _lookup_vendor_popularity(operating_system: str, hostname: str = "") -> float:
    """Look up vendor popularity index from OS string or hostname."""
    text = f"{operating_system} {hostname}".lower()
    for keyword, score in _VENDOR_POPULARITY.items():
        if keyword in text:
            return score
    return 0.1


def _encode_mission(mission: str) -> int:
    mapping = {"Core": 3, "Support": 2, "Peripheral": 1}
    try:
        return mapping.get(mission, 2)
    except Exception:
        return 2


def _encode_wellbeing(wellbeing: str) -> int:
    mapping = {"Severe": 3, "Moderate": 2, "Minimal": 1}
    try:
        return mapping.get(wellbeing, 1)
    except Exception:
        return 1


_RCE_PATTERNS = [r"remote code execution", r"arbitrary code", r"execute arbitrary"]
_PRIVESC_PATTERNS = [r"privilege escalation", r"elevat\w+ privilege"]
_BYPASS_PATTERNS = [r"bypass", r"authentication bypass", r"access control"]
_DOS_PATTERNS = [r"denial of service", r"dos", r"resource exhaustion"]
_TRAVERSAL_PATTERNS = [r"directory traversal", r"path traversal", r"\.\.[\\/]"]

_MITRE_TOP_25_CWES = {
    "CWE-787",
    "CWE-79",
    "CWE-89",
    "CWE-416",
    "CWE-78",
    "CWE-20",
    "CWE-125",
    "CWE-22",
    "CWE-352",
    "CWE-434",
    "CWE-862",
    "CWE-476",
    "CWE-287",
    "CWE-190",
    "CWE-502",
    "CWE-77",
    "CWE-119",
    "CWE-798",
    "CWE-918",
    "CWE-306",
    "CWE-362",
    "CWE-269",
    "CWE-94",
    "CWE-863",
    "CWE-276",
}


def _synthetic_patch_applied(
    patch_available: bool, cvss: float, last_patch: str, vuln_age: int
) -> bool:
    """Synthetically determine if a patch has likely been applied.

    Uses CMDB last_patch_date, CVSS severity, and vulnerability age to
    model common SOC patching behaviour.
    """
    if not patch_available:
        return False
    if not last_patch:
        return False

    from datetime import date

    parsed = _parse_cmdb_date(last_patch)
    if parsed is None:
        return False
    days_since_patch = (date.today() - parsed).days

    if days_since_patch <= 30:
        return True
    if cvss >= 9.0 and days_since_patch <= 90:
        return True
    if cvss >= 7.0 and days_since_patch <= 60:
        return True
    if vuln_age > 180 and cvss >= 7.0:
        return True
    return False


def _synthetic_lateral(asset_ctx: dict) -> int:
    """Estimate how many hosts this asset can reach based on zone and role."""
    zone = (asset_ctx.get("network_zone") or "").lower()
    role = (asset_ctx.get("role") or "").lower()

    ZONE_BASELINE = {
        "protected": 15,
        "restricted": 8,
        "dmz": 5,
        "management": 3,
    }
    base = 5
    for key, val in ZONE_BASELINE.items():
        if key in zone:
            base = val
            break

    role_lower = role
    if any(
        k in role_lower
        for k in ("server", "database", "domain controller", "file", "application")
    ):
        base += 5

    return base


def _synthetic_boundary(asset_ctx: dict, internet_facing: bool) -> int:
    """Can this asset cross network boundaries? 1 = yes, 0 = no."""
    zone = (asset_ctx.get("network_zone") or "").lower()
    if internet_facing or "dmz" in zone:
        return 1
    return 0


def _synthetic_downstream(asset_ctx: dict) -> int:
    """Number of assets that depend on this one — from CMDB or role estimation."""
    deps = asset_ctx.get("dependent_assets", "")
    if isinstance(deps, list) and len(deps) > 0:
        return len(deps)
    if isinstance(deps, str) and deps.strip():
        items = [d.strip() for d in deps.split(",") if d.strip()]
        if len(items) > 0:
            return len(items)

    role = (asset_ctx.get("role") or "").lower()
    if "domain controller" in role:
        return 20
    if "database" in role:
        return 10
    if "file server" in role or "file" in role:
        return 8
    if "application" in role or "web server" in role:
        return 5
    if any(k in role for k in ("print", "dns", "dhcp")):
        return 15
    return 2


def _synthetic_internet_scan(
    cisa_kev: bool,
    epss_score: float,
    exploitdb_has_poc: bool,
    vulnerability_age_days: int,
    cvss_score: float,
) -> bool:
    """Determine if attackers are actively scanning for a CVE.

    Uses KEV status, EPSS score, exploit availability, CVE age, and CVSS
    to estimate whether internet-wide scanning is likely occurring.
    No external API required.
    """
    if cisa_kev:
        return True
    if epss_score >= 0.50 and exploitdb_has_poc:
        return True
    if 0 < vulnerability_age_days < 30 and cvss_score >= 9.0:
        return True
    if epss_score >= 0.90:
        return True
    return False


def _synthetic_scan_status(detected: bool) -> str:
    return "active_scanning_detected" if detected else "no_scan_activity"


def _enrich_threat_pulses(cve_id: str) -> int:
    otx = query_otx_pulses(cve_id)
    return otx.get("pulse_count", 0)


def _threat_pulses_status(otx_result: dict) -> str:
    if not otx_result.get("queried", False):
        return "not_configured"
    count = otx_result.get("pulse_count", 0)
    if count > 0:
        return f"{count}_threat_pulses"
    return "no_threat_intel_available"


def build_feature_vector(payload, mission_tags: dict, tier_0_result: dict) -> dict:
    """Build the full 37-feature dict + description for the Tier 1 XGBoost model.

    Matches feature order in ml/xgboost_predictor.predict() and
    ml/train_xgboost.build_tabular_features().

    Args:
        payload: The IngestRequest Pydantic model
        mission_tags: Output from pre_tier.predict_mission_tags()
        tier_0_result: Output from tier_0.evaluate_tier_0()

    Returns:
        dict with all features + "description" key for SBERT text encoding
    """
    hostname = payload.hostname
    data_classification = lookup_data_classification(hostname)
    internet_facing = is_internet_facing(hostname)
    description = (payload.raw_description or "").lower()
    cvss_vec = _parse_cvss_vector(payload.cvss_vector or "")
    asset_ctx = _cmdb_context(hostname)

    nvd = get_nvd_data(payload.vulnerability_id)
    cwe_class = nvd.get("cwe_class", "")
    is_top_25 = cwe_class in _MITRE_TOP_25_CWES if cwe_class else False
    vulnerability_age = nvd.get("vulnerability_age_days", 0)
    last_patch = asset_ctx.get("last_patch_date", "")
    operating_system = asset_ctx.get("operating_system", "")

    exploitdb_has_poc = _has_exploitdb_poc(payload.vulnerability_id)
    internet_scan = _synthetic_internet_scan(
        payload.cisa_kev
        if hasattr(payload, "cisa_kev") and payload.cisa_kev
        else False,
        payload.epss_score or 0.0,
        exploitdb_has_poc,
        vulnerability_age,
        payload.cvss_score or 0.0,
    )
    otx_result = query_otx_pulses(payload.vulnerability_id)

    return {
        "cvss_av": _cvss_av(cvss_vec.get("AV", "N")),
        "cvss_ac": _cvss_ac(cvss_vec.get("AC", "L")),
        "cvss_pr": _cvss_pr(cvss_vec.get("PR", "N")),
        "cvss_ui": _cvss_ui(cvss_vec.get("UI", "N")),
        "cvss_s": _cvss_s(cvss_vec.get("S", "U")),
        "cvss_c": _cvss_cia(cvss_vec.get("C", "N")),
        "cvss_i": _cvss_cia(cvss_vec.get("I", "N")),
        "cvss_a": _cvss_cia(cvss_vec.get("A", "N")),
        "cvss_score": payload.cvss_score,
        "epss_score": payload.epss_score,
        "patch_available": nvd.get("patch_available", True),
        "patch_applied": _synthetic_patch_applied(
            nvd.get("patch_available", False),
            payload.cvss_score,
            last_patch,
            vulnerability_age,
        ),
        "internet_facing": internet_facing,
        "domain_joined": _derive_domain_joined(hostname),
        "data_classification": data_classification,
        "mission_prevalence": mission_tags.get("mission_prevalence", "Support"),
        "public_wellbeing_impact": mission_tags.get(
            "public_wellbeing_impact", "Minimal"
        ),
        "lateral_reachability": _synthetic_lateral(asset_ctx),
        "boundary_reachability": _synthetic_boundary(asset_ctx, internet_facing),
        "downstream_assets": _synthetic_downstream(asset_ctx),
        "patch_lag_days": _compute_patch_lag(last_patch, vulnerability_age),
        "exploitdb_has_poc": exploitdb_has_poc,
        "metasploit_has_payload": _has_metasploit_payload(payload.vulnerability_id),
        "internet_scan_detected": internet_scan,
        "threat_intel_pulses": otx_result.get("pulse_count", 0),
        "nvd_reference_count": nvd.get("nvd_reference_count", 0),
        "cve_desc_tokens": len(description),
        "vulnerability_age_days": vulnerability_age,
        "vendor_popularity_index": _lookup_vendor_popularity(
            operating_system, hostname
        ),
        "cvss_exploitability_sub": nvd.get("cvss_exploitability_sub", 0.0),
        "cvss_impact_sub": nvd.get("cvss_impact_sub", 0.0),
        "is_top_25_cwe": is_top_25,
        "is_rce_signature": int(any(re.search(p, description) for p in _RCE_PATTERNS)),
        "is_privesc_signature": int(
            any(re.search(p, description) for p in _PRIVESC_PATTERNS)
        ),
        "is_bypass_signature": int(
            any(re.search(p, description) for p in _BYPASS_PATTERNS)
        ),
        "is_dos_signature": int(any(re.search(p, description) for p in _DOS_PATTERNS)),
        "is_traversal_signature": int(
            any(re.search(p, description) for p in _TRAVERSAL_PATTERNS)
        ),
        "threat_intel_status": {
            "internet_scan": _synthetic_scan_status(internet_scan),
            "threat_pulses": _threat_pulses_status(otx_result),
        },
        "description": payload.raw_description or "",
    }


def query_rag(hostname: str, cve_id: str, cwe_class: str = "") -> dict:
    """Query internal documentation repositories for asset configuration.

    Calls the LanceDB vector store via backend/ml/vector_store.py.
    Falls back to empty context if the store is not yet populated.

    Args:
        hostname: The fully qualified hostname of the asset
        cve_id: The CVE identifier string
        cwe_class: Optional CWE class string to narrow RAG results

    Returns:
        dict with 'documents' list, 'status' string, and 'rag_context' string
    """
    try:
        from ml.vector_store import query_rag as vs_query_rag

        return vs_query_rag(hostname, cwe_class=cwe_class)
    except Exception:
        return {
            "documents": [],
            "status": "RAG store not yet populated",
            "rag_context": "",
        }


def get_asset_context(hostname: str) -> dict:
    """Get full asset context from the CMDB adapter.

    Returns all available metadata for a hostname, or a default dict for unknowns.
    """
    return _cmdb_context(hostname)
