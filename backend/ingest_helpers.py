"""
Stub implementations for CMDB lookups and asset classification.

Each function is independently replaceable when real integrations are built.
The ingest router calls these functions — it never contains lookup tables
or CMDB stubs itself.
"""

import re

KNOWN_HOSTS = {
    "PRD-MOVEIT-WEB01.health.wa.gov.au": {
        "data_classification": "Category 3",
        "internet_facing": True,
        "network_zone": "DMZ-Health-External",
        "operating_system": "Windows Server 2019 Standard",
        "role": "Managed File Transfer Server — Inter-Hospital Health Information Exchange",
        "business_owner": "WA Health — Health Support Services, ICT Operations",
        "technical_owner": "Health Support Services — Infrastructure Platforms Team",
        "interface_type": "Internet-facing HTTPS (no VPN required)",
        "patch_cycle": "Monthly (second Sunday, 0200-0600 AWST)",
        "last_patch_date": "14 May 2026",
        "last_scan_date": "27 June 2026",
        "registered_applications": "Progress MOVEit Transfer 2023.0.0, IIS 10.0",
        "dependent_assets": "PRD-SQL-CLUSTER01.health.wa.gov.au, PRD-FILE-SAN01.health.wa.gov.au",
        "service_account": "",
    },
    "PRD-CITRIX-ADC01.transport.wa.gov.au": {
        "data_classification": "Category 3",
        "internet_facing": True,
        "network_zone": "DMZ-Transport-External",
        "operating_system": "Citrix NetScaler ADC VPX 13.1-49.13 (FreeBSD-based)",
        "role": "Perimeter Remote Access Gateway — Department of Transport",
        "business_owner": "Department of Transport — ICT Services",
        "technical_owner": "Transport ICT — Networks and Security Team",
        "interface_type": "Internet-facing HTTPS (external VIP on port 443)",
        "patch_cycle": "Ad-hoc (appliance updates applied during scheduled maintenance windows)",
        "last_patch_date": "15 March 2026",
        "last_scan_date": "28 June 2026",
        "registered_applications": "Citrix Gateway, Citrix Load Balancer (TEMIS), Citrix Content Switching (DVS Online)",
        "dependent_assets": "PRD-TEMIS-APP01.transport.wa.gov.au, PRD-DVS-WEB01.transport.wa.gov.au, PRD-MARINE-DOC01.transport.wa.gov.au (+ 19 others)",
        "service_account": "",
    },
    "PRD-PRINT-SVR05.education.wa.edu.au": {
        "data_classification": "Category 2",
        "internet_facing": False,
        "network_zone": "EDU-Internal-Servers (VLAN 215)",
        "operating_system": "Windows Server 2022 Standard (build 20348)",
        "role": "Centralised Print Management Server — Department of Education (North Metropolitan Education Region)",
        "business_owner": "Department of Education — ICT Services and Infrastructure",
        "technical_owner": "Education ICT — End User Computing Team",
        "interface_type": "Internal network only (TCP 9191, TCP 9192, TCP 9164)",
        "patch_cycle": "Monthly (third Saturday, 2200-0400 AWST)",
        "last_patch_date": "20 June 2026",
        "last_scan_date": "27 June 2026",
        "registered_applications": "PaperCut MF 22.0.6, Microsoft Print Server role, PaperCut Mobility Print",
        "dependent_assets": "28 managed printers across 14 school campuses, PRD-FILE-PRINT01.education.wa.edu.au",
        "service_account": "DOMAIN_EDU\\svc-papercut-prd",
    },
    "PRD-RMM-GW01.sharedservices.wa.gov.au": {
        "data_classification": "Category 3",
        "internet_facing": False,
        "network_zone": "SSC-Management-Segment (VLAN 48)",
        "operating_system": "Windows Server 2022 Standard (build 20348)",
        "role": "Remote Monitoring and Management Gateway — WA Shared Services Centre",
        "business_owner": "Department of Finance — Shared Services ICT",
        "technical_owner": "Shared Services Centre — Endpoint Management Team",
        "interface_type": "Internal network only (TCP 8040 for web interface, TCP 8041 for relay)",
        "patch_cycle": "Monthly (first Sunday, 0100-0600 AWST)",
        "last_patch_date": "7 June 2026",
        "last_scan_date": "28 June 2026",
        "registered_applications": "ConnectWise ScreenConnect 23.9.7.8804, Microsoft SQL Server 2022 Express",
        "dependent_assets": "14 managed endpoints across DLGSC, DWER, DPLH, Finance, DBCA",
        "service_account": "SSC-MGMT\\svc-screenconnect",
    },
    "PRD-FILE-STORE02.communities.wa.gov.au": {
        "data_classification": "Category 3",
        "internet_facing": False,
        "network_zone": "Communities-Internal-Servers (VLAN 312)",
        "operating_system": "Windows Server 2019 Standard (build 17763)",
        "role": "Departmental File Storage Server — Child Protection and Family Services Division",
        "business_owner": "Department of Communities — Child Protection and Family Support",
        "technical_owner": "Communities ICT — Infrastructure and Operations",
        "interface_type": "Internal network only (SMB TCP 445, RPC dynamic ports)",
        "patch_cycle": "Monthly (second Saturday, 2200-0400 AWST)",
        "last_patch_date": "20 June 2026",
        "last_scan_date": "28 June 2026",
        "registered_applications": "Microsoft Office 365 Apps for Enterprise, Windows File Server role, Microsoft Defender for Endpoint",
        "dependent_assets": "PRD-CASEMGT-APP01.communities.wa.gov.au, PRD-CASEMGT-DB01.communities.wa.gov.au, 42 caseworker workstations",
        "service_account": "Local System",
    },
    "PRD-WIKI-CORE01.wapol.internal.wa.gov.au": {
        "data_classification": "Category 4",
        "internet_facing": False,
        "network_zone": "WAPOL-Internal-Management (VLAN 92)",
        "operating_system": "Ubuntu 22.04.3 LTS",
        "role": "Internal Knowledge Management Wiki — WA Police Force Operational Doctrine and Procedures",
        "business_owner": "WA Police Force — ICT Division, Information Management Branch",
        "technical_owner": "WAPOL ICT — Applications and Platforms Team",
        "interface_type": "Internal HTTP via reverse proxy (TCP 8090 on loopback)",
        "patch_cycle": "Ad-hoc (application patches applied outside standard OS patch cycle)",
        "last_patch_date": "15 June 2026",
        "last_scan_date": "28 June 2026",
        "registered_applications": "Atlassian Confluence Data Center 8.5.1, PostgreSQL 14.9, Apache HTTPD 2.4",
        "dependent_assets": "PRD-WIKI-DB01.wapol.internal.wa.gov.au, PRD-WIKI-CORE02.wapol.internal.wa.gov.au",
        "service_account": "",
    },
    "PRD-ITSM-TOOL01.finance.wa.gov.au": {
        "data_classification": "Category 2",
        "internet_facing": False,
        "network_zone": "Finance-Internal-Applications (VLAN 67)",
        "operating_system": "Windows Server 2022 Standard (build 20348)",
        "role": "IT Service Management Platform — Department of Finance Internal ICT Support and Procurement Ticketing",
        "business_owner": "Department of Finance — ICT Services",
        "technical_owner": "Finance ICT — Service Management Team",
        "interface_type": "HTTPS via reverse proxy (NGINX) with IP allow-listing; internal network access on TCP 8443",
        "patch_cycle": "Monthly (fourth Saturday, 2200-0400 AWST)",
        "last_patch_date": "27 June 2026",
        "last_scan_date": "28 June 2026",
        "registered_applications": "Zoho ManageEngine ServiceDesk Plus 14.0, PostgreSQL 14.8, Java Runtime Environment 11.0.19",
        "dependent_assets": "PRD-DC01.finance.wa.gov.au (LDAP), PRD-ITSM-DB01.finance.wa.gov.au",
        "service_account": "",
    },
}


def lookup_data_classification(hostname: str) -> str:
    """Look up the PRIS Act data classification for an asset.

    Stub: returns known values for the 7 demo hosts, defaults to Category 2 for unknowns.
    """
    if hostname in KNOWN_HOSTS:
        return KNOWN_HOSTS[hostname]["data_classification"]
    return "Category 2"


def is_internet_facing(hostname: str) -> bool:
    """Determine if an asset is exposed to the public internet.

    Stub: returns known values for the 7 demo hosts, defaults to False for unknowns.
    """
    if hostname in KNOWN_HOSTS:
        return KNOWN_HOSTS[hostname]["internet_facing"]
    return False


def _parse_cvss_vector(vector: str) -> dict:
    """Parse a CVSS v3.1 vector string into component dict."""
    if not vector:
        return {}
    try:
        return {p.split(":")[0]: p.split(":")[1] for p in vector.split("/")}
    except Exception:
        return {}


def _cvss_av(v):    return {"N": 3, "A": 2, "L": 1, "P": 0}.get(str(v), 3)
def _cvss_ac(v):    return {"L": 1, "H": 0}.get(str(v), 1)
def _cvss_pr(v):    return {"N": 2, "L": 1, "H": 0}.get(str(v), 2)
def _cvss_ui(v):    return {"N": 1, "R": 0}.get(str(v), 1)
def _cvss_s(v):     return {"C": 1, "U": 0}.get(str(v), 0)
def _cvss_cia(v):   return {"H": 2, "L": 1, "N": 0}.get(str(v), 2)

def _encode_classification(klass: str) -> int:
    mapping = {"Category 4": 4, "Category 3": 3, "Category 2": 2, "Category 1": 1}
    try:
        return mapping.get(klass, 2)
    except Exception:
        return 2

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
    "CWE-787", "CWE-79", "CWE-89", "CWE-416", "CWE-78",
    "CWE-20", "CWE-125", "CWE-22", "CWE-352", "CWE-434",
    "CWE-862", "CWE-476", "CWE-287", "CWE-190", "CWE-502",
    "CWE-77", "CWE-119", "CWE-798", "CWE-918", "CWE-306",
    "CWE-362", "CWE-269", "CWE-94", "CWE-863", "CWE-276",
}


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
        "patch_available": True,
        "patch_applied": False,
        "internet_facing": internet_facing,
        "domain_joined": True,
        "data_classification": data_classification,
        "mission_prevalence": mission_tags.get("mission_prevalence", "Support"),
        "public_wellbeing_impact": mission_tags.get("public_wellbeing_impact", "Minimal"),
        "lateral_reachability": 0,
        "boundary_reachability": 0,
        "downstream_assets": 0,
        "patch_lag_days": 0,
        "exploitdb_has_poc": False,
        "metasploit_has_payload": False,
        "greynoise_active_scan": False,
        "otx_threat_pulses": 0,
        "nvd_reference_count": 0,
        "cve_desc_tokens": len(description),
        "vulnerability_age_days": 0,
        "vendor_popularity_index": 0.0,
        "cvss_exploitability_sub": 0.0,
        "cvss_impact_sub": 0.0,
        "is_top_25_cwe": False,
        "is_rce_signature": int(any(re.search(p, description) for p in _RCE_PATTERNS)),
        "is_privesc_signature": int(any(re.search(p, description) for p in _PRIVESC_PATTERNS)),
        "is_bypass_signature": int(any(re.search(p, description) for p in _BYPASS_PATTERNS)),
        "is_dos_signature": int(any(re.search(p, description) for p in _DOS_PATTERNS)),
        "is_traversal_signature": int(any(re.search(p, description) for p in _TRAVERSAL_PATTERNS)),
        "description": payload.raw_description or "",
    }


def query_rag(hostname: str, cve_id: str) -> dict:
    """Query internal documentation repositories for asset configuration.

    Calls the LanceDB vector store via backend/ml/vector_store.py.
    Falls back to empty context if the store is not yet populated.

    Args:
        hostname: The fully qualified hostname of the asset
        cve_id: The CVE identifier string

    Returns:
        dict with 'documents' list and 'status' string
    """
    try:
        from ml.vector_store import query_rag as vs_query_rag
        return vs_query_rag(hostname)
    except Exception:
        return {"documents": [], "status": "RAG store not yet populated"}


def get_asset_context(hostname: str) -> dict:
    """Get full asset context from the KNOWN_HOSTS stub.

    Returns all available metadata for a hostname, or a default dict for unknowns.
    """
    if hostname in KNOWN_HOSTS:
        return dict(KNOWN_HOSTS[hostname])
    return {
        "data_classification": "Category 2",
        "internet_facing": False,
        "network_zone": "Unknown",
        "operating_system": "Unknown",
        "role": "",
        "business_owner": "",
        "technical_owner": "",
        "interface_type": "Internal network only",
        "patch_cycle": "",
        "last_patch_date": "",
        "last_scan_date": "",
        "registered_applications": "",
        "dependent_assets": "",
        "service_account": "",
    }
