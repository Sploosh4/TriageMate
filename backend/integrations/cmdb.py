"""
CMDB Adapter — abstract asset context provider.

Returns full asset metadata for a given hostname.
Ships with a KNOWN_HOSTS stub as the default implementation.
Swap the provider via TRIAGEMATE_CMDB_PROVIDER env var:
  "stub" (default) — uses the KNOWN_HOSTS dict below
  "servicenow"    — placeholder for ServiceNow CMDB integration
  "itop"          — placeholder for iTop integration
"""

import os
import json
import logging
from pathlib import Path

logger = logging.getLogger("triagemate.cmdb")

_MOCK_CMDB_PATH = Path(__file__).parent.parent / "data" / "mock_cmdb.json"
_FILE_CMDB: dict[str, dict] | None = None


def _load_file_cmdb() -> dict[str, dict]:
    """Load the mock CMDB from JSON file, keyed by hostname."""
    global _FILE_CMDB
    if _FILE_CMDB is not None:
        return _FILE_CMDB
    try:
        with open(_MOCK_CMDB_PATH) as f:
            hosts = json.load(f)
        _FILE_CMDB = {h["hostname"]: h for h in hosts}
        logger.info("Loaded %d hosts from mock_cmdb.json", len(_FILE_CMDB))
        return _FILE_CMDB
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("mock_cmdb.json not loaded: %s", e)
        _FILE_CMDB = {}
        return _FILE_CMDB


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
        "data_classification": "Category 4",
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


def _get_provider() -> str:
    return os.getenv("TRIAGEMATE_CMDB_PROVIDER", "stub").lower()


def lookup_data_classification(hostname: str) -> str:
    """Look up the PRIS Act data classification for an asset.

    Delegates to the current CMDB provider.
    Defaults to Category 1 for unknown hosts.
    """
    ctx = get_asset_context(hostname)
    return ctx.get("data_classification", "Category 1")


def is_internet_facing(hostname: str) -> bool:
    """Determine if an asset is exposed to the public internet.

    Delegates to the current CMDB provider.
    Defaults to False for unknown hosts.
    """
    ctx = get_asset_context(hostname)
    return ctx.get("internet_facing", False)


def get_asset_context(hostname: str) -> dict:
    """Get full asset context from the configured CMDB provider.

    Returns all available metadata for a hostname, or a default dict for unknowns.
    """
    provider = _get_provider()
    if provider == "stub":
        return _stub_lookup(hostname)
    elif provider == "servicenow":
        logger.warning(
            "ServiceNow CMDB provider not yet implemented; falling back to stub"
        )
        return _stub_lookup(hostname)
    elif provider == "itop":
        logger.warning("iTop CMDB provider not yet implemented; falling back to stub")
        return _stub_lookup(hostname)
    else:
        logger.warning(f"Unknown CMDB provider '{provider}'; falling back to stub")
        return _stub_lookup(hostname)


def _stub_lookup(hostname: str) -> dict:
    """Stub CMDB lookup — file CMDB (if DEMO_MODE), then KNOWN_HOSTS, then defaults."""
    demo_mode = os.getenv("DEMO_MODE", "").lower() == "true"
    if demo_mode:
        file_db = _load_file_cmdb()
        if hostname in file_db:
            return dict(file_db[hostname])
    if hostname in KNOWN_HOSTS:
        return dict(KNOWN_HOSTS[hostname])
    return {
        "data_classification": "Category 1",
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
