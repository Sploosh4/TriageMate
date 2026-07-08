"""
Load research references from the WA government infrastructure research report.

Parses the pipe-delimited table in Section 6 of:
    backend/reports/intel/wa-gov-infrastructure-research.md

Inserts all rows into the ``research_references`` table.
Skips duplicates on ``ref_id``.

Usage:
    python -m scripts.load_research_refs
"""

import logging
import re
from pathlib import Path

from database import get_db, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("triagemate.load_research_refs")

REPORT_PATH = (
    Path(__file__).resolve().parent.parent
    / "reports"
    / "intel"
    / "wa-gov-infrastructure-research.md"
)


def parse_references_table(text: str) -> list[dict]:
    """Parse the pipe-delimited references table from Section 6.

    Returns a list of dicts with keys: ref_id, category, finding, source_url, confidence.
    """
    rows = []
    in_table = False
    header_detected = False

    for line in text.splitlines():
        stripped = line.strip()

        # Detect table start: header row with "Ref ID"
        if stripped.startswith("| Ref ID |") and "Category" in stripped:
            in_table = True
            header_detected = True
            continue

        # Skip separator rows (e.g. |---|---|---|---|)
        if in_table and re.match(r"^\|[\s\-|]+\|$", stripped):
            continue

        # End table at empty line or next section break
        if in_table and header_detected:
            if not stripped or not stripped.startswith("|"):
                break

            # Parse pipe-delimited row
            parts = [p.strip() for p in stripped.split("|")]
            # parts[0] is empty (before first |), parts[-1] is empty (after last |)
            # So actual columns are parts[1:6]
            if len(parts) >= 6:
                ref_id = parts[1]
                category = parts[2]
                finding = parts[3]
                source_url = parts[4]
                confidence = parts[5]

                # Skip non-data rows
                if ref_id and ref_id != "Ref ID":
                    rows.append(
                        {
                            "ref_id": ref_id,
                            "category": category,
                            "finding": finding,
                            "source_url": source_url,
                            "confidence": confidence if confidence else "assumed",
                        }
                    )

    return rows


def _hardcoded_references() -> list[dict]:
    """Fallback: 97 hardcoded references from the research report.

    Used if table parsing fails or yields unexpected count.
    Hand-curated from Section 6 of the WA government infrastructure research report.
    """
    refs = [
        # Agency references (AGENCY-001 to AGENCY-023)
        {
            "ref_id": "AGENCY-001",
            "category": "Agency",
            "finding": "Department of Health (WA Health) uses health.wa.gov.au",
            "source_url": "wa.gov.au/organisation/department-of-health",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-002",
            "category": "Agency",
            "finding": "Department of Justice uses justice.wa.gov.au",
            "source_url": "wa.gov.au/organisation/department-of-justice",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-003",
            "category": "Agency",
            "finding": "Department of Transport and Major Infrastructure uses transport.wa.gov.au",
            "source_url": "wa.gov.au/organisation/department-of-transport-and-major-infrastructure",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-004",
            "category": "Agency",
            "finding": "Department of Education uses education.wa.edu.au",
            "source_url": "wa.gov.au/organisation/department-of-education",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-005",
            "category": "Agency",
            "finding": "WA Police Force uses police.wa.gov.au",
            "source_url": "wa.gov.au (agency listing), police.wa.gov.au",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-006",
            "category": "Agency",
            "finding": "Department of Finance uses finance.wa.gov.au",
            "source_url": "wa.gov.au (agency listing)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-007",
            "category": "Agency",
            "finding": "Department of Primary Industries and Regional Development uses dpird.wa.gov.au",
            "source_url": "wa.gov.au/organisation/department-of-primary-industries-and-regional-development",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-008",
            "category": "Agency",
            "finding": "Department of Communities uses communities.wa.gov.au",
            "source_url": "wa.gov.au/organisation/department-of-communities",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-009",
            "category": "Agency",
            "finding": "Parliament of Western Australia uses parliament.wa.gov.au",
            "source_url": "wa.gov.au/organisation/parliament-of-western-australia",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-010",
            "category": "Agency",
            "finding": "WA Electoral Commission uses elections.wa.gov.au",
            "source_url": "wa.gov.au/organisation/western-australian-electoral-commission",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-011",
            "category": "Agency",
            "finding": "WA Country Health Service is a sub-agency of Health; wacountry.health.wa.gov.au",
            "source_url": "wa.gov.au/organisation/wa-country-health-service",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-012",
            "category": "Agency",
            "finding": "Department of Fire and Emergency Services uses dfes.wa.gov.au",
            "source_url": "wa.gov.au/organisation/department-of-fire-and-emergency-services",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-013",
            "category": "Agency",
            "finding": "Department of Biodiversity, Conservation and Attractions uses dbca.wa.gov.au",
            "source_url": "wa.gov.au (agency listing)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-014",
            "category": "Agency",
            "finding": "Department of Water and Environmental Regulation",
            "source_url": "wa.gov.au (agency listing)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-015",
            "category": "Agency",
            "finding": "Department of Housing and Works uses dohw.wa.gov.au",
            "source_url": "wa.gov.au/organisation/department-of-housing-and-works",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-016",
            "category": "Agency",
            "finding": "Department of Energy and Economic Diversification uses deed.wa.gov.au",
            "source_url": "wa.gov.au (agency listing)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-017",
            "category": "Agency",
            "finding": "Dept of Creative Industries, Tourism and Sport uses cits.wa.gov.au",
            "source_url": "wa.gov.au (agency listing)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-018",
            "category": "Agency",
            "finding": "Water Corporation uses watercorporation.com.au",
            "source_url": "wa.gov.au (agency listing)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-019",
            "category": "Agency",
            "finding": "Main Roads Western Australia",
            "source_url": "wa.gov.au (agency listing)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-020",
            "category": "Agency",
            "finding": "Public Transport Authority",
            "source_url": "wa.gov.au (agency listing)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-021",
            "category": "Agency",
            "finding": "Shared Services Centre operates as part of Finance",
            "source_url": "mock_cmdb.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-022",
            "category": "Agency",
            "finding": "Office of the Auditor General uses audit.wa.gov.au",
            "source_url": "wa.gov.au (agency listing)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "AGENCY-023",
            "category": "Agency",
            "finding": "Corruption and Crime Commission uses ccc.wa.gov.au",
            "source_url": "wa.gov.au (agency listing)",
            "confidence": "confirmed",
        },
        # Enterprise software references (SOFTWARE-001 to SOFTWARE-020)
        {
            "ref_id": "SOFTWARE-001",
            "category": "Enterprise",
            "finding": "SAP ERP used in WA government for financial/HR",
            "source_url": "mock_cmdb.json (SAP-FIN01), industry pattern",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-002",
            "category": "Enterprise",
            "finding": "Progress MOVEit Transfer used for MFT in WA Health",
            "source_url": "mock_cmdb.json (MOVEIT-WEB01)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-003",
            "category": "Enterprise",
            "finding": "Citrix ADC/NetScaler used as remote access gateway",
            "source_url": "mock_cmdb.json (CITRIX-ADC01)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-004",
            "category": "Enterprise",
            "finding": "Microsoft Exchange Server for email",
            "source_url": "mock_cmdb.json (EXCHANGE-CAS01, FIRE-COMMS01)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-005",
            "category": "Enterprise",
            "finding": "Microsoft SharePoint used for intranet/staff portal",
            "source_url": "mock_cmdb.json (STAFFPORTAL01 - SharePoint 2019)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-006",
            "category": "Enterprise",
            "finding": "Atlassian Confluence used for internal knowledge base",
            "source_url": "mock_cmdb.json (WIKI-CORE01 - Confluence 8.5.1)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-007",
            "category": "Enterprise",
            "finding": "Zoho ManageEngine ServiceDesk Plus for IT ticketing",
            "source_url": "mock_cmdb.json (ITSM-TOOL01 - ServiceDesk Plus 14.0)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-008",
            "category": "Enterprise",
            "finding": "Moodle LMS used by Department of Education",
            "source_url": "mock_cmdb.json (STUDENT-DB01 - Moodle 4.3 LTS)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-009",
            "category": "Enterprise",
            "finding": "Oracle E-Business Suite likely used for HR/finance in some agencies",
            "source_url": "Industry pattern, CISA KEV Oracle entries",
            "confidence": "likely",
        },
        {
            "ref_id": "SOFTWARE-010",
            "category": "Enterprise",
            "finding": "Student Information System (PowerSchool/SAS2000) used by DoE",
            "source_url": "Industry pattern, seek.com.au IT job ads",
            "confidence": "assumed",
        },
        {
            "ref_id": "SOFTWARE-011",
            "category": "Enterprise",
            "finding": "WebPAS/iPHIS patient administration in WA Health",
            "source_url": "jobs.health.wa.gov.au job descriptions",
            "confidence": "likely",
        },
        {
            "ref_id": "SOFTWARE-012",
            "category": "Enterprise",
            "finding": "ConnectWise ScreenConnect for remote management",
            "source_url": "mock_cmdb.json (RMM-GW01 - ScreenConnect 23.9.7)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-013",
            "category": "Enterprise",
            "finding": "PaperCut MF for print management",
            "source_url": "mock_cmdb.json (PRINT-SVR05 - PaperCut MF 22.0.6)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-014",
            "category": "Enterprise",
            "finding": "CAD Dispatch Platform for emergency services",
            "source_url": "mock_cmdb.json (CAD-DISPATCH01, ES-DISPATCH01)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-015",
            "category": "Enterprise",
            "finding": "Xylem Aanderaa GeoView for marine documentation",
            "source_url": "mock_cmdb.json (MARINE-DOC01 - GeoView 3.5)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-016",
            "category": "Enterprise",
            "finding": "Apache Struts used in Communities case management",
            "source_url": "mock_cmdb.json (CASEMGT-APP01 - Struts 2.5.30)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-017",
            "category": "Enterprise",
            "finding": "PostgreSQL used by multiple agencies",
            "source_url": "mock_cmdb.json (multiple hosts)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-018",
            "category": "Enterprise",
            "finding": "Microsoft SQL Server used by multiple agencies",
            "source_url": "mock_cmdb.json (multiple hosts)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-019",
            "category": "Enterprise",
            "finding": "Shibboleth IdP for Education identity management",
            "source_url": "mock_cmdb.json (EDU-IDM01)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "SOFTWARE-020",
            "category": "Enterprise",
            "finding": "Schneider Electric SCADA for water treatment",
            "source_url": "mock_cmdb.json (WTR-SCADA01)",
            "confidence": "confirmed",
        },
        # Hostname references (HOSTNAME-001 to HOSTNAME-008)
        {
            "ref_id": "HOSTNAME-001",
            "category": "Hostname",
            "finding": "Base pattern: {location}-{ENV}-{APP}{NUM}.{dept}.wa.gov.au",
            "source_url": "docs/reference/hostname-standards.md, observed patterns",
            "confidence": "confirmed",
        },
        {
            "ref_id": "HOSTNAME-002",
            "category": "Hostname",
            "finding": "Location code `per` for Perth datacentre",
            "source_url": "mock_cmdb.json, demo_scenarios.json (all hosts use per-)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "HOSTNAME-003",
            "category": "Hostname",
            "finding": "Environment codes: PRD/DEV/TST/STG/UAT/DR/EOL/MIG/ACT",
            "source_url": "hostname-standards.md, CMDB (only PRD observed)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "HOSTNAME-004",
            "category": "Hostname",
            "finding": "30+ role codes confirmed (WEB, APP, DB, DC, ADC, etc.)",
            "source_url": "mock_cmdb.json (exhaustive server roles)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "HOSTNAME-005",
            "category": "Hostname",
            "finding": "OS indicators (WIN/LNX/SOL) are industry standard",
            "source_url": "Industry pattern",
            "confidence": "assumed",
        },
        {
            "ref_id": "HOSTNAME-006",
            "category": "Hostname",
            "finding": "Network zone indicators: DMZ, Internal, Management, Ops, OT",
            "source_url": "mock_cmdb.json (VLAN assignments)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "HOSTNAME-007",
            "category": "Hostname",
            "finding": "Domain controller naming: DC01, DC02 pattern",
            "source_url": "mock_cmdb.json (per-PRD-DC01.finance.wa.gov.au)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "HOSTNAME-008",
            "category": "Hostname",
            "finding": "17 different agency domain suffixes confirmed",
            "source_url": "mock_cmdb.json, wa.gov.au/organisation listings",
            "confidence": "confirmed",
        },
        # Network/Topology references (NETWORK-001 to NETWORK-006)
        {
            "ref_id": "NETWORK-001",
            "category": "Topology",
            "finding": "5 distinct DMZ segments across agencies",
            "source_url": "mock_cmdb.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "NETWORK-002",
            "category": "Topology",
            "finding": "12 internal VLAN segments with numbering",
            "source_url": "mock_cmdb.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "NETWORK-003",
            "category": "Topology",
            "finding": "Azure Australia East/Central, AWS Sydney used for cloud",
            "source_url": "Industry standard (Microsoft, AWS documentation)",
            "confidence": "assumed",
        },
        {
            "ref_id": "NETWORK-004",
            "category": "Topology",
            "finding": "Shared Services Centre provides cross-agency network",
            "source_url": "mock_cmdb.json, wa.gov.au/publications",
            "confidence": "confirmed",
        },
        {
            "ref_id": "NETWORK-005",
            "category": "Topology",
            "finding": "Separate AD forest for WAPOL internal systems",
            "source_url": "mock_cmdb.json (wapol.internal.wa.gov.au)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "NETWORK-006",
            "category": "Topology",
            "finding": "OT/ICS segmentation for SCADA/water infrastructure",
            "source_url": "mock_cmdb.json (Water-OT-Segment VLAN 501)",
            "confidence": "confirmed",
        },
        # CVE references (CVE-001 to CVE-040)
        {
            "ref_id": "CVE-001",
            "category": "CVE",
            "finding": "CVE-2023-34362 - MOVEit SQLi RCE",
            "source_url": "CISA KEV, mock_cmdb.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-002",
            "category": "CVE",
            "finding": "CVE-2024-0204 - MOVEit auth bypass",
            "source_url": "CISA KEV",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-003",
            "category": "CVE",
            "finding": "CVE-2024-5806 - MOVEit auth bypass",
            "source_url": "CISA KEV, demo_scenarios.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-004",
            "category": "CVE",
            "finding": "CVE-2023-3519 - Citrix ADC RCE",
            "source_url": "CISA KEV, mock_cmdb.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-005",
            "category": "CVE",
            "finding": "CVE-2019-19781 - Citrix ADC RCE",
            "source_url": "CISA KEV, demo_scenarios.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-006",
            "category": "CVE",
            "finding": "CVE-2023-4966 - Citrix Bleed info disclosure",
            "source_url": "CISA KEV, demo_scenarios.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-007",
            "category": "CVE",
            "finding": "CVE-2023-22515 - Confluence admin takeover",
            "source_url": "CISA KEV, mock_cmdb.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-008",
            "category": "CVE",
            "finding": "CVE-2023-22518 - Confluence improper auth",
            "source_url": "CISA KEV",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-009",
            "category": "CVE",
            "finding": "CVE-2022-26134 - Confluence OGNL RCE",
            "source_url": "CISA KEV",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-010",
            "category": "CVE",
            "finding": "CVE-2022-47966 - ManageEngine SAML RCE",
            "source_url": "CISA KEV, mock_cmdb.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-011",
            "category": "CVE",
            "finding": "CVE-2024-4317 - ManageEngine auth bypass RCE",
            "source_url": "CISA KEV, demo_scenarios.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-012",
            "category": "CVE",
            "finding": "CVE-2023-23397 - Outlook/Exchange NTLM relay",
            "source_url": "CISA KEV, mock_cmdb.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-013",
            "category": "CVE",
            "finding": "CVE-2023-27350 - PaperCut RCE",
            "source_url": "CISA KEV, mock_cmdb.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-014",
            "category": "CVE",
            "finding": "CVE-2024-1708 - ScreenConnect auth bypass RCE",
            "source_url": "CISA KEV, mock_cmdb.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-015",
            "category": "CVE",
            "finding": "CVE-2023-36884 - Office/Windows HTML RCE",
            "source_url": "CISA KEV, demo_scenarios.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-016",
            "category": "CVE",
            "finding": "CVE-2020-14750 - Oracle WebLogic RCE",
            "source_url": "CISA KEV",
            "confidence": "likely",
        },
        {
            "ref_id": "CVE-017",
            "category": "CVE",
            "finding": "CVE-2021-26855 - Exchange ProxyLogon SSRF",
            "source_url": "CISA KEV",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-018",
            "category": "CVE",
            "finding": "CVE-2023-24955 - SharePoint RCE",
            "source_url": "CISA KEV",
            "confidence": "likely",
        },
        {
            "ref_id": "CVE-019",
            "category": "CVE",
            "finding": "CVE-2026-35273 - Oracle zero-day (current KEV)",
            "source_url": "CISA KEV (kev_cache.json)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-020",
            "category": "CVE",
            "finding": "CVE-2024-21182 - Oracle CVE",
            "source_url": "CISA KEV (kev_cache.json)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-021",
            "category": "CVE",
            "finding": "CVE-2022-0492 - Linux kernel container escape",
            "source_url": "CISA KEV (kev_cache.json)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-022",
            "category": "CVE",
            "finding": "CVE-2008-4250 - Windows MS08-067 legacy RCE",
            "source_url": "CISA KEV (kev_cache.json)",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-023",
            "category": "CVE",
            "finding": "CVE-2020-0796 - SMBGhost Windows SMB RCE",
            "source_url": "CISA KEV, demo_scenarios.json",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-024",
            "category": "CVE",
            "finding": "65% of government-relevant KEV CVEs are Critical (9.0+)",
            "source_url": "KEV catalog analysis",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-025",
            "category": "Threat",
            "finding": "CWE-89 SQL Injection in citizen portals",
            "source_url": "NVD, ACSC threat reports",
            "confidence": "likely",
        },
        {
            "ref_id": "CVE-026",
            "category": "Threat",
            "finding": "CWE-306 Missing Authentication on perimeter systems",
            "source_url": "NVD, ACSC threat reports",
            "confidence": "likely",
        },
        {
            "ref_id": "CVE-027",
            "category": "Threat",
            "finding": "CWE-78 OS Command Injection on network devices",
            "source_url": "NVD, ACSC threat reports",
            "confidence": "likely",
        },
        {
            "ref_id": "CVE-028",
            "category": "Threat",
            "finding": "CWE-287 Improper Authentication in identity systems",
            "source_url": "NVD, ASD threat reports",
            "confidence": "likely",
        },
        {
            "ref_id": "CVE-029",
            "category": "Threat",
            "finding": "CWE-269 Privilege escalation in AD environments",
            "source_url": "NVD, ACSC AD guidance",
            "confidence": "likely",
        },
        {
            "ref_id": "CVE-030",
            "category": "Threat",
            "finding": "CWE-22 Path traversal on file servers",
            "source_url": "NVD, ACSC threat reports",
            "confidence": "likely",
        },
        {
            "ref_id": "CVE-031",
            "category": "Threat",
            "finding": "CWE-918 SSRF from DMZ to internal networks",
            "source_url": "NVD, ASD threat reports",
            "confidence": "likely",
        },
        {
            "ref_id": "CVE-032",
            "category": "Threat",
            "finding": "CWE-200 Information exposure (PII leakage)",
            "source_url": "NVD, OAIC reports",
            "confidence": "likely",
        },
        {
            "ref_id": "CVE-033",
            "category": "EPSS",
            "finding": "CVE-2023-34362 EPSS: 0.96-0.97",
            "source_url": "FIRST.org EPSS cache",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-034",
            "category": "EPSS",
            "finding": "CVE-2023-3519 EPSS: 0.97-0.98",
            "source_url": "FIRST.org EPSS cache",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-035",
            "category": "EPSS",
            "finding": "CVE-2023-22515 EPSS: 0.97-0.98",
            "source_url": "FIRST.org EPSS cache",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-036",
            "category": "EPSS",
            "finding": "CVE-2022-47966 EPSS: 0.95-0.97",
            "source_url": "FIRST.org EPSS cache",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-037",
            "category": "EPSS",
            "finding": "CVE-2023-23397 EPSS: 0.96-0.97",
            "source_url": "FIRST.org EPSS cache",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-038",
            "category": "EPSS",
            "finding": "CVE-2020-0796 EPSS: 0.95-0.97",
            "source_url": "FIRST.org EPSS cache",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-039",
            "category": "EPSS",
            "finding": "CVE-2023-36884 EPSS: 0.40-0.60",
            "source_url": "FIRST.org EPSS cache",
            "confidence": "confirmed",
        },
        {
            "ref_id": "CVE-040",
            "category": "EPSS",
            "finding": "CVE-2022-0333 (Moodle) EPSS: 0.05-0.10",
            "source_url": "FIRST.org EPSS cache",
            "confidence": "confirmed",
        },
    ]
    return refs


def load_references() -> None:
    """Parse research references from the report and insert into DB."""
    # Ensure tables exist
    init_db()

    # Try parsing the table from the markdown report
    report_path = REPORT_PATH
    if not report_path.exists():
        logger.warning("Report not found at %s — using hardcoded fallback", report_path)
        refs = _hardcoded_references()
    else:
        text = report_path.read_text(encoding="utf-8")
        refs = parse_references_table(text)
        if len(refs) < 80:
            logger.warning(
                "Parsed only %d references from table (expected 85+) — "
                "using hardcoded fallback",
                len(refs),
            )
            refs = _hardcoded_references()
        else:
            logger.info("Parsed %d references from markdown table", len(refs))

    # Insert into database
    db = get_db()
    try:
        inserted = 0
        skipped = 0
        for ref in refs:
            try:
                cursor = db.execute(
                    """
                    INSERT INTO research_references (ref_id, category, finding, source_url, confidence)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (ref_id) DO NOTHING
                    """,
                    (
                        ref["ref_id"],
                        ref["category"],
                        ref["finding"],
                        ref["source_url"],
                        ref["confidence"],
                    ),
                )
                if cursor.rowcount and cursor.rowcount > 0:
                    inserted += 1
                else:
                    skipped += 1
            except Exception as exc:
                logger.warning("Insert failed for ref_id %s: %s", ref["ref_id"], exc)
                skipped += 1

        db.commit()
        logger.info("Inserted %d references, skipped %d", inserted, skipped)
        print(
            f"Inserted {inserted} rows into research_references, skipped {skipped} duplicates"
        )
    finally:
        db.close()


def main() -> None:
    load_references()


if __name__ == "__main__":
    main()
