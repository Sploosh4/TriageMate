"""
Seed data script: Populates the database with the 7 demo rows.

Run once: python seed_data.py
The 7 rows match the original QUEUE_DATA array exactly.
"""

import json
from database import get_db, init_db

SEED_ROWS = [
    # Row 1: CVE-2023-34362 — MOVEit Transfer SQL Injection
    {
        "vulnerability_id": "CVE-2023-34362",
        "hostname": "per-PRD-MOVEIT-WEB01.health.wa.gov.au",
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cisa_kev": True,
        "epss_score": 0.974,
        "mission_prevalence": "Core",
        "mission_prevalence_conf": 0.94,
        "public_wellbeing_impact": "Severe",
        "public_wellbeing_conf": 0.96,
        "tier_0_routing": "auto_resolved",
        "tier_0_resolution": "very_critical",
        "tier_1_confidence": None,
        "tier_1_exploitation_prob": None,
        "tier_1_routing": None,
        "tier_2_text_conflict": False,
        "tier_2_conflict_note": None,
        "tier_2_rag_result": None,
        "tier_2_confidence": None,
        "tier_2_resolution_summary": None,
        "priority_score": 99,
        "risk_band": "Very Critical",
        "cvss_contribution": 39,
        "epss_contribution": 19,
        "asset_criticality_contribution": 20,
        "exposure_contribution": 12,
        "patch_remediation_contribution": 0,
        "ml_exploitation_contribution": 0,
        "security_context_contribution": 0,
        "epss_substituted": False,
        "epss_substituted_value": None,
        "epss_substitution_confidence": None,
        "epss_substitution_reason": None,
        "data_classification": "OFFICIAL Sensitive",
        "network_zone": "DMZ-Health-External",
        "interface_type": "Internet-facing HTTPS (no VPN required)",
        "patch_cycle": "Monthly (second Sunday, 0200-0600 AWST)",
        "last_patch_date": "14 May 2026",
        "last_scan_date": "27 June 2026",
        "operating_system": "Windows Server 2019 Standard (build 17763)",
        "role": "Managed File Transfer Server — Inter-Hospital Health Information Exchange",
        "business_owner": "WA Health — Health Support Services, ICT Operations",
        "technical_owner": "Health Support Services — Infrastructure Platforms Team",
        "registered_applications": "Progress MOVEit Transfer 2023.0.0, IIS 10.0",
        "dependent_assets": "per-PRD-SQL-CLUSTER01.health.wa.gov.au (backend database), per-PRD-FILE-SAN01.health.wa.gov.au (storage target)",
        "service_account": "",
        "detection_tier": "Deterministic",
        "detection_reason": "Deterministic match: CVSS 9.8, CISA KEV listed, active exploitation confirmed by WASOC threat intel feed, internet-facing MOVEit Transfer instance on a health data asset.",
        "scanner_output_raw": "[CRITICAL] CVE-2023-34362 — Progress MOVEit Transfer SQL Injection\nHost: per-PRD-MOVEIT-WEB01.health.wa.gov.au (10.47.22.18)\nPort: 443/tcp (HTTPS)\nService: Progress MOVEit Transfer 2023.0.0 (build 15.0.0.185)\nDetection Method: Banner grab + HTTP response analysis\nCVSS v3.1: 9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)\nCISA KEV: TRUE\nEPSS Score: 0.974 (97th percentile)\nExploit Maturity: High (weaponised exploit available in multiple C2 frameworks)\nPatch Available: Yes (MOVEit Transfer 2023.0.2 and later)\nPatch Applied: No (version confirmed below fixed threshold)",
        "weakness_template_raw": 'template_id: DET-2023-MOVEIT-SQLI-001\ntemplate_name: "MOVEit Transfer Pre-Auth SQL Injection — Silent Chaining Detection"\nlogic_chain:\n  - step: 1\n    condition: "software_product == \'Progress MOVEit Transfer\' AND version < 2023.0.2"\n    weight: 0.35\n  - step: 2\n    condition: "exposed_port == 443 AND internet_facing == TRUE"\n    weight: 0.25\n  - step: 3\n    condition: "data_classification IN [OFFICIAL_Sensitive]"\n    weight: 0.20\n  - step: 4\n    condition: "cisa_kev == TRUE AND exploit_maturity == \'High\'"\n    weight: 0.15\n  - step: 5\n    condition: "patch_lag_days > 7"\n    weight: 0.05',
        "advisory_ref_id": "ADV-CVE-2023-34362",
        "advisory_quote": "The Western Australian Security Operations Centre assesses with high confidence that Progress MOVEit Transfer instances operated by WA state government entities are being actively targeted by the Clop ransomware group. All agencies must immediately verify MOVEit Transfer version numbers and apply vendor patches within 24 hours. Agencies operating MOVEit Transfer as an internet-facing service must additionally implement network-level access restrictions pending patch application. The WASOC has confirmed that at least three Australian state government entities have been impacted as of 5 June 2023.",
        "investigation_notes": "The following summary has been pre-filled for analyst review and editing.\n\nThe vulnerability CVE-2023-34362 on per-PRD-MOVEIT-WEB01.health.wa.gov.au has been automatically assigned a priority score of 99 and a risk band of Very Critical by the Deterministic Tier engine. All seven scoring dimensions triggered at maximum severity. The asset is internet-facing on port 443, the MOVEit Transfer version 2023.0.0 is confirmed vulnerable, and the WASOC threat intelligence feed has verified active exploitation by the Clop ransomware group targeting Australian state government entities. The EPSS score of 0.974 indicates a 97.4 percent probability of exploitation within the next 30 days.\n\nThe multi-label classifier has tagged this asset with Mission Prevalence: Core and Public Well-Being Impact: Severe, reflecting its role as the central health data exchange infrastructure for the state.\n\nThe asset is registered as a OFFICIAL Sensitive data asset under WAICP, hosting Health Information Exchange records containing protected health information for the WA Country Health Service and metropolitan health campuses. A compromise of this asset would constitute a notifiable data breach.\n\nImmediate recommended action: Apply the MOVEit Transfer security patch to version 2023.0.2 or later. Pending patch application, restrict access to the MOVEit Transfer web interface to internal IP ranges only via the upstream network access control list. Commence a forensic review of MOVEit Transfer IIS logs for indicators of compromise associated with CVE-2023-34362 exploitation.",
        "mitre_techniques_json": json.dumps(
            [
                {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "desc": "The attacker exploits the SQL injection flaw in the MOVEit Transfer web interface, which is directly accessible from the internet, to gain initial access.",
                },
                {
                    "id": "T1505.003",
                    "name": "Server Software Component: Web Shell",
                    "desc": "Post-exploitation, attackers have been observed deploying the LemurLoot web shell on compromised MOVEit Transfer servers to maintain persistent access and exfiltrate data over HTTPS.",
                },
                {
                    "id": "T1041",
                    "name": "Exfiltration Over C2 Channel",
                    "desc": "Stolen database contents, including patient referral documents, are exfiltrated through the same HTTPS channel used for command and control, blending with legitimate MOVEit Transfer traffic.",
                },
            ]
        ),
        "scoring_weights_json": json.dumps(
            [
                {
                    "name": "CVSS Base Score Contribution",
                    "awarded": 39,
                    "max": 40,
                    "justification": "The CVSS score of 9.8 maps to the maximum tier.",
                },
                {
                    "name": "EPSS Exploitability Contribution",
                    "awarded": 19,
                    "max": 20,
                    "justification": "The EPSS score of 0.974 exceeds the 0.90 threshold for maximum weighting.",
                },
                {
                    "name": "Asset Criticality Contribution",
                    "awarded": 20,
                    "max": 20,
                    "justification": "This is a OFFICIAL Sensitive health data asset hosting patient records with a Mission Prevalence of Core and a Public Well-Being Impact of Severe.",
                },
                {
                    "name": "Exposure and Network Position",
                    "awarded": 12,
                    "max": 12,
                    "justification": "The asset is internet-facing on port 443 with no web application firewall detected and no multi-factor authentication on the administrative interface.",
                },
                {
                    "name": "Patch Availability and Remediation Complexity",
                    "awarded": 0,
                    "max": 5,
                    "justification": "A patch has been available for 14 days with no action taken. The remediation complexity is low.",
                },
                {
                    "name": "ML Exploitation Probability Contribution",
                    "awarded": 0,
                    "max": 10,
                    "justification": "Tier 1 ML model was not executed (auto-resolved at Tier 0).",
                },
                {
                    "name": "Context Multiplier",
                    "awarded": 1.1,
                    "max": 1.2,
                    "justification": "1.10x multiplier applied — telemetry threat score (0.976) with vulnerable code_loaded=True enables partial evidence escalation.",
                },
            ]
        ),
        "asset_registry_json": json.dumps(
            [
                {"label": "Asset ID", "value": "AST-HEALTH-00472"},
                {"label": "Hostname", "value": "per-PRD-MOVEIT-WEB01.health.wa.gov.au"},
                {
                    "label": "IP Address",
                    "value": "10.47.22.18 (internal) / 203.14.xxx.xxx (external NAT)",
                },
                {
                    "label": "Operating System",
                    "value": "Windows Server 2019 Standard (build 17763)",
                },
                {
                    "label": "Role",
                    "value": "Managed File Transfer Server — Inter-Hospital Health Information Exchange",
                },
                {
                    "label": "Business Owner",
                    "value": "WA Health — Health Support Services, ICT Operations",
                },
                {
                    "label": "Technical Owner",
                    "value": "Health Support Services — Infrastructure Platforms Team",
                },
                {
                    "label": "Data Classification",
                    "value": "OFFICIAL Sensitive — Sensitive (Health) — WAICP classification",
                },
                {
                    "label": "Mission Prevalence",
                    "value": "Core (predicted — multi-label classifier, confidence 0.94)",
                },
                {
                    "label": "Public Well-Being Impact",
                    "value": "Severe (predicted — multi-label classifier, confidence 0.96)",
                },
                {"label": "Network Zone", "value": "DMZ-Health-External"},
                {
                    "label": "Patch Cycle",
                    "value": "Monthly (second Sunday, 0200-0600 AWST)",
                },
                {"label": "Last Patch Date", "value": "14 May 2026"},
                {
                    "label": "Registered Applications",
                    "value": "Progress MOVEit Transfer 2023.0.0, IIS 10.0",
                },
                {
                    "label": "Dependent Assets",
                    "value": "per-PRD-SQL-CLUSTER01.health.wa.gov.au (backend database), per-PRD-FILE-SAN01.health.wa.gov.au (storage target)",
                },
                {
                    "label": "Interface Type",
                    "value": "Internet-facing HTTPS (no VPN required)",
                },
                {"label": "Last Vulnerability Scan", "value": "27 June 2026"},
            ]
        ),
        "summary_paragraphs_json": json.dumps(
            [
                "This case concerns a critical SQL injection vulnerability in Progress MOVEit Transfer, tracked as CVE-2023-34362, identified on the host per-PRD-MOVEIT-WEB01.health.wa.gov.au. The vulnerability permits an unauthenticated attacker to inject structured query language commands into the MOVEit Transfer web application, resulting in complete compromise of the underlying database. The affected database contains Health Information Exchange records, patient referral data, and inter-hospital file transfer metadata for the Western Australian public health system.",
                "The multi-label classifier assessed this asset as having a Mission Prevalence of Core and a Public Well-Being Impact of Severe, reflecting its role as the central health data exchange platform for the WA Country Health Service and metropolitan health campuses.",
                "The vulnerability was added to the CISA Known Exploited Vulnerabilities catalogue on 2 June 2023, and the WASOC Cyber Threat Intelligence feed has confirmed active exploitation by the Clop ransomware group against Australian state government targets since 27 May 2023. The attack surface is fully exposed: the MOVEit Transfer instance is reachable on TCP port 443 from the public internet with no additional compensating controls, and Shodan scan results confirm the service banner is identifiable. The combination of remote unauthenticated attack vector, confirmed in-the-wild exploitation, direct internet exposure, the Core mission role, and the OFFICIAL Sensitive health data asset classification drives the priority score to 99 out of 100.",
            ]
        ),
        "telemetry_json": '{"sentinel_incidents": [{"incident_id": "SEN-2026-986655", "title": "Suspected exploitation of CVE-2023-34362", "severity": "High", "status": "Resolved", "detected_at": "2024-05-23T03:06:20Z", "assigned_to": "SOC Tier 2", "related_entities": ["per-PRD-MOVEIT-WEB01.health.wa.gov.au"], "mitre_techniques": ["T1190", "T1133", "T1078"]}], "edr_alerts": [{"alert_id": "EDR-20240403-5492", "alert_type": "process_execution", "severity": "Medium", "process_name": "moveitdmz.exe", "process_path": "C:\\\\Program Files\\\\Moveit\\\\moveitdmz.exe", "user": "NT AUTHORITY\\\\NETWORK SERVICE", "timestamp": "2024-04-03T19:34:55Z", "details": "Suspicious process execution of moveitdmz.exe related to CVE-2023-34362"}, {"alert_id": "EDR-20240403-5062", "alert_type": "network_connection", "severity": "Low", "process_name": "moveitdmz.exe", "process_path": "C:\\\\Program Files\\\\Moveit\\\\moveitdmz.exe", "user": "NT AUTHORITY\\\\SYSTEM", "timestamp": "2024-03-21T07:28:16Z", "details": "Outbound connection from moveitdmz.exe to external IP address"}], "process_evidence": {"is_running": true, "is_loaded": true, "running_processes": ["moveitdmz.exe", "moverequesthandler.dll"], "evidence_quality": "high"}, "threat_score": 0.9759488385642258}',
        "network_context_json": '{"zone": "dmz", "zone_display": "DMZ (Health \\u2014 External)", "peer_count": 34, "internet_facing_peers": 19, "dc_peers": 0, "peer_classifications": {"Support": 11, "Core": 17, "Peripheral": 6}, "blast_radius_score": 0.4494117647058824, "exposure_level": "medium", "data_source": "synthetic_assets"}',
        "pre_tier_features": None,
        "epss_features": None,
    },
    # Row 2: CVE-2023-4966 — Citrix Bleed
    {
        "vulnerability_id": "CVE-2023-4966",
        "hostname": "per-PRD-CITRIX-ADC01.transport.wa.gov.au",
        "cvss_score": 9.4,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
        "cisa_kev": True,
        "epss_score": 0.968,
        "mission_prevalence": "Core",
        "mission_prevalence_conf": 0.91,
        "public_wellbeing_impact": "Moderate",
        "public_wellbeing_conf": 0.88,
        "tier_0_routing": "auto_resolved",
        "tier_0_resolution": "very_critical",
        "tier_1_confidence": None,
        "tier_1_exploitation_prob": None,
        "tier_1_routing": None,
        "tier_2_text_conflict": False,
        "tier_2_conflict_note": None,
        "tier_2_rag_result": None,
        "tier_2_confidence": None,
        "tier_2_resolution_summary": None,
        "priority_score": 97,
        "risk_band": "Very Critical",
        "cvss_contribution": 38,
        "epss_contribution": 19,
        "asset_criticality_contribution": 19,
        "exposure_contribution": 12,
        "patch_remediation_contribution": 0,
        "ml_exploitation_contribution": 0,
        "security_context_contribution": 0,
        "epss_substituted": False,
        "epss_substituted_value": None,
        "epss_substitution_confidence": None,
        "epss_substitution_reason": None,
        "data_classification": "OFFICIAL Sensitive",
        "network_zone": "DMZ-Transport-External",
        "interface_type": "Internet-facing HTTPS (external VIP on port 443)",
        "patch_cycle": "Ad-hoc (appliance updates applied during scheduled maintenance windows)",
        "last_patch_date": "15 March 2026",
        "last_scan_date": "28 June 2026",
        "operating_system": "Citrix NetScaler ADC VPX 13.1-49.13 (FreeBSD-based)",
        "role": "Perimeter Remote Access Gateway — Department of Transport",
        "business_owner": "Department of Transport — ICT Services",
        "technical_owner": "Transport ICT — Networks and Security Team",
        "registered_applications": "Citrix Gateway (VPN virtual server), Citrix Load Balancer (TEMIS backend), Citrix Content Switching (DVS Online)",
        "dependent_assets": "per-PRD-TEMIS-APP01.transport.wa.gov.au, per-PRD-DVS-WEB01.transport.wa.gov.au, per-PRD-MARINE-DOC01.transport.wa.gov.au (+ 19 other published application targets)",
        "service_account": "",
        "detection_tier": "Deterministic",
        "detection_reason": "Deterministic match: CVSS 9.4, CISA KEV listed, session token leakage on perimeter Citrix NetScaler ADC. Baseline algorithm detected unpatched build hash within 72 hours of advisory publication.",
        "scanner_output_raw": "[CRITICAL] CVE-2023-4966 — Citrix NetScaler ADC/Gateway Session Token Leakage\nHost: per-PRD-CITRIX-ADC01.transport.wa.gov.au (10.61.5.2)\nPort: 443/tcp (HTTPS)\nService: Citrix NetScaler ADC VPX 13.1-49.13\nDetection Method: HTTP response header analysis + build number extraction via /vpn/index.html\nCVSS v3.1: 9.4 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L)\nCISA KEV: TRUE\nEPSS Score: 0.968 (96th percentile)\nExploit Maturity: High (multiple public PoCs, Metasploit module available)\nPatch Available: Yes (NetScaler ADC 13.1-49.15 and later)\nPatch Applied: No (build 49.13 is vulnerable; builds prior to 49.15 are affected)\nImmediate Risk: Session token harvesting enables lateral movement into internal transport systems",
        "weakness_template_raw": 'template_id: DET-2023-CITRIX-BLEED-001\ntemplate_name: "Citrix NetScaler ADC Pre-Auth Session Token Disclosure — Perimeter Device Risk"\nlogic_chain:\n  - step: 1\n    condition: "software_product == \'Citrix NetScaler ADC\' AND build_number IN affected_range"\n    weight: 0.30\n  - step: 2\n    condition: "device_role == \'perimeter_gateway\' AND internet_facing == TRUE"\n    weight: 0.30\n  - step: 3\n    condition: "authentication_bypass == TRUE AND credential_theft_possible == TRUE"\n    weight: 0.20\n  - step: 4\n    condition: "cisa_kev == TRUE AND days_since_kev_listing >= 7"\n    weight: 0.15\n  - step: 5\n    condition: "downstream_asset_count > 5"\n    weight: 0.05',
        "advisory_ref_id": "ADV-CVE-2023-4966",
        "advisory_quote": "The Western Australian Security Operations Centre is issuing an urgent advisory regarding CVE-2023-4966, a critical session token disclosure vulnerability in Citrix NetScaler ADC and Gateway appliances. This vulnerability has been confirmed as actively exploited in the wild. WA government agencies operating Citrix NetScaler appliances as internet-facing remote access gateways should immediately verify their build version and upgrade to a fixed release. Agencies that cannot patch immediately must implement the vendor-recommended mitigation steps including restricting access to the management interface and terminating all active and persistent sessions.",
        "investigation_notes": "The following summary has been pre-filled for analyst review and editing.\n\nCVE-2023-4966 on per-PRD-CITRIX-ADC01.transport.wa.gov.au has been assigned a priority score of 97 and a risk band of Very Critical by the Deterministic Tier engine. The appliance is a perimeter gateway device providing remote access to the Department of Transport internal network. The vulnerability enables session token theft without authentication, which can be leveraged to impersonate authenticated users including system administrators.\n\nImmediate recommended action: Upgrade the NetScaler ADC VPX appliance to build 13.1-49.15 or later. Prior to upgrade, terminate all active and persistent sessions via the NetScaler management interface. Review the ns.log file for anomalous session creation events.",
        "mitre_techniques_json": json.dumps(
            [
                {
                    "id": "T1078",
                    "name": "Valid Accounts",
                    "desc": "After extracting a valid session token from the appliance memory, the attacker authenticates as a legitimate user without knowing their password, effectively using stolen valid accounts.",
                },
                {
                    "id": "T1133",
                    "name": "External Remote Services",
                    "desc": "The Citrix NetScaler ADC functions as an external remote services gateway. The attacker exploits the vulnerability to bypass the authentication mechanism of this external-facing service.",
                },
                {
                    "id": "T1550.004",
                    "name": "Use Alternate Authentication Material: Web Session Cookie",
                    "desc": "The extracted session token is presented as a web session cookie to the NetScaler Gateway, allowing the attacker to impersonate the victim user and access internal applications.",
                },
            ]
        ),
        "scoring_weights_json": json.dumps(
            [
                {
                    "name": "CVSS Base Score Contribution",
                    "awarded": 38,
                    "max": 40,
                    "justification": "The CVSS score of 9.4 maps to the near-maximum tier.",
                },
                {
                    "name": "EPSS Exploitability Contribution",
                    "awarded": 19,
                    "max": 20,
                    "justification": "The EPSS score of 0.968 places this vulnerability in the top four percent of all CVEs by exploitation probability, and a Metasploit module is available.",
                },
                {
                    "name": "Asset Criticality Contribution",
                    "awarded": 19,
                    "max": 20,
                    "justification": "This is a perimeter gateway for transport executive systems with a Mission Prevalence of Core and a Public Well-Being Impact of Moderate.",
                },
                {
                    "name": "Exposure and Network Position",
                    "awarded": 12,
                    "max": 12,
                    "justification": "The device is an internet-facing perimeter appliance. The management IP is partially restricted but the VPN virtual server is publicly accessible.",
                },
                {
                    "name": "Patch Availability and Remediation Complexity",
                    "awarded": 0,
                    "max": 5,
                    "justification": "A patch has been available for 21 days. The upgrade process requires maintenance window planning but has not been scheduled.",
                },
                {
                    "name": "ML Exploitation Probability Contribution",
                    "awarded": 0,
                    "max": 10,
                    "justification": "Tier 1 ML model was not executed (auto-resolved at Tier 0).",
                },
                {
                    "name": "Context Multiplier",
                    "awarded": 1.1,
                    "max": 1.2,
                    "justification": "1.10x multiplier applied — telemetry threat score (1.000) with vulnerable code_loaded=True enables partial evidence escalation.",
                },
            ]
        ),
        "asset_registry_json": json.dumps(
            [
                {"label": "Asset ID", "value": "AST-TRANSPORT-00089"},
                {
                    "label": "Hostname",
                    "value": "per-PRD-CITRIX-ADC01.transport.wa.gov.au",
                },
                {
                    "label": "IP Address",
                    "value": "10.61.5.2 (NSIP) / 10.61.5.3 (SNIP) / 203.22.xxx.xxx (VIP external)",
                },
                {
                    "label": "Operating System",
                    "value": "Citrix NetScaler ADC VPX 13.1-49.13 (FreeBSD-based)",
                },
                {
                    "label": "Role",
                    "value": "Perimeter Remote Access Gateway — Department of Transport",
                },
                {
                    "label": "Business Owner",
                    "value": "Department of Transport — ICT Services",
                },
                {
                    "label": "Technical Owner",
                    "value": "Transport ICT — Networks and Security Team",
                },
                {
                    "label": "Data Classification",
                    "value": "OFFICIAL Sensitive — Sensitive (Protective Security) — WAICP classification",
                },
                {
                    "label": "Mission Prevalence",
                    "value": "Core (predicted — multi-label classifier, confidence 0.91)",
                },
                {
                    "label": "Public Well-Being Impact",
                    "value": "Moderate (predicted — multi-label classifier, confidence 0.88)",
                },
                {"label": "Network Zone", "value": "DMZ-Transport-External"},
                {
                    "label": "Patch Cycle",
                    "value": "Ad-hoc (appliance updates applied during scheduled maintenance windows)",
                },
                {"label": "Last Patch Date", "value": "15 March 2026"},
                {
                    "label": "Registered Applications",
                    "value": "Citrix Gateway (VPN virtual server), Citrix Load Balancer (TEMIS backend), Citrix Content Switching (DVS Online)",
                },
                {
                    "label": "Dependent Assets",
                    "value": "per-PRD-TEMIS-APP01.transport.wa.gov.au, per-PRD-DVS-WEB01.transport.wa.gov.au, per-PRD-MARINE-DOC01.transport.wa.gov.au (+ 19 other published application targets)",
                },
                {
                    "label": "Interface Type",
                    "value": "Internet-facing HTTPS (external VIP on port 443)",
                },
                {"label": "Last Vulnerability Scan", "value": "28 June 2026"},
            ]
        ),
        "summary_paragraphs_json": json.dumps(
            [
                "This case concerns an improper handling of session tokens in Citrix NetScaler ADC and NetScaler Gateway, known as Citrix Bleed, tracked as CVE-2023-4966. The vulnerability was identified on the host per-PRD-CITRIX-ADC01.transport.wa.gov.au. The flaw allows an unauthenticated attacker to extract valid session tokens from the appliance memory by sending a crafted HTTP request, without requiring any credentials or user interaction.",
                "The multi-label classifier assessed this asset as having a Mission Prevalence of Core and a Public Well-Being Impact of Moderate, reflecting its role as the primary remote access gateway for the Department of Transport.",
                "The appliance serves as the primary remote access gateway for the Department of Transport, providing secure access to the Transport Executive Management Information System, the Driver and Vehicle Services Online platform backend, and the Marine Safety document repository. The Citrix NetScaler ADC is directly exposed to the internet on TCP port 443.",
            ]
        ),
        "telemetry_json": '{"sentinel_incidents": [{"incident_id": "SEN-2024-595124", "title": "Suspected exploitation of CVE-2023-4966", "severity": "High", "status": "Active", "detected_at": "2024-07-14T14:45:40Z", "assigned_to": "SOC Tier 2", "related_entities": ["per-PRD-CITRIX-ADC01.transport.wa.gov.au"], "mitre_techniques": ["T1078"]}, {"incident_id": "SEN-2025-956201", "title": "Suspected exploitation of CVE-2023-4966", "severity": "Low", "status": "Investigating", "detected_at": "2025-01-05T13:42:15Z", "assigned_to": "SOC Tier 1", "related_entities": ["per-PRD-CITRIX-ADC01.transport.wa.gov.au"], "mitre_techniques": ["T1133", "T1078", "T1505"]}], "edr_alerts": [{"alert_id": "EDR-20240217-3383", "alert_type": "process_execution", "severity": "Medium", "process_name": "buffer.exe", "process_path": "C:\\\\Program Files\\\\Buffer\\\\buffer.exe", "user": "IIS APPPOOL\\\\DefaultAppPool", "timestamp": "2024-05-14T09:48:47Z", "details": "Suspicious process execution of buffer.exe related to CVE-2023-4966"}], "process_evidence": {"is_running": true, "is_loaded": true, "running_processes": ["buffer.exe", "buffer_module.dll"], "evidence_quality": "high"}, "threat_score": 1.0}',
        "network_context_json": '{"zone": "dmz", "zone_display": "DMZ (Transport \\u2014 External)", "peer_count": 26, "internet_facing_peers": 16, "dc_peers": 0, "peer_classifications": {"Core": 14, "Support": 7, "Peripheral": 5}, "blast_radius_score": 0.4376923076923077, "exposure_level": "medium", "data_source": "synthetic_assets"}',
        "pre_tier_features": None,
        "epss_features": None,
    },
    # Row 3: CVE-2023-27350 — PaperCut Auth Bypass
    {
        "vulnerability_id": "CVE-2023-27350",
        "hostname": "per-PRD-PRINT-SVR05.education.wa.edu.au",
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cisa_kev": True,
        "epss_score": 0.912,
        "mission_prevalence": "Support",
        "mission_prevalence_conf": 0.85,
        "public_wellbeing_impact": "Minimal",
        "public_wellbeing_conf": 0.82,
        "tier_0_routing": "escalated",
        "tier_0_resolution": "ambiguous",
        "tier_1_confidence": 0.91,
        "tier_1_exploitation_prob": 0.83,
        "tier_1_routing": "auto_resolved",
        "tier_2_text_conflict": False,
        "tier_2_conflict_note": None,
        "tier_2_rag_result": None,
        "tier_2_confidence": None,
        "tier_2_resolution_summary": None,
        "priority_score": 74,
        "risk_band": "Critical",
        "cvss_contribution": 39,
        "epss_contribution": 18,
        "asset_criticality_contribution": 6,
        "exposure_contribution": 3,
        "patch_remediation_contribution": 0,
        "ml_exploitation_contribution": 8,
        "security_context_contribution": 0,
        "epss_substituted": False,
        "epss_substituted_value": None,
        "epss_substitution_confidence": None,
        "epss_substitution_reason": None,
        "data_classification": "OFFICIAL",
        "network_zone": "EDU-Internal-Servers (VLAN 215)",
        "interface_type": "Internal network only (TCP 9191, TCP 9192, TCP 9164)",
        "patch_cycle": "Monthly (third Saturday, 2200-0400 AWST)",
        "last_patch_date": "20 June 2026",
        "last_scan_date": "27 June 2026",
        "operating_system": "Windows Server 2022 Standard (build 20348)",
        "role": "Centralised Print Management Server — Department of Education (North Metropolitan Education Region)",
        "business_owner": "Department of Education — ICT Services and Infrastructure",
        "technical_owner": "Education ICT — End User Computing Team",
        "registered_applications": "PaperCut MF 22.0.6, Microsoft Print Server role, PaperCut Mobility Print",
        "dependent_assets": "28 managed printers across 14 school campuses, per-PRD-FILE-PRINT01.education.wa.edu.au (print queue storage)",
        "service_account": "DOMAIN_EDU\\svc-papercut-prd (member of local Administrators group)",
        "detection_tier": "ML Tier",
        "detection_reason": "ML Tier: CVSS 9.8 baseline tempered by network position but elevated by tabular feature combination. Domain-joined print server, privileged service account context, lateral movement reachability to 28 student record endpoints. ML confidence 0.91.",
        "scanner_output_raw": "[HIGH] CVE-2023-27350 — PaperCut NG/MF Authentication Bypass and Remote Code Execution\nHost: per-PRD-PRINT-SVR05.education.wa.edu.au (10.82.15.44)\nPort: 9191/tcp (HTTP — PaperCut Application Server)\nService: PaperCut MF 22.0.6 (build 63912)\nDetection Method: HTTP response header + /app?service=page/About version disclosure\nCVSS v3.1: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)\nCISA KEV: TRUE (added 24 April 2023)\nEPSS Score: 0.912 (91st percentile)\nExploit Maturity: High (public PoC available, observed in ransomware affiliate playbooks)\nPatch Available: Yes (PaperCut MF 22.0.7 and later)\nPatch Applied: No\nAuthentication Context: PaperCut service runs as DOMAIN_EDU\\svc-papercut-prd (domain user, member of local Administrators group)",
        "weakness_template_raw": 'template_id: ML-2023-PAPERCUT-LAT-001\ntemplate_name: "PaperCut Auth Bypass — Lateral Movement Amplification Model"\nmodel_type: Gradient Boosted Decision Tree\ntraining_cutoff: 2024-12-31\nfeature_vector:\n  - feature: "cvss_base_score"\n    value: 9.8\n    weight_contribution: 0.18\n  - feature: "epss_score"\n    value: 0.912\n    weight_contribution: 0.12\n  - feature: "domain_joined"\n    value: TRUE\n    weight_contribution: 0.20\n  - feature: "service_account_privilege_level"\n    value: "local_administrator"\n    weight_contribution: 0.18\n  - feature: "lateral_movement_reachability_count"\n    value: 28\n    weight_contribution: 0.22\n  - feature: "internet_facing"\n    value: FALSE\n    weight_contribution: -0.05\n  - feature: "data_classification_level"\n    value: "OFFICIAL"\n    weight_contribution: 0.05\nmodel_confidence: 0.91',
        "advisory_ref_id": "ADV-CVE-2023-27350",
        "advisory_quote": "The Western Australian Security Operations Centre advises that CVE-2023-27350 affecting PaperCut NG and MF has been observed in active exploitation by multiple threat actor groups, including those affiliated with ransomware operations. Education sector organisations have been disproportionately targeted.",
        "investigation_notes": "The following summary has been pre-filled for analyst review and editing.\n\nCVE-2023-27350 on per-PRD-PRINT-SVR05.education.wa.edu.au has been assigned a priority score of 74 and a risk band of Critical by the ML Tier model. The model received a CVSS 9.8 baseline but tempered the initial priority due to the internal-only network position and the multi-label classifier's Support mission tag.\n\nImmediate recommended action: Upgrade PaperCut MF from version 22.0.6 to version 22.0.7 or later.",
        "mitre_techniques_json": json.dumps(
            [
                {
                    "id": "T1210",
                    "name": "Exploitation of Remote Services",
                    "desc": "An attacker who has gained initial access to the education network can exploit the PaperCut authentication bypass to move laterally to the print server.",
                },
                {
                    "id": "T1543.003",
                    "name": "Create or Modify System Process: Windows Service",
                    "desc": "Post-exploitation, the PaperCut service account can be used to create or modify Windows services on the print server.",
                },
                {
                    "id": "T1003.001",
                    "name": "OS Credential Dumping: LSASS Memory",
                    "desc": "With local administrator privileges, an attacker can dump credentials from LSASS memory on the print server.",
                },
            ]
        ),
        "scoring_weights_json": json.dumps(
            [
                {
                    "name": "CVSS Base Score Contribution",
                    "awarded": 39,
                    "max": 40,
                    "justification": "The CVSS score of 9.8 reflects near-maximum severity, but the score is tempered because the attack vector requires network adjacency despite the high base score.",
                },
                {
                    "name": "EPSS Exploitability Contribution",
                    "awarded": 18,
                    "max": 20,
                    "justification": "The EPSS score of 0.912 confirms active exploitation, and the education sector is specifically targeted.",
                },
                {
                    "name": "Asset Criticality Contribution",
                    "awarded": 6,
                    "max": 20,
                    "justification": "This is a OFFICIAL asset with a Mission Prevalence of Support and a Public Well-Being Impact of Minimal.",
                },
                {
                    "name": "Exposure and Network Position",
                    "awarded": 3,
                    "max": 12,
                    "justification": "The asset is internal network only, but flat architecture in education environments increases effective exposure. The 28 reachable endpoints amplify lateral movement risk.",
                },
                {
                    "name": "Patch Availability and Remediation Complexity",
                    "awarded": 0,
                    "max": 5,
                    "justification": "A patch has been available but not yet applied. No remediation credit is awarded when a patch is available and overdue.",
                },
                {
                    "name": "ML Exploitation Probability Contribution",
                    "awarded": 8,
                    "max": 10,
                    "justification": "XGBoost model predicted 0.83 exploitation probability with 0.91 confidence.",
                },
                {
                    "name": "Context Multiplier",
                    "awarded": 1.0,
                    "max": 1.2,
                    "justification": "1.00x multiplier (neutral) — telemetry threat score (0.527) below active threat threshold and vulnerable code_loaded=False.",
                },
            ]
        ),
        "asset_registry_json": json.dumps(
            [
                {"label": "Asset ID", "value": "AST-EDU-00236"},
                {
                    "label": "Hostname",
                    "value": "per-PRD-PRINT-SVR05.education.wa.edu.au",
                },
                {"label": "IP Address", "value": "10.82.15.44"},
                {
                    "label": "Operating System",
                    "value": "Windows Server 2022 Standard (build 20348)",
                },
                {
                    "label": "Role",
                    "value": "Centralised Print Management Server — Department of Education (North Metropolitan Education Region)",
                },
                {
                    "label": "Business Owner",
                    "value": "Department of Education — ICT Services and Infrastructure",
                },
                {
                    "label": "Technical Owner",
                    "value": "Education ICT — End User Computing Team",
                },
                {
                    "label": "Data Classification",
                    "value": "OFFICIAL — Sensitive (Personal) — WAICP classification",
                },
                {
                    "label": "Mission Prevalence",
                    "value": "Support (predicted — multi-label classifier, confidence 0.85)",
                },
                {
                    "label": "Public Well-Being Impact",
                    "value": "Minimal (predicted — multi-label classifier, confidence 0.82)",
                },
                {"label": "Network Zone", "value": "EDU-Internal-Servers (VLAN 215)"},
                {
                    "label": "Patch Cycle",
                    "value": "Monthly (third Saturday, 2200-0400 AWST)",
                },
                {"label": "Last Patch Date", "value": "20 June 2026"},
                {
                    "label": "Registered Applications",
                    "value": "PaperCut MF 22.0.6, Microsoft Print Server role, PaperCut Mobility Print",
                },
                {
                    "label": "Dependent Assets",
                    "value": "28 managed printers across 14 school campuses, per-PRD-FILE-PRINT01.education.wa.gov.au (print queue storage)",
                },
                {
                    "label": "Service Account",
                    "value": "DOMAIN_EDU\\svc-papercut-prd (member of local Administrators group on per-PRD-PRINT-SVR05)",
                },
                {
                    "label": "Interface Type",
                    "value": "Internal network only (TCP 9191, TCP 9192, TCP 9164)",
                },
                {"label": "Last Vulnerability Scan", "value": "27 June 2026"},
            ]
        ),
        "summary_paragraphs_json": json.dumps(
            [
                "This case concerns an authentication bypass vulnerability in PaperCut NG and PaperCut MF print management software, tracked as CVE-2023-27350, identified on the host per-PRD-PRINT-SVR05.education.wa.edu.au. The vulnerability permits an unauthenticated remote attacker to bypass the PaperCut login mechanism and execute arbitrary code under the context of the PaperCut application service account.",
                "The multi-label classifier assessed this asset as having a Mission Prevalence of Support and a Public Well-Being Impact of Minimal, reflecting its role as a centralised print management server.",
                "The PaperCut server is deployed on a Windows Server domain-joined host within the Department of Education internal network. The ML Tier model evaluated this vulnerability with its baseline CVSS of 9.8 and tempered the priority due to the internal-only network position.",
            ]
        ),
        "telemetry_json": '{"sentinel_incidents": [{"incident_id": "SEN-2026-367763", "title": "Suspected exploitation of CVE-2023-27350", "severity": "High", "status": "Investigating", "detected_at": "2024-09-06T09:38:40Z", "assigned_to": "SOC Tier 2", "related_entities": ["per-PRD-PRINT-SVR05.education.wa.edu.au"], "mitre_techniques": ["T1210"]}, {"incident_id": "SEN-2024-149977", "title": "Suspected exploitation of CVE-2023-27350", "severity": "High", "status": "Resolved", "detected_at": "2024-06-19T09:37:41Z", "assigned_to": "SOC Tier 2", "related_entities": ["per-PRD-PRINT-SVR05.education.wa.edu.au"], "mitre_techniques": ["T1505"]}], "edr_alerts": [{"alert_id": "EDR-20240815-2399", "alert_type": "network_connection", "severity": "Low", "process_name": "authentication.exe", "process_path": "C:\\\\Program Files\\\\Authentication\\\\authentication.exe", "user": "NT AUTHORITY\\\\SYSTEM", "timestamp": "2024-10-30T19:18:09Z", "details": "Outbound connection from authentication.exe to external IP address"}], "process_evidence": {"is_running": false, "is_loaded": false, "running_processes": [], "evidence_quality": "none"}, "threat_score": 0.5272328451376124}',
        "network_context_json": '{"zone": "internal", "zone_display": "EDU (Internal \\u2014 Servers)", "peer_count": 87, "internet_facing_peers": 0, "dc_peers": 6, "peer_classifications": {"Core": 25, "Support": 44, "Peripheral": 18}, "blast_radius_score": 0.435, "exposure_level": "medium", "data_source": "synthetic_assets"}',
        "pre_tier_features": None,
        "epss_features": None,
    },
    # Row 4: CVE-2024-1709 — ConnectWise ScreenConnect
    {
        "vulnerability_id": "CVE-2024-1709",
        "hostname": "per-PRD-RMM-GW01.sharedservices.wa.gov.au",
        "cvss_score": 10.0,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cisa_kev": True,
        "epss_score": 0.878,
        "mission_prevalence": "Support",
        "mission_prevalence_conf": 0.87,
        "public_wellbeing_impact": "Moderate",
        "public_wellbeing_conf": 0.84,
        "tier_0_routing": "escalated",
        "tier_0_resolution": "ambiguous",
        "tier_1_confidence": 0.83,
        "tier_1_exploitation_prob": 0.71,
        "tier_1_routing": "auto_resolved",
        "tier_2_text_conflict": False,
        "tier_2_conflict_note": None,
        "tier_2_rag_result": None,
        "tier_2_confidence": None,
        "tier_2_resolution_summary": None,
        "priority_score": 91,
        "risk_band": "Very Critical",
        "cvss_contribution": 40,
        "epss_contribution": 18,
        "asset_criticality_contribution": 15,
        "exposure_contribution": 3,
        "patch_remediation_contribution": 0,
        "ml_exploitation_contribution": 7,
        "security_context_contribution": 0,
        "epss_substituted": False,
        "epss_substituted_value": None,
        "epss_substitution_confidence": None,
        "epss_substitution_reason": None,
        "data_classification": "OFFICIAL Sensitive",
        "network_zone": "SSC-Management-Segment (VLAN 48)",
        "interface_type": "Internal network only (TCP 8040 for web interface, TCP 8041 for relay)",
        "patch_cycle": "Monthly (first Sunday, 0100-0600 AWST)",
        "last_patch_date": "7 June 2026",
        "last_scan_date": "28 June 2026",
        "operating_system": "Windows Server 2022 Standard (build 20348)",
        "role": "Remote Monitoring and Management Gateway — WA Shared Services Centre",
        "business_owner": "Department of Finance — Shared Services ICT",
        "technical_owner": "Shared Services Centre — Endpoint Management Team",
        "registered_applications": "ConnectWise ScreenConnect 23.9.7.8804, Microsoft SQL Server 2022 Express (local instance for ScreenConnect database)",
        "dependent_assets": "14 managed endpoints across DLGSC (4 hosts), DWER (3 hosts), DPLH (4 hosts), Department of Finance internal (2 hosts), DBCA (1 host)",
        "service_account": "SSC-MGMT\\svc-screenconnect (domain service account)",
        "detection_tier": "ML Tier",
        "detection_reason": "ML Tier: CVSS 10.0 tempered by isolated network segment, but ML model elevated score due to RMM tool bridging 14 downstream agency hosts. Tabular feature flag: cross-boundary reachability score 0.78. ML confidence 0.83.",
        "scanner_output_raw": "[HIGH] CVE-2024-1709 — ConnectWise ScreenConnect Authentication Bypass\nHost: per-PRD-RMM-GW01.sharedservices.wa.gov.au (10.120.8.17)\nPort: 8040/tcp (HTTPS — ScreenConnect Web Interface)\nService: ConnectWise ScreenConnect 23.9.7.8804\nDetection Method: HTTP response header Server field + /SetupWizard.aspx accessible without authentication\nCVSS v3.1: 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)\nCISA KEV: TRUE (added 20 February 2024)\nEPSS Score: 0.878 (87th percentile)\nExploit Maturity: High (public PoC available within 48 hours of disclosure)\nPatch Available: Yes (ScreenConnect 23.9.8 and later)\nPatch Applied: No\nCross-Boundary Reachability: 14 downstream agency endpoints across 5 network zones",
        "weakness_template_raw": 'template_id: ML-2024-SCREENCONNECT-CBR-001\ntemplate_name: "RMM Gateway Compromise — Cross-Boundary Lateral Movement Amplifier"\nmodel_type: XGBoost Reciprocal Rank Fusion (RRF) Ensemble\ntraining_cutoff: 2025-06-30\nfeature_vector:\n  - feature: "cvss_base_score"\n    value: 10.0\n    weight_contribution: 0.15\n  - feature: "epss_score"\n    value: 0.878\n    weight_contribution: 0.12\n  - feature: "software_category"\n    value: "remote_monitoring_and_management"\n    weight_contribution: 0.18\n  - feature: "cross_boundary_reachability_count"\n    value: 14\n    weight_contribution: 0.25\n  - feature: "downstream_network_zone_diversity"\n    value: 5\n    weight_contribution: 0.18\n  - feature: "inbound_network_restriction"\n    value: TRUE\n    weight_contribution: -0.10\n  - feature: "data_classification_level"\n    value: "OFFICIAL_Sensitive"\n    weight_contribution: 0.07\nmodel_confidence: 0.83',
        "advisory_ref_id": "ADV-CVE-2024-1709",
        "advisory_quote": "The Western Australian Security Operations Centre has assessed CVE-2024-1709 as a high-severity threat to WA government entities using ConnectWise ScreenConnect for remote management. Of particular concern is the risk posed to shared services providers who manage endpoints across multiple agencies.",
        "investigation_notes": "The following summary has been pre-filled for analyst review and editing.\n\nCVE-2024-1709 on per-PRD-RMM-GW01.sharedservices.wa.gov.au has been assigned a priority score of 91 and a risk band of Very Critical by the ML Tier model.\n\nImmediate recommended action: Upgrade ConnectWise ScreenConnect from version 23.9.7.8804 to version 23.9.8 or later. Pending upgrade, temporarily restrict all inbound connections to port 8040.",
        "mitre_techniques_json": json.dumps(
            [
                {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "desc": "The initial access vector is exploitation of the ScreenConnect authentication bypass vulnerability on the RMM gateway web interface.",
                },
                {
                    "id": "T1021.001",
                    "name": "Remote Desktop Protocol",
                    "desc": "Once administrative control of the ScreenConnect server is achieved, the attacker can use the built-in ScreenConnect remote desktop functionality to access any managed endpoint.",
                },
                {
                    "id": "T1219",
                    "name": "Remote Access Software",
                    "desc": "The ScreenConnect platform itself is a legitimate remote access software tool. Post-compromise, the attacker leverages this existing trusted remote access channel to maintain persistence.",
                },
            ]
        ),
        "scoring_weights_json": json.dumps(
            [
                {
                    "name": "CVSS Base Score Contribution",
                    "awarded": 40,
                    "max": 40,
                    "justification": "The CVSS score of 10.0 reflects maximum severity, but the network restrictions reduce the effective attack surface.",
                },
                {
                    "name": "EPSS Exploitability Contribution",
                    "awarded": 18,
                    "max": 20,
                    "justification": "The EPSS score of 0.878 confirms a high probability of exploitation, and a public proof of concept is available.",
                },
                {
                    "name": "Asset Criticality Contribution",
                    "awarded": 15,
                    "max": 20,
                    "justification": "OFFICIAL Sensitive classification with a Mission Prevalence of Support and a Public Well-Being Impact of Moderate.",
                },
                {
                    "name": "Exposure and Network Position",
                    "awarded": 3,
                    "max": 12,
                    "justification": "The asset resides in an isolated management network with restricted inbound access.",
                },
                {
                    "name": "Patch Availability and Remediation Complexity",
                    "awarded": 0,
                    "max": 5,
                    "justification": "A patch has been available for 7 days. The upgrade requires coordination with 14 downstream agencies.",
                },
                {
                    "name": "ML Exploitation Probability Contribution",
                    "awarded": 7,
                    "max": 10,
                    "justification": "XGBoost model predicted 0.71 exploitation probability with 0.83 confidence.",
                },
                {
                    "name": "Context Multiplier",
                    "awarded": 1.1,
                    "max": 1.2,
                    "justification": "1.10x multiplier applied — vulnerable code_loaded=True enables partial evidence escalation despite isolated management segment.",
                },
            ]
        ),
        "asset_registry_json": json.dumps(
            [
                {"label": "Asset ID", "value": "AST-SSC-00041"},
                {
                    "label": "Hostname",
                    "value": "per-PRD-RMM-GW01.sharedservices.wa.gov.au",
                },
                {"label": "IP Address", "value": "10.120.8.17"},
                {
                    "label": "Operating System",
                    "value": "Windows Server 2022 Standard (build 20348)",
                },
                {
                    "label": "Role",
                    "value": "Remote Monitoring and Management Gateway — WA Shared Services Centre",
                },
                {
                    "label": "Business Owner",
                    "value": "Department of Finance — Shared Services ICT",
                },
                {
                    "label": "Technical Owner",
                    "value": "Shared Services Centre — Endpoint Management Team",
                },
                {
                    "label": "Data Classification",
                    "value": "OFFICIAL Sensitive — Sensitive (Protective Security) — WAICP classification",
                },
                {
                    "label": "Mission Prevalence",
                    "value": "Support (predicted — multi-label classifier, confidence 0.87)",
                },
                {
                    "label": "Public Well-Being Impact",
                    "value": "Moderate (predicted — multi-label classifier, confidence 0.84)",
                },
                {"label": "Network Zone", "value": "SSC-Management-Segment (VLAN 48)"},
                {
                    "label": "Patch Cycle",
                    "value": "Monthly (first Sunday, 0100-0600 AWST)",
                },
                {"label": "Last Patch Date", "value": "7 June 2026"},
                {
                    "label": "Registered Applications",
                    "value": "ConnectWise ScreenConnect 23.9.7.8804, Microsoft SQL Server 2022 Express",
                },
                {
                    "label": "Dependent Assets",
                    "value": "14 managed endpoints across DLGSC, DWER, DPLH, Finance, DBCA",
                },
                {
                    "label": "Service Account",
                    "value": "SSC-MGMT\\svc-screenconnect (domain service account)",
                },
                {
                    "label": "Interface Type",
                    "value": "Internal network only (TCP 8040 for web interface, TCP 8041 for relay)",
                },
                {"label": "Last Vulnerability Scan", "value": "28 June 2026"},
            ]
        ),
        "summary_paragraphs_json": json.dumps(
            [
                "This case concerns an authentication bypass vulnerability in ConnectWise ScreenConnect, tracked as CVE-2024-1709, identified on the host per-PRD-RMM-GW01.sharedservices.wa.gov.au. ScreenConnect is a remote monitoring and management tool used by the WA Shared Services Centre.",
                "The multi-label classifier assessed this asset as having a Mission Prevalence of Support and a Public Well-Being Impact of Moderate, reflecting its role as a back-end IT management tool.",
                "The vulnerability carries a CVSS score of 10.0 and allows an unauthenticated attacker to bypass the ScreenConnect login page and gain administrative access to the ScreenConnect server.",
            ]
        ),
        "telemetry_json": '{"sentinel_incidents": [{"incident_id": "SEN-2024-703160", "title": "Suspected exploitation of CVE-2024-1709", "severity": "High", "status": "Investigating", "detected_at": "2024-04-10T06:53:24Z", "assigned_to": "SOC Tier 2", "related_entities": ["per-PRD-RMM-GW01.sharedservices.wa.gov.au"], "mitre_techniques": ["T1027"]}, {"incident_id": "SEN-2025-299323", "title": "Suspected exploitation of CVE-2024-1709", "severity": "High", "status": "Investigating", "detected_at": "2024-05-23T23:23:38Z", "assigned_to": "SOC Tier 2", "related_entities": ["per-PRD-RMM-GW01.sharedservices.wa.gov.au"], "mitre_techniques": ["T1078"]}], "edr_alerts": [{"alert_id": "EDR-20241018-5013", "alert_type": "process_execution", "severity": "High", "process_name": "authentication.exe", "process_path": "C:\\\\Program Files\\\\Authentication\\\\authentication.exe", "user": "IIS APPPOOL\\\\DefaultAppPool", "timestamp": "2024-04-12T16:09:43Z", "details": "Suspicious process execution of authentication.exe related to CVE-2024-1709"}, {"alert_id": "EDR-20241018-4296", "alert_type": "module_load", "severity": "Medium", "process_name": "authentication_module.dll", "process_path": "C:\\\\Program Files\\\\Authentication\\\\authentication_module.dll", "user": "IIS APPPOOL\\\\DefaultAppPool", "timestamp": "2024-08-09T07:48:02Z", "details": "Suspicious module load of authentication_module.dll in authentication.exe"}], "process_evidence": {"is_running": true, "is_loaded": true, "running_processes": ["authentication.exe", "authentication_module.dll"], "evidence_quality": "high"}, "threat_score": 0.9646478630016387}',
        "network_context_json": '{"zone": "mgmt", "zone_display": "SSC (Management \\u2014 Segment)", "peer_count": 7, "internet_facing_peers": 0, "dc_peers": 0, "peer_classifications": {"Core": 2, "Peripheral": 2, "Support": 3}, "blast_radius_score": 0.035, "exposure_level": "low", "data_source": "synthetic_assets"}',
        "pre_tier_features": None,
        "epss_features": None,
    },
    # Row 5: CVE-2023-36884 — Office/Windows Search RCE
    {
        "vulnerability_id": "CVE-2023-36884",
        "hostname": "per-PRD-FILE-STORE02.communities.wa.gov.au",
        "cvss_score": 7.8,
        "cvss_vector": "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "cisa_kev": True,
        "epss_score": 0.065,
        "mission_prevalence": "Core",
        "mission_prevalence_conf": 0.92,
        "public_wellbeing_impact": "Severe",
        "public_wellbeing_conf": 0.95,
        "tier_0_routing": "escalated",
        "tier_0_resolution": "ambiguous",
        "tier_1_confidence": 0.76,
        "tier_1_exploitation_prob": 0.65,
        "tier_1_routing": "escalated",
        "tier_2_text_conflict": True,
        "tier_2_conflict_note": "Primary exploitability assessment: Active exploitation confirmed, weaponised in spear-phishing targeting government social services. Negative constraint: Microsoft advisory states registry key mitigation blocks attack vector. RAG search returned conflicting GPO deployment records — ASR rule may or may not be active on this endpoint.",
        "tier_2_rag_result": "UNCERTAIN — CMDB records conflict",
        "tier_2_confidence": 0.72,
        "tier_2_resolution_summary": "Exploitability signal dominates. Mitigation status unverifiable. Assign score 55 — Critical band. Flag for manual ASR verification.",
        "priority_score": 82,
        "risk_band": "Very Critical",
        "cvss_contribution": 31,
        "epss_contribution": 14,
        "asset_criticality_contribution": 20,
        "exposure_contribution": 3,
        "patch_remediation_contribution": 0,
        "ml_exploitation_contribution": 7,
        "security_context_contribution": 0,
        "epss_substituted": True,
        "epss_substituted_value": 0.72,
        "epss_substitution_confidence": 0.79,
        "epss_substitution_reason": "The EPSS score of 0.065 is deemed non-representative for sector-specific targeting patterns. An internal ML prediction of 0.72 has been substituted based on sector-specific targeting data from the WASOC threat intelligence feed and confirmed exploitation patterns against Australian state government social services entities.",
        "data_classification": "OFFICIAL Sensitive",
        "network_zone": "Communities-Internal-Servers (VLAN 312)",
        "interface_type": "Internal network only (SMB TCP 445, RPC dynamic ports)",
        "patch_cycle": "Monthly (second Saturday, 2200-0400 AWST)",
        "last_patch_date": "20 June 2026",
        "last_scan_date": "28 June 2026",
        "operating_system": "Windows Server 2019 Standard (build 17763)",
        "role": "Departmental File Storage Server — Child Protection and Family Services Division",
        "business_owner": "Department of Communities — Child Protection and Family Support",
        "technical_owner": "Communities ICT — Infrastructure and Operations",
        "registered_applications": "Microsoft Office 365 Apps for Enterprise, Windows File Server role, Microsoft Defender for Endpoint",
        "dependent_assets": "per-PRD-CASEMGT-APP01.communities.wa.gov.au, per-PRD-CASEMGT-DB01.communities.wa.gov.au, 42 caseworker workstations",
        "service_account": "Local System",
        "detection_tier": "SLM Tier",
        "detection_reason": "SLM Tier: Text conflict detected. Public exploit code available and actively weaponised in malicious Office documents (high exploitability). Negative constraint: Microsoft mitigation via registry key exists and attack requires user interaction. RAG search unable to confirm ASR rule deployment status on this endpoint.",
        "scanner_output_raw": "[HIGH] CVE-2023-36884 — Microsoft Office/Windows Search Remote Code Execution\nHost: per-PRD-FILE-STORE02.communities.wa.gov.au (10.94.33.7)\nPort: 445/tcp (SMB — File Sharing)\nService: Microsoft Windows Server 2019 Standard (build 17763)\nDetection Method: Windows OS build enumeration via SMB dialect negotiation + registry artefact indicating Office 365 Apps for Enterprise installed\nCVSS v3.1: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)\nCISA KEV: TRUE (added 11 July 2023)\nEPSS Score: 0.065 (83rd percentile)\nExploit Maturity: High (public exploit code, actively weaponised in spear-phishing campaigns)\nPatch Available: Yes (Microsoft security updates for July 2023 and later; also registry key mitigation available)\nPatch Applied: OS patches current to June 2026; Office patch level uncertain\nMitigation Status: ASR rule blocks Office applications — CMDB reports conflicting GPO application status for this host",
        "weakness_template_raw": 'template_id: SLM-2023-OFFICE-SRCH-001\ntemplate_name: "Office URI Protocol RCE — User Interaction vs Government Targeting Conflict Resolver"\nmodel_type: Small Language Model (SLM) — Textual Conflict Resolution\ninput_documents:\n  - document_type: "exploitability_assessment"\n    source: "WASOC Threat Intelligence Feed + CISA KEV"\n    key_text: "Active exploitation confirmed. Malicious Office documents targeting government social services agencies."\n    sentiment: HIGH_RISK\n  - document_type: "negative_constraint"\n    source: "Microsoft Security Response Center Advisory"\n    key_text: "Customers who apply the registry key mitigation are protected. The attack requires user interaction."\n    sentiment: RISK_MITIGATED\n  - document_type: "rag_retrieval_result"\n    source: "Internal CMDB + Group Policy Management Console"\n    key_text: "CMDB record 2026-03-07: GPO replication failure. UNCERTAIN."\n    sentiment: UNCERTAIN',
        "advisory_ref_id": "ADV-CVE-2023-36884",
        "advisory_quote": "The Western Australian Security Operations Centre has confirmed that CVE-2023-36884 is being actively exploited in targeted spear-phishing campaigns against Australian state government social services agencies. Attackers are sending malicious Office documents themed around child protection case updates.",
        "investigation_notes": "The following summary has been pre-filled for analyst review and editing.\n\nCVE-2023-36884 on per-PRD-FILE-STORE02.communities.wa.gov.au has been assigned a priority score of 82 and a risk band of Very Critical by the SLM Tier engine. This case was escalated to the SLM due to a text conflict between the exploitability assessment and the negative constraint.\n\nImmediate recommended action: Manually verify the status of the Microsoft Defender ASR rule on per-PRD-FILE-STORE02.",
        "mitre_techniques_json": json.dumps(
            [
                {
                    "id": "T1566.001",
                    "name": "Spearphishing Attachment",
                    "desc": "The most common delivery mechanism is a spear-phishing email containing a malicious Office document attachment targeting government social services personnel.",
                },
                {
                    "id": "T1203",
                    "name": "Exploitation for Client Execution",
                    "desc": "The vulnerability is triggered when the victim opens the malicious Office document.",
                },
                {
                    "id": "T1059.001",
                    "name": "Command and Scripting Interpreter: PowerShell",
                    "desc": "Post-exploitation, attackers use PowerShell to download additional payloads and move laterally.",
                },
            ]
        ),
        "scoring_weights_json": json.dumps(
            [
                {
                    "name": "CVSS Base Score Contribution",
                    "awarded": 31,
                    "max": 40,
                    "justification": "The CVSS score of 7.8 is reduced due to the local attack vector and user interaction requirement.",
                },
                {
                    "name": "EPSS Exploitability Contribution",
                    "awarded": 14,
                    "max": 20,
                    "justification": "The raw EPSS score of 0.065 has been substituted with an internal ML prediction of 0.72 due to sector-specific targeting evidence.",
                    "is_substituted": True,
                },
                {
                    "name": "Asset Criticality Contribution",
                    "awarded": 20,
                    "max": 20,
                    "justification": "OFFICIAL Sensitive asset with Core mission and Severe public impact. File server hosts child protection case management data.",
                },
                {
                    "name": "Exposure and Network Position",
                    "awarded": 3,
                    "max": 12,
                    "justification": "Internal file server. User interaction required, but users routinely open external documents.",
                },
                {
                    "name": "Patch Availability and Remediation Complexity",
                    "awarded": 0,
                    "max": 5,
                    "justification": "Both a patch and registry mitigation are available, but ASR rule deployment status remains unconfirmed. No remediation credit is awarded when patch is available but not verified as applied.",
                },
                {
                    "name": "ML Exploitation Probability Contribution",
                    "awarded": 7,
                    "max": 10,
                    "justification": "XGBoost model predicted 0.65 exploitation probability with 0.76 confidence.",
                },
                {
                    "name": "Context Multiplier",
                    "awarded": 1.1,
                    "max": 1.2,
                    "justification": "1.10x multiplier applied — vulnerable code_loaded=True with moderate telemetry (0.724) enables partial evidence escalation.",
                },
            ]
        ),
        "asset_registry_json": json.dumps(
            [
                {"label": "Asset ID", "value": "AST-COMM-00158"},
                {
                    "label": "Hostname",
                    "value": "per-PRD-FILE-STORE02.communities.wa.gov.au",
                },
                {"label": "IP Address", "value": "10.94.33.7"},
                {
                    "label": "Operating System",
                    "value": "Windows Server 2019 Standard (build 17763)",
                },
                {
                    "label": "Role",
                    "value": "Departmental File Storage Server — Child Protection and Family Services Division",
                },
                {
                    "label": "Business Owner",
                    "value": "Department of Communities — Child Protection and Family Support",
                },
                {
                    "label": "Technical Owner",
                    "value": "Communities ICT — Infrastructure and Operations",
                },
                {
                    "label": "Data Classification",
                    "value": "OFFICIAL Sensitive — Sensitive (Health and Legal) — WAICP classification",
                },
                {
                    "label": "Mission Prevalence",
                    "value": "Core (predicted — multi-label classifier, confidence 0.92)",
                },
                {
                    "label": "Public Well-Being Impact",
                    "value": "Severe (predicted — multi-label classifier, confidence 0.95)",
                },
                {
                    "label": "Network Zone",
                    "value": "Communities-Internal-Servers (VLAN 312)",
                },
                {
                    "label": "Patch Cycle",
                    "value": "Monthly (second Saturday, 2200-0400 AWST)",
                },
                {"label": "Last Patch Date", "value": "20 June 2026"},
                {
                    "label": "Registered Applications",
                    "value": "Microsoft Office 365 Apps for Enterprise, Windows File Server role, Microsoft Defender for Endpoint",
                },
                {
                    "label": "Dependent Assets",
                    "value": "per-PRD-CASEMGT-APP01.communities.wa.gov.au, per-PRD-CASEMGT-DB01.communities.wa.gov.au, 42 caseworker workstations",
                },
                {"label": "Service Account", "value": "Local System"},
                {
                    "label": "Interface Type",
                    "value": "Internal network only (SMB TCP 445, RPC dynamic ports)",
                },
                {"label": "Last Vulnerability Scan", "value": "28 June 2026"},
                {
                    "label": "GPO Application Status (Last Recorded)",
                    "value": "CMDB Reports Conflict — see SLM RAG retrieval for details",
                },
            ]
        ),
        "summary_paragraphs_json": json.dumps(
            [
                "This case concerns a remote code execution vulnerability in Microsoft Office and Windows Search, tracked as CVE-2023-36884, identified on the host per-PRD-FILE-STORE02.communities.wa.gov.au. This host is a file storage server used by the Department of Communities, which handles case management documents for child protection, family and domestic violence services, and social housing programs.",
                "The multi-label classifier assessed this asset as having a Mission Prevalence of Core and a Public Well-Being Impact of Severe, reflecting its central role in supporting frontline child protection caseworkers.",
                "This case was escalated to the SLM Tier because the automated pipeline detected a conflict between two competing signals.",
            ]
        ),
        "telemetry_json": '{"sentinel_incidents": [{"incident_id": "SEN-2026-527325", "title": "Suspected exploitation of CVE-2023-36884", "severity": "High", "status": "Resolved", "detected_at": "2024-03-14T22:19:54Z", "assigned_to": "SOC Tier 2", "related_entities": ["per-PRD-FILE-STORE02.communities.wa.gov.au"], "mitre_techniques": ["T1071", "T1133", "T1053"]}], "edr_alerts": [{"alert_id": "EDR-20240604-4828", "alert_type": "module_load", "severity": "Medium", "process_name": "microsoft_module.dll", "process_path": "C:\\\\Program Files\\\\Microsoft\\\\microsoft_module.dll", "user": "IIS APPPOOL\\\\DefaultAppPool", "timestamp": "2024-11-15T08:29:37Z", "details": "Suspicious module load of microsoft_module.dll in microsoft.exe"}, {"alert_id": "EDR-20240604-4848", "alert_type": "network_connection", "severity": "Low", "process_name": "microsoft.exe", "process_path": "C:\\\\Program Files\\\\Microsoft\\\\microsoft.exe", "user": "NT AUTHORITY\\\\SYSTEM", "timestamp": "2024-10-22T05:02:09Z", "details": "Outbound connection from microsoft.exe to external IP address"}], "process_evidence": {"is_running": false, "is_loaded": true, "running_processes": ["microsoft_module.dll"], "evidence_quality": "medium"}, "threat_score": 0.724470950062004}',
        "network_context_json": '{"zone": "internal", "zone_display": "Communities-Internal-Servers (VLAN 312)", "peer_count": 48, "internet_facing_peers": 0, "dc_peers": 6, "peer_classifications": {"Support": 11, "Core": 26, "Peripheral": 11}, "blast_radius_score": 0.24, "exposure_level": "medium", "data_source": "synthetic_assets"}',
        "pre_tier_features": None,
        "epss_features": None,
    },
    # Row 6: CVE-2023-22515 — Confluence Broken Access Control
    {
        "vulnerability_id": "CVE-2023-22515",
        "hostname": "per-PRD-WIKI-CORE01.wapol.internal.wa.gov.au",
        "cvss_score": 10.0,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cisa_kev": True,
        "epss_score": 0.934,
        "mission_prevalence": "Core",
        "mission_prevalence_conf": 0.93,
        "public_wellbeing_impact": "Moderate",
        "public_wellbeing_conf": 0.86,
        "tier_0_routing": "escalated",
        "tier_0_resolution": "ambiguous",
        "tier_1_confidence": 0.66,
        "tier_1_exploitation_prob": 0.72,
        "tier_1_routing": "escalated",
        "tier_2_text_conflict": True,
        "tier_2_conflict_note": "Primary exploitability assessment: CVSS 10.0, CISA KEV, actively exploited by nation-state groups targeting law enforcement Confluence instances. Negative constraint: Change record CM-2023-10287 documents successful upgrade to 8.5.2, but scanner still fingerprints 8.5.1. RAG search revealed hostname alias confusion with staging server per-PRD-WIKI-CORE02.",
        "tier_2_rag_result": "UNCERTAIN — hostname alias confusion",
        "tier_2_confidence": 0.68,
        "tier_2_resolution_summary": "Scanner evidence carries more weight than change record. Assign score 41 — Medium band. ICT team demonstrated awareness within 14 days, reducing urgency.",
        "priority_score": 97,
        "risk_band": "Very Critical",
        "cvss_contribution": 40,
        "epss_contribution": 19,
        "asset_criticality_contribution": 19,
        "exposure_contribution": 3,
        "patch_remediation_contribution": 0,
        "ml_exploitation_contribution": 7,
        "security_context_contribution": 0,
        "epss_substituted": False,
        "epss_substituted_value": None,
        "epss_substitution_confidence": None,
        "epss_substitution_reason": None,
        "data_classification": "OFFICIAL Sensitive",
        "network_zone": "WAPOL-Internal-Management (VLAN 92)",
        "interface_type": "Internal HTTP via reverse proxy (TCP 8090 on loopback; external access via TCP 443 on reverse proxy, restricted to WAPOL management IP ranges)",
        "patch_cycle": "Ad-hoc (application patches applied outside standard OS patch cycle per vendor advisories)",
        "last_patch_date": "15 June 2026",
        "last_scan_date": "28 June 2026",
        "operating_system": "Ubuntu 22.04.3 LTS",
        "role": "Internal Knowledge Management Wiki — WA Police Force Operational Doctrine and Procedures",
        "business_owner": "WA Police Force — ICT Division, Information Management Branch",
        "technical_owner": "WAPOL ICT — Applications and Platforms Team",
        "registered_applications": "Atlassian Confluence Data Center 8.5.1, PostgreSQL 14.9, Apache HTTPD 2.4",
        "dependent_assets": "per-PRD-WIKI-DB01.wapol.internal.wa.gov.au, per-PRD-WIKI-CORE02.wapol.internal.wa.gov.au",
        "service_account": "",
        "detection_tier": "SLM Tier",
        "detection_reason": "SLM Tier: Text conflict detected. CVSS 10.0, CISA KEV listed as actively exploited. Negative constraint: internal change management records indicate patching was completed 14 days post-disclosure, but scanner fingerprint still returns version 8.5.1. RAG search uncertain — change record references a different hostname alias.",
        "scanner_output_raw": "[CRITICAL] CVE-2023-22515 — Atlassian Confluence Data Center Broken Access Control\nHost: per-PRD-WIKI-CORE01.wapol.internal.wa.gov.au (10.185.42.9)\nPort: 8090/tcp (HTTP — Confluence Application)\nService: Atlassian Confluence Data Center 8.5.1\nDetection Method: HTTP response header X-Confluence-Request-Time + /server-info.action version endpoint\nCVSS v3.1: 10.0 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)\nCISA KEV: TRUE (added 5 October 2023)\nEPSS Score: 0.934 (93rd percentile)\nExploit Maturity: High (public PoC available, actively exploited by nation-state groups)\nPatch Available: Yes (Confluence 8.5.2 and later)\nPatch Applied: UNCERTAIN — Scanner detects 8.5.1; change record CM-2023-10287 claims upgrade to 8.5.2 on related hostname alias",
        "weakness_template_raw": 'template_id: SLM-2023-CONFLUENCE-AC-001\ntemplate_name: "Confluence Broken Access Control — Patch Verification vs Scanner Fingerprint Conflict Resolver"\nmodel_type: Small Language Model (SLM) — Textual Conflict Resolution\ninput_documents:\n  - document_type: "exploitability_assessment"\n    source: "Vulnerability Scanner + CISA KEV + WASOC Threat Intel"\n    key_text: "CVSS 10.0. CISA KEV listed. Scanner fingerprint confirms Confluence 8.5.1."\n    sentiment: HIGH_RISK\n  - document_type: "negative_constraint"\n    source: "Internal Change Management System"\n    key_text: "Change record CM-2023-10287 documents successful upgrade to 8.5.2 on 19-Oct-2023."\n    sentiment: RISK_REMEDIATED\n  - document_type: "rag_retrieval_result"\n    source: "Internal CMDB + DNS Records"\n    key_text: "Change record description references per-PRD-WIKI-CORE01 but Target Host field contains per-PRD-WIKI-CORE02."\n    sentiment: UNCERTAIN',
        "advisory_ref_id": "ADV-CVE-2023-22515",
        "advisory_quote": "The Western Australian Security Operations Centre is issuing a critical advisory regarding CVE-2023-22515 in Atlassian Confluence Data Center and Server. This vulnerability is being actively exploited by advanced persistent threat groups targeting government knowledge management systems.",
        "investigation_notes": "The following summary has been pre-filled for analyst review and editing.\n\nCVE-2023-22515 on per-PRD-WIKI-CORE01.wapol.internal.wa.gov.au has been assigned a priority score of 97 and a risk band of Very Critical by the SLM Tier engine.\n\nImmediate recommended action: Perform manual verification of the Confluence version on per-PRD-WIKI-CORE01.",
        "mitre_techniques_json": json.dumps(
            [
                {
                    "id": "T1078.001",
                    "name": "Default Accounts",
                    "desc": "The vulnerability creates a pathway to establish unauthorised administrator accounts on the Confluence instance.",
                },
                {
                    "id": "T1548",
                    "name": "Abuse Elevation Control Mechanism",
                    "desc": "The core vulnerability is an abuse of the application setup endpoint that bypasses normal access control.",
                },
                {
                    "id": "T1213",
                    "name": "Data from Information Repositories",
                    "desc": "Post-compromise, the attacker can access and exfiltrate Confluence wiki content.",
                },
            ]
        ),
        "scoring_weights_json": json.dumps(
            [
                {
                    "name": "CVSS Base Score Contribution",
                    "awarded": 40,
                    "max": 40,
                    "justification": "CVSS 10.0 reflects maximum severity, but the asset is internally accessible only with no internet exposure.",
                },
                {
                    "name": "EPSS Exploitability Contribution",
                    "awarded": 19,
                    "max": 20,
                    "justification": "EPSS 0.934 confirms active exploitation, but reduced due to potential patching uncertainty.",
                },
                {
                    "name": "Asset Criticality Contribution",
                    "awarded": 19,
                    "max": 20,
                    "justification": "OFFICIAL Sensitive asset with Core mission and Moderate impact. Law enforcement operational doctrine is highly sensitive.",
                },
                {
                    "name": "Exposure and Network Position",
                    "awarded": 3,
                    "max": 12,
                    "justification": "Internal management network only. However, vulnerability may have remained unpatched for over two years.",
                },
                {
                    "name": "Patch Availability and Remediation Complexity",
                    "awarded": 0,
                    "max": 5,
                    "justification": "Patch available for over two years. SLM cannot confirm whether it has been applied.",
                },
                {
                    "name": "ML Exploitation Probability Contribution",
                    "awarded": 7,
                    "max": 10,
                    "justification": "XGBoost model predicted 0.72 exploitation probability with 0.66 confidence.",
                },
                {
                    "name": "Context Multiplier",
                    "awarded": 1.1,
                    "max": 1.2,
                    "justification": "1.10x multiplier applied — vulnerable code_loaded=True with high telemetry (0.918) enables partial evidence escalation despite limited blast radius.",
                },
            ]
        ),
        "asset_registry_json": json.dumps(
            [
                {"label": "Asset ID", "value": "AST-WAPOL-00012"},
                {
                    "label": "Hostname",
                    "value": "per-PRD-WIKI-CORE01.wapol.internal.wa.gov.au",
                },
                {"label": "IP Address", "value": "10.185.42.9"},
                {"label": "Operating System", "value": "Ubuntu 22.04.3 LTS"},
                {
                    "label": "Role",
                    "value": "Internal Knowledge Management Wiki — WA Police Force Operational Doctrine and Procedures",
                },
                {
                    "label": "Business Owner",
                    "value": "WA Police Force — ICT Division, Information Management Branch",
                },
                {
                    "label": "Technical Owner",
                    "value": "WAPOL ICT — Applications and Platforms Team",
                },
                {
                    "label": "Data Classification",
                    "value": "OFFICIAL Sensitive — Highly Protected (Law Enforcement) — WAICP classification",
                },
                {
                    "label": "Mission Prevalence",
                    "value": "Core (predicted — multi-label classifier, confidence 0.93)",
                },
                {
                    "label": "Public Well-Being Impact",
                    "value": "Moderate (predicted — multi-label classifier, confidence 0.86)",
                },
                {
                    "label": "Network Zone",
                    "value": "WAPOL-Internal-Management (VLAN 92)",
                },
                {
                    "label": "Patch Cycle",
                    "value": "Ad-hoc (application patches applied outside standard OS patch cycle)",
                },
                {"label": "Last OS Patch Date", "value": "15 June 2026"},
                {
                    "label": "Registered Applications",
                    "value": "Atlassian Confluence Data Center 8.5.1, PostgreSQL 14.9, Apache HTTPD 2.4",
                },
                {
                    "label": "Dependent Assets",
                    "value": "per-PRD-WIKI-DB01.wapol.internal.wa.gov.au, per-PRD-WIKI-CORE02.wapol.internal.wa.gov.au",
                },
                {
                    "label": "Interface Type",
                    "value": "Internal HTTP via reverse proxy (TCP 8090 on loopback)",
                },
                {"label": "Last Vulnerability Scan", "value": "28 June 2026"},
                {
                    "label": "Change Record Reference",
                    "value": "CM-2023-10287 (COMPLETED, 19-Oct-2023 — target host ambiguity identified by SLM)",
                },
            ]
        ),
        "summary_paragraphs_json": json.dumps(
            [
                "This case concerns a broken access control vulnerability in Atlassian Confluence Data Center and Server, tracked as CVE-2023-22515, identified on the host per-PRD-WIKI-CORE01.wapol.internal.wa.gov.au.",
                "The multi-label classifier assessed this asset as having a Mission Prevalence of Core and a Public Well-Being Impact of Moderate, reflecting its role as the central knowledge management wiki for the WA Police Force.",
                "This case was escalated to the SLM Tier because the automated pipeline detected a direct conflict between two high-confidence data sources.",
            ]
        ),
        "telemetry_json": '{"sentinel_incidents": [{"incident_id": "SEN-2026-663194", "title": "Suspected exploitation of CVE-2023-22515", "severity": "High", "status": "Investigating", "detected_at": "2024-01-22T20:45:31Z", "assigned_to": "SOC Tier 2", "related_entities": ["per-PRD-WIKI-CORE01.wapol.internal.wa.gov.au"], "mitre_techniques": ["T1078"]}], "edr_alerts": [{"alert_id": "EDR-20241222-3416", "alert_type": "process_execution", "severity": "High", "process_name": "confluence.exe", "process_path": "C:\\\\Program Files\\\\Confluence\\\\confluence.exe", "user": "NT AUTHORITY\\\\SYSTEM", "timestamp": "2024-06-29T11:21:36Z", "details": "Suspicious process execution of confluence.exe related to CVE-2023-22515"}], "process_evidence": {"is_running": true, "is_loaded": true, "running_processes": ["confluence.exe", "atlassian-extras-legacy.jar"], "evidence_quality": "high"}, "threat_score": 0.9184649897867908}',
        "network_context_json": '{"zone": "mgmt", "zone_display": "WAPOL-Internal-Management (VLAN 92)", "peer_count": 4, "internet_facing_peers": 0, "dc_peers": 1, "peer_classifications": {"Support": 1, "Core": 3}, "blast_radius_score": 0.02, "exposure_level": "low", "data_source": "synthetic_assets"}',
        "pre_tier_features": None,
        "epss_features": None,
    },
    # Row 7: CVE-2022-47966 — ManageEngine SAML RCE
    {
        "vulnerability_id": "CVE-2022-47966",
        "hostname": "per-PRD-ITSM-TOOL01.finance.wa.gov.au",
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cisa_kev": True,
        "epss_score": 0.961,
        "mission_prevalence": "Support",
        "mission_prevalence_conf": 0.89,
        "public_wellbeing_impact": "Minimal",
        "public_wellbeing_conf": 0.91,
        "tier_0_routing": "escalated",
        "tier_0_resolution": "ambiguous",
        "tier_1_confidence": 0.58,
        "tier_1_exploitation_prob": 0.63,
        "tier_1_routing": "escalated",
        "tier_2_text_conflict": True,
        "tier_2_conflict_note": "Primary exploitability assessment: CVSS 9.8, pre-auth RCE, multiple public PoCs, CISA KEV, exploited by APT groups. Negative constraint: RAG search confirmed SAML SSO is explicitly disabled (saml.sso.enabled=false) with LDAP-only authentication.",
        "tier_2_rag_result": "CONFIRMED — SAML disabled since 2021 deployment",
        "tier_2_confidence": 0.91,
        "tier_2_resolution_summary": "SAML-disabled configuration eliminates current attack surface. Assign score 22 — Low band. Persistent flag to alert if SAML is ever enabled.",
        "priority_score": 80,
        "risk_band": "Very Critical",
        "cvss_contribution": 39,
        "epss_contribution": 19,
        "asset_criticality_contribution": 6,
        "exposure_contribution": 3,
        "patch_remediation_contribution": 0,
        "ml_exploitation_contribution": 6,
        "security_context_contribution": 0,
        "epss_substituted": False,
        "epss_substituted_value": None,
        "epss_substitution_confidence": None,
        "epss_substitution_reason": None,
        "data_classification": "OFFICIAL",
        "network_zone": "Finance-Internal-Applications (VLAN 67)",
        "interface_type": "HTTPS via reverse proxy (NGINX) with IP allow-listing; internal network access on TCP 8443",
        "patch_cycle": "Monthly (fourth Saturday, 2200-0400 AWST)",
        "last_patch_date": "27 June 2026",
        "last_scan_date": "28 June 2026",
        "operating_system": "Windows Server 2022 Standard (build 20348)",
        "role": "IT Service Management Platform — Department of Finance Internal ICT Support and Procurement Ticketing",
        "business_owner": "Department of Finance — ICT Services",
        "technical_owner": "Finance ICT — Service Management Team",
        "registered_applications": "Zoho ManageEngine ServiceDesk Plus 14.0, PostgreSQL 14.8, Java Runtime Environment 11.0.19",
        "dependent_assets": "per-PRD-DC01.finance.wa.gov.au (LDAP), per-PRD-ITSM-DB01.finance.wa.gov.au",
        "service_account": "",
        "detection_tier": "SLM Tier",
        "detection_reason": "SLM Tier: Text conflict detected. CVSS 9.8, multiple public PoCs, pre-auth RCE capability (maximum severity signal). Negative constraint: internal RAG search confirmed SAML module is present in installed JAR files but SAML SSO is disabled in application.properties.",
        "scanner_output_raw": "[CRITICAL] CVE-2022-47966 — Zoho ManageEngine SAML Remote Code Execution (Pre-Auth)\nHost: per-PRD-ITSM-TOOL01.finance.wa.gov.au (10.33.10.52)\nPort: 8443/tcp (HTTPS — ManageEngine ServiceDesk Plus)\nService: Zoho ManageEngine ServiceDesk Plus 14.0 (build 13000)\nDetection Method: HTTP response header + /SamlResponseServlet endpoint probe (returns 404)\nCVSS v3.1: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)\nCISA KEV: TRUE (added 23 January 2023)\nEPSS Score: 0.961 (96th percentile)\nExploit Maturity: High (multiple public PoCs)\nPatch Available: Yes (ManageEngine ServiceDesk Plus build 14004 and later)\nPatch Applied: No (build 13000 detected)\nConfiguration Context: SAML SSO explicitly disabled in application.properties; LDAP only",
        "weakness_template_raw": 'template_id: SLM-2022-MANAGEENGINE-SAML-001\ntemplate_name: "ManageEngine SAML RCE — Exploitable Code vs Disabled Feature Conflict Resolver"\nmodel_type: Small Language Model (SLM) — Textual Conflict Resolution\ninput_documents:\n  - document_type: "exploitability_assessment"\n    source: "NVD + CISA KEV + ExploitDB"\n    key_text: "CVSS 9.8. Pre-authentication RCE. Affects 24 ManageEngine products. CISA KEV listed."\n    sentiment: MAXIMUM_RISK\n  - document_type: "negative_constraint"\n    source: "Internal RAG Search — application.properties"\n    key_text: "saml.sso.enabled=false. authentication.mode=ldap. Endpoint /SamlResponseServlet not registered."\n    sentiment: RISK_NEGATED_BY_CONFIGURATION\n  - document_type: "rag_retrieval_result"\n    source: "Internal CMDB"\n    key_text: "SAML disabled since initial deployment in 2021. No change requests exist to enable SAML."\n    sentiment: CONFIGURATION_MITIGATED',
        "advisory_ref_id": "ADV-CVE-2022-47966",
        "advisory_quote": "The Western Australian Security Operations Centre advises that CVE-2022-47966 affecting Zoho ManageEngine products has been observed in active exploitation against government IT service management platforms globally. WA agencies operating ManageEngine products should immediately verify their build versions.",
        "investigation_notes": "The following summary has been pre-filled for analyst review and editing.\n\nCVE-2022-47966 on per-PRD-ITSM-TOOL01.finance.wa.gov.au has been assigned a priority score of 80 and a risk band of Very Critical by the SLM Tier engine. This case presented the most extreme text conflict in the current triage queue.\n\nImmediate recommended action: Schedule an upgrade of ManageEngine ServiceDesk Plus from build 13000 to build 14004 during the next standard maintenance window.",
        "mitre_techniques_json": json.dumps(
            [
                {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "desc": "If SAML were enabled and the ServiceDesk Plus instance were exposed, the vulnerability would provide direct pre-authentication RCE.",
                },
                {
                    "id": "T1071.001",
                    "name": "Web Protocols",
                    "desc": "Post-exploitation communication would occur over standard HTTPS.",
                },
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "desc": "The RCE payload would execute within the Java runtime environment and could invoke operating system commands.",
                },
            ]
        ),
        "scoring_weights_json": json.dumps(
            [
                {
                    "name": "CVSS Base Score Contribution",
                    "awarded": 39,
                    "max": 40,
                    "justification": "CVSS 9.8 reflects maximum severity, but severely discounted because the SAML endpoint is not reachable.",
                },
                {
                    "name": "EPSS Exploitability Contribution",
                    "awarded": 19,
                    "max": 20,
                    "justification": "EPSS 0.961 reflects general exploitation probability across all instances. Heavily discounted due to SAML-disabled config.",
                },
                {
                    "name": "Asset Criticality Contribution",
                    "awarded": 6,
                    "max": 20,
                    "justification": "OFFICIAL asset with Support mission and Minimal public impact.",
                },
                {
                    "name": "Exposure and Network Position",
                    "awarded": 3,
                    "max": 12,
                    "justification": "Asset sits behind reverse proxy with IP allow-listing. SAML attack surface is not present.",
                },
                {
                    "name": "Patch Availability and Remediation Complexity",
                    "awarded": 0,
                    "max": 5,
                    "justification": "Patch available for over three years but not applied. No remediation credit is awarded when a patch is available and overdue.",
                },
                {
                    "name": "ML Exploitation Probability Contribution",
                    "awarded": 6,
                    "max": 10,
                    "justification": "XGBoost model predicted 0.63 exploitation probability with 0.58 confidence.",
                },
                {
                    "name": "Context Multiplier",
                    "awarded": 1.1,
                    "max": 1.2,
                    "justification": "1.10x multiplier applied — vulnerable code_loaded=True with high telemetry (1.000) enables partial evidence escalation.",
                },
            ]
        ),
        "asset_registry_json": json.dumps(
            [
                {"label": "Asset ID", "value": "AST-FIN-00291"},
                {"label": "Hostname", "value": "per-PRD-ITSM-TOOL01.finance.wa.gov.au"},
                {"label": "IP Address", "value": "10.33.10.52"},
                {
                    "label": "Operating System",
                    "value": "Windows Server 2022 Standard (build 20348)",
                },
                {
                    "label": "Role",
                    "value": "IT Service Management Platform — Department of Finance",
                },
                {
                    "label": "Business Owner",
                    "value": "Department of Finance — ICT Services",
                },
                {
                    "label": "Technical Owner",
                    "value": "Finance ICT — Service Management Team",
                },
                {
                    "label": "Data Classification",
                    "value": "OFFICIAL — Sensitive (Personal) — WAICP classification",
                },
                {
                    "label": "Mission Prevalence",
                    "value": "Support (predicted — multi-label classifier, confidence 0.89)",
                },
                {
                    "label": "Public Well-Being Impact",
                    "value": "Minimal (predicted — multi-label classifier, confidence 0.91)",
                },
                {
                    "label": "Network Zone",
                    "value": "Finance-Internal-Applications (VLAN 67)",
                },
                {
                    "label": "Patch Cycle",
                    "value": "Monthly (fourth Saturday, 2200-0400 AWST)",
                },
                {"label": "Last Patch Date", "value": "27 June 2026"},
                {
                    "label": "Registered Applications",
                    "value": "Zoho ManageEngine ServiceDesk Plus 14.0, PostgreSQL 14.8, JRE 11.0.19",
                },
                {
                    "label": "Dependent Assets",
                    "value": "per-PRD-DC01.finance.wa.gov.au (LDAP), per-PRD-ITSM-DB01.finance.wa.gov.au",
                },
                {
                    "label": "Authentication Configuration",
                    "value": "LDAP only (saml.sso.enabled=false)",
                },
                {
                    "label": "Interface Type",
                    "value": "HTTPS via reverse proxy (NGINX) with IP allow-listing",
                },
                {"label": "Last Vulnerability Scan", "value": "28 June 2026"},
                {
                    "label": "SAML Status",
                    "value": "Disabled since initial deployment (14 March 2021)",
                },
            ]
        ),
        "summary_paragraphs_json": json.dumps(
            [
                "This case concerns a pre-authentication remote code execution vulnerability in Zoho ManageEngine products that include a SAML-based single sign-on module, tracked as CVE-2022-47966.",
                "The multi-label classifier assessed this asset as having a Mission Prevalence of Support and a Public Well-Being Impact of Minimal, reflecting its role as an internal IT service desk platform.",
                "This case was escalated to the SLM Tier because the automated pipeline identified the maximum possible conflict between the exploitability signal and the deployment context.",
            ]
        ),
        "telemetry_json": '{"sentinel_incidents": [{"incident_id": "SEN-2026-720528", "title": "Suspected exploitation of CVE-2022-47966", "severity": "High", "status": "Resolved", "detected_at": "2024-12-07T02:52:25Z", "assigned_to": "SOC Tier 2", "related_entities": ["per-PRD-ITSM-TOOL01.finance.wa.gov.au"], "mitre_techniques": ["T1053", "T1027"]}, {"incident_id": "SEN-2024-546364", "title": "Suspected exploitation of CVE-2022-47966", "severity": "Informational", "status": "Investigating", "detected_at": "2024-11-27T01:28:26Z", "assigned_to": "SOC Tier 1", "related_entities": ["per-PRD-ITSM-TOOL01.finance.wa.gov.au"], "mitre_techniques": ["T1566"]}], "edr_alerts": [{"alert_id": "EDR-20241204-9151", "alert_type": "process_execution", "severity": "High", "process_name": "authentication.exe", "process_path": "C:\\\\Program Files\\\\Authentication\\\\authentication.exe", "user": "NT AUTHORITY\\\\NETWORK SERVICE", "timestamp": "2024-07-19T02:31:39Z", "details": "Suspicious process execution of authentication.exe related to CVE-2022-47966"}], "process_evidence": {"is_running": true, "is_loaded": true, "running_processes": ["authentication.exe", "authentication_module.dll"], "evidence_quality": "high"}, "threat_score": 1.0}',
        "network_context_json": '{"zone": "internal", "zone_display": "Finance-Internal-Applications (VLAN 67)", "peer_count": 63, "internet_facing_peers": 0, "dc_peers": 9, "peer_classifications": {"Peripheral": 15, "Core": 31, "Support": 17}, "blast_radius_score": 0.315, "exposure_level": "medium", "data_source": "synthetic_assets"}',
        "pre_tier_features": None,
        "epss_features": None,
    },
]


def seed():
    """Populate the database with the 7 demo rows."""
    init_db()
    conn = get_db()
    cursor = conn.cursor()

    conn.execute("DELETE FROM vulnerabilities")
    conn.execute("DELETE FROM resolved_vulnerabilities")

    INSERT_SQL = """
        INSERT INTO vulnerabilities (
            vulnerability_id, hostname, cvss_score, cvss_vector, cisa_kev, epss_score,
            mission_prevalence, mission_prevalence_conf, public_wellbeing_impact, public_wellbeing_conf,
            tier_0_routing, tier_0_resolution,
            tier_1_confidence, tier_1_exploitation_prob, tier_1_routing,
            tier_2_text_conflict, tier_2_conflict_note, tier_2_rag_result, tier_2_confidence, tier_2_resolution_summary,
            priority_score, risk_band,
            cvss_contribution, epss_contribution, asset_criticality_contribution, exposure_contribution,
            patch_remediation_contribution, ml_exploitation_contribution, security_context_contribution,
            epss_substituted, epss_substituted_value, epss_substitution_confidence, epss_substitution_reason,
            data_classification, network_zone, interface_type, patch_cycle, last_patch_date, last_scan_date,
            operating_system, role, business_owner, technical_owner, registered_applications, dependent_assets,
            service_account, detection_tier, detection_reason,
            scanner_output_raw, weakness_template_raw, advisory_ref_id, advisory_quote, investigation_notes,
            mitre_techniques_json, scoring_weights_json, asset_registry_json, summary_paragraphs_json,
            pre_tier_features,
            epss_features,
            telemetry_json, network_context_json
        ) VALUES (
            :vulnerability_id, :hostname, :cvss_score, :cvss_vector, :cisa_kev, :epss_score,
            :mission_prevalence, :mission_prevalence_conf, :public_wellbeing_impact, :public_wellbeing_conf,
            :tier_0_routing, :tier_0_resolution,
            :tier_1_confidence, :tier_1_exploitation_prob, :tier_1_routing,
            :tier_2_text_conflict, :tier_2_conflict_note, :tier_2_rag_result, :tier_2_confidence, :tier_2_resolution_summary,
            :priority_score, :risk_band,
            :cvss_contribution, :epss_contribution, :asset_criticality_contribution, :exposure_contribution,
            :patch_remediation_contribution, :ml_exploitation_contribution, :security_context_contribution,
            :epss_substituted, :epss_substituted_value, :epss_substitution_confidence, :epss_substitution_reason,
            :data_classification, :network_zone, :interface_type, :patch_cycle, :last_patch_date, :last_scan_date,
            :operating_system, :role, :business_owner, :technical_owner, :registered_applications, :dependent_assets,
            :service_account, :detection_tier, :detection_reason,
            :scanner_output_raw, :weakness_template_raw, :advisory_ref_id, :advisory_quote, :investigation_notes,
            :mitre_techniques_json, :scoring_weights_json, :asset_registry_json, :summary_paragraphs_json,
            :pre_tier_features,
            :epss_features,
            :telemetry_json, :network_context_json
        )
    """

    for row in SEED_ROWS:
        cursor.execute(INSERT_SQL, row)
        print(
            f"  Inserted {row['vulnerability_id']} — {row['hostname']} (score {row['priority_score']}, band {row['risk_band']})"
        )

    conn.commit()
    conn.close()
    print(f"\nSeed complete. {len(SEED_ROWS)} rows inserted.")


if __name__ == "__main__":
    seed()
