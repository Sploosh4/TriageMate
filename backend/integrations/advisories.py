"""
Advisory reference enrichment — CVE → advisory lookup stub.

In production, this would query WASOC advisories, CSA alerts,
vendor bulletins, or CISA KEV. For now, a static mapping for top CVEs
with a fallback generator.
"""

import logging

logger = logging.getLogger("triagemate.advisories")

CVE_ADVISORIES: dict[str, dict] = {
    "CVE-2023-34362": {
        "ref_id": "ADV-CVE-2023-34362",
        "quote": "The Western Australian Security Operations Centre assesses with high confidence that Progress MOVEit Transfer instances operated by WA state government entities are being actively targeted by the Clop ransomware group. All agencies must immediately verify MOVEit Transfer version numbers and apply vendor patches within 24 hours.",
    },
    "CVE-2023-4966": {
        "ref_id": "ADV-CVE-2023-4966",
        "quote": "The Western Australian Security Operations Centre is issuing an urgent advisory regarding CVE-2023-4966, a critical session token disclosure vulnerability in Citrix NetScaler ADC and Gateway appliances. This vulnerability has been confirmed as actively exploited in the wild.",
    },
    "CVE-2023-27350": {
        "ref_id": "ADV-CVE-2023-27350",
        "quote": "The Western Australian Security Operations Centre advises that CVE-2023-27350 affecting PaperCut NG and MF has been observed in active exploitation by multiple threat actor groups, including those affiliated with ransomware operations. Education sector organisations have been disproportionately targeted.",
    },
    "CVE-2024-1709": {
        "ref_id": "ADV-CVE-2024-1709",
        "quote": "The Western Australian Security Operations Centre has assessed CVE-2024-1709 as a high-severity threat to WA government entities using ConnectWise ScreenConnect for remote management. Of particular concern is the risk posed to shared services providers who manage endpoints across multiple agencies.",
    },
    "CVE-2023-36884": {
        "ref_id": "ADV-CVE-2023-36884",
        "quote": "The Western Australian Security Operations Centre has confirmed that CVE-2023-36884 is being actively exploited in targeted spear-phishing campaigns against Australian state government social services agencies. Attackers are sending malicious Office documents themed around child protection case updates.",
    },
    "CVE-2023-22515": {
        "ref_id": "ADV-CVE-2023-22515",
        "quote": "The Western Australian Security Operations Centre is issuing a critical advisory regarding CVE-2023-22515 in Atlassian Confluence Data Center and Server. This vulnerability is being actively exploited by advanced persistent threat groups targeting government knowledge management systems.",
    },
    "CVE-2022-47966": {
        "ref_id": "ADV-CVE-2022-47966",
        "quote": "The Western Australian Security Operations Centre advises that CVE-2022-47966 affecting Zoho ManageEngine products has been observed in active exploitation against government IT service management platforms globally. WA agencies operating ManageEngine products should immediately verify their build versions.",
    },
}


def get_advisory(cve_id: str) -> dict:
    """Look up advisory reference for a CVE.

    Returns dict with advisory_ref_id and advisory_quote.
    Falls back to a generic CISA-style advisory for unknown CVEs.
    """
    if cve_id in CVE_ADVISORIES:
        return dict(CVE_ADVISORIES[cve_id])

    logger.warning("No advisory mapping for %s — using generic fallback", cve_id)
    return {
        "ref_id": f"ADV-{cve_id}",
        "quote": f"A security advisory has been published for {cve_id}. Analysts should review vendor documentation and WASOC threat intelligence for further details.",
    }
