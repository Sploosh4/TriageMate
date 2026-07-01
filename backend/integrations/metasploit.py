"""
Metasploit payload lookup — checks NVD references for Metasploit modules.

Free, no auth required. Uses NVD data already fetched per ingest.
Independently skippable — fails gracefully to False on any error.
"""

import logging
from integrations.nvd import get_nvd_data

logger = logging.getLogger("triagemate.metasploit")


def has_payload(cve_id: str) -> bool:
    """Check if a CVE has a Metasploit module.

    Checks NVD references for URLs containing 'metasploit' or 'rapid7.com'
    or reference tags containing 'metasploit'.

    Returns False on any error or missing data.
    """
    try:
        nvd = get_nvd_data(cve_id)
        refs = nvd.get("references_raw", [])
        for r in refs:
            url = r.get("url", "").lower()
            if "metasploit" in url or "rapid7.com" in url:
                return True
            for tag in r.get("tags", []):
                if "metasploit" in tag.lower():
                    return True
    except Exception as e:
        logger.warning("Metasploit lookup failed for %s: %s", cve_id, e)
    return False
