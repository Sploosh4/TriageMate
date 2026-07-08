"""
Metasploit payload lookup — checks ExploitDB CSV and NVD references.

First checks ExploitDB CSV (if loaded) for entries with platform="metasploit",
then falls back to NVD reference tag scraping for Metasploit URLs.

Free, no auth required.
"""

import logging
from integrations.nvd import get_nvd_data
from integrations.exploitdb import _lookup_edb

logger = logging.getLogger("triagemate.metasploit")


def has_payload(cve_id: str) -> bool:
    """Check if a CVE has a Metasploit module.

    First checks ExploitDB CSV for entries where author='Metasploit'
    (the standard way ExploitDB categorises Metasploit framework modules).
    Falls back to NVD references for URLs containing 'metasploit' or 'rapid7.com'.

    Returns False on any error or missing data.
    """
    try:
        exploits = _lookup_edb(cve_id)
        if any("metasploit" in e.get("author", "").lower() for e in exploits):
            return True
    except Exception as e:
        logger.warning("Metasploit EDB CSV lookup failed for %s: %s", cve_id, e)

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
        logger.warning("Metasploit NVD fallback lookup failed for %s: %s", cve_id, e)
    return False
