"""
Tenable.io export JSON → IngestRequest field mapper.

Tenable v2 API export format (from WASOC's Tenable.sc or Tenable.io):
    Single finding:
        {"asset": {...}, "plugin": {...}, "output": "..."}
    Webhook envelope:
        {"type": "vuln_found", "finding": {"asset": {...}, "plugin": {...}, ...}}
    Batch export:
        [{"asset": {...}, "plugin": {...}, ...}, ...]

Field mapping per Intel Team ruling (2026-07-01):
    Tenable path                                  IngestRequest field
    ─────────────────────────────────────────────────────────────────
    plugin.cve[0]                                 vulnerability_id
    asset.fqdn (fallback hostname)                 hostname
    plugin.cvss3_base_score (→ v2)                 cvss_score
    plugin.cvss3_vector (strip "CVSS:3.1/")        cvss_vector
    asset.ipv4                                     target_ip
    plugin.description                              raw_description
    output (top-level)                              scanner_output_raw
    plugin.synopsis                                 weakness_template_raw
    plugin.exploit_available                        has_public_poc
    plugin.has_patch + patch_publication_date       vendor_patch_status
    plugin.exploit_available + metasploit           exploit_maturity
"""

import logging
from typing import Optional
from models import IngestRequest

logger = logging.getLogger("triagemate.tenable")


def _first_cve(plugin: dict) -> str:
    """Extract the first CVE ID from plugin.cve array, or synthesize one."""
    cve_list = plugin.get("cve", [])
    if cve_list and isinstance(cve_list, list) and cve_list[0]:
        return cve_list[0].strip()
    plugin_id = plugin.get("id", "UNKNOWN")
    return f"TENABLE-{plugin_id}"


def _extract_hostname(asset: dict) -> str:
    """Extract FQDN from asset, falling back to hostname then ipv4."""
    fqdn = asset.get("fqdn", "")
    if fqdn:
        return fqdn
    hostname = asset.get("hostname", "")
    if hostname:
        return hostname
    ipv4 = asset.get("ipv4", "")
    if isinstance(ipv4, list) and ipv4:
        return ipv4[0]
    return ipv4 or "unknown-host"


def _compute_exploit_maturity(plugin: dict) -> int:
    """Compute exploit_maturity 0-4 from Tenable plugin fields.

    0 = No exploit available
    1 = Exploit available (PoC or weaponized)
    3 = Metasploit module available
    """
    exploit_available = plugin.get("exploit_available", False)
    if not exploit_available:
        return 0
    metasploit = plugin.get("metasploit", None) or plugin.get(
        "exploit_framework_metasploit", None
    )
    if metasploit:
        return 3
    return 1


def _compute_vendor_patch_status(plugin: dict) -> int:
    """Compute vendor_patch_status 0/1 from Tenable patch fields.

    0 = no patch available
    1 = patch available
    """
    has_patch = plugin.get("has_patch", False)
    patch_date = plugin.get("patch_publication_date", None)
    if has_patch and patch_date:
        return 1
    return 0


def _clean_cvss_vector(raw: str) -> str:
    """Strip 'CVSS:3.1/' or 'CVSS:3.0/' prefix from Tenable vector strings."""
    if not raw:
        return ""
    for prefix in ("CVSS:3.1/", "CVSS:3.0/", "CVSS:3.1", "CVSS:3.0"):
        if raw.startswith(prefix):
            return raw[len(prefix) :]
    return raw


def parse_tenable_finding(raw: dict) -> Optional[IngestRequest]:
    """Map a single Tenable finding dict to an IngestRequest.

    Args:
        raw: A Tenable finding with 'asset' and 'plugin' keys.

    Returns:
        IngestRequest or None if mapping fails.
    """
    try:
        asset = raw.get("asset", {})
        plugin = raw.get("plugin", {})
        output = raw.get("output", "")

        vulnerability_id = _first_cve(plugin)
        hostname = _extract_hostname(asset)
        cvss_score = float(plugin.get("cvss3_base_score", 0.0) or 0.0)
        cvss_vector = _clean_cvss_vector(plugin.get("cvss3_vector", "") or "")

        ipv4 = asset.get("ipv4", "")
        target_ip = ipv4[0] if isinstance(ipv4, list) and ipv4 else (ipv4 or "")

        raw_description = plugin.get("description", "") or ""
        scanner_output_raw = output or ""
        weakness_template_raw = plugin.get("synopsis", "") or ""

        has_public_poc = bool(plugin.get("exploit_available", False))
        exploit_maturity = _compute_exploit_maturity(plugin)
        vendor_patch_status = _compute_vendor_patch_status(plugin)

        return IngestRequest(
            vulnerability_id=vulnerability_id,
            hostname=hostname,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cisa_kev=False,
            epss_score=None,
            target_ip=target_ip,
            raw_description=raw_description,
            scanner_output_raw=scanner_output_raw,
            weakness_template_raw=weakness_template_raw,
            exploit_maturity=exploit_maturity,
            has_public_poc=has_public_poc,
            vendor_patch_status=vendor_patch_status,
        )
    except Exception as e:
        logger.warning("Failed to map Tenable finding: %s", e)
        return None


def parse_tenable_webhook(raw: dict) -> Optional[IngestRequest]:
    """Unwrap a Tenable webhook envelope and map the finding.

    Accepts:
        {"type": "vuln_found", "finding": {"asset": {...}, "plugin": {...}, ...}}
        {"asset": {...}, "plugin": {...}, ...}  (bare finding, no envelope)

    Returns:
        IngestRequest or None.
    """
    if "type" in raw and "finding" in raw:
        return parse_tenable_finding(raw["finding"])
    if "asset" in raw and "plugin" in raw:
        return parse_tenable_finding(raw)
    logger.warning(
        "Unrecognized Tenable webhook format — expected 'finding' or 'asset'+'plugin' keys"
    )
    return None


def parse_tenable_batch(raw: list[dict]) -> list[IngestRequest]:
    """Map a list of Tenable findings to IngestRequest list.

    Skips any items that fail mapping (logs warning, continues).
    """
    results: list[IngestRequest] = []
    for i, item in enumerate(raw):
        parsed = parse_tenable_finding(item)
        if parsed is not None:
            results.append(parsed)
        else:
            logger.warning("Skipping Tenable finding at index %d — failed to map", i)
    return results
