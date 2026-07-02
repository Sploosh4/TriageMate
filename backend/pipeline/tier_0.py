"""
Tier 0: Deterministic routing rules for vulnerability prioritisation.

No ML required. These rules are production-ready from day one.
Thresholds are configurable constants at the top of the file.
"""

import logging

logger = logging.getLogger("triagemate.tier_0")

# Threshold constants
KEV_CVSS_THRESHOLD = 9.0
KEV_EPSS_THRESHOLD = 0.90
LOW_CVSS_THRESHOLD = 4.0
LOW_EPSS_THRESHOLD = 0.10


def evaluate_tier_0(
    cvss_score: float,
    cisa_kev: bool,
    epss_score: float,
    data_classification: str,
    internet_facing: bool,
) -> dict:
    """
    Deterministic rules for Tier 0 routing.

    Returns routing decision and a tentative score band.

    Args:
        cvss_score: CVSS v3.1 base score (0-10)
        cisa_kev: Whether the CVE is in the CISA Known Exploited Vulnerabilities catalog
        epss_score: EPSS exploitation probability score (0-1)
        data_classification: PRIS Act data classification level
        internet_facing: Whether the asset is exposed to the public internet

    Returns:
        dict with 'routing' ('auto_resolved' or 'escalated') and 'resolution'
    """
    # Auto-resolve as Very Critical if:
    # - CISA KEV listed AND CVSS >= 9.0 AND internet-facing
    if cisa_kev and cvss_score >= KEV_CVSS_THRESHOLD and internet_facing:
        logger.info(
            "Tier 0 auto-resolve very_critical for KEV+CVSS+IF",
            extra={"event": "tier_0_resolve"},
        )
        return {"routing": "auto_resolved", "resolution": "very_critical"}

    # Auto-resolve as Very Critical if:
    # - CISA KEV listed AND EPSS >= 0.90 AND data classification is Category 3 or 4
    if (
        cisa_kev
        and epss_score >= KEV_EPSS_THRESHOLD
        and data_classification in ("Category 3", "Category 4")
    ):
        logger.info(
            "Tier 0 auto-resolve very_critical for KEV+EPSS+Cat3/4",
            extra={"event": "tier_0_resolve"},
        )
        return {"routing": "auto_resolved", "resolution": "very_critical"}

    # Auto-resolve as Low if:
    # - Not CISA KEV AND CVSS < 4.0 AND EPSS < 0.10
    if (
        not cisa_kev
        and cvss_score < LOW_CVSS_THRESHOLD
        and epss_score < LOW_EPSS_THRESHOLD
    ):
        logger.info(
            "Tier 0 auto-resolve low for CVSS+EPSS thresholds",
            extra={"event": "tier_0_resolve"},
        )
        return {"routing": "auto_resolved", "resolution": "low"}

    logger.info("Tier 0 escalate ambiguous", extra={"event": "tier_0_resolve"})
    # Everything else is ambiguous — escalate to Tier 1
    return {"routing": "escalated", "resolution": "ambiguous"}


def requires_recheck(tier_0_result: dict, created_at_days_ago: int) -> bool:
    """
    Determine if a low-severity classification needs a 7-day re-check.

    Args:
        tier_0_result: Output from evaluate_tier_0()
        created_at_days_ago: Days since the vulnerability was first classified.

    Returns:
        True if the case should be re-evaluated.
    """
    return (
        tier_0_result["routing"] == "auto_resolved"
        and tier_0_result["resolution"] == "low"
        and created_at_days_ago >= 7
    )
