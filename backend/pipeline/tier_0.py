"""
Tier 0: Deterministic routing rules for vulnerability prioritisation.

No ML required. These rules are production-ready from day one.
Thresholds are configurable constants at the top of the file.
"""

import logging

from ml.xgboost_predictor import CWE_EPSS_THRESHOLDS

logger = logging.getLogger("triagemate.tier_0")

# Threshold constants
KEV_CVSS_THRESHOLD = 9.0
KEV_EPSS_THRESHOLD = 0.90
LOW_CVSS_THRESHOLD = 4.0
LOW_EPSS_THRESHOLD = 0.10
NVD_REF_THRESHOLD = 21


def evaluate_tier_0(
    cvss_score: float,
    cisa_kev: bool,
    epss_score: float,
    data_classification: str,
    internet_facing: bool,
    nvd_reference_count: int = 0,
    cwe_class: str = "",
) -> dict:
    """
    Deterministic rules for Tier 0 routing.

    Returns routing decision and a tentative score band.

    Args:
        cvss_score: CVSS v3.1 base score (0-10)
        cisa_kev: Whether the CVE is in the CISA Known Exploited Vulnerabilities catalog
        epss_score: EPSS exploitation probability score (0-1)
        data_classification: WAICP data classification level
        internet_facing: Whether the asset is exposed to the public internet
        nvd_reference_count: Number of NVD references for the CVE (used for high-signal auto-resolve)
        cwe_class: CWE identifier (e.g. "CWE-78") for CWE-stratified EPSS threshold lookups

    Returns:
        dict with 'routing' ('auto_resolved' or 'escalated') and 'resolution'
    """
    # Auto-resolve as Very Critical if NVD reference count >= 21
    # Research: CVEs with 21+ NVD references have 9.5× baseline KEV rate
    if nvd_reference_count >= NVD_REF_THRESHOLD:
        logger.info(
            "Tier 0 auto-resolve very_critical for NVD reference count >= %d",
            NVD_REF_THRESHOLD,
            extra={"event": "tier_0_resolve"},
        )
        return {"routing": "auto_resolved", "resolution": "very_critical"}

    # Auto-resolve as Very Critical if:
    # - CISA KEV listed AND CVSS >= 9.0 AND internet-facing
    if cisa_kev and cvss_score >= KEV_CVSS_THRESHOLD and internet_facing:
        logger.info(
            "Tier 0 auto-resolve very_critical for KEV+CVSS+IF",
            extra={"event": "tier_0_resolve"},
        )
        return {"routing": "auto_resolved", "resolution": "very_critical"}

    # Auto-resolve as Very Critical if:
    # - CISA KEV listed AND EPSS >= CWE-stratified threshold (or monolithic 0.90)
    #   AND data classification is OFFICIAL Sensitive
    # Use CWE-stratified KEV threshold if available, otherwise use monolithic 0.90
    kev_threshold = (
        CWE_EPSS_THRESHOLDS.get(cwe_class, KEV_EPSS_THRESHOLD)
        if cwe_class
        else KEV_EPSS_THRESHOLD
    )
    if (
        cisa_kev
        and epss_score >= kev_threshold
        and data_classification == "OFFICIAL Sensitive"
    ):
        logger.info(
            "Tier 0 auto-resolve very_critical for KEV+EPSS+Sensitive",
            extra={"event": "tier_0_resolve"},
        )
        return {"routing": "auto_resolved", "resolution": "very_critical"}

    # Auto-resolve as Low if:
    # - Not CISA KEV AND CVSS < 4.0 AND EPSS < CWE-aware threshold
    # NOTE: CWE-stratified thresholds (from xgboost_predictor.CWE_EPSS_THRESHOLDS) are used
    # for the low-severity auto-resolve. For CWE-78 (OS Command Injection), the threshold
    # is 0.515 (vs 0.10 monolithic), meaning CVEs with EPSS up to 0.515 are auto-resolved
    # as low. This is intentional — the thresholds are empirically derived from EPSS
    # evaluation analysis showing optimal F1 thresholds per CWE class.
    # See analysis/epss_eval.py for the stratified analysis methodology.
    cwe_low_threshold = CWE_EPSS_THRESHOLDS.get(cwe_class, LOW_EPSS_THRESHOLD)
    if (
        not cisa_kev
        and cvss_score < LOW_CVSS_THRESHOLD
        and epss_score < cwe_low_threshold
    ):
        logger.info(
            "Tier 0 auto-resolve low for CVSS+EPSS thresholds (CWE=%s, threshold=%.3f)",
            cwe_class or "unknown",
            cwe_low_threshold,
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
