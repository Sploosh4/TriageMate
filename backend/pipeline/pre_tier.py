"""
Pre-Tier: Multi-label classifier for mission tags (Mission Prevalence and
Public Well-Being Impact).

MVP Implementation (Stub):
Returns hardcoded tags for the 7 known demo hosts.
For any unknown host, returns default values.

Replace with a trained multi-label classifier when labeled asset data is available.
"""

KNOWN_TAGS = {
    "PRD-MOVEIT-WEB01.health.wa.gov.au": ("Core", 0.94, "Severe", 0.96),
    "PRD-CITRIX-ADC01.transport.wa.gov.au": ("Core", 0.91, "Moderate", 0.88),
    "PRD-PRINT-SVR05.education.wa.edu.au": ("Support", 0.85, "Minimal", 0.82),
    "PRD-RMM-GW01.sharedservices.wa.gov.au": ("Support", 0.87, "Moderate", 0.84),
    "PRD-FILE-STORE02.communities.wa.gov.au": ("Core", 0.92, "Severe", 0.95),
    "PRD-WIKI-CORE01.wapol.internal.wa.gov.au": ("Core", 0.93, "Moderate", 0.86),
    "PRD-ITSM-TOOL01.finance.wa.gov.au": ("Support", 0.89, "Minimal", 0.91),
}


def predict_mission_tags(hostname: str, ip: str) -> dict:
    """
    Predict mission prevalence and public well-being impact for an asset.

    Stub: returns the tags from the demo dataset for the 7 known hosts.
    For any unknown host, returns default values.

    Args:
        hostname: The fully qualified hostname of the asset
        ip: The IP address of the asset

    Returns:
        dict with 'mission_prevalence', 'mission_prevalence_confidence',
        'public_wellbeing_impact', 'public_wellbeing_confidence'
    """
    if hostname in KNOWN_TAGS:
        mp, mp_conf, pwi, pwi_conf = KNOWN_TAGS[hostname]
        return {
            "mission_prevalence": mp,
            "mission_prevalence_confidence": mp_conf,
            "public_wellbeing_impact": pwi,
            "public_wellbeing_confidence": pwi_conf
        }

    return {
        "mission_prevalence": "Support",
        "mission_prevalence_confidence": 0.60,
        "public_wellbeing_impact": "Minimal",
        "public_wellbeing_confidence": 0.60
    }
