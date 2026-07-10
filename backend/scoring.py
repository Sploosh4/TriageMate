"""
Final priority score calculation.

Combines outputs from all pipeline stages into a score
with per-dimension breakdown for the frontend scoring weights display.

Weights sum to 112 (CVSS 40 + EPSS 20 + criticality 20 + exposure 12 +
patch 5 + ml_exploitation 10 + security_context 5). The final total is clamped to 0-100.
"""

from pipeline.config.scoring import (
    SCORING_WEIGHTS,
    CLAMP_MIN,
    CLAMP_MAX,
    CRITICALITY_MAX,
    PATCH_MAX,
    SECURITY_CONTEXT_MAX,
)


def _round_half_up(x):
    """Round to nearest int, .5 always rounds up (not banker's rounding)."""
    return int(x + 0.5)


def calculate_final_score(
    cvss_score,
    epss_score,
    mission_prevalence,
    public_wellbeing,
    data_classification,
    internet_facing,
    patch_available=True,
    patch_applied=False,
    tier_1_result=None,
    tier_2_result=None,
    substituted_epss=None,
    telemetry_threat_score: float = 0.0,
    network_blast_radius: float = 0.0,
) -> dict:
    """
    Calculate the priority score from seven weighted dimensions plus optional Tier 2 score adjustment.
    Weights sum to 112; final total is clamped to 0-100.

    Returns a dict with per-dimension breakdown for the scoring weights display.

    Args:
        cvss_score: CVSS v3.1 base score (0-10)
        epss_score: EPSS exploitation probability score (0-1)
        mission_prevalence: 'Core', 'Support', or 'Peripheral'
        public_wellbeing: 'Severe', 'Moderate', or 'Minimal'
        data_classification: WAICP classification level
        internet_facing: Whether the asset is exposed to the public internet
        patch_available: Whether a security patch is available
        patch_applied: Whether the patch has been applied
        tier_1_result: Output from Tier 1 (optional)
        tier_2_result: Output from Tier 2 (optional)

    Returns:
        dict with 'total' (0-100), 'band', and 'dimensions' breakdown
    """
    dimensions = {}

    # CVSS contribution (max CRITICALITY_MAX via weight 40)
    cvss_pct = cvss_score / 10.0
    dimensions["cvss"] = _round_half_up(cvss_pct * SCORING_WEIGHTS["cvss"])

    # EPSS contribution (max ML_EXPLOITATION_MAX via weight 20) — use substituted EPSS if available
    effective_epss = substituted_epss if substituted_epss is not None else epss_score
    dimensions["epss"] = _round_half_up(effective_epss * SCORING_WEIGHTS["epss"])

    # ML exploitation probability contribution (max ML_EXPLOITATION_MAX)
    # Uses the XGBoost model prediction from Tier 1 pipeline.
    # ZERO contribution when Tier 1 was not run (e.g. auto-resolved at Tier 0).
    ml_exploitation = 0
    if tier_1_result and tier_1_result.get("exploitation_probability") is not None:
        ml_exploitation = _round_half_up(
            tier_1_result["exploitation_probability"]
            * SCORING_WEIGHTS["ml_exploitation"]
        )
    dimensions["ml_exploitation"] = ml_exploitation

    # Security Context (max SECURITY_CONTEXT_MAX) — Sprint 17
    security_context = round(telemetry_threat_score * 3 + network_blast_radius * 2)
    security_context = max(CLAMP_MIN, min(SECURITY_CONTEXT_MAX, security_context))
    dimensions["security_context"] = security_context

    # Asset criticality (max CRITICALITY_MAX) — based on data classification and mission tags
    # POLICY NOTE: The 12/4/0 point spread for OFFICIAL Sensitive/OFFICIAL is an
    # operational policy choice calibrated against WA SOC risk appetite.
    # It is NOT mandated by WAICP itself.
    criticality = 0
    if data_classification == "OFFICIAL Sensitive":
        criticality += 12
    elif data_classification == "OFFICIAL":
        criticality += 4
    if mission_prevalence == "Core":
        criticality += 6
    elif mission_prevalence == "Support":
        criticality += 2
    if public_wellbeing == "Severe":
        criticality += 2
    elif public_wellbeing == "Moderate":
        criticality += 1
    dimensions["criticality"] = min(CRITICALITY_MAX, criticality)

    # Exposure (max EXPOSURE_MAX — actual code only produces 3 for internal or 12 for internet-facing)
    exposure = 0
    if internet_facing:
        exposure += 12
    else:
        exposure += 3
    dimensions["exposure"] = exposure

    # Patch availability (max PATCH_MAX)
    patch_score = 0
    if not patch_available:
        patch_score = 0  # no remediation available — neutral, not punitive
    elif patch_available and patch_applied:
        patch_score = PATCH_MAX  # remediated
    else:
        patch_score = 0  # patch exists but not applied — overdue
    dimensions["patch"] = patch_score

    total = sum(dimensions.values())

    # Apply Tier 2 adjustments if available
    if tier_2_result and tier_2_result.get("score_adjustment"):
        adjustment = max(-20, min(20, tier_2_result["score_adjustment"]))
        total += adjustment

    total = max(CLAMP_MIN, min(CLAMP_MAX, total))

    # Map to band
    if total <= 25:
        band = "Low"
    elif total <= 50:
        band = "Medium"
    elif total <= 75:
        band = "Critical"
    else:
        band = "Very Critical"

    return {"total": total, "band": band, "dimensions": dimensions}
