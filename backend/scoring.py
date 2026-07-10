"""
Final priority score calculation.

Combines outputs from all pipeline stages into a score
with per-dimension breakdown for the frontend scoring weights display.

Weights sum to 107 (CVSS 40 + EPSS 20 + criticality 20 + exposure 12 +
patch 5 + ml_exploitation 10). The final total is clamped to 0-100.

Security Context was removed as a dimension in Sprint 21 and replaced
by a proportional multiplier (1.20/1.10/1.00/0.85/0.70) applied to the
total score before Tier 2 adjustment.
"""

from pipeline.config.scoring import (
    SCORING_WEIGHTS,
    CLAMP_MIN,
    CLAMP_MAX,
    CRITICALITY_MAX,
    PATCH_MAX,
    CONTEXT_MULTIPLIER_VALUES,
    TELEMETRY_ACTIVE_THRESHOLD,
)


def _round_half_up(x):
    """Round to nearest int, .5 always rounds up (not banker's rounding)."""
    return int(x + 0.5)


def _determine_context_multiplier(
    telemetry_threat_score: float,
    vulnerable_code_loaded: bool | None = None,
    confirmed_mitigated: bool = False,
    confirmed_false_positive: bool = False,
) -> float:
    """Determine the security context multiplier based on telemetry evidence.

    Returns one of: 1.20, 1.10, 1.00, 0.85, 0.70

    Decision matrix (evaluated in order, first match wins):
    1. confirmed_false_positive → 0.70
    2. confirmed_mitigated → 0.85
    3. telemetry_threat_score >= 3.0 AND vulnerable_code_loaded == True → 1.20
    4. telemetry_threat_score >= 3.0 XOR vulnerable_code_loaded == True → 1.10
    5. default → 1.00 (neutral, no penalty for missing data)

    NOTE: network_blast_radius was explicitly excluded from the multiplier model.
    Blast radius is a static network property already captured in the Exposure
    dimension. Only dynamic threat evidence (telemetry + code load status)
    drives the multiplier.

    The telemetry active threshold (3.0) is on a 0-10 threat score scale.
    """
    # Order matters: first match wins
    if confirmed_false_positive:
        return CONTEXT_MULTIPLIER_VALUES["false_positive"]
    if confirmed_mitigated:
        return CONTEXT_MULTIPLIER_VALUES["mitigated"]

    telemetry_active = telemetry_threat_score >= TELEMETRY_ACTIVE_THRESHOLD
    code_loaded = vulnerable_code_loaded is True

    if telemetry_active and code_loaded:
        return CONTEXT_MULTIPLIER_VALUES["active_threat_loaded"]
    if telemetry_active or code_loaded:
        return CONTEXT_MULTIPLIER_VALUES["partial_evidence"]

    return CONTEXT_MULTIPLIER_VALUES["neutral"]


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
    vulnerable_code_loaded: bool | None = None,
    confirmed_mitigated: bool = False,
    confirmed_false_positive: bool = False,
) -> dict:
    """
    Calculate the priority score from six weighted dimensions plus a security context
    multiplier and optional Tier 2 score adjustment.
    Weights sum to 107; final total is clamped to 0-100.

    Returns a dict with per-dimension breakdown, context_multiplier, and band.

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
        telemetry_threat_score: Threat score from security telemetry (0-10)
        network_blast_radius: Network blast radius score (retained for backward compat)
        vulnerable_code_loaded: Whether vulnerable code is loaded in memory
        confirmed_mitigated: Whether the vulnerability is confirmed mitigated
        confirmed_false_positive: Whether the finding is a confirmed false positive

    Returns:
        dict with 'total' (0-100), 'band', 'dimensions', and 'context_multiplier'
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

    # Apply multiplier BEFORE Tier 2 adjustment
    # Rationale: Multiplier reflects deterministic environmental context (telemetry).
    # Tier 2 LLM adjustment should have the final say on top of context-adjusted score.
    context_multiplier = _determine_context_multiplier(
        telemetry_threat_score=telemetry_threat_score,
        vulnerable_code_loaded=vulnerable_code_loaded,
        confirmed_mitigated=confirmed_mitigated,
        confirmed_false_positive=confirmed_false_positive,
    )
    total = round(total * context_multiplier)

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

    # DEPRECATED: security_context was removed in Sprint 21 (replaced by multiplier).
    # Keep field set to 0 for backward compatibility with API consumers.
    dimensions["security_context"] = 0

    return {
        "total": total,
        "band": band,
        "dimensions": dimensions,
        "context_multiplier": context_multiplier,
    }
