"""
Read-only configuration endpoint.
Exposes all TriageMate config values grouped by domain.
No auth required — config values are not sensitive.
"""

import logging
from fastapi import APIRouter
from pipeline.config import thresholds, scoring, feature_names

logger = logging.getLogger("triagemate.config")
router = APIRouter(tags=["Config"])


@router.get("/api/config")
def get_config():
    """Return all config values grouped by domain."""
    return {
        "thresholds": {
            "nvd_ref_threshold": thresholds.NVD_REF_THRESHOLD,
            "kev_cvss_threshold": thresholds.KEV_CVSS_THRESHOLD,
            "kev_epss_threshold": thresholds.KEV_EPSS_THRESHOLD,
            "low_cvss_threshold": thresholds.LOW_CVSS_THRESHOLD,
            "low_epss_threshold": thresholds.LOW_EPSS_THRESHOLD,
            "cwe_epss_thresholds": thresholds.CWE_EPSS_THRESHOLDS,
            "default_epss_threshold": thresholds.DEFAULT_EPSS_THRESHOLD,
            "low_prob_threshold": thresholds.LOW_PROB_THRESHOLD,
            "mid_prob_threshold": thresholds.MID_PROB_THRESHOLD,
            "high_prob_threshold": thresholds.HIGH_PROB_THRESHOLD,
            "uncertainty_threshold": thresholds.UNCERTAINTY_THRESHOLD,
            "drift_warning_psi": thresholds.DRIFT_WARNING_PSI,
            "drift_critical_psi": thresholds.DRIFT_CRITICAL_PSI,
        },
        "scoring": {
            "weights": scoring.SCORING_WEIGHTS,
            "total_weight": scoring.TOTAL_WEIGHT,
            "clamp_min": scoring.CLAMP_MIN,
            "clamp_max": scoring.CLAMP_MAX,
            "context_multiplier": scoring.CONTEXT_MULTIPLIER_VALUES,
            "telemetry_active_threshold": scoring.TELEMETRY_ACTIVE_THRESHOLD,
        },
        "feature_names": {
            "tabular_count": len(feature_names.TABULAR_FEATURE_ORDER),
            "tabular_names": feature_names.TABULAR_FEATURE_ORDER,
        },
    }
