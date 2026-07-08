"""
Tier 1 XGBoost exploitation probability predictor.

Loads the trained XGBoost model and provides a predict() function
for the 35 tabular features + CVE description text.
"""

import threading

import numpy as np
import xgboost as xgb
import joblib
from pathlib import Path

from ml.encoder import encode_description

MODEL_FILE = Path(__file__).parent / "xgboost_model.pkl"
CALIBRATOR_FILE = Path(__file__).parent / "xgboost_calibrator.pkl"
THRESHOLD_INFO_FILE = Path(__file__).parent / "threshold_info.json"

# Probability + uncertainty zoning thresholds for routing decisions.
LOW_PROB_THRESHOLD = 0.20
MID_PROB_THRESHOLD = 0.40
HIGH_PROB_THRESHOLD = 0.50
UNCERTAINTY_THRESHOLD = 0.10

# Pre-model EPSS thresholds by CWE — fast-path bypass before XGBoost inference.
CWE_EPSS_THRESHOLDS = {
    "CWE-22": 0.085,  # Path Traversal
    "CWE-78": 0.515,  # OS Command Injection
    "CWE-787": 0.716,  # Out-of-bounds Write
    "CWE-79": 0.600,  # XSS
    "CWE-89": 0.500,  # SQL Injection
    "CWE-416": 0.550,  # Use-After-Free
    "CWE-20": 0.400,  # Input Validation
    "CWE-843": 0.300,  # Type Confusion (10.9× KEV rate)
}
DEFAULT_EPSS_THRESHOLD = 0.84

# Tabular feature keys in the EXACT order xgboost_predictor.predict() builds
# the feature vector for XGBoost inference. Must match build_tabular_features()
# in train_xgboost.py index-by-index. 35 features total.
TABULAR_FEATURE_ORDER = [
    "cvss_av",
    "cvss_ac",
    "cvss_pr",
    "cvss_ui",
    "cvss_s",
    "cvss_c",
    "cvss_i",
    "cvss_a",
    "epss_score",
    "patch_available",
    "patch_applied",
    "internet_facing",
    "domain_joined",
    "data_classification",
    "mission_prevalence",
    "public_wellbeing_impact",
    "lateral_reachability",
    "boundary_reachability",
    "downstream_assets",
    "patch_lag_days",
    "exploitdb_has_poc",
    "metasploit_has_payload",
    "threat_intel_pulses",
    "nvd_reference_count",
    "cve_desc_tokens",
    "vulnerability_age_days",
    "vendor_popularity_index",
    "cvss_exploitability_sub",
    "cvss_impact_sub",
    "is_top_25_cwe",
    "is_rce_signature",
    "is_privesc_signature",
    "is_bypass_signature",
    "is_dos_signature",
    "is_traversal_signature",
]

_model = None
_calibrator = None
_lock = threading.Lock()


def _get_model():
    global _model
    if _model is None:
        with _lock:
            if _model is None:
                if not MODEL_FILE.exists():
                    raise FileNotFoundError(
                        f"XGBoost model not found at {MODEL_FILE}. "
                        "Run the training pipeline first."
                    )
                _model = joblib.load(MODEL_FILE)
    return _model


def _get_calibrator():
    global _calibrator
    if _calibrator is None and CALIBRATOR_FILE.exists():
        with _lock:
            if _calibrator is None and CALIBRATOR_FILE.exists():
                _calibrator = joblib.load(CALIBRATOR_FILE)
    return _calibrator


def _tier_zero_check(features: dict) -> dict | None:
    """Pre-model check: if EPSS + CWE signal is strong enough, skip XGBoost."""
    cwe = features.get("cwe_class", "")
    epss = features.get("epss_score", 0.0)
    kev = features.get("cisa_kev", False)

    # KEV fast-path: CISA has already confirmed exploitation
    if kev and epss >= 0.30:
        return {
            "exploitation_probability": 0.95,
            "confidence": 0.90,
            "routing": "escalated",
            "ensemble_std": 0.0,
            "tier": "tier_0_kev",
        }

    # CWE-stratified EPSS threshold
    threshold = CWE_EPSS_THRESHOLDS.get(cwe, DEFAULT_EPSS_THRESHOLD)
    if epss >= threshold:
        return {
            "exploitation_probability": round(min(0.99, epss + 0.10), 3),
            "confidence": 0.70,
            "routing": "escalated",
            "ensemble_std": 0.0,
            "tier": "tier_0_epss",
        }

    return None


def _build_tabular_array(features: dict) -> np.ndarray:
    """Build tabular feature array from features dict using TABULAR_FEATURE_ORDER.

    Each key in TABULAR_FEATURE_ORDER maps to a feature extractor:
    - Boolean fields use int(features.get(key, default))
    - Categorical fields use encoding helpers
    - Numeric fields use features.get(key, default)
    """
    # Per-key defaults and extraction logic
    _defaults = {
        "cvss_av": 3,
        "cvss_ac": 1,
        "cvss_pr": 2,
        "cvss_ui": 1,
        "cvss_s": 0,
        "cvss_c": 2,
        "cvss_i": 2,
        "cvss_a": 2,
        "epss_score": 0.0,
        "lateral_reachability": 0,
        "boundary_reachability": 0,
        "downstream_assets": 0,
        "patch_lag_days": 0,
        "threat_intel_pulses": 0,
        "nvd_reference_count": 0,
        "cve_desc_tokens": 0,
        "vulnerability_age_days": 0,
        "vendor_popularity_index": 0.0,
        "cvss_exploitability_sub": 0.0,
        "cvss_impact_sub": 0.0,
    }
    _bool_keys = {
        "patch_available",
        "patch_applied",
        "internet_facing",
        "domain_joined",
        "exploitdb_has_poc",
        "metasploit_has_payload",
        "is_top_25_cwe",
        "is_rce_signature",
        "is_privesc_signature",
        "is_bypass_signature",
        "is_dos_signature",
        "is_traversal_signature",
    }
    _bool_defaults = {
        "patch_available": True,
        "domain_joined": True,
    }

    row = []
    for key in TABULAR_FEATURE_ORDER:
        if key == "data_classification":
            val = _encode_classification(features.get(key, "OFFICIAL"))
        elif key == "mission_prevalence":
            val = _encode_mission(features.get(key, "Support"))
        elif key == "public_wellbeing_impact":
            val = _encode_wellbeing(features.get(key, "Minimal"))
        elif key in _bool_keys:
            default = _bool_defaults.get(key, False)
            val = int(features.get(key, default))
        else:
            val = features.get(key, _defaults.get(key, 0.0))
        row.append(val)

    return np.array([row], dtype=np.float32)


def predict(features: dict) -> dict:
    """
    Predict exploitation probability for a vulnerability + asset combination.

    Required features:
        epss_score, mission_prevalence, public_wellbeing_impact,
        internet_facing, description (CVE text, optional)
    All other 35 features default to neutral values when missing.
    Note: cvss_score is NOT consumed by this function — it is used directly
    by the scoring engine (scoring.py), not by the XGBoost model.

    Returns:
        exploitation_probability (0-1), confidence (0-1),
        routing (auto_resolved|escalated), ensemble_std (float)
    """
    # Tier-0: KEV + CWE-stratified EPSS before model inference
    tier0 = _tier_zero_check(features)
    if tier0 is not None:
        return tier0

    model = _get_model()

    if hasattr(model, "calibrated_classifiers_"):
        xgb_model = model.calibrated_classifiers_[0].base_estimator
    else:
        xgb_model = model

    description = features.get("description", "")

    tabular = _build_tabular_array(features)

    if description:
        text_vec = encode_description(description).reshape(1, -1)
    else:
        text_vec = np.zeros((1, 384), dtype=np.float32)

    X = np.hstack([tabular, text_vec])

    prob = float(model.predict_proba(X)[0, 1])

    # Calibrate probability if a Platt scaler exists
    calibrator = _get_calibrator()
    if calibrator is not None:
        prob = float(calibrator.predict_proba([[prob]])[0, 1])

    n_trees = xgb_model.n_estimators
    booster = xgb_model.get_booster()
    dmat = xgb.DMatrix(X)
    step_size = max(min(100, n_trees // 8), 1)
    cumulative_probs = []
    for n_t in range(step_size, n_trees + step_size, step_size):
        n_t = min(n_t, n_trees)
        margin = booster.predict(dmat, iteration_range=(0, n_t), output_margin=True)
        p = float(1.0 / (1.0 + np.exp(-margin[0])))
        cumulative_probs.append(p)

    ensemble_std = float(np.std(cumulative_probs))

    # Combined probability + uncertainty zoning routing.
    if prob >= MID_PROB_THRESHOLD:
        routing = "escalated"
    elif prob >= LOW_PROB_THRESHOLD:
        if ensemble_std > UNCERTAINTY_THRESHOLD:
            routing = "escalated"
        else:
            routing = "auto_resolved"
    else:
        routing = "auto_resolved"

    return {
        "exploitation_probability": round(prob, 3),
        "confidence": round(1.0 - min(ensemble_std * 2, 1.0), 3),
        "routing": routing,
        "ensemble_std": round(ensemble_std, 4),
        "tier": "tier_1_xgboost",
    }


def _encode_classification(klass: str) -> int:
    mapping = {
        "OFFICIAL Sensitive": 4,
        "OFFICIAL": 2,
        "Category 1": 1,
    }  # WAICP: OFFICIAL (was PRIS Act Category 1)
    return mapping.get(klass, 2)


def _encode_mission(mission: str) -> int:
    mapping = {"Core": 3, "Support": 2, "Peripheral": 1}
    return mapping.get(mission, 2)


def _encode_wellbeing(wellbeing: str) -> int:
    mapping = {"Severe": 3, "Moderate": 2, "Minimal": 1}
    return mapping.get(wellbeing, 1)
