"""
Tier 1 XGBoost exploitation probability predictor.

Loads the trained XGBoost model and provides a predict() function
for the 35 tabular features + CVE description text.

Supports model version management via model_registry.json — the active
model can be changed at runtime with set_active_version().
"""

import json
import logging
import threading

import numpy as np
import xgboost as xgb
import joblib
from pathlib import Path

from ml.encoder import encode_description

from pipeline.config.thresholds import (
    CWE_EPSS_THRESHOLDS,
    DEFAULT_EPSS_THRESHOLD,
    LOW_PROB_THRESHOLD,
    MID_PROB_THRESHOLD,
    UNCERTAINTY_THRESHOLD,
)
from pipeline.config.feature_names import TABULAR_FEATURE_ORDER

logger = logging.getLogger(__name__)

# Default paths (fallbacks when registry is unavailable)
MODEL_FILE = Path(__file__).parent / "xgboost_model.pkl"
CALIBRATOR_FILE = Path(__file__).parent / "xgboost_calibrator.pkl"
THRESHOLD_INFO_FILE = Path(__file__).parent / "threshold_info.json"
PCA_MODEL_PATH = Path(__file__).parent / "pca_model.pkl"

REGISTRY_PATH = Path(__file__).parent / "model_registry.json"

# Dynamic model paths — initialised from registry at import time.
# Fall back to default constants if the registry cannot be read.
_active_model_path: Path = MODEL_FILE
_active_calibrator_path: Path | None = CALIBRATOR_FILE
_active_threshold_path: Path | None = THRESHOLD_INFO_FILE

_model = None
_calibrator = None
_pca_model = None
_lock = threading.Lock()


def _get_model():
    global _model
    if _model is None:
        with _lock:
            if _model is None:
                model_path = _active_model_path
                if not model_path.exists():
                    raise FileNotFoundError(
                        f"XGBoost model not found at {model_path}. "
                        "Run the training pipeline first."
                    )
                _model = joblib.load(model_path)
    return _model


def _get_calibrator():
    global _calibrator
    cal_path = _active_calibrator_path
    if _calibrator is None and cal_path is not None and cal_path.exists():
        with _lock:
            if _calibrator is None and cal_path is not None and cal_path.exists():
                _calibrator = joblib.load(cal_path)
    return _calibrator


# ── PCA dimensionality reduction ─────────────────────────────────
# Apply PCA to SBERT embeddings if PCA model exists.
# Graceful degradation: if PCA model is missing, use raw 384-dim embeddings.


def _load_pca():
    """Load PCA model from disk. Returns None if not available."""
    global _pca_model
    if _pca_model is None and PCA_MODEL_PATH.exists():
        _pca_model = joblib.load(PCA_MODEL_PATH)
        logger.info("PCA model loaded: %d components", _pca_model.n_components_)
    return _pca_model


def _apply_pca(text_vec: np.ndarray) -> np.ndarray:
    """Apply PCA to SBERT embedding. Returns reduced or original vector."""
    pca = _load_pca()
    if pca is not None:
        return pca.transform(text_vec.reshape(1, -1))
    logger.debug("PCA model not found — using raw 384-dim embedding")
    return text_vec.reshape(1, -1)


def _read_registry() -> dict:
    """Read the model registry JSON file. Returns empty structure on error."""
    try:
        if REGISTRY_PATH.exists():
            with open(REGISTRY_PATH) as f:
                return json.load(f)
    except Exception:
        pass
    return {"active_version": None, "versions": []}


def _init_active_paths_from_registry():
    """Initialise module-level path variables from the model registry.

    Called at import time and after registry changes. Falls back to default
    constants if the registry cannot be read or the active version is unknown.
    """
    global _active_model_path, _active_calibrator_path, _active_threshold_path
    registry = _read_registry()
    active_version = registry.get("active_version")
    if active_version:
        base = Path(__file__).parent
        for v in registry.get("versions", []):
            if v["version"] == active_version:
                _active_model_path = base / v["model_file"]
                _active_calibrator_path = (
                    base / v["calibrator_file"] if v.get("calibrator_file") else None
                )
                _active_threshold_path = (
                    base / v["threshold_file"] if v.get("threshold_file") else None
                )
                return
    # Fallback to defaults
    _active_model_path = MODEL_FILE
    _active_calibrator_path = CALIBRATOR_FILE
    _active_threshold_path = THRESHOLD_INFO_FILE


def set_active_version(version: str):
    """Switch the active XGBoost model version at runtime.

    Reads the registry to resolve *version* to file paths, updates the
    module-level path variables, and resets the in-memory model/calibrator
    cache so the next call to predict() triggers a lazy reload.

    Thread-safe: acquires the same _lock used by _get_model() / _get_calibrator().
    """
    global _active_model_path, _active_calibrator_path, _active_threshold_path
    global _model, _calibrator

    registry = _read_registry()
    base = Path(__file__).parent
    found = None
    for v in registry.get("versions", []):
        if v["version"] == version:
            found = v
            break

    if found is None:
        raise ValueError(f"Version '{version}' not found in model registry.")

    with _lock:
        _active_model_path = base / found["model_file"]
        _active_calibrator_path = (
            base / found["calibrator_file"] if found.get("calibrator_file") else None
        )
        _active_threshold_path = (
            base / found["threshold_file"] if found.get("threshold_file") else None
        )
        # Invalidate in-memory cache — forces lazy reload on next predict()
        _model = None
        _calibrator = None


def get_active_version_info() -> dict:
    """Return the active version's metadata from the registry."""
    registry = _read_registry()
    active_version = registry.get("active_version")
    if active_version:
        for v in registry.get("versions", []):
            if v["version"] == active_version:
                return {
                    "version": v["version"],
                    "label": v["label"],
                    "metrics": v.get("metrics", {}),
                    "created_at": v.get("created_at", ""),
                }
    return {"version": None, "label": "", "metrics": {}, "created_at": ""}


# ── Initialise active paths from registry at module load time ────────
_init_active_paths_from_registry()


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
        "cvss_c": 0,
        "cvss_i": 0,
        "cvss_a": 0,
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
        "patch_available": False,
        "domain_joined": False,
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

    Uses the multi-window KEV model (5-class softprob) to produce:
    - exploitation_probability: probability of ANY KEV membership (0-1)
    - window_probabilities: per-window breakdown for transparency

    Required features:
        epss_score, mission_prevalence, public_wellbeing_impact,
        internet_facing, description (CVE text, optional)
    All other 35 features default to neutral values when missing.
    Note: cvss_score is NOT consumed by this function — it is used directly
    by the scoring engine (scoring.py), not by the XGBoost model.

    Returns:
        exploitation_probability (0-1), window_probabilities (dict),
        confidence (0-1), routing (auto_resolved|escalated),
        ensemble_std (float), tier (str)
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

    # Apply PCA to SBERT embedding if PCA model is available
    pca = _load_pca()
    if pca is not None:
        text_vec = pca.transform(text_vec)
        # text_vec is now (1, n_components)

    X = np.hstack([tabular, text_vec])

    # predict_proba output shape depends on model version:
    #   - Multi-class (v4+):  (1, 5) — per-window probabilities
    #   - Binary (legacy):    (1, 2) — negative/positive class
    raw_probs = model.predict_proba(X)[0]
    n_classes = len(raw_probs)

    if n_classes == 5:
        # Multi-window KEV model (5-class softprob)
        probabilities = raw_probs
        prob_any_kev = float(probabilities[1:].sum())
        window_probs = {
            "not_kev": float(probabilities[0]),
            "window_30d": float(probabilities[1]),
            "window_90d": float(probabilities[2]),
            "window_365d": float(probabilities[3]),
            "window_gt_365d": float(probabilities[4]),
        }
    elif n_classes == 2:
        # Legacy binary model — prob[1] is the positive (KEV) class
        prob_any_kev = float(raw_probs[1])
        window_probs = {
            "not_kev": float(raw_probs[0]),
            "window_30d": 0.0,
            "window_90d": 0.0,
            "window_365d": 0.0,
            "window_gt_365d": 0.0,
        }
    else:
        # Fallback: unexpected number of classes
        prob_any_kev = (
            float(raw_probs[-1]) if len(raw_probs) > 1 else float(raw_probs[0])
        )
        window_probs = {
            "not_kev": 1.0 - prob_any_kev,
            "window_30d": 0.0,
            "window_90d": 0.0,
            "window_365d": 0.0,
            "window_gt_365d": 0.0,
        }

    # Calibrate probability if a Platt scaler exists (applied to any-KEV prob)
    calibrator = _get_calibrator()
    if calibrator is not None:
        prob_any_kev = float(calibrator.predict_proba([[prob_any_kev]])[0, 1])

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
    # Uses any-KEV probability for backward-compatible routing decisions.
    if prob_any_kev >= MID_PROB_THRESHOLD:
        routing = "escalated"
    elif prob_any_kev >= LOW_PROB_THRESHOLD:
        if ensemble_std > UNCERTAINTY_THRESHOLD:
            routing = "escalated"
        else:
            routing = "auto_resolved"
    else:
        routing = "auto_resolved"

    return {
        "exploitation_probability": round(prob_any_kev, 3),
        "window_probabilities": window_probs,
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
