"""
Tier 1 XGBoost exploitation probability predictor.

Loads the trained XGBoost model and provides a predict() function
for the 37 tabular features + CVE description text.
"""

import numpy as np
import joblib
from pathlib import Path

from ml.encoder import encode_description

MODEL_FILE = Path(__file__).parent / "xgboost_model.pkl"
ESCALATION_STD_THRESHOLD = 0.15

_model = None


def _get_model():
    global _model
    if _model is None:
        if not MODEL_FILE.exists():
            raise FileNotFoundError(
                f"XGBoost model not found at {MODEL_FILE}. "
                "Run the training pipeline first."
            )
        _model = joblib.load(MODEL_FILE)
    return _model


def predict(features: dict) -> dict:
    """
    Predict exploitation probability for a vulnerability + asset combination.

    Required features:
        cvss_score, epss_score, mission_prevalence, public_wellbeing_impact,
        internet_facing, description (CVE text, optional)
    All other 37 features default to neutral values when missing.

    Returns:
        exploitation_probability (0-1), confidence (0-1),
        routing (auto_resolved|escalated), ensemble_std (float)
    """
    model = _get_model()

    if hasattr(model, "calibrated_classifiers_"):
        xgb_model = model.calibrated_classifiers_[0].base_estimator
    else:
        xgb_model = model

    description = features.get("description", "")

    tabular = np.array([[
        features.get("cvss_av", 3),
        features.get("cvss_ac", 1),
        features.get("cvss_pr", 2),
        features.get("cvss_ui", 1),
        features.get("cvss_s", 0),
        features.get("cvss_c", 2),
        features.get("cvss_i", 2),
        features.get("cvss_a", 2),
        features.get("epss_score", 0.0),
        int(features.get("patch_available", True)),
        int(features.get("patch_applied", False)),
        int(features.get("internet_facing", False)),
        int(features.get("domain_joined", True)),
        _encode_classification(features.get("data_classification", "Category 2")),
        _encode_mission(features.get("mission_prevalence", "Support")),
        _encode_wellbeing(features.get("public_wellbeing_impact", "Minimal")),
        features.get("lateral_reachability", 0),
        features.get("boundary_reachability", 0),
        features.get("downstream_assets", 0),
        features.get("patch_lag_days", 0),
        int(features.get("exploitdb_has_poc", False)),
        int(features.get("metasploit_has_payload", False)),
        int(features.get("greynoise_active_scan", False)),
        features.get("otx_threat_pulses", 0),
        features.get("nvd_reference_count", 0),
        features.get("cve_desc_tokens", 0),
        features.get("vulnerability_age_days", 0),
        features.get("vendor_popularity_index", 0.0),
        features.get("cvss_exploitability_sub", 0.0),
        features.get("cvss_impact_sub", 0.0),
        int(features.get("is_top_25_cwe", False)),
        int(features.get("is_rce_signature", False)),
        int(features.get("is_privesc_signature", False)),
        int(features.get("is_bypass_signature", False)),
        int(features.get("is_dos_signature", False)),
        int(features.get("is_traversal_signature", False)),
    ]], dtype=np.float32)

    if description:
        try:
            text_vec = encode_description(description).reshape(1, -1)
        except FileNotFoundError:
            text_vec = np.zeros((1, 32), dtype=np.float32)
    else:
        text_vec = np.zeros((1, 32), dtype=np.float32)

    X = np.hstack([tabular, text_vec])

    prob = float(model.predict_proba(X)[0, 1])

    n_trees = xgb_model.n_estimators
    booster = xgb_model.get_booster()
    step_size = max(min(100, n_trees // 8), 1)
    cumulative_probs = []
    for n_t in range(step_size, n_trees + step_size, step_size):
        n_t = min(n_t, n_trees)
        margin = booster.predict(
            X, iteration_range=(0, n_t), output_margin=True
        )
        p = float(1.0 / (1.0 + np.exp(-margin[0])))
        cumulative_probs.append(p)

    ensemble_std = float(np.std(cumulative_probs))
    routing = "escalated" if ensemble_std > ESCALATION_STD_THRESHOLD else "auto_resolved"

    return {
        "exploitation_probability": round(prob, 3),
        "confidence": round(1.0 - min(ensemble_std * 2, 1.0), 3),
        "routing": routing,
        "ensemble_std": round(ensemble_std, 4),
    }


def _encode_classification(klass: str) -> int:
    mapping = {"Category 4": 4, "Category 3": 3, "Category 2": 2, "Category 1": 1}
    return mapping.get(klass, 2)


def _encode_mission(mission: str) -> int:
    mapping = {"Core": 3, "Support": 2, "Peripheral": 1}
    return mapping.get(mission, 2)


def _encode_wellbeing(wellbeing: str) -> int:
    mapping = {"Severe": 3, "Moderate": 2, "Minimal": 1}
    return mapping.get(wellbeing, 1)
