"""
Pre-Tier: Multi-label classifier for mission tags (Mission Prevalence and
Public Well-Being Impact).

Architecture:
  Phase 1 (ML):  Uses a trained MultiOutputClassifier(RandomForestClassifier)
                 from backend/ml/pre_tier_model.pkl to predict tags for any
                 hostname based on hostname-derived features.
  Phase 0 (Fallback): Falls back to the KNOWN_TAGS dict for the 7 known demo
                      hosts, or returns default values if the model is absent.

The return dict shape (API contract) NEVER changes:
  {
      "mission_prevalence": str,            # "Core" | "Support" | "Peripheral"
      "mission_prevalence_confidence": float,  # 0.0-1.0
      "public_wellbeing_impact": str,       # "Severe" | "Moderate" | "Minimal"
      "public_wellbeing_confidence": float,     # 0.0-1.0
  }
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ─── PHASE 0: KNOWN HOSTS (Demo / Fallback) ────────────────────────────────

KNOWN_TAGS = {
    "PRD-MOVEIT-WEB01.health.wa.gov.au": ("Core", 0.94, "Severe", 0.96),
    "PRD-CITRIX-ADC01.transport.wa.gov.au": ("Core", 0.91, "Moderate", 0.88),
    "PRD-PRINT-SVR05.education.wa.edu.au": ("Support", 0.85, "Minimal", 0.82),
    "PRD-RMM-GW01.sharedservices.wa.gov.au": ("Support", 0.87, "Moderate", 0.84),
    "PRD-FILE-STORE02.communities.wa.gov.au": ("Core", 0.92, "Severe", 0.95),
    "PRD-WIKI-CORE01.wapol.internal.wa.gov.au": ("Core", 0.93, "Moderate", 0.86),
    "PRD-ITSM-TOOL01.finance.wa.gov.au": ("Support", 0.89, "Minimal", 0.91),
}

# ─── MODEL (lazy-loaded) ────────────────────────────────────────────────────

_model_data = None
_model_attempted = False

DEFAULT_RESPONSE = {
    "mission_prevalence": "Support",
    "mission_prevalence_confidence": 0.60,
    "public_wellbeing_impact": "Minimal",
    "public_wellbeing_confidence": 0.60,
}


def _load_model():
    """Load the trained Pre-Tier model from disk (called once on first demand)."""
    global _model_data, _model_attempted
    if _model_attempted:
        return
    _model_attempted = True

    model_path = Path(__file__).parent.parent / "ml" / "pre_tier_model.pkl"
    if not model_path.exists():
        logger.warning(
            "Pre-Tier model not found at %s — using rule-based fallback", model_path
        )
        return

    try:
        import joblib

        _model_data = joblib.load(model_path)
        logger.info(
            "Loaded Pre-Tier model from %s (features=%d)",
            model_path,
            _model_data.get("n_features", "?"),
        )
    except Exception as e:
        logger.warning(
            "Failed to load Pre-Tier model: %s — using rule-based fallback", e
        )
        _model_data = None


def _predict_with_model(hostname: str) -> dict | None:
    """Attempt ML model prediction; returns None on any failure."""
    global _model_data
    if _model_data is None:
        _load_model()
    if _model_data is None:
        return None

    try:
        from ml.pretier_features import extract_features, feature_vector_to_array
        import numpy as np

        features = extract_features(hostname)
        X = np.array([feature_vector_to_array(features)], dtype=np.float64)

        model = _model_data["model"]
        mission_classes = _model_data["classes"]["mission"]
        wellbeing_classes = _model_data["classes"]["wellbeing"]

        # predict returns (n_samples, n_outputs)
        pred_pair = model.predict(X)[0]
        mp_pred_idx = int(pred_pair[0])
        pwi_pred_idx = int(pred_pair[1])

        # predict_proba returns a list of arrays, one per output
        mp_probas = model.predict_proba(X)[0][0]  # shape (n_classes,)
        pwi_probas = model.predict_proba(X)[1][0]

        mp_label = mission_classes[mp_pred_idx]
        pwi_label = wellbeing_classes[pwi_pred_idx]
        mp_conf = float(mp_probas[mp_pred_idx])
        pwi_conf = float(pwi_probas[pwi_pred_idx])

        return {
            "mission_prevalence": mp_label,
            "mission_prevalence_confidence": round(mp_conf, 4),
            "public_wellbeing_impact": pwi_label,
            "public_wellbeing_confidence": round(pwi_conf, 4),
        }
    except Exception as e:
        logger.warning("Pre-Tier model prediction failed for %s: %s", hostname, e)
        return None


# ─── PUBLIC API ─────────────────────────────────────────────────────────────


def predict_mission_tags(hostname: str, ip: str) -> dict:
    """
    Predict mission prevalence and public well-being impact for an asset.

    Resolution order:
      1. KNOWN_TAGS dict (7 demo hosts) — always returns hardcoded values
         with original confidence scores.
      2. ML model (if available) — for unknown hosts, extracts hostname
         features and runs the trained classifier.
      3. Default fallback — Support / Minimal with 0.60 confidence.

    Args:
        hostname: The fully qualified hostname of the asset
        ip: The IP address of the asset (currently unused)

    Returns:
        dict with 'mission_prevalence', 'mission_prevalence_confidence',
        'public_wellbeing_impact', 'public_wellbeing_confidence'
    """
    # Priority 1: Known demo hosts (always exact match)
    if hostname in KNOWN_TAGS:
        mp, mp_conf, pwi, pwi_conf = KNOWN_TAGS[hostname]
        return {
            "mission_prevalence": mp,
            "mission_prevalence_confidence": mp_conf,
            "public_wellbeing_impact": pwi,
            "public_wellbeing_confidence": pwi_conf,
        }

    # Priority 2: ML model
    result = _predict_with_model(hostname)
    if result is not None:
        return result

    # Priority 3: Default fallback
    return dict(DEFAULT_RESPONSE)
