"""
Pre-Tier: Multi-label classifier for mission tags (Mission Prevalence and
Public Well-Being Impact).

Architecture:
  Phase 1 (KNOWN_TAGS — primary): Checks the KNOWN_TAGS dict first for the
                       31 known demo hosts (all using WAICP OFFICIAL/OFFICIAL
                       Sensitive classifications). This is the fastest path
                       and covers all demo hosts.
  Phase 2 (ML — fallback): Uses a trained MultiOutputClassifier(RandomForestClassifier)
                 from backend/ml/pre_tier_model.pkl to predict tags for any
                 hostname based on hostname-derived features (unknown hosts).
  Phase 3 (Default — last resort): Returns Support/Minimal with 0.60 confidence
                 when neither KNOWN_TAGS nor ML model can produce a result.

The return dict shape (API contract) NEVER changes:
  {
      "mission_prevalence": str,            # "Core" | "Support" | "Peripheral"
      "mission_prevalence_confidence": float,  # 0.0-1.0
      "public_wellbeing_impact": str,       # "Severe" | "Moderate" | "Minimal"
      "public_wellbeing_confidence": float,     # 0.0-1.0
  }
"""

import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

# ─── PHASE 0: KNOWN HOSTS (Demo / Fallback) ────────────────────────────────

KNOWN_TAGS = {
    # Original 7 (1 renamed)
    "per-PRD-MOVEIT-WEB01.health.wa.gov.au": ("Core", 0.94, "Severe", 0.96),
    "per-PRD-CITRIX-ADC01.transport.wa.gov.au": ("Core", 0.91, "Moderate", 0.88),
    "per-PRD-PRINT-SVR05.education.wa.edu.au": ("Support", 0.85, "Minimal", 0.82),
    "per-PRD-RMM-GW01.sharedservices.wa.gov.au": ("Support", 0.87, "Moderate", 0.84),
    "per-PRD-FILE-STORE02.communities.wa.gov.au": ("Core", 0.92, "Severe", 0.95),
    "per-PRD-WIKI-CORE01.police.wa.gov.au": ("Core", 0.93, "Moderate", 0.86),
    "per-PRD-ITSM-TOOL01.finance.wa.gov.au": ("Support", 0.89, "Minimal", 0.91),
    # New 23
    "per-PRD-EHR-APP01.health.wa.gov.au": ("Core", 0.93, "Severe", 0.95),
    "per-PRD-SQL-CLUSTER01.health.wa.gov.au": ("Core", 0.91, "Severe", 0.94),
    "per-PRD-FILE-SAN01.health.wa.gov.au": ("Core", 0.90, "Severe", 0.93),
    "per-PRD-MARINE-DOC01.transport.wa.gov.au": ("Core", 0.88, "Moderate", 0.87),
    "per-PRD-TEMIS-APP01.transport.wa.gov.au": ("Core", 0.89, "Moderate", 0.86),
    "per-PRD-STUDENT-DB01.education.wa.edu.au": ("Core", 0.92, "Moderate", 0.90),
    "per-PRD-EDU-IDM01.education.wa.edu.au": ("Support", 0.87, "Moderate", 0.85),
    "per-PRD-CASEMGT-APP01.communities.wa.gov.au": ("Core", 0.94, "Severe", 0.95),
    "per-PRD-CAD-DISPATCH01.police.wa.gov.au": ("Core", 0.95, "Severe", 0.96),
    "per-PRD-BUDGET-DB01.finance.wa.gov.au": ("Support", 0.86, "Minimal", 0.88),
    "per-PRD-COURT-FILE01.justice.wa.gov.au": ("Core", 0.93, "Severe", 0.95),
    "per-PRD-JURY-DB01.justice.wa.gov.au": ("Core", 0.90, "Moderate", 0.89),
    "per-PRD-WTR-SCADA01.watercorporation.com.au": ("Core", 0.94, "Severe", 0.95),
    "per-PRD-FIRE-COMMS01.dfes.wa.gov.au": ("Core", 0.93, "Severe", 0.96),
    "per-PRD-ES-DISPATCH01.dfes.wa.gov.au": ("Core", 0.92, "Severe", 0.95),
    "per-PRD-SSC-PROXY01.sharedservices.wa.gov.au": ("Support", 0.85, "Minimal", 0.86),
    "per-PRD-EXCHANGE-CAS01.health.wa.gov.au": ("Core", 0.91, "Severe", 0.94),
    "per-PRD-FLEET-MGMT01.transport.wa.gov.au": ("Support", 0.86, "Moderate", 0.85),
    "per-PRD-STAFFPORTAL01.education.wa.edu.au": ("Support", 0.87, "Minimal", 0.86),
    "per-PRD-SAP-FIN01.finance.wa.gov.au": ("Core", 0.90, "Moderate", 0.88),
    "per-PRD-LEGAL-DB01.justice.wa.gov.au": ("Core", 0.91, "Moderate", 0.89),
    "per-PRD-EMS-OPS01.dfes.wa.gov.au": ("Core", 0.93, "Severe", 0.95),
    "per-PRD-PARLIAMENT-WEB01.parliament.wa.gov.au": (
        "Support",
        0.88,
        "Moderate",
        0.87,
    ),
    "per-PRD-AQIS-DB01.dpird.wa.gov.au": ("Support", 0.86, "Moderate", 0.85),
}

# ─── MODEL (lazy-loaded) ────────────────────────────────────────────────────

_model_data = None
_model_attempted = False
_lock = threading.Lock()

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
    with _lock:
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


def predict_mission_tags(hostname: str) -> dict:
    """
    Predict mission prevalence and public well-being impact for an asset.

    Resolution order:
      1. KNOWN_TAGS dict (31 demo hosts) — always returns hardcoded values
         with original confidence scores.
      2. ML model (if available) — for unknown hosts, extracts hostname
         features and runs the trained classifier.
      3. Default fallback — Support / Minimal with 0.60 confidence.

    Args:
        hostname: The fully qualified hostname of the asset

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


def extract_pre_tier_features(hostname: str) -> dict:
    """Extract the 60-dim Pre-Tier feature vector for drift monitoring.

    Uses the same ml.pretier_features.extract_features() as the model prediction.
    Returns a dict of feature_name: value suitable for JSON serialization and drift computation.
    """
    from ml.pretier_features import extract_features as _extract

    features = _extract(hostname)
    if features is None:
        return {}
    return features
