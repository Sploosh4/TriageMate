"""
EPSS substitution — hybrid ML + rule engine (v4 with fallback chain).

Adjusts raw FIRST.org EPSS scores based on sector-specific threat intelligence.
EPSS is a global exploitation probability — it is not sector-aware. This module:

  1. Attempts to use an XGBoost model v4 (backend/ml/epss_model_v4.pkl) for prediction.
  2. Falls back to v3 model (backend/ml/epss_model_v3.pkl) if v4 absent.
  3. Falls back to v2 model (backend/ml/epss_model_v2.pkl) if v3 absent.
  4. Falls back to v1 model (backend/ml/epss_model.pkl) if v2 absent.
  5. Falls back to the heuristic rule engine if no model is available.

The rule engine applies multipliers for CVEs that target specific sectors
(government, healthcare, education, etc.) more than the global average.
"""

import logging
import os
import warnings

import joblib
import numpy as np

warnings.filterwarnings("ignore", category=FutureWarning)

logger = logging.getLogger("triagemate.epss_substitute")

# ── Constants used by both rule engine and ML fallback ────────────────────
CVE_ADJUSTMENTS = {
    "CVE-2023-36884": {
        "health": 8.0,
        "communities": 10.0,
        "police": 6.0,
        "default": 3.0,
        "source": "CISA-Microsoft advisory, GreyNoise sector scan data",
        "date": "2024-01-15",
    },
    "CVE-2023-34362": {
        "health": 8.0,
        "default": 4.0,
        "source": "CISA KEV, Clop ransomware campaign targeting healthcare",
        "date": "2024-03-01",
    },
    "CVE-2023-4966": {
        "health": 5.0,
        "transport": 7.0,
        "default": 3.0,
        "source": "Citrix Bleed attack chain, state-aligned actor targeting perimeter gateways",
        "date": "2024-02-10",
    },
}

CWE_MULTIPLIERS = {
    "CWE-78": 1.5,
    "CWE-434": 1.5,
    "CWE-862": 1.5,
}

KEV_MULTIPLIER = 2.0
DEFAULT_MULTIPLIER = 1.0
MAX_EPSS = 0.99
MAX_CONFIDENCE = 0.95
MIN_CHANGE_THRESHOLD = 0.1

# Feature encoding constants for v1 model
AGENCIES_V1 = [
    "health",
    "transport",
    "education",
    "sharedservices",
    "communities",
    "police",
    "finance",
]

CWES_V1 = [
    "CWE-78",
    "CWE-89",
    "CWE-79",
    "CWE-22",
    "CWE-434",
    "CWE-862",
    "CWE-787",
    "CWE-125",
    "CWE-20",
    "CWE-200",
    "CWE-287",
]

# Feature encoding constants for v2 model
AGENCIES_V2 = [
    "health",
    "transport",
    "education",
    "sharedservices",
    "communities",
    "police",
    "finance",
    "watercorporation",
    "dpird",
    "justice",
]

CWES_V2 = [
    # Original 11
    "CWE-78",
    "CWE-89",
    "CWE-79",
    "CWE-22",
    "CWE-434",
    "CWE-862",
    "CWE-787",
    "CWE-125",
    "CWE-20",
    "CWE-200",
    "CWE-287",
    # New additions (9 more = 20 total)
    "CWE-306",
    "CWE-269",
    "CWE-295",
    "CWE-611",
    "CWE-918",
    "CWE-190",
    "CWE-416",
    "CWE-476",
    "CWE-352",
]

# Minimum confidence threshold for ML predictions
ML_CONFIDENCE_THRESHOLD = 0.3


# ── Load ML model on import (try v4 first, then v3, v2, v1) ────────────────
_model = None
_model_metadata = None
_model_is_v2 = False  # True for v4, v3 and v2 (same 37-feature layout)
_model_version = None  # "v1", "v2", "v3", or "v4"
_model_feature_names = None
_model_agencies = None
_model_cwes = None

_ml_dir = os.path.dirname(__file__)

# Try v4 model first (sector-aware, trained on research-grounded synthetic findings)
_model_v4_path = os.path.join(_ml_dir, "epss_model_v4.pkl")
if os.path.isfile(_model_v4_path):
    try:
        _artifact = joblib.load(_model_v4_path)
        _model = _artifact["model"]
        _model_metadata = _artifact.get("metadata", {})
        _model_feature_names = _artifact.get("feature_names", [])
        _model_agencies = _artifact.get("agencies", AGENCIES_V2)
        _model_cwes = _artifact.get("cwes", CWES_V2)
        _model_is_v2 = True  # v4 uses same 37-feature layout as v2/v3
        _model_version = "v4"
        logger.info(
            "Loaded EPSS substitution ML model v4 from %s "
            "(R²=%.4f, RMSE=%.4f, %d features, %d agencies, %d CWEs, "
            "training_source=%s)",
            _model_v4_path,
            _model_metadata.get("r2", 0),
            _model_metadata.get("rmse", 0),
            _model_metadata.get("n_features", 0),
            _model_metadata.get("n_agencies", len(_model_agencies)),
            _model_metadata.get("n_cwes", len(_model_cwes)),
            _model_metadata.get("training_source", "unknown"),
        )
    except Exception as exc:
        logger.warning(
            "Failed to load EPSS ML model v4 from %s: %s", _model_v4_path, exc
        )
        _model = None
else:
    logger.info("No EPSS ML model v4 found at %s", _model_v4_path)

# Try v3 model second (fallback — only if v4 didn't load)
if _model is None:
    _model_v3_path = os.path.join(_ml_dir, "epss_model_v3.pkl")
    if os.path.isfile(_model_v3_path):
        try:
            _artifact = joblib.load(_model_v3_path)
            _model = _artifact["model"]
            _model_metadata = _artifact.get("metadata", {})
            _model_feature_names = _artifact.get("feature_names", [])
            _model_agencies = _artifact.get("agencies", AGENCIES_V2)
            _model_cwes = _artifact.get("cwes", CWES_V2)
            _model_is_v2 = True  # v3 uses same 37-feature layout as v2
            _model_version = "v3"
            logger.info(
                "Loaded EPSS substitution ML model v3 from %s "
                "(R²=%.4f, RMSE=%.4f, %d features, %d agencies, %d CWEs, "
                "training_source=%s)",
                _model_v3_path,
                _model_metadata.get("r2", 0),
                _model_metadata.get("rmse", 0),
                _model_metadata.get("n_features", 0),
                _model_metadata.get("n_agencies", len(_model_agencies)),
                _model_metadata.get("n_cwes", len(_model_cwes)),
                _model_metadata.get("training_source", "unknown"),
            )
        except Exception as exc:
            logger.warning(
                "Failed to load EPSS ML model v3 from %s: %s", _model_v3_path, exc
            )
            _model = None
    else:
        logger.info("No EPSS ML model v3 found at %s", _model_v3_path)

# Try v2 model second (fallback — only if v3 didn't load)
if _model is None:
    _model_v2_path = os.path.join(_ml_dir, "epss_model_v2.pkl")
    if os.path.isfile(_model_v2_path):
        try:
            _artifact = joblib.load(_model_v2_path)
            _model = _artifact["model"]
            _model_metadata = _artifact.get("metadata", {})
            _model_feature_names = _artifact.get("feature_names", [])
            _model_agencies = _artifact.get("agencies", AGENCIES_V2)
            _model_cwes = _artifact.get("cwes", CWES_V2)
            _model_is_v2 = True
            _model_version = "v2"
            logger.info(
                "Loaded EPSS substitution ML model v2 from %s "
                "(R²=%.4f, RMSE=%.4f, %d features, %d agencies, %d CWEs)",
                _model_v2_path,
                _model_metadata.get("r2", 0),
                _model_metadata.get("rmse", 0),
                _model_metadata.get("n_features", 0),
                _model_metadata.get("n_agencies", len(_model_agencies)),
                _model_metadata.get("n_cwes", len(_model_cwes)),
            )
        except Exception as exc:
            logger.warning(
                "Failed to load EPSS ML model v2 from %s: %s", _model_v2_path, exc
            )
            _model = None
    else:
        logger.info("No EPSS ML model v2 found at %s", _model_v2_path)

# Fall back to v1 model if v2 not loaded
if _model is None:
    _model_v1_path = os.path.join(_ml_dir, "epss_model.pkl")
    if os.path.isfile(_model_v1_path):
        try:
            _artifact = joblib.load(_model_v1_path)
            _model = _artifact["model"]
            _model_metadata = _artifact.get("metadata", {})
            _model_feature_names = _artifact.get("feature_names", [])
            _model_agencies = _artifact.get("agencies", AGENCIES_V1)
            _model_cwes = _artifact.get("cwes", CWES_V1)
            _model_is_v2 = False
            _model_version = "v1"
            logger.info(
                "Loaded EPSS substitution ML model v1 from %s "
                "(R²=%.4f, RMSE=%.4f, %d features)",
                _model_v1_path,
                _model_metadata.get("r2", 0),
                _model_metadata.get("rmse", 0),
                _model_metadata.get("n_features", 0),
            )
        except Exception as exc:
            logger.warning(
                "Failed to load EPSS ML model v1 from %s: %s", _model_v1_path, exc
            )
            _model = None
    else:
        logger.info("No EPSS ML model found — rule engine only.")

if _model is None:
    logger.warning("No EPSS ML model loaded — all substitutions will use rule engine.")


# ── Helper functions ──────────────────────────────────────────────────────


def _extract_agency(hostname: str) -> str:
    for agency in [
        "health",
        "transport",
        "education",
        "sharedservices",
        "communities",
        "police",
        "wapol",
        "finance",
        "watercorporation",
        "dpird",
        "justice",
    ]:
        if f".{agency}." in hostname:
            if agency == "wapol":
                return "police"
            return agency
    return "unknown"


def _build_feature_vector_v1(
    raw_epss: float,
    cvss_score: float,
    cisa_kev: bool,
    cwe_class: str,
    agency: str,
) -> list:
    """Build the 22-element feature vector matching v1 training encoding."""
    features = []

    # Continuous features
    features.append(raw_epss)  # 1
    features.append(cvss_score)  # 2

    # Binary
    features.append(1.0 if cisa_kev else 0.0)  # 3

    # One-hot agency
    agency_list = _model_agencies + ["unknown"]
    for a in agency_list:
        features.append(1.0 if agency == a else 0.0)

    # One-hot CWE
    for c in _model_cwes:
        features.append(1.0 if cwe_class == c else 0.0)

    return features


def _build_feature_vector_v2(
    raw_epss: float,
    cvss_score: float,
    cisa_kev: bool,
    cwe_class: str,
    agency: str,
    exploit_maturity: int = 0,
    has_public_poc: bool = False,
    vendor_patch_status: int = 0,
) -> list:
    """Build the 37-element feature vector matching v2 training encoding.

    Layout: raw_epss, cvss_score, exploit_maturity, cisa_kev, has_public_poc,
            vendor_patch_status, 11x agency OHE, 20x CWE OHE
    Total: 6 + 11 + 20 = 37
    """
    features = []

    # Continuous
    features.append(raw_epss)
    features.append(cvss_score)

    # Ordinal
    features.append(float(exploit_maturity))

    # Binary
    features.append(1.0 if cisa_kev else 0.0)
    features.append(1.0 if has_public_poc else 0.0)

    # Ordinal
    features.append(float(vendor_patch_status))

    # One-hot agency
    agency_list = _model_agencies + ["unknown"]
    for a in agency_list:
        features.append(1.0 if agency == a else 0.0)

    # One-hot CWE
    for c in _model_cwes:
        features.append(1.0 if cwe_class == c else 0.0)

    return features


def _rule_engine(
    cve_id: str,
    raw_epss: float | None,
    hostname: str,
    cisa_kev: bool = False,
    cwe_class: str = "",
) -> dict:
    """Original heuristic rule engine for EPSS substitution.

    When raw_epss is None (not provided by scanner), generates a floor:
      - 0.3 for CISA KEV CVEs
      - 0.05 conservative default otherwise

    Returns the same dict shape as calculate_substitution.
    """
    sector_multiplier = DEFAULT_MULTIPLIER
    reasons = []

    if raw_epss is None:
        floor = 0.3 if cisa_kev else 0.05
        return {
            "substituted": True,
            "substituted_epss": floor,
            "original_epss": 0.0,
            "confidence": 0.5,
            "model_version": "rule_engine",
            "reason": f"EPSS not provided. Floor generated from {'CISA KEV' if cisa_kev else 'conservative default'} ({floor}).",
        }

    if cisa_kev:
        sector_multiplier = max(sector_multiplier, KEV_MULTIPLIER)
        reasons.append("CISA KEV actively exploited")

    agency = _extract_agency(hostname)
    adjustment = CVE_ADJUSTMENTS.get(cve_id)
    if adjustment:
        agency_mult = adjustment.get(agency, adjustment.get("default", 1.0))
        if agency_mult > 1.0:
            sector_multiplier = max(sector_multiplier, agency_mult)
            reasons.append(
                f"CVE known to disproportionately target {agency} sector "
                f"({adjustment.get('source', 'threat intelligence')})"
            )

    # CWE multiplier
    if cwe_class and cwe_class in CWE_MULTIPLIERS:
        cwe_mult = CWE_MULTIPLIERS[cwe_class]
        sector_multiplier = max(sector_multiplier, cwe_mult)
        reasons.append(
            f"CWE {cwe_class} vulnerability class multiplier {cwe_mult:.1f}x"
        )

    if sector_multiplier <= DEFAULT_MULTIPLIER:
        return {
            "substituted": False,
            "substituted_epss": raw_epss,
            "original_epss": raw_epss,
            "confidence": 0.0,
            "model_version": "rule_engine",
            "reason": "",
        }

    substituted_epss = round(min(MAX_EPSS, raw_epss * sector_multiplier), 4)
    change = substituted_epss - raw_epss
    substituted = change >= MIN_CHANGE_THRESHOLD
    confidence = round(min(MAX_CONFIDENCE, 0.5 + sector_multiplier * 0.15), 2)

    reason = (
        f"Sector multiplier {sector_multiplier:.1f}x applied: {'; '.join(reasons)}."
    )

    logger.debug(
        "EPSS rule substitution for %s on %s: "
        "%s -> %s (multiplier %.1fx, substituted=%s)",
        cve_id,
        hostname,
        raw_epss,
        substituted_epss,
        sector_multiplier,
        substituted,
    )

    return {
        "substituted": substituted,
        "substituted_epss": substituted_epss,
        "original_epss": raw_epss,
        "confidence": confidence,
        "model_version": "rule_engine",
        "reason": reason,
    }


def _compute_confidence_v2(
    raw_epss: float,
    pred: float,
    exploit_maturity: int = 0,
    has_public_poc: bool = False,
    vendor_patch_status: int = 0,
    cisa_kev: bool = False,
) -> float:
    """Compute substitution confidence for v2 model.

    Uses model R² as the base, then adjusts upward based on the number of
    "risk signals" present in the input features. More signals = higher
    confidence that substitution is warranted.
    """
    base_conf = _model_metadata.get("r2", 0.3)

    # Count risk signals
    risk_signals = 0
    if cisa_kev:
        risk_signals += 1
    if exploit_maturity >= 2:
        risk_signals += 1  # weaponized or in-the-wild
    if has_public_poc:
        risk_signals += 1
    if vendor_patch_status == 2:
        risk_signals += 1  # no patch available
    elif vendor_patch_status == 1:
        risk_signals += 0.5  # temporary fix only

    # Adjustment ratio (how much the prediction differs from raw EPSS)
    change = abs(pred - raw_epss)
    adjustment_ratio = min(1.0, change / (raw_epss + 0.001))

    # Combine: base + risk signal boost + adjustment ratio
    signal_boost = min(0.4, risk_signals * 0.10)  # up to +0.4 for 4+ signals
    confidence = round(
        min(MAX_CONFIDENCE, base_conf + signal_boost + adjustment_ratio * 0.3),
        4,
    )
    return confidence


def _ml_predict(
    raw_epss: float,
    hostname: str,
    cisa_kev: bool = False,
    cvss_score: float = 5.0,
    cwe_class: str = "",
    exploit_maturity: int = 0,
    has_public_poc: bool = False,
    vendor_patch_status: int = 0,
) -> dict:
    """Predict sector-adjusted EPSS using the ML model.

    Uses v2 feature encoding if the loaded model is v2, otherwise falls back
    to v1 encoding. Falls back to rule engine if prediction confidence is
    below threshold or prediction fails.

    If raw_epss is None (not provided), defers to rule engine for floor handling.
    """
    if raw_epss is None:
        return _rule_engine(
            cve_id="",
            raw_epss=None,
            hostname=hostname,
            cisa_kev=cisa_kev,
            cwe_class=cwe_class,
        )

    agency = _extract_agency(hostname)

    # Build feature vector using the appropriate encoding for the loaded model
    if _model_is_v2:
        features = _build_feature_vector_v2(
            raw_epss=raw_epss,
            cvss_score=cvss_score,
            cisa_kev=cisa_kev,
            cwe_class=cwe_class,
            agency=agency,
            exploit_maturity=exploit_maturity,
            has_public_poc=has_public_poc,
            vendor_patch_status=vendor_patch_status,
        )
    else:
        features = _build_feature_vector_v1(
            raw_epss=raw_epss,
            cvss_score=cvss_score,
            cisa_kev=cisa_kev,
            cwe_class=cwe_class,
            agency=agency,
        )

    X = np.array([features])

    try:
        pred_raw = float(_model.predict(X)[0])
    except Exception as exc:
        logger.warning("ML prediction failed (%s), falling back to rules.", exc)
        return _rule_engine(
            cve_id="",
            raw_epss=raw_epss,
            hostname=hostname,
            cisa_kev=cisa_kev,
            cwe_class=cwe_class,
        )

    # Clamp to [0, 1]
    pred = max(0.0, min(1.0, pred_raw))
    change = abs(pred - raw_epss)

    # Build confidence
    if _model_is_v2:
        confidence = _compute_confidence_v2(
            raw_epss=raw_epss,
            pred=pred,
            exploit_maturity=exploit_maturity,
            has_public_poc=has_public_poc,
            vendor_patch_status=vendor_patch_status,
            cisa_kev=cisa_kev,
        )
    else:
        # v1 confidence formula
        base_conf = _model_metadata.get("r2", 0.3)
        adjustment_ratio = min(1.0, change / (raw_epss + 0.001))
        confidence = round(min(MAX_CONFIDENCE, base_conf + adjustment_ratio * 0.4), 4)

    substituted = (
        pred != raw_epss
        and change >= MIN_CHANGE_THRESHOLD
        and confidence >= ML_CONFIDENCE_THRESHOLD
    )

    model_label = _model_version or ("v2" if _model_is_v2 else "v1")
    reason = (
        f"ML model {model_label} prediction "
        f"(R²={_model_metadata.get('r2', 0):.2f}, "
        f"conf={confidence:.2f}): {raw_epss:.4f} -> {pred:.4f}"
    )

    if not substituted:
        reason = f"ML prediction below substitution threshold: {reason}"

    logger.debug(
        "EPSS ML substitution (%s): %s -> %s (change=%.4f, conf=%.4f, substituted=%s)",
        model_label,
        raw_epss,
        pred,
        change,
        confidence,
        substituted,
    )

    return {
        "substituted": substituted,
        "substituted_epss": round(pred, 4),
        "original_epss": raw_epss,
        "confidence": confidence,
        "reason": reason,
        "model_version": model_label,
    }


# ── Main entry point ──────────────────────────────────────────────────────


def calculate_substitution(
    cve_id: str,
    raw_epss: float | None,
    hostname: str,
    cisa_kev: bool = False,
    cvss_score: float = 5.0,
    cwe_class: str = "",
    exploit_maturity: int = 0,
    has_public_poc: bool = False,
    vendor_patch_status: int = 0,
) -> dict:
    """
    Calculate a sector-adjusted EPSS score for a given CVE and asset.

    Uses the ML model (v4 preferred, v3 fallback, v2 fallback, v1 last resort)
    when available and confident; falls back to the heuristic rule engine otherwise.

    Args:
        cve_id: The CVE identifier (e.g., CVE-2023-36884)
        raw_epss: The original FIRST.org EPSS score (0-1)
        hostname: The FQDN of the asset
        cisa_kev: Whether the CVE is in CISA's Known Exploited Vulnerabilities
        cvss_score: CVSS v3.1 base score (0-10, default 5.0)
        cwe_class: CWE class string (e.g., "CWE-78", default "")
        exploit_maturity: Exploit maturity level (0=None, 1=POC, 2=Weaponized,
                          3=InWild, default 0)
        has_public_poc: Whether a public PoC exists (default False)
        vendor_patch_status: Patch status (0=OfficialFix, 1=TemporaryFix,
                             2=Unavailable, default 0)

    Returns:
        dict with substituted (bool), substituted_epss (float),
        original_epss (float), confidence (float), reason (str)
    """
    if _model is not None:
        # ML path
        result = _ml_predict(
            raw_epss=raw_epss,
            hostname=hostname,
            cisa_kev=cisa_kev,
            cvss_score=cvss_score,
            cwe_class=cwe_class,
            exploit_maturity=exploit_maturity,
            has_public_poc=has_public_poc,
            vendor_patch_status=vendor_patch_status,
        )
        if result["substituted"] and result["confidence"] >= ML_CONFIDENCE_THRESHOLD:
            logger.info(
                "EPSS substitution for %s on %s: %s -> %s (conf=%.4f, ML model)",
                cve_id,
                hostname,
                raw_epss,
                result["substituted_epss"],
                result["confidence"],
            )
            return result

        # ML didn't produce a confident substitution — fall through to rules
        logger.debug(
            "ML prediction for %s on %s not confident enough "
            "(conf=%.4f < threshold=%.1f), falling back to rules",
            cve_id,
            hostname,
            result.get("confidence", 0),
            ML_CONFIDENCE_THRESHOLD,
        )

    # Fallback: rule engine
    result = _rule_engine(
        cve_id=cve_id,
        raw_epss=raw_epss,
        hostname=hostname,
        cisa_kev=cisa_kev,
        cwe_class=cwe_class,
    )

    if result["substituted"]:
        logger.info(
            "EPSS substitution for %s on %s: %s -> %s (rule engine)",
            cve_id,
            hostname,
            raw_epss,
            result["substituted_epss"],
        )

    return result
