"""
Tier 1: ML exploitation probability prediction.

Uses the trained XGBoost model from backend/ml/xgboost_predictor.py.
Falls back to a heuristic stub if the model is not yet trained.
"""

import logging

logger = logging.getLogger("triagemate.tier_1")


def evaluate_tier_1(features: dict) -> dict:
    """
    Evaluate a vulnerability using XGBoost with ensemble variance routing.

    Args:
        features: Dict containing feature values including at minimum:
            cvss_score, epss_score, mission_prevalence,
            public_wellbeing_impact, internet_facing, description (optional)

    Returns:
        dict with 'exploitation_probability' (0-1), 'confidence' (0-1),
        and 'routing' ('auto_resolved' or 'escalated')
    """
    try:
        from ml.xgboost_predictor import predict

        result = predict(features)
        logger.info(
            "Tier 1 XGBoost: prob=%.3f, conf=%.3f, routing=%s",
            result["exploitation_probability"],
            result["confidence"],
            result["routing"],
            extra={"event": "tier_1_predict"},
        )
        return result
    except (
        FileNotFoundError,
        ImportError,
        ModuleNotFoundError,
        ValueError,
        OSError,
        RuntimeError,
        TypeError,
    ):
        result = _heuristic_evaluate(features)
        logger.info(
            "Tier 1 heuristic: prob=%.3f, conf=%.3f, routing=%s",
            result["exploitation_probability"],
            result["confidence"],
            result["routing"],
            extra={"event": "tier_1_predict"},
        )
        return result


def _heuristic_evaluate(features: dict) -> dict:
    """Heuristic fallback when XGBoost model is not yet trained."""
    cvss = features.get("cvss_score", 5.0)
    epss = features.get("epss_score", 0.5)
    mission = features.get("mission_prevalence", "Support")
    wellbeing = features.get("public_wellbeing_impact", "Minimal")
    internet_facing = features.get("internet_facing", False)
    reachability = features.get("lateral_reachability_count", 0)
    domain_joined = features.get("domain_joined", False)
    priv_account = features.get("privileged_service_account", False)
    cross_boundary = features.get("cross_boundary_reachability", 0)

    base_score = (cvss / 10.0) * 0.4 + epss * 0.3
    env_score = 0.0
    if not internet_facing:
        env_score -= 0.15
    if reachability > 20:
        env_score += 0.15
    if domain_joined and priv_account:
        env_score += 0.12
    if cross_boundary > 5:
        env_score += 0.10
    if mission == "Core":
        env_score += 0.08
    if wellbeing == "Severe":
        env_score += 0.10

    exploitation_prob = min(1.0, max(0.0, base_score + env_score))
    confidence = 0.85
    if reachability > 20 and not internet_facing:
        confidence = 0.78
    if cross_boundary > 10:
        confidence = 0.72

    if exploitation_prob >= 0.50:
        routing = "escalated"
    elif exploitation_prob >= 0.30:
        routing = "escalated" if confidence <= 0.80 else "auto_resolved"
    else:
        routing = "auto_resolved"

    return {
        "exploitation_probability": round(exploitation_prob, 3),
        "confidence": round(confidence, 3),
        "routing": routing,
    }
