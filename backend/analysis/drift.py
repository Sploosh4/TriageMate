"""
ML Drift Monitoring — PSI (Population Stability Index) computation.

Provides:
- compute_psi(): Standard PSI formula for a single feature
- compute_drift(): Aggregate drift assessment across all tabular features
- send_drift_webhook(): POST drift alert to configured webhook URL
"""

import asyncio
import math
import os
import logging
from datetime import datetime, timezone

from pipeline.config.thresholds import DRIFT_WARNING_PSI, DRIFT_CRITICAL_PSI

logger = logging.getLogger("triagemate.drift")

# ── Drift webhook configuration ─────────────────────────────────────────────
DRIFT_WEBHOOK_URL = os.getenv("TRIAGEMATE_DRIFT_WEBHOOK_URL", "")

# Rate limiting: suppress duplicate notifications within 6 hours per model
_last_webhook: dict[str, datetime] = {}
_WEBHOOK_SUPPRESSION_HOURS = 6


async def send_drift_webhook(
    model_name: str,
    psi_value: float,
    threshold: float,
    details: dict | None = None,
) -> bool:
    """POST drift alert to configured webhook URL.

    Returns True if webhook was sent, False if suppressed or no URL configured.
    Rate-limited: same model + same severity level suppressed for 6 hours.
    """
    if not DRIFT_WEBHOOK_URL:
        return False

    # Rate limiting suppression
    now = datetime.now(timezone.utc)
    severity = "critical" if psi_value >= 0.25 else "warning"
    key = f"{model_name}:{severity}"

    if key in _last_webhook:
        elapsed = (now - _last_webhook[key]).total_seconds()
        if elapsed < _WEBHOOK_SUPPRESSION_HOURS * 3600:
            logger.debug(
                "Drift webhook suppressed for %s (last sent %.1f hrs ago)",
                key,
                elapsed / 3600,
            )
            return False

    payload = {
        "event": "drift_detected",
        "model": model_name,
        "psi": round(psi_value, 4),
        "threshold": threshold,
        "severity": severity,
        "timestamp": now.isoformat(),
        "details": details or {},
    }

    try:
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(DRIFT_WEBHOOK_URL, json=payload)
            resp.raise_for_status()

        _last_webhook[key] = now
        logger.info(
            "Drift webhook sent for %s (PSI=%.4f, severity=%s)",
            model_name,
            psi_value,
            severity,
        )
        return True

    except Exception as e:
        logger.warning("Drift webhook failed for %s: %s", model_name, str(e)[:200])
        return False


EPSILON = 0.0001  # Small epsilon to avoid log(0)


def compute_psi(expected_probs: list[float], actual_counts: list[int]) -> float:
    """Compute Population Stability Index for one feature.

    Args:
        expected_probs: Expected proportion per bin (from reference distribution).
            Should sum to ~1.0.
        actual_counts: Count of observations in each bin for the current window.

    Returns:
        PSI value (float >= 0). 0 means identical distributions.
    """
    total_actual = sum(actual_counts)
    if total_actual == 0:
        return 0.0

    psi = 0.0
    for expected_p, actual_count in zip(expected_probs, actual_counts):
        actual_p = actual_count / total_actual

        # Skip bins where either proportion is zero to avoid division by zero
        if expected_p == 0.0:
            continue
        if actual_p == 0.0:
            actual_p = EPSILON

        psi += (actual_p - expected_p) * math.log(actual_p / expected_p)

    return psi


def _get_drift_status(psi: float) -> str:
    """Classify PSI value into stability status.

    Thresholds:
        psi < DRIFT_WARNING_PSI         → "stable"
        DRIFT_WARNING_PSI ≤ psi < DRIFT_CRITICAL_PSI → "warning"
        psi ≥ DRIFT_CRITICAL_PSI        → "critical"
    """
    if psi >= DRIFT_CRITICAL_PSI:
        return "critical"
    if psi >= DRIFT_WARNING_PSI:
        return "warning"
    return "stable"


def _fire_webhook_sync(
    model_name: str,
    psi_value: float,
    threshold: float,
    details: dict | None = None,
) -> None:
    """Fire drift webhook from a synchronous context.

    Tries to use the running event loop; falls back to asyncio.run().
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(
                send_drift_webhook(
                    model_name=model_name,
                    psi_value=psi_value,
                    threshold=threshold,
                    details=details,
                )
            )
        else:
            asyncio.run(
                send_drift_webhook(
                    model_name=model_name,
                    psi_value=psi_value,
                    threshold=threshold,
                    details=details,
                )
            )
    except RuntimeError:
        asyncio.run(
            send_drift_webhook(
                model_name=model_name,
                psi_value=psi_value,
                threshold=threshold,
                details=details,
            )
        )


def compute_drift(
    features_json_list: list[dict],
    reference_dists: dict,
    model_name: str = "unknown",
) -> dict:
    """Compute drift metrics for all features against reference distributions.

    Args:
        features_json_list: List of dicts, each with feature_name: value entries
            for the 35 tabular features (encoded numeric values).
        reference_dists: The reference distribution JSON loaded from
            backend/ml/reference_distributions.json.

    Returns:
        Dict with:
            - features: dict of feature_name -> {psi, status}
            - composite_psi: float (mean of all feature PSIs)
            - status: overall status string
            - total_samples: int
    """
    ref_features = reference_dists.get("features", {})

    if not features_json_list:
        # No data — return zero drift for all reference features
        feature_results = {}
        for fname in ref_features:
            feature_results[fname] = {"psi": 0.0, "status": "stable"}
        return {
            "features": feature_results,
            "composite_psi": 0.0,
            "status": "stable",
            "total_samples": 0,
        }

    n_features = len(ref_features)
    feature_results = {}
    composite_sum = 0.0

    for fname, ref in ref_features.items():
        bins = ref["bins"]
        expected = ref["expected"]
        num_bins = len(bins) - 1

        # Bin the actual values
        actual_counts = [0] * num_bins

        for feature_row in features_json_list:
            val = feature_row.get(fname)
            if val is None:
                continue
            # Find which bin this value falls into
            placed = False
            for i in range(num_bins):
                low = bins[i]
                high = bins[i + 1]
                if i == num_bins - 1:
                    # Last bin includes upper bound
                    if low <= val <= high:
                        actual_counts[i] += 1
                        placed = True
                        break
                else:
                    if low <= val < high:
                        actual_counts[i] += 1
                        placed = True
                        break
            if not placed:
                # Value outside range — put in last bin
                actual_counts[-1] += 1

        psi = compute_psi(expected, actual_counts)
        status = _get_drift_status(psi)
        feature_results[fname] = {"psi": round(psi, 6), "status": status}
        composite_sum += psi

    composite_psi = composite_sum / n_features if n_features > 0 else 0.0
    overall_status = _get_drift_status(composite_psi)

    # Fire webhook if composite PSI exceeds warning threshold
    if composite_psi >= DRIFT_WARNING_PSI:
        _fire_webhook_sync(
            model_name=model_name,
            psi_value=composite_psi,
            threshold=DRIFT_WARNING_PSI,
            details={
                "feature_count": n_features,
                "sample_count": len(features_json_list),
            },
        )

    return {
        "features": feature_results,
        "composite_psi": round(composite_psi, 6),
        "status": overall_status,
        "total_samples": len(features_json_list),
    }
