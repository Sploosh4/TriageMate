"""
Scoring dimension weights and caps for the priority score calculator.

Supports optional JSON config file override (scoring_weights.json) for
runtime customization of the six scoring dimension weights.
Weights sum to 107; final total is clamped to 0-100.
Each dimension has a maximum value cap enforced by scoring.py.

Security Context was removed as a dimension in Sprint 21 and replaced
by a proportional multiplier (1.20/1.10/1.00/0.85/0.70) applied to the
total score. Multiplier constants live in this module.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger("triagemate.config.scoring")

# Hardcoded defaults
SCORING_WEIGHTS = {
    "cvss": 40,
    "epss": 20,
    "criticality": 20,
    "exposure": 12,
    "patch": 5,
    "ml_exploitation": 10,
}

# Validation rules
_MIN_WEIGHT = 1
_MAX_WEIGHT = 100
_MIN_TOTAL = 100

TOTAL_WEIGHT = sum(SCORING_WEIGHTS.values())  # 107
CLAMP_MIN = 0
CLAMP_MAX = 100

# Dimension-specific caps
CRITICALITY_MAX = 20
EXPOSURE_MAX = 12
PATCH_MAX = 5
ML_EXPLOITATION_MAX = 10

# Security Context Multiplier configuration (Sprint 21)
# Replaces the old additive Security Context dimension (0-5 points)
# with a proportional multiplier applied to the total score.
CONTEXT_MULTIPLIER_VALUES = {
    "active_threat_loaded": 1.20,
    "partial_evidence": 1.10,
    "neutral": 1.00,
    "mitigated": 0.85,
    "false_positive": 0.70,
}
TELEMETRY_ACTIVE_THRESHOLD = 3.0  # On 0-10 threat score scale

# Optional override file
_CONFIG_FILE = Path(__file__).parent / "scoring_weights.json"


def _load_weights_override() -> dict | None:
    """Load scoring_weights.json if it exists and is valid.

    Returns the override dict, or None if file doesn't exist or is invalid.
    Logs WARNING on invalid config and falls back to defaults.
    """
    if not _CONFIG_FILE.exists():
        return None

    try:
        with open(_CONFIG_FILE) as f:
            data = json.load(f)

        if not isinstance(data, dict):
            logger.warning("scoring_weights.json: root must be a dict")
            return None

        weights = data.get("weights", {})
        if not isinstance(weights, dict):
            logger.warning("scoring_weights.json: 'weights' must be a dict")
            return None

        # Validate all weight keys exist
        required = {
            "cvss",
            "epss",
            "criticality",
            "exposure",
            "patch",
            "ml_exploitation",
        }
        if set(weights.keys()) != required:
            logger.warning(
                "scoring_weights.json: expected keys %s, got %s",
                required,
                set(weights.keys()),
            )
            return None

        # Validate each weight
        for key, value in weights.items():
            if not isinstance(value, int) or value < _MIN_WEIGHT or value > _MAX_WEIGHT:
                logger.warning(
                    "scoring_weights.json: %s=%s is invalid (must be int %d-%d)",
                    key,
                    value,
                    _MIN_WEIGHT,
                    _MAX_WEIGHT,
                )
                return None

        # Validate total
        total = sum(weights.values())
        if total < _MIN_TOTAL:
            logger.warning(
                "scoring_weights.json: total=%d < minimum %d", total, _MIN_TOTAL
            )
            return None

        return weights

    except (json.JSONDecodeError, OSError) as e:
        logger.warning("scoring_weights.json: %s", e)
        return None


# Try to load override at module import time
_override = _load_weights_override()
if _override is not None:
    SCORING_WEIGHTS = _override
    logger.info("Loaded scoring weights from %s: %s", _CONFIG_FILE, SCORING_WEIGHTS)

TOTAL_WEIGHT = sum(SCORING_WEIGHTS.values())


def reload_weights() -> dict:
    """Reload scoring weights from config file (or defaults).

    Returns the active SCORING_WEIGHTS dict.
    Call this after the config file is updated to apply changes in-memory.
    """
    global SCORING_WEIGHTS, TOTAL_WEIGHT

    override = _load_weights_override()
    if override is not None:
        SCORING_WEIGHTS = override
    else:
        # Reset to hardcoded defaults
        SCORING_WEIGHTS = {
            "cvss": 40,
            "epss": 20,
            "criticality": 20,
            "exposure": 12,
            "patch": 5,
            "ml_exploitation": 10,
        }

    TOTAL_WEIGHT = sum(SCORING_WEIGHTS.values())
    logger.info(
        "Scoring weights reloaded: %s (total=%d)", SCORING_WEIGHTS, TOTAL_WEIGHT
    )
    return SCORING_WEIGHTS


def reset_weights_to_defaults() -> dict:
    """Delete the config file and reload defaults."""
    if _CONFIG_FILE.exists():
        _CONFIG_FILE.unlink()
    return reload_weights()


__all__ = [
    "SCORING_WEIGHTS",
    "TOTAL_WEIGHT",
    "CLAMP_MIN",
    "CLAMP_MAX",
    "CRITICALITY_MAX",
    "EXPOSURE_MAX",
    "PATCH_MAX",
    "ML_EXPLOITATION_MAX",
    "CONTEXT_MULTIPLIER_VALUES",
    "TELEMETRY_ACTIVE_THRESHOLD",
    "reload_weights",
    "reset_weights_to_defaults",
    "_MIN_WEIGHT",
    "_MAX_WEIGHT",
    "_MIN_TOTAL",
    "_CONFIG_FILE",
]
