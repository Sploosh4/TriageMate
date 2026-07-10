"""
Scoring dimension weights and caps for the priority score calculator.

Weights sum to 112; final total is clamped to 0-100.
Each dimension has a maximum value cap enforced by scoring.py.
"""

# Scoring dimension weights — sum = 112, clamped to 0-100
SCORING_WEIGHTS = {
    "cvss": 40,
    "epss": 20,
    "criticality": 20,
    "exposure": 12,
    "patch": 5,
    "ml_exploitation": 10,
    "security_context": 5,
}
TOTAL_WEIGHT = sum(SCORING_WEIGHTS.values())  # 112
CLAMP_MIN = 0
CLAMP_MAX = 100

# Dimension-specific caps
CRITICALITY_MAX = 20
EXPOSURE_MAX = 12
PATCH_MAX = 5
ML_EXPLOITATION_MAX = 10
SECURITY_CONTEXT_MAX = 5

__all__ = [
    "SCORING_WEIGHTS",
    "TOTAL_WEIGHT",
    "CLAMP_MIN",
    "CLAMP_MAX",
    "CRITICALITY_MAX",
    "EXPOSURE_MAX",
    "PATCH_MAX",
    "ML_EXPLOITATION_MAX",
    "SECURITY_CONTEXT_MAX",
]
