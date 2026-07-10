"""
Business-logic thresholds for pipeline routing and drift monitoring.

These are magic numbers that require regular tuning and are shared
across multiple pipeline modules (Tier 0, Tier 1, drift analysis).
Single-file thresholds (e.g., MAX_RETRIES in nvd.py) stay local.
"""

# ── Tier 0 thresholds ───────────────────────────────────────────────────────
NVD_REF_THRESHOLD = 21  # NVD reference count threshold for auto-resolve
KEV_CVSS_THRESHOLD = 9.0  # CVSS threshold for KEV + CVSS auto-resolve
KEV_EPSS_THRESHOLD = 0.90  # EPSS floor for KEV escalation (fallback)
LOW_CVSS_THRESHOLD = 4.0  # CVSS below this triggers low auto-resolve
LOW_EPSS_THRESHOLD = 0.10  # EPSS fallback threshold when CWE not in stratification

# ── CWE-stratified EPSS thresholds ──────────────────────────────────────────
# Derived from EPSS evaluation analysis (analysis/epss_eval.py).
# Each threshold is the optimal F1 operating point for that CWE class.
CWE_EPSS_THRESHOLDS: dict[str, float] = {
    "CWE-22": 0.085,  # Path Traversal
    "CWE-78": 0.515,  # OS Command Injection
    "CWE-787": 0.716,  # Out-of-bounds Write
    "CWE-79": 0.600,  # XSS
    "CWE-89": 0.500,  # SQL Injection
    "CWE-416": 0.550,  # Use-After-Free
    "CWE-20": 0.400,  # Input Validation
    "CWE-843": 0.300,  # Type Confusion
    "CWE-125": 0.400,  # Out-of-bounds Read
    "CWE-476": 0.450,  # NULL Pointer Dereference
    "CWE-862": 0.350,  # Missing Authorization
    "CWE-434": 0.500,  # File Upload (Unrestricted)
    "CWE-306": 0.350,  # Missing Authentication
    "CWE-269": 0.400,  # Privilege Escalation (Improper)
}
DEFAULT_EPSS_THRESHOLD = 0.60  # Monolithic fallback for unstratified CWEs

# ── XGBoost probability thresholds ──────────────────────────────────────────
# Used for routing decisions in xgboost_predictor.py
LOW_PROB_THRESHOLD = 0.20
MID_PROB_THRESHOLD = 0.40
HIGH_PROB_THRESHOLD = 0.50
UNCERTAINTY_THRESHOLD = 0.10

# ── Drift PSI thresholds ────────────────────────────────────────────────────
# Used by analysis/drift.py for composite and per-feature drift status
DRIFT_WARNING_PSI = 0.10
DRIFT_CRITICAL_PSI = 0.25

__all__ = [
    "NVD_REF_THRESHOLD",
    "KEV_CVSS_THRESHOLD",
    "KEV_EPSS_THRESHOLD",
    "LOW_CVSS_THRESHOLD",
    "LOW_EPSS_THRESHOLD",
    "CWE_EPSS_THRESHOLDS",
    "DEFAULT_EPSS_THRESHOLD",
    "LOW_PROB_THRESHOLD",
    "MID_PROB_THRESHOLD",
    "HIGH_PROB_THRESHOLD",
    "UNCERTAINTY_THRESHOLD",
    "DRIFT_WARNING_PSI",
    "DRIFT_CRITICAL_PSI",
]
