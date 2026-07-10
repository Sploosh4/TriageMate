"""
Canonical feature name lists for ML model inference and training.

Each list is the single source of truth for its model's feature order.
Consumers import from here instead of maintaining duplicate copies.
"""

# Tabular feature names in positional order — 35 features.
# Used by xgboost_predictor.py (inference) and train_xgboost.py (training).
TABULAR_FEATURE_ORDER = [
    "cvss_av",
    "cvss_ac",
    "cvss_pr",
    "cvss_ui",
    "cvss_s",
    "cvss_c",
    "cvss_i",
    "cvss_a",
    "epss_score",
    "patch_available",
    "patch_applied",
    "internet_facing",
    "domain_joined",
    "data_classification",
    "mission_prevalence",
    "public_wellbeing_impact",
    "lateral_reachability",
    "boundary_reachability",
    "downstream_assets",
    "patch_lag_days",
    "exploitdb_has_poc",
    "metasploit_has_payload",
    "threat_intel_pulses",
    "nvd_reference_count",
    "cve_desc_tokens",
    "vulnerability_age_days",
    "vendor_popularity_index",
    "cvss_exploitability_sub",
    "cvss_impact_sub",
    "is_top_25_cwe",
    "is_rce_signature",
    "is_privesc_signature",
    "is_bypass_signature",
    "is_dos_signature",
    "is_traversal_signature",
]

# Pre-Tier feature names (60-dim) — populated from pre_tier.py
PRE_TIER_FEATURE_NAMES: list[str] = []

# EPSS v4/v3/v2 feature names (37-dim) — from epss_substitutor.py
EPSS_V2_FEATURE_NAMES: list[str] = [
    "raw_epss",
    "cvss_score",
    "exploit_maturity",
    "cisa_kev",
    "has_public_poc",
    "vendor_patch_status",
    "agency_health",
    "agency_transport",
    "agency_education",
    "agency_sharedservices",
    "agency_communities",
    "agency_police",
    "agency_finance",
    "agency_watercorporation",
    "agency_dpird",
    "agency_justice",
    "agency_unknown",
    "cwe_CWE-78",
    "cwe_CWE-89",
    "cwe_CWE-79",
    "cwe_CWE-22",
    "cwe_CWE-434",
    "cwe_CWE-862",
    "cwe_CWE-787",
    "cwe_CWE-125",
    "cwe_CWE-20",
    "cwe_CWE-200",
    "cwe_CWE-287",
    "cwe_CWE-306",
    "cwe_CWE-269",
    "cwe_CWE-295",
    "cwe_CWE-611",
    "cwe_CWE-918",
    "cwe_CWE-190",
    "cwe_CWE-416",
    "cwe_CWE-476",
    "cwe_CWE-352",
]

# EPSS v1 feature names (22-dim) — from epss_substitutor.py
EPSS_V1_FEATURE_NAMES: list[str] = [
    "raw_epss",
    "cvss_score",
    "cisa_kev",
    "agency_health",
    "agency_transport",
    "agency_education",
    "agency_sharedservices",
    "agency_communities",
    "agency_police",
    "agency_finance",
    "agency_unknown",
    "cwe_CWE-78",
    "cwe_CWE-89",
    "cwe_CWE-79",
    "cwe_CWE-22",
    "cwe_CWE-434",
    "cwe_CWE-862",
    "cwe_CWE-787",
    "cwe_CWE-125",
    "cwe_CWE-20",
    "cwe_CWE-200",
    "cwe_CWE-287",
]

__all__ = [
    "TABULAR_FEATURE_ORDER",
    "PRE_TIER_FEATURE_NAMES",
    "EPSS_V2_FEATURE_NAMES",
    "EPSS_V1_FEATURE_NAMES",
]
