---
name: feature-vector-spec
description: Exact feature list and contract for build_feature_vector() — never remove or rename keys, only append
---

## Contract
`build_feature_vector()` in `backend/ingest_helpers.py` must always return the same set of feature keys. Never rename or remove keys — only append new ones.

## Current feature keys (42 top-level keys)
```
cvss_av, cvss_ac, cvss_pr, cvss_ui, cvss_s, cvss_c, cvss_i, cvss_a,
cvss_score, epss_score, patch_available, osv_fixed_versions, osv_package,
osv_ecosystem, patch_applied, internet_facing, domain_joined,
data_classification, mission_prevalence, public_wellbeing_impact,
lateral_reachability, boundary_reachability, downstream_assets,
patch_lag_days, exploitdb_has_poc, metasploit_has_payload,
internet_scan_detected, threat_intel_pulses, nvd_reference_count,
cve_desc_tokens, vulnerability_age_days, vendor_popularity_index,
cvss_exploitability_sub, cvss_impact_sub, is_top_25_cwe, is_rce_signature,
is_privesc_signature, is_bypass_signature, is_dos_signature,
is_traversal_signature, threat_intel_status, description
```

## When you add a feature you MUST also:
1. Add it to the returned dict in `build_feature_vector()`
2. Add it to `backend/scripts/build_training_corpus.py` (CSV header + row builder)
3. Regenerate: `python backend/scripts/build_training_corpus.py`
4. Retrain XGBoost: `python backend/ml/train_xgboost.py`

## Verify
```bash
python -c "from ingest_helpers import build_feature_vector; print('ok')"
```
