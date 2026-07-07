---
name: ml-engineering
description: ML model development, XGBoost tuning, feature vector design, training pipelines, EPSS data, NVD corpus, LanceDB vector store, pre-tier classifier. Use when training models, building corpus, engineering features, or evaluating ML performance.
---

# TriageMate ML Engineering

## Model Inventory
- **Tier 1:** XGBoost (68 features, ROC-AUC 0.9677) — `backend/ml/xgboost_model.pkl`
- **Pre-Tier:** RandomForest multi-label classifier — `backend/ml/pre_tier_model.pkl`
- **EPSS Substitution:** XGBoost regressor (v1/v2/v3) — `backend/ml/epss_model.pkl`

## Feature Vector Contract
68 features = 35 tabular + 33 signature/derived features
`build_feature_vector()` in `backend/ingest_helpers.py`

### Contract
`build_feature_vector()` must always return the same set of feature keys. Never rename or remove keys — only append new ones.

### Current feature keys (42 top-level keys)
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

### When you add a feature you MUST also:
1. Add it to the returned dict in `build_feature_vector()`
2. Add it to `backend/scripts/build_training_corpus.py` (CSV header + row builder)
3. Regenerate: `python backend/scripts/build_training_corpus.py`
4. Retrain XGBoost: `python backend/ml/train_xgboost.py`

### Verify
```bash
python -c "from ingest_helpers import build_feature_vector; print('ok')"
```

## Key Files
- `backend/pipeline/ingest_helpers.py` — `build_feature_vector()`, CWE lookups
- `backend/pipeline/pre_tier.py` — `KNOWN_TAGS` dict, mission/impact tag assignment
- `backend/ml/train_xgboost.py` — XGBoost training pipeline
- `backend/ml/train_pre_tier.py` — Pre-tier classifier training
- `backend/ml/train_epss_v2.py`, `train_epss_v3.py` — EPSS model training
- `backend/ml/xgboost_predictor.py` — XGBoost inference
- `backend/ml/epss_substitutor.py` — EPSS substitution engine
- `backend/ml/encoder.py` — SentenceTransformer SBERT
- `backend/ml/vector_store.py` — LanceDB RAG store
- `backend/integrations/nvd.py` — NVD API v2 client
- `backend/scripts/build_training_corpus.py` — unified NPZ builder
- `backend/scripts/fetch_nvd_corpus.py` — bulk NVD fetcher
- `backend/data/nvd_cache.json` — offline NVD cache

## Score Contract
All 7 demo rows must score within ±3 of: 94, 87, 71, 55, 63, 41, 22

## Training Rules
- Training data MUST exclude the 7 demo CVEs (data leakage prevention)
- Feature count must stay at 68 — any addition/removal requires full retraining + score re-validation
- After retraining, always report ROC-AUC, per-class accuracy, and 7-row score verification

## Data Pipeline
- NVD corpus: `backend/data/nvd_corpus.json` (200K+ CVEs)
- Training data: `backend/ml/training_data.npz`
- Training scripts: `backend/ml/train_*.py`
- Corpus builder: `backend/scripts/build_training_corpus.py`

## Related Skills
- `ml-toolbox` — exact CLI commands for training, corpus building, data fetching
