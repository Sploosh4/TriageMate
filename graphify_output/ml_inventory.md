# TriageMate — ML Model Inventory

> Canonical reference — read this before touching any ML code.

> Generated: 2026-07-07 23:53:35

---

## Model Summary

| Artifact | File | Size | Type |
|----------|------|------|------|
| epss_model | `backend/ml/epss_model.pkl` | 523 KB | pickled model |
| epss_model_v2 | `backend/ml/epss_model_v2.pkl` | 1 MB | pickled model |
| epss_model_v3 | `backend/ml/epss_model_v3.pkl` | 1 MB | pickled model |
| pre_tier_model | `backend/ml/pre_tier_model.pkl` | 5 MB | pickled model |
| xgboost_model | `backend/ml/xgboost_model.pkl` | 1 MB | pickled model |
| xgboost_model_old | `backend/ml/xgboost_model_old.pkl` | 1 MB | pickled model |
| training_data | `backend/ml/training_data.npz` | 156 MB | numpy training data |
| training_data_v2 | `backend/ml/training_data_v2.npz` | 341 MB | numpy training data |
| enriched_cves | `backend/ml/enriched_cves.json` | 179 MB | JSON data |
| nvd_checkpoint | `backend/ml/nvd_checkpoint.json` | 72 B | JSON data |
| nvd_cves_cached | `backend/ml/nvd_cves_cached.json` | 80 MB | JSON data |
| pretier_supplemental | `backend/ml/pretier_supplemental.json` | 206 KB | JSON data |
| pretier_training_data | `backend/ml/pretier_training_data.json` | 37 KB | JSON data |

## Script Inventory

| Script | Path | Description |
|--------|------|-------------|
| encoder | `backend/ml/encoder.py` | SBERT text encoder — raw 384-dimensional embeddings. |
| epss_substitutor | `backend/ml/epss_substitutor.py` | EPSS substitution — hybrid ML + rule engine (v3 with fallback chain). |
| fetch_epss_data | `backend/ml/fetch_epss_data.py` | Fetch real EPSS scores from FIRST.org and cache them locally. |
| generate_supplemental_hostnames | `backend/ml/generate_supplemental_hostnames.py` | Generate 300+ supplemental WA Government hostname records with diverse, |
| ingest_docs | `backend/ml/ingest_docs.py` | CLI script to ingest documents into the LanceDB vector store. |
| pretier_features | `backend/ml/pretier_features.py` | Shared feature extraction for the Pre-Tier multi-label classifier. |
| train_epss_substitutor | `backend/ml/train_epss_substitutor.py` | Train an XGBoost EPSS substitution model using synthetic training data. |
| train_epss_v2 | `backend/ml/train_epss_v2.py` | Train an improved XGBoost EPSS substitution model (v2). |
| train_epss_v3 | `backend/ml/train_epss_v3.py` | Train EPSS substitution model v3 using real FIRST.org EPSS data. |
| train_pre_tier | `backend/ml/train_pre_tier.py` | Offline training pipeline for the Pre-Tier multi-label classifier. |
| train_xgboost | `backend/ml/train_xgboost.py` | Offline XGBoost training pipeline — two-phase design. |
| vector_store | `backend/ml/vector_store.py` | LanceDB embedded vector store for RAG document retrieval. |
| xgboost_predictor | `backend/ml/xgboost_predictor.py` | Tier 1 XGBoost exploitation probability predictor. |
| build_cwe_hierarchy | `backend/scripts/build_cwe_hierarchy.py` | Build CWE hierarchy JSON from MITRE CWE XML. |
| build_training_corpus | `backend/scripts/build_training_corpus.py` | Unified training corpus builder — combines all data sources into |
| build_vendor_index | `backend/scripts/build_vendor_index.py` | Build vendor_popularity.json from NVD corpus vendor frequency. |
| fetch_nvd_corpus | `backend/scripts/fetch_nvd_corpus.py` | Bulk NVD API 2.0 corpus builder — fetch 200K+ CVEs with full metadata. |
| refresh_caches | `backend/scripts/refresh_caches.py` | Refresh demo data caches for TriageMate. |
| calibration_audit | `backend/analysis/calibration_audit.py` | Calibration audit for the Tier 1 XGBoost exploitation-probability model. |
| epss_eval | `backend/analysis/epss_eval.py` | EPSS as Standalone Predictor — Baseline Analysis |
| feature_parity_check | `backend/analysis/feature_parity_check.py` | Feature parity checker — verifies that build_training_corpus.py and |
| validate_conversion | `backend/analysis/validate_conversion.py` | Validate enriched_cves.json against build_tabular_features expectations. |
| rate_limit | `backend/middleware/rate_limit.py` | import time |

## ML Directory (`backend/ml/`)

- `README.md`  (1 KB)
- `encoder.py`  (2 KB)
- `enriched_cves.json`  (179 MB)
- `epss_model.pkl`  (523 KB)
- `epss_model_v2.pkl`  (1 MB)
- `epss_model_v3.pkl`  (1 MB)
- `epss_substitutor.py`  (20 KB)
- `fetch_epss_data.py`  (4 KB)
- `generate_supplemental_hostnames.py`  (14 KB)
- `ingest_docs.py`  (7 KB)
- `nvd_checkpoint.json`  (72 B)
- `nvd_cves_cached.json`  (80 MB)
- `pre_tier_model.pkl`  (5 MB)
- `pretier_features.py`  (12 KB)
- `pretier_supplemental.json`  (206 KB)
- `pretier_training_data.json`  (37 KB)
- `train_epss_substitutor.py`  (10 KB)
- `train_epss_v2.py`  (18 KB)
- `train_epss_v3.py`  (12 KB)
- `train_pre_tier.py`  (12 KB)
- `train_xgboost.py`  (44 KB)
- `training_data.npz`  (156 MB)
- `training_data_v2.npz`  (341 MB)
- `vector_store.py`  (13 KB)
- `xgboost_model.pkl`  (1 MB)
- `xgboost_model_old.pkl`  (1 MB)
- `xgboost_predictor.py`  (8 KB)

## Data Directory (`backend/data/`)

- `demo_scenarios.json`  (4 KB)
- `epss_cache.json`  (20 MB)
- `files_exploits.csv`  (10 MB)
- `kev_cache.json`  (518 KB)
- 📁 `lancedb/`  (4 KB)
- `mock_cmdb.json`  (28 KB)
- `nvd_cache.json`  (118 KB)
- `nvd_corpus.json`  (205 MB)
- `vendor_popularity.json`  (405 KB)

---

## Pre-Tier: RandomForest Multi-Label Classifier

- **File:** `backend/ml/pre_tier_model.pkl`
- **Feature extractor:** `backend/ml/pretier_features.py`
- **Input:** 60-dimensional hostname feature vector
- **Output:** Two classification labels:
  - `mission_prevalence` -> {Core, Support, Peripheral}
  - `public_wellbeing_impact` -> {Severe, Moderate, Minimal}
- **Architecture:** `MultiOutputClassifier(RandomForestClassifier, n_estimators=200)`
- **Resolution order:**
  1. KNOWN_TAGS dict (31 WA gov hostnames in `pipeline/pre_tier.py`)
  2. ML model -- for unknown hostnames
  3. Default fallback -> Support / Minimal, confidence 0.60
- **Training script:** `backend/ml/train_pre_tier.py`
- **Training data:** `backend/ml/pretier_training_data.json`
- **Lines of code (predictor):** 203
- **Lines of code (feature extractor):** 425
- **Notes:** Model loaded lazily via `threading.Lock` on first inference. Never retrained from the live app.

## Tier 1: XGBoost Exploitation Predictor

### WARNING: Deployed model is stale

| Metric | Current Deployed | New Training Data |
|--------|-----------------|-------------------|
| Samples | 93,000 (Sprint 3) | 253,568 |
| Features | 419 (35 + 384 SBERT) | 419 (35 + 384 SBERT) |
| ROC-AUC | 0.9677 | Unknown (not yet trained) |
| KEV recall | 835 of 1,631 (51%) | Unknown |
| Status | Live in production | Built, NOT retrained on this data |

**Command to retrain:** `python -m ml.train_xgboost --train --data-file ml/training_data_v2.npz`

- **File:** `backend/ml/xgboost_model.pkl`
- **Predictor wrapper:** `backend/ml/xgboost_predictor.py`
- **Input:** 419 total dimensions = 35 tabular + 384 SBERT embedding

  **35 tabular features** from `ingest_helpers.py`:
  - 8 CVSS metrics (av, ac, pr, ui, s, c, i, a)
  - cvss_score, epss_score
  - patch_available, patch_applied
  - internet_facing, domain_joined
  - data_classification, mission_prevalence
  - public_wellbeing_impact, lateral_reachability
  - boundary_reachability, downstream_assets
  - patch_lag_days
  - exploitdb_has_poc, metasploit_has_payload
  - internet_scan_detected, threat_intel_pulses
  - nvd_reference_count, cve_desc_tokens
  - vulnerability_age_days, vendor_popularity_index
  - cvss_exploitability_sub, cvss_impact_sub
  - is_top_25_cwe
  - is_rce, is_privesc, is_bypass, is_dos, is_traversal signatures

  **384 SBERT embedding** from `ml/encoder.py`:
  - Model: `all-MiniLM-L6-v2`
  - Cache: `@lru_cache(maxsize=8192)`
  - PCA removed in v2.5 (previously 64-dim)

  **IMPORTANT -- dimension note:**
  - NPZ stores 420 columns (36 tabular + 384 SBERT)
  - Model input is 419 dims (35 tabular + 384 SBERT)
  - `osv_lead_days` is metadata, NOT a model input

- **Output:** Binary exploitation probability [0, 1]
- **ROC-AUC:** 0.9677 (current deployed -- Sprint 3 retrain on 93K records)
  - Pre-fix (label leakage) ROC-AUC was 0.9946 -- NOT representative
- **Routing thresholds:**
  - P >= 0.65 -> Auto-resolve exploited (skip Tier 2)
  - P <= 0.35 -> Auto-resolve low risk
  - 0.35 < P < 0.65 -> Route to Tier 2 (LLM)
  - Ensemble std >= 0.15 -> Route to Tier 2 (uncertain)
- **Training data:** `backend/ml/training_data_v2.npz` (253,568 samples, 341 MB)
- **Training script:** `backend/ml/train_xgboost.py` (two-phase: gather + train)
- **Calibrator:** `backend/ml/xgboost_calibrator.pkl` (NOT YET GENERATED)
- **Lines of code (predictor):** 233
- **Lines of code (training):** 1195
- **Status:** 🔧 Retrain pending -- corpus built, model not retrained on v2 data

## EPSS Substitution Models

Three generations of EPSS substitution models for CVEs missing EPSS scores:

### epss_model (v1) -- Deprecated

- **File:** `backend/ml/epss_model.pkl` (523 KB)
- **Training script:** `backend/ml/train_epss_substitutor.py`
- **Data:** Synthetic training data only
- **Status:** Deprecated -- replaced by v2

### epss_model_v2 -- Deprecated

- **File:** `backend/ml/epss_model_v2.pkl` (1 MB)
- **Training script:** `backend/ml/train_epss_v2.py`
- **Data:** Improved synthetic training data
- **Status:** Deprecated -- replaced by v3

### epss_model_v3 -- Current

- **File:** `backend/ml/epss_model_v3.pkl` (1 MB)
- **Training script:** `backend/ml/train_epss_v3.py`
- **Architecture:** XGBoost regressor (XGBRegressor)
- **Input features:** EPSS score (or None), CWE category, synthetic sector weights
- **Output:** Sector-adjusted EPSS score [0, 1]
- **Data:** Real FIRST.org EPSS data (`backend/data/epss_cache.json`, 344,852 scores)
- **Predictor wrapper:** `backend/ml/epss_substitutor.py` (hybrid ML + rule engine with fallback chain)
- **Used by:** `backend/routers/ingest.py` during ingestion pipeline
- **Status:** Active -- v3 is the live model

## Training Pipeline (XGBoost)

```
NVD API 2.0 feeds
  -> fetch_nvd_corpus.py
    -> nvd_corpus.json (186K CVEs, 145 MB)
      -> build_training_corpus.py (+ EPSS, KEV, vendor index, ExploitDB)
        -> training_data_v2.npz (253K samples, 420 cols, 341 MB)
          -> train_xgboost.py
            -> xgboost_model.pkl
            -> xgboost_calibrator.pkl
```

## Data Sources

| Resource | File | Size |
|----------|------|------|
| NVD Corpus | `backend/data/nvd_corpus.json` | 205 MB |
| EPSS Cache | `backend/data/epss_cache.json` | 20 MB |
| KEV Cache | `backend/data/kev_cache.json` | 518 KB |
| CMDB | `backend/data/mock_cmdb.json` | 28 KB |
| Training v2 | `backend/ml/training_data_v2.npz` | 341 MB |
| KEV Coverage | -- | 835 of 1,631 (51.2% -- 516 missing, mostly pre-2019) |
| ExploitDB | `backend/data/files_exploits.csv` | 10 MB |

## SBERT Encoder

- **File:** `backend/ml/encoder.py`
- **Model:** `sentence-transformers/all-MiniLM-L6-v2`
- **Input:** Raw text (CVE description)
- **Output:** 384-dimensional float32 vector
- **Cache:** `@lru_cache(maxsize=8192)`
- **Memory:** ~90 MB after first load
- **Pre-loaded:** During FastAPI lifespan startup via `_get_embedder()`
- **Called by:** Tier 1 (XGBoost) and vector_store (RAG)

## Tier 2: Cloud LLM

- **File:** `backend/pipeline/tier_2.py`
- **Providers:** OpenAI gpt-4o-mini, Anthropic, TogetherAI
- **Env vars:** `TRIAGEMATE_LLM_API_KEY`, `TRIAGEMATE_LLM_PROVIDER`
- **Prompt:** Force-reflection (Step A -> B -> C -> structured JSON)
- **Cost:** ~$0.0004/analysis (gpt-4o-mini)
- **Fallback chain:** Primary -> Backup -> KNOWN_CONFLICTS -> Neutral default
- **RAG:** LanceDB at `backend/data/lancedb/` with 9 demo documents
- **Doc ingestion:** `backend/ml/ingest_docs.py` (CLI for adding documents)
