# TriageMate — ML Model Inventory

> Canonical reference — read this before touching any ML code.

> Generated: 2026-07-11 15:33:52

---

## Model Summary

| Artifact | File | Size | Type |
|----------|------|------|------|
| epss_model | `backend/ml/epss_model.pkl` | 523 KB | pickled model |
| epss_model_v2 | `backend/ml/epss_model_v2.pkl` | 1 MB | pickled model |
| epss_model_v3 | `backend/ml/epss_model_v3.pkl` | 1 MB | pickled model |
| epss_model_v4 | `backend/ml/epss_model_v4.pkl` | 373 KB | pickled model |
| pre_tier_model | `backend/ml/pre_tier_model.pkl` | 24 MB | pickled model |
| xgboost_calibrator | `backend/ml/xgboost_calibrator.pkl` | 827 B | pickled model |
| xgboost_model | `backend/ml/xgboost_model.pkl` | 1 MB | pickled model |
| training_data | `backend/ml/training_data.npz` | 156 MB | numpy training data |
| training_data_v2 | `backend/ml/training_data_v2.npz` | 341 MB | numpy training data |
| enriched_cves | `backend/ml/enriched_cves.json` | 179 MB | JSON data |
| epss_reference_distributions | `backend/ml/epss_reference_distributions.json` | 9 KB | JSON data |
| model_registry | `backend/ml/model_registry.json` | 595 B | JSON data |
| model_registry_epss | `backend/ml/model_registry_epss.json` | 2 KB | JSON data |
| model_registry_pre_tier | `backend/ml/model_registry_pre_tier.json` | 407 B | JSON data |
| nvd_checkpoint | `backend/ml/nvd_checkpoint.json` | 72 B | JSON data |
| nvd_cves_cached | `backend/ml/nvd_cves_cached.json` | 80 MB | JSON data |
| pre_tier_metrics | `backend/ml/pre_tier_metrics.json` | 2 KB | JSON data |
| pre_tier_reference_distributions | `backend/ml/pre_tier_reference_distributions.json` | 12 KB | JSON data |
| pretier_supplemental | `backend/ml/pretier_supplemental.json` | 206 KB | JSON data |
| pretier_training_data | `backend/ml/pretier_training_data.json` | 37 KB | JSON data |
| reference_distributions | `backend/ml/reference_distributions.json` | 15 KB | JSON data |
| synthetic_data_v2 | `backend/ml/synthetic_data_v2.json` | 1 MB | JSON data |
| synthetic_findings_v4 | `backend/ml/synthetic_findings_v4.json` | 344 KB | JSON data |
| synthetic_holdout_v2 | `backend/ml/synthetic_holdout_v2.json` | 233 KB | JSON data |
| threshold_info | `backend/ml/threshold_info.json` | 403 B | JSON data |

## Script Inventory

| Script | Path | Description |
|--------|------|-------------|
| encoder | `backend/ml/encoder.py` | SBERT text encoder — raw 384-dimensional embeddings. |
| epss_substitutor | `backend/ml/epss_substitutor.py` | EPSS substitution — hybrid ML + rule engine (v4 with fallback chain). |
| fetch_epss_data | `backend/ml/fetch_epss_data.py` | Fetch real EPSS scores from FIRST.org and cache them locally. |
| generate_supplemental_hostnames | `backend/ml/generate_supplemental_hostnames.py` | Generate 300+ supplemental WA Government hostname records with diverse, |
| generate_synthetic_data_v2 | `backend/ml/generate_synthetic_data_v2.py` | Synthetic Data Generator v2 — Research-Backed WA Government Hostname Generation. |
| generate_synthetic_findings | `backend/ml/generate_synthetic_findings.py` | Generate synthetic Tenable-style vulnerability findings for EPSS v4 training. |
| ingest_docs | `backend/ml/ingest_docs.py` | CLI script to ingest documents into the LanceDB vector store. |
| pretier_features | `backend/ml/pretier_features.py` | Shared feature extraction for the Pre-Tier multi-label classifier. |
| train_epss_substitutor | `backend/ml/train_epss_substitutor.py` | Train an XGBoost EPSS substitution model using synthetic training data. |
| train_epss_v2 | `backend/ml/train_epss_v2.py` | Train an improved XGBoost EPSS substitution model (v2). |
| train_epss_v3 | `backend/ml/train_epss_v3.py` | Train EPSS substitution model v3 using real FIRST.org EPSS data. |
| train_epss_v4 | `backend/ml/train_epss_v4.py` | Train EPSS substitution model v4 using sector-aware synthetic findings. |
| train_pre_tier | `backend/ml/train_pre_tier.py` | Offline training pipeline for the Pre-Tier multi-label classifier. |
| train_xgboost | `backend/ml/train_xgboost.py` | Offline XGBoost training pipeline — two-phase design. |
| vector_store | `backend/ml/vector_store.py` | LanceDB embedded vector store for RAG document retrieval. |
| xgboost_predictor | `backend/ml/xgboost_predictor.py` | Tier 1 XGBoost exploitation probability predictor. |
| aggregate_tenable_sectors | `backend/scripts/aggregate_tenable_sectors.py` | Aggregate Tenable vulnerability scan findings by (CVE, sector) for EPSS |
| bughunt_multiplier_check | `backend/scripts/bughunt_multiplier_check.py` | Bug Hunt: Context multiplier edge case verification. |
| build_cwe_hierarchy | `backend/scripts/build_cwe_hierarchy.py` | Build CWE hierarchy JSON from MITRE CWE XML. |
| build_training_corpus | `backend/scripts/build_training_corpus.py` | Unified training corpus builder — combines all data sources into |
| build_vendor_index | `backend/scripts/build_vendor_index.py` | Build vendor_popularity.json from NVD corpus vendor frequency. |
| check_benchmark_regression | `backend/scripts/check_benchmark_regression.py` | Called by CI pipeline after benchmarks run. |
| compute_canonical_scores | `backend/scripts/compute_canonical_scores.py` | Compute canonical scores from seed data using the live scoring pipeline. |
| compute_epss_reference | `backend/scripts/compute_epss_reference.py` | Compute EPSS reference distributions for drift monitoring. |
| compute_pretier_reference | `backend/scripts/compute_pretier_reference.py` | Compute reference distributions for Pre-Tier drift monitoring. |
| compute_reference_dists | `backend/scripts/compute_reference_dists.py` | Compute reference distributions for ML drift monitoring. |
| fetch_nvd_corpus | `backend/scripts/fetch_nvd_corpus.py` | Bulk NVD API 2.0 corpus builder — fetch 200K+ CVEs with full metadata. |
| ingest_synthetic_to_db | `backend/scripts/ingest_synthetic_to_db.py` | Ingest synthetic data from a JSON file into the TriageMate database. |
| load_research_refs | `backend/scripts/load_research_refs.py` | Load research references from the WA government infrastructure research report. |
| refresh_caches | `backend/scripts/refresh_caches.py` | Refresh demo data caches for TriageMate. |
| stress_report | `backend/scripts/stress_report.py` | Stress test report generator for TriageMate. |
| validate_synthetic_data | `backend/scripts/validate_synthetic_data.py` | Data Validation Toolkit for Synthetic WA Government Hostname Data. |
| verify_seed_scores | `backend/scripts/verify_seed_scores.py` | Loads seed_data.py demo CVEs, runs the scoring pipeline, |
| calibration_audit | `backend/analysis/calibration_audit.py` | Calibration audit for the Tier 1 XGBoost exploitation-probability model. |
| drift | `backend/analysis/drift.py` | ML Drift Monitoring — PSI (Population Stability Index) computation. |
| epss_eval | `backend/analysis/epss_eval.py` | EPSS as Standalone Predictor — Baseline Analysis |
| feature_parity_check | `backend/analysis/feature_parity_check.py` | Feature parity checker — verifies that build_training_corpus.py and |
| stress_db | `backend/analysis/stress_db.py` | Stress test result database module. |
| validate_conversion | `backend/analysis/validate_conversion.py` | Validate enriched_cves.json against build_tabular_features expectations. |
| rate_limit | `backend/middleware/rate_limit.py` | import os |

## ML Directory (`backend/ml/`)

- `README.md`  (368 B)
- `encoder.py`  (2 KB)
- `enriched_cves.json`  (179 MB)
- `epss_model.pkl`  (523 KB)
- `epss_model_v2.pkl`  (1 MB)
- `epss_model_v3.pkl`  (1 MB)
- `epss_model_v4.pkl`  (373 KB)
- `epss_reference_distributions.json`  (9 KB)
- `epss_substitutor.py`  (24 KB)
- `fetch_epss_data.py`  (4 KB)
- `generate_supplemental_hostnames.py`  (14 KB)
- `generate_synthetic_data_v2.py`  (29 KB)
- `generate_synthetic_findings.py`  (17 KB)
- `ingest_docs.py`  (7 KB)
- `model_registry.json`  (595 B)
- `model_registry_epss.json`  (2 KB)
- `model_registry_pre_tier.json`  (407 B)
- `nvd_checkpoint.json`  (72 B)
- `nvd_cves_cached.json`  (80 MB)
- `pre_tier_metrics.json`  (2 KB)
- `pre_tier_model.pkl`  (24 MB)
- `pre_tier_reference_distributions.json`  (12 KB)
- `pretier_features.py`  (18 KB)
- `pretier_supplemental.json`  (206 KB)
- `pretier_training_data.json`  (37 KB)
- `reference_distributions.json`  (15 KB)
- `synthetic_data_v2.json`  (1 MB)
- `synthetic_findings_v4.json`  (344 KB)
- `synthetic_holdout_v2.json`  (233 KB)
- `threshold_info.json`  (403 B)
- `train_epss_substitutor.py`  (10 KB)
- `train_epss_v2.py`  (18 KB)
- `train_epss_v3.py`  (12 KB)
- `train_epss_v4.py`  (14 KB)
- `train_pre_tier.py`  (22 KB)
- `train_xgboost.py`  (50 KB)
- `training_data.npz`  (156 MB)
- `training_data_v2.npz`  (341 MB)
- `vector_store.py`  (14 KB)
- `xgboost_calibrator.pkl`  (827 B)
- `xgboost_model.pkl`  (1 MB)
- `xgboost_predictor.py`  (15 KB)

## Data Directory (`backend/data/`)

- `demo_scenarios.json`  (4 KB)
- `epss_cache.json`  (20 MB)
- `files_exploits.csv`  (10 MB)
- `kev_cache.json`  (518 KB)
- 📁 `lancedb/`  (4 KB)
- `mock_cmdb.json`  (28 KB)
- `nvd_cache.json`  (118 KB)
- `nvd_corpus.json`  (205 MB)
- `triagemate.db`  (0 B)
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
- **Lines of code (predictor):** 216
- **Lines of code (feature extractor):** 647
- **Notes:** Model loaded lazily via `threading.Lock` on first inference. Never retrained from the live app.

## Tier 1: XGBoost Exploitation Predictor

### Model State: Retrained

| Metric | Value |
|--------|-------|
| Samples | 253,568 |
| Features | 419 (35 tabular + 384 SBERT) |
| ROC-AUC | 0.9459 |
| Training date | 2026-07-08 |

- **File:** `backend/ml/xgboost_model.pkl`
- **Predictor wrapper:** `backend/ml/xgboost_predictor.py`
- **Input:** 419 total dimensions = 35 tabular + 384 SBERT embedding

  **35 tabular features** from `ingest_helpers.py`:
  - 8 CVSS metrics (av, ac, pr, ui, s, c, i, a)
  - cvss_score (metadata only, NOT a model input), epss_score
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

  **Dimension note:**
  - Feature vector: 419 columns (35 tabular + 384 SBERT)
  - Model trained on 419 features — predictor sends 419 features — aligned ✓

- **Output:** Binary exploitation probability [0, 1]
- **ROC-AUC:** 0.9459 (retrained on 253,568 samples, 2026-07-08)
- **Routing thresholds:**
  - P >= 0.65 -> Auto-resolve exploited (skip Tier 2)
  - P <= 0.35 -> Auto-resolve low risk
  - 0.35 < P < 0.65 -> Route to Tier 2 (LLM)
  - Ensemble std >= 0.15 -> Route to Tier 2 (uncertain)
- **Training data:** `backend/ml/training_data_v2.npz` (253,568 samples, 341 MB)
- **Training script:** `backend/ml/train_xgboost.py` (two-phase: gather + train)
- **Calibrator:** `backend/ml/xgboost_calibrator.pkl` (LogisticRegression, EXISTS)
- **Lines of code (predictor):** 438
- **Lines of code (training):** 1353
- **Status:** ✅ Retrained 2026-07-08 on 253,568 samples (v2 data)
  ⚠️ Dimension mismatch: model trained with 420 features, predictor sends 419

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
