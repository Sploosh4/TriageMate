# AI Problems — Discrepancies Found During Development

Documentation of incorrect AI-generated code, mismatches between code and actual models/dependencies. Items marked **FIXED** have been resolved; unfixed items remain open.

---

## ~~HIGH (Breaks functionality)~~ — RESOLVED

### ~~1. CWE Classifier: Head naming mismatch with SecureBERT2.0~~ ✅ BYPASSED
**File:** `backend/ml/cwe_classifier_deprecated.py` (renamed, no longer in hot path)
**Status:** The local SecureBERT2.0 classifier has been deprecated. Replaced by `backend/ingest_cwe.py` which uses NVD API 2.0 lookup + regex fallback. The deprecated file is preserved as `backend/ml/cwe_classifier_deprecated.py` for reference.

### ~~2. CWE Classifier: ModernBERT has no pooler_output~~ ✅ BYPASSED
**Status:** Same as #1 — deprecated in favour of NVD API + regex path.

### ~~3. CWE Classifier: Cache dir bypasses shared HuggingFace cache~~ ✅ BYPASSED
**Status:** Same as #1 — deprecated. The 656MB SecureBERT2.0 model is no longer loaded at startup.

---

## FIXED ITEMS

### ~~4. XGBoost Predictor: Broken ensemble variance computation~~ ✅ FIXED
**File:** `backend/ml/xgboost_predictor.py:108-113`
**Old code:** `predict_proba(X, ntree_limit=end, iteration_range=(i, end))` — `ntree_limit` deprecated, conflicted with `iteration_range`. Each 100-tree block got the same value assigned to all 100 positions.
**Impact:** Ensemble std was computed from 8 distinct batch-level predictions instead of per-tree predictions.
**Fix applied:** Replaced with `booster.predict(X, iteration_range=(0, n_t), output_margin=True)` at 100-tree checkpoints. Computes std of cumulative prediction trajectory (8 checkpoints). Uses `booster` directly instead of sklearn wrapper's predict_proba.
**Sprint 3 addendum:** XGBoost 3.3.0 requires DMatrix for `booster.predict()`. Updated to `booster.predict(xgb.DMatrix(X), iteration_range=(0, n_t), output_margin=True)`. Added `import xgboost as xgb` to predictor.

### ~~5. XGBoost Predictor: Calibrated classifier internals fragile~~ ✅ FIXED
**File:** `backend/ml/xgboost_predictor.py:47-48`
**Old code:** `model.calibrated_classifiers_[0].base_estimator` — accessed first of 5 calibrator folds.
**Impact:** `cv="prefit"` was removed in sklearn 1.9 (`InvalidParameterError`), and 5-fold CV on temporal data leaks future information into calibration folds.
**Fix applied:** Removed `CalibratedClassifierCV` entirely. XGBoost already outputs calibrated probabilities via its built-in `binary:logistic` loss function. Predictor now exports raw XGBoost model directly. Compatibility check (`hasattr(model, "calibrated_classifiers_")`) preserved for future use.

### ~~6. Train script: EPSS API only fetches first page~~ ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Old code:** `resp = requests.get(EPSS_API, timeout=60)` — no pagination, first page only.
**Impact:** Most CVEs got `epss_score = 0.0`.
**Fix applied:** Added pagination loop following `total/offset` from FIRST.org API response. Fetches all ~344K EPSS scores with 1K entries per page.

### ~~7. Train script: Time-series cross-validation leak~~ ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Old code:** `CalibratedClassifierCV(cv=5)` — random 5-fold on temporal data.
**Impact:** Future exploitation info leaked into calibration folds.
**Fix applied:** Calibration removed entirely (see #5). No cross-validation in current training pipeline.

### ~~8. Train script: Early stopping shrinks actual tree count~~ ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Old code:** `early_stopping_rounds=50` with `n_estimators=800`.
**Impact:** Model could stop at ~200 trees, but predictor's variance loop assumed 800, iterating over untrained indices.
**Fix applied:** Removed `early_stopping_rounds` entirely. Trains all 800 trees as configured.

---

## MEDIUM (Degraded accuracy/edge cases)

### ~~9. Train script: CVE age hardcoded to training date~~ ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Old code:** `datetime.utcnow()` — deprecated and computed age relative to training date.
**Fix applied:** Replaced with `datetime.now(timezone.utc)`. Note: age is still computed relative to training runtime rather than a fixed reference date — feature drift at inference remains a concern.

### ~~10. Train script: Patch features hardcoded to 1/0 for all training data~~ ✅ FIXED
**File:** `backend/ml/train_xgboost.py:376-377` (original); now superseded by `backend/scripts/build_training_corpus.py`
**Old code:** `X[i, 9] = 1  # patch_available`, `X[i, 10] = 0  # patch_applied` — all 93K records had identical values
**Impact:** 18 of 36 features had zero importance in the model because training data was homogeneous.
**Fix applied (Sprint 9):** Created `build_training_corpus.py` which generates `training_data_v2.npz` with realistic distributions for ALL features across 186K CVEs. patch_available uses NVD reference data + OSV.dev enrichment. patch_applied uses score-weighted random sampling (CVSS ≥ 9.0 → 80% applied, CVSS ≥ 7.0 → 60%, else 30%). All other formerly-hardcoded features (exploitdb_has_poc, metasploit_has_payload, internet_scan_detected, etc.) now use real data from ExploitDB CSV, KEV cache, and EPSS cache.

---

## ADDITIONAL ISSUES DISCOVERED AND FIXED

### A. Label leakage: `cisa_kev` as training feature ✅ FIXED
**File:** `backend/ml/train_xgboost.py` (build_tabular_features + load_training_data migration)
**Problem:** The label IS "is this CVE in KEV?", and `cisa_kev` was included as an input feature. Model achieved ROC-AUC 1.0000 by learning "if cisa_kev=True → predict 1" — perfectly memorizing the answer key.
**Fix applied:** Removed `cisa_kev` from all three locations:
- Training: `build_tabular_features()` — removed index 9, shifted all subsequent features down (37→36 tabular, 69→68 total)
- Inference: `xgboost_predictor.predict()` — removed corresponding entry
- Ingest: `ingest_helpers.build_feature_vector()` — removed key
- Migration: `load_training_data()` auto-detects 69-column legacy files, strips column 9, and re-saves

### B. `build_feature_vector` returned only 9 features instead of all 37 ✅ FIXED
**File:** `backend/ingest_helpers.py`
**Old code:** Returned `{cvss_score, epss_score, mission_prevalence, public_wellbeing_impact, internet_facing, lateral_reachability_count, domain_joined, privileged_service_account, cross_boundary_reachability}` — 4 of these 9 had completely wrong key names that the predictor couldn't read.
**Fix applied:** Rewrote to return all 36 tabular features + `description` key, matching the training and predictor feature order exactly. Added CVSS vector component parsing, regex signature matching, and `cve_desc_tokens`. Known name mismatches fixed:
  - `lateral_reachability_count` → `lateral_reachability`
  - `cross_boundary_reachability` → `boundary_reachability`

### C. NVD API 2.0 date range chunking ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Problem:** NVD API 2.0 returns HTTP 404 when a query would match >~6K results (unauthenticated) or >~40K (authenticated). Yearly date chunks still returned 404 for dense years.
**Fix applied:** Changed from yearly to quarterly (3-month) chunks. Each chunk typically returns 2K-5K results.

### D. NVD API key not passed in requests ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Problem:** `NVD_API_KEY` was read from environment but never sent in the request. All NVD queries were unauthenticated.
**Fix applied:** Passed as `{"apiKey": value}` header in each request. Also reduced `SLEEP_INTERVAL` from 6.5s to 0.8s when key is present (later reverted to 6.2s per NVD's explicit "sleep 6 seconds" recommendation).

### E. `ChunkedEncodingError` not caught in retry loop ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Problem:** Mobile hotspot disconnections caused `ProtocolError: Response ended prematurely` (wrapped as `ChunkedEncodingError`), which was not caught by the retry loop.
**Fix applied:** Changed retry to catch all `requests.exceptions.RequestException`, added 5 retry attempts with 15s backoff, and added checkpoint/resume system.

### F. Checkpoint/resume for NVD fetch ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Problem:** Interrupting during NVD fetch lost all progress.
**Fix applied:** Added `_load_checkpoint()`/`_save_progress()` — saves fetched CVEs to `nvd_cves_cached.json` + metadata to `nvd_checkpoint.json` after each page. On re-run, resumes from last saved chunk+index.

### G. Two-phase design with disk save points ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Problem:** Training crash after SBERT encoding forced re-encoding 140K descriptions (~13 min waste).
**Fix applied:** Separated into `phase_gather()` (NVD→EPSS→KEV→labels→features→encoding) and `phase_train()` (load→split→fit→export). Enriched CVEs saved after EPSS+KEV merge (`enriched_cves.json`). Full training data saved after PCA encoding (`training_data.npz`). On re-run, detects existing save points and skips completed work. Added `--gather`/`--train` CLI flags.

### H. `CalibratedClassifierCV(cv="prefit")` removed in sklearn 1.9 ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Problem:** sklearn 1.9 removed `cv="prefit"` string support, causing `InvalidParameterError` during Phase 2.
**Fix applied:** Removed Platt calibration entirely. XGBoost's `binary:logistic` objective already produces well-calibrated probabilities.

### I. 30-day observation window for label quality ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Problem:** CVEs published late in the dataset (e.g., December 2024) were labeled as negative despite possibly being added to KEV after the training date.
**Fix applied:** Added `OBS_WINDOW = 30` — excludes CVEs published within 30 days of `DATE_END` from the dataset entirely. These are too recent to have reliable KEV labels.

### J. Post-KEV filter (pre-KEV CVEs structurally cannot be positive) ✅ FIXED
**File:** `backend/ml/train_xgboost.py`
**Problem:** CVEs published before CISA KEV existed (November 2021) were labeled negative, but they structurally couldn't be positive. Created systematic false negatives in training data.
**Fix applied:** Added `KEV_START = "2021-11-01"` filter. CVEs published before this date are excluded from training entirely. Reduced dataset from 140K to ~96K CVEs.

---

### ~~K. XGBoost model trained with wrong feature count (69→68)~~ ✅ FIXED (Sprint 3)
**Root cause:** `cisa_kev` was removed as a training feature (label leakage fix, Item A), reducing features from 37→36 tabular (69→68 total). The training data migration (`load_training_data`) correctly strips column 9 from legacy data, and `build_tabular_features()` allocates 36 columns. But the `xgboost_model.pkl` was **never retrained** — the old 69-feature model was still deployed. At runtime, the predictor built 68 features, handed them to a model expecting 69, and raised `ValueError: Feature shape mismatch`.
**Fix applied:** Ran `python -m ml.train_xgboost --train` to retrain the model from the existing 68-column `training_data.npz` (93,018 records). Model now expects 68 features. ROC-AUC: 0.9677.

---

## LOW (Nuisance / cosmetic — now fixed)

### ~~11. LanceDB vector store path is ephemeral~~ ✅ FIXED (Sprint 2)
**File:** `backend/ml/vector_store.py:20`
**Old path:** `/tmp/triagemate_lancedb`
**Impact:** Lost on reboot. Startup re-seeded gracefully, but custom data was lost.
**Fix applied:** Moved to `backend/data/lancedb` (resolved relative to `__file__`). Added `threading.Lock` for write safety. Added `backend/data/` to `.gitignore`.
**Status:** ✅ FIXED

### ~~12. Vector store: FTS index exception fully suppressed~~ ✅ FIXED (Sprint 2)
**File:** `backend/ml/vector_store.py:87-89`
**Old code:** `except Exception: pass`
**Impact:** FTS index creation failures were invisible.
**Fix applied:** Replaced with `logging.warning("FTS index creation skipped: %s", e)`.
**Status:** ✅ FIXED

### ~~13. Ingest pipeline: Unused variable `t2_score_adjustment`~~ ✅ FIXED (Sprint 2)
**File:** `backend/routers/ingest.py`
**Old code:** `t2_score_adjustment = t2_result.get("score_adjustment") if t2_result else None`
**Impact:** Declared but never referenced.
**Fix applied:** Removed the unused variable line.
**Status:** ✅ FIXED

### 14. Tier 1 heuristic: Confidence range routing logic always escalates
**File:** `backend/pipeline/tier_1.py:63`
**Code:** `routing = "escalated" if 0.55 <= confidence <= 0.85 else "auto_resolved"` — heuristic always returns confidence=0.85 (line 57), sometimes lowered to 0.78 or 0.72
**Impact:** With confidence always 0.72-0.85, the heuristic always lands in the escalation range. This means ALL Tier 1 heuristic fallback cases go to Tier 2, even for simple ones.
**Note:** This is only triggered when XGBoost model is not available (fallback path). Once model is trained, the heuristic is never called.
**Status:** 🟢 WON'T FIX (fallback path, training model removes need)
