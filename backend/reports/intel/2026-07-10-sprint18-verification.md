# Sprint 18 — Pre-Implementation Verification

**Date:** 2026-07-10
**Requested by:** Commander (sprint planning)
**Sources consulted:** `tier_0.py`, `ingest_helpers.py`, `ingest.py`, `xgboost_predictor.py`, `epss_substitutor.py`, `pre_tier.py`, `database.py`, `queue.py`, `pretier_features.py`, `test_drift.py`, `test_drift_ml.py`, `threshold_info.json`, `reference_distributions.json`, `2026-07-09-router-bugs-verification.md`, `2026-07-10-cwe-epss-investigation.md`

---

## Item 1: NVD Reference Count ≥21 Tier 0 Rule

**Status: NOT_STARTED** — No implementation exists.

### Evidence
- `nvd_reference_count` **is** already collected in the feature dict (`backend/ingest_helpers.py:478`) and is part of the XGBoost tabular feature vector (`backend/ml/xgboost_predictor.py:80`).
- **However**, `evaluate_tier_0()` in `backend/pipeline/tier_0.py:19-25` does **NOT** accept `nvd_reference_count` as a parameter. Its signature is:
  ```python
  def evaluate_tier_0(cvss_score, cisa_kev, epss_score, data_classification, internet_facing)
  ```
- The constant `NVD_REF_THRESHOLD` does **NOT** exist anywhere in the codebase (only in the sprint plan).
- `ingest.py` (line ~158-165) calls `evaluate_tier_0()` without any `nvd_reference_count` argument and does **not** call `get_nvd_data()` directly (it only calls it indirectly via `get_cwe()` at line 109).
- No `test_tier0.py` exists in `backend/tests/`.

### What's Already in Place
- `get_nvd_data()` returns `"nvd_reference_count"` key (`integrations/nvd.py:86,298`)
- `build_feature_vector()` extracts it (`ingest_helpers.py:478`)
- Cached via 24h TTL — second call is free

---

## Item 2: CWE-Stratified EPSS Thresholds — Fix Dead Code

**Status: PARTIALLY_DONE** — Part A (dead code fix) is **already complete**. Parts B and C are **not started**.

### Part A: Add `cwe_class` and `cisa_kev` to `build_feature_vector()`
**Status: ✅ ALREADY DONE** — Both keys are present in the returned dict.

- `backend/ingest_helpers.py:498`: `"cisa_kev": bool(payload.cisa_kev) if hasattr(payload, "cisa_kev") else False,`
- `backend/ingest_helpers.py:499`: `"cwe_class": cwe_class,`
- This means `_tier_zero_check()` in `backend/ml/xgboost_predictor.py:218-245` can now successfully read:
  - `features.get("cwe_class", "")` → returns actual CWE class
  - `features.get("cisa_kev", False)` → returns actual KEV status
- The `CWE_EPSS_THRESHOLDS` dict (lines 41-50) and the logic in `_tier_zero_check()` (lines 234-236) are now **working code**, not dead code.
- **Note:** The 2026-07-09 audit report (`backend/reports/audits/2026-07-09-router-bugs-verification.md:135-170`) confirmed this as Bug 4 (HIGH). The fix appears to have been applied in the latest commit `2881e1d "Bug finding sprint: 26 bugs fixed across codebase"`. The investigation report `backend/reports/intel/2026-07-10-cwe-epss-investigation.md` was written before this fix and its finding #1 (lines 163-170) is **now out of date** — the fix is already in place.

### Part B: Extend CWE-stratified thresholds to Tier 0's `evaluate_tier_0()`
**Status: ❌ NOT STARTED**

- `evaluate_tier_0()` (tier_0.py:19-25) does **NOT** accept `cwe_class` parameter.
- `ingest.py:110` computes `cwe_class`, but line 159-165 passes zero CWE context to Tier 0.
- The `LOW_EPSS_THRESHOLD = 0.10` (tier_0.py:16) remains monolithic.
- No CWE-aware EPSS threshold logic exists in Tier 0.

### Part C: Expand CWE threshold coverage (optional bonus)
**Status: ❌ NOT STARTED** — Still exactly 8 CWEs in `CWE_EPSS_THRESHOLDS`.

---

## Item 3: Pre-Tier RF Drift Monitoring

**Status: NOT_STARTED** — No implementation exists.

### Evidence
- **Database schema:** Neither `pre_tier_features` nor any such column exists in:
  - `vulnerabilities` table (SQLite: database.py:272-381, PG: database.py:549-657)
  - `resolved_vulnerabilities` table (SQLite: database.py:398-483, PG: database.py:675-760)
  - The only ML drift column is `tier_1_features TEXT` (database.py:375, 432, 652, 709)
- **Pipeline:** `pre_tier.py:_predict_with_model()` (lines 121-162) returns only mission tags dict — does **not** return or store feature vectors. No `extract_pre_tier_features()` function exists.
- **API endpoint:** No `GET /api/drift/pre-tier` endpoint exists. The drift endpoints are:
  - `GET /api/drift` (general drift, queue.py:41)
  - `GET /api/drift/ml` (XGBoost drift, queue.py:221)
- **Reference distributions:** No `pre_tier_reference_distributions.json` exists. Only `backend/ml/reference_distributions.json` exists (for XGBoost model).
- **Scripts:** No `compute_pre_tier_reference.py` script exists.
- **Tests:** No Pre-Tier drift tests exist. Existing drift tests cover only `GET /api/drift` (`test_drift.py`) and `GET /api/drift/ml` (`test_drift_ml.py`).

### What's Already in Place (can be reused)
- `backend/ml/pretier_features.py:361` — `extract_features(hostname)` already returns a 60-dim feature dict
- `backend/ml/pretier_features.py:602` — `feature_vector_to_array(features)` converts to fixed-order list
- `backend/analysis/drift.py:62` — `compute_drift()` can be reused (same as ML drift)
- `backend/routers/queue.py:209` — `_load_reference_dists()` pattern can be reused

---

## Item 4: EPSS Drift Monitoring

**Status: NOT_STARTED** — No implementation exists.

### Evidence
- **Database schema:** Neither `epss_features` nor any such column exists in:
  - `vulnerabilities` table (SQLite and PG)
  - `resolved_vulnerabilities` table (SQLite and PG)
- **Pipeline:** `calculate_substitution()` in `epss_substitutor.py:627-712` returns only `{substituted, substituted_epss, original_epss, confidence, reason, model_version}` — no feature vectors. No internal feature vector is stored or returned.
- **API endpoint:** No `GET /api/drift/epss` endpoint exists.
- **Reference distributions:** No `epss_reference_distributions.json` exists.
- **Scripts:** No `compute_epss_reference.py` script exists.
- **Tests:** No EPSS drift tests exist.

### What's Already in Place (can be reused)
- `epss_substitutor.py:326` — `_build_feature_vector_v2()` builds 37-dim feature vector (used internally by `_ml_predict()`)
- `epss_substitutor.py:297` — `_build_feature_vector_v1()` builds 22-dim feature vector
- `analysis/drift.py:62` — `compute_drift()` can be reused
- `queue.py:209` — `_load_reference_dists()` pattern can be reused

---

## Bonus Items

### Bonus A: Extend CWE_EPSS_THRESHOLDS Coverage
**Status: ❌ NOT STARTED**
- Exactly **8 CWEs** present in `CWE_EPSS_THRESHOLDS` (xgboost_predictor.py:41-50), not >8
- `DEFAULT_EPSS_THRESHOLD` is still 0.84

### Bonus B: CWE-Stratified KEV Threshold in Tier 0
**Status: ❌ NOT STARTED**
- `KEV_EPSS_THRESHOLD = 0.90` is still monolithic

### Bonus C: Update `threshold_info.json` with CWE Data
**Status: ❌ NOT STARTED**
- `threshold_info.json` contains: `{"classification_threshold": 0.4724170854271357, "val_f1": 0.7415730337078652}`
- No CWE-stratified data present

### Bonus D: Document Scoring Weight Design
**Status: ❌ NOT STARTED**
- No `docs/architecture/scoring-weights.md` exists

---

## Summary

| Item | Status | Effort |
|------|--------|--------|
| **1: NVD Ref Count ≥21 Tier 0 Rule** | 🔴 NOT_STARTED | ~30 min |
| **2A: Fix build_feature_vector() dead code** | ✅ **ALREADY DONE** | 0 min — skip |
| **2B: CWE-stratified thresholds in Tier 0** | 🔴 NOT_STARTED | ~45 min |
| **2C: Expand CWE threshold coverage** | 🔴 NOT_STARTED | ~20 min |
| **3: Pre-Tier RF Drift Monitoring** | 🔴 NOT_STARTED | ~3-4 hrs |
| **4: EPSS Drift Monitoring** | 🔴 NOT_STARTED | ~3-4 hrs |
| **Bonus A: Extend CWE_EPSS_THRESHOLDS** | 🔴 NOT_STARTED | ~20 min |
| **Bonus B: CWE KEV threshold** | 🔴 NOT_STARTED | ~15 min |
| **Bonus C: Update threshold_info.json** | 🔴 NOT_STARTED | ~15 min |
| **Bonus D: Scoring weights doc** | 🔴 NOT_STARTED | ~30 min |

### Items That Can Proceed
- **Item 1** — fully unimplemented, ready for strike
- **Items 2B, 2C** — Part A is done (lucky break), so only the Tier 0 extension remains
- **Items 3, 4** — fully unimplemented, both have reusable building blocks (`extract_features()` for Pre-Tier; `_build_feature_vector_v2/v1()` for EPSS; `compute_drift()` and `_load_reference_dists()` pattern)
- **All Bonus items** — fully unimplemented

### Items Already Done (skip)
- **Item 2 Part A** — both `cisa_kev` and `cwe_class` are already in `build_feature_vector()`'s returned dict. The `_tier_zero_check()` dead code bug is already fixed. The sprint plan should be updated to mark this as complete.

### Risks/Concerns
1. **The investigation report is stale.** `backend/reports/intel/2026-07-10-cwe-epss-investigation.md` was written before the Part A fix was applied. Its "Critical" finding (#1) about missing `cwe_class`/`cisa_kev` is **no longer valid**. Recommend the bookkeeper flag it as OUTDATED.
2. **Drift monitoring (Items 3, 4) requires schema migrations** — new columns on 4 table definitions (SQLite vulnerabilities + resolved_vulnerabilities, PG vulnerabilities + resolved_vulnerabilities). Must ensure both SQLite and PG schema methods are updated in the same commit.
3. **Reference distribution files** need to be generated from training data before the endpoints can return meaningful results. These are not trivial to produce.
4. **Item 2 Part C mentions `epss_eval.py` as a data source** for extending thresholds. Verify that `epss_eval.py` has been run with the current dataset.
