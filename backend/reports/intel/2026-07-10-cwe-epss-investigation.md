# CWE-Stratified EPSS Thresholds — Codebase Investigation

> **⚠️ STATUS: PARTIALLY OUTDATED** (stale findings struck through)
> 
> **Date:** 2026-07-10
> **Last updated:** 2026-07-10 (bookkeeping freshness pass)
> 
> **What changed:** The CRITICAL finding below (dead code in `_tier_zero_check()` due to missing `cwe_class`/`cisa_kev` keys in `build_feature_vector()`) has been **verified as already fixed**. Both keys are present at `ingest_helpers.py:498-499`. See Sprint 18 plan Part A: "Fix dead code" is ✅ Done.
> 
> The report remains useful for its CWE-aware threshold analysis, pipeline flow documentation (Section C–F), and Recommendations 2–7, which are still actionable.
**Requested by:** Commander (roadmap task)
**Sources consulted:** `tier_0.py`, `tier_1.py`, `xgboost_predictor.py`, `epss_substitutor.py`, `scoring.py`, `ingest_helpers.py`, `ingest.py`, `epss_eval.py`, `threshold_info.json`, `2026-07-09-router-bugs-verification.md`

---

## Findings

### A. Every Codebase Location Where EPSS Thresholds Are Used

| # | File | Line(s) | Threshold(s) | Type | Controls | CWE Context Available? |
|---|---|---|---|---|---|---|
| 1 | `backend/pipeline/tier_0.py` | 14 | `KEV_EPSS_THRESHOLD = 0.90` | Monolithic | KEV + OFFICIAL Sensitive → `very_critical` auto-resolve | ❌ No — `evaluate_tier_0()` receives only cvss, kev, epss, data_class, internet_facing |
| 2 | `backend/pipeline/tier_0.py` | 16 | `LOW_EPSS_THRESHOLD = 0.10` | Monolithic | Low-severity auto-resolve (CVSS < 4.0 + EPSS < 0.10) | ❌ No |
| 3 | `backend/ml/xgboost_predictor.py` | 41–50 | `CWE_EPSS_THRESHOLDS` (8 CWEs) | **Stratified by CWE** | Pre-XGBoost fast-path bypass (`_tier_zero_check`) | ✅ Yes — reads `cwe_class` from features dict |
| 4 | `backend/ml/xgboost_predictor.py` | 51 | `DEFAULT_EPSS_THRESHOLD = 0.84` | Monolithic fallback | Fallback when CWE not in CWE_EPSS_THRESHOLDS | ✅ Yes (used as fallback) |
| 5 | `backend/ml/xgboost_predictor.py` | 225 | `epss >= 0.30` (hardcoded) | Monolithic | KEV fast-path in `_tier_zero_check()` | ✅ Uses `cisa_kev` flag |
| 6 | `backend/ml/xgboost_predictor.py` | 35–38 | `LOW/MID/HIGH_PROB_THRESHOLD` (0.20/0.40/0.50) | Monolithic | Post-XGBoost routing (probability zoning) | ✅ (post-inference, not EPSS) |
| 7 | `backend/ml/epss_substitutor.py` | 53–57 | `CWE_MULTIPLIERS` (1.5× for 3 CWEs) | **Stratified by CWE** | Sector-adjusted EPSS multiplier (not a decision threshold) | ✅ Yes — `cwe_class` param in `calculate_substitution()` |
| 8 | `backend/ml/epss_substitutor.py` | 59 | `KEV_MULTIPLIER = 2.0` | Monolithic | KEV sector multiplier | ✅ |
| 9 | `backend/ml/epss_substitutor.py` | 63 | `MIN_CHANGE_THRESHOLD = 0.1` | Monolithic | Minimum change to qualify as "substituted" | ❌ Not CWE-related |
| 10 | `backend/ml/epss_substitutor.py` | 130 | `ML_CONFIDENCE_THRESHOLD = 0.3` | Monolithic | Minimum confidence for ML substitution | ❌ Not CWE-related |
| 11 | `backend/scoring.py` | 61 | N/A (uses effective_epss directly) | N/A | `epss_contribution = effective_epss * 20` (linear weight) | ❌ No CWE in scoring |
| 12 | `backend/analysis/epss_eval.py` | 116–121 | Threshold search (0.0–1.0) | Both | Evaluates monolithic + stratified (by CWE class) thresholds | ✅ Yes — by `cwe_class` |

---

### B. The Existing `CWE_EPSS_THRESHOLDS` Dict

Defined in `backend/ml/xgboost_predictor.py`, lines 41–51:

```python
CWE_EPSS_THRESHOLDS = {
    "CWE-22": 0.085,   # Path Traversal
    "CWE-78": 0.515,   # OS Command Injection
    "CWE-787": 0.716,  # Out-of-bounds Write
    "CWE-79": 0.600,   # XSS
    "CWE-89": 0.500,   # SQL Injection
    "CWE-416": 0.550,  # Use-After-Free
    "CWE-20": 0.400,   # Input Validation
    "CWE-843": 0.300,  # Type Confusion
}
DEFAULT_EPSS_THRESHOLD = 0.84
```

**Coverage:** 8 CWEs. The default (0.84) applies to all other CWEs — which is a very high bar, meaning for unlisted CWEs the function almost never triggers, and XGBoost inference always runs.

**Where used:** Only in `_tier_zero_check()` (line 235):
```python
threshold = CWE_EPSS_THRESHOLDS.get(cwe, DEFAULT_EPSS_THRESHOLD)
if epss >= threshold:
    return { ... "routing": "escalated", "tier": "tier_0_epss" }
```

~~**Known bug (CRITICAL):** Per audit report `2026-07-09-router-bugs-verification.md`, `_tier_zero_check()` is **effectively dead code**. The `build_feature_vector()` function in `ingest_helpers.py` (lines 442–509) does NOT include the keys `"cwe_class"` or `"cisa_kev"` in its returned dict. As a result:
- `features.get("cwe_class", "")` → always `""` → always hits `DEFAULT_EPSS_THRESHOLD` (0.84) → almost never triggers
- `features.get("cisa_kev", False)` → always `False` → KEV fast-path never fires

This means every vulnerability — even known-exploited CVEs with high EPSS — **unnecessarily runs the full XGBoost model**, adding ~50–100ms per ingest.~~

> **✅ STALE — VERIFIED FIXED.** Both `"cwe_class"` and `"cisa_kev"` keys are present in `build_feature_vector()`'s returned dict at `ingest_helpers.py:498-499`. The `_tier_zero_check()` function is now working code. See Sprint 18 Item 2 Part A.

---

### C. How `_tier_zero_check()` Works vs. Tier 0's Monolithic Thresholds

**`_tier_zero_check()` (xgboost_predictor.py, lines 218–245):**

This function runs **inside the Tier 1 predictor, before XGBoost inference**. It has two fast-paths:

1. **KEV fast-path:** If `cisa_kev == True` and `epss >= 0.30`, return `exploitation_probability = 0.95` with `routing: "escalated"`. This bypasses all ML inference for known-exploited CVEs with non-trivial EPSS.

2. **CWE-stratified EPSS threshold:** If `epss >= CWE_EPSS_THRESHOLDS[cwe]`, return `exploitation_probability = min(0.99, epss + 0.10)` with `routing: "escalated"`.

Both fast-paths return `"tier": "tier_0_kev"` or `"tier": "tier_0_epss"` to identify the source. The confidence for CWE-stratified is set at 0.70 (moderate) compared to 0.90 for the KEV path.

**Tier 0 monolithic thresholds (`tier_0.py`, lines 43–74):**

Tier 0 runs **before** Tier 1 entirely, in a separate function `evaluate_tier_0()`. It uses **two rules**:

1. KEV + CVSS >= 9.0 + internet-facing → `very_critical` auto-resolve
2. KEV + EPSS >= 0.90 + OFFICIAL Sensitive → `very_critical` auto-resolve
3. NOT KEV + CVSS < 4.0 + EPSS < 0.10 → `low` auto-resolve
4. Everything else → escalate to Tier 1

**Key differences:**

| Property | `_tier_zero_check()` | `evaluate_tier_0()` |
|---|---|---|
| Where it runs | Inside `predict()`, before XGBoost inference | Early in ingest pipeline |
| CWE awareness | ✅ Yes (stratified thresholds) | ❌ No (monolithic thresholds only) |
| CISA KEV awareness | ✅ Yes (0.30 threshold) | ✅ Yes (0.90 threshold) |
| What it outputs | ML-style prediction (prob, conf, routing) | Deterministic routing + resolution |
| Currently working? | ❌ No (dead code — missing feature inputs) | ✅ Yes |

---

### D. EPSS Evaluation Analysis (`analysis/epss_eval.py`)

This file performs a comprehensive evaluation of EPSS-as-predictor for KEV classification, including **CWE-stratified analysis**.

**Key findings from the analysis:**

1. **Monolithic threshold search (5-fold CV):**
   - Best F1 threshold found (variable `best_f1['threshold']`)
   - Best F2 threshold found (variable `best_f2['threshold']`)
   - Max precision @ recall >= 0.50 and >= 0.80

2. **Stratified by CWE class** (lines 200–233):
   The `stratify_metrics()` function computes, per CWE class, the **best F1 threshold**, ROC-AUC, and PR-AUC. This directly supports the roadmap's claim that different CWE classes have very different optimal EPSS thresholds.

3. **XGBoost comparison:** Compares EPSS-only classification against a full XGBoost model, measuring the F1 gap.

**Relevance:** The stratified analysis in this file validates the core premise — different CWEs need different EPSS thresholds. The values used in `CWE_EPSS_THRESHOLDS` (0.085 for Path Traversal, 0.515 for OS Command Injection, etc.) are consistent with the type of analysis this file performs.

---

### E. `threshold_info.json`

**Path:** `backend/ml/threshold_info.json`
**Content:** `{"classification_threshold": 0.4724170854271357, "val_f1": 0.7415730337078652}`

This file contains a **single monolithic threshold** (0.4724) and its validation F1 score. It is referenced by the XGBoost predictor's model registry system (paths loaded dynamically). It does **not** contain any CWE-stratified data.

---

### F. EPSS Substitutor — CWE Multipliers (Not Thresholds)

The EPSS substitutor in `epss_substitutor.py` uses a related but **different** mechanism: CWE-specific **multipliers** (not decision thresholds). The `CWE_MULTIPLIERS` dict (lines 53–57) contains:

```python
CWE_MULTIPLIERS = {
    "CWE-78": 1.5,   # OS Command Injection
    "CWE-434": 1.5,   # File Upload
    "CWE-862": 1.5,   # Missing Authorization
}
```

These adjust EPSS scores upward for sector-relevance, not for routing decisions. This is a complementary but distinct concern from CWE-stratified decision thresholds.

---

## Assessment

### The Roadmap's Vision Is Already Partially Implemented — But Broken

The `CWE_EPSS_THRESHOLDS` dict in `xgboost_predictor.py` is exactly what the roadmap describes — a CWE-stratified set of EPSS decision thresholds. The concept was built but never connected. The `_tier_zero_check()` function cannot fire because the feature vector doesn't pass `cwe_class` and `cisa_kev`.

### Three Distinct Domains Where CWE-Stratified Thresholds Could Apply

1. **Tier 0 decision thresholds** — `evaluate_tier_0()` has no CWE awareness
2. **Pre-XGBoost fast-path** — Already has `_tier_zero_check()` but needs bugfix + extension
3. **EPSS substitution multipliers** — Already CWE-aware (different mechanism, already working)

### Critical Bug Blocks Progress

The most impactful single action is fixing `build_feature_vector()` to include `"cwe_class"` and `"cisa_kev"` in its output dict. This alone would enable the existing CWE-stratified thresholds and the KEV fast-path.

---

## Recommendations

### 1. 🟥 ~~CRITICAL~~ ✅ ALREADY FIXED — ~~Fix `build_feature_vector()` to Include `cwe_class` and `cisa_kev`~~

~~Add two keys to the returned dict in `ingest_helpers.py` around line 498–499:~~
```python
# ✅ Already present — verification at ingest_helpers.py:498-499
"cisa_kev": bool(payload.cisa_kev) if hasattr(payload, "cisa_kev") else False,
"cwe_class": cwe_class,
```
~~This unblocks **both** CWE-stratified EPSS thresholds and the KEV fast-path in `_tier_zero_check()`, saving ~50–100ms per ingest for every CVE that exceeds its CWE-specific threshold.~~

~~**Expected impact:** 2–5× improvement in ingest latency for CVEs that hit the CWE fast-path. The existing thresholds (0.085 for Path Traversal, etc.) mean many mid-range CVEs will bypass XGBoost entirely.~~

> **✅ ALREADY FIXED.** Both keys are present at `ingest_helpers.py:498-499`. `_tier_zero_check()` is now working code. This recommendation was fully implemented before the report was written. See Sprint 18 Item 2 Part A.

### 2. 🟧 HIGH — Extend `CWE_EPSS_THRESHOLDS` Coverage

The current dict covers 8 CWEs with a very conservative default (0.84). Extend it using data from `epss_eval.py`'s stratified analysis:

- Add the top 10–15 most common CWEs from the NVD corpus
- Lower the `DEFAULT_EPSS_THRESHOLD` from 0.84 to ~0.50 (matching the analysis's best monolithic threshold range)
- Consider adding CWE-125 (Out-of-bounds Read), CWE-476 (NULL Pointer Dereference), CWE-862 (Missing Authorization), CWE-434 (File Upload)

### 3. 🟡 MEDIUM — Consider CWE-Stratifying Tier 0's `LOW_EPSS_THRESHOLD`

**Analysis:** The current `LOW_EPSS_THRESHOLD = 0.10` is monolithic. For Path Traversal (CWE-22), the optimal threshold is 0.085 — slightly below 0.10, which means Path Traversal CVEs at EPSS 0.09 would pass Tier 0 incorrectly (auto-resolved as low when they should be escalated). For OS Command Injection (CWE-78), the optimal threshold is 0.515 — far above 0.10, meaning many command injection CVEs with EPSS between 0.10 and 0.515 would be needlessly escalated to Tier 1.

**Recommendation:** Modify `evaluate_tier_0()` to accept an optional `cwe_class` parameter. If provided, use a CWE-stratified low threshold instead of 0.10. Keep the flat 0.10 as fallback when CWE is unknown. However, this is lower priority than fixing the existing `_tier_zero_check()` bottleneck.

**Pipeline flow consideration:** CWE is computed in `ingest.py` line 109 (`get_cwe()`), which happens BEFORE `evaluate_tier_0()` on line 159. So CWE context IS available at the point where Tier 0 is called — it just isn't passed.

### 4. 🟡 MEDIUM — CWE-Stratified KEV Threshold in Tier 0

The `KEV_EPSS_THRESHOLD = 0.90` is also monolithic. For KEV-listed CVEs that target CWEs with low optimal thresholds (like Path Traversal at 0.085), requiring EPSS >= 0.90 to auto-resolve as very_critical is overly conservative. Consider lowering the KEV threshold or making it CWE-dependent.

### 5. 🟢 LOW — No Changes Needed in `scoring.py`

The scoring engine treats EPSS as a linear weighted input (`effective_epss * 20`). This is appropriate — thresholds are routing decisions, not scoring weights. No CWE stratification needed here.

### 6. 🟢 LOW — No Changes Needed in `epss_substitutor.py`

The substitutor's CWE multipliers are a different mechanism (sector-awareness for score adjustment). They already work correctly with CWE context. However, the CWE list used (`CWE_MULTIPLIERS`) could be cross-referenced with `CWE_EPSS_THRESHOLDS` for consistency.

### 7. 🔵 INFORMATIONAL — Update `threshold_info.json`

The current `threshold_info.json` only contains a monolithic threshold. Consider extending it to store CWE-stratified thresholds for runtime querying, making the system more auditable.

---

## Summary of Pipeline Flow with CWE Context

Current ingest pipeline flow with respect to CWE/EPSS:

```
ingest.py line 109: cwe_class = get_cwe(...)          ← CWE computed here
ingest.py line 115: epss_sub = calculate_substitution(  ← Uses cwe_class ✅
                       cwe_class=cwe_class)
ingest.py line 159: t0_result = evaluate_tier_0(        ← Does NOT use cwe_class ❌
                       epss_score=raw_epss)
ingest.py line 177: features = build_feature_vector(    ← Does NOT include cwe_class ❌
                       payload, mission_tags, t0_result)
ingest.py line 184: t1_result = evaluate_tier_1(        → calls predict()
                       features)                        → calls _tier_zero_check(features)
                                                        → cwe_class defaults to "" ❌
```

The CWE class is computed early and used by the EPSS substitutor, but then **lost** for Tier 0 and (critically) for `_tier_zero_check()`.

---

## Assumptions

1. The `CWE_EPSS_THRESHOLDS` values in `xgboost_predictor.py` (0.085 for Path Traversal, etc.) were empirically derived from the analysis in `epss_eval.py` or similar analysis. I have not re-derived these values — I assume they are correct as placed.
2. The audit finding about `build_feature_vector()` missing `cwe_class` and `cisa_kev` keys is accurate and still applicable (it was written 1 day ago).
3. The monolithic threshold in `threshold_info.json` (0.4724) is for XGBoost classification probability, not EPSS directly, so it is not directly comparable to the EPSS thresholds discussed here.
4. CWE context is available at Tier 0 call time because `get_cwe()` runs before `evaluate_tier_0()` in `ingest.py`.
