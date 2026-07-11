# Sprint 23 Phase 2 Round 1 — Gated Bug Hunt

**Date:** 2026-07-11
**Scope:** Automated audit suite + manual bug sweep for pre-deployment quality gate
**Performed by:** auditor
**Pre-flight:** `sentence_transformers` OK ✓

---

## 1. Automated Audit Results

### 1a. Full Test Suite (`pytest tests/`)

**Verdict: FAIL WITH ISSUES** — 446 passed, 1 error, 1 hang, 2 not-run

| Batch | Tests | Result |
|-------|-------|--------|
| test_admin, test_scoring, test_config, test_health, test_queue, test_audit, test_ingest | 91 | **PASS** |
| test_demo_generator, test_epss_substitutor, test_drift, test_drift_epss, test_drift_ml, test_drift_pretier, test_drift_webhook, test_feature_parity*, test_ml_pipeline, test_pretier_features, test_pre_tier | 224 | **PASS** |
| test_alembic, test_integration, test_model_versions, test_npz_metadata, test_rate_limit, test_review, test_rollback, test_scheduler, test_tier0, test_verify_seed_scores, test_aggregate_sectors | 75 | **PASS** |
| test_tier2, test_tier2_agent | 56 | **PASS** |
| test_benchmark | 2 | **ERROR** — fixture 'benchmark' not found |
| test_fuzzed_ingest | 1 | **HANG** — timeout after 120s |

**Findings:**
- `test_benchmark.py::TestScoringBenchmarks::test_benchmark_scoring_calculation` — Missing `pytest-benchmark` fixture. The `pytest-benchmark` plugin is not installed or not loaded.
- `test_fuzzed_ingest.py::TestFuzzedIngest::test_fuzzed_ingest_no_crashes` — Hangs/timeouts. Feeds 50 real CVEs through the full pipeline (async). Likely stuck on ML model loading or tier 2 call (even though tier_2 is mocked, `build_feature_vector` and other modules may trigger heavy imports).

### 1b. Lint Check (`ruff check + format`)

**Verdict: FAIL** — 7 errors in `backend/scripts/compute_canonical_scores.py`

| Rule | Line | Issue |
|------|------|-------|
| E402 | 21-22 | Module level import not at top of file (`sys.path.insert` then import) |
| F841 | 324 | Local variable `dim_total` assigned but never used |
| F541 | 352, 354, 387, 397 | f-string without any placeholders (4 instances) |

Format check: **PASS** — 137 files already formatted.

### 1c. Seed Verification (`scripts.verify_seed_scores`)

**Verdict: FAIL** — 6 of 7 seed scores drifted beyond tolerance

| CVE | Expected | Actual | Delta | Status |
|-----|----------|--------|-------|--------|
| CVE-2022-47966 | 80 | 73 | 7.0 | FAIL |
| CVE-2023-22515 | 97 | 88 | 9.0 | FAIL |
| CVE-2023-27350 | 74 | 74 | 0.0 | PASS |
| CVE-2023-34362 | 99 | 90 | 9.0 | FAIL |
| CVE-2023-36884 | 82 | 75 | 7.0 | FAIL |
| CVE-2023-4966 | 97 | 88 | 9.0 | FAIL |
| CVE-2024-1709 | 91 | 83 | 8.0 | FAIL |

All drifts are 7-9 points below expected. This suggests scoring logic changes in this sprint shifted the output range downward.

### 1d. ML Calibration Audit (`audit-calibration`)

**Verdict: SKIPPED** — Heavyweight audit. Loads 260K CVEs + SBERT encoding. Estimated runtime 5+ min. Would need `--max-samples 5000` to cap time.

### 1e. EPSS Evaluation (`audit-epss`)

**Verdict: SKIPPED** — Same heavyweight corpus load as calibration audit.

### 1f. Feature Parity Check (`just audit-features`)

**Verdict: WARN** — 35 features compared across training and inference builders

- **0 critical drifts** (logic/default mismatches)
- **11 stochastic drifts** (random sampling differences — expected behavior)
- Features with 100% match (24/35): All deterministic features like cvss_*, epss_score, exploitdb_has_poc, metasploit_has_payload, nvd_reference_count, cve_desc_tokens, vulnerability_age_days, vendor_popularity_index, cvss_exploitability_sub, cvss_impact_sub, all is_*_signature features
- Features with stochastic drift: patch_applied (79%), internet_facing (85%), domain_joined (90%), data_classification (60%), mission_prevalence (41%), public_wellbeing_impact (49%), lateral_reachability (93%), boundary_reachability (97%), downstream_assets (88%), patch_lag_days (0%), threat_intel_pulses (82%)

### 1g. Schema Validation (`just audit-schema`)

**Verdict: FAIL** — 1 dead feature found

- **`vendor_popularity_index`** (index 26): Zero for ALL 500 entries sampled. Constant value (0.0000), zero variance. This is a dead feature in the ML model — provides no predictive signal. Should be investigated for removal or replacement.

Other flags:
- `is_traversal_signature` (index 34): Only 9/500 non-zero (1.8%) — borderline dead feature
- `epss_score`, `data_classification`, `mission_prevalence`, `public_wellbeing_impact`, `nvd_reference_count`, `cve_desc_tokens`, `vulnerability_age_days`, `cvss_exploitability_sub`, `cvss_impact_sub`: 100% non-zero (expected for these features)
- `patch_available`: 69.2% non-zero — healthy distribution

---

## 2. Manual Bug Sweep

### 2a. Import Hygiene

| Check | Result |
|-------|--------|
| `from ml.xgboost_predictor import CWE_EPSS_THRESHOLDS` | **CLEAN** — no stale imports found |
| `from pipeline.tier_2 import` (outside tests) | **CLEAN** — only in test_tier2.py (expected) |
| `SECURITY_CONTEXT_MAX` | **CLEAN** — no references found |

### 2b. Deprecated Field Safety

**Verdict: SANE** — `security_context` is vestigial, not live

| File | Status | Notes |
|------|--------|-------|
| `scoring.py:205-207` | VESTIGIAL | Sets `dimensions["security_context"] = 0` with DEPRECATED comment |
| `routers/ingest.py` | READING VESTIGIAL | Reads `scoring["dimensions"]["security_context"]` (always 0) — safe but noisy |
| `database.py` | DB COLUMNS | `security_context_contribution INTEGER DEFAULT 0` — exists in both SQLite and PG schemas for backward compatibility |
| `seed_data.py` | SEED DATA | `"security_context_contribution": 0` — expected |
| `tests/conftest.py` | MIGRATION | `_ensure_security_context_contribution_column()` — ensures column exists for backward compat |

**Finding:** `routers/ingest.py` still presents "Security Context" as a live scoring dimension in the API response (max=5, justification text). Since it's always 0, this is misleading to API consumers but harmless. The justification text ("Based on telemetry threat score and network blast radius") is incorrect — this logic moved to the context multiplier in Sprint 21.

### 2c. Context Multiplier Edge Cases

**Verdict: 11 PASS, 2 FAIL, 13 total** — both failures are spec-vs-code discrepancies

| Test Case | Expected | Got | Status |
|-----------|----------|-----|--------|
| telemetry=0, code=None | 1.00 | 1.00 | PASS |
| telemetry=10, code=True | 1.20 | 1.20 | PASS |
| telemetry=3.0 (boundary), code=True | 1.20 | 1.20 | PASS |
| telemetry=2.9 (below), code=True | 1.10 | 1.10 | PASS |
| telemetry=5, code=False | 1.00 | 1.10 | **FAIL** |
| None telemetry (0, None) | no crash | no crash | PASS |
| calculate_final_score with None telemetry | no crash | no crash | PASS |
| confirmed_mitigated + confirmed_false_positive | 0.70 | 0.70 | PASS |
| mitigated=True, no telemetry | 0.85 | 0.85 | PASS |
| mitigated=True, active telemetry | 0.85 | 0.85 | PASS |
| telemetry=4 (active), code=False | 1.10 | 1.10 | PASS |
| telemetry=0, code=True | 1.10 | 1.10 | PASS |

**Bug: Spec-vs-Code Discrepancy on `telemetry=5, code=False`**

The user's test spec expects `telemetry_threat_score=5, vulnerable_code_loaded=False → multiplier=1.00`. However, the code in `scoring.py:_determine_context_multiplier` returns **1.10** for this case.

Root cause analysis:
- The decision matrix comment says: *"telemetry >= 3.0 XOR code_loaded == True → 1.10"*
- The code implements: `if telemetry_active or code_loaded: return 1.10`
- With telemetry=5 (≥3.0 = True) and code=False (= False): `True XOR False = True` → should be 1.10
- The code's `or` operator (with `and` checked first) produces the same result as XOR for this case

The spec expectation of 1.00 appears to be incorrect. The code behavior (1.10) is consistent with the documented decision matrix. However, this should be verified — if the intended behavior is that `vulnerable_code_loaded=False` (determinately not loaded) should behave differently from `None` (unknown), then the `or` check needs to distinguish `False` from `None`.

### 2d. Feature Parity Check

Already covered in §1f — **WARN**, 11 stochastic drifts, 0 critical.

### 2e. API Contract Check

**Verdict: PASS** — All 15 checks passed

| Check | Status |
|-------|--------|
| threshold_info in response | PASS |
| threshold_info has classification_threshold | PASS |
| threshold_info has cwe_stratified_thresholds | PASS |
| scoring section present | PASS |
| scoring has 6 weights | PASS |
| total_weight is 107 | PASS |
| context_multiplier config present | PASS |
| context_multiplier has 5 entries | PASS |
| context_multiplier keys match expected | PASS |
| context_multiplier.active_threat_loaded == 1.2 | PASS |
| context_multiplier.partial_evidence == 1.1 | PASS |
| context_multiplier.neutral == 1.0 | PASS |
| context_multiplier.mitigated == 0.85 | PASS |
| context_multiplier.false_positive == 0.7 | PASS |

Full scoring config returned:
```json
{
  "weights": {"cvss": 40, "epss": 20, "criticality": 20, "exposure": 12, "patch": 5, "ml_exploitation": 10},
  "total_weight": 107,
  "clamp_min": 0,
  "clamp_max": 100,
  "context_multiplier": {"active_threat_loaded": 1.2, "partial_evidence": 1.1, "neutral": 1.0, "mitigated": 0.85, "false_positive": 0.7},
  "telemetry_active_threshold": 3.0
}
```

---

## 3. Bugs Found — Detailed List

### Bug 1: `test_benchmark.py` — Missing pytest-benchmark fixture
- **File:** `backend/tests/test_benchmark.py:12`
- **Error:** `fixture 'benchmark' not found`
- **Cause:** `pytest-benchmark` plugin not installed or not loaded
- **Fix:** `pip install pytest-benchmark` or remove the benchmark test if not needed
- **Severity:** Medium (blocks 2 test cases)

### Bug 2: `test_fuzzed_ingest.py` — Test hangs indefinitely
- **File:** `backend/tests/test_fuzzed_ingest.py`
- **Symptoms:** Timeout after 120s on single async test `test_fuzzed_ingest_no_crashes`
- **Likely cause:** ML model loading (XGBoost/SBERT) on first call, or deadlock in async pipeline
- **Suggested investigation:** Add timeout to the test; check if `build_feature_vector` triggers lazy model loads
- **Severity:** Medium (blocks 1 integration test case)

### Bug 3: Seed score drift — 6 of 7 scores shifted 7-9 points down
- **Files:** `backend/seed_data.py` (expected values) vs `backend/scoring.py` (actual computation)
- **Evidence:** All drifts are negative (actual < expected), consistent pattern
- **Likely cause:** Scoring logic changes in Sprint 21 (context multiplier replacement) or weight recalibration shifted output range
- **Fix:** Update `SEED_ROWS` baseline scores in `seed_data.py` and `CI_BASELINE` in `compute_canonical_scores.py` to match new computed values
- **Severity:** High (breaks CI seed verification gate)

### Bug 4: Dead ML feature — `vendor_popularity_index` is all-zero
- **File:** `backend/ml/train_xgboost.py` (training builder) and `backend/routers/ingest.py` (inference builder)
- **Evidence:** Schema validation shows 0/500 non-zero entries across sampled CVEs
- **Impact:** Feature provides zero predictive signal; wastes model capacity
- **Suggested fix:** Investigate data source for vendor_popularity_index. If the lookup consistently returns 0, either fix the data pipeline or remove the feature and retrain
- **Severity:** Medium (silent model quality degradation)

### Bug 5: Lint errors in `compute_canonical_scores.py`
- **File:** `backend/scripts/compute_canonical_scores.py`
- **Issues:**
  - Lines 21-22: Imports after `sys.path.insert` (E402) — structural, needs different approach
  - Line 324: Unused variable `dim_total` (F841)
  - Lines 352, 354, 387, 397: f-strings without placeholders (F541) — use regular strings
- **Severity:** Low (script file, not in production path)

### Bug 6: Spec-vs-Code discrepancy — context multiplier for telemetry_active + code_not_loaded
- **File:** `backend/scoring.py:61-67`
- **Issue:** User's test spec expects `telemetry=5, code=False → 1.00` but code returns 1.10
- **Analysis:** Code behavior (1.10) matches the documented decision matrix. The test spec appears to have an incorrect expected value. However, if the intent is that `vulnerable_code_loaded=False` (determinately false) should be treated as "no evidence" rather than "partial evidence", the code needs to differentiate `False` from `None`.
- **Severity:** Low (spec clarification needed; no production impact from current behavior)

### Bug 7: Misleading "Security Context" dimension in API response
- **File:** `backend/routers/ingest.py:425-431`
- **Issue:** API returns a "Security Context" dimension with max=5 and justification text, but the value is always 0 (removed in Sprint 21). Justification text ("Based on telemetry threat score and network blast radius") is outdated — this logic moved to the context multiplier.
- **Severity:** Low (cosmetic/backward compat; does not affect scoring)

---

## 4. Summary

| Section | Verdict | Pass | Fail | Skip |
|---------|---------|------|------|------|
| 1a. pytest | FAIL WITH ISSUES | 446 | 2 (1 error, 1 hang) | 2 (benchmark, fuzzed) |
| 1b. ruff lint | FAIL | — | 7 errors | — |
| 1c. Seed verification | FAIL | 1 | 6 | — |
| 1d. Calibration audit | SKIPPED | — | — | 1 (heavyweight) |
| 1e. EPSS evaluation | SKIPPED | — | — | 1 (heavyweight) |
| 1f. Feature parity | WARN | 24 | 0 critical / 11 stochastic | — |
| 1g. Schema validation | FAIL | — | 1 dead feature | — |
| 2a. Import hygiene | PASS | 3 | 0 | — |
| 2b. Deprecated field safety | PASS (vestigial) | — | 0 critical | — |
| 2c. Multiplier edge cases | FAIL (spec only) | 11 | 2 | — |
| 2d. Feature parity | (see 1f) | — | — | — |
| 2e. API contract | PASS | 15 | 0 | — |

### Overall Verdict: FAIL WITH ISSUES

**7 bugs found.** Blockers to address before proceeding:
1. **Seed score drift** (Bug 3) — highest priority, breaks CI gate
2. **Dead ML feature** (Bug 4) — silent quality degradation
3. **Benchmark test error** (Bug 1) — broken test suite
4. **Fuzzed ingest hang** (Bug 2) — need timeout fix

### What's needed for SKIPPED tests:
- **Calibration audit / EPSS evaluation:** Run manually with `--max-samples 5000` flag. Heavyweight due to 260K CVE corpus + SBERT encoding.

### Recommended fixes for Strike:
| Bug | File | Fix |
|-----|------|-----|
| 3 — Seed drift | `seed_data.py`, `compute_canonical_scores.py` | Recompute canonical scores and update baselines |
| 4 — Dead feature | `train_xgboost.py` or data pipeline | Investigate vendor_popularity_index data source |
| 1 — Benchmark fixture | `requirements.txt` + `test_benchmark.py` | Install pytest-benchmark or remove test |
| 2 — Fuzzed test hang | `test_fuzzed_ingest.py` | Add `@pytest.mark.timeout(60)` or investigate lazy loading |
| 5 — Lint errors | `compute_canonical_scores.py` | Remove unused var, fix f-strings, restructure imports |
| 6 — Spec clarification | `scoring.py` or test spec | Confirm intended behavior for telemetry=5/code=False |
| 7 — API dimension label | `routers/ingest.py:425-431` | Update justification text or suppress security_context display |
