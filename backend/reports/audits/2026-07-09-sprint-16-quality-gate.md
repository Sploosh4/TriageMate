# Sprint 16 Quality Gate — ML Monitoring Foundation

**Date:** 2026-07-09
**Scope:** Sprint 16 additions — Pre-Tier RF tests + feature parity guard + model registry, EPSS tests + feature parity guard + model registry
**Performed by:** auditor
**Pre-flight:** `sentence_transformers` OK. All 5 test files import successfully. EPSS eval analysis script requires `pandas` + `sklearn` (not installed).

## Results

### 1. Existing Analysis Scripts

| Script | Result | Details |
|--------|--------|---------|
| `feature_parity_check` | PASS (WARN) | 35 features checked on 100 CVEs. 11/35 show stochastic drift (expected random sampling differences). 0 critical drifts. |
| `calibration_audit --max-samples 5000` | PASS | Raw ECE=0.0052 (GOOD), Calibrated ECE=0.0023 (GOOD), 55% improvement via Platt. 9 overconfident raw bins, 5 after calibration. |
| `epss_eval` | SKIPPED | Requires `pandas` and `sklearn` (`missing`) — not installed in venv. See "What's Needed to Make Runnable" below. |

### 2. New Pre-Tier Tests

| Test File | Tests | Passed | Failed | Time |
|-----------|-------|--------|--------|------|
| `tests/test_pretier_features.py` | 57 | 57 | 0 | 0.42s |
| `tests/test_pre_tier.py` | 16 | 16 | 0 | 6.10s |
| `tests/test_feature_parity_pretier.py` | 9 | 9 | 0 | 1.65s |
| **Pre-Tier subtotal** | **82** | **82** | **0** | |

### 3. New EPSS Tests

| Test File | Tests | Passed | Failed | Time |
|-----------|-------|--------|--------|------|
| `tests/test_epss_substitutor.py` | 37 | 37 | 0 | 1.99s |
| `tests/test_feature_parity_epss.py` | 14 | 14 | 0 | 1.51s |
| **EPSS subtotal** | **51** | **51** | **0** | |

### 4. Registry JSON Validity

| Registry | Valid? |
|----------|--------|
| `ml/model_registry_pre_tier.json` | ✅ Valid JSON |
| `ml/model_registry_epss.json` | ✅ Valid JSON |

**Pre-Tier registry** (v1 active): RandomForest MultiOutputClassifier, 200 trees, 60 features, holdout_accuracy=0.383, trained on 2957 samples.

**EPSS registry** (v4 active): XGBRegressor, 300 trees depth=8, 37 features, R²=0.9911, RMSE=0.0128. Fallback chain: v4→v3→v2→v1→rule_engine.

### 5. Feature Parity Spot-Check

| File | Contract | Verifies |
|------|----------|----------|
| `test_feature_parity_pretier.py` | **60-dim** | Feature count=60, unique names, both training+inference import shared module, deterministic, count-change guard, index 59=`system_category`, inference produces 60-dim vector |
| `test_feature_parity_epss.py` | **37-dim** | Both builders produce 37 elements, exact element-by-element parity across 10 test cases (diverse agencies/CWEs/edge cases), agency list order matches, CWE list order matches, feature names layout correct (6 continuous + 11 agency OHE + 20 CWE OHE) |

Both files correctly assert their respective contracts. The EPSS parity test is especially thorough — it parametrizes 10 distinct scenarios and reports exact mismatched indices if divergence is detected.

## Findings

### Finding 1: numpy deprecation warnings in test_pre_tier.py
**Severity:** 🟡 LOW

`test_pre_tier.py` generates ~1606 identical deprecation warnings:
```
DeprecationWarning: Setting the shape on a NumPy array has been deprecated in NumPy 2.5.
  array.shape = self.shape
```
**Source:** `joblib/numpy_pickle.py` (joblib 1.5.3 loading pre_tier_model.pkl with numpy 2.5.0)
**Impact:** Tests pass cleanly. No functional regression.
**Action:** Upgrade joblib to ≥1.6.0 when available, or pin numpy to <2.5. This is a third-party compatibility issue, not a TriageMate code defect.

### Finding 2: EPSS eval analysis script cannot run
**Severity:** 🟡 LOW

`analysis/epss_eval.py` requires `pandas` and `sklearn` (`scikit-learn`) which are not installed in the current Python environment.
**Impact:** The EPSS substitution accuracy analysis cannot be run as part of this gate.
**Action:** Install `pandas` and `scikit-learn` if EPSS analysis is needed. Note: this is a heavyweight script (loads full NVD corpus), so it may still be human-only as per audit-checklist.

### Finding 3: Pre-Tier model accuracy is modest (38.3%)
**Severity:** 🟢 INFO

The Pre-Tier model registry reports holdout_accuracy=0.383 and cv_mean_overall_accuracy=0.419. This is a multi-label classification (31 mission tags) so accuracy is expected to be moderate. Not a regression — this is the baseline for Sprint 16.

### Finding 4: Both registry files are well-structured
**Severity:** 🟢 INFO

Both registries include version history, model type, training metadata, creation timestamps, and active-version flags. The EPSS registry includes a fallback chain. No structural issues.

## Verdict

**PASS** — 133 passed, 0 failed, 1 skipped

| Metric | Count |
|--------|-------|
| ✅ Passed | 133 (82 Pre-Tier + 51 EPSS) |
| ❌ Failed | 0 |
| ⏭️ Skipped | 1 (epss_eval analysis script — missing pandas/sklearn) |
| ✅ JSON valid | 2/2 registries |

**No regressions detected.** All 133 new tests pass. Both feature parity guards correctly enforce the 60-dim (Pre-Tier) and 37-dim (EPSS) contracts. The two registry JSONs are valid and well-structured.

### What's needed to make skipped tests runnable
- `pip install pandas scikit-learn` to enable `analysis/epss_eval.py`
- Note: even after installing deps, EPSS eval loads the full 260K CVE corpus and takes ~5 min — flagged as HUMAN ONLY in audit-checklist

### Out of scope, but noted
- joblib/numpy 2.5 compatibility warning (1606 deprecation warnings in test_pre_tier.py) — consider upgrading joblib or pinning numpy
