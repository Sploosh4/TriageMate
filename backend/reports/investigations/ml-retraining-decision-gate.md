# ML Retraining Decision Gate Assessment

**Date:** 2026-07-14
**Author:** Strike Team (automated)
**Task:** Sprint 28 ML Retraining Decision Gate

> **⚠️ Corrected 2026-07-14:** Previous version said "RETRAIN WITH CAVEATS" — this was too permissive.
> Safe operational decision is DO NOT RETRAIN until prerequisites are met.

---

## Decision: DO NOT RETRAIN

The assessment identified three blocking issues that prevent a responsible retraining decision:

1. **Degenerate validation/test sets from unstratified chronological split** — The val set (81 records, 100% positive) and test set (125 records, 100% positive) are too small and imbalanced to produce reliable evaluation metrics. Training has 116,193 records; the split allocates only 0.18% to val/test.

2. **Binary vs multi-class mismatch between registry claims and saved artifacts** — The registry claims `n_classes: 5` and "Multi-window KEV (5-class)" but the loaded model has `classes_ = [0, 1]`. Any retraining against 5-class targets would need a fundamentally different model configuration.

3. **No reliable baseline metrics (ROC-AUC 0.9459 likely inflated)** — The reported 0.9459 ROC-AUC is unreliable because it was evaluated on a test set with only one class (100% positive), making false positive rate undefined. Without a trustworthy baseline, we cannot measure improvement or regression.

---

## Criterion 1: Training Data Quality → WARNING

### Label Construction Logic
**PASS.** The multi-window KEV label system is clean and correct:

- `construct_labels()` (lines 575-651) assigns labels 0-4 based on days-since-KEV-addition, with proper point-in-time filtering (KEV entries added after DATE_END=2024-12-31 get label 0).
- Dynamic observation window replaces the old hardcoded `OBS_WINDOW=30` with median KEV lag (~190 days, computed from actual KEV/CVE overlap at line 1027-1031).
- Selective exclusion: only label-0 CVEs in the observation window are removed; label-1+ CVEs (rapid exploitation) are preserved.

### Sprint 27 / 28 ML Fixes Applied
| Bug | File | Status | Evidence |
|---|---|---|---|
| ML-CRIT-1 (CVE IDs discarded) | `train_xgboost.py:1337` | **FIXED** | `cve_ids_arr = data.get("cve_ids", ...)` now assigns to variable |
| ML-CRIT-2 (Ensemble std crash) | `xgboost_predictor.py:395-406` | **FIXED** | Multi-class softmax handling added for `n_classes >= 3` |
| ML-CRIT-3 (None in encode_batch) | `encoder.py:58-60` | **FIXED** | None check returns zero vectors |
| ML-CRIT-4 (Identical noise RNG) | `train_epss_v4.py` | **FIXED** | No `default_rng(42)` in `_compute_exploitation_rate` |
| ML-CRIT-5 (Hardcoded 384-dim) | `train_xgboost.py:1117` | **NOT FIXED** | `X_train.shape[1] - 384` still hardcoded (benign while SBERT_DIM=384) |
| SCRIPT-CRIT-1 (Default mismatch) | `analysis/feature_parity_check.py:115-117,132-135` | **FIXED** | Both train/inference encode default to 1 |
| SCRIPT-CRIT-2 (Non-deterministic hash) | `scripts/compute_epss_reference.py:148-156` | **FIXED** | Uses `zlib.crc32` instead of `hash()` |
| SCRIPT-CRIT-3 (Null crash fetch) | `scripts/fetch_nvd_corpus.py:324` | **FIXED** | Uses `(vuln.get("cve") or {}).get("id", "")` |

### ⚠️ Training Data Volume Anomaly
The current `training_data.npz` (saved 2026-07-10, 163 MB) has **116,399 records** with the following split:

| Split | Records | Positives | KEV % |
|---|---|---|---|
| Train (≤2023-06-30) | 116,193 | 1,033 | 0.89% |
| Val (2023-07-01 to 2023-12-31) | 81 | 81 | **100.00%** |
| Test (≥2024-01-01) | 125 | 125 | **100.00%** |

The source `enriched_cves.json` (260,636 CVEs) contains:
- Mid-2023 period (Jul-Dec 2023): **14,763 CVEs** (88 KEV = 0.60%)
- Post-2024 period (Jan 2024+): **117,488 CVEs** (440 KEV = 0.37%)

After the observation window filter (which only removes label-0 CVEs published after ~2024-06-24), mid-2023 CVEs should be **unaffected** — yet only 81 of 14,763 survived. This represents a **99.5% unexplained reduction** in the validation period.

**Implication:** The current model's reported metrics (ROC-AUC 0.9459, Accuracy 0.88) are **unreliable** because val/test sets are tiny and non-representative.

**Recommendation:** Before retraining, run a clean `--gather --train` with logging to trace the mid-2023→training_data count mismatch.

---

## Criterion 2: Feature Contract Parity → PASS

### Canonical Feature List
`backend/pipeline/config/feature_names.py` defines **35 tabular features** (`TABULAR_FEATURE_ORDER`). Verified:
- 35 unique names, no duplicates
- All names match between training (`build_tabular_features` in `train_xgboost.py`) and inference (`_build_tabular_array` in `xgboost_predictor.py`)
- `vendor_popularity_index` is at index 26 (consistent with training, where it's always 0)

### SBERT Dimension
384 dimensions from `all-MiniLM-L6-v2` (defined in `encoder.py:SBERT_DIM = 384`).

**Total: 35 + 384 = 419 features** — matches current model's `n_features_in_` ✓

### Parity Test Results
All **9 feature contract tests PASS**:
```
test_tabular_registry_is_unique_and_expected_size .............. PASS
test_runtime_feature_vector_has_exact_tabular_and_metadata_contract PASS
test_predictor_builds_values_in_canonical_order ............... PASS
test_cvss_cia_defaults_to_zero ................................. PASS
test_patch_available_defaults_to_false ......................... PASS
test_domain_joined_defaults_to_false ........................... PASS
test_cvss_cia_runtime_build_feature_vector .................... PASS
test_training_builders_emit_canonical_width_and_saved_names ... PASS
test_legacy_reference_count_is_supported ...................... PASS
```

All **9 pretier feature parity tests PASS**:
```
test_feature_count_is_60, test_feature_list_length_matches_count,
test_all_feature_names_are_unique, ... all PASS
```

### 7 Demo CVEs Excluded
Zero demo CVEs found in training data ✓

---

## Criterion 3: Split Strategy → WARNING

### Current Split: Chronological
- Train cutoff: 2023-06-30 (1,033 positives / 116,193 total = 0.89%)
- Val cutoff: 2023-12-31 (81 positives / 81 total = 100%)
- Test: 2024-01-01+ (125 positives / 125 total = 100%)

### Assessment
Chronological splits are **standard for temporal forecasting models** and are the right choice for KEV prediction, which has a strong temporal component (newer CVEs have had less time to be exploited).

### ⚠️ Problem
The val/test splits are **not reliable for evaluation** due to:
- Tiny size (81 + 125 = 206 records vs 116,193 in training — a 0.18% split)
- 100% positive in both val and test sets (no negatives to evaluate against)
- The F1 threshold tuning on a 100%-positive validation set will produce misleading results

The observation window filter should only remove label-0 CVEs after ~2024-06-24, not the entire mid-2023 period. The imbalance suggests a data pipeline issue that needs investigation before a meaningful split can be achieved.

**Recommendation:** Fix the mid-2023 data pipeline issue first, then re-evaluate the split quality. A fresh `--gather --train` run should naturally produce a better-distributed split if the enriched_cves.json is complete.

---

## Criterion 4: Evaluation Baseline → WARNING

### Current Model State
| Property | Value |
|---|---|
| Model type | **Binary** XGBClassifier (NOT 5-class) |
| Classes | [0, 1] (n_classes=2) |
| Input features | 419 (35 tabular + 384 SBERT) |
| PCA model | **Not found** on disk |
| objective | `multi:softprob` (but trained as binary) |
| n_estimators | 800 |

### Registry Claims (model_registry.json — may be stale)
| Metric | Registry Value |
|---|---|
| ROC-AUC (any-KEV) | 0.9459 |
| Accuracy (5-class) | 0.88 |
| n_classes | **5 (INCORRECT — model is actually binary)** |
| Threshold | 0.472 |
| Val F1 | 0.742 |
| Score baseline | [99, 97, 74, 91, 82, 97, 80] |

### ⚠️ Critical Finding
The model registry claims `n_classes: 5` and "Multi-window KEV (5-class)" as the label, but the loaded model has `classes_ = [0, 1]` with 2-class predict_proba output. The registry metadata is **out of sync** with the actual model on disk.

### Current Metrics Reliability
Given the val/test set composition (100% positive, tiny), the reported ROC-AUC of 0.9459 is likely **inflated**:
- A 100%-positive test set means false positive rate is undefined (no negatives to be wrong about)
- The ROC-AUC calculation on a test set with only one class is degenerate

### 7 Demo Score Baseline
Expected scores: [99, 97, 74, 91, 82, 97, 80]
Not re-verified in this assessment (requires running the full pipeline with demo CVEs), but the baseline exists in the registry.

---

## Criterion 5: Legacy Compatibility → PASS

### Old Checkpoint Loading
The 69→68 column migration code (lines 157-165) handles old `training_data.npz` files:
```python
if n_cols == 69:
    keep = [i for i in range(69) if i != 9]
    X = X[:, keep]
```
Test `test_legacy_reference_count_is_supported` PASSES ✓

### Inference Backward Compatibility
`xgboost_predictor.py` handles both binary (2-class) and multi-class (5-class) models at lines 345-380. Old models load and predict without errors.

### PCA Graceful Degradation
If no PCA model is found, inference falls back to raw 384-dim embeddings (lines 83-98 of xgboost_predictor.py).

---

## Prerequisites for Retraining (Future Sprint)

Before any retraining can proceed, these prerequisites must be met in order:

### P1 — Fresh `--gather` Run with Debug Logging
Run a fresh `--gather` with detailed logging to trace the mid-2023 data volume anomaly (14,763 enriched CVEs → 81 training records in the validation period).

**Command:**
```bash
cd /home/jpc/Documents/Cybersecurity (Temp)/TriageMate/TriageMate MVP
source backend/.venv/bin/activate
python -m ml.train_xgboost --gather 2>&1 | tee /tmp/retrain-gather.log
```

**Check:**
```
grep -E 'Multi-window labels|Excluding|Keeping|Val set|Test set' /tmp/retrain-gather.log
```

The val set should contain ~14,000+ records with ~0.6% positive rate, not 81 records at 100%.

### P2 — Verify Val/Test Class Distributions
After a clean gather, verify the split produces val/test sets with both positive and negative samples. The KEV % should fall in a realistic range (0.3%–2.0%).

### P3 — Establish Baseline with Stratified Temporal Cross-Validation
Run a proper evaluation using stratified temporal cross-validation to establish a trustworthy baseline ROC-AUC. Only then can we define acceptance criteria for improvement.

### P4 — Only Then Run `--train` Against Defined Acceptance Criteria
Once P1–P3 are satisfactory, run `--train` and verify against defined acceptance criteria.

---

## Retraining Commands (Post-Prerequisites)

Once P1–P4 are resolved:

```bash
# Step 1: Fresh gather (fetch NVD/EPSS/KEV, build features, encode)
cd /home/jpc/Documents/Cybersecurity (Temp)/TriageMate/TriageMate MVP
source backend/.venv/bin/activate
python -m ml.train_xgboost --gather --train

# Step 2: Verify 7 demo scores
python backend/scripts/verify_seed_scores.py

# Step 3: Run full test suite
python -m pytest backend/tests/ -v

# Step 4: Update registry
# (edit backend/ml/model_registry.json with new metrics)
```

### Acceptance Criteria
| Criterion | Target |
|---|---|
| ROC-AUC (any-KEV) | ≥ 0.92 |
| Test set negative count | > 1,000 records |
| Test set KEV % | 0.3% - 2.0% (realistic range) |
| Val set F1 | ≥ 0.70 |
| 7 demo scores | Within ±3 of [99, 97, 74, 91, 82, 97, 80] |
| Feature count | 419 (35 + 384) |
| All feature contract tests | PASS |

---

## Summary

| Criterion | Verdict | Key Issue |
|---|---|---|
| 1. Training Data Quality | **WARNING** | mid-2023 pipeline gap (14,763→81 records) needs investigation |
| 2. Feature Contract Parity | **PASS** | 35+384=419, all 9 tests pass |
| 3. Split Strategy | **WARNING** | Chronological OK, but val/test sets are tiny and degenerate |
| 4. Evaluation Baseline | **WARNING** | Metrics unreliable; registry claims 5-class but model is binary |
| 5. Legacy Compatibility | **PASS** | Old checkpoints load, migration code works |

**Overall: DO NOT RETRAIN** — The assessment identified three blocking issues: degenerate val/test splits, binary-vs-multi-class registry mismatch, and unreliable baseline metrics. A responsible retraining decision requires completing the prerequisites first (fresh `--gather` run, verify class distributions, establish stratified temporal baseline). See "Prerequisites for Retraining (Future Sprint)" above.
