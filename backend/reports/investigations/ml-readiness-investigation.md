# ML Readiness Investigation: ML-HIGH-3 & ML-HIGH-4

**Date:** 2026-07-14  
**Scope:** Legacy checkpoint dimensions (ML-HIGH-3) + Training split stratification (ML-HIGH-4)  
**Investigator:** Strike Team  
**Status:** Complete

---

## Scope A: ML-HIGH-3 — Legacy/Changed-Dimension Checkpoint

### Finding A1: Current Dimension Contract

All artifacts consistently show **419 features** (35 tabular + 384 SBERT text embeddings):

| Artifact | Path | Shape | Feature Names |
|---|---|---|---|
| Training data (v1) | `backend/ml/training_data.npz` | (116399, 419) | 35 tabular + `sbert_0..383` |
| Training data (v2) | `backend/ml/training_data_v2.npz` | (253568, 419) | 35 tabular + `text_sbert_0..383` |
| XGBoost model | `backend/ml/xgboost_model.pkl` | `n_features_in_=419` | N/A |

### Finding A2: Tabular Features (35-dim) — Matches Canonical List

All 35 tabular features in both `.npz` files match `TABULAR_FEATURE_ORDER` from `backend/pipeline/config/feature_names.py` exactly. No ordinals differ between datasets.

### Finding A3: Feature Name Prefix Drift (Minor, Non-Breaking)

The two NPZ files use **different prefixes** for the 384 text embedding dimensions:

| Source | Prefix | Example |
|---|---|---|
| `training_data.npz` (from `train_xgboost.py`) | `sbert_` | `sbert_0` |
| `training_data_v2.npz` (from `build_training_corpus.py`) | `text_sbert_` | `text_sbert_0` |

This is cosmetic — the model reads positional features, not named ones. But it confirms two separate pipeline code paths produced these files.

### Finding A4: Evidence of 69-Column Legacy Format (Migration Code)

The function `load_training_data()` in `backend/ml/train_xgboost.py` (line 158) contains:

```python
if n_cols == 69:
    print("\n  [migrate] Old 69-column data detected. Stripping cisa_kev (column 9)...")
    keep = [i for i in range(69) if i != 9]
    X = X[:, keep]
    save_training_data(X, y_arr, dates_arr, cve_ids_arr, path)
```

This proves a **69-column legacy format** existed at some point. Column 9 was `cisa_kev` (a boolean CISA KEV flag), which was removed during a migration. No 69-column `.npz` file remains on disk — any such file was either auto-migrated or cleaned up. The migration is still live code, so if a 69-column file were to appear, it would be auto-converted.

### Finding A5: Model Version Staleness (Important Discovery)

The saved `xgboost_model.pkl` is a **binary classifier** (`objective: binary:logistic`, `n_classes_: 2`), but the training code now targets **5-class multi-class** (`multi:softprob`, `num_class=5`):

| Property | Saved Model | Current Training Code |
|---|---|---|
| Objective | `binary:logistic` | `multi:softprob` |
| Classes | 2 (`[0, 1]`) | 5 (`[0, 1, 2, 3, 4]`) |
| `scale_pos_weight` | 115.1 (binary) | N/A (uses per-sample weights) |

The model registry (`model_registry.json`) claims `n_classes: 5` and `roc_auc_any_kev: 0.9459` — but this metadata is **out of sync with the actual serialized model**.

**Impact:** If a retraining is triggered with `--gather --train`, the new multi-class model will be incompatible with any downstream code that expects the binary classification output. However, the current model's binary output is what the inference pipeline (`xgboost_predictor.py`) consumes — the staleness is in the **code's intent vs. the model's actual training**.

### Finding A6: Labels Are Still Binary in Both NPZ Files

Despite the code's multi-window label construction (`construct_labels()` returning 0-4), both saved NPZ files contain **only binary labels** (0/1):

| File | Label 0 | Label 1 | Labels 2-4 |
|---|---|---|---|
| `training_data.npz` | 115,160 (98.9%) | 1,239 (1.1%) | None |
| `training_data_v2.npz` | 251,951 (99.4%) | 1,617 (0.6%) | None |

The files were built with an older version of the labeling logic (or a binary-only code path).

### Finding A7: Inference Pipeline Handles Both Binary and Multi-Class

`xgboost_predictor.py` (lines 342–368) explicitly handles both formats:

```python
if n_classes == 5:
    # Multi-window KEV model (5-class softprob)
    ...
elif n_classes == 2:
    # Legacy binary model — prob[1] is the positive (KEV) class
    ...
```

This means the binary→5-class discrepancy is **backward-compatible by design**. The inference layer tolerates either model version.

### ML-HIGH-3 Verdict

**RISK: LOW.** No legacy `.npz` with mismatched dimensions exists on disk. The 69-column risk is mitigated by auto-migration code. The binary vs. 5-class model gap is handled gracefully by the inference pipeline. Retraining with `--gather --train` would produce a 5-class model that inference already supports.

---

## Scope B: ML-HIGH-4 — Training Split Class Distribution

### Finding B1: No Stratified Split

The `phase_train()` function in `backend/ml/train_xgboost.py` uses a **chronological split** based on date cutoffs:

```python
train_mask = dates <= "2023-06-30"
val_mask   = (dates > "2023-06-30") & (dates <= "2023-12-31")
test_mask  = dates > "2023-12-31"
```

There is **no `stratify` parameter**. The split is purely temporal. `sklearn.model_selection.train_test_split` is not used anywhere in the training pipeline.

Fallback behavior (if dates aren't parseable) uses `np.random.permutation` — also unstratified.

### Finding B2: Class Distribution Is Highly Imbalanced

| Dataset | Class 0 | Class 1 (KEV) | Total | Pos. Rate |
|---|---|---|---|---|
| `training_data.npz` | 115,160 | 1,239 | 116,399 | **1.06%** |
| `training_data_v2.npz` | 251,951 | 1,617 | 253,568 | **0.64%** |

The positive rate is **<1.1%** in both datasets. Without stratification, it is highly likely that the validation and test sets contain very few or zero positive samples in some splits.

### Finding B3: Observation Window Filtering Reduces Positives Further

Both pipelines apply a temporal observation window filter that removes recent label-0 CVEs from training:
- `train_xgboost.py` (v1): Uses dynamic median KEV lag (~190 days)
- `build_training_corpus.py` (v2): Uses hardcoded `OBS_WINDOW_DAYS = 30`

This improves label quality but further reduces an already small positive set.

### Finding B4: No Train/Test Split in build_training_corpus.py

The `build_training_corpus.py` script only builds the full corpus (all data). It does **not** perform any train/test split. Splitting is handled separately by `train_xgboost.py` when training begins. This design means the corpus builder is agnostic to split strategy.

### Finding B5: Practical Impact on Validation

Given ~1,239 positives in `training_data.npz` spread across a ~6-year date range (2019–2024):
- Train (2019 — 2023-06-30): ~4.5 years of data → ~950 positives
- Val (2023-07 — 2023-12-31): ~6 months → ~145 positives
- Test (2024): ~1 year → ~144 positives

These are approximate but show the test/val sets are small. A random unstratified split could easily have a validation set with <50 positives, making Platt calibration unreliable (the code already warns about this: `if n_val_pos < 2: Skipping calibration`).

### ML-HIGH-4 Verdict

**RISK: MEDIUM.** The unstratified chronological split is reasonable for time-series data (avoids lookahead bias), but the extreme class imbalance (0.6–1.1%) means:
1. Validation and test sets may have very few positives
2. Model calibration can be unreliable in low-positive splits
3. Metrics like F1 and ROC-AUC can be unstable across splits

---

## Proposed Next Actions

### For ML-HIGH-3 (Legacy Checkpoint)

| # | Action | Priority | Owner |
|---|---|---|---|
| 1 | Audit `xgboost_predictor.py` to confirm it expects binary output (0/1) or multi-class (0-4) | **HIGH** (before any retraining) | Strike |
| 2 | After audit, either (a) align the training code back to binary if that's what inference expects, or (b) update inference to handle 5-class output | **HIGH** | Strike + ML |
| 3 | Remove the 69-column migration code from `load_training_data()` since no 69-column files exist and the current contract is 419-dim | **LOW** (code hygiene) | Strike |
| 4 | Synchronize model registry metadata with actual model attributes (fix `n_classes: 5` → `2` if binary is correct) | **MEDIUM** | ML |

### For ML-HIGH-4 (Training Split)

| # | Action | Priority | Owner |
|---|---|---|---|
| 1 | Add `stratify=y` to the random fallback split path (line ~367 in `train_xgboost.py`) | **LOW** (temporal split is primary) | Strike |
| 2 | For the chronological split, log per-split class distribution to detect when a split has too few positives | **MEDIUM** | Strike |
| 3 | Consider time-series CV (e.g., `TimeSeriesSplit`) instead of a single chronological holdout to get more stable metrics | **MEDIUM** | ML |
| 4 | Add a minimum-positive threshold check: fail training if any split has <10 positives | **MEDIUM** | ML |

---

## Files Examined

| File | Path |
|---|---|
| Training data v1 | `backend/ml/training_data.npz` |
| Training data v2 | `backend/ml/training_data_v2.npz` |
| XGBoost model | `backend/ml/xgboost_model.pkl` |
| XGBoost calibrator | `backend/ml/xgboost_calibrator.pkl` |
| Feature names config | `backend/pipeline/config/feature_names.py` |
| Training pipeline | `backend/ml/train_xgboost.py` |
| Corpus builder | `backend/scripts/build_training_corpus.py` |
| Model registry | `backend/ml/model_registry.json` |
| Pre-tier model | `backend/ml/pre_tier_model.pkl` |

---

## Assumptions

**Assumption 1:** The 419-dim contract described in the task scope is the current canonical contract. The system prompt mentions "68 features for XGBoost" — this appears to be stale documentation from a much earlier version of the project. The actual feature contract is **35 tabular + 384 SBERT = 419**.

**Assumption 2:** The chronological split is the intended primary split strategy. The task asks about `stratify` in `train_test_split`, but the code doesn't use `train_test_split` at all. The temporal split based on date cutoffs is the design.

**Assumption 3:** The binary model (2 classes) is what inference currently expects, even though the training code targets 5 classes. This conclusion is based on:
- The saved model having `n_classes_: 2`
- The calibrator being binary
- The labels in both NPZ files being binary (0/1)
