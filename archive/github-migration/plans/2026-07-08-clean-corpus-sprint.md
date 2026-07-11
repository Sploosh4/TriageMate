# Sprint: Clean Corpus

**Date:** 8 July 2026
**Type:** Corrective Sprint  
**Commander:** Current  

## Goal

Fix the 420 vs 419 dimension mismatch at the root: rebuild the training corpus without `osv_lead_days`, retrain the model on a clean 419-feature dataset, and revert the predictor to match. Along the way, implement the TASK_STORE_COLUMNS_IN_NPZ proposal so graphify can mechanically verify feature parity going forward.

## Context

The previous retrain (2026-07-08) produced a model expecting 420 features because `build_training_corpus.py` included `osv_lead_days` as the 36th tabular feature, and `train_xgboost.py` trained on all NPZ columns. The predictor was built for 35 tabular features. We applied a band-aid (Option A: padded predictor to 420), but the root cause remains — the corpus includes a metadata column as a model input. This sprint fixes it properly.

## Work Items  

### Item 1: Store column names in NPZ + rebuild corpus
- **Assigned to:** strike (ml-engineering)  
- **Description:** Modify `backend/scripts/build_training_corpus.py` to store a `columns` array in the NPZ metadata. This array must list all 35 tabular feature names in the exact order they appear in the NPZ's X matrix. Also ensure `osv_lead_days` is EXCLUDED from the X matrix (it's metadata). Rebuild the corpus.
- **Expected output:** `training_data_v2.npz` regenerated with 419 columns (35 tabular + 384 SBERT) and a `columns` array of 35 feature names. `osv_lead_days` stored separately as metadata.
- **Verification:** `np.load()` shows `columns` key, X.shape is (n, 419), no `osv_lead_days` in columns list.

### Item 2: Retrain on clean 419-feature corpus + revert predictor
- **Assigned to:** strike (ml-engineering)  
- **Description:** Retrain XGBoost on the regenerated 419-column corpus. After training, revert the predictor from 36 tabular back to 35 tabular (remove the `osv_lead_days` padding added in the Option A band-aid). Verify scores match baseline.
- **Expected output:** New `xgboost_model.pkl`, `xgboost_calibrator.pkl`, `threshold_info.json`. Predictor at 35 tabular features. All 7 demo scores within ±5 of baseline.

## Verification  
- `np.load('training_data_v2.npz')['columns']` returns 35 feature names
- `X.shape[1] == 419`
- Model expects 419 features (`booster.num_features() == 419`)
- Predictor builds 35 tabular features (no `osv_lead_days`)
- All 7 demo row scores match baseline
- `just graphify` regenerates and `feature_parity.md` shows 35 tabular features in both inference and training
- Feature-parity guard test passes
