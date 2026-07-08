---
name: ml-engineering
description: ML model development, XGBoost tuning, feature vector design, training pipelines, EPSS data, NVD corpus, LanceDB vector store, pre-tier classifier. Use when training models, building corpus, engineering features, or evaluating ML performance.
---

# TriageMate ML Engineering

## Model Inventory

→ See `graphify_output/ml_inventory.md` for the canonical model inventory
  (feature counts, ROC-AUC, file sizes, training dates — auto-generated, always current).
  Regenerate with: `just graphify`

## Feature Vector Contract

→ See `graphify_output/ml_inventory.md` §Tier 1 for current feature dimensions
  (tabular count, SBERT dimension, total training features) and model training details.
→ See `graphify_output/feature_parity.md` for inference/training parity status.

`build_feature_vector()` lives in `backend/ingest_helpers.py`

### Contract
`build_feature_vector()` must always return the same set of feature keys. Never rename or remove keys — only append new ones.

### Current feature keys

→ See `graphify_output/feature_parity.md` for the complete, auto-generated
  feature key list with tabular/metadata classification.
→ See `graphify_output/ml_inventory.md` §Tier 1 for feature descriptions.
  Regenerate with: `just graphify`

### When you add a feature you MUST also:
1. Add it to the returned dict in `build_feature_vector()`
2. Add it to `backend/scripts/build_training_corpus.py` (CSV header + row builder)
3. Regenerate: `python backend/scripts/build_training_corpus.py`
4. Retrain XGBoost: `python backend/ml/train_xgboost.py`

### Verify
```bash
python -c "from ingest_helpers import build_feature_vector; print('ok')"
```

## Key Files
- `backend/ingest_helpers.py` — `build_feature_vector()`, CWE lookups
- `backend/pipeline/pre_tier.py` — `KNOWN_TAGS` dict, mission/impact tag assignment
- `backend/ml/train_xgboost.py` — XGBoost training pipeline
- `backend/ml/train_pre_tier.py` — Pre-tier classifier training
- `backend/ml/train_epss_v2.py`, `train_epss_v3.py` — EPSS model training
- `backend/ml/xgboost_predictor.py` — XGBoost inference
- `backend/ml/epss_substitutor.py` — EPSS substitution engine
- `backend/ml/encoder.py` — SentenceTransformer SBERT
- `backend/ml/vector_store.py` — LanceDB RAG store
- `backend/integrations/nvd.py` — NVD API v2 client
- `backend/scripts/build_training_corpus.py` — unified NPZ builder
- `backend/scripts/fetch_nvd_corpus.py` — bulk NVD fetcher
- `backend/data/nvd_cache.json` — offline NVD cache

## Score Contract
All 7 demo rows must score within ±3 of: 94, 87, 71, 63, 55, 41, 22

## Training Rules
- Training data MUST exclude the 7 demo CVEs (data leakage prevention)
- Any tabular feature addition/removal or SBERT dimension change requires
  full retraining + score re-validation against the 7 demo rows.
- Check current feature counts: see `graphify_output/ml_inventory.md` §Tier 1
  and `graphify_output/feature_parity.md`.
- Verify training/inference parity: run `just audit-features`.
- After retraining, always report ROC-AUC, per-class accuracy, and 7-row score verification

## Data Pipeline
- NVD corpus: `backend/data/nvd_corpus.json` (200K+ CVEs)
- Training data (current): `backend/ml/training_data_v2.npz`; legacy: `backend/ml/training_data.npz`
- Training scripts: `backend/ml/train_*.py`
- Corpus builder: `backend/scripts/build_training_corpus.py`

## Related Skills
- `ml-toolbox` — exact CLI commands for training, corpus building, data fetching
