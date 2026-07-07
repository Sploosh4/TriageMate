---
name: ml-toolbox
description: ML CLI commands for training, corpus building, data fetching, model evaluation. Use when running train_xgboost, build_training_corpus, fetch_nvd_corpus, refresh_caches, train_pre_tier, or any ML pipeline script.
---

# ML Toolbox — CLI Commands

All commands run from `backend/`.

## Training

```bash
# XGBoost exploitation model (Tier 1)
python -m ml.train_xgboost              # full pipeline (gather + train)
python -m ml.train_xgboost --train       # train only (skip gather)
python -m ml.train_xgboost --gather      # gather only (skip train)

# Pre-Tier RandomForest classifier
python -m ml.train_pre_tier

# EPSS substitution models
python -m ml.train_epss_v2
python -m ml.train_epss_v3
python -m ml.train_epss_substitutor
```

## Data Pipeline

```bash
# Fetch EPSS training data
python -m ml.fetch_epss_data

# Bulk NVD corpus (200K+ CVEs)
python -m scripts.fetch_nvd_corpus
python -m scripts.fetch_nvd_corpus --resume     # resume from checkpoint
python -m scripts.fetch_nvd_corpus --use-feeds   # use yearly feeds instead of API

# Build unified training NPZ
python -m scripts.build_training_corpus
python -m scripts.build_training_corpus --limit 1000   # test mode
python -m scripts.build_training_corpus --skip-sbert   # skip text encoding

# Refresh caches
python -m scripts.refresh_caches                # all caches
python -m scripts.refresh_caches --source nvd   # NVD only
python -m scripts.refresh_caches --source kev   # CISA KEV only
python -m scripts.refresh_caches --source epss  # EPSS only

# Build CWE hierarchy
python -m scripts.build_cwe_hierarchy
python -m scripts.build_cwe_hierarchy --download    # download MITRE XML first

# Build vendor popularity index
python -m scripts.build_vendor_index

# Generate supplemental hostnames for training
python -m ml.generate_supplemental_hostnames

# Ingest documents into LanceDB vector store
python -m ml.ingest_docs
```

## File Locations

| What | Where |
|---|---|
| XGBoost model | `backend/ml/xgboost_model.pkl` |
| Pre-Tier model | `backend/ml/pre_tier_model.pkl` |
| EPSS models | `backend/ml/epss_model.pkl`, `backend/ml/epss_model_v2.pkl`, `backend/ml/epss_model_v3.pkl` |
| Training data | `backend/ml/training_data.npz`, `backend/ml/training_data_v2.npz` |
| NVD corpus | `backend/data/nvd_corpus.json` |
| NVD cache | `backend/data/nvd_cache.json` |
| EPSS cache | `backend/data/epss_cache.json` |
| KEV cache | `backend/data/kev_cache.json` |
| Checkpoint | `backend/ml/nvd_checkpoint.json` |
| Training JSON | `backend/ml/pretier_training_data.json` |
| Supplemental | `backend/ml/pretier_supplemental.json` |

## Post-Training Validation

```bash
# Quick validation
python -c "from ingest_helpers import build_feature_vector; print('ok')"

# Run tests
pytest backend/tests/ -v

# ML-specific analysis
python -m analysis.calibration_audit
python -m analysis.epss_eval
python -m analysis.feature_parity_check
```

## Training Screens
- ROC-AUC must be reported after every retraining
- 7 demo row scores must be verified (±3 tolerance)
- Training data must exclude 7 demo CVEs
