---
name: ml-toolbox
description: ML CLI commands for training, synthetic data, corpus building, data fetching, model evaluation. Use when running train_xgboost, generate_synthetic_data_v2, train_pre_tier, build_training_corpus, fetch_nvd_corpus, refresh_caches, load_research_refs, or any ML pipeline script.
---

# ML Toolbox — CLI Commands

## GitHub Workflow

Test `gh` access before relying on it. Use subagent operations when Level 4+ verified; otherwise route mutations through the commander.

All commands run from `backend/`.

## Training

```bash
# XGBoost exploitation model (Tier 1)
python -m ml.train_xgboost              # full pipeline (gather + train)
python -m ml.train_xgboost --train       # train only (skip gather)
python -m ml.train_xgboost --gather      # gather only (skip train)

# Pre-Tier RandomForest classifier
python -m ml.train_pre_tier                # JSON files (legacy)
python -m ml.train_pre_tier --from-db       # SQLite synthetic_assets (Sprint 14+)

# EPSS substitution models
python -m ml.train_epss_v2
python -m ml.train_epss_v3
python -m ml.train_epss_v4
python -m ml.train_epss_substitutor

# Retrain all ML models from scratch (synthetic data → pre-tier → EPSS v4)
just retrain-all                    # convenience wrapper (runs from backend/)
```

## Synthetic Data (Sprint 14+)

```bash
# Generate synthetic WA gov hostnames (1,500–2,000 rows)
python -m ml.generate_synthetic_data_v2      # inserts into synthetic_assets table
# Also produces: backend/ml/synthetic_data_v2.json, backend/ml/synthetic_holdout_v2.json

# Generate host-to-vulnerability mappings (777 rows for EPSS v4)
python -m ml.generate_synthetic_findings     # inserts into synthetic_findings table

# Load research references into DB
python -m scripts.load_research_refs          # seeds the research_references table
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

# Generate supplemental hostnames for training  # DEPRECATED — use generate_synthetic_data_v2 instead
python -m ml.generate_supplemental_hostnames  # DEPRECATED

# Ingest documents into LanceDB vector store
python -m ml.ingest_docs
```

→ See `graphify_output/ml_inventory.md` for the canonical file inventory with exact sizes. Paths below are stable by convention.

## File Locations

| What | Where |
|---|---|
| XGBoost model | `backend/ml/xgboost_model.pkl` |
| Pre-Tier model | `backend/ml/pre_tier_model.pkl` |
| EPSS models | `backend/ml/epss_model.pkl`, `backend/ml/epss_model_v2.pkl`, `backend/ml/epss_model_v3.pkl`, `backend/ml/epss_model_v4.pkl` |
| Training data | `backend/ml/training_data.npz`, `backend/ml/training_data_v2.npz` |
| NVD corpus | `backend/data/nvd_corpus.json` |
| NVD cache | `backend/data/nvd_cache.json` |
| EPSS cache | `backend/data/epss_cache.json` |
| KEV cache | `backend/data/kev_cache.json` |
| Checkpoint | `backend/ml/nvd_checkpoint.json` |
| Training JSON | `backend/ml/pretier_training_data.json` |
| Supplemental | `backend/ml/pretier_supplemental.json` |
| Synthetic data v2 (full) | `backend/ml/synthetic_data_v2.json` |
| Synthetic data v2 (holdout) | `backend/ml/synthetic_holdout_v2.json` |
| Pre-Tier metrics | `backend/ml/pre_tier_metrics.json` |

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

# Synthetic data / DB integrity checks
python -c "from database import get_db; db = get_db(); print('Assets:', db.execute('SELECT COUNT(*) FROM synthetic_assets').fetchone()[0]); print('Findings:', db.execute('SELECT COUNT(*) FROM synthetic_findings').fetchone()[0]); print('Refs:', db.execute('SELECT COUNT(*) FROM research_references').fetchone()[0]); db.close()"
```

## Training Screens
- ROC-AUC must be reported after every retraining
- 7 demo row scores must be verified (±3 tolerance)
- Training data must exclude 7 demo CVEs

## Feature Notes (Pre-Tier)
- `has_known_system` (binary) has been replaced by `system_category` (ordinal 0-8) — feature index 59
- `system_category` categorises system names into functional categories based on the WA government naming conventions
- See `backend/ml/pretier_features.py` for the full category mapping
