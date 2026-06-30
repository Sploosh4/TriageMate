# TriageMate ML Artifacts

Model artifacts are stored here.
Tier 2 uses cloud API — see `backend/pipeline/tier_2.py`.

## Future Files (placeholder)

| File | Purpose | Research Priority |
|---|---|---|
| `encoder.py` | SBERT embedding + PCA reduction for text-based features | Priority 3 |
| `cwe_classifier.py` | CWE classification model (SecureBERT2.0) | Priority 4 |
| `xgboost_predictor.py` | XGBoost exploitation probability model | Priority 5 |
| `vector_store.py` | LanceDB RAG document store for internal docs | Priority 2 |
| `epss_substitutor.py` | Sector-adjusted EPSS prediction model | Priority 7 |

## Architecture Rule

Pipeline files (`backend/pipeline/`) call ML files (`backend/ml/`), never the other way around.
