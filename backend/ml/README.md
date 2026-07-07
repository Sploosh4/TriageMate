# TriageMate ML Artifacts

Model artifacts are stored here.
Tier 2 uses cloud API — see `backend/pipeline/tier_2.py`.

## Active ML Components

| File | Purpose | Status |
|---|---|---|
| `encoder.py` | SBERT embedding for CVE description text features | Active — called by `xgboost_predictor.py` |
| `xgboost_predictor.py` | XGBoost exploitation probability model | Active — core of Tier 1 pipeline |
| `vector_store.py` | LanceDB RAG document store for internal docs | Active — called by Tier 2 pipeline |
| `epss_substitutor.py` | Sector-adjusted EPSS prediction model (v3/v2/v1 + rule fallback) | Active — called on every ingest |
| `cwe_classifier.py` | CWE classification (SecureBERT2.0) — **deprecated** | Replaced by NVD API + `ingest_cwe.py` |

## Architecture Rule

Pipeline files (`backend/pipeline/`) call ML files (`backend/ml/`), never the other way around.
