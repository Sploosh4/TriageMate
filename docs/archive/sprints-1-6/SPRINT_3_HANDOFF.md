# Sprint 3 Handoff — TriageMate MVP

> **Status: ARCHIVED** — Sprint 3 historical record

**Date:** 30 June 2026
**Status:** Tier 1 XGBoost model retrained, all pipeline stages running with real ML. Feature mismatch bug fixed, DMatrix compatibility fixed, all 7 demo rows validated with exact expected scores.

---

## 1. What Sprint 3 Built

Sprint 3 fixed the XGBoost model that had been broken since the `cisa_kev` label-leakage fix removed a feature column without retraining. The model now produces real exploitation probabilities for all cases that reach Tier 1.

- **Model retrained** — `python -m ml.train_xgboost --train` loaded the existing 68-column `training_data.npz` (93,018 records) and trained a fresh XGBoost classifier (800 trees, max_depth=4, learning_rate=0.03, scale_pos_weight=183.8). ROC-AUC: 0.9677.
- **DMatrix fix** — XGBoost 3.3.0 requires `DMatrix` for `booster.predict()` with `iteration_range`. The ensemble variance computation was using raw numpy arrays, causing a `TypeError` on XGBoost 3.3.0. Fixed by wrapping with `xgb.DMatrix(X)`.
- **Full validation** — All 7 demo rows verified with exact expected scores (94, 87, 71, 55, 63, 41, 22) and correct tier assignments (Deterministic/ML Tier/SLM Tier).

---

## 2. Root Cause: The 69→68 Feature Mismatch

### History

1. The original XGBoost model was trained with 69 features (37 tabular + 32 PCA text). `cisa_kev` was included as an input feature.
2. During a bug fix, it was discovered that `cisa_kev` is the **label** (target variable being predicted), not a feature. Including it caused ROC-AUC = 1.0 (the model memorised the answer key). Item A in `AI_PROBLEMS.md`.
3. `cisa_kev` was removed from training, inference, and ingest code. The `load_training_data()` migration function was added to detect and strip the old column from cached training data.
4. `build_tabular_features()` was updated to allocate 36 columns (37 - 1). Total features became 68 (36 tabular + 32 PCA).
5. **What was missed:** The `xgboost_model.pkl` was never retrained after the fix. The file on disk was still the old 69-feature model.
6. At runtime: `xgboost_predictor.py` built 68 features → `model.predict_proba(X)` received a 68-column array → model expected 69 → `ValueError: Feature shape mismatch, expected: 69, got 68`.

### The Fix

```bash
python -m ml.train_xgboost --train
```

This command:
1. Loaded the existing `training_data.npz` (93,018 records × 68 features) — already migrated via `load_training_data()`
2. Split temporally: 42,515 train (≤2023-06-30), 14,709 val (2023-07-01 to 2023-12-31), 35,794 test (>2023-12-31)
3. Trained XGBoost with `scale_pos_weight=183.8` (42,285 negative / 230 positive in training set)
4. Saved new `xgboost_model.pkl` expecting 68 features

### DMatrix Compatibility (Secondary Fix)

The ensemble variance computation in `xgboost_predictor.py` calls `booster.predict(X, iteration_range=..., output_margin=True)`. XGBoost 3.3.0 requires the input to be a `DMatrix` object when using `iteration_range`, not a raw numpy array. Added:

```python
import xgboost as xgb
dmat = xgb.DMatrix(X)
margin = booster.predict(dmat, iteration_range=(0, n_t), output_margin=True)
```

---

## 3. Model Performance

| Metric | Value |
|---|---|
| Training records | 42,515 |
| Validation records | 14,709 |
| Test records | 35,794 |
| Positive class (Exploited) | 230 train (0.54%) |
| Class weight (`scale_pos_weight`) | 183.8 |
| ROC-AUC | 0.9677 |
| Precision (Exploited) | 0.49 |
| Recall (Exploited) | 0.49 |
| Ensemble std escalation threshold | 0.15 |

The recall/precision of 0.49 for the exploited class is reasonable given extreme class imbalance (0.54% positive). The ROC-AUC of 0.9677 indicates strong ranking ability — cases at high risk are correctly ranked above low-risk cases, even if the absolute probability calibration is imperfect.

---

## 4. Validation Results

All 7 demo rows verified against the running server:

| ID | CVE | Expected Score | Actual Score | Tier | Pass |
|---|---|---|---|---|---|
| 1 | CVE-2023-34362 | 94 | 94 | Deterministic | ✅ |
| 2 | CVE-2023-4966 | 87 | 87 | Deterministic | ✅ |
| 3 | CVE-2023-27350 | 71 | 71 | ML Tier | ✅ |
| 4 | CVE-2024-1709 | 55 | 55 | ML Tier | ✅ |
| 5 | CVE-2023-36884 | 63 | 63 | SLM Tier | ✅ |
| 6 | CVE-2023-22515 | 41 | 41 | SLM Tier | ✅ |
| 7 | CVE-2022-47966 | 22 | 22 | SLM Tier | ✅ |

### Additional checks:
- `/api/health` — `llm_available: true`, `rag_documents: 7` ✅
- `/api/metrics` — `critical: 2, low_confidence: 4, exposed: 2, human: 3` ✅
- Case 5 substitution — `hasSubstitution: True`, `textConflict: True` ✅
- Case 7 text conflict — `score: 22, band: Low, conflict: True` ✅
- Frontend files — all 200 OK ✅
- New ingest via API — returns correct response ✅

---

## 5. Changes Made This Sprint

| File | Change |
|---|---|
| `ml/xgboost_predictor.py` | Added `import xgboost as xgb`. Wrapped `booster.predict()` input with `xgb.DMatrix(X)`. |
| `ml/xgboost_model.pkl` | **Replaced.** Retrained from 69→68 features. |
| `ml/training_data.npz` | Unchanged (already migrated to 68 columns). |
| `ML cache files` (`enriched_cves.json`, `pca_reducer.pkl`, `nvd_cves_cached.json`, `nvd_checkpoint.json`) | Unchanged. |
| Various `.md` docs | Updated to reflect Sprint 3 status. |

---

## 6. How the Pipeline Runs Now

The full pipeline is now running with real models at every stage:

```
POST /api/ingest
  │
  ▼
Pre-Tier: hostname dictionary lookup → mission tags
  │
  ▼
Tier 0: 3 deterministic rules → auto-resolve or escalate
  │
  ├── auto-resolved → score → DB → return
  │
  ▼ escalated
Tier 1: XGBoost (68 features, ROC-AUC 0.9677) → prob + ensemble std → auto-resolve or escalate
  │
  ├── auto-resolved → score → DB → return
  │
  ▼ escalated
Tier 2: Cloud LLM (OpenAI/Anthropic/Together) + RAG context → force-reflection → score_adjustment
  │
  ▼
scoring engine (5 dimensions) → 0-100 score → DB → return
```

---

## 7. What Remains — Sprint 4 Options

The pipeline scaffolding is complete. Remaining work is either ML improvements or production polish:

| Priority | Item | Effort | Notes |
|---|---|---|---|
| **1** | Pre-Tier multi-label classifier | 1–2 weeks | Replace 7-host dictionary with RandomForest. Needs 200–500 labeled assets |
| **2** | CWE encoder integration | 1 week | Fix AI_PROBLEMS #1–3 first (SecureBERT head naming, pooler_output, cache dir) |
| **3** | EPSS substitution model | 2–4 weeks | Sector-adjusted EPSS for CVEs like CVE-2023-36884 |
| **4** | Production hardening | Ongoing | Docker, CI/CD, auth, rate limiting |
| **5** | Frontend polish | Varies | Dashboard, notifications, customisation |

### Open Bugs (non-blocking)
- `AI_PROBLEMS.md` #1–3: CWE classifier (not in hot path)
- `AI_PROBLEMS.md` #10: Training patch features hardcoded (minor bias)
- `AI_PROBLEMS.md` #14: Heuristic always escalates (never reached now)

---

## 8. Quick Start

```bash
cd "TriageMate MVP/backend"
source venv/bin/activate
pip install -r requirements.txt
python seed_data.py              # Populate 7 demo rows
cp .env.example .env             # Edit .env with your API key
uvicorn main:app --reload        # Start at http://localhost:8000
```

**Verify all three pipeline tiers:**
```bash
# Health check
curl -s http://localhost:8000/api/health | python3 -m json.tool

# 7 demo rows (all correct scores)
curl -s http://localhost:8000/api/queue | python3 -m json.tool | head -10

# Ingest a CVE that reaches Tier 1 (non-KEV, ambiguous)
curl -s -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"vulnerability_id":"CVE-2024-TEST","hostname":"PRD-PRINT-SVR05.education.wa.edu.au","cvss_score":6.5,"cvss_vector":"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","cisa_kev":false,"epss_score":0.25,"target_ip":"10.0.0.1","raw_description":"Test"}' \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print('Score:',d['queueRow']['priorityScore'],'Tier:',d['queueRow']['tier'])"
# Expected: ML Tier (resolved by XGBoost model)
```
