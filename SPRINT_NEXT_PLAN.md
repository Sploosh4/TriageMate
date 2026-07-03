# Sprint NEXT Plan — Model Retrain + Operational Upgrades

> **Created:** 2 July 2026 (after Sprint 9 — Data Supremacy)
> **Target:** Items 1, 2, 3, 6, 8 from the Next Wave roadmap
> 
> **Status update (2 July 2026 20:34 AWST):**
> - Item 1: corpus build DONE (144708 samples, 67 features, 19.6 MB). Training command not yet run.
> - Item 2: Pre-Tier RF — ALREADY DONE (Intel confirmed pretier_features.py + model exist)
> - Item 3: Drift Dashboard — DONE
> - Item 6: Human Review Queue — DONE
> - Item 8: Alembic migrations — DONE

---

## Item 1: XGBoost Retrain on `training_data_v2.npz`

**Goal:** Retrain the XGBoost exploitation probability model on 186K records with real feature distributions, replacing the old model that had 15 hardcoded features.

**Why now:** The old model (93K records) had 18 of 36 tabular features with zero importance because training data hardcoded them to constants. The new dataset has realistic variance across ALL features. Retraining is a one-command operation and the single highest-impact accuracy improvement possible.

### Command

```bash
cd backend && source venv/bin/activate
python -m ml.train_xgboost --train --data-file ml/training_data_v2.npz
```

This loads `training_data_v2.npz` (186K x 68), splits train/val/test chronologically, trains XGBoost (binary:logistic, 800 trees, scale_pos_weight for KEV imbalance), evaluates ROC-AUC, and saves to `backend/ml/xgboost_model.pkl`.

### Verification

```bash
# 1. Startup test
uvicorn main:app --reload &
sleep 3

# 2. 7 demo row scores within ±3 of expected
curl -s http://localhost:8000/api/queue | python3 -c "
import sys,json
rows=json.load(sys.stdin)['rows'][:7]
expected=[94,87,71,63,55,41,22]
for r,e in zip(rows,expected):
    ok='OK' if abs(r['priorityScore']-e)<=3 else 'MISMATCH'
    print(f'{r[\"vulnerabilityId\"]}: {r[\"priorityScore\"]} (expected {e}) {ok}')
"

# 3. All tests pass
kill %1 2>/dev/null
python -m pytest tests/ -v
```

**If scores shift significantly** (more than ±3 for any row): the scoring engine weights in `backend/scoring.py` may need adjustment to account for the more nuanced model output.

---

## Item 2: Pre-Tier RandomForest Classifier

**Goal:** Replace the hardcoded `KNOWN_TAGS` dict in `backend/pipeline/pre_tier.py` with a RandomForest model trained on the mock CMDB data, enabling ML-based prediction of `mission_prevalence` and `public_wellbeing_impact` for any hostname.

### Why Now

The current pre-tier uses a 31-entry dict (from `backend/data/mock_cmdb.json`) that maps hostnames to hardcoded tag values. Any unknown hostname gets defaults (`Support`, `Minimal`). A RandomForest trained on hostname features (department, role, domain suffix, OS, applications) would generalize to unseen hosts.

### What to Build

**1. Feature engineering script** — `backend/scripts/pretier_features.py` (NEW)

Extract features from each CMDB host entry:
- Department encoding (one-hot: health, transport, education, communities, wapol, finance, justice, water)
- Role encoding (one-hot: server, database, dc, web, file, app, print, network, security)
- OS type encoding (Windows vs Linux vs Other)
- Internet-facing flag (bool)
- Network zone (dmz, protected, restricted, management)
- Domain suffix (.health.wa.gov.au, .transport.wa.gov.au, etc.)
- Registered application count (int)
- Dependent assets count (int)

Labels (from mock_cmdb.json):
- `mission_prevalence`: Core / Support / Peripheral
- `public_wellbeing_impact`: Severe / Moderate / Minimal

**2. Training script** — `backend/scripts/train_pretier_model.py` (NEW)

- Load mock_cmdb.json → 31 records
- Apply SMOTE or random oversampling to generate 500 synthetic records (vary features, preserve label distributions)
- Train two RandomForest classifiers (one per label, multi-class)
- Evaluate with 5-fold cross-validation
- Save model: `backend/ml/pretier_classifier.pkl`

**3. Modify** `backend/pipeline/pre_tier.py`

- Add `_model_predict(hostname, asset_ctx) → dict` that:
  - Extracts features from hostname + asset context
  - Calls the RandomForest models
  - Returns `{mission_prevalence, public_wellbeing_impact}` with confidence scores
- Keep `KNOWN_TAGS` dict as fallback when model confidence is low
- Log when model is used vs fallback

### Verification

```bash
# New model predicts tags for known hosts
python3 -c "
from pipeline.pre_tier import predict_mission_tags
for h in ['per-PRD-MOVEIT-WEB01.health.wa.gov.au', 'per-TST-DC01.det.wa.gov.au']:
    tags = predict_mission_tags(h)
    print(f'{h}: {tags}')
"

# Unknown hostname still works (falls back to defaults)
predict_mission_tags('unknown-new-host.demo.wa.gov.au')

# All tests pass
pytest tests/ -v
```

---

## Item 3: Model Drift Monitoring Dashboard

**Goal:** Add a frontend dashboard panel that visualizes model drift using the data `audit.py` already collects (7.5% random sample of auto-resolved cases). Show score distribution trends, tier routing percentages, and feature drift alerts.

### Why Now

`audit.py` has been running silently since Sprint 1, collecting audit records on every deployment. This data is currently stored in the `resolved_vulnerabilities` table but never visualized. A drift dashboard makes the data visible and catchable before scores degrade.

### What to Build

**Backend — New endpoint:** `GET /api/drift`

Return aggregated drift metrics from `resolved_vulnerabilities`:
```json
{
  "score_trend": {"last_7_days": [84, 82, 85, 81, 83, 80, 86], "avg": 83},
  "tier_routing": {"auto_resolved": 0.72, "escalated": 0.28},
  "risk_band_distribution": {"very_critical": 0.05, "critical": 0.15, "high": 0.30, "medium": 0.35, "low": 0.15},
  "detection_tier_trend": {"deterministic": 0.40, "ml": 0.35, "llm": 0.20, "slm_conflict": 0.05},
  "feature_drift": [
    {"feature": "epss_score", "train_mean": 0.12, "infer_mean": 0.15, "drift": "warning"},
    {"feature": "cvss_score", "train_mean": 7.2, "infer_mean": 7.1, "drift": "ok"}
  ],
  "total_audited": 1542,
  "period_days": 30
}
```

**Modified:** `backend/routers/queue.py` — add the `/api/drift` route.

**Frontend — New component:** `frontend/js/components/driftDashboard.js`

Render:
- Score trend sparkline (last 30 days)
- Tier routing pie chart (auto vs escalated)
- Risk band bar chart
- Feature drift table (feature name, training mean, inference mean, drift status)
- All built with CSS-only charts (no chart library — use CSS bars and colored indicators)

**Modified:** `frontend/index.html` — add drift tab/panel
**Modified:** `frontend/css/triagemate.css` — drift dashboard styles
**Modified:** `frontend/js/app.js` — wire drift endpoint call

### Verification

```bash
# Backend endpoint returns data
curl -s http://localhost:8000/api/drift | python3 -m json.tool

# Frontend renders drift panel with data
# No blank panels, no JS console errors

# All tests pass
pytest tests/ -v
```

---

## Item 6: Tier 3 Human Review Queue

**Goal:** Add a dedicated UI for analysts to review auto-resolved cases, provide feedback, and override decisions. Feedback data feeds future model retraining.

### What to Build

**Backend — New endpoints:**

`GET /api/case/{id}/history` — return case event log (when resolved, by which tier, any overrides)

`POST /api/case/{id}/review` — analyst feedback submission:
```json
{
  "analyst_decision": "confirm" | "override",
  "override_score": 85,
  "override_band": "critical",
  "notes": "This is actually more severe — EPSS underestimates",
  "analyst_name": "jsmith"
}
```

`GET /api/review/queue` — return cases flagged for review (human-resolved cases from Tier 3, or random sample from auto-resolved)

`POST /api/review/flag/{id}` — flag a case for human review (from queue or case view)

**Modified:** `backend/routers/cases.py` — add review endpoints
**Modified:** `backend/routers/ingest.py` — add flagging logic
**Modified:** `backend/models.py` — add `ReviewRequest`, `ReviewResponse` models
**Modified:** `backend/database.py` — add `reviews` table (migration), add `flagged_for_review` column to `vulnerabilities`

**Frontend — New component:** `frontend/js/components/reviewQueue.js`

- List of flagged cases with tier info, score, hostname
- Click to expand → case detail panel + feedback form
- Feedback form: confirm/override buttons, score slider, band selector, notes textarea, analyst name
- Submit feedback → auto-refresh queue

**Modified:** `frontend/index.html` — add review tab/panel
**Modified:** `frontend/css/triagemate.css` — review UI styles
**Modified:** `frontend/js/app.js` — wire review endpoints

### Verification

```bash
# Review queue endpoint
curl -s http://localhost:8000/api/review/queue | python3 -m json.tool

# Submit feedback
curl -X POST http://localhost:8000/api/case/1/review \
  -H 'Content-Type: application/json' \
  -d '{"analyst_decision":"confirm","notes":"Looks correct","analyst_name":"test"}'

# Flag a case
curl -X POST http://localhost:8000/api/review/flag/1

# All tests pass
pytest tests/ -v
```

---

## Item 8: Alembic Database Migrations

**Goal:** Replace the ad-hoc `_migrate_add_column()` pattern in `database.py` with proper Alembic versioned migrations.

### Why Now

`database.py` has accumulated 8+ schema migration helpers as one-off functions (add column X, add column Y). These work but are undocumented and untestable. Before any further schema changes (Item 6 needs a `reviews` table and `flagged_for_review` column), the schema needs versioned migrations.

### What to Build

**1. Install Alembic** — `pip install alembic`

**2. Initialize Alembic** — `cd backend && alembic init alembic`

- Configure `alembic.ini` to point at `backend/triagemate.db`
- Configure `alembic/env.py` to use `DatabaseManager` connection

**3. Create initial migration** — capture the current 52-column schema as migration 001:

```bash
alembic revision --autogenerate -m "initial_schema"
```

Verify it matches current `database.py` schema exactly.

**4. Refactor** `backend/database.py`:

- Remove all `_migrate_add_column_X()` functions
- Replace with: for production, Alembic handles migrations
- Keep `init_db()` for SQLite dev (CREATE TABLE IF NOT EXISTS)
- Add `run_migrations()` that calls `alembic upgrade head` via subprocess or import

**5. Update** `backend/main.py`:

- In the lifespan startup, call `database.run_migrations()` instead of ad-hoc migration functions

### Verification

```bash
# Initial migration works
cd backend
alembic upgrade head
# Schema matches current state

# App starts without errors
uvicorn main:app --reload &
curl -s http://localhost:8000/api/queue | python3 -c "import sys,json; print(len(json.load(sys.stdin)['rows']),'rows')"

# New migration (test): add a column, verify it works
alembic revision --autogenerate -m "test_migration"
alembic upgrade head

# Rollback works
alembic downgrade -1

# All tests pass
kill %1 2>/dev/null
pytest tests/ -v
```

---

## Implementation Order

```
Wave 1 (Parallel):
  Item 1: Retrain XGBoost — corpus BUILD DONE (144708 samples, 67 features). Training NOT YET RUN.
  Item 8: Alembic migrations — DONE

Wave 2 (After Item 8):
  Item 6: Tier 3 Human Review queue — DONE
  Item 2: Pre-Tier RandomForest — DONE (was already implemented)

Wave 3 (After Item 6):
  Item 3: Drift dashboard — DONE

Verification:
  All 37 tests pass. All endpoints verified: /api/queue, /api/review/queue, /api/drift, /api/case/{id}/review, /api/case/{id}/history
```

> **Sprint NEXT complete as of 2 July 2026 20:34 AWST.** Only remaining action: run `python -m ml.train_xgboost --train --data-file ml/training_data_v2.npz` to retrain the XGBoost model on the new 144K-sample corpus.
