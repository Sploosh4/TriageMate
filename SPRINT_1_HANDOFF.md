# Sprint 1 Handoff — TriageMate MVP

**Date:** 29 June 2026
**Status:** Application scaffolding complete. All API endpoints, pipeline stubs, and frontend refactoring done and verified. Ready for ML model replacement and RAG integration.

---

## 1. What Sprint 1 Built

TriageMate is now a client-server application: a Python/FastAPI backend serving a static HTML/JS frontend. The original single-file `index.html` demo (1,618 lines, all inline) has been split into 24 files across a `backend/` and `frontend/` directory tree. The demo's 7 vulnerability rows are stored in a SQLite database and served through REST API endpoints. Every pipeline stage exists as a working stub — Tier 0 is production-ready, Tiers 1 and 2 use heuristics and a known-conflicts cache respectively, and Pre-Tier uses a hardcoded dictionary.

The application runs with `uvicorn main:app` from the `backend/` directory and serves the frontend at `http://localhost:8000`.

---

## 2. Project Structure

```
TriageMate MVP/
├── index.html                              # Original demo (preserved, unused)
├── demo-reference.html                     # Original demo with header comment
├── SPRINT_1_HANDOFF.md                     # This file
├── Additional Instructions/
│   ├── TriageMate MVP Transformation.md    # THE authoritative spec (1312 lines)
│   ├── TriageMate ML Research Prompt.md    # Research questions for ML components
│   └── TriageMate ML Research.md           # Pre-existing (may contain answers)
│
├── backend/
│   ├── main.py                             # FastAPI entry point
│   ├── database.py                         # SQLite schema + connection helper
│   ├── models.py                           # Pydantic models (6 classes, camelCase aliases)
│   ├── scoring.py                          # Final priority score calculation (pure math)
│   ├── ingest_helpers.py                   # CMDB stubs (KNOWN_HOSTS dictionary)
│   ├── seed_data.py                        # Populates DB with the 7 demo rows
│   ├── requirements.txt                    # fastapi, uvicorn, pydantic, httpx
│   ├── triagemate.db                       # SQLite database (auto-created)
│   ├── venv/                               # Python virtual environment
│   ├── __init__.py
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── queue.py                        # GET /api/queue + GET /api/metrics
│   │   ├── cases.py                        # GET /api/case/{id}
│   │   └── ingest.py                       # POST /api/ingest (runs full pipeline)
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── pre_tier.py                     # STUB: Dictionary of 7 known hosts
│   │   ├── tier_0.py                       # REAL: Deterministic rules (no ML)
│   │   ├── tier_1.py                       # STUB: Heuristic blending function
│   │   └── tier_2.py                       # STUB: Cloud LLM integration + KNOWN_CONFLICTS cache
│   └── ml/
│       ├── __init__.py
│       └── README.md                       # Placeholder for future ML artifacts
│
└── frontend/
    ├── index.html                          # Stripped HTML (140 lines, no mock data)
    ├── css/
    │   └── triagemate.css                  # Extracted CSS (17KB, unchanged from demo)
    └── js/
        ├── api.js                          # fetchQueue(), fetchCase(), fetchMetrics()
        ├── app.js                          # Orchestration: state, init(), event listeners
        └── components/
            ├── queue.js                    # Queue table rendering + helpers
            ├── caseView.js                 # Case view rendering (all 4 panels)
            └── metricBoxes.js              # Summary metric box counts
```

---

## 3. How to Run

```bash
cd "TriageMate MVP/backend"

# Activate virtual environment
source venv/bin/activate

# Seed the database (one-time; already done)
python seed_data.py

# Start the server
uvicorn main:app --reload
```

Then open `http://localhost:8000`. The frontend loads, fetches from `/api/queue`, and renders identically to `demo-reference.html`.

**API docs:** `http://localhost:8000/docs` (auto-generated OpenAPI/Swagger UI).

**Ingest a new vulnerability:**
```bash
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability_id": "CVE-2024-9999",
    "hostname": "PRD-TEST.agency.wa.gov.au",
    "cvss_score": 7.5,
    "cisa_kev": false,
    "epss_score": 0.32,
    "target_ip": "10.0.0.1",
    "raw_description": "RCE in web framework."
  }'
```

---

## 4. Pipeline Architecture

### How a vulnerability flows through the system

```
POST /api/ingest
    │
    ▼
Pre-Tier (pre_tier.py)      → mission_prevalence, public_wellbeing_impact
    │
    ▼
Tier 0 (tier_0.py)          → auto_resolved (very_critical / low) or escalated
    │
    ├── auto_resolved → calculate_final_score() → INSERT DB → return CaseResponse
    │
    ▼ escalated
Tier 1 (tier_1.py)          → auto_resolved or escalated (Shannon entropy gate)
    │
    ├── auto_resolved → calculate_final_score() → INSERT DB → return CaseResponse
    │
    ▼ escalated
Tier 2 (tier_2.py)          → cloud LLM force-reflection or KNOWN_CONFLICTS fallback
    │
    ▼
calculate_final_score()     → 0-100 priority score with 5-dimension breakdown
    │
    ▼
INSERT DB → return CaseResponse
```

### Tier 0 — Deterministic Rules (REAL, production-ready)

File: `backend/pipeline/tier_0.py`

Three rules with configurable threshold constants:
1. CISA KEV + CVSS >= 9.0 + internet-facing → very_critical (auto-resolved)
2. CISA KEV + EPSS >= 0.90 + data classification Category 3/4 → very_critical (auto-resolved)
3. Not CISA KEV + CVSS < 4.0 + EPSS < 0.10 → low (auto-resolved)
4. Everything else → ambiguous → escalated to Tier 1

No ML needed. The only future work is tuning the threshold constants.

### Tier 1 — Heuristic Stub

File: `backend/pipeline/tier_1.py`

Current implementation: a heuristic function blending CVSS (40%), EPSS (30%), and environmental modifiers (mission tags, internet-facing, lateral reachability, domain-joined, privileged accounts, cross-boundary). Returns exploitation probability, confidence, and routing decision.

Replace with: an XGBoost model using a 37-feature hybrid matrix (tabular features + SBERT text embeddings compressed to 16-64 dimensions via PCA/UMAP). Research priority: **Can implement this week** using public NVD + EPSS + CISA KEV data.

### Tier 2 — Cloud LLM + Known Conflicts Cache

File: `backend/pipeline/tier_2.py`

Current implementation has two paths:
1. **Cloud LLM** (if API key configured): Sends force-reflection prompt to OpenAI/Anthropic/Together AI. Provider configured via env vars `TRIAGEMATE_LLM_PROVIDER`, `TRIAGEMATE_LLM_API_KEY`, `TRIAGEMATE_LLM_MODEL`.
2. **Known Conflicts Fallback** (always available): The `KNOWN_CONFLICTS` dictionary contains pre-resolved assessments for CVE-2023-36884, CVE-2023-22515, and CVE-2022-47966. Unknown CVEs return a neutral default (`text_conflict: false, confidence: 0.30, score_adjustment: 0`).

The cloud LLM integration is production-ready. Cost at gpt-4o-mini pricing: ~$0.0004 per analysis (~$0.40 per 1,000 vulnerabilities). To enable it, set `TRIAGEMATE_LLM_API_KEY` in the environment.

---

## 5. Key Design Decisions

### Pydantic camelCase Aliasing
The frontend expects camelCase field names (e.g., `vulnerabilityId`, `riskBand`). The backend Pydantic models use snake_case internally. All models inherit from `BaseModelConfig` which sets:
```python
model_config = {
    "alias_generator": camel_case,
    "populate_by_name": True,
    "protected_namespaces": (),
}
```
FastAPI serializes responses using aliases (camelCase) by default. The `populate_by_name=True` allows both snake_case and camelCase when creating models from Python, which is used when deserializing JSON columns from the database. The `protected_namespaces = ()` prevents Pydantic v2 warnings about fields like `model_confidence`.

### `interfaceType` on Queue Rows
The frontend's "exposed" metric filter originally read `row.caseView.assetRegistry` to check for internet-facing assets. Since queue rows no longer include the full case view, `interface_type` was added to the `QueueRow` model and included in the SQL query. The frontend filter now checks `row.interfaceType.toLowerCase().indexOf('internet-facing') !== -1`.

### `ingest_helpers.py` Separation
CMDB lookups and asset classification stubs live in `ingest_helpers.py`, not in the ingest router. Each function (`lookup_data_classification`, `is_internet_facing`, `build_feature_vector`, `query_rag`, `get_asset_context`) is independently replaceable when real integrations are built.

### Single-Table Database
SQLite with one `vulnerabilities` table (~52 columns). JSON payloads (MITRE techniques, scoring weights, asset registry entries, summary paragraphs) are stored as TEXT columns parsed at the application layer. Designed for easy migration to PostgreSQL — no DB-specific features used.

### Scoring Engine
File: `backend/scoring.py` — `calculate_final_score()`. Five weighted dimensions:
- CVSS contribution: max 40 (CVSS score / 10.0 * 40)
- EPSS contribution: max 20 (EPSS score * 20)
- Asset criticality: max 20 (data classification + mission tags)
- Exposure: max 15 (internet-facing = 12, internal = 3)
- Patch availability: max 5 (available but not applied = 0, applied = 5)

Band mapping: 0-25→Low, 26-50→Medium, 51-75→Critical, 76-100→Very Critical.
Tier 2 score adjustments are applied after the dimension sum.

---

## 6. The 7 Demo Rows (Expected Scores)

These MUST be preserved. When replacing stubs with real ML models, the model outputs for these 7 inputs must produce scores within 3 points of the demo values (per §8.8 of the ML Research Prompt).

| ID | CVE | Hostname | Score | Band | Tier |
|---|---|---|---|---|---|
| 1 | CVE-2023-34362 | PRD-MOVEIT-WEB01.health.wa.gov.au | 94 | Very Critical | Deterministic |
| 2 | CVE-2023-4966 | PRD-CITRIX-ADC01.transport.wa.gov.au | 87 | Very Critical | Deterministic |
| 3 | CVE-2023-27350 | PRD-PRINT-SVR05.education.wa.edu.au | 71 | Critical | ML Tier |
| 4 | CVE-2024-1709 | PRD-RMM-GW01.sharedservices.wa.gov.au | 55 | Critical | ML Tier |
| 5 | CVE-2023-36884 | PRD-FILE-STORE02.communities.wa.gov.au | 63 | Critical | SLM Tier |
| 6 | CVE-2023-22515 | PRD-WIKI-CORE01.wapol.internal.wa.gov.au | 41 | Medium | SLM Tier |
| 7 | CVE-2022-47966 | PRD-ITSM-TOOL01.finance.wa.gov.au | 22 | Low | SLM Tier |

Special features to note:
- **Row 5** has `epss_substituted=True` (raw EPSS 0.065 → substituted 0.72, confidence 0.79). The `isSubstituted` flag appears on the scoring weight named "EPSS Exploitability Contribution".
- **Rows 5, 6, 7** have `text_conflict=True` — the frontend applies `.text-conflict` CSS class (yellow background, left border).
- **Row 7** has the lowest score (22, Low band) despite CVSS 9.8 — the SLM resolved that SAML is disabled, eliminating the attack surface.

---

## 7. What Sprint 1 Intentionally Avoided

- Authentication / user management
- Database migrations (Alembic)
- Docker / containerization
- CI/CD
- Model versioning / experiment tracking
- Real-time vulnerability scanner integration
- RAG document store (returns empty stub)
- API authentication or rate limiting

---

## 8. API Contract (MUST NOT CHANGE)

Replacing stubs with real models must preserve these contracts exactly.

### GET /api/queue
Returns `{"rows": [QueueRow, ...]}`. Each `QueueRow` has:
`id`, `vulnerabilityId`, `hostname`, `priorityScore`, `riskBand`, `detectionReason`, `tier`, `compliance`, `complianceCategory`, `interfaceType`

### GET /api/case/{id}
Returns `{"queueRow": QueueRow, "caseView": CaseViewData}`.

`CaseViewData` contains:
`summaryParagraphs`, `missionPrevalence`, `mitreTechniques`, `textConflict`, `textConflictNote`, `scannerOutput`, `weaknessTemplate`, `advisoryRefId`, `advisoryQuote`, `investigationNotes`, `hasSubstitution`, `substitutionBlock`, `scoreGaugeValue`, `scoreGaugeBand`, `gaugeBandColour`, `scoringWeights`, `assetRegistry`

### GET /api/metrics
Returns `{"criticalActions": int, "lowConfidence": int, "exposed": int, "needsHumanValidation": int}`

### POST /api/ingest
Accepts `IngestRequest`:
```json
{"vulnerability_id": str, "hostname": str, "cvss_score": float,
 "cvss_vector": str|null, "cisa_kev": bool, "epss_score": float,
 "target_ip": str, "raw_description": str}
```
Returns `CaseResponse` (same shape as GET /api/case/{id}).

---

## 9. Frontend Rendering Contract

The frontend renders the API response directly. Key points:

- `renderCase(caseResponse)` unwraps `caseResponse.caseView` — all rendering logic uses camelCase field names.
- `renderQueue(rows, filter, activeMetricFilter)` — `rows` is the array from `response.rows`, each row has camelCase fields.
- `updateMetricBoxes(rows)` — calculates counts from `rows` array. The "exposed" count checks `row.interfaceType`.
- All DOM element IDs, CSS class names, accordion behavior, keyboard shortcuts (Escape, Enter/Space) are unchanged from the demo.
- `escHtml()` is defined in `queue.js` and shared with `caseView.js` (global scope in browser context).

---

## 10. What Remains — Implementation Priority

These are ordered by easiest-to-hardest (matching the ML Research Prompt's implementation priority).

### Priority 1: Enable Cloud LLM Tier 2 (5 minutes)

Already built. Just set environment variables:
```bash
export TRIAGEMATE_LLM_API_KEY="sk-..."
export TRIAGEMATE_LLM_PROVIDER="openai"   # or "anthropic" or "together"
export TRIAGEMATE_LLM_MODEL="gpt-4o-mini"
```
The `KNOWN_CONFLICTS` fallback already handles the 3 demo SLM CVEs. An API key enables live analysis for unknown CVEs at ~$0.0004 per call.

### Priority 2: RAG Vector Store

File to create: `backend/ml/vector_store.py`
Vector database: LanceDB (recommended for single-machine MVP — zero config, embedded, fast on CPU). ChromaDB or FAISS are alternatives.

Needs:
- An embedding model for indexing internal documentation
- A chunking strategy for technical docs
- Integration into `ingest_helpers.py` → `query_rag()` (currently returns empty dict)
- RAG context passed into `tier_2.py`'s `build_prompt()`

### Priority 3: Tier 1 XGBoost Model

**Current stub:** `backend/pipeline/tier_1.py` — heuristic function (~55 lines).
**Target:** `backend/ml/xgboost_predictor.py` — loads a trained XGBoost model.

Training data: Public NVD + EPSS + CISA KEV (no proprietary data needed). The ML Research Prompt has detailed questions about the 37 features, SBERT embedding dimensionality, PCA vs UMAP, and hyperparameters.

Replacement steps:
1. Train model in a Jupyter notebook using public data
2. Export with `joblib.dump(model, "backend/ml/xgboost_model.pkl")`
3. Create `backend/ml/xgboost_predictor.py` that loads the model and exposes a `predict(features) -> dict` function
4. Update `tier_1.py` to call the predictor instead of the heuristic
5. Add Shannon entropy check: `H(p) > 0.35` → escalate to Tier 2

### Priority 4: CWE Encoder (Tier 2 pre-processing)

File to create: `backend/ml/cwe_classifier.py`

A 125M-parameter model (ModernBERT or RoBERTa-base) fine-tuned on NVD CVE-to-CWE mappings (~200K examples). Runs locally — small enough for CPU. Classifies short CVE description text into CWE classes. Added to `tier_2.py` as a pre-processing step before the decoder.

### Priority 5: Pre-Tier Multi-Label Classifier

**Current stub:** `backend/pipeline/pre_tier.py` — dictionary lookup of 7 known hosts (~35 lines).
**Target:** A scikit-learn `MultiOutputClassifier` wrapping a `RandomForestClassifier`.

Training data: 200-500 internally labeled assets (requires analyst time). Can bootstrap with rules-based heuristics from CMDB data (OU paths, VLAN membership, installed applications, agency type).

### Priority 6: EPSS Substitution Model

File to create: `backend/ml/epss_substitutor.py`

Replaces raw EPSS scores with sector-adjusted predictions. The demo shows this for CVE-2023-36884 where EPSS=0.065 doesn't reflect sector targeting. Requires sector-weighted exploitation data from threat intelligence. Can start as a simple heuristic multiplier.

### Priority 7: Production Hardening (not in MVP scope)

- Authentication / API key protection
- Database migrations
- Docker deployment
- CI/CD pipeline
- Real-time scanner integration (webhook receiver for `/api/ingest`)
- Model versioning and experiment tracking

---

## 11. The ML Research Prompt

File: `Additional Instructions/TriageMate ML Research Prompt.md` (258 lines)

This document was designed for a different AI to answer detailed research questions about:
- **Component 1:** Tier 1 XGBoost model — 37 features, SBERT embedding integration, training data sources, hyperparameters, calibration
- **Component 2:** Tier 2 SLM — encoder model selection (ModernBERT vs RoBERTa), decoder model selection (cloud LLM provider comparison), RAG implementation, prompt caching
- **Component 3:** Pre-Tier multi-label classifier — feature engineering, model architecture, training data construction
- **Component 4:** EPSS substitution model — model design, data sources, integration strategy

The Addendum (lines 186-237) updates Component 2 for cloud API usage instead of local 7B-8B models.

**If you have the output of this research prompt**, use it to guide the model replacement work in Priorities 3-6. The research prompt asks for concrete library names, model versions, parameter values, and training dataset references.

**If you do not have the output**, the priority 1 and 2 work (cloud LLM enablement and RAG store) can proceed without it. Priorities 3-6 should wait for or generate the research answers.

---

## 12. Known Gotchas

1. **Server startup directory:** `uvicorn` MUST be run from `backend/`. The static file mounts (`/css`, `/js`) and root route use relative paths (`../frontend/...`).

2. **Virtual environment:** Always activate `backend/venv/` before running Python commands. The `requirements.txt` specifies exact versions.

3. **DB reset:** Delete `backend/triagemate.db` and re-run `python seed_data.py` to get a clean 7-row state. The `init_db()` function uses `CREATE TABLE IF NOT EXISTS` so old data persists across restarts.

4. **Frontend globals:** All JS files run in the browser's global scope. Load order matters: `api.js` (no deps) → `queue.js` → `caseView.js` → `metricBoxes.js` → `app.js` (calls all others).

5. **Scoring weight `isSubstituted` flag:** The seed data stores `is_substituted` (snake_case) in the JSON column. Pydantic's `populate_by_name=True` handles deserialization. The API response serializes as `isSubstituted` (camelCase).

6. **`demo-reference.html`**: The original single-file demo with a header comment. Compare against this to verify frontend rendering.

7. **Tier 2 async:** `evaluate_tier_2()` is `async def` and must be awaited. The ingest endpoint handler is also `async`.

8. **Metrics SQL** (in `routers/queue.py`): Relies on `detection_tier`, `tier_1_confidence`, `interface_type`, and `risk_band` columns being correct. If the ingest endpoint changes HOW it sets these columns, the metric counts will break.

---

## 13. Quick Verification Commands

```bash
# Check all endpoints
curl -s http://localhost:8000/api/queue | python3 -m json.tool | head -5
curl -s http://localhost:8000/api/metrics
curl -s http://localhost:8000/api/case/1 | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['caseView']['scoreGaugeValue'])"
curl -s http://localhost:8000/api/case/5 | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['caseView']['hasSubstitution'])"

# Test ingest pipeline
curl -s -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"vulnerability_id":"CVE-2024-TEST","hostname":"PRD-TEST.wa.gov.au","cvss_score":7.5,"cisa_kev":false,"epss_score":0.32}' \
  | python3 -m json.tool | head -10

# Verify frontend serves
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/css/triagemate.css
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/js/api.js
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/js/app.js

# Open interactive API docs
# http://localhost:8000/docs
```
