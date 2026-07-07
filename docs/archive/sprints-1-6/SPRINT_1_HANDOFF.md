# Sprint 1 Handoff — TriageMate MVP

> **Sprint 3 status:** XGBoost model retrained and running (68 features, ROC-AUC 0.9677). See `SPRINT_3_HANDOFF.md` for details.
> **Sprint 2 status:** Cloud LLM Tier 2 enabled and RAG vector store built. See `SPRINT_2_HANDOFF.md` for details.
> This document remains the definitive reference for API contracts (§8), demo rows (§6), and design decisions (§5).

**Date:** 29 June 2026
**Status:** Application scaffolding complete. All API endpoints, pipeline stubs, and frontend refactoring done and verified. Ready for ML model replacement and RAG integration.

---

## 1. What Sprint 1 Built

TriageMate is now a client-server application: a Python/FastAPI backend serving a static HTML/JS frontend. The original single-file `index.html` demo (1,618 lines, all inline) has been split into 24 files across a `backend/` and `frontend/` directory tree. The demo's 7 vulnerability rows are stored in a SQLite database and served through REST API endpoints. Every pipeline stage exists as a working stub — Tier 0 is production-ready, Tiers 1 and 2 use heuristics and a known-conflicts cache respectively, and Pre-Tier uses a hardcoded dictionary.

The application runs with `uvicorn main:app` from the `backend/` directory and serves the frontend at `http://localhost:8000`.

---

## 2. Project Structure

> **Note:** This structure is updated for Sprint 2. See `ROADMAP.md §8` for the authoritative project file map.

```
TriageMate MVP/
├── index.html                              # Original demo (preserved, unused)
├── demo-reference.html                     # Original demo with header comment
├── SPRINT_1_HANDOFF.md                     # This file
├── Additional Instructions/
│   ├── TriageMate ML Implementation Plan — Final.md  # ML architecture decisions
│   └── ARCHIVED/                            # Superseded documents
│
├── backend/
│   ├── main.py                             # FastAPI entry point
│   ├── database.py                         # SQLite schema + connection helper
│   ├── models.py                           # Pydantic models (6 classes, camelCase aliases)
│   ├── scoring.py                          # Final priority score calculation (pure math)
│   ├── ingest_helpers.py                   # CMDB stubs (KNOWN_HOSTS dictionary)
│   ├── seed_data.py                        # Populates DB with the 7 demo rows
│   ├── requirements.txt                    # fastapi, uvicorn, pydantic, httpx, anthropic, etc
│   ├── .env.example                        # Environment variable template
│   ├── triagemate.db                       # SQLite database (auto-created)
│   ├── data/                               # Persistent LanceDB vector store (auto-created)
│   ├── routers/
│   │   ├── queue.py                        # GET /api/queue + GET /api/metrics
│   │   ├── cases.py                        # GET /api/case/{id}
│   │   └── ingest.py                       # POST /api/ingest (runs full pipeline)
│   ├── pipeline/
│   │   ├── pre_tier.py                     # STUB: Dictionary of 7 known hosts
│   │   ├── tier_0.py                       # REAL: Deterministic rules (no ML)
│   │   ├── tier_1.py                       # HYBRID: XGBoost + heuristic fallback
│   │   └── tier_2.py                       # REAL: Multi-provider cloud LLM + KNOWN_CONFLICTS fallback
│   └── ml/
│       ├── encoder.py                      # SBERT + PCA feature encoding
│       ├── xgboost_predictor.py            # XGBoost inference wrapper
│       ├── xgboost_model.pkl               # Trained model (~96K CVEs)
│       ├── pca_reducer.pkl                 # PCA transformation
│       ├── train_xgboost.py                # Training pipeline (2-phase)
│       ├── vector_store.py                 # LanceDB RAG store (persistent, TTL cache, write lock)
│       ├── cwe_classifier.py               # 🐛 BROKEN — not in use
│       ├── ingest_docs.py                  # Document ingestion for RAG
│       └── README.md                       # Artifact index
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

See `ROADMAP.md §7` for full setup and run instructions.

Quick summary:
```bash
cd "TriageMate MVP/backend"
source venv/bin/activate
python seed_data.py
uvicorn main:app --reload
# Open http://localhost:8000
```

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

### Tier 1 — Hybrid (XGBoost + Heuristic Fallback)

File: `backend/pipeline/tier_1.py`

Current implementation has two paths:
1. **XGBoost model** (primary): Calls `ml/xgboost_predictor.predict()` with a 68-feature hybrid vector (36 tabular + 32 PCA text features). The model was trained on ~96K post-KEV CVEs using public NVD + EPSS + CISA KEV data.
2. **Heuristic fallback** (when model unavailable): Blends CVSS (40%), EPSS (30%), and environmental modifiers. Returns exploitation probability, confidence, and routing decision.

The heuristic exists only as a fallback for environments where the ML model is not yet deployed. The XGBoost path is the primary evaluation route.

### Tier 2 — Real: Multi-Provider Cloud LLM + Known Conflicts Cache (Sprint 2)

File: `backend/pipeline/tier_2.py`

**Production-ready cloud LLM integration with three provider backends:**

1. **OpenAI:** Schema-enforced via `response_format: {"type": "json_schema", "strict": true}` with `TriageConflictResult` Pydantic model. Handles refusals (`finish_reason: "content_filter"`). Keep-alive via `httpx`.
2. **Anthropic:** Structured outputs via `client.messages.parse()` with `output_config.format` and Pydantic model. Handles refusals (`stop_reason="refusal"`) and truncation (`stop_reason="max_tokens"` retry). `cache_control` blocks for prompt caching.
3. **Together AI:** JSON Schema guidance via `response_format` (best-effort, not constrained decoding). Schema always embedded in prompt text. Hardcoded model support set (e.g., `Llama-3.3-70B`).

**Resilience:** Exponential backoff retry (3 attempts, 1s/2s/4s) on `ConnectTimeout`, `ConnectError`, 5xx. Respects `Retry-After` on 429. Do NOT retry on `ReadTimeout` (partial request cost risk) or 4xx auth errors. Backup provider automatic failover (primary → backup → KNOWN_CONFLICTS → neutral default).

**Prompt caching:** OpenAI uses automatic prefix matching (static system message first). Anthropic uses explicit `cache_control: {"type": "ephemeral"}` on system block. Together AI has no caching.

**Configuration (via environment variables or `.env`):**
- `TRIAGEMATE_LLM_PROVIDER` — `openai` | `anthropic` | `together`
- `TRIAGEMATE_LLM_API_KEY` — Provider API key
- `TRIAGEMATE_LLM_MODEL` — Default: `gpt-4o-mini`
- `TRIAGEMATE_LLM_MAX_TOKENS` — Default: `1024`
- `TRIAGEMATE_LLM_TIMEOUT` — Default: `30` seconds
- `TRIAGEMATE_LLM_BACKUP_PROVIDER` — Optional secondary provider
- `TRIAGEMATE_LLM_BACKUP_API_KEY` — Backup provider API key
- `TRIAGEMATE_LLM_BACKUP_MODEL` — Backup provider model

**Fallback cache:** The `KNOWN_CONFLICTS` dictionary contains pre-resolved assessments for CVE-2023-36884, CVE-2023-22515, and CVE-2022-47966. Unknown CVEs without API key return a neutral default (`text_conflict: false, confidence: 0.30, score_adjustment: 0`).

**Cost tracking:** Module-level accumulators log per-call metrics (provider, model, latency, input/output/cached tokens, estimated cost) as JSON lines. Accessible via `get_cost_tracking()`.

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

## 7. What Sprint 1 Intentionally Avoided (and Sprint 2 Status)

| Avoided | Sprint 2 Status |
|---|---|
| Authentication / user management | Still avoided (MVP on localhost) |
| Database migrations (Alembic) | Still avoided (SQLite single table) |
| Docker / containerization | Still avoided |
| CI/CD | Still avoided |
| Model versioning / experiment tracking | Still avoided |
| Real-time vulnerability scanner integration | Still avoided |
| **RAG document store** (returns empty stub) | **✅ Built in Sprint 2** — see SPRINT_2_HANDOFF.md |
| API authentication or rate limiting | Still avoided |

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

### GET /api/health (Sprint 2)
Returns `{"status": "ok", "version": "0.2.0", "tier_2_provider": str, "llm_available": bool, "rag_documents": int, "rag_store_path": str}`. Does NOT probe the LLM API (would incur cost) — reports configuration status only.

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

## 10. Implementation Priority (as of Sprint 2)

> **Sprint 3 delivered:** Priority 3 below is now **complete** (XGBoost model retrained and validated). See `SPRINT_3_HANDOFF.md` for details.
> **Sprint 2 delivered:** Priorities 1 and 2 below are now **complete**. See `SPRINT_2_HANDOFF.md` for full details.

### ✅ Priority 3: Tier 1 XGBoost Tuning — DONE (Sprint 3)
Retrained the XGBoost model on 93,018 post-KEV CVEs with 68 features (36 tabular + 32 PCA text). ROC-AUC 0.9677. Fixed the 69→68 feature count mismatch caused by the `cisa_kev` label-leakage removal. Fixed XGBoost 3.3.0 DMatrix compatibility in the ensemble variance computation. All 7 demo rows validated with exact expected scores.

### ✅ Priority 1: Enable Cloud LLM Tier 2 — DONE (Sprint 2)
Multi-provider cloud LLM integration (OpenAI/Anthropic/Together AI) with:
- Schema-enforced structured outputs via `json_schema` / `client.messages.parse()`
- Exponential backoff retry (3 attempts, `Retry-After` respect)
- Backup provider automatic failover
- Prompt caching structure (static first → dynamic second)
- Cost tracking with per-call token logging
- API key validation and startup warnings

### ✅ Priority 2: RAG Vector Store — DONE (Sprint 2)
LanceDB vector store at `backend/data/lancedb` with:
- 7 seeded demo documents (1 per hostname, covering CMDB records, GPO reports, change records, application configs)
- TTL cache (60s, keyed by hostname)
- `threading.Lock` for write safety
- `ingest_docs.py` CLI with chunking, path traversal protection, file size limits
- FTS index fallback with logged errors

### Priority 3: Tier 1 XGBoost Tuning (Model Already Trained)

**Current state:** `backend/pipeline/tier_1.py` — hybrid (tries XGBoost, falls back to heuristic).  
**Model file:** `backend/ml/xgboost_model.pkl` — trained on ~96K post-KEV CVEs with 36 tabular + 32 PCA text features.  
**Predictor:** `backend/ml/xgboost_predictor.py` — loads the model, builds feature vector, ensemble variance routing.  

Remaining work:
1. Validate model accuracy against the 7 demo rows (±3 point tolerance)
2. Tune hyperparameters using WA-specific validation data when available
3. Replace the heuristic fallback with a pass-through once the model is validated
4. Add Shannon entropy check: `H(p) > 0.35` → escalate to Tier 2 (currently using ensemble std)

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
