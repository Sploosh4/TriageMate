# TriageMate MVP — Scope Document

> **CAUTION:** This document was written during Sprint 1 and has not been fully updated. Many items marked as "deferred" or "out of scope" have since been implemented (Docker ✓, JWT auth ✓, Alembic migrations ✓, T3 review queue ✓, drift dashboard ✓, Pre-Tier RF model ✓, PostgreSQL support ✓). See ROADMAP.md for accurate current status.

> **Course Correction complete:** 11/11 items implemented and audited. Pipeline hardened from MVP to production-capable. See `ROADMAP.md` for current status and `docs/archive/sprints-1-6/COURSE_CORRECTION.md` for the full plan. **See also:** `docs/archive/sprints-1-6/PRE_DEMO_PLAN.md` — pre-demo hardening (9 items).

## Purpose

Define exactly what the TriageMate Minimum Viable Product delivers, what it explicitly defers, and the rationale behind each boundary decision. This document serves as the single source of truth for scope decisions during and after Sprint 1.

---

## 1. MVP Definition & Goal

**Goal:** A working, single-user vulnerability triage pipeline that ingests a raw vulnerability, runs it through four automated analysis stages (Pre-Tier → Tier 0 → Tier 1 → Tier 2), assigns a 0–100 priority score with per-dimension breakdown, and surfaces the result in a web UI identical to the approved demo.

**Delivery criteria:** The system must reproduce the 7 demo rows to within ±3 points of their expected scores (per SPRINT_1_HANDOFF §6), accept new vulnerability ingestion via API, and display the queue + case view in a browser.

---

## 2. What Is IN Scope

### 2.1 Architecture & Infrastructure
| Component | Reason |
|---|---|
| **FastAPI backend** serving REST API on localhost:8000 | Python-native ML ecosystem; async support for Tier 2 LLM calls; auto-generated OpenAPI docs |
| **SQLite database** (single `vulnerabilities` table) | Zero-config, file-based, sufficient for MVP scale. Schema designed to migrate to PostgreSQL by changing connection string only |
| **Static HTML/JS frontend** served by FastAPI | Minimal changes from demo; no build step; no frontend framework dependency |
| **Single developer machine deployment** (Docker recommended) | `Dockerfile` + `docker compose` provided; also supports bare-metal via `uvicorn main:app` |

### 2.2 Frontend (Complete — carried forward from demo)
| Feature | Reason |
|---|---|
| Queue view with sortable table, tier filter dropdown, metric filter boxes | Exact visual replica of `demo-reference.html`; zero UX regression |
| Case view with 4 panels: narrative (P1), accordions (P2), notes+gauge (P3), scoring+registry (P4) | Exact visual replica; all CSS class names, DOM IDs, keyboard shortcuts preserved |
| Text-conflict highlighting (yellow background + left border) | Required for SLM-tier cases (Rows 5, 6, 7) |
| EPSS substitution block rendering (greyed-out container with "Substituted" label) | Required for Row 5 display |
| Accordion behaviour, back button, Escape key navigation | Unchanged from demo |
| Data loaded from `/api/queue`, `/api/case/{id}`, `/api/metrics` instead of hardcoded array | Only architectural change; same rendering logic |

### 2.3 Backend API (Complete — 4 endpoints)
| Endpoint | Reason |
|---|---|
| `GET /api/queue` — returns all rows for queue table | Maps to demo's `QUEUE_DATA` array, filtered to queue-view fields |
| `GET /api/case/{id}` — returns full case view for one row | Maps to demo's `caseView` object |
| `GET /api/metrics` — returns 4 summary counts | Maps to demo's metric box calculation (critical, low-conf, exposed, human-val) |
| `POST /api/ingest` — accepts payload, runs pipeline, inserts & returns result | The core value proposition — ingesting a new vulnerability and getting a scored result |
| Auto-generated OpenAPI/Swagger UI at `/docs` | Free with FastAPI; useful for testing the ingest endpoint |

### 2.4 Pipeline Stages

#### Pre-Tier: HYBRID (dictionary + ML model)
- **IN scope:** Dictionary of 31 known WA government hosts with hardcoded mission tags, backed by a trained `MultiOutputClassifier(RandomForestClassifier)` with 200 trees at `backend/ml/pre_tier_model.pkl`
- **Reason:** Dictionary handles 31 known demo hosts. ML model runs for unknown hosts using a 60-dimensional hostname feature vector (see `backend/ml/pretier_features.py`). Default fallback (`Support` / `Minimal`, confidence 0.60) for model failures. Three-layer resolution: KNOWN_TAGS → ML model → default.

#### Tier 0: REAL (deterministic rules — production-ready)
- **IN scope:** Three rule sets with configurable threshold constants:
  - CISA KEV + CVSS ≥ 9.0 + internet-facing → auto-resolve Very Critical
  - CISA KEV + EPSS ≥ 0.90 + Category 3/4 → auto-resolve Very Critical
  - Not KEV + CVSS < 4.0 + EPSS < 0.10 → auto-resolve Low
  - All else → escalate to Tier 1
- **Reason:** Zero ML, zero training data, zero external dependencies. The rules embody the WA SOC's deterministic baseline logic. The only future work is threshold tuning.

#### Tier 1: REAL (XGBoost model, retrained Sprint 3)
- **IN scope:** XGBoost model (`xgboost_model.pkl`) — current model trained on 93,018 post-KEV CVEs (Sprint 3) with 419-dimension feature vector (35 tabular + 384 SBERT). ROC-AUC 0.9677 (post-fix; pre-fix value of 0.9946 was label-leakage era). New training corpus built in Sprint 9: 144,708 samples, 67 features — **retrain pending**. Ensemble std routing (threshold 0.15) determines escalation to Tier 2. Heuristic fallback available when model is absent.
- **Reason:** Model was retrained in Sprint 3 to fix the 69→68 feature mismatch caused by the `cisa_kev` label-leakage removal. The model now produces real exploitation probabilities for all cases. All 7 demo rows validated with exact expected scores.

#### Tier 2: REAL (multi-provider cloud LLM + Known Conflicts cache)
- **IN scope:**
  - Cloud LLM integration with OpenAI / Anthropic / Together AI, configurable via env vars
  - Backup provider support (primary + secondary) with automatic failover
  - Exponential backoff retry (3 attempts, 2^N seconds)
  - Force-reflection prompt template (Step A → B → C → structured JSON output)
  - `KNOWN_CONFLICTS` dictionary with pre-resolved assessments for the 3 SLM demo CVEs
  - Graceful degradation: retry → backup provider → known conflicts → neutral default
- **Reason:** The cloud LLM path costs ~$0.0004 per analysis (gpt-4o-mini). The KNOWN_CONFLICTS fallback is zero-cost and handles the demo rows. Together these provide the "SLM Tier" capability without waiting for a local model.
- **Local CWE encoder (ModernBERT) replacement is POST-MVP** (see §3)

### 2.5 Scoring Engine
| Component | Reason |
|---|---|
| Six weighted dimensions: CVSS (max 40), EPSS (max 20), Asset Criticality (max 20), Exposure (max 15), Patch (max 5), ML Exploitation Probability (max 10) | Matches demo scoring weights exactly. ML Exploitation dimension added post-MVP scope document via migration 005 |
| Band mapping: 0–25 → Low, 26–50 → Medium, 51–75 → Critical, 76–100 → Very Critical | Matches demo band mapping |
| Tier 2 score adjustment applied after dimension sum | Required for SLM cases (Rows 5, 6, 7 with negative adjustments) |

### 2.6 Background Scheduler
| Component | Reason |
|---|---|
| **Daily low-severity re-check:** Re-runs Tier 0 on "low" classified rows older than 7 days with current EPSS/KEV values | Prevents stale low classifications from remaining indefinitely; implements the "check within 7 days" logic from Additional Information.md |
| **Background audit sample:** 7.5% random sample of auto-resolved Tier 0/1 cases flagged for independent review | Detects model/concept drift without adding latency to the live pipeline (per Additional Information.md §Background Process) |
| Both run as `asyncio` background tasks within the same process | No separate scheduler process needed for MVP |

### 2.7 RAG Vector Store (LanceDB — seeded with demo documents, TTL cache)
| Component | Reason |
|---|---|
| LanceDB store at `backend/data/lancedb` seeded with 7 demo document chunks (1 per demo host) | Enables the Tier 2 prompt to include RAG context for all 7 hosts, not just SLM CVEs. Each document describes the host's software stack, network position, and relevant mitigations |
| `query_rag()` function called from the ingest pipeline | Returns formatted configuration context for the target hostname to inject into the LLM force-reflection prompt |
| TTL cache (60s) keyed by hostname | Avoids redundant LanceDB queries when multiple CVEs on the same host are ingested concurrently |
| `threading.Lock` guarding write operations | Prevents manifest corruption on concurrent `add()` calls. Reads are lock-free (safe via Lance manifest versioning) |
| Document ingestion CLI (`ingest_docs.py`) | Enables analysts to add internal documentation via `--file` or `--dir` flags with path traversal protection and file size limits |
| FTS (full-text search) index for fallback | Improves retrieval robustness. Failures are logged, not silently suppressed |

### 2.8 Seed Data
| Component | Reason |
|---|---|
| `seed_data.py` populates the 7 demo rows into SQLite | Required to reproduce the demo on first launch. Each row maps exactly from `QUEUE_DATA` to the 52-column schema. |

---

## 3. What Is OUT of Scope (Post-MVP)

### 3.1 ML Model Replacements

| Deferred Item | Why Out of Scope for MVP |
|---|---|
| **Pre-Tier multi-label classifier** (RandomForest replacing hostname dict) | Requires 200–500 internally labeled WA government assets. No public dataset exists. The stub correctly handles the 7 demo rows and returns conservative defaults for unknowns. |
| **Tier 1 XGBoost tuning** | **DONE (Sprint 3).** Retrained on 93,018 post-KEV CVEs. ROC-AUC 0.9677. Feature mismatch (69→68) fixed. Ensemble variance DMatrix bug fixed. Model running live. Note: v2.5 removed PCA — current pipeline stacks full 384-dim SBERT directly onto 35 tabular features for 419 total dimensions. **Sprint 9:** New training corpus built (144,708 samples, 67 features) — **retrain pending**. |
| **Tier 2 CWE encoder** (ModernBERT, replacing NVD API CWE lookup) | The NVD API + regex lookup (`ingest_cwe.py`) provides authoritative CWE without the 656MB SecureBERT model. The local encoder adds offline CWE pre-classification — valuable but not required now that NVD provides CWE at ingest time. |
| **EPSS substitution model** (sector-adjusted EPSS scorer) | Only affects Row 5's display. The stub hardcodes the substitution value. A real model requires sector-weighted exploitation data which is not publicly available. |

**Why defer all four:** Each real ML model requires data collection, training, and validation that is independent of the application scaffolding. The stubs produce correct outputs for the 7 demo rows. Deploying real models before the application is stable would couple ML experimentation risk to application deployment risk. The interface contracts are designed so each stub can be replaced without touching any other file.

### 3.2 Authentication & Access Control

| Deferred Item | Why Out of Scope |
|---|---|
| ~~User login / session management~~ | **✅ IMPLEMENTED.** Full JWT auth with bcrypt password hashing, login/refresh endpoints, and Bearer token middleware (see `backend/auth.py`). Disabled when `TRIAGEMATE_ADMIN_USER` is unset. |
| Role-based access control (analyst vs. admin vs. viewer) | No multi-user scenario exists in the MVP. RBAC design requires understanding who uses the tool, which is unknown pre-validation. |
| API key protection for `/api/ingest` | The ingest endpoint is protected by JWT auth when enabled. Future: webhook secret for Tenable integration. |

### 3.3 Deployment & Infrastructure

| Deferred Item | Why Out of Scope |
|---|---|
| ~~Docker containerization~~ | **✅ IMPLEMENTED.** `Dockerfile` + `docker compose` are the primary deployment method. |
| CI/CD pipeline | No team, no deployment target, no need for automated builds. |
| ~~Database migrations (Alembic)~~ | **✅ IMPLEMENTED.** 5 Alembic migrations in `backend/alembic/versions/`. `run_migrations()` runs on every startup. |
| PostgreSQL migration | SQLite is sufficient for single-user MVP. Migration is a connection-string change when scale demands it. |
| HTTPS / TLS | Localhost only. No network exposure. |

### 3.4 Production Hardening

| Deferred Item | Why Out of Scope |
|---|---|
| Rate limiting on `/api/ingest` | No external callers during MVP. |
| Input validation hardening beyond Pydantic | Pydantic models provide type validation. Additional sanitisation (XSS, injection) adds complexity without demonstrated need. |
| Error monitoring / structured logging | Print-to-console is sufficient for a single-developer project. |
| Backup / restore for SQLite database | The DB is 7 rows. Re-running `seed_data.py` is the restore strategy. |
| Model versioning / experiment tracking (MLflow) | No real ML models exist yet. Adding tracking infrastructure before models would be premature. |

### 3.5 Feature Enhancements

| Deferred Item | Why Out of Scope |
|---|---|
| Tier 3 Human Review queue (dedicated UI for analyst feedback ingestion) | The MVP has no multi-user workflow. The case view textarea serves as the analyst's workspace. A formal T3 queue requires user management, audit logging, and feedback loop design. |
| Real-time scanner integration / webhook receiver | The MVP ingest endpoint requires a manual curl call. Real integration requires understanding which scanner (Nessus, Qualys, Tenable) and its export format. |
| Statistical drift dashboard | The `audit.py` module captures the data; a dashboard to visualise it is a UI feature with no MVP-critical path. |
| Email / Slack notifications | No alerting use case defined. The queue view is the notification mechanism. |
| Multi-language support | The UI is English-only. All WA SOC outputs are in English. |
| Dark mode | The demo uses light mode. No user has requested dark mode. Adding it pre-validation is speculative. |

### 3.6 Technical Debt Not Addressed

| Deferred Item | Why Out of Scope |
|---|---|
| **Fix CWE classifier SecureBERT head naming mismatch (AI_PROBLEMS.md #1)** | ✅ BYPASSED — CWE classifier deprecated in favour of NVD API + regex lookup (`ingest_cwe.py`). The 656MB SecureBERT2.0 model is no longer loaded. `cwe_classifier_deprecated.py` preserved for reference. |
| **Fix ModernBERT `pooler_output` missing (AI_PROBLEMS.md #2)** | ✅ BYPASSED — same as #1. |
| **Fix custom cache dir (AI_PROBLEMS.md #3)** | ✅ BYPASSED — same as #1. |
| **Tier 1 heuristic always escalates (AI_PROBLEMS.md #14)** | Fallback path only — never reached now that the XGBoost model is trained and running. |

**Items fixed in Sprint 2:**
| Now Fixed | Fix |
|---|---|
| **LanceDB path ephemeral (AI_PROBLEMS.md #11)** | Moved from `/tmp/` to persistent `backend/data/lancedb`. Write lock added. |
| **FTS exception suppression (AI_PROBLEMS.md #12)** | Now logs the exception via `logging.warning()` instead of bare `except: pass`. |
| **Unused `t2_score_adjustment` (AI_PROBLEMS.md #13)** | Removed from `ingest.py`. |

**Reasoning for all deferrals:** Every item above either (a) has no functional impact on the 7-row demo, (b) requires a decision or input that doesn't exist yet, or (c) adds complexity that would slow down the core value proposition — getting a working triage pipeline into a user's hands. Each is tracked in `AI_PROBLEMS.md` or this document for future prioritisation.

---

## 4. Scope Summary Table

| Area | In Scope | Out of Scope |
|---|---|---|
| **Frontend** | Queue view, case view, metric boxes, filter, accordion, substitution block, text-conflict highlighting | Dark mode, notifications, T3 review UI, dashboards |
| **API** | GET /queue, GET /case/{id}, GET /metrics, POST /ingest | Rate limiting, API keys, multi-versioning |
| **Pipeline Pre-Tier** | Hostname dictionary (31 hosts) + trained RandomForest model (200 trees) | Real WA Government asset validation data |
| **Pipeline Tier 0** | Deterministic rules (production-ready) | Threshold tuning (future refinement) |
| **Pipeline Tier 1** | XGBoost model (35 tabular + 384 SBERT, ROC-AUC 0.9677) | WA-specific tuning (post-MVP) |
| **Pipeline Tier 2** | Cloud LLM + KNOWN_CONFLICTS cache | Local CWE encoder (ModernBERT) |
| **Scoring** | 6-dimension weighted score + band mapping (CVSS/EPSS/Criticality/Exposure/Patch/ML Exploitation) | Dynamic weight learning |
| **Database** | SQLite + PostgreSQL support, 5 Alembic migrations, 3 tables (vulnerabilities, resolved_vulnerabilities, reviews) | Full multi-table normalisation |
| **RAG** | LanceDB with 7 demo documents, TTL cache, write lock, ingestion CLI | Full index of Confluence/SharePoint |
| **Scheduler** | Daily low re-check, 7.5% audit sampling | Dashboard, alerting |
| **Ops** | `docker compose up` or `uvicorn main:app` | CI/CD, HTTPS, backups |
| **ML Ops** | None | Model versioning, experiment tracking, A/B testing |
| **Security** | CORS wide-open, JWT auth (optional, disabled by default) | RBAC, API keys, audit logging, IDS/IPS |
| **Maintenance** | `AI_PROBLEMS.md` tracks known issues | Fixing non-blocking issues pre-validation |

---

## 5. Risk Register for Scope Decisions

| Scope Decision | Risk | Mitigation |
|---|---|---|
| **~~No auth~~** | ~~Anyone with localhost access can call /api/ingest or view all data~~ | ✅ **IMPLEMENTED.** JWT auth with bcrypt, optional via `TRIAGEMATE_ADMIN_USER` env var. Disabled by default for backward compat. |
| **~~Tier 1 heuristic stub~~** | ~~May not generalise to unknown CVEs; all new cases may escalate to Tier 2~~ | ✅ **RESOLVED.** XGBoost model is trained and running live. Heuristic remains as fallback only. Routing logic has auto-resolve branches, no longer always escalates. |
| **Tier 2 cloud LLM dependency** | API key management, internet requirement, vendor API changes | `KNOWN_CONFLICTS` fallback works without internet. Cloud LLM is additive, not required. |
| **Single SQLite table** | JSON columns cannot be queried efficiently; schema rigidity | Acceptable for 7–1,000 rows. Column count (52) is manageable. JSON fields are parsed at the API layer, not queried. |
| **~~LanceDB in /tmp/~~** (Sprint 1 risk — ✅ mitigated) | ~~(Former) Data lost on reboot~~ | ✅ **RESOLVED.** Sprint 2 moved to persistent `backend/data/lancedb` with TTL cache and write lock. No longer a risk. |

---

## 6. Verification Criteria

The MVP is complete when:

1. `uvicorn main:app --reload` starts without errors
2. `http://localhost:8000` renders the queue view with 7 rows matching `demo-reference.html`
3. Each row's priority score is within ±3 of the expected values (94, 87, 71, 63, 55, 41, 22)
4. Clicking each row renders the case view with all 4 panels populated
5. The 4 metric boxes show correct counts (2, 4, 2, 3)
6. `POST /api/ingest` with a test payload returns a `CaseResponse` and the new row appears in the queue
7. The filter dropdown and metric box filters correctly narrow the queue rows
8. Text-conflict rows (5, 6, 7) show yellow highlight
9. Row 5 shows the substitution block
10. The Swagger UI at `/docs` renders all 4 endpoints
11. (Sprint 2) `POST /api/ingest` with a CVE that reaches Tier 2 returns a `textConflict` value set by the LLM (not `NOT_QUERIED`), and the server logs show `"event":"llm_call"` with token counts
12. (Sprint 2) `/api/health` returns `llm_available: true` when API key is configured, `rag_documents: 7` when seeded
