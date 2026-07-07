# TriageMate — Master Roadmap & Status

> Last updated: 2 July 2026
> Status key: ✅ Done · 🟡 Needs config · 🔧 In progress · 📋 Todo · ⏭️ Post-MVP · 🐛 Known bug

---

## Sprint Status

| Sprint | Name | Status |
|---|---|---|
| Sprint 1 | Application Scaffolding | ✅ Complete |
| Sprint 2 | Cloud LLM + RAG | ✅ Complete |
| Sprint 3 | XGBoost Model Fix | ✅ Complete |
| Course Correction | Production Readiness (11 items) | ✅ Complete |
| Sprint 4 | Pre-Demo Hardening (9 items) | ✅ Complete |
| Sprint 5 | Demo Data Generator (17 items) | ✅ Complete |
| Sprint 6 | Production Hardening (PostgreSQL + JWT) | ✅ Complete |
| Sprint 7 | Operations Foundation | ✅ Complete |
| Sprint 8 | Feature Field Enrichment | ✅ Complete |
| **Sprint 9** | **Data Supremacy** | ✅ Complete |

---

## Sprint 9 — Data Supremacy

### Data Corpus Built

| Resource | Volume | Source |
|---|---|---|
| `nvd_corpus.json` | 186,102 CVEs, 145MB | NVD 2.0 feeds |
| `kev_cache.json` | 1,631 entries | CISA KEV |
| `epss_cache.json` | 344,852 scores | FIRST.org |
| `files_exploits.csv` | 47,089 exploits, 25,037 CVE mappings | ExploitDB |
| `vendor_popularity.json` | 17,100 vendors | NVD corpus |
| `training_data_v2.npz` | 186K raw CVEs → 144K filtered training set, 67 features (+ 1 label = 68 columns) | Unified corpus builder with temporal filters |

### Feature Field Status — ALL 37 FIELDS FILLED

| # | Field | Source |
|---|---|---|
| 1-8 | cvss_av/ac/pr/ui/s/c/i/a | CVSS vector from NVD corpus |
| 9 | cvss_score | NVD corpus |
| 10 | epss_score | EPSS cache |
| 11 | patch_available | NVD refs + OSV.dev |
| 12 | patch_applied | Realistic distribution (score-weighted sampling) |
| 13 | internet_facing | CMDB / synthetic |
| 14 | domain_joined | Hostname pattern |
| 15 | data_classification | CMDB → WAICP |
| 16 | mission_prevalence | Pre-tier tags |
| 17 | public_wellbeing_impact | Pre-tier tags |
| 18 | lateral_reachability | CMDB / synthetic |
| 19 | boundary_reachability | CMDB / synthetic |
| 20 | downstream_assets | CMDB / synthetic |
| 21 | patch_lag_days | Computed from CMDB + NVD |
| 22 | exploitdb_has_poc | ExploitDB CSV (25K direct mappings) |
| 23 | metasploit_has_payload | ExploitDB CSV |
| 24 | internet_scan_detected | Synthetic (KEV + EPSS heuristic) |
| 25 | threat_intel_pulses | OTX API (when configured) |
| 26 | nvd_reference_count | NVD corpus |
| 27 | cve_desc_tokens | Computed from description |
| 28 | vulnerability_age_days | NVD corpus |
| 29 | vendor_popularity_index | 17,100-vendor frequency index |
| 30 | cvss_exploitability_sub | NVD corpus |
| 31 | cvss_impact_sub | NVD corpus |
| 32 | is_top_25_cwe | NVD CWE → MITRE Top 25 |
| 33 | is_rce_signature | Regex on description |
| 34 | is_privesc_signature | Regex on description |
| 35 | is_bypass_signature | Regex on description |
| 36 | is_dos_signature | Regex on description |
| 37 | is_traversal_signature | Regex on description |

### New Integrations

| Integration | File | Purpose |
|---|---|---|
| OSV.dev | `backend/integrations/osv.py` | Precise fixed-in-version patch data |
| ExploitDB CSV | `backend/integrations/exploitdb.py` | Direct CVE-to-exploit mapping (25K CVEs) |
| Metasploit CSV | `backend/integrations/metasploit.py` | Metasploit module detection via EDB |

### New Scripts

| Script | Purpose |
|---|---|
| `backend/scripts/fetch_nvd_corpus.py` | Bulk NVD corpus builder (API 2.0 + feed fallback) |
| `backend/scripts/refresh_caches.py` | KEV + EPSS cache refresh |
| `backend/scripts/build_training_corpus.py` | Unified training dataset with real distributions |
| `backend/scripts/build_vendor_index.py` | Vendor frequency from NVD corpus |
| `backend/scripts/build_cwe_hierarchy.py` | CWE weakness hierarchy parser |

### AI_PROBLEMS Fixed

| # | Issue | Resolution |
|---|---|---|
| #10 | Patch features hardcoded in training | FIXED — real distributions across 186K CVEs |

---

## Application Scaffolding (Sprint 1)

### Backend Core

| Item | Status | Notes |
|---|---|---|
| FastAPI entry point (`main.py`) | ✅ Done | CORS, static mounts, startup lifecycle, .env auto-loading |
| SQLite database + schema (`database.py`) | ✅ Done | 63-column `vulnerabilities` table, DatabaseManager (SQLite + PostgreSQL) |
| Pydantic models (`models.py`) | ✅ Done | 10 models, camelCase aliasing |
| Scoring engine (`scoring.py`) | ✅ Done | 6 dimensions → 0–100 score → band mapping |
| Background scheduler (`scheduler.py`) | ✅ Done | Daily low-severity re-check |
| Background audit (`audit.py`) | ✅ Done | 7.5% random sample of auto-resolved cases |

### API Endpoints

| Item | Status |
|---|---|
| `GET /api/queue` | ✅ Done |
| `GET /api/case/{id}` | ✅ Done |
| `GET /api/metrics` | ✅ Done |
| `POST /api/ingest` | ✅ Done |
| `POST /api/ingest/batch` | ✅ Done |
| `POST /api/ingest/tenable` | ✅ Done (Tenable webhook) |
| `GET /api/health` | ✅ Done |
| `POST /api/auth/login` | ✅ Done (JWT) |
| `POST /api/auth/refresh` | ✅ Done |
| Swagger UI at `/docs` | ✅ Done |

### Pipeline Stages

| Stage | Status | Notes |
|---|---|---|
| Pre-Tier | ✅ Done | Hostname dictionary + pre-tier model (60-dim RF) |
| Tier 0 | ✅ Done | Deterministic rules: KEV + CVSS + EPSS |
| Tier 1 | ✅ Done | XGBoost (35 tabular + 384 SBERT = 419 total features, ROC-AUC 0.9677 post-fix; pre-fix was 0.9946 with label leakage) + calibration + probability-zoned routing |
| Tier 2 | ✅ Done | Multi-provider cloud LLM (OpenAI/Anthropic/Together) |
| KNOWN_CONFLICTS | ✅ Done | Pre-resolved for demo CVEs |
| RAG context injection | ✅ Done | LanceDB vector store |

### ML Artifacts

| Item | Status |
|---|---|
| XGBoost model (`xgboost_model.pkl`) | 🔧 Retraining — New: 144K records, ROC-AUC 0.9946, trained, calibrator pending (needs retrain run) |
| SBERT encoder (`encoder.py`) | ✅ Done — all-MiniLM-L6-v2, 384-dim (PCA removed v2.5) |
| Training pipeline (`train_xgboost.py`) | ✅ Done — two-phase, checkpoint/resume, calibration, temporal bias fixes |
| Training data v2 (`training_data_v2.npz`) | 🔧 Retrain pending — 144K samples, 67 features (35 tabular + 384 SBERT), temporal + observation window filters applied |
| Pre-tier model (`pre_tier_model.pkl`) | ✅ Done — 60-dim MultiOutputClassifier |
| Calibrator (`xgboost_calibrator.pkl`) | 🔧 Will generate after retrain — Platt scaling on val set |
| Drift dashboard (`GET /api/drift`) | ✅ Done — CSS-only charts, 30-day trend, tier routing, risk bands |
| Review queue (4 endpoints) | ✅ Done — flag, review, history, queue listing |
| Alembic migrations (001–005) | ✅ Done — versioned schema, no ad-hoc helpers |
| LanceDB vector store | ✅ Done — 9 demo docs, FTS index |
| CWE classifier | 🐛 Deprecated — replaced by NVD API + regex |

---

## Configuration

| Item | Status |
|---|---|
| Tier 2 cloud LLM | ✅ Configured — OpenAI gpt-4o-mini |
| NVD API key | ✅ Configured |
| OTX API key | ✅ Configured |
| JWT auth | ⏭️ Disabled by default — env vars unset |
| PostgreSQL | ⏭️ SQLite is default — set DATABASE_URL for PG |
| `.env` file | ✅ Present at `backend/.env` |
| `.env` auto-loading | ✅ Bulletproof — `.env` loaded relative to script path |

---

## Known Bugs

See `AI_PROBLEMS.md` for the authoritative tracker.

**Still Unfixed:**
- #14 TRIVIAL: Tier 1 heuristic always escalates (fallback path — never reached)

---

## Sprint NEXT — Items Complete (Retrain Pending)

These items were planned after Sprint 9. Items 2, 3, 6, 8 are ✅ Done; Item 1 (XGBoost retrain) is 🔧 Retraining (code fixes applied, model not yet retrained). Items 4, 5, 7 are deferred per the table below.

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | XGBoost retrain on `training_data_v2.npz` | 🔧 Retraining | 144K records, 35 tabular features (419 total with SBERT), 8 fixes applied (KEV starvation, hardcoded features, calibration, routing, PCA leakage, temporal bias, label leakage, scoring disconnect) |
| 2 | Pre-Tier RandomForest classifier | ✅ Already existed | 60-dim MultiOutputClassifier with KNOWN_TAGS fallback. No changes needed. |
| 3 | Model drift monitoring dashboard | ✅ Done | `GET /api/drift`, CSS-only charts, 4 panels |
| 4 | Rate limiting + CI/CD | 📋 Todo | Token bucket on ingest + GitHub Actions |
| 5 | Retrain EPSS substitution model | 📋 Todo | Blocked on sector-weighted exploitation data |
| 6 | Tier 3 Human Review queue | ✅ Done | 4 endpoints, alembic 004 migration, frontend review panel |
| 7 | Cloud deploy + HTTPS | 📋 Todo | Move from localhost to real deployment |
| 8 | Alembic database migrations | ✅ Done | 5 versioned migrations, ad-hoc helpers removed, wired into startup |

### Deferred (no current plan)

| Item | Reason |
|------|--------|
| Pre-Tier multi-label classifier | Blocked on labeled WA gov data |
| Tier 2 CWE encoder (ModernBERT) | Blocked on SecureBERT bug fixes |
| Email / Slack notifications | Low immediate priority — no webhook config exists |
| Cloud deploy + HTTPS | Out of MVP scope — needs Docker, reverse proxy, DNS |

---

## Sprint NEXT+: Post-Retrain Hardening

Planned after model retraining completes. Focus: test coverage, operational guards, and modest feature additions.

### Wave 1 — Must Do (Tests + Guards)

| # | Item | Effort | Description |
|---|------|--------|-------------|
| 9 | **Tests for new endpoints** | 4 hrs | `GET /api/review/queue`, `POST /api/review/flag/{id}`, `POST /api/case/{id}/review`, `GET /api/case/{id}/history`, `GET /api/drift` — all untested |
| 10 | **Feature-parity guard test** | 1 hr | Tests that `build_tabular_features()` output (35 cols) matches `xgboost_predictor.py` input by index. Catches column drift permanently. |
| 11 | **Seed data ML dimension** | 30 min | Verify `seed_data.py` populates `ml_exploitation_contribution` in all 7 demo rows. Currently unknown if NULL or 0. |
| 12 | **Retrain verification** | 1 hr | After training completes: compare queue scores to baseline [94,87,71,63,55,41,22] ±3, check ML contribution appears in scoring weights, verify calibrator loads |

### Wave 2 — Operational Resilience

| # | Item | Effort | Description |
|---|------|--------|-------------|
| 13 | **Model rollback** | 2 hrs | Save models to `ml/models/` with dated filenames. `--rollback` flag in train script to revert. Human-readable training log with metrics per run. |
| 14 | **Auto-resolved audit sampling** | 2 hrs | Extend `audit.py` to sample 1% of Tier 1 auto-resolved cases. Currently only samples Tier 0 routing. Redundant with routing fix but provides independent safety net. |
| 15 | **Cache freshness in health** | 1 hr | Add `kev_last_refresh`, `epss_last_refresh`, `nvd_last_success` timestamps to `/api/health`. Let operators see staleness at a glance. |

### Wave 3 — Feature Additions

| # | Item | Effort | Description |
|---|------|--------|-------------|
| 16 | **Rate limiting** | 1 day | Token bucket on `/api/ingest` + `/api/ingest/batch`. Prevents scanner floods. Configurable via env var. |
| 17 | **EPSS substitution retrain** | 1-2 days | Block lifted — 344K EPSS dataset already in `epss_cache.json`. Retrain the substitution model on real EPSS distributions. |
| 18 | **Model comparison endpoint** | 1 hr | `GET /api/model/info` — returns training date, record count, ROC-AUC, recall, precision, calibration threshold. Makes model quality visible from frontend. |

---

## Quick Start

```bash
cd backend && source venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0
# Open http://localhost:8000
```

### Verification

```bash
# Tests
python -m pytest tests/ -v

# Queue scores (7 demo rows: 94, 87, 71, 63, 55, 41, 22)
curl -s http://localhost:8000/api/queue | python3 -c "
import sys,json
rows=json.load(sys.stdin)['rows'][:7]
expected=[94,87,71,63,55,41,22]
for r,e in zip(rows,expected):
    ok='OK' if abs(r['priorityScore']-e)<=3 else 'MISMATCH'
    print(f'{r[\"vulnerabilityId\"]}: {r[\"priorityScore\"]} (expected {e}) {ok}')
"

# Health
curl -s http://localhost:8000/api/health | python3 -m json.tool
```

---

## Project File Map

```
TriageMate MVP/
├── AGENTS.md                             # Agent instructions (real file at root)
├── MVP_SCOPE.md → docs/architecture/MVP_SCOPE.md
├── ROADMAP.md → docs/planning/ROADMAP.md
├── AI_PROBLEMS.md → docs/reference/AI_PROBLEMS.md
├── DEMO_SCRIPT.md → docs/guides/DEMO_SCRIPT.md
├── WINDOWS_SETUP.md → docs/guides/WINDOWS_SETUP.md
├── SPRINT_NEXT_PLAN.md → docs/planning/SPRINT_NEXT_PLAN.md
├── RESEARCH_FINDINGS.md → docs/research/RESEARCH_FINDINGS.md
├── XGBOOST_INVESTIGATION_REPORT.md → docs/reference/XGBOOST_INVESTIGATION_REPORT.md
├── TRIAGEMATE_BOOK_PROMPT.md → docs/guides/TRIAGEMATE_BOOK_PROMPT.md
├── index.html                            # Original demo (preserved)
├── demo-reference.html                   # Visual reference
│
├── docs/
│   ├── architecture/
│   │   └── MVP_SCOPE.md                  # Scope authority
│   ├── guides/
│   │   ├── DEMO_SCRIPT.md                # Demo walkthrough
│   │   ├── WINDOWS_SETUP.md              # Windows hosting instructions
│   │   └── TRIAGEMATE_BOOK_PROMPT.md     # Book generation prompt
│   ├── planning/
│   │   ├── ROADMAP.md                    # Master status (this file)
│   │   └── SPRINT_NEXT_PLAN.md           # Active retrain plan
│   ├── reference/
│   │   ├── AI_PROBLEMS.md                # Bug tracker
│   │   ├── XGBOOST_INVESTIGATION_REPORT.md
│   │   ├── TriageMate ML Implementation Plan — Final.md
│   │   └── Hostname and Data Classification Standards.md
│   ├── research/
│   │   └── RESEARCH_FINDINGS.md
│   └── archive/
│       ├── handoffs/
│       │   └── SPRINT_9_HANDOFF.md
│       └── sprints-1-6/
│           ├── SPRINT_1_HANDOFF.md … SPRINT_8_HANDOFF.md
│           ├── PRE_DEMO_PLAN.md, COURSE_CORRECTION.md
│           └── SPRINT_9_BRIEFING_PLAN.md, TEAM_BRIEFING.md
│
├── backend/
│   ├── main.py                           # FastAPI entry point + .env loading
│   ├── database.py                       # DatabaseManager (SQLite + PostgreSQL)
│   ├── models.py                         # Pydantic models
│   ├── scoring.py                        # Priority score engine (6 dims)
│   ├── ingest_helpers.py                 # 35-feature vector builder
│   ├── auth.py                           # JWT auth
│   ├── logging_config.py                 # Structured JSON logging
│   ├── .env                              # API keys (gitignored)
│   ├── .env.example                      # Environment template
│   │
│   ├── routers/
│   │   ├── auth.py                       # Login / refresh
│   │   ├── queue.py                      # GET /api/queue, /api/metrics
│   │   ├── cases.py                      # GET /api/case/{id}
│   │   └── ingest.py                     # POST /api/ingest, batch, tenable, demo
│   │
│   ├── pipeline/
│   │   ├── pre_tier.py                   # Asset mission tagging
│   │   ├── tier_0.py                     # Deterministic KEV/CVSS/EPSS rules
│   │   ├── tier_1.py                     # XGBoost + heuristic fallback
│   │   └── tier_2.py                     # Cloud LLM with RAG context
│   │
│   ├── integrations/
│   │   ├── cmdb.py                       # CMDB adapter (stub)
│   │   ├── nvd.py                        # NVD enrichment + OSV enhancement
│   │   ├── osv.py                        # OSV.dev fix version data
│   │   ├── exploitdb.py                  # ExploitDB CSV + NVD fallback
│   │   ├── metasploit.py                 # Metasploit detection
│   │   ├── greynoise.py                  # Synthetic scan detection
│   │   ├── otx.py                        # AlienVault OTX threat pulses
│   │   ├── mitre_mapping.py              # CWE → MITRE ATT&CK
│   │   ├── advisories.py                 # Advisory reference lookup
│   │   ├── tenable.py                    # Tenable webhook parser
│   │   └── demo_generator.py             # Demo scenario generator
│   │
│   ├── scripts/
│   │   ├── fetch_nvd_corpus.py           # Bulk NVD corpus (API + feeds)
│   │   ├── refresh_caches.py             # KEV + EPSS cache refresh
│   │   ├── build_training_corpus.py      # Training dataset builder
│   │   ├── build_vendor_index.py         # Vendor frequency index
│   │   └── build_cwe_hierarchy.py        # CWE hierarchy parser
│   │
│   ├── ml/
│   │   ├── encoder.py                    # SBERT (PCA removed v2.5)
│   │   ├── xgboost_predictor.py          # Inference + ensemble variance
│   │   ├── xgboost_model.pkl             # Trained model (needs retrain)
│   │   ├── training_data.npz             # Original training data
│   │   ├── training_data_v2.npz          # 144K real-distribution dataset
│   │   ├── pre_tier_model.pkl            # Pre-tier classifier
│   │   ├── train_xgboost.py              # Two-phase training pipeline
│   │   ├── vector_store.py               # LanceDB RAG store
│   │   ├── epss_substitutor.py           # EPSS substitution
│   │   ├── ingest_docs.py                # Document ingestion CLI
│   │   └── README.md                     # ML artifact index
│   │
│   ├── data/
│   │   ├── nvd_corpus.json               # 186K CVEs (145MB, gitignored)
│   │   ├── nvd_cache.json                # 175 demo CVEs
│   │   ├── kev_cache.json                # 1,631 KEV entries
│   │   ├── epss_cache.json               # 344K EPSS scores
│   │   ├── files_exploits.csv            # 47K ExploitDB entries
│   │   ├── vendor_popularity.json        # 17K vendor frequencies
│   │   ├── mock_cmdb.json                # 31 fictional WA gov hosts
│   │   └── lancedb/                      # Vector store
│   │
│   └── tests/                            # 37 tests
│
└── frontend/
    ├── index.html                        # HTML shell
    ├── css/triagemate.css                 # Stylesheet
    └── js/
        ├── api.js                        # Auth-aware fetch wrapper
        ├── app.js                        # State + init + events
        └── components/
            ├── auth.js                   # Login modal + token mgmt
            ├── queue.js                  # Queue table
            ├── caseView.js               # Case detail panels
            ├── metricBoxes.js            # Metric counts
            └── demoControls.js           # Demo generator UI
```
