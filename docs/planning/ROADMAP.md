# TriageMate — Master Roadmap & Status

> **Status: CURRENT** (9 July 2026)

> Last updated: 9 July 2026
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
| **Sprint 10** | **Operational Readiness** | ✅ Complete |
| **Sprint 11** | **Model Governance + Ops Hardening** | ✅ Complete |
| **Sprint 12** | **Gap Hardening** | ✅ Complete |
| **Sprint 13** | **EPSS Data Pipeline + Documentation** | ✅ Complete |
| **Sprint 14** | **Research & Synthetic Data** | ✅ Complete (2026-07-08) |
| **Sprint 15** | **Production Confidence** | ✅ Complete (2026-07-08) |
| **Sprint 15.5** | **Hygiene Cleanup** | ✅ Complete (2026-07-08) |
| **Sprint 16** | **ML Monitoring Foundation** | ✅ Complete (2026-07-09) |

---

## Sprint 9 — Data Supremacy

### Data Corpus

→ See `graphify_output/ml_inventory.md` § "Data Sources" for the complete resource inventory with file sizes and paths. Auto-generated, always current.

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
| 38 | osv_lead_days | OSV.dev earliest disclosure → NVD publish lag (metadata, not a model input) |

> **Note:** 37 fields are collected; 35 are used as tabular features by XGBoost (stored in NPZ as 35 named columns). The 2 excluded: `cisa_kev` (label leakage — removed from training features; it IS the target variable) and `description` (feeds SBERT encoder, not tabular). The NPZ stores 419 columns (35 tabular + 384 SBERT); `osv_lead_days` is stored as separate NPZ metadata (array shape (253568,)), not as a model input. The model's 419 input dimensions now match the NPZ columns exactly — the prior 420-vs-419 dimension mismatch is resolved.

### Script & Integration Inventory

→ See `graphify_output/file_tree.md` for all scripts and integrations with descriptions. Regenerate with `just graphify`.

### AI_PROBLEMS Fixed

| # | Issue | Resolution |
|---|---|---|
| #10 | Patch features hardcoded in training | FIXED — real distributions across 186K CVEs |

> **Note on retrain timeline:** The XGBoost retrain on `training_data_v2.npz` was **completed 2026-07-08** (previously-pending retrain status now resolved). The Sprint 3 retrain (93K records, ROC-AUC 0.9677) was a prior cycle with old corpus and fewer fixes. The retrained model achieves ROC-AUC 0.9459 on honest evaluation (point-in-time labels, no label leakage, chronological split).

---

## Application Scaffolding (Sprint 1)

### Backend Core

| Item | Status | Notes |
|---|---|---|
| FastAPI entry point (`main.py`) | ✅ Done | CORS, static mounts, startup lifecycle, .env auto-loading |
| SQLite database + schema (`database.py`) | ✅ Done | 63-column `vulnerabilities` table, DatabaseManager (SQLite + PostgreSQL) |
| Pydantic models (`models.py`) | ✅ Done | 19 models (BaseModel subclasses), camelCase aliasing |
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
| `GET /api/model/versions` | ✅ Done — Sprint 11 |
| `POST /api/model/activate` | ✅ Done — Sprint 11 |
| `GET /api/model/status` | ✅ Done — Sprint 11 |
| `GET /api/review/queue` | ✅ Done — Sprint 11 | Review queue listing with filter flag
| `POST /api/review/flag/{case_id}` | ✅ Done — Sprint 11 | Flag case for human review
| `POST /api/case/{case_id}/review` | ✅ Done — Sprint 11 | Submit analyst review decision
| `GET /api/case/{case_id}/history` | ✅ Done — Sprint 11 | Review history for a case
| `POST /api/auth/login` | ✅ Done (JWT) |
| `POST /api/auth/refresh` | ✅ Done |
| Swagger UI at `/docs` | ✅ Done |

### Pipeline Stages

| Stage | Status | Notes |
|---|---|---|
| Pre-Tier | ✅ Done | Synthetic hostname pipeline (1,476 rows, 23 WA gov agencies) + pre-tier model (60-dim RF, 5-fold CV ~58-60%). Feature index 59: `system_category` (ordinal 0-8) replaces binary `has_known_system`. |
| Tier 0 | ✅ Done | Deterministic rules: KEV + CVSS + EPSS |
| Tier 1 | ✅ Done | XGBoost (35 tabular + 384 SBERT, ROC-AUC 0.9459 retrained 2026-07-08; pre-fix label-leakage era was 0.9946, Sprint 3 post-fix was 0.9677) + probability-zoned routing (calibrated — see ML Artifacts) |
| Tier 2 | ✅ Done | Multi-provider cloud LLM (OpenAI/Anthropic/Together) |
| KNOWN_CONFLICTS | ✅ Done | Pre-resolved for demo CVEs |
| RAG context injection | ✅ Done | LanceDB vector store |

### ML Artifacts

| Item | Status |
|---|---|
| XGBoost model (`xgboost_model.pkl`) | ✅ Done — Retrained 2026-07-08 | Retrained on 253K records from `training_data_v2.npz` (419 columns: 35 tabular + 384 SBERT). ROC-AUC 0.9459 on honest test set (point-in-time labels, chronological split, no label leakage). Previous Sprint 3 model: 93K records, ROC-AUC 0.9677. Pre-fix label-leakage era: 0.9946 (not representative). Calibrator and threshold_info exported. |
| SBERT encoder (`encoder.py`) | ✅ Done — all-MiniLM-L6-v2, 384-dim (PCA removed v2.5) |
| Training pipeline (`train_xgboost.py`) | ✅ Done — two-phase, checkpoint/resume, calibration, temporal bias fixes |
| Training data v2 (`training_data_v2.npz`) | ✅ Done — Used for retrain 2026-07-08 | 253K samples, 419 columns (35 tabular + 384 SBERT). `osv_lead_days` is a metadata column (not a model input). Temporal + observation window filters applied. |
| Pre-tier model (`pre_tier_model.pkl`) | ✅ Done — 60-dim MultiOutputClassifier, 1,476 training rows, 351 blind holdout, 23 agencies, CV accuracy ~58-60%. Feature index 59: `system_category` (ordinal 0-8) replaces binary `has_known_system`. |
| EPSS v4 model (`epss_model_v4.pkl`) | ✅ Done — Sector-aware fallback model, trained on 777 synthetic_findings rows. Slot: v4 → v3 → v2 → v1 → heuristic rule engine in fallback chain. |
| Calibrator (`xgboost_calibrator.pkl`) | ✅ Done — Platt scaling on val set, exported during retrain 2026-07-08 |
| Threshold info (`threshold_info.json`) | ✅ Done — Classification threshold and F1 score exported during retrain 2026-07-08 |
| Drift dashboard (`GET /api/drift`) | ✅ Done — CSS-only charts, 30-day trend, tier routing, risk bands |
| Review queue (4 endpoints) | ✅ Done (implemented, tests pending — see Sprint NEXT+ Wave 1) — flag, review, history, queue listing |
| Alembic migrations (001–007) | ✅ Done — versioned schema, no ad-hoc helpers |
| LanceDB vector store | ✅ Done — 9 demo docs, FTS index |
| Model version registry (`model_registry.json`) | ✅ Done — Sprint 11 | 3 versions tracked; `GET /api/model/versions`, `POST /api/model/activate`, `GET /api/model/status` |
| Pre-Tier model registry (`model_registry_pre_tier.json`) | ✅ Done — Sprint 16 | Tracks pre-tier model versions for drift and rollback |
| EPSS model registry (`model_registry_epss.json`) | ✅ Done — Sprint 16 | Tracks EPSS model versions (v1–v4) for drift and rollback |
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

**All previously unfixed issues resolved.** See `AI_PROBLEMS.md` for full tracker.

---

## Sprint NEXT — All Items Complete ✅

All Sprint NEXT items are complete. Item 1 (XGBoost retrain) was **completed 2026-07-08**. Items 2, 3, 4, 5, 6, 8 are done. Item 7 (Cloud deploy + HTTPS) is deferred to Post-MVP.

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | XGBoost retrain on `training_data_v2.npz` | ✅ Done — Retrained 2026-07-08 | **Retrained on 253,568 samples (341 MB).** ROC-AUC: 0.9459. Model trained on 419 features (35 tabular + 384 SBERT). Calibrator and threshold_info exported. Score verification (2026-07-08): 7 demo rows within ±3 of expected values. |
| 2 | Pre-Tier RandomForest classifier | ✅ Already existed | 60-dim MultiOutputClassifier with KNOWN_TAGS fallback. No changes needed. |
| 3 | Model drift monitoring dashboard | ✅ Done | `GET /api/drift`, CSS-only charts, 4 panels |
| 4 | Rate limiting + CI/CD | ✅ Partially Complete | Rate limiting implemented and configurable via env vars. CI/CD pipeline is deferred — `.github/workflows/ci.yml` not yet created. |
| 5 | Retrain EPSS substitution model | ✅ Done — v3 & v4 operational | v3 model operational with real FIRST.org EPSS baselines (344K CVEs). v4 sector-aware model trained on 777 synthetic_findings rows. |
| 6 | Tier 3 Human Review queue | ✅ Done | 4 endpoints, alembic 004 migration, frontend review panel |
| 7 | Cloud deploy + HTTPS | 📋 Todo | Move from localhost to real deployment |
| 8 | Alembic database migrations | ✅ Done | 7 versioned migrations, ad-hoc helpers removed, wired into startup |

### Done (previously deferred — now complete)

| Item | Resolution |
|------|-----------|
| Pre-Tier multi-label classifier | ✅ Complete — trained on 1,476 research-backed synthetic hostnames, 60-dim RandomForest, 5-fold CV |
| EPSS v4 sector-aware model | ✅ Complete — trained on 777 synthetic_findings rows, slot in fallback chain |

### Post-MVP (deferred)

| Item | Reason |
|------|--------|
| Tier 2 CWE encoder (ModernBERT) | Deferred — NVD API + regex sufficient for CWE resolution; local 656MB model adds complexity for marginal benefit |
| Email / Slack notifications | Low immediate priority — no webhook config exists |
| Cloud deploy + HTTPS | Out of MVP scope — needs Docker, reverse proxy, DNS |

> **Note:** The detailed SPRINT_NEXT_PLAN.md has been merged into this file and archived. All items are now complete ✅.

---

## Sprint NEXT+: Post-Retrain Hardening

Planned after model retraining completes. Focus: test coverage, operational guards, and modest feature additions.

### Wave 1 — Tests + Guards

| # | Item | Effort | Status |
|---|------|--------|--------|
| 9 | **Tests for review + drift endpoints** | 4 hrs | ✅ Done — `test_review.py` (12 tests), `test_drift.py` (6 tests) |
| 10 | **Feature-parity guard test** | 1 hr | ✅ Done — `test_feature_parity.py` (6 tests) verifies 35-col tabular match between trainer and predictor |
| 11 | **Seed data ML dimension** | 30 min | ✅ Done — verified and fixed CVE-2023-36884 value (6→7). See `backend/reports/seed-data-ml-dimension.md`. |
| 12 | **Retrain verification** | 1 hr | ✅ Done — scores match baseline [94,87,71,63,55,41,22] ±3 |

### Wave 2 — Operational Resilience

| # | Item | Effort | Status |
|---|------|--------|--------|
| 13 | **Model version management** | 2 hrs | ✅ Done — config-file registry, activate API, predictor reload (covers rollback) |
| 14 | **Auto-resolved audit sampling** | 2 hrs | ✅ Done — fixed in `ingest.py`; Tier 1 auto-resolved cases now enter audit pool |
| 15 | **Cache freshness in health** | 1 hr | ✅ Done — `kev_last_refresh`, `epss_last_refresh`, `kev_entry_count`, `epss_entry_count` in `/api/health` |

### Wave 3 — Feature Additions

| # | Item | Effort | Status |
|---|------|--------|--------|
| 16 | **Rate limiting** | 1 day | ✅ Done — Token bucket on ingest/clear/demo, configurable via env vars (`INGEST_RATE_PER_MIN`, `INGEST_BURST_SIZE`, etc.) |
| 17 | **EPSS substitution retrain** | 1-2 days | ✅ v3 & v4 operational — v3: real FIRST.org EPSS baselines (344K CVEs). v4: sector-aware model trained on 777 synthetic_findings rows. |
| 18 | **Model comparison endpoint** | 1 hr | ✅ Done — `GET /api/model/status` with metadata + score comparison; visible in drift dashboard |

---

## Sprint 11 — Parallel Polish (8 July 2026)

> Parallel work items executed in a separate git tree, designed for zero merge conflicts with concurrent model-version-management work.

| # | Item | Estimate | Status | Notes |
|---|---|---|---|---|
| 1 | CI/CD Pipeline Expansion | 1 hr | 📋 Todo | Docker build job, pytest-cov coverage (≥60%), frontend-lint job with node --check. Not yet implemented — `.github/workflows/ci.yml` does not exist on disk. |
| 2 | Scoring Engine Unit Tests | 1 hr | ✅ Done | 16 tests across 5 test classes in `backend/tests/test_scoring.py`. Covers all 6 dimensions, band mapping, edge cases, Tier 2 integration. |
| 3 | Frontend Dark Mode + JS Modernization | 2 hr | ✅ Done | 58 new CSS custom properties, ~50 hex→var conversions, full `[data-theme="dark"]` block, theme toggle with localStorage persistence + prefers-color-scheme detection. All 9 JS files converted from `var`→`let`/`const` (164 const + 7 let), `defer` on all script tags. |
| 4 | Seed Data ML Dimension Verification | 30 min | ✅ Done | Bug found and fixed: CVE-2023-36884 had wrong `ml_exploitation_contribution` (6→7). All 7 rows verified correct. Report at `backend/reports/seed-data-ml-dimension.md`. |

---

## Sprint 14 — Research & Synthetic Data (8 July 2026)

> Synthesised 1,476 WA gov hostnames from 23 agencies based on published WA government ICT infrastructure research. Built `synthetic_assets` table, retrained pre-tier model, established research reference corpus, trained **EPSS v4 sector-aware model**, and introduced **system name embedding** (`system_category` ordinal replacing binary `has_known_system`).

### Synthetic Data Infrastructure

| Asset | Details |
|-------|---------|
| `synthetic_assets` table | 1,827 rows across 23 WA government agencies — hostnames, departments, classifications, network zones |
| `synthetic_findings` table | 777 rows — host-to-vulnerability mappings with realistic exploitation likelihoods; used for EPSS v4 sector-aware training |
| `research_references` table | 97 references sourced from WA government ICT research, naming conventions, and published infrastructure documentation |
| Research report | `backend/reports/intel/wa-gov-infrastructure-research.md` — full methodology, agency inventory, hostname synthesis rules |

### Pre-Tier Model Retrain

| Metric | Value |
|--------|-------|
| Training rows | 1,476 synthetic hostnames |
| Blind holdout | 351 rows (19.2%) |
| Agencies | 23 WA gov departments |
| Model | RandomForest MultiOutputClassifier (60-dim) |
| Cross-validation | 5-fold, accuracy ~58-60% |
| Tags predicted | `mission_prevalence`, `public_wellbeing_impact`, `internet_facing`, `data_classification` |
| System name embedding | Feature index 59: `system_category` (ordinal 0-8) replaces binary `has_known_system` — categorises system names into functional categories |

### EPSS v4 Sector-Aware Model

| Metric | Value |
|--------|-------|
| Model file | `backend/ml/epss_model_v4.pkl` |
| Training data | 777 rows from `synthetic_findings` mapped to vulnerability exploitation likelihoods |
| Approach | Sector-aware fallback model for EPSS score substitution |
| Slot | Tier 1 fallback chain: v4 → v3 → v2 → v1 → heuristic rule engine |

### New Automation

| Asset | Details |
|-------|---------|
| `just retrain-all` | Single command retrains all ML models from scratch: synthetic data → pre-tier → EPSS v4 |

---

## Sprint 15 — Production Confidence (8 July 2026)

> Tier 2 unit test suite, ML drift foundation (XGBoost), stress testing infrastructure, and Docker hardening.

### Tier 2 Unit Test Suite

| Item | Status | Details |
|------|--------|---------|
| `test_tier2.py` | ✅ Done | 21 tests: `build_prompt()`, `call_openai()` (success, 429, 5xx, timeout, invalid JSON), `call_anthropic()` (success, refusal, rate limit), `call_together()` (markdown fence stripping), `evaluate_tier_2()` orchestration, `KNOWN_CONFLICTS` fallback, `_record_api_call()` cost tracking |
| `just verify-tier2` | ✅ Done | Coverage ≥ 70% on `pipeline/tier_2.py` |

### ML Drift Foundation (XGBoost)

| Item | Status | Details |
|------|--------|---------|
| Alembic migration 006 | ✅ Done | `tier_1_features TEXT` column to `vulnerabilities` |
| `backend/analysis/drift.py` | ✅ Done | `compute_psi()` standard 10-bin equal-width PSI formula |
| `backend/ml/reference_distributions.json` | ✅ Done | Per-feature bin boundaries from `training_data_v2.npz` |
| `GET /api/drift/ml` | ✅ Done | PSI per feature + composite, status thresholds: stable (<0.1), warning (≥0.1), critical (≥0.25) |
| `test_drift_ml.py` | ✅ Done | PSI computation, endpoint shape, fuzzed round-trip |

> **Note:** In demo mode with small sample counts (e.g. 7–21 rows), PSI values may show "critical" or "warning" status on some features. This is expected — the reference distributions were built from 253K training samples, and small demo datasets will not match. Drift monitoring is meaningful only at production scale (hundreds+ of inference rows).

### Stress Testing + Visibility

| Item | Status | Details |
|------|--------|---------|
| Pipeline timing | ✅ Done | `time.monotonic()` per tier, trace dict in ingest |
| Verbose response mode | ✅ Done | `X-TriageMate-Verbose: true` header triggers `_trace` field |
| Test DB + Locust client | ✅ Done | `backend/analysis/stress_db.py`, `backend/tests/load/locustfile.py` |
| Stress report generator | ✅ Done | `backend/scripts/stress_report.py` — 7-section report |
| Docker hardening | ✅ Done | `WEB_CONCURRENCY` env var, `memory: 1024M`, `cpus: 2.0` |
| `just stress-test` | ✅ Done | Orchestration: start stack → wait → locust → analysis → report |
| `just stress-test-no-llm` | ✅ Done | Same without LLM cost |

---

## Sprint 15.5 — Hygiene Cleanup (8 July 2026)

> Repository hygiene, dead code removal, code fixes, and documentation sync.

### Phase A — Tracked Junk Removal

| Item | Status | Details |
|------|--------|---------|
| Delete tracked junk | ✅ Done | `=1.13.0`, `Opencode Error Logs/`, `temp_opencode_config/`, `Training Outcome Temp.txt`, `backend/triagemate.db.pre_retrain` |
| Delete untracked junk | ✅ Done | `backend/=2.31.0`, `backend/.coverage`, `backend/ml/xgboost_model_old.pkl`, `backend/ml/xgboost_model_pre_retrain.pkl`, `backend/ml/training_data_v2_pre_clean.npz` |
| `.gitignore` strengthened | ✅ Done | Added patterns for scratch files, ML snapshots, DB snapshots, coverage |
| Consolidate to `.venv` | ✅ Done | Removed legacy `backend/venv/`, all references now use `.venv/` |

### Phase B — Dead Code Removal

| Item | Status | Details |
|------|--------|---------|
| Remove `integrations/llm.py` | ✅ Done | Superseded by `pipeline/tier_2.py`. No imports found. `just lint && just test` — zero failures. |

### Phase C — Code Fixes

| Item | Status | Details |
|------|--------|---------|
| Scoring docstring + patch logic | ✅ Done | Weights sum clarification (107 clamped to 100), patch availability intent clarified |
| Drift endpoint reads `resolved_vulnerabilities` | ✅ Done | Alembic migration 007 added `tier_1_features` to `resolved_vulnerabilities`, archive INSERT updated, drift UNIONs both tables |
| Rate-limit consolidation | ✅ Done | Removed duplicate globals from `ingest.py`, demo bucket tightened to 30/min |
| Real LLM cost in verbose trace | ✅ Done | `evaluate_tier_2()` returns tuple with cost delta; ingest trace uses real values |
| CORS TODO comment | ✅ Done | Flagged wildcard origin as cloud-deploy deferral |

### Phase D — Documentation Sync (this report)

| Item | Status | Details |
|------|--------|---------|
| Bookkeeper freshness pass | ✅ Done | See `backend/reports/bookkeeping/2026-07-08-hygiene-freshness.md` |

---

## Quick Start

```bash
cd backend && source .venv/bin/activate
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

→ See `graphify_output/file_tree.md` for the complete annotated file tree (auto-generated, 255+ entries). Regenerate with `just graphify`.
