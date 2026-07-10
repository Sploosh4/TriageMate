# TriageMate — Roadmap

> **Status: CURRENT** (10 July 2026)
> 
> Previous roadmap archived to `docs/archive/ROADMAP-2026-07-09.md` (Sprints 1–16b complete).

---

## Current State

| Metric | Value |
|---|---|
| Tests | 412 pass, 0 fail |
| Open bugs | 0 (AI_PROBLEMS.md is clean) |
| Sprints completed | 17, 18, 19, 20 |
| Pipeline stages | Pre-Tier → Tier 0 → Tier 1 → Tier 2 → Tier 3 (Human Review) |
| Enrichment sources | 14 integrations (NVD, OSV, OTX, ExploitDB, Metasploit, Tenable, GreyNoise [deprecated], CMDB [stub], Advisories [stub], MITRE, CWE classifier, Demo generator, **Synthetic Telemetry**, **Network Context**) |
| Demo rows | 7 CVEs, scores 98/91/73/66/58/44/26 (±3 tolerance) |
| Auth | JWT (disabled by default, env-var-gated) |
| Database | SQLite (default), PostgreSQL (available via DATABASE_URL) |
| CI/CD | `.github/workflows/ci.yml` — full pipeline (matrix test, coverage, lint, Docker) |

### ML Models

| Model | Type | Status | Monitoring |
|---|---|---|---|
| XGBoost (Tier 1) | 419-dim, ROC-AUC 0.9459 | ✅ Active | Tests ✅, Parity ✅, Registry ✅, Calibration ✅, Drift ✅ |
| Pre-Tier RF | 60-dim RandomForest, ~38% holdout acc | ✅ Active | Tests ✅, Parity ✅, Registry ✅, Calibration ❌, Drift ✅ |
| EPSS v4 | 37-dim XGBRegressor, R² 0.99 | ✅ Active (fallback #1) | Tests ✅, Parity ✅, Registry ✅, Calibration ❌, Drift ✅ |
| EPSS v1–v3 | XGBRegressor | Fallback #2–#4 | Tests ✅, Parity ✅, Registry ✅, Calibration ❌, Drift ❌ |

---

## Sprint 17 — ✅ Complete (Security Context)

| # | Item | Status | Description |
|---|---|---|---|
| **1** | **Security Telemetry Module** | ✅ Done | `synthetic_telemetry.py` — Synthetic Sentinel incidents + EDR alerts + process evidence (is the vulnerable code loaded?). Adds `telemetry_json` to DB. |
| **2** | **Network Context Panel** | ✅ Done | `network_context.py` — DB-first peer discovery from `synthetic_assets` (1,827 assets). Blast radius, zone display, peer counts. Adds `network_context_json` to DB. |
| **3** | **Alembic Migration 008** | ✅ Done | Adds `telemetry_json`, `network_context_json` to both tables. |
| **4** | **7th Scoring Dimension** | ✅ Done | "Security Context" (max 5, total weight 112). Composite: threat_score × 3 + blast_radius × 2. |
| **5** | **Panel 5 Frontend** | ✅ Done | Full-width security context panel below scoring breakdown. Two-column telemetry grid + blast radius bar. |
| **6** | **Seed data recalculated** | ✅ Done | New scores: 98/91/73/66/58/44/26. Synthetic assets populated. |

---

## Sprint 18 — ✅ Complete (Quick Wins + Monitoring)

| # | Item | Effort | Status | Description |
|---|---|---|---|---|
| **1** | **NVD Reference Count ≥21 Tier 0 rule** | 30 min | ✅ Done | CVEs with 21+ NVD references auto-resolve as `very_critical` at Tier 0. Free signal — 9.5× baseline KEV rate. |
| **2** | **CWE-Stratified EPSS Thresholds — Extend to Tier 0** | 45 min | ✅ Done | ✅ Part A (fix dead code in `_tier_zero_check()`) already done. Part B: Tier 0's `LOW_EPSS_THRESHOLD` is now CWE-aware instead of monolithic 0.10. |
| **3** | **Pre-Tier RF Drift Monitoring** | 5–6 hrs | ✅ Done | PSI-based drift endpoint for Pre-Tier model (60-dim). DB migration, pipeline capture, reference dists, API. |
| **4** | **EPSS Drift Monitoring** | 5–6 hrs | ✅ Done | PSI-based drift endpoint for EPSS fallback models (37/22-dim). Same pattern as Item 3. |
| **—** | **Bonus A: CWE_EPSS_THRESHOLDS coverage** | 20 min | ✅ Done | Extended CWE-stratified thresholds to cover additional CWE families. |
| **—** | **Bonus B: CWE-stratified KEV threshold** | 15 min | ✅ Done | KEV threshold now varies by CWE category instead of monolithic value. |
| **—** | **Bonus C: threshold_info.json** | 15 min | ✅ Done | Published consolidated threshold documentation to API. |
| **—** | **Bonus D: Scoring weight documentation** | 1 hr | ✅ Done | `docs/architecture/scoring-weights.md` — full weight design rationale, 112-sum, clamping. |

---

## Sprint 19 — ✅ Complete (Config + Retraining + Closing the Loop)

*Executed 10 July 2026. See `.opencode/plans/2026-07-10-sprint-19.md` for full detail.*

| # | Item | Status | Description |
|---|---|---|---|
| **1** | **Shared Config Module** | ✅ Done | Created `backend/pipeline/config/` package with domain-grouped config modules (`thresholds.py`, `scoring.py`, `feature_names.py`, `__init__.py`). Moved all shared business-logic constants out of individual files. Single source of truth for constants across training and inference. |
| **2** | **Scheduled Retraining Triggers** | ✅ Done | Extended `scheduler.py` to trigger model retraining on drift (PSI ≥0.10) or on a periodic schedule (weekly default). Lock mechanism, configurable env vars, `GET /api/system/retrain-status` endpoint. Closes the drift-detection loop from Sprint 18. |
| **3** | **NPZ Column Names — Fix train_xgboost.py** | ✅ Done | Added `feature_names` metadata (all 419 dims: 35 tabular + 384 SBERT) to `training_data.npz` saved by `train_xgboost.py:save_training_data()`. Enables graphify to verify column correspondence between training output and inference input. |
| **4** | **Concept Drift — Prediction Distribution + Ground Truth Stubs** | ✅ Done | Added prediction-level drift monitoring: `GET /api/drift/concept` endpoint for output distribution tracking, `POST /api/feedback/{id}` for ground-truth feedback (API stubs only — schema deferred to Sprint 20), and `GET /api/drift/accuracy` stub. |
| **—** | **Bonus A: Scoring Property Tests** | ✅ Done | Property-based tests for `backend/scoring.py` covering edge cases: all-zero, all-max, negative inputs, clamping, band boundaries. |
| **—** | **Bonus F: Seed Data Freshness Check** | ✅ Done | `backend/scripts/verify_seed_scores.py` script that verifies seed data scores match the canonical contract from `test_model_versions.py`. Integrated via `just verify-seeds`. |

> **Note:** Bonuses B–G from the original sprint plan were **deferred to Sprint 20**, but Sprint 20 focused on its own Items 1–3. Bonuses have been reorganized: Config API (Bonus B) → Sprint 21 Bonus A, Drift Webhook (Bonus C) → Sprint 21 Bonus B, CI benchmarks / Alembic / Rollback (Bonuses D/E/G) → Sprint 22.

---

## Sprint 20 — ✅ Complete (Agentic LLM + Customizable Weights + Safe PCA)

*Executed 10 July 2026. See `.opencode/plans/2026-07-10-sprint-20-planning.md` for full detail.*

| # | Item | Status | Description |
|---|---|---|---|
| **1** | **Multi-Step Agentic LLM** | ✅ Done | Transformed Tier 2 from single-shot to multi-step agent with 12 tools (KEV, NVD, EPSS, CWE, MITRE, network, telemetry, advisories, ExploitDB, Metasploit, CMDB, RAG). 15-step limit, $0.50 cost budget, feature-flag gated (`TRIAGEMATE_AGENT_ENABLED=false`). Graceful fallback to single-shot. 31 new tests. |
| **2** | **Customizable Risk Multipliers** | ✅ Done | Scoring weights exposed via `scoring_weights.json` override. Admin API endpoints (`GET/PUT /api/admin/config/scoring`, `POST /reset`). Frontend admin settings page with 7 sliders and live demo CVE score preview. 18 new tests. |
| **3** | **Safe PCA Dimensionality Reduction** | ✅ Done | PCA re-introduced with correct train/test hygiene — fitted on training split only. 384 SBERT dims reduced via `n_components=0.95`. Saved to `pca_model.pkl`. Graceful fallback if PCA model missing. 16 new tests. |

---

## Sprint 21 — 🟡 Planned (Multiplier-Based Security Scoring + Quick Wins)

*Planned 13 July 2026 (earliest — Sprint 20 must complete first). See `.opencode/plans/2026-07-10-sprint-21.md` for full detail.*

| # | Item | Status | Description |
|---|---|---|---|
| **1** | **Multiplier-Based Security Scoring** | 🟡 Planned | Replace additive Security Context (0-5 pts) with proportional multiplier (1.20/1.10/1.00/0.85/0.70). Lock in scoring formula for MVP. Updates scoring.py, frontend, tests, and demo CVE scores. |
| **—** | **Bonus A: Config API** | 🟡 Planned | Read-only `GET /api/config` exposing thresholds, scoring weights, and multiplier config. |
| **—** | **Bonus B: Drift Webhook** | 🟡 Planned | POST drift alerts to configured webhook URL when PSI ≥ 0.10. |

---

## Later — Medium-Term Engineering

| # | Item | Effort | Description |
|---|---|---|---|
| **8** | **Scheduled retraining** | — | ✅ **Completed in Sprint 19** (Item 2) — Retraining triggers, lock mechanism, status endpoint implemented. |
| **9** | **Concept drift monitoring** | — | ✅ **Completed in Sprint 19** (Item 4) — Prediction distribution tracking, ground-truth API stubs, accuracy endpoint. |
| **11** | **Shared config module** | — | ✅ **Completed in Sprint 19** (Item 1) — `backend/pipeline/config/` package created. |
| **12** | **Multiplier-based security scoring** | 1 day | 🟡 **Planned for Sprint 21.** Replace additive Security Context dimension with a proportional multiplier model. Active incident + loaded code → score × 1.2. Confirmed inactive → score × 0.8. Industry-grade approach that scales context impact with existing severity. |
| **13** | **EPSS v4 retrain on real data** | 1–2 days | ⏸️ **Deferred to Post-MVP.** Retrain EPSS v4 on real (non-synthetic) Tenable scan aggregation data. Deferred per commander analysis. Requires real Tenable scan aggregation data. |
| **14** | **Multi-window labels** | 6 hrs | 🟡 **Planned for Sprint 22.** Replace single binary KEV label with 30/90/365d observation windows. Deferred from Sprint 21 — scoring formula must be locked first before changing ML target variable. |

---

## Post-MVP — Infrastructure & Platform

| # | Item | Description |
|---|---|---|
| **15** | Cloud deploy + HTTPS + CORS restriction | Docker, reverse proxy, DNS, TLS, restrict `allow_origins=["*"]` |
| **16** | Real Microsoft Sentinel integration | Replace synthetic with actual Azure Sentinel API |
| **17** | Real EDR/SIEM connectors | Defender, SentinelOne, CrowdStrike, Splunk |
| **18** | CMDB real integration | ServiceNow or iTop API replacement for stub |
| **19** | WASOC incident data | Replace 7-CVE advisories.py stub with live feed |
| **20** | RBAC / multi-user | Analyst vs. admin vs. viewer roles |
| **21** | MLflow experiment tracking | Model versioning, A/B testing, experiment registry |
| **22** | Email / Slack notifications | Webhook-driven alerting |
| **23** | PostgreSQL default deployment | Switch default from SQLite to PostgreSQL |
| **24** | `pytest-benchmark` + CI perf gates | Granular performance regression detection |
| **25** | DeepSeek V4 Flash Tier 2 provider | Additional LLM provider for fallback chain |

---

## Quick Start

```bash
cd backend && source .venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0
# Open http://localhost:8000
```

### Verification

```bash
just test   # 412 tests, 412 pass
just lint   # ruff check + format
just gate   # Full quality gate: lint → test → audit-all
```
