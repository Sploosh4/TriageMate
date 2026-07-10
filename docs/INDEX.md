# TriageMate — Documentation Index

> **For AI agents:** Start here. This file tells you what every document contains and whether it's trustworthy.

## Status Key
| Badge | Meaning |
|---|---|
| `CURRENT` | Up-to-date and authoritative — trust this |
| `OUTDATED` | Historical context, may contradict current state — read with caution |
| `ARCHIVED` | Preserved for reference, do not modify |

---

## Core Documents (read order for new AI agents)

| # | File | Status | Description |
|---|---|---|---|
| 1 | `planning/ROADMAP.md` | CURRENT | **Master status.** What exists, what's broken, what's next. Sprints 17, 18, 19 & 20 complete ✅. Start here. |
| 2 | `architecture/MVP_SCOPE.md` | OUTDATED | Sprint 1 scope boundaries. Many deferred items are now done. See caution banner. |
| 3 | `reference/AI_PROBLEMS.md` | CURRENT | Bug tracker. All historical issues resolved. |
| 4 | `archive/ml-implementation-plan.md` | ARCHIVED | → Replaced by `graphify_output/ml_inventory.md` (auto-generated, run `just graphify`) |

## Architecture

| File | Status | Description |
|---|---|---|
| `architecture/MVP_SCOPE.md` | OUTDATED | Scope authority from Sprint 1. Many deferred items now implemented. ROC-AUC figure updated to 0.9459. |
| `architecture/scoring-weights.md` | CURRENT | Scoring weight design — 7 dimensions (112-sum, clamped 0–100). Rationale, clamping, bands, demo CVE scores. Added Sprint 18. |
| `architecture/comparison-vs-described-system.md` | CURRENT | Maps each of 5 described system areas to actual implementation — identifies what was simplified, added onto, or completely changed. Generated 2026-07-10. |

## Planning

| File | Status | Description |
|---|---|---|
| `planning/ROADMAP.md` | CURRENT | Forward-looking roadmap. Sprints 17, 18, 19 & 20 complete ✅. Sprint 19 added shared config module, scheduled retraining triggers, NPZ column names, concept drift monitoring, scoring property tests, and seed data freshness check. Sprint 20 added multi-step agentic LLM, customizable risk multipliers, and safe PCA. |
| `planning/HANDOFF-2026-07-08.md` | CURRENT | Handoff document covering ML drift monitoring, Tier 2 LLM query coverage, network topology/Sentinel status, and stress testing status. Answers what was deferred post-MVP. |
| `planning/ai-doc-strategy-2026-07-07.md` | CURRENT | This consolidation plan — how and why docs were restructured. |
| `archive/file-consolidation-plan-2026-07-07.md` | ARCHIVED | Bookkeeper's consolidation proposals — superseded by current doc structure. See `docs/INDEX.md`. |

## Reference

| File | Status | Description |
|---|---|---|
| `reference/AI_PROBLEMS.md` | CURRENT | Bug tracker — all historical issues resolved. |
| `reference/xgboost-investigation-report.md` | CURRENT | Root cause analysis of XGBoost false-negative rate. ✅ All 8 fixes applied, model retrained 2026-07-08. |
| `archive/ml-implementation-plan.md` | ARCHIVED | → Replaced by `graphify_output/ml_inventory.md` (auto-generated, run `just graphify`) |
| `reference/hostname-standards.md` | CURRENT | WA government hostname conventions, data classification, department naming. |
| `backend/ml/README.md` | CURRENT | ML artifact index — lists active and pending ML components, lives with code. |

## Research

| File | Status | Description |
|---|---|---|
| `research/RESEARCH_FINDINGS.md` | OUTDATED | Strategic gap analysis from July 3. Some findings superseded by Sprint NEXT. See ROADMAP.md for current status. |
| `../backend/reports/intel/wa-gov-infrastructure-research.md` | CURRENT | WA Government ICT infrastructure research — 23 agencies, hostname synthesis rules, findings methodology (913 lines, 54 KB). Generated Sprint 14. |

## Guides

| File | Status | Description |
|---|---|---|
| `guides/WINDOWS_SETUP.md` | CURRENT | Windows 10/11 setup guide with troubleshooting. |

## Archive

| File | Status | Description |
|---|---|---|
| `archive/SPRINT_NEXT_PLAN.md` | ARCHIVED | Sprint NEXT detailed plan (merged into ROADMAP.md) |
| `archive/handoffs/SPRINT_9_HANDOFF.md` | ARCHIVED | Sprint 9 handoff — data supremacy. |
| `archive/sprints-1-6/*.md` | ARCHIVED | Sprint 1-6 handoffs, plans, team briefings. |
| `archive/ROADMAP-2026-07-09.md` | ARCHIVED | Sprint 1–16b roadmap — superseded by new forward-looking ROADMAP.md (9 July 2026). |

---

## Quick Reference: Which File for Which Question?

| Question | Read |
|---|---|---|
| What's the current state of the project? | `planning/ROADMAP.md` |
| What's broken? | `reference/AI_PROBLEMS.md` (all historical issues resolved) |
| What ML models exist and how do they work? | `graphify_output/ml_inventory.md` (auto-generated) |
| How do I train the model? | `planning/ROADMAP.md` §ML Models table or `backend/ml/` scripts |
| How do I retrain all ML models from scratch? | Use `just retrain-all` — see ROADMAP.md §Current State (ML Models table) |
| How do I set up on Windows? | `guides/WINDOWS_SETUP.md` |
| What WA gov conventions apply? | `reference/hostname-standards.md` |
| What data does the corpus contain? | `planning/ROADMAP.md` §Current State (Enrichment sources: 14 integrations) |
| What's the scoring engine logic? | `architecture/scoring-weights.md` (current) or `architecture/MVP_SCOPE.md` §2.5 (outdated) |
| What pipeline stages exist? | `planning/ROADMAP.md` §Current State (Pipeline stages table row) |
| Full file tree | `graphify_output/file_tree.md` (auto-generated) |
| ML models + training | `graphify_output/ml_inventory.md` (auto-generated) |
| Do inference and training feature columns match? | `graphify_output/feature_parity.md` (auto-generated) |
| How to generate synthetic data? | `backend/ml/generate_synthetic_data_v2.py` — `python -m ml.generate_synthetic_data_v2` |
| How to load research references? | `backend/scripts/load_research_refs.py` — `python -m scripts.load_research_refs` |
| What's in the WA gov infrastructure research? | `backend/reports/intel/wa-gov-infrastructure-research.md` |
| What are the 3 new Sprint 14 DB tables? | `docs/INDEX.md` §New Database Tables (Sprint 14 detail preserved here) |
| What is EPSS v4 and where does it fit? | Fallback model in Tier 1: v4 → v3 → v2 → v1 → heuristic rule engine. See ROADMAP.md §Current State (ML Models table: EPSS v4). |
| What is system name embedding? | Feature index 59: `system_category` (ordinal 0-8) replaces binary `has_known_system` in Pre-Tier. See `archive/ROADMAP-2026-07-09.md` §Sprint 14 for original detail. |

## New Database Tables (Sprint 14)

| Table | Rows | Purpose |
|---|---|---|
| `synthetic_assets` | 1,827 | Synthetic WA gov hostnames across 23 agencies — hostname, agency, environment, network zone, mission/wellbeing labels, blind holdout flag, research source refs |
| `synthetic_findings` | 777 | Host-to-vulnerability mappings with realistic exploitation likelihoods; used for EPSS v4 sector-aware training |
| `research_references` | 97 | WA government ICT research references — agency inventories, software profiles, hostname conventions, methodology citations |

## New Scripts (Sprint 14)

| Script | Command | Purpose |
|---|---|---|
| `backend/ml/generate_synthetic_data_v2.py` | `python -m ml.generate_synthetic_data_v2` | Generates 1,500–2,000 synthetic WA gov hostnames with probabilistic labels, blind holdout, and confidence scores; inserts into `synthetic_assets` |
| `backend/ml/generate_synthetic_findings.py` | `python -m ml.generate_synthetic_findings` | Generates host-to-vulnerability mappings with exploitation likelihoods for EPSS v4 training; inserts into `synthetic_findings` |
| `backend/ml/train_epss_v4.py` | `python -m ml.train_epss_v4` | Trains the EPSS v4 sector-aware substitution model from `synthetic_findings` data |
| `backend/scripts/load_research_refs.py` | `python -m scripts.load_research_refs` | Seeds or refreshes `research_references` table from embedded WA gov ICT research corpus |

## New Automation (Sprint 14)

| Command | Purpose |
|---|---|
| `just retrain-all` | Retrains all ML models from scratch: synthetic data → pre-tier → EPSS v4 |

## New ML Test Files (Sprint 16 — ML Monitoring Foundation)

| File | Purpose |
|---|---|
| `backend/tests/test_pretier_features.py` | Pre-Tier feature extraction unit tests |
| `backend/tests/test_pre_tier.py` | Pre-Tier model integration tests |
| `backend/tests/test_feature_parity_pretier.py` | Feature parity check between pre-tier training and inference |
| `backend/tests/test_feature_parity_epss.py` | Feature parity check between EPSS training and inference |
| `backend/tests/test_epss_substitutor.py` | EPSS substitution model unit/integration tests |
| `backend/ml/model_registry_pre_tier.json` | Pre-Tier model version registry (drift tracking, rollback) |
| `backend/ml/model_registry_epss.json` | EPSS model version registry (v1–v4 tracking, rollback) |

**Total test count:** 412+ tests (up from 142) — includes 5 new test files for Pre-Tier and EPSS monitoring, plus 3 drift test files (XGBoost, EPSS, Pre-Tier) from Sprint 18, plus scoring property tests, seed verification, scheduler, NPZ metadata, and concept drift tests from Sprint 19, plus 65 new tests from Sprint 20 (agent tools, admin API, PCA).

## Sprint 17 — ✅ Complete (Security Telemetry, Network Context & Panel 5)

| Component | Files | Purpose |
|---|---|---|
| **Security Telemetry** | `backend/integrations/synthetic_telemetry.py` | Generates realistic Sentinel/EDR telemetry (incidents, alerts, process evidence) with threat scores for demo CVEs. Ingest pipeline calls this to populate `telemetry_json`. |
| **Network Context** | `backend/integrations/network_context.py` | Produces network blast-radius scores and peer topology from `synthetic_assets` table. Ingest pipeline calls this to populate `network_context_json`. |
| **Panel 5 Frontend** | `frontend/index.html`, `frontend/js/components/caseView.js`, `frontend/css/triagemate.css` | New case-view panel for security telemetry (Sentinel incidents, EDR alerts, process evidence) and network context (blast radius gauge, zone display, peer counts). |
| **7th Scoring Dimension** | `backend/scoring.py` | "Security Context" (max 5): composite of telemetry threat score (×3) and network blast radius (×2), clamped to 0–5. |
| **Score Contract** | `backend/routers/models.py` (baseline), `backend/tests/test_model_versions.py` (assertion) | Updated expected scores: **98/91/73/66/58/44/26** (Sprint 17+ recalculation, verified against `routers/models.py:89`). |

## Sprint 18 — ✅ Complete (Quick Wins + Monitoring)

| Component | Files | Purpose |
|---|---|---|
| **NVD ≥21 References Rule** | `backend/pipeline/tier_zero.py` | CVEs with 21+ NVD references auto-resolve as `very_critical` at Tier 0. 9.5× baseline KEV rate. |
| **CWE-Stratified EPSS Thresholds** | `backend/pipeline/tier_zero.py` | Tier 0's `LOW_EPSS_THRESHOLD` is now CWE-aware — different CWE families get different thresholds. |
| **Pre-Tier RF Drift Monitoring** | `backend/analysis/drift.py`, `backend/tests/test_drift_pretier.py`, `backend/routers/drift.py` | PSI-based drift endpoint for Pre-Tier model (60-dim). DB migration, pipeline capture, reference distributions. |
| **EPSS Drift Monitoring** | `backend/analysis/drift.py`, `backend/tests/test_drift_epss.py`, `backend/routers/drift.py` | PSI-based drift endpoint for EPSS fallback models (37/22-dim). Same pattern as Pre-Tier drift. |
| **XGBoost Drift Endpoint** | `backend/analysis/drift.py`, `backend/tests/test_drift_ml.py` | ML-level drift endpoint for Tier 1 XGBoost (419-dim). |
| **General Drift Endpoint** | `backend/analysis/drift.py`, `backend/tests/test_drift.py`, `backend/routers/drift.py` | Pipeline-level drift stats (total audited, tier routing, feature drift). |
| **Bonus Items** | Various | CWE_EPSS_THRESHOLDS coverage extended, CWE-stratified KEV threshold, `threshold_info.json` endpoint, `docs/architecture/scoring-weights.md` |

**Sprint 18 new test files:**
- `backend/tests/test_drift.py` — General drift endpoint tests
- `backend/tests/test_drift_ml.py` — ML drift endpoint + PSI computation tests
- `backend/tests/test_drift_epss.py` — EPSS drift endpoint tests
- `backend/tests/test_drift_pretier.py` — Pre-Tier drift endpoint tests

## Sprint 19 — ✅ Complete (Config + Retraining + Closing the Loop)

| Component | Files | Purpose |
|---|---|---|
| **Shared Config Module** | `backend/pipeline/config/__init__.py`, `backend/pipeline/config/thresholds.py`, `backend/pipeline/config/scoring.py`, `backend/pipeline/config/feature_names.py` | Domain-grouped config package. Single source of truth for all shared business-logic constants — thresholds, scoring weights, feature names, drift PSI thresholds. Centralize-vs-local rules documented in `__init__.py` docstring. |
| **Scheduled Retraining Triggers** | `backend/scheduler.py`, `backend/main.py` | Drift-triggered and time-triggered model retraining. Lock mechanism prevents concurrent retrains. `GET /api/system/retrain-status` endpoint, configurable `RETRAIN_DRIFT_THRESHOLD` and `RETRAIN_INTERVAL_HOURS` env vars. |
| **NPZ Column Names** | `backend/ml/train_xgboost.py` | `feature_names` metadata (419 dims: 35 tabular + 384 SBERT) added to `training_data.npz`. Enables graphify column correspondence verification between training output and inference input. |
| **Concept Drift Monitoring** | `backend/routers/drift.py`, `backend/models.py` | `GET /api/drift/concept` for prediction distribution tracking, `POST /api/feedback/{id}` for ground-truth feedback (API stubs, schema deferred to Sprint 20), `GET /api/drift/accuracy` stub. |
| **Bonus A: Scoring Property Tests** | `backend/tests/test_scoring.py` | Property-based tests covering edge cases: all-zero, all-max, negative inputs, clamping, band boundaries. |
| **Bonus F: Seed Data Freshness Check** | `backend/scripts/verify_seed_scores.py`, `backend/tests/test_verify_seed_scores.py` | `verify_seed_scores.py` script verifies seed data scores match canonical contract from `test_model_versions.py`. Integrated via `just verify-seeds`. |

**Sprint 19 new test files:**
- `backend/tests/test_scheduler.py` — Retraining scheduler tests (drift check, lock mechanism, status endpoint, no-drift-no-action)
- `backend/tests/test_npz_metadata.py` — NPZ feature_names dimension and backward compatibility tests
- `backend/tests/test_verify_seed_scores.py` — Seed score verification tests (detects drift, passes when correct)

## Sprint 20 — ✅ Complete (Agentic LLM + Customizable Weights + Safe PCA)

| Component | Files | Purpose |
|---|---|---|
| **Multi-Step Agentic LLM** | `backend/pipeline/tier_2/tools.py`, `backend/pipeline/tier_2/agent.py`, `backend/pipeline/tier_2/__init__.py` | Transformed Tier 2 from single-shot to multi-step agent with 12 read-only tools (KEV, NVD, EPSS, CWE, MITRE, network, telemetry, advisories, ExploitDB, Metasploit, CMDB, RAG). 15-step limit, $0.50 cost budget per CVE. Feature-flag gated (`TRIAGEMATE_AGENT_ENABLED=false`). Graceful fallback to single-shot. 31 new tests. |
| **Customizable Risk Multipliers** | `backend/routers/admin.py`, `frontend/js/components/adminSettings.js`, `backend/pipeline/config/scoring.py` | Scoring weights exposed via optional `scoring_weights.json` override file (gitignored, created at runtime). Admin API endpoints: `GET /api/admin/config/scoring`, `PUT /api/admin/config/scoring`, `POST /api/admin/config/scoring/reset`. Frontend admin settings page with 7 sliders and live demo CVE score preview. Validation rules: weights ≥1 ≤100, sum ≥100. 18 new tests. |
| **Safe PCA Dimensionality Reduction** | `backend/ml/train_xgboost.py`, `backend/ml/xgboost_predictor.py`, `backend/ml/encoder.py` | PCA re-introduced with correct train/test hygiene — fitted on training split only. 384 SBERT dims reduced via `n_components=0.95` (retains ~50–80 dims). Saved to `pca_model.pkl` (generated at training time). Graceful fallback to full 384-dim if PCA model missing. ROC-AUC guardrail: ≥0.9359 (0.01 below baseline 0.9459). 16 new tests (embedded in `test_ml_pipeline.py`). |

**Sprint 20 new/modified test files:**
- `backend/tests/test_tier2_agent.py` — Tool unit tests + agent loop tests (KEV, NVD, EPSS, step limit, cost budget, feature flag, fallback) — 633 lines
- `backend/tests/test_admin.py` — Admin config API tests (GET/PUT/POST, validation, auth, persistence) — 356 lines
- `backend/tests/test_ml_pipeline.py` — PCA tests added (fit on train only, save/load, transform consistency, no leakage) — 6 new test methods

## Graphify — Auto-Generated Knowledge Artifacts

These files are regenerated on demand with `just graphify`. They are always current with the codebase.

| File | Description |
|---|---|
| `graphify_output/file_tree.md` | Complete annotated directory tree (299 entries, auto-generated) |
| `graphify_output/api_deps.md` | Python import dependency map (421 dependencies, auto-generated) |
| `graphify_output/ml_inventory.md` | Canonical ML model and script inventory |
| `graphify_output/knowledge_graph.json` | Structured CVE↔hostname↔CWE knowledge graph |
| `graphify_output/feature_parity.md` | Tabular feature parity check (inference vs training vs inventory) |

---

## Notes

**Archive files:** Files under `docs/archive/` (sprint handoffs S1–S6, superseded plans) are preserved for historical context but are not listed in this index. They are **ARCHIVED** — do not use as reference for current state.

**Root-level `.md` symlinks:** Files like `ROADMAP.md`, `AI_PROBLEMS.md`, etc. at the project root are symlinks into `docs/`. Always read the canonical copy under `docs/`.

**Auto-generated files:** Files under `graphify_output/` are regenerated with `just graphify`. Their freshness depends on the last run. If they look stale, run `just graphify` to regenerate.
