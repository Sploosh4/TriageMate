# TriageMate — Roadmap

> **Status: CURRENT** (14 July 2026)
> 
> Previous roadmap archived to `docs/archive/ROADMAP-2026-07-09.md` (Sprints 1–16b complete).

---

## Current State

| Metric | Value |
|---|---|
| Tests | 457 pass, 0 fail, 1 skipped |
| Open remediation work | 7 Sprint 29 issues (#58–#64) |
| Sprints completed | 17, 18, 19, 20, 21, 22, 23, **24**, **25**, **26**, **27**, **28** |
| Current sprint | **Sprint 30 — Documentation Cleanup** 🔴 In Progress |
| Pipeline stages | Pre-Tier → Tier 0 → Tier 1 → Tier 2 → Tier 3 (Human Review) |
| Enrichment sources | 14 integrations (NVD, OSV, OTX, ExploitDB, Metasploit, Tenable, GreyNoise [deprecated], CMDB [stub], Advisories [stub], MITRE, CWE classifier, Demo generator, **Synthetic Telemetry**, **Network Context**) |
| Demo rows | 7 CVEs, scores 99/97/74/91/82/97/80 (±3 tolerance) |
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
| **4** | **7th Scoring Dimension** | ✅ Done | "Security Context" (max 5, total weight 112, later reduced to 107 in Sprint 21). Composite: threat_score × 3 + blast_radius × 2. |
| **5** | **Panel 5 Frontend** | ✅ Done | Full-width security context panel below scoring breakdown. Two-column telemetry grid + blast radius bar. |
| **6** | **Seed data recalculated** | ✅ Done | New scores: 99/97/74/91/82/97/80. Further refined in Sprint 23 (Score Reconciliation) to correct for pipeline discrepancies. Synthetic assets populated. |

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
| **—** | **Bonus D: Scoring weight documentation** | 1 hr | ✅ Done | `docs/architecture/scoring-weights.md` — full weight design rationale, 112-sum at the time (later 107-sum), clamping. |

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

---

## Sprint 20 — ✅ Complete (Agentic LLM + Customizable Weights + Safe PCA)

*Executed 10 July 2026. See `.opencode/plans/2026-07-10-sprint-20-planning.md` for full detail.*

| # | Item | Status | Description |
|---|---|---|---|
| **1** | **Multi-Step Agentic LLM** | ✅ Done | Transformed Tier 2 from single-shot to multi-step agent with 12 tools (KEV, NVD, EPSS, CWE, MITRE, network, telemetry, advisories, ExploitDB, Metasploit, CMDB, RAG). 15-step limit, $0.50 cost budget, feature-flag gated (`TRIAGEMATE_AGENT_ENABLED=false`). Graceful fallback to single-shot. 31 new tests. |
| **2** | **Customizable Risk Multipliers** | ✅ Done | Scoring weights exposed via `scoring_weights.json` override. Admin API endpoints (`GET/PUT /api/admin/config/scoring`, `POST /reset`). Frontend admin settings page with 7 sliders and live demo CVE score preview. 18 new tests. |
| **3** | **Safe PCA Dimensionality Reduction** | ✅ Done | PCA re-introduced with correct train/test hygiene — fitted on training split only. 384 SBERT dims reduced via `n_components=0.95`. Saved to `pca_model.pkl`. Graceful fallback if PCA model missing. 16 new tests. |

---

## Sprint 21 — ✅ Complete (Multiplier-Based Security Scoring + Quick Wins)

*Executed 10 July 2026. See `.opencode/plans/2026-07-10-sprint-21.md` for full detail.*

| # | Item | Status | Description |
|---|---|---|---|
| **1** | **Multiplier-Based Security Scoring** | ✅ Done | Replaced additive Security Context (0-5 pts) with proportional multiplier (1.20/1.10/1.00/0.85/0.70). Scoring weights reduced from 7 to 6 dimensions (total 107). Frontend updated to show context multiplier. Backward-compat `security_context=0` field retained. |
| **—** | **Bonus A: Config API** | ✅ Done | Read-only `GET /api/config` exposing thresholds, scoring weights, multiplier config, and feature names. |
| **—** | **Bonus B: Drift Webhook** | ✅ Done | POST drift alerts to configured webhook URL when PSI ≥ 0.10. Rate-limited to once per 6 hours per model. |

---

## Sprint 22 — ✅ Complete (Multi-Window KEV Labels + Infrastructure)

*Executed 10 July 2026.*

| # | Item | Status | Description |
|---|---|---|---|
| **1** | **Multi-Window KEV Labels** | ✅ Done | Replaced binary KEV label (0/1) with 5-class multi-window labels (0=not KEV, 1=≤30d, 2=31-90d, 3=91-365d, 4=>365d). XGBoost switched to `multi:softprob` with `num_class=5`. Predictor returns `exploitation_probability` (any-KEV prob) + `window_probabilities` for transparency. Full backward compatibility with Tier 1 and scoring engine. |
| **2** | **CI Benchmark Gates** | ✅ Done | Added pytest-benchmark for scoring calculator (3 benchmarks). CI runs on main branch with 10% regression threshold. `just bench` and `just bench-check` recipes. |
| **3** | **Alembic Schema Catch-Up** | ✅ Done | Created migration 009 adding `pre_tier_features` and `epss_features` columns to both tables. |
| **4** | **Model Registry Rollback API** | ✅ Done | `POST /api/models/xgboost/rollback?version=<tag>` with lock mechanism, validation, cache invalidation. |

---

## Sprint 23 — ✅ Complete (Score Reconciliation + Bug Hunt)

*Executed 11 July 2026. See `.opencode/plans/2026-07-11-sprint-23.md` for full detail.*

| # | Item | Status | Description |
|---|---|---|---|
| **0** | **Discovery — Determine Canonical Scores** | ✅ Done | Mapped 7 conflicting score locations, ran live pipeline, identified root causes (Sprint 21 multiplier not applied to seed data, verify script missing `vulnerable_code_loaded` param, rows 5–7 manually overridden). Established canonical contract: `[99, 97, 74, 91, 82, 97, 80]`. |
| **1** | **Code Fixes** | ✅ Done | Fixed CI benchmark branch bug (`main`→`master`). Exposed `threshold_info.json` via `GET /api/config`. Corrected seed_data scores and restructured `scoring_weights_json`. Updated models.py baseline, verify script, and test assertions. |
| **2** | **Gated Bug Hunt** | ✅ Done | 2 rounds of automated + manual bug sweep. 7 bugs fixed: seed score drift (HIGH), pytest-benchmark fixture, fuzzed test hang, import hygiene, multiplier edge cases, lint errors, dead feature documentation. |
| **3** | **Documentation Cleanup** | ✅ Done | Updated INDEX.md (added Sprints 21/22), ROADMAP.md, scoring-weights.md, comparison-vs-described-system.md. Created retroactive Sprint 22 plan file. |
| **4** | **Gated Bookkeeping** | ✅ Done | 2 rounds of freshness verification. All 9 known issues resolved. |
| **5** | **Final Quality Gate & Commit** | ✅ Done | `just gate` passed (lint → test → verify-seeds → graphify → audit-all). 449 tests, 0 fail. API verified. 4 additional bugs caught and fixed during gate. Committed as `bb9a25e`. |

---

## Sprint 24 — ✅ Complete (GitHub-Native Work Tracking for AI Workflow)

*Executed 11 July 2026. See `.opencode/plans/2026-07-11-sprint-24.md` for full detail. GitHub verification completed 2026-07-11.*

| # | Item | Status | Description |
|---|---|---|---|
| **0** | **Design** | ✅ Done | Designed label taxonomy (25 labels: 9 defaults + 16 custom), 4 issue templates, milestone hierarchy (11 milestones), archive directory structure. |
| **1** | **GitHub Infrastructure** | ✅ Done | Created 25 labels (9 defaults + 16 custom), 11 milestones, 4 issue templates + config.yml, set repo description + 6 topics. Wiki and Project Board deferred per AI-utility analysis. |
| **2** | **Backfill** | ✅ Done | Created closed Issues for all 31 resolved AI_PROBLEMS.md entries, backlog item, and 5 Sprint 24 tracking issues. 37 total issues created. Past sprint vanity issues explicitly excluded. |
| **3** | **Archive & Manifest** | ✅ Done | Archived sprint plans to `archive/github-migration/` (no doc duplication), created migration manifest, created `.opencodeignore` to exclude archive from AI tooling, updated INDEX.md and ROADMAP.md to reference Issues+Milestones. |
| **4** | **Verification** | ✅ Done | Gated verification loop completed. All labels, milestones, issues, templates, archive, symlinks verified. Bookkeeper freshness pass clean. |
| **5** | **Final Gate & Commit** | ✅ Done | Full quality gate (lint → test → graphify → audit), git commit `ed1821e` with descriptive message, pushed to remote. |

---

## Sprint 25 — ✅ Complete (GitHub-Native Workflow Operationalization)

*Executed 11 July 2026. See `.opencode/plans/2026-07-11-sprint-25.md` for full detail.*

| # | Item | Status | Description |
|---|---|---|---|
| **0** | **Audit Current State** | ✅ Complete | Verified Sprint 24, tested subagent `gh` access (Level 5/5), inventoried 16 project + 2 global skills |
| **1** | **Sprint 25 Infra** | ✅ Complete | Created 7 GitHub Issues (#40-#46), updated ROADMAP.md |
| **2** | **Core Agent Updates** | ✅ Complete | Updated AGENTS.md + 5 agent files for GitHub-native conditional-access workflow |
| **3** | **Skill File Updates** | ✅ Complete | Updated 14 of 15 project skills; updated github-basics and archived-files (under 25 words) |
| **4** | **Capability Test** | ✅ Complete | Validated Level 5/5 branch/PR/merge workflow via PR #47 |
| **5** | **Verification** | ✅ Complete | Bookkeeper, cross-file checks |
| **6** | **Quality Gate & Commit** | ✅ Complete | `just gate`, commit, push |

---

## Sprint 26 — ✅ Complete (Feature Contract Enforcement)

*Executed 12 July 2026. Commits `586caac`, `5b01c13`. See `.opencode/plans/2026-07-12-sprint-26.md` for full detail.*

| # | Item | Status | Description |
|---|---|---|---|
| **0** | **Pre-Flight Diagnostics** | ✅ Complete | Established exact baseline — run graphify, audit-features, inventoried all feature-defining files |
| **1** | **Fix Existing Discrepancies** | ✅ Complete | Fixed 5 real bugs: CIA defaults (predictor + ingest_helpers + parity_check), patch_available, domain_joined, reference_count→nvd_reference_count, docstring stale count, parity_check hardcoded defaults sync; rebuilt corpus + retrain |
| **2** | **Feature Contract Test** | ✅ Complete | Created `test_feature_contract.py` with 6 tests: canonical registry completeness, training compliance, inference compliance, default value consistency, NPZ column match, extra keys documentation |
| **3** | **CI Integration** | ✅ Complete | Added `just check-feature-contract` recipe, wired into `just gate`; CI runs contract tests via existing `pytest tests/` suite |
| **4** | **Verification** | ✅ Complete | Full test suite, quality gate, graphify parity 0 mismatches, seed verification, bookkeeper pass |

---

## Sprint 27 — ✅ Complete (Bug Fix Sprint)

*Executed 13 July 2026. See `.opencode/plans/2026-07-13-bug-fix-sprint.md` for full detail. Merged via PR #50.*

| # | Phase | Status | Description |
|---|---|---|---|
| **1** | **Security & Authentication** | ✅ Complete | Auth added to unprotected router endpoints, frontend XSS fixed (caseView.js), password hash leak removed, agent hostname confusion resolved |
| **2** | **Agentic Tier-2 Safety** | ✅ Complete | Neutral-fallback routing, bounded agent input/tool calls, response validation, agent_enabled flag fix, conflict value normalization |
| **3** | **ML Correctness** | ✅ Complete | CVE ID retention in train path, multi-class ensemble std crash fix, encoder None guard, deterministic EPSS noise, encoding default alignment, deterministic reference distributions, NVD null-cve guard |
| **4** | **Scoring & Data Integrity** | ✅ Complete | Hardcoded patch status fix, analytics columns added to DDL, security_context_contribution migration, migration defaults/type fixes, resolved_at added to archive |
| **5** | **Robustness & Resource Protection** | ✅ Complete | Bare except fix in ALTER TABLE, scheduler TOCTOU race fix, OSV JSONDecodeError catch, Tenable empty IPv4 guard, HTTPError dead code fix, CWE cache bounding, temp directory leak fix, connection leak fix |
| **6** | **Pipeline Robustness** | ✅ Complete | Agent cost budget documented, atomic scoring_weights.json writes, PRE_TIER_FEATURE_NAMES populated |
| **7** | **Frontend Polish** | ✅ Complete | Screen fade-out animation fixed, reviewQueue state management fixed, 204 No Content crash fixed, dead code removed |

---

## Sprint 28 — ✅ Complete (Evidence and ML Readiness)

*Executed 14 July 2026. See `.opencode/plans/2026-07-14-sprint-28.md` and GitHub Milestone #12 for full detail.*

| # | Item | Status | Description |
|---|---|---|---|
| **1** | **Phase 7.5 — Keydown Listener Investigation** | ✅ Complete | Listener accumulation confirmed under auth flow, guard flag added, JSDOM regression test written |
| **2** | **Phase 7.6 — Scoring Weight Zero Decision** | ✅ Complete | Zero NOT supported; minimum of 1 retained as intentional design; decision record at `docs/architecture/weight-zero-decision.md` |
| **3** | **Phase 8 — Evidence-Needed Investigation Pass** | ✅ Complete | All 23 items investigated; 7 tracked reports in `backend/reports/investigations/` |
| **4** | **Documentation & Tracking Update** | ✅ Complete | ROADMAP updated, Sprint 27 recorded complete, INDEX.md fixed, comparison doc marked OUTDATED |
| **5** | **ML Retraining Decision Gate** | ✅ Complete | Decision: DO NOT RETRAIN — three blocking issues identified (degenerate val/test splits, binary-vs-multi-class registry mismatch, unreliable baseline metrics). As of Sprint 30, **2 of 3 blocking issues resolved**: degenerate splits fixed by the point-in-time split policy (PR #68) and registry metadata corrected (3c). Only establishing a reliable baseline (3d) remains pending authorization. |

## Sprint 29 — ✅ Complete (Investigation Findings Remediation)

*Started 14 July 2026. See `.opencode/plans/2026-07-14-sprint-29.md` and GitHub Issues #58–#64 for full detail.*

| # | Item | Status | Description |
|---|---|---|---|
| **1** | **Product/Security Decisions** | ⏳ Planned | rag_query hostname binding (PIPE-HIGH-5) + /api/config exposure (ROUTER-LOW-1) |
| **2a** | **Webhook malformed-JSON handling** | ✅ Done | ROUTER-LOW-5 — malformed Tenable JSON now returns HTTP 400 with regression coverage (`060df23`). |
| **2b** | **Test isolation / shared-state races** | ✅ Done | TEST-CRIT-1, TEST-MED-1/2, and TEST-LOW-3/4/6 isolation fixes merged in PR #65; the complete Python test matrix passed. |
| **2c** | **Seed-data idempotency** | ✅ Done | INFRA-HIGH-2 — cross-database unique constraint, conflict-safe insert, migration 013, and regression coverage (`88a4d0c`). |
| **2d** | **OTX throttling handling** | ✅ Done | INT-MED-3 — Retry 429 responses with `Retry-After` support and exponential backoff; safe fallback after retry exhaustion. |
| **2e** | **Rate-limit policy and implementation** | ✅ Done | CORE-MED-5 and ROUTER-LOW-8 — slowapi per-route limits, CI-installed dependency, and threshold-file status distinction. Merged in PR #66. |
| **3** | **ML Data-Readiness Work** | ✅ Complete | Point-in-time split policy implemented via PR #68 (split-before-filter with primary/prospective/censored cohorts). Fresh gather validated healthy splits: Train 69,223 (0.93% KEV), Val 20,144 (0.99% KEV), Test 26,766 (0.49% KEV). Split degeneracy (3a) resolved; registry metadata mismatch (3c) resolved. Baseline (3d) remains pending a deliberate authorization — not blocked, deferred. Do **not** retrain until baseline is established. |

---

## Later — Medium-Term Engineering

| # | Item | Effort | Description |
|---|---|---|---|
| **8** | **Scheduled retraining** | — | ✅ **Completed in Sprint 19** (Item 2) — Retraining triggers, lock mechanism, status endpoint implemented. |
| **9** | **Concept drift monitoring** | — | ✅ **Completed in Sprint 19** (Item 4) — Prediction distribution tracking, ground-truth API stubs, accuracy endpoint. |
| **11** | **Shared config module** | — | ✅ **Completed in Sprint 19** (Item 1) — `backend/pipeline/config/` package created. |
| **12** | **Multiplier-based security scoring** | — | ✅ **Completed in Sprint 21** (Item 1) — Replaced additive Security Context with proportional multiplier (1.20/1.10/1.00/0.85/0.70). Total weight reduced to 107. |
| **13** | **EPSS v4 retrain on real data** | 1–2 days | ⏸️ **Deferred to Post-MVP.** Retrain EPSS v4 on real (non-synthetic) Tenable scan aggregation data. Deferred per commander analysis. Requires real Tenable scan aggregation data. |
| **14** | **Multi-window labels** | — | ✅ **Completed in Sprint 22** (Item 1) — Replaced binary KEV label with 5-class multi-window labels (0=not KEV, 1=≤30d, 2=31-90d, 3=91-365d, 4=>365d). |

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
| **24** | `pytest-benchmark` + CI perf gates | Granular performance regression detection | ✅ **Completed in Sprint 22** (Item 2) — `just bench` and `just bench-check` recipes, CI benchmark step with 10% regression threshold. |
| **25** | DeepSeek V4 Flash Tier 2 provider | Additional LLM provider for fallback chain |

---

## File Placement Policy

| Subagent output | Destination |
|---|---|
| Sprint plan | `.opencode/plans/YYYY-MM-DD-sprint-N.md` |
| Audit report | `backend/reports/audits/<name>.md` |
| Bookkeeping report | `backend/reports/bookkeeping/<name>.md` |
| Intel/research report | `backend/reports/intel/<name>.md` |
| Permanent documentation | `docs/<category>/<name>.md` |
| Everything else | Ask the commander |

---

## Quick Start

```bash
cd backend && source .venv/bin/activate
uvicorn main:app --reload --host 0.0.0.0
# Open http://localhost:8000
```

### Verification

```bash
just test   # complete suite (fuzz test skipped)
just test full=true   # complete suite, including fuzz testing
just lint   # ruff check + format
just gate   # full gate with a 10-CVE calibration sample
just gate full=true   # full gate with the full calibration audit + fuzz testing
```
