# Chapter 16: MVP Roadmap and Future

**Target:** 1500–3000 words · Self-contained · Podcast-script style

---

You have read fifteen chapters and now you know TriageMate inside out — the architecture, the database, the four-tier pipeline, the scoring engine, the ML models, the LLM integration, the external data sources, the frontend, the deployment. Now comes the honest question: what is actually *done*, and what is still *coming*?

This chapter is the roadmap and the retrospective. Nine sprints of work, item by item, followed by the next few sprints and the features that are explicitly *not* on the roadmap — because they do not serve the mission.

---

## Recap of What Is Done — Nine Sprints

### Sprint 1 — Application Scaffolding

Everything built from scratch. FastAPI backend on Python 3.11. SQLite database for development. Pydantic models for validation. The scoring engine launched with five dimensions: CVSS severity (40 points), EPSS probability (20 points), asset criticality (20 points), exposure and access complexity (15 points), and patch availability (5 points). That five-dimension structure has never needed revision — it was one of the earliest design decisions and it has held stable through every sprint.

The four-tier pipeline was sketched: Pre-Tier (stub), Tier 0 deterministic rules, Tier 1 XGBoost, Tier 2 LLM (stub). Three core API endpoints: `/api/queue` returns the prioritised queue, `/api/case/{id}` returns the full tier outputs for a vulnerability, `/api/ingest` accepts new vulnerabilities and pushes them through the pipeline. A scheduler and audit table were stubbed for future use.

The frontend is a single-page application with four screens — Queue, Case, Review Queue, Drift Dashboard — all wireframes with hard-coded data at this point. Seed data was seven rows designed to exercise different scoring paths. Verification criteria: all seven rows scored within ±3 of expected values [94, 87, 71, 55, 63, 41, 22]. Sprint 1 passed its gate cleanly.

### Sprint 2 — Cloud LLM + RAG

Real LLM integration — OpenAI, Anthropic, or Together — with a force-reflection prompt that instructs the LLM to reason step by step before producing a score override, preventing surface-level pattern matching. A backup provider chain: if the primary is rate-limited or down, fall through to the next provider; if all fail, fall back to a hard-coded `KNOWN_CONFLICTS` dictionary.

The vector store was built with LanceDB. Nine seed documents were embedded via Sentence-BERT (all-MiniLM-L6-v2, 384 dimensions). RAG context injection in Tier 2 retrieves similar past cases and injects them into the LLM prompt, giving the model concrete examples to reason from. Prompt caching economics were analysed — cached prompts cost roughly 50% less. Cost tracking logs every LLM call with token counts, provider, model, and estimated USD cost.

### Sprint 3 — XGBoost Model Fix

The most painful and rewarding sprint. Three bugs fixed. The ensemble variance DMatrix bug caused miscalculated tree disagreement — the model reported high confidence when individual trees disagreed. The Platt calibration fix removed `cv="prefit"`, which was incorrect for train-calibrate splits. The PCA data leakage fix removed PCA from the training pipeline — it was being fitted *before* the train-test split, artificially inflating test metrics. Version 2.5 eliminated PCA entirely; XGBoost handles feature importance internally.

Temporal bias fixes had three parts: chronological splits (train on older data, test on newer data), point-in-time labels (exploitation outcome based on what was known at observation time, not today), and a 365-day observation window for fair assessment. Results: ROC-AUC improved from 0.9677 to 0.9946. The model generalised to future holdout data far better than the original.

### Course Correction — Eleven Items

Structured JSON logging with request-scoped correlation IDs. Global exception handler with consistent error responses. Graceful startup degradation — the app starts in a limited state if non-critical subsystems fail. Centralised `config.py` with validation and defaults. Test suite rewritten with isolated databases, deterministic seed data, and mocked external services.

### Sprint 4 — Pre-Demo Hardening

Nine items focused on demo reliability. Pipeline no longer crashes on malformed input — missing CVSS gets a default, bad LLM output gets a fallback. Demo row verification automated with a script that compares actual to expected scores. Edge case handling for missing CVE IDs, duplicate CVEs, impossible CVSS scores, and unknown assets.

### Sprint 5 — Demo Data Generator

Seventeen items. A demo data generator with configurable scenarios — health-sector breach, critical infrastructure, routine patching, and mixed. A Tenable CSV parser for importing real scan output. Batch ingest with progress reporting via task ID. Clear and resolve endpoints for resetting demo state, rate-limited to prevent accidents during live demos.

### Sprint 6 — Production Hardening

PostgreSQL compatibility layer with three components: `_PGCompatRow` wraps rows for PostgreSQL-safe operations, `_PGCursor` provides a unified iterator, `_PGConnection` abstracts connection management. Dual-dialect DDL so every `CREATE TABLE` works on both SQLite and PostgreSQL, auto-selected at startup. Optional JWT authentication with middleware that validates tokens and attaches user identity for audit logging. Centralised `.env` configuration with sensible defaults.

### Sprint 7 — Operations Foundation

Docker multi-stage build — first stage installs dependencies and downloads model weights, second stage copies only application code. Docker Compose with three services: API server, PostgreSQL (optional), and scheduled task runner with health checks and volume mounts. Structured JSON logging compatible with ELK and Loki. Health endpoint at `/api/health` returning database status, ML model load status, LLM provider status, vector store status, and uptime. Background scheduler using APScheduler for daily low-severity re-checks and audit sampling.

### Sprint 8 — Feature Field Enrichment

All 37 feature fields now filled with real distributions — previously 18 were hard-coded constants with zero importance in the XGBoost model. Three new integrations: OSV.dev for open-source vulnerability data, ExploitDB CSV parsing for exploit-to-CVE mapping, and Metasploit module checks. Four new data pipeline scripts: `fetch_nvd_corpus.py`, `refresh_caches.py`, `build_training_corpus.py`, `build_vendor_index.py`, and `build_cwe_hierarchy.py`.

### Sprint 9 — Data Supremacy

The data corpus numbers: 186,102 NVD CVEs, 344,852 EPSS scores, 1,631 KEV entries, 47,089 ExploitDB entries, 17,100 vendors indexed. A new ML exploitation contribution dimension added (migration 005). Training data v2 generated — 186,102 feature vectors, 68 columns, all real distributions, temporal bias fixes applied. The XGBoost retrain was deferred to Sprint NEXT because the training pipeline needed minor adjustments for the expanded feature set.

---

## What Is Coming — Sprint NEXT

### Item 1 — XGBoost Retrain

The single highest-impact improvement available. The current model was trained with 18 hard-coded zero-importance features — effectively running on 19 features, some with questionable distributions. The retrain uses `training_data_v2.npz` — 186,102 records with 67 features, every one populated with real data from NVD, EPSS, KEV, and ExploitDB. Command:

```bash
python -m ml.train_xgboost --train --data-file ml/training_data_v2.npz
```

Verification: all seven demo rows within ±3 of expected scores [94, 87, 71, 55, 63, 41, 22], and all 37 automated tests passing. The new model captures real variance across all 67 features — CWE depth, vendor prevalence, and exploit maturity now contribute to predictions. The ROC-AUC should improve marginally, but more importantly the calibration will be more reliable.

### Item 2 — Pre-Tier RF Activation

The Pre-Tier stage currently uses a dictionary-based hostname lookup (`KNOWN_TAGS`). This fails for unknown assets. An already-trained RandomForest model (MultiOutputClassifier, 150 trees, 55 features) is stored at `ml/models/pretier_model.pkl`. Train on SMOTE-augmented data from 31 real hosts. Activation: replace the dict with the model as primary classifier, keep dictionary as fallback for predictions below 0.7 confidence. Verify all demo rows still produce expected classifications.

### Item 3 — EPSS Substitution Retrain

The 344,852 real EPSS scores are loaded in `epss_cache.json`. Retrain the XGBRegressor substitution model on actual scores instead of synthetic rule-engine mimics. Features are the eight CVSS v3.1 subscores. Expected R² improvement from ~0.72 to ~0.85. Block lifted — data is available, script is ready.

### Item 4 — Rate Limiting Configuration

Token bucket parameters exposed as environment variables: `RATE_LIMIT_INGEST_PER_MINUTE`, `RATE_LIMIT_DEMO_PER_MINUTE`, `RATE_LIMIT_CLEAR_PER_MINUTE`. Per-path configuration prevents scanner floods by isolating ingest, queue, and health endpoint limits.

### Items 5–8 — Already Completed

Drift Dashboard: frontend screen with score distribution plots, calibration curve, ROC-AUC trend, and cluster analysis, served by `/api/drift`. Human Review queue: `/api/review/queue` endpoint returning vulnerabilities needing manual inspection with LLM reasoning attached. Alembic migrations: five schema migrations covering Sprint 1 through Sprint 9, auto-applied in production.

---

## Sprint NEXT+ — Operational Hardening

Model rollback mechanism: dated model filenames, `--rollback` flag in training script, human-readable training logs with dataset fingerprint, hyperparameters, evaluation metrics, and git commit hash.

Cache freshness in health endpoint: add `kev_last_refresh`, `epss_last_refresh`, `nvd_last_success` timestamps to `/api/health` for operator visibility into data staleness.

Tests for untested endpoints: `GET /api/review/queue`, `POST /api/review/flag/{id}`, `POST /api/case/{id}/review`, `GET /api/case/{id}/history`, `GET /api/drift` — test suite grows from 37 to ~50.

Feature-parity guard test: verify `build_tabular_features()` output (35 columns) matches `xgboost_predictor.py` input by column index. Catches column drift permanently — if a feature is added to one but not the other, the test fails immediately.

Seed data ML dimension verification: ensure `seed_data.py` populates `ml_exploitation_contribution` in all seven demo rows with non-null values.

---

## What Is Explicitly Post-MVP

**RBAC** — one role (operator), no separation of viewer, triager, administrator. Not needed for the small-team SOC.

**Email/Slack notifications** — no push alerts. The analyst checks the queue. Notification infrastructure is a separate concern.

**ModernBERT CWE encoder replacement** — all-MiniLM-L6-v2 works well enough. Re-embedding the entire vector store for an incremental quality gain is not worth the sprint time.

**Cloud deploy + HTTPS** — the system runs on Docker anywhere. HTTPS is handled by whatever reverse proxy the operator puts in front of it. Cloud-specific templates would lock the system to a hosting model.

**Dynamic weight learning** — the five fixed scoring weights produce sensible rankings and are trivially explainable to analysts. Learning weights from data is a research direction, not an MVP requirement.

**Multi-language support** — English only. The WA Government SOC operates in English.

**Dark mode** — cosmetic CSS work that does not affect triage outcomes.

**Real-time WebSocket updates** — the frontend polls on a timer. WebSockets would add connection management overhead for a few seconds of latency improvement.

---

## The Vision

Imagine an analyst opening the queue dashboard — fifty new vulnerabilities from overnight scanning, already triaged. The four metric boxes show three Very Critical actions and two needing human validation. The analyst clicks the first Very Critical: it is a KEV entry on an internet-facing health system, auto-resolved by Tier 0 at score 92. Quick sanity check, click confirm.

The second case is an SLM where the LLM found a text conflict — the scanner says RCE but the system's vector store has the patch record showing it was applied three weeks ago. The LLM's reasoning is displayed: "The patch advisory KB5028185 addresses CVE-2025-XXXXX per vendor bulletin. The scanner may be reporting based on pre-patch fingerprinting." The analyst checks the change management system, confirms the patch, submits as false positive.

Fifteen minutes of work covers what would have taken hours of manual CVE research, EPSS lookups, KEV cross-referencing, and asset register queries. The pipeline handles the rest: daily re-checks catch rising EPSS scores, the drift dashboard tracks model health, and the audit feedback loop continuously improves the system. That is the TriageMate vision — not replacing the analyst, but giving them back their time.
