# TriageMate — Comprehensive Book Generation Prompt

## Objective

Generate a complete, multi-chapter "book" about the **TriageMate** application in the form of a set of interconnected `.md` files. These chapters will be uploaded to **NotebookLM** and used with its **Audio Deep Dive** feature to generate podcast episodes about the application. Every chapter must be **self-contained, narrative-driven, and explanatory** — written to be *read aloud* as a podcast script, not as dry technical reference.

The book must capture a **faithful balance** between:

1. **What TriageMate currently IS** — the fully implemented codebase as of Sprint 9 (July 2026).
2. **What the MVP WILL BE** — the near-future state including items in `SPRINT_NEXT_PLAN.md`, `MVP_SCOPE.md`, and `ROADMAP.md` that are planned but not yet built.

**Do NOT** focus on speculative post-MVP features (cloud deploy, RBAC, Slack notifications, ModernBERT CWE encoder). Only include what's explicitly in the MVP scope or the Sprint NEXT plan.

---

## How to Work (Use Subagents Heavily)

You have the ability to spawn **multiple subagents** to work in parallel. Use them aggressively:

### Phase 1 — Exploration (3-4 subagents in parallel)
Spawn separate subagents to each read a slice of the codebase:

| Subagent | Task |
|----------|------|
| **SA-DB** | Read `backend/database.py`, `backend/models.py`, the Alembic migrations in `backend/alembic/versions/`, and inspect `backend/triagemate.db` (SQLite). Return: full table schemas, all columns with types, relationships between tables, any triggers or indices, migration history. |
| **SA-BACKEND** | Read `backend/main.py`, `backend/pipeline/*.py`, `backend/scoring.py`, `backend/ingest_helpers.py`, `backend/routers/*.py`. Return: the request flow from ingest → pipeline → scoring → response, router endpoint signatures, middleware, config loading, scheduler. |
| **SA-FRONTEND** | Read `frontend/index.html`, `frontend/js/app.js`, `frontend/js/components/*.js`, `frontend/css/triagemate.css`. Return: page architecture, component hierarchy, state management, API integration pattern, auth flow, event wiring. |
| **SA-ML** | Read `backend/ml/xgboost_predictor.py`, `backend/ml/encoder.py`, `backend/ml/vector_store.py`, `backend/ml/epss_substitutor.py`, `backend/pipeline/tier_2.py`, `backend/integrations/*.py`. Return: model architecture, feature vector (list all 42 keys), LLM provider chain, RAG flow, all external integrations with their auth/cache/fallback behaviour. |

### Phase 2 — Document Review (2 subagents in parallel)
| Subagent | Task |
|----------|------|
| **SA-DOCS** | Read `ROADMAP.md`, `MVP_SCOPE.md`, `SPRINT_NEXT_PLAN.md`, `AI_PROBLEMS.md`, `DEMO_SCRIPT.md`. Return: what's done vs planned, sprint history, known bugs, verification criteria, acceptance tests. |
| **SA-SKILLS** | Read `.opencode/skills/*/SKILL.md`, `Additional Instructions/Hostname and Data Classification Standards.md`, `Additional Instructions/TriageMate ML Implementation Plan - Final.md`. Return: architectural rules, data classification standards, ML implementation plan details, integration patterns. |

### Phase 3 — Chapter Writing (one subagent per chapter, ALL in parallel)
After exploration completes and you have all the information, spawn one subagent per chapter. Each writes its own `.md` file. They do NOT need to coordinate — the chapter boundaries are predefined.

### Phase 4 — Index Assembly
After all chapter files are written, run a final verification:
- Scan each chapter for [TBD] or [TODO] markers — fill them or flag them.
- Check that cross-references between chapters are consistent.
- Generate the `index.md` table of contents.
- Verify word counts per chapter (target: 1500-3000 words each).

---

## Chapter Structure (16 Chapters)

Write **exactly these 16 chapters** as separate `.md` files in a directory called `triagemate-book/` at the project root. Each chapter should be **1500-3000 words**, balanced between what's implemented and what's planned for the MVP.

### Chapter 1 — `01-executive-summary.md`
The "elevator pitch" chapter. What is TriageMate? Why does it exist? Who is it for (WA SOC analysts)? The problem it solves (vulnerability overload, prioritisation paralysis). High-level architecture in plain language. The one-paragraph origin story (started as a demo, evolved through 9 sprints). Current state (production-capable MVP) and immediate future (Sprint NEXT retrain + hardening).

### Chapter 2 — `02-architecture-overview.md`
System architecture: FastAPI backend, SQLite/PostgreSQL database, static HTML/JS frontend, no build step. The 4-tier pipeline (Pre-Tier → Tier 0 → Tier 1 → Tier 2) + scoring engine. Include a clear mermaid sequence diagram showing the data flow from ingest to result. Explain the design philosophy: monolithic backend, no ORM, PostgreSQL compatibility layer, lazy-loaded ML models. Discuss the architectural rules: pipeline calls ML, not the other way around; integrations are independently skippable; features are immutable once released.

### Chapter 3 — `03-database-schema.md`
Deep dive into all 3 tables: `vulnerabilities`, `resolved_vulnerabilities`, `reviews`. For each table: list every column with type and purpose, explain relationships (application-level FK, no DB constraints), discuss the dual-dialect pattern (SQLite vs PostgreSQL DDL in `database.py`), the 5 Alembic migrations, JSON columns and their structure (scoring_weights_json, mitre_techniques_json, summary_paragraphs_json, asset_registry_json). Explain the `_PGCompatRow` wrapper, migration helper pattern, and the audit/flag columns.

### Chapter 4 — `04-ingest-pipeline.md`
The complete journey of a vulnerability from raw scanner output to scored queue entry. Step by step: schema validation → CMDB matching → telemetry gathering → threat intel enrichment → feature vector construction (`build_feature_vector()` — list all 42 keys) → pipeline execution → scoring → database insert. Cover the three ingest routes (single POST, batch, Tenable webhook parser). Discuss the background scheduler tasks (daily low-severity re-check, weekly cache refresh). Explain the `seed_data.py` mechanism.

### Chapter 5 — `05-pipeline-tier-0-deterministic.md`
Tier 0: the deterministic rule engine. Explain each rule with pseudocode:
- R1: KEV + CVSS ≥ 9.0 + internet-facing → Very Critical
- R2: KEV + EPSS ≥ 0.90 + Category 3/4 → Very Critical
- R3: NOT KEV + CVSS < 4.0 + EPSS < 0.10 → Low
- Default → escalate
Discuss the SSVC alignment, configurable threshold constants, the "ambiguous" routing concept, and why this tier is "production-ready, zero ML, zero training data." Planned MVP work: threshold tuning, adding more rule patterns based on SOC feedback.

### Chapter 6 — `06-pipeline-tier-1-xgboost.md`
Tier 1: the XGBoost exploitation probability model. Full narrative: 37 tabular features + 384-dim SBERT embedding, training data strategy (KEV as positive class, ~15:1 imbalance, scale_pos_weight), model architecture (800 trees, max_depth=4, Platt calibration), ROC-AUC 0.9677-0.9946. Explain ensemble variance routing (std of 800 tree predictions > 0.15 → escalate to Tier 2). Explain the 93K → 144K → 186K training data evolution across sprints. Cover the fallback heuristic path. Planned MVP work: the Sprint NEXT retrain on `training_data_v2.npz` (186K records, 67 features, real distributions, temporal bias fixes, label leakage removal).

### Chapter 7 — `07-pipeline-tier-2-cloud-llm.md`
Tier 2: the cloud LLM layer. Explain the force-reflection prompt template (Step A → B → C → structured JSON), provider chain (OpenAI gpt-4o-mini primary → Anthropic backup → Together AI tertiary → KNOWN_CONFLICTS fallback → neutral default), exponential backoff retry (3 attempts, 2^N seconds), prompt caching economics (50-90% discount on cached prefixes). Explain the RAG context injection: deterministic pre-query against LanceDB, max 2000 tokens injected into prompt, TTL cache by hostname. Explain the score adjustment range [-70, +10] and why. Cover the demo row conflict examples (Office RCE -15, Confluence -37, ManageEngine -66). Planned MVP work: none — this tier is complete. Local model replacement is explicitly post-MVP.

### Chapter 8 — `08-pipeline-pre-tier.md`
Pre-Tier: asset mission classification. Current state: hostname dictionary stub (31 entries from `mock_cmdb.json`, hardcoded mission tags + fallback to Support/Minimal at 0.60 confidence). The real RF model (60-dim MultiOutputClassifier, 150 trees) that's already trained on the mock CMDB data but hasn't replaced the stub yet. Explain the features: department, role, OS, internet-facing, network zone, domain suffix, app count, asset count. Explain the confidence-based fallback pattern (model → dict → defaults). Planned MVP work: replacing the stub with the RF model, generating synthetic training data via SMOTE (500+ records from 31 real hosts).

### Chapter 9 — `09-scoring-engine.md`
The 0-100 priority score. Explain the 6 dimensions: CVSS (max 40), EPSS (max 20), Asset Criticality (max 20), Exposure (max 15), Patch/Remediation (max 5), ML Exploitation (max 10). Explain the band mapping: 0-25 Low, 26-50 Medium, 51-75 Critical, 76-100 Very Critical. Explain the EPSS substitution model (v3 is current best, sector-adjusted meta-scorer, activation only when raw EPSS < 0.10 AND sector_multiplier > 5.0). Explain the scoring_weights_json output format. Planned MVP work: dynamic weight learning is post-MVP, but the EPSS substitution retrain is planned (344K real EPSS scores available, blocked lifted in Sprint NEXT).

### Chapter 10 — `10-ml-ecosystem.md`
The full ML model inventory. Tabular:

| Model | Purpose | Algorithm | Training Data | Status |
|-------|---------|-----------|--------------|--------|
| XGBoost | Exploitation probability | XGBoost classifier, 800 trees | 186K CVEs (68 features) | Trained |
| Pre-Tier RF | Mission + wellbeing classification | MultiOutput RF, 150 trees | 31 mock CMDB hosts | Trained |
| EPSS v3 | Sector-adjusted EPSS | Regularised regression | 344K EPSS scores | Trained (best) |
| EPSS v2 | Sector-adjusted EPSS | Regularised regression | 344K EPSS scores | Trained (fallback) |
| EPSS v1 | Sector-adjusted EPSS | Regularised regression | 186K CVEs | Trained (fallback) |
| SBERT | Text embedding | all-MiniLM-L6-v2 | Pretrained | Cached |
| LanceDB | Vector store | In-process Arrow | 9 seed docs | Seeded |

Explain the training data pipeline: `fetch_nvd_corpus.py` → `build_training_corpus.py` → `train_xgboost.py`. Explain the PCA reduction (384→32 dims, preserves >85% variance). Explain the feature vector contract (42 keys, never rename/remove, only append). Discuss the lazy-loading singleton pattern for all models.

### Chapter 11 — `11-external-integrations.md`
All external data sources. Tabular:

| Integration | Type | Auth | TTL | Fallback |
|-------------|------|------|-----|----------|
| NVD API 2.0 | CVE enrichment | Optional API key | 24h | Empty results |
| OSV.dev | Patch version data | None | 1h | Empty results |
| ExploitDB CSV | PoC existence | None | Process lifetime | NVD fallback |
| Metasploit | Payload existence | None | Process lifetime | Empty results |
| OTX | Threat pulses | API key | 1h | Empty results |
| Tenable | Scanner parser | None (file) | N/A | Rejection |
| CMDB | Asset context | Stub | Process lifetime | Conservative defaults |
| Advisories | WASOC references | Stub | Process lifetime | Empty results |
| MITRE Mapping | CWE → ATT&CK | Stub | Process lifetime | Empty results |
| RAG (LanceDB) | Internal docs | Local | 60s TTL | Empty context |

Explain the integration contract: TTL cache, graceful degradation, independently skippable, structured logging. Explain how new integrations are added per the 4-step pattern. Discuss GreyNoise (deprecated due to rate limits — potential MVP return).

### Chapter 12 — `12-frontend-spa.md`
The single-page application architecture. Four screens: Queue (sortable table, metric boxes, tier filter, search), Case (4 panels: narrative P1, accordions P2, notes+gauge P3, scoring+registry P4), Review Queue (expandable rows, approve/override/reject actions), Drift Dashboard (4 CSS-only charts: score trend, tier routing, risk bands, feature drift). Explain the JS architecture: `api.js` (auth-aware fetch wrapper with auto-refresh), `app.js` (state singleton, event bus, screen routing), component files (queue.js, caseView.js, metricBoxes.js, etc.). Explain the auth flow (JWT login modal, Bearer token injection, auto-refresh on 401). The CSS-only chart approach (no charting library, pure CSS for drift display). Keyboard shortcuts (Ctrl+S save notes, Escape back).

### Chapter 13 — `13-security-auth-rate-limiting.md`
Security architecture. Auth: JWT-based, optional (disabled when env vars unset), bcrypt password hashing, access + refresh token pairs, middleware-enforced Bearer extraction. Rate limiting: token bucket per path (ingest 30/min burst 50, demo 10/min burst 15, clear 2/min burst 3). CORS: wide-open (localhost MVP). Input validation: Pydantic models with camelCase aliasing. Planned MVP work: rate limiting was item 16 in Sprint NEXT (token bucket configurable via env var, prevents scanner floods). Auth hardening for production is post-MVP (RBAC, API keys, audit logging).

### Chapter 14 — `14-operations-and-deployment.md`
How TriageMate runs. Current: `uvicorn main:app --reload` on localhost, SQLite backend, `.env` configuration, no containerization. Docker config: multi-stage Dockerfile (Python 3.12-slim, non-root user, SBERT pre-cache), docker-compose.yml (PostgreSQL 16 + app with health checks). Testing: 37 tests in 6 files (pytest, SQLite in-memory for test isolation). Background processes: daily low-severity re-check (7-day window), 7.5% audit sampling. Logging: structured JSON logs, configurable format. Planned MVP work: the Sprint NEXT hardening items (model rollback mechanism, cache freshness in health endpoint, tests for new review/drift endpoints, feature-parity guard test).

### Chapter 15 — `15-data-corpus-and-training.md`
The training data that powers the ML models. NVD corpus: 186,102 CVEs, 145MB, built via `fetch_nvd_corpus.py` (API 2.0 + feed fallback). KEV cache: 1,631 entries from CISA. EPSS cache: 344,852 scores from FIRST.org. ExploitDB: 47,089 exploits, 25,037 CVE mappings. Vendor index: 17,100 vendors from NVD corpus. Training data v2: 186K feature vectors, 68 columns. Explain the temporal bias fixes: chronological train/val/test split, observation window filters, no look-ahead on EPSS/KEV. Explain the feature engineering pipeline: `build_training_corpus.py` unifies all sources. The 5 corpus scripts and their roles. The NVD checkpoint/resume mechanism for incremental updates.

### Chapter 16 — `16-mvp-roadmap-and-future.md`
The capstone chapter. Summarise what's done (all 9 sprints, all pipeline stages, full data corpus, drift dashboard, review queue, PostgreSQL support, Docker, Alembic, 37 tests) and what's coming in the immediate MVP window: XGBoost retrain (the single highest-impact improvement), Pre-Tier RF model activation (replacing the hostname dict), EPSS substitution retrain (344K real scores), rate limiting configuration, hardened tests and operational guards. Map each item to its sprint/plan document. End with a vision paragraph: what TriageMate looks like as a production SOC tool for the WA Government — the pipeline, the dashboards, the analyst workflow.

---

## Writing Guidelines for NotebookLM Audio Deep Dive

1. **Narrative voice**: Write as if you're explaining the system to an intelligent colleague who knows nothing about TriageMate. Use analogies. Avoid jargon where possible; define it where unavoidable.

2. **Conversational but precise**: These chapters will be read aloud as podcast scripts. Prefer shorter sentences. Read each paragraph aloud as you write it — if it sounds stilted, rewrite it.

3. **Balance is critical**: Every chapter should contain BOTH a "What's Implemented" subsection and a "What's Planned (MVP)" subsection. The ratio should be approximately 70/30 implemented-to-planned overall, but some chapters will skew more one way (e.g., Chapter 5 is mostly implemented, Chapter 16 is mostly planned).

4. **Self-contained chapters**: Each chapter should be understandable on its own. Avoid "as we discussed in Chapter 3" without briefly restating the relevant context. Remember that in NotebookLM, chapters may be ingested individually.

5. **Avoid lists in podcast prose**: Long bullet lists don't translate to audio. Instead of "There are 5 features: A, B, C, D, E", write "There are 5 features. First is A, which does... Then B handles... The third, C, is responsible for..." Paragraph form, not list form.

6. **Make it interesting**: Why should the listener care? Connect each chapter back to the SOC analyst's pain point — information overload, false positives, prioritisation paralysis. Every technical detail should serve the story of how TriageMate makes the analyst's life better.

7. **Code references**: Reference file paths and line numbers in natural language (e.g., "The feature vector builder lives in `backend/ingest_helpers.py`") rather than as sterile citations.

8. **Diagrams**: Include mermaid.js diagram blocks where they aid understanding (especially in Chapter 2). NotebookLM can handle mermaid in markdown.

---

## Output Format

- All files go in `triagemate-book/` at the project root.
- Each file is named `NN-chapter-name.md` where NN is the zero-padded chapter number.
- Include a `triagemate-book/index.md` table of contents with one-line summaries of each chapter.
- Front matter in each file is optional but if used, keep it minimal (just the chapter title and a 1-sentence summary).
- Each file should be valid markdown. Use `##` and `###` for subsections. Do NOT use `#` (H1) except for the chapter title.

## Final Checks Before Finishing

- [ ] All 16 chapter files exist in `triagemate-book/`
- [ ] `index.md` has a complete table of contents
- [ ] Every file is valid markdown
- [ ] No [TBD] or [TODO] placeholders remain
- [ ] Each chapter is 1500-3000 words
- [ ] Balance is approximately 70/30 implemented-to-planned
- [ ] No speculative post-MVP content (RBAC, Slack, ModernBERT, cloud deploy)
- [ ] Chapters are self-contained and readable as podcast scripts

---

## Context: Project Root at

```
/home/jpc/Documents/Cybersecurity (Temp)/TriageMate/TriageMate MVP
```

Run your exploration subagents against this path. Write the output files to the same root under `triagemate-book/`.
