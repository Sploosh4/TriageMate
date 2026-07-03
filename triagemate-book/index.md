# TriageMate — Complete Book

> A comprehensive deep-dive into the TriageMate vulnerability triage pipeline, written for NotebookLM Audio Deep Dive.
> Generated July 2026 — Sprint 9 (Data Supremacy) status.

---

## Table of Contents

1. **[01-executive-summary.md](01-executive-summary.md)** — The elevator pitch: what TriageMate is, the problem it solves (vulnerability overload, prioritisation paralysis for WA SOC analysts), high-level architecture, origin story (demo → 9 sprints), current production-capable MVP state, and near-future Sprint NEXT roadmap.

2. **[02-architecture-overview.md](02-architecture-overview.md)** — System architecture: FastAPI backend, SQLite/PostgreSQL database, static HTML/JS frontend, the 4-tier pipeline (Pre-Tier → Tier 0 → Tier 1 → Tier 2) + scoring engine. Includes a mermaid.js sequence diagram showing end-to-end data flow from ingest to result. Covers design philosophy, architectural rules, middleware stack, startup lifecycle, and file map.

3. **[03-database-schema.md](03-database-schema.md)** — Deep dive into all 3 tables (vulnerabilities, resolved_vulnerabilities, reviews) with every column, type, and purpose. Explains the dual-dialect pattern (SQLite vs PostgreSQL DDL), the _PGCompatRow wrapper, migration helper pattern, 5 Alembic migrations, JSON column structures, and application-level foreign key relationships.

4. **[04-ingest-pipeline.md](04-ingest-pipeline.md)** — The complete journey of a vulnerability from raw scanner output to scored queue entry. Covers all 14 pipeline steps: Pre-Tier mission classification, asset context, CWE classification, EPSS substitution, Tier 0 deterministic rules, feature vector construction (42 keys), Tier 1 XGBoost, RAG query, Tier 2 LLM, final scoring, detection tier labelling, MITRE mapping, advisory lookup, audit selection, and DB insert. Also covers the three ingest routes (single, batch, Tenable) and background scheduler tasks.

5. **[05-pipeline-tier-0-deterministic.md](05-pipeline-tier-0-deterministic.md)** — Tier 0: the deterministic rule engine. Three SSVC-aligned rules (KEV + High CVSS + Internet-facing → Very Critical, KEV + High EPSS + Sensitive → Very Critical, Low CVSS + Low EPSS → Low), configurable threshold constants, the 7-day re-check logic, and why this tier is production-ready with zero ML and zero training data.

6. **[06-pipeline-tier-1-xgboost.md](06-pipeline-tier-1-xgboost.md)** — Tier 1: the XGBoost exploitation probability model. 35 tabular features + 384-dim SBERT embedding (419 total), 800 trees at depth 4, Platt calibration, ROC-AUC 0.9677–0.9946. Covers training data evolution (93K → 144K → 186K records), temporal bias fixes (chronological splits, point-in-time labels, observation windows), ensemble variance routing (std > 0.15 → escalate to Tier 2), CWE-stratified fast paths, and the Sprint NEXT retrain plan.

7. **[07-pipeline-tier-2-cloud-llm.md](07-pipeline-tier-2-cloud-llm.md)** — Tier 2: the cloud LLM layer. The force-reflection prompt template (Step A → B → C → structured JSON), multi-provider fallback chain (OpenAI → Anthropic → Together → KNOWN_CONFLICTS → neutral default), exponential backoff retry, prompt caching economics (50-90% cost reduction), RAG context injection from LanceDB, the asymmetric score adjustment range [-70, +10], and three real KNOWN_CONFLICTS case studies.

8. **[08-pipeline-pre-tier.md](08-pipeline-pre-tier.md)** — Pre-Tier: asset mission classification. The current KNOWN_TAGS dict stub (31 hardcoded hosts), the already-trained RandomForest model (MultiOutputClassifier, 150 trees, 55 features) that hasn't replaced the stub yet, the confidence-based fallback pattern (model → dict → defaults), and the Sprint NEXT activation plan with synthetic training data generation.

9. **[09-scoring-engine.md](09-scoring-engine.md)** — The 0-100 priority score. Six weighted dimensions: CVSS (max 40), EPSS (max 20), ML Exploitation (max 10), Asset Criticality (max 20), Exposure (max 15), Patch/Remediation (max 5) plus Tier 2 adjustment (±20 clamped). Risk band mapping (Low/Medium/Critical/Very Critical). EPSS substitution model chain (v3/v2/v1/rule engine) with activation gate. Scoring weights JSON output format.

10. **[10-ml-ecosystem.md](10-ml-ecosystem.md)** — The full ML model inventory: XGBoost (exploitation probability, 800 trees), Pre-Tier RF (mission + wellbeing, 150 trees), EPSS v3/v2/v1 (sector-adjusted regression), SBERT (all-MiniLM-L6-v2, 384-dim), LanceDB (in-process vector store). Training data pipeline scripts, feature vector contract (42 keys, never rename/remove, only append), PCA removal decision, lazy-loading singleton pattern.

11. **[11-external-integrations.md](11-external-integrations.md)** — All 11 external data sources: NVD API 2.0, OSV.dev, ExploitDB CSV, Metasploit, AlienVault OTX, GreyNoise (deprecated), CMDB stub, MITRE ATT&CK mapping, Advisory references, Tenable parser, Demo generator. Auth patterns, cache TTLs, fallback behaviours, and the 4-step integration contract for adding new sources.

12. **[12-frontend-spa.md](12-frontend-spa.md)** — The single-page application. Four screens: Queue (sortable table, metric boxes, tier filter, search), Case (4 panels: narrative P1, accordions P2, notes+gauge P3, scoring+registry P4), Review Queue (expandable rows, approve/override/reject actions), Drift Dashboard (4 CSS-only charts). JS architecture (api.js, app.js, 7 components), JWT auth flow, keyboard shortcuts, responsive breakpoints, and the CSS-only chart approach.

13. **[13-security-auth-rate-limiting.md](13-security-auth-rate-limiting.md)** — Security architecture. JWT authentication (optional, bcrypt hashing, access + refresh token pair, auto-refresh on 401). Token bucket rate limiting (ingest 30/min burst 50, demo 10/min burst 15, clear 2/min burst 3). CORS, Pydantic input validation, parameterised SQL queries, XSS mitigation via escHtml(), secrets management via .env. Planned Sprint NEXT rate limiting configurability.

14. **[14-operations-and-deployment.md](14-operations-and-deployment.md)** — Operations. Current `uvicorn main:app --reload` deployment. Docker multi-stage build + docker-compose with PostgreSQL. Structured JSON logging. 37 tests in 6 files (pytest). Background processes (daily low-severity re-check, 7.5% audit sampling). 8-step startup sequence. Health endpoint. .env configuration reference. Sprint NEXT+ operational hardening (model rollback, cache freshness, test expansion, feature-parity guard).

15. **[15-data-corpus-and-training.md](15-data-corpus-and-training.md)** — The training data that powers the ML models. NVD corpus (186,102 CVEs, 145MB), KEV cache (1,631 CISA entries), EPSS cache (344,852 FIRST.org scores), ExploitDB (47,089 exploits, 25,037 CVE mappings), training data v2 (186K feature vectors, 68 columns). Temporal bias fixes (chronological splits, point-in-time labels, observation window, PCA removal). Label construction strategy. Corpus scripts.

16. **[16-mvp-roadmap-and-future.md](16-mvp-roadmap-and-future.md)** — The capstone. Recap of all 9 sprints, immediate Sprint NEXT deliverables (XGBoost retrain, Pre-Tier RF activation, EPSS substitution retrain, rate limiting config), Sprint NEXT+ hardening items (model rollback, cache freshness, test expansion), explicit post-MVP exclusions, and the vision for TriageMate as a production SOC tool for the WA Government.

---

**Total: 16 chapters, ~44,900 words**

Generated for NotebookLM Audio Deep Dive — each chapter is self-contained, conversational, and structured for read-aloud podcast format.
