# TriageMate — File Tree

> Generated from: `/home/jpc/Documents/Cybersecurity (Temp)/TriageMate/TriageMate MVP`

```
TriageMate MVP/
├── .github/
│   └── workflows/
│       └── ci.yml  name: TriageMate CI
├── .opencode/
│   ├── agents/
│   │   ├── auditor.md  [Audit Type]
│   │   ├── bookkeeper.md
│   │   ├── commander.md
│   │   ├── intel.md  [Topic]
│   │   └── strike.md
│   ├── ARCHIVED/
│   │   ├── agents/
│   │   │   ├── backend-engineer.md
│   │   │   ├── cloud-llm-engineer.md
│   │   │   ├── devops-engineer.md
│   │   │   ├── frontend-dev.md
│   │   │   ├── ml-engineer.md
│   │   │   ├── privacy-legal-advisor.md
│   │   │   ├── ux-designer.md
│   │   │   └── wa-gov-consultant.md
│   │   └── skills/
│   │       └── dual-database-ddl/
│   │           └── SKILL.md
│   ├── plans/
│   │   ├── 2026-07-07-doc-cleanup-sprint.md  Sprint: Documentation Cleanup & Tool Audit
│   │   ├── 2026-07-07-skill-system-consolidation.md  Plan: Skill System Consolidation
│   │   └── 2026-07-08-clean-corpus-sprint.md  Sprint: Clean Corpus
│   ├── skills/
│   │   ├── audit-checklist/
│   │   │   └── SKILL.md  Audit Checklist
│   │   ├── backend-engineering/
│   │   │   └── SKILL.md  TriageMate Backend Engineering
│   │   ├── cloud-llm-engineering/
│   │   │   └── SKILL.md  TriageMate Cloud LLM Engineering
│   │   ├── devops-engineering/
│   │   │   └── SKILL.md  TriageMate DevOps Engineering
│   │   ├── frontend-engineering/
│   │   │   └── SKILL.md  TriageMate Frontend Engineering
│   │   ├── intel-toolbox/
│   │   │   └── SKILL.md  Intel Toolbox — Data Sources & Integrations
│   │   ├── ml-engineering/
│   │   │   └── SKILL.md  TriageMate ML Engineering
│   │   ├── ml-toolbox/
│   │   │   └── SKILL.md  ML Toolbox — CLI Commands
│   │   ├── new-integration-pattern/
│   │   │   └── SKILL.md
│   │   ├── privacy-legal-advising/
│   │   │   └── SKILL.md  Privacy & Legal Advising
│   │   ├── triage-toolbox/
│   │   │   └── SKILL.md  TriageMate Project Toolbox
│   │   ├── ux-designing/
│   │   │   └── SKILL.md  TriageMate UX Design
│   │   └── wa-gov-consulting/
│   │       └── SKILL.md  WA Government Consulting
│   ├── .gitignore  63.0 B
│   ├── DESIGN_RATIONALE.md  Agent & Skill Descriptions — Design Rationale
│   └── RESTRUCTURE_HANDOFF.md  OpenCode Restructure — Handoff Note
├── backend/
│   ├── alembic/
│   │   ├── versions/
│   │   │   ├── 001_initial_schema.py  Initial schema for TriageMate
│   │   │   ├── 002_add_analytics_columns.py  Add analytics tracking columns
│   │   │   ├── 003_add_resolved_vulnerabilities.py  Add resolved_vulnerabilities table
│   │   │   ├── 004_add_review_queue.py  Add review queue columns and reviews table
│   │   │   └── 005_add_ml_exploitation.py  Add ml_exploitation_contribution column
│   │   ├── env.py  Override sqlalchemy.url with DATABASE_URL env var if set
│   │   ├── README  38.0 B
│   │   └── script.py.mako  """${message}
│   ├── analysis/
│   │   ├── calibration_audit.py  Expected Calibration Error — identical formula to train_xgboost.py.
│   │   ├── epss_eval.py  1. Load and Align Data
│   │   ├── feature_parity_check.py  19.9 KB
│   │   └── validate_conversion.py  9.4 KB
│   ├── data/
│   │   ├── lancedb/
│   │   │   ├── __manifest/  (LanceDB internal — 3 files, 1015.0 B)
│   │   │   └── asset_documentation.lance/
│   │   │       ├── _indices/  (LanceDB internal — 757 files, 1.9 MB)
│   │   │       ├── _transactions/  (LanceDB internal — 193 files, 96.0 KB)
│   │   │       ├── _versions/  (LanceDB internal — 194 files, 218.6 KB)
│   │   │       └── data/  (LanceDB internal — 2 files, 38.6 KB)
│   │   ├── demo_scenarios.json  3.6 KB
│   │   ├── epss_cache.json  19.5 MB
│   │   ├── files_exploits.csv  9.7 MB
│   │   ├── kev_cache.json  518.0 KB
│   │   ├── mock_cmdb.json  27.8 KB
│   │   ├── nvd_cache.json  117.7 KB
│   │   ├── nvd_corpus.json  204.7 MB
│   │   └── vendor_popularity.json  405.3 KB
│   ├── integrations/
│   │   ├── __init__.py
│   │   ├── advisories.py
│   │   ├── cmdb.py  Load the mock CMDB from JSON file, keyed by hostname.
│   │   ├── demo_generator.py  ─── Caches (lazy-loaded, module-level) ───────────────────────────────
│   │   ├── exploitdb.py  Parse files_exploits.csv into an in-memory CVE-to-exploit lookup.
│   │   ├── greynoise.py  Query GreyNoise Community API for internet scan activity on a CVE.
│   │   ├── llm.py  ... proceed with LLM call
│   │   ├── metasploit.py  Check if a CVE has a Metasploit module.
│   │   ├── mitre_mapping.py
│   │   ├── nvd.py  ─── Demo mode: local cache read path ─────────────────────────────────
│   │   ├── osv.py  Query OSV.dev for fix version data for a CVE.
│   │   ├── otx.py  Query AlienVault OTX API for threat pulses referencing a CVE.
│   │   └── tenable.py  Extract the first CVE ID from plugin.cve array, or synthesize one.
│   ├── middleware/
│   │   ├── __init__.py
│   │   └── rate_limit.py
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── encoder.py  Encode a single CVE description into a 384-dimensional vector.
│   │   ├── enriched_cves.json  179.1 MB
│   │   ├── epss_substitutor.py  ── Constants used by both rule engine and ML fallback ────────────────────
│   │   ├── fetch_epss_data.py  Download and parse the current EPSS data from FIRST.org.
│   │   ├── generate_supplemental_hostnames.py  ─── AGENCIES AND THEIR DOMAINS ──────────────────────────────────────────────
│   │   ├── ingest_docs.py  Size limits
│   │   ├── nvd_checkpoint.json  72.0 B
│   │   ├── nvd_cves_cached.json  79.6 MB
│   │   ├── pretier_features.py  ─── AGENCY DEFINITIONS ─────────────────────────────────────────────────────
│   │   ├── pretier_supplemental.json  205.9 KB
│   │   ├── pretier_training_data.json  37.0 KB
│   │   ├── README.md  TriageMate ML Artifacts
│   │   ├── threshold_info.json  78.0 B
│   │   ├── train_epss_substitutor.py  ── seed for reproducibility ──────────────────────────────────────────────
│   │   ├── train_epss_v2.py  ── seed for reproducibility ──────────────────────────────────────────────
│   │   ├── train_epss_v3.py  ── Constants (identical to v2 for drop-in compatibility) ──────────────────
│   │   ├── train_pre_tier.py  ─── PATHS ──────────────────────────────────────────────────────────────────
│   │   ├── train_xgboost.py
│   │   ├── vector_store.py
│   │   └── xgboost_predictor.py  Probability + uncertainty zoning thresholds for routing decisions.
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── pre_tier.py  ─── PHASE 0: KNOWN HOSTS (Demo / Fallback) ────────────────────────────────
│   │   ├── tier_0.py  Threshold constants
│   │   ├── tier_1.py  Heuristic fallback when XGBoost model is not yet trained.
│   │   └── tier_2.py  Provider configuration from environment
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth.py  Authenticate with admin credentials.
│   │   ├── cases.py
│   │   ├── ingest.py  Map WAICP classification to numeric compliance category.
│   │   └── queue.py  )
│   ├── scripts/
│   │   ├── __init__.py
│   │   ├── build_cwe_hierarchy.py  Download cwec_latest.xml.zip and return contents as bytes.
│   │   ├── build_training_corpus.py  Bulletproof: find .env relative to this script, not CWD
│   │   ├── build_vendor_index.py
│   │   ├── fetch_nvd_corpus.py  Bulletproof: find .env relative to this script, not CWD
│   │   └── refresh_caches.py  Bulletproof: find .env relative to this script, not CWD
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py  Disable LLM API key before any app imports to prevent real API calls
│   │   ├── test_demo_generator.py  Structural Tests (6)
│   │   ├── test_feature_parity.py  ── Tabular feature keys in the EXACT order xgboost_predictor.predict() builds th
│   │   ├── test_fuzzed_ingest.py  ── Mock responses for network-dependent pipeline functions ─────────────
│   │   ├── test_health.py  Health endpoint smoke tests.
│   │   ├── test_ingest.py  Remove any previously created test records before each ingest test.
│   │   ├── test_integration.py  Test the full ingest pipeline end-to-end.
│   │   └── test_queue.py  Expected priority scores in descending order (matching the seed data)
│   ├── .env  1009.0 B
│   ├── .env.example  1.7 KB
│   ├── __init__.py
│   ├── alembic.ini
│   ├── audit.py  Determine if a case should enter the audit pool.
│   ├── auth.py  Configuration
│   ├── database.py  Default SQLite database path (can be overridden by tests)
│   ├── ingest_cwe.py  Get CWE classification for a CVE.
│   ├── ingest_helpers.py  Look up the WAICP data classification for an asset.
│   ├── logging_config.py
│   ├── main.py  ─── Load .env BEFORE any module reads os.getenv() ─────────────────────
│   ├── models.py  Convert snake_case to camelCase for API responses.
│   ├── pytest.ini  47.0 B
│   ├── requirements.txt  psycopg2-binary>=2.9.9
│   ├── scheduler.py  ).fetchall()
│   ├── scoring.py  Round to nearest int, .5 always rounds up (not banker's rounding).
│   ├── seed_data.py  Row 1: CVE-2023-34362 — MOVEit Transfer SQL Injection
│   ├── triagemate.db  96.0 KB
│   ├── triagemate.db.backup  1.3 MB
│   └── triagemate.db.pre_retrain  96.0 KB
├── backlog/
│   └── TASK_STORE_COLUMNS_IN_NPZ.md  Task: Store Column Names in NPZ Metadata
├── docs/
│   ├── architecture/
│   │   └── MVP_SCOPE.md  TriageMate MVP — Scope Document
│   ├── archive/
│   │   ├── handoffs/
│   │   │   └── SPRINT_9_HANDOFF.md  Sprint 9 Handoff — Commander Briefing
│   │   ├── sprints-1-6/
│   │   │   ├── COURSE_CORRECTION.md  TriageMate — Course Correction Plan
│   │   │   ├── DEMO_DATA_GENERATOR_PLAN.md  Demo Data Generator — Implementation Plan (Revision 1)
│   │   │   ├── DEMO_DATA_GENERATOR_SCOPE.md  Demo Data Generator — Scope Document
│   │   │   ├── PRE_DEMO_PLAN.md  TriageMate — Pre-Demo Hardening Plan
│   │   │   ├── SPRINT_1_HANDOFF.md  Sprint 1 Handoff — TriageMate MVP
│   │   │   ├── SPRINT_2_HANDOFF.md  Sprint 2 Handoff — TriageMate MVP
│   │   │   ├── SPRINT_3_HANDOFF.md  Sprint 3 Handoff — TriageMate MVP
│   │   │   ├── SPRINT_7_HANDOFF.md  Sprint 7 Handoff — Commander Briefing
│   │   │   ├── SPRINT_8_HANDOFF.md  Sprint 8 Handoff — Commander Briefing
│   │   │   ├── SPRINT_9_BRIEFING_PLAN.md  Sprint 9 Briefing — Data Supremacy
│   │   │   └── TEAM_BRIEFING.md  TriageMate — Team Briefing (Sprint 5: Demo Data Generator)
│   │   ├── Additional Information.md  ARCHIVED — Following a Piece of Data: The TriageMate Pipeline Journey
│   │   ├── External Auditor Response.md  External Audit Report — Demo Data Generator
│   │   ├── EXTERNAL_AUDITOR_PROMPT.md  External Auditor Prompt — Demo Data Generator
│   │   ├── ml-implementation-plan.md  TriageMate ML Implementation Plan — Final
│   │   ├── SECOND_WAVE_PROMPT.md  Wave 2 Audit Prompt — LOGIC & SEMANTIC CORRECTNESS
│   │   ├── SPRINT_NEXT_PLAN.md  Sprint NEXT Plan — Model Retrain + Operational Upgrades
│   │   ├── TriageMate ML Research Prompt.md  ARCHIVED — TriageMate ML Research Prompt
│   │   ├── TriageMate ML Research.md  ARCHIVED — Machine Learning Architecture and Implementation Roadmap
│   │   └── TriageMate MVP Transformation.md  SUPERSEDED — TriageMate MVP Transformation Plan
│   ├── guides/
│   │   └── WINDOWS_SETUP.md  TriageMate — Windows Setup Guide
│   ├── planning/
│   │   ├── ai-doc-strategy-2026-07-07.md  AI Documentation Strategy Proposal
│   │   ├── file-consolidation-plan-2026-07-07.md  .md File Consolidation Plan
│   │   └── ROADMAP.md  TriageMate — Master Roadmap & Status
│   ├── reference/
│   │   ├── AI_PROBLEMS.md  AI Problems — Discrepancies Found During Development
│   │   ├── hostname-standards.md  **Technical Reference Architecture for Hostname Nomenclature and Information Gov
│   │   └── xgboost-investigation-report.md  XGBoost Exploitation Model — Investigation Report
│   ├── research/
│   │   └── RESEARCH_FINDINGS.md  TriageMate — Sprint NEXT+2 Research Findings
│   └── INDEX.md  TriageMate — Documentation Index
├── frontend/
│   ├── css/
│   │   └── triagemate.css  :root {
│   ├── js/
│   │   ├── components/
│   │   │   ├── auth.js  // auth.js — Authentication for TriageMate
│   │   │   ├── caseView.js  // caseView.js — Case view rendering
│   │   │   ├── demoControls.js  // demoControls.js — Demo Data Generator UI controls
│   │   │   ├── driftDashboard.js  // driftDashboard.js — Model Drift Dashboard (CSS-only charts)
│   │   │   ├── metricBoxes.js  // metricBoxes.js — Summary metric boxes
│   │   │   ├── queue.js  // queue.js — Queue table rendering with search, sort, and tier badges
│   │   │   └── reviewQueue.js  // reviewQueue.js — Tier 3 Human Review Queue
│   │   ├── api.js  // api.js — Single responsibility: talk to the backend
│   │   └── app.js  // app.js — Application state and initialization
│   └── index.html  9.7 KB
├── graphify_output/
│   ├── api_deps.md  TriageMate — API Dependency Map
│   ├── feature_parity.md  TriageMate — Feature Parity Report
│   ├── file_tree.md  TriageMate — File Tree
│   ├── knowledge_graph.json  11.4 KB
│   └── ml_inventory.md  TriageMate — ML Model Inventory
├── .dockerignore  328.0 B
├── .env.example  1.7 KB
├── .gitignore  524.0 B
├── .pre-commit-config.yaml  413.0 B
├── AGENTS.md  TriageMate Project Rules
├── AI_PROBLEMS.md  AI Problems — Discrepancies Found During Development
├── demo-reference.html  <!--
├── docker-compose.yml  1.8 KB
├── Dockerfile  1.3 KB
├── index.html  119.4 KB
├── justfile  4.7 KB
├── MVP_SCOPE.md  TriageMate MVP — Scope Document
├── opencode.jsonc  924.0 B
├── requirements-dev.txt  115.0 B
├── RESEARCH_FINDINGS.md  TriageMate — Sprint NEXT+2 Research Findings
├── ROADMAP.md  TriageMate — Master Roadmap & Status
├── triagemate.db  12.0 KB
├── WINDOWS_SETUP.md  TriageMate — Windows Setup Guide
└── XGBOOST_INVESTIGATION_REPORT.md  XGBoost Exploitation Model — Investigation Report
```
