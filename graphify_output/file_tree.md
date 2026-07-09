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
│   │   ├── 2026-07-08-clean-corpus-sprint.md  Sprint: Clean Corpus
│   │   ├── 2026-07-08-hygiene-plan.md  Hygiene & Cleanup Plan
│   │   ├── 2026-07-08-sprint-11.md  Sprint 11: Model Governance + Ops Hardening
│   │   ├── 2026-07-08-sprint-12.md  Sprint 12: Gap Hardening — Docs, Research, Bookkeeping
│   │   ├── 2026-07-08-sprint-13.md  Sprint 13: EPSS Data Pipeline + Documentation
│   │   ├── 2026-07-08-sprint-15-HALFWAY.md  Sprint 15 — Halfway Handoff
│   │   ├── 2026-07-08-sprint-15.md  Sprint 15 — Production Confidence
│   │   ├── 2026-07-08-sprint-exploitdb-fixes.md  Sprint Plan: ExploitDB/Metasploit Integration Fixes
│   │   ├── 2026-07-08-sprint-operational-readiness.md  Sprint: Operational Readiness
│   │   ├── 2026-07-08-sprint-parallel-polish.md  Sprint: Parallel Polish
│   │   ├── 2026-07-08-sprint-research-synthetic-data.md  Sprint Plan: Research & Synthetic Data Infrastructure
│   │   └── 2026-07-09-sprint-16.md  Sprint 16 — ML Monitoring Foundation
│   ├── skills/
│   │   ├── audit-checklist/
│   │   │   └── SKILL.md  Audit Checklist
│   │   ├── backend-engineering/
│   │   │   └── SKILL.md  TriageMate Backend Engineering
│   │   ├── cloud-llm-engineering/
│   │   │   └── SKILL.md  TriageMate Cloud LLM Engineering
│   │   ├── codebase-review/
│   │   │   └── SKILL.md  Codebase Review — Soft Skills & Methodology
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
│   │   │   ├── 005_add_ml_exploitation.py  Add ml_exploitation_contribution column
│   │   │   ├── 006_add_tier_1_features_column.py  Add tier_1_features TEXT column to vulnerabilities
│   │   │   └── 007_add_tier_1_features_to_resolved.py  Add tier_1_features TEXT column to resolved_vulnerabilities
│   │   ├── env.py  Override sqlalchemy.url with DATABASE_URL env var if set
│   │   ├── README  38.0 B
│   │   └── script.py.mako  """${message}
│   ├── analysis/
│   │   ├── calibration_audit.py  Expected Calibration Error — identical formula to train_xgboost.py.
│   │   ├── drift.py  Compute Population Stability Index for one feature.
│   │   ├── epss_eval.py  1. Load and Align Data
│   │   ├── feature_parity_check.py  19.9 KB
│   │   ├── stress_db.py  Create SQLite database at path with the stress test schema.
│   │   └── validate_conversion.py  9.4 KB
│   ├── data/
│   │   ├── lancedb/
│   │   │   ├── __manifest/  (LanceDB internal — 3 files, 1015.0 B)
│   │   │   └── asset_documentation.lance/
│   │   │       ├── _indices/  (LanceDB internal — 789 files, 2.0 MB)
│   │   │       ├── _transactions/  (LanceDB internal — 201 files, 100.1 KB)
│   │   │       ├── _versions/  (LanceDB internal — 202 files, 228.4 KB)
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
│   │   ├── cache_health.py  Return KEV cache freshness info for the health endpoint.
│   │   ├── cmdb.py  Load the mock CMDB from JSON file, keyed by hostname.
│   │   ├── demo_generator.py  ─── Caches (lazy-loaded, module-level) ───────────────────────────────
│   │   ├── exploitdb.py  Parse files_exploits.csv into an in-memory CVE-to-exploit lookup.
│   │   ├── greynoise.py  Query GreyNoise Community API for internet scan activity on a CVE.
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
│   │   ├── generate_synthetic_data_v2.py  ═══════════════════════════════════════════════════════════════════════════
│   │   ├── generate_synthetic_findings.py  Ensure backend is importable
│   │   ├── ingest_docs.py  Size limits
│   │   ├── model_registry.json  564.0 B
│   │   ├── model_registry_epss.json  2.0 KB
│   │   ├── model_registry_pre_tier.json  407.0 B
│   │   ├── nvd_checkpoint.json  72.0 B
│   │   ├── nvd_cves_cached.json  79.6 MB
│   │   ├── pre_tier_metrics.json  1.7 KB
│   │   ├── pretier_features.py  ─── AGENCY DEFINITIONS ─────────────────────────────────────────────────────
│   │   ├── pretier_supplemental.json  205.9 KB
│   │   ├── pretier_training_data.json  37.0 KB
│   │   ├── README.md  TriageMate ML Artifacts
│   │   ├── reference_distributions.json  14.5 KB
│   │   ├── synthetic_data_v2.json  1.2 MB
│   │   ├── synthetic_findings_v4.json  343.7 KB
│   │   ├── synthetic_holdout_v2.json  232.8 KB
│   │   ├── threshold_info.json  78.0 B
│   │   ├── train_epss_substitutor.py  ── seed for reproducibility ──────────────────────────────────────────────
│   │   ├── train_epss_v2.py  ── seed for reproducibility ──────────────────────────────────────────────
│   │   ├── train_epss_v3.py  ── Constants (identical to v2 for drop-in compatibility) ──────────────────
│   │   ├── train_epss_v4.py  Ensure backend is importable
│   │   ├── train_pre_tier.py  ─── PATHS ──────────────────────────────────────────────────────────────────
│   │   ├── train_xgboost.py
│   │   ├── vector_store.py
│   │   └── xgboost_predictor.py  Default paths (fallbacks when registry is unavailable)
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
│   │   ├── ingest.py  Build template-based summary paragraphs matching demo row style.
│   │   ├── models.py  Read the model registry JSON file.
│   │   └── queue.py  )
│   ├── scripts/
│   │   ├── __init__.py
│   │   ├── aggregate_tenable_sectors.py  ═════════════════════════════════════════════════════════════════════════════
│   │   ├── build_cwe_hierarchy.py  Download cwec_latest.xml.zip and return contents as bytes.
│   │   ├── build_training_corpus.py  Bulletproof: find .env relative to this script, not CWD
│   │   ├── build_vendor_index.py
│   │   ├── compute_reference_dists.py  Extract only the 35 tabular features
│   │   ├── fetch_nvd_corpus.py  Bulletproof: find .env relative to this script, not CWD
│   │   ├── ingest_synthetic_to_db.py  Return the intersection of data keys with actual table columns,
│   │   ├── load_research_refs.py  Parse the pipe-delimited references table from Section 6.
│   │   ├── refresh_caches.py  Bulletproof: find .env relative to this script, not CWD
│   │   ├── stress_report.py  20.7 KB
│   │   └── validate_synthetic_data.py  ── Path setup: make ``backend/`` importable from ``backend/scripts/`` ──
│   ├── tests/
│   │   ├── load/
│   │   │   └── locustfile.py  Ensure analysis/stress_db is importable
│   │   ├── __init__.py
│   │   ├── conftest.py  Disable LLM API key before any app imports to prevent real API calls
│   │   ├── test_aggregate_sectors.py  Test suite for aggregate_findings().
│   │   ├── test_audit.py  Direct tests of the should_audit() function with controlled randomness.
│   │   ├── test_demo_generator.py  Structural Tests (6)
│   │   ├── test_drift.py  GET /api/drift smoke tests.
│   │   ├── test_drift_ml.py  Expected camelCase keys from the MlDriftResponse model
│   │   ├── test_epss_substitutor.py  Verify the module initialises without error and loads a model.
│   │   ├── test_feature_parity.py  ── Tabular feature keys in the EXACT order xgboost_predictor.predict() builds th
│   │   ├── test_feature_parity_epss.py  ── Test cases: (raw_epss, cvss_score, cisa_kev, cwe_class, agency,
│   │   ├── test_feature_parity_pretier.py  ── Expected contract ────────────────────────────────────────────────────────
│   │   ├── test_fuzzed_ingest.py  ── Mock responses for network-dependent pipeline functions ─────────────
│   │   ├── test_health.py  Health endpoint smoke tests.
│   │   ├── test_ingest.py  Remove any previously created test records before each ingest test.
│   │   ├── test_integration.py  Test the full ingest pipeline end-to-end.
│   │   ├── test_model_versions.py  ── Session-scoped save/restore to isolate tests ──────────────────────
│   │   ├── test_pre_tier.py  ── Helpers ──────────────────────────────────────────────────────────────────
│   │   ├── test_pretier_features.py  Return only nonzero feature entries from an extract_features() dict.
│   │   ├── test_queue.py  Expected priority scores in descending order (matching the seed data)
│   │   ├── test_rate_limit.py  Delete CVE-TEST-RL-* records from the database.
│   │   ├── test_review.py  Required keys for a review queue item (camelCase via ReviewQueueItem model)
│   │   ├── test_scoring.py  Core Sanity Tests
│   │   └── test_tier2.py  ── Shared test data ─────────────────────────────────────────────────────
│   ├── .coverage  52.0 KB
│   ├── .env  1009.0 B
│   ├── .env.example  2.0 KB
│   ├── __init__.py
│   ├── alembic.ini
│   ├── audit.py  Determine if a case should enter the audit pool.
│   ├── auth.py  Configuration
│   ├── database.py  Default SQLite database path (can be overridden by tests)
│   ├── ingest_cwe.py  Get CWE classification for a CVE.
│   ├── ingest_helpers.py  Look up the WAICP data classification for an asset.
│   ├── logging_config.py
│   ├── main.py  ─── Resolve project root from this file's location ────────────────────
│   ├── models.py  Convert snake_case to camelCase for API responses.
│   ├── pytest.ini  47.0 B
│   ├── requirements.txt  psycopg2-binary>=2.9.9
│   ├── scheduler.py  ).fetchall()
│   ├── scoring.py  Round to nearest int, .5 always rounds up (not banker's rounding).
│   ├── seed_data.py  Row 1: CVE-2023-34362 — MOVEit Transfer SQL Injection
│   ├── triagemate.db  156.0 KB
│   └── triagemate.db.backup  1.3 MB
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
│   │   ├── file-consolidation-plan-2026-07-07.md  .md File Consolidation Plan
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
│   │   ├── HANDOFF-2026-07-08.md  Handoff Document — 2026-07-08
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
│   └── index.html  10.7 KB
├── graphify_output/
│   ├── api_deps.md  TriageMate — API Dependency Map
│   ├── feature_parity.md  TriageMate — Feature Parity Report
│   ├── file_tree.md  TriageMate — File Tree
│   ├── knowledge_graph.json  11.4 KB
│   └── ml_inventory.md  TriageMate — ML Model Inventory
├── .dockerignore  328.0 B
├── .env.example  1.8 KB
├── .gitignore  587.0 B
├── .pre-commit-config.yaml  415.0 B
├── =2.2.0  1.0 KB
├── AGENTS.md  TriageMate Project Rules
├── AI_PROBLEMS.md  AI Problems — Discrepancies Found During Development
├── demo-reference.html  <!--
├── docker-compose.yml  1.9 KB
├── Dockerfile  1.4 KB
├── index.html  119.4 KB
├── justfile  7.6 KB
├── MVP_SCOPE.md  TriageMate MVP — Scope Document
├── opencode.jsonc  924.0 B
├── requirements-dev.txt  130.0 B
├── RESEARCH_FINDINGS.md  TriageMate — Sprint NEXT+2 Research Findings
├── ROADMAP.md  TriageMate — Master Roadmap & Status
├── triagemate.db  156.0 KB
├── WINDOWS_SETUP.md  TriageMate — Windows Setup Guide
└── XGBOOST_INVESTIGATION_REPORT.md  XGBoost Exploitation Model — Investigation Report
```
