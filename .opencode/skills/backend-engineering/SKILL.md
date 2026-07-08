---
name: backend-engineering
description: Python, FastAPI, SQLite, database schema, pipeline logic, API endpoints, Pydantic models, scoring engine. Use when editing backend/ files, designing APIs, modifying the pipeline, or changing database schema.
---

# TriageMate Backend Engineering

## Stack
- Python 3.12 with type hints
- FastAPI framework: routers, middleware, dependency injection, Pydantic v2 models
- SQLite (dev) / PostgreSQL (production via DATABASE_URL)
- Four-stage pipeline: Pre-Tier → Tier 0 → Tier 1 → Tier 2

## Pipeline Architecture
```
Pre-Tier: hostname dictionary → mission/public-wellbeing tags
Tier 0:   deterministic rules → auto-resolve or escalate
Tier 1:   XGBoost exploitation probability predictor.
          → See `graphify_output/ml_inventory.md` §Tier 1 for current model metrics.
          → See `graphify_output/feature_parity.md` for inference/training parity status.
Tier 2:   Cloud LLM (force-reflection prompt, multi-provider failover)
Scoring:  6-dimension weighted formula (CVSS, EPSS, Asset Criticality, Exposure, Patch, ML Exploitation) → 0-100
```

## Key Files
- `backend/database.py` — `get_db()` connection manager, dual DDL (SQLite + PostgreSQL)
- `backend/models.py` — Pydantic schemas
- `backend/scoring.py` — Priority score calculator
- `backend/pipeline/pre_tier.py` — Mission tag assignment
- `backend/pipeline/tier_0.py` — Deterministic routing rules
- `backend/pipeline/tier_1.py` — XGBoost exploitation probability
- `backend/pipeline/tier_2.py` — Cloud LLM conflict resolution
- `backend/ingest_helpers.py` — `build_feature_vector()`, CWE lookups
- `backend/routers/` — API endpoint routers (auth, cases, ingest, models, queue)

## Conventions
- Database access: always use `get_db()` — never create new connection paths
- Models: Pydantic v2 in `backend/models.py` or the relevant router file
- Imports: match existing patterns in neighboring files
- Logging: use `backend/logging_config.py` for JSON-structured logs

## Dual Database DDL

Every schema change in `database.py` requires entries in **both** `_init_db_sqlite()` and `_init_db_pg()`.

### Steps
1. Open `backend/database.py`
2. Locate the `vulnerabilities` table in `_init_db_sqlite()`
3. Add your new column there with SQLite-compatible type
4. Locate the identical table in `_init_db_pg()`
5. Add the matching column there with PostgreSQL-compatible type
6. Repeat for `resolved_vulnerabilities` table in both methods
7. Also add to the migration helper list at the bottom of each method if this is a post-MVP column

### Type mapping
| SQLite     | PostgreSQL          |
|------------|---------------------|
| INTEGER    | SERIAL (PK) / INTEGER |
| REAL       | REAL                |
| TEXT       | TEXT / VARCHAR(n)   |
| BOOLEAN    | BOOLEAN             |
| TIMESTAMP  | TIMESTAMP           |

### Checklist
- Column added to `_init_db_sqlite()` → `vulnerabilities`
- Column added to `_init_db_pg()` → `vulnerabilities`
- Column added to `_init_db_sqlite()` → `resolved_vulnerabilities`
- Column added to `_init_db_pg()` → `resolved_vulnerabilities`
- Types match across both dialects

## MCP Tool: db (SQLite)
A local MCP server registered in `opencode.jsonc` that provides direct read-only queries against `triagemate.db`. Use it for:
- Quick data validation after schema changes or scoring edits
- Checking cache contents, demo rows, or pipeline state
- Exploring the schema without opening a SQLite shell

Equivalent to `just db-shell` but callable inline by the LLM.

## Score Contract
The 7 demo rows must score within ±3 of: 94, 87, 71, 63, 55, 41, 22

## Database Tables (Sprint 14+)

Three new tables were added during Sprint 14 for synthetic data and research reference management:

### `synthetic_assets`
- **Rows:** 1,827
- **Purpose:** Holds synthetic WA Government hostnames with probabilistic labels for Pre-Tier model training
- **Key columns:** `hostname` (UNIQUE), `agency`, `agency_domain`, `system_name`, `environment`, `os_platform`, `role`, `network_zone`, `is_internet_facing`, `is_dc`, `in_holdout`, `mission_prevalence`, `public_wellbeing_impact`, `confidence_mp`, `confidence_wi`, `source_research_ref`, `generated_at`, `validation_status`, `validation_errors`
- **Populated by:** `python -m ml.generate_synthetic_data_v2`
- **Consumed by:** `ml.train_pre_tier` (with `--from-db` flag)

### `synthetic_findings`
- **Rows:** 777
- **Purpose:** Maps synthetic hosts to vulnerabilities with realistic exploitation likelihoods; designed for EPSS v4 sector-aware training
- **Key columns:** (host_id, vulnerability_id, exploitation_likelihood, etc.)
- **Populated by:** `python -m ml.generate_synthetic_findings`
- **Consumed by:** `ml.train_epss_v4`

### `research_references`
- **Rows:** 97
- **Purpose:** WA Government ICT research reference corpus — agency inventories, software profiles, hostname conventions, methodology citations
- **Key columns:** `ref_id`, `category` (AGENCY/SOFTWARE/SYSTEM/SECTOR), `title`, `description`, `source`, `reference_url`, `created_at`
- **Populated by:** `python -m scripts.load_research_refs`
- **Source report:** `backend/reports/intel/wa-gov-infrastructure-research.md`

### Feature Index 59 — `system_category` (replaces `has_known_system`)
- Feature index 59 in the Pre-Tier 60-dim feature vector uses `system_category` (ordinal 0-8) instead of the binary `has_known_system`
- Categorises system names into functional categories (e.g., infrastructure, security, database, application, network, storage, identity, end-user, general)
- See `backend/ml/pretier_features.py` for the `get_system_category()` mapping function

### Dual DDL pattern
Each of these tables was added to **both** `_init_db_sqlite()` and `_init_db_pg()` in `backend/database.py`. The synthetic tables (`synthetic_assets`, `synthetic_findings`, `research_references`) are created with `CREATE TABLE IF NOT EXISTS`.

## Related Skills
- `ml-engineering` — when touching build_feature_vector(), feature vector contracts, training, or ML models
- `new-integration-pattern` — when adding a new enrichment source
