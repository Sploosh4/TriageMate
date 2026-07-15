---
name: backend-engineering
description: Python, FastAPI, SQLite, database schema, pipeline logic, API endpoints, Pydantic models, scoring engine. Use when editing backend/ files, designing APIs, modifying the pipeline, or changing database schema.
---

# TriageMate Backend Engineering

## GitHub Workflow

Use the current assigned task workspace; never create or switch worktrees. Report the workspace path, branch, SHA, and verification evidence to the Commander; `git-steward` owns Git/GitHub lifecycle actions.

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
- `backend/ml/xgboost_predictor.py` — `CWE_EPSS_THRESHOLDS` dict (14 CWE-stratified EPSS thresholds), `DEFAULT_EPSS_THRESHOLD` (0.60), XGBoost prediction

### CWE-Stratified EPSS Thresholds
Defined in `backend/ml/xgboost_predictor.py` as `CWE_EPSS_THRESHOLDS`. These thresholds are used in two places:
1. **Tier 0 (xgboost_predictor.py `_tier_zero_check`):** If EPSS >= CWE-specific threshold, the vulnerability fast-path-escalates before XGBoost inference.
2. **Tier 0 (pipeline/tier_0.py):**
   - **Low-severity auto-resolve:** If CVSS < 4.0, not KEV, and EPSS < CWE-specific threshold, auto-resolve as low.
   - **KEV + Sensitive auto-resolve:** If KEV-listed, EPSS >= CWE-specific KEV threshold (from same dict), and OFFICIAL Sensitive, auto-resolve as very_critical.
3. **Tier 0 (pipeline/tier_0.py) — KEV bypass:** KEV-listed CVEs on OFFICIAL Sensitive assets use the CWE-stratified threshold instead of monolithic 0.90, so a CWE-22 KEV (threshold 0.085) can auto-resolve with EPSS as low as 0.085.

The default (unlisted CWE) uses `DEFAULT_EPSS_THRESHOLD = 0.60` (reduced from 0.84 in Sprint 18 for better recall). Methodology is documented in the dict's comment block and sourced from `backend/analysis/epss_eval.py`.

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
- New migrations are forward-only; never edit an applied revision.
- Verify a clean SQLite upgrade before sign-off. From `backend/`, use a fresh
  temporary database and require `alembic upgrade head` to exit successfully:

  ```bash
  tmpdir=$(mktemp -d /tmp/triagemate-alembic.XXXXXX)
  DATABASE_URL="sqlite:///$tmpdir/fresh.db" .venv/bin/alembic upgrade head
  DATABASE_URL="sqlite:///$tmpdir/fresh.db" .venv/bin/alembic current
  ```

- After an authorized push/PR update, require the self-hosted GitHub Actions
  checks to pass with `gh pr checks <pr-number> --watch`. Local tests alone do
  not verify the committed workflow revision; see `audit-checklist`.

## MCP Tool: db (SQLite)
A local MCP server registered in `opencode.jsonc` that provides direct read-only queries against `triagemate.db`. Use it for:
- Quick data validation after schema changes or scoring edits
- Checking cache contents, demo rows, or pipeline state
- Exploring the schema without opening a SQLite shell

Equivalent to `just db-shell` but callable inline by the LLM.

## Score Contract
The 7 demo rows must score within ±3 of: 99, 97, 74, 91, 82, 97, 80
(Source: `routers/models.py:89`, verified by `tests/test_model_versions.py:134`)

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
