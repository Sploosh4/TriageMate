# Bookkeeping Report — Freshness Pass

**Date:** 2026-07-08
**Trigger:** Sprint 14 — Research & Synthetic Data infrastructure
**Sprint additions audited:**
- New research report: `backend/reports/intel/wa-gov-infrastructure-research.md`
- New sprint plan: `.opencode/plans/2026-07-08-sprint-research-synthetic-data.md`
- New scripts: `ingest_synthetic_to_db.py`, `load_research_refs.py`, `validate_synthetic_data.py`
- New generator: `backend/ml/generate_synthetic_data_v2.py`
- New metrics: `backend/ml/pre_tier_metrics.json`
- New data files: `synthetic_data_v2.json`, `synthetic_holdout_v2.json`
- New DB tables: `synthetic_assets`, `synthetic_findings`, `research_references` (in `database.py`)
- Updated: `train_pre_tier.py` (added `--from-db` support)

---

## Auto-Fixed

| File | Fix | Before → After |
|------|-----|----------------|
| `docs/INDEX.md` line 33 | Sprint count stale | `13 completed, 1 in progress` → `14 completed` |

**Applied:** Sprint 14 is marked ✅ Complete in ROADMAP.md. INDEX.md still said "13 completed, 1 in progress" — corrected to match current state (Sprint 14 done, no sprints in progress).

---

## Items Flagged for Human Review

### P1 — Cross-file Contradictions / Missing Documentation

| # | File | Issue | Details |
|---|------|-------|---------|
| 1 | `docs/INDEX.md` | Missing research report entry | The new `backend/reports/intel/wa-gov-infrastructure-research.md` is not listed in INDEX.md. Should be added under a "Research" or "Intel Reports" section. |
| 2 | `docs/INDEX.md` | Missing Sprint 14 plan entry | The sprint plan `.opencode/plans/2026-07-08-sprint-research-synthetic-data.md` is not listed. INDEX.md's "Planning" table could reference it or note it under ROADMAP.md. |
| 3 | `docs/INDEX.md` | Missing new database tables | INDEX.md doesn't mention the new `synthetic_assets`, `synthetic_findings`, or `research_references` tables. Consider adding a brief note or cross-reference. |
| 4 | `.opencode/skills/ml-toolbox/SKILL.md` | Old script reference | Line 57 still references `python -m ml.generate_supplemental_hostnames` — this is the OLD script. The NEW generator is `generate_synthetic_data_v2.py`. Both exist, but the skill should mention both or replace the reference. |
| 5 | `.opencode/skills/ml-toolbox/SKILL.md` | Missing new commands | Does not document: `python -m ml.generate_synthetic_data_v2`, `python -m scripts.ingest_synthetic_to_db`, `python -m scripts.validate_synthetic_data`, `python -m scripts.load_research_refs`. |
| 6 | `.opencode/skills/ml-toolbox/SKILL.md` | Missing `--from-db` flag for pre-tier | `train-pretier` now supports `python -m ml.train_pre_tier --from-db` but this is not documented. |
| 7 | `.opencode/skills/ml-toolbox/SKILL.md` | File locations table stale | Missing entries for `synthetic_data_v2.json`, `synthetic_holdout_v2.json`, `pre_tier_metrics.json`. |
| 8 | `.opencode/skills/backend-engineering/SKILL.md` | Missing new tables | The skill describes the schema conventions and dual-DDL process but doesn't mention the new `synthetic_assets`, `synthetic_findings`, and `research_references` tables. Should document these under the Database section. |
| 9 | `backend/triagemate.db` | New tables missing | The database currently only contains `vulnerabilities` and `sqlite_sequence`. The `synthetic_assets`, `synthetic_findings`, and `research_references` tables defined in `database.py` were never created in the active database. The pre_tier model was retrained with `--from-db` (metrics confirm 1,476 training rows), so the tables existed previously but are now missing. **The triagemate.db may have been overwritten.** |

### P2 — Skill / CLI gaps

| # | File | Issue | Details |
|---|------|-------|---------|
| 10 | `.opencode/skills/triage-toolbox/SKILL.md` | No just commands for synthetic data | The skill lists ML training commands but has no entries for the synthetic data scripts (generate, ingest, validate, load-research). Also `train-pretier` doesn't document the `--from-db` option. |
| 11 | `justfile` | Missing just recipes | No `just` recipes for: `generate-synthetic-data`, `ingest-synthetic-data`, `validate-synthetic-data`, `load-research-refs`. The `just train-pretier` recipe does not pass `--from-db`. |
| 12 | `graphify_output/*.md` | Auto-generated artifacts stale | `file_tree.md` and `ml_inventory.md` don't reflect the new synthetic data files or scripts. Run `just graphify` to regenerate. |

### P3 — Minor / Non-urgent

| # | File | Issue | Details |
|---|------|-------|---------|
| 13 | `AGENTS.md` | Quick reference table incomplete | The quick reference table in AGENTS.md line 18-30 doesn't include a reference to the new research report (`backend/reports/intel/wa-gov-infrastructure-research.md`) despite the report being a major new knowledge artifact. |
| 14 | `backend/ml/generate_supplemental_hostnames.py` | Old file not removed | The sprint plan called for this file to be "rewritten" to `generate_synthetic_data_v2.py`. Instead, a new file was created and both coexist. The old file may still be useful (legacy training path) but its purpose should be documented, or it should be deprecated/archived. |

---

## Orphans Found

| Orphan | Referenced By | Type |
|--------|--------------|------|
| `research_references` table (empty/missing in DB) | Referenced by all 1827 rows in synthetic_assets validation | **Data gap** — 1539/1827 rows failed research traceability (Check 8 of validation). The `research_references` table does not currently exist in `triagemate.db`. References in the generator use `ref_id` patterns (e.g., `AGENCY-001, SOFTWARE-002`) that were never loaded into the database. |

---

## Coverage Gaps

| Feature / File | Missing From |
|----------------|-------------|
| `generate_synthetic_data_v2.py` | `ml-toolbox/SKILL.md`, `triage-toolbox/SKILL.md`, `justfile` |
| `ingest_synthetic_to_db.py` | `ml-toolbox/SKILL.md`, `triage-toolbox/SKILL.md`, `justfile` |
| `validate_synthetic_data.py` | `ml-toolbox/SKILL.md`, `triage-toolbox/SKILL.md`, `justfile` |
| `load_research_refs.py` | `ml-toolbox/SKILL.md`, `triage-toolbox/SKILL.md`, `justfile` |
| `pre_tier_metrics.json` | `ml-toolbox/SKILL.md` (file locations table) |
| `synthetic_data_v2.json` | `ml-toolbox/SKILL.md` (file locations table) |
| `synthetic_holdout_v2.json` | `ml-toolbox/SKILL.md` (file locations table) |
| `--from-db` option for `train_pre_tier.py` | `ml-toolbox/SKILL.md`, `triage-toolbox/SKILL.md`, `justfile` |
| `synthetic_assets` / `synthetic_findings` / `research_references` tables | `backend-engineering/SKILL.md` |
| `backend/reports/intel/wa-gov-infrastructure-research.md` | `docs/INDEX.md`, `AGENTS.md` |

---

## Cross-File Contradiction Scan

| Check | Result |
|-------|--------|
| INDEX.md vs ROADMAP.md — sprint count | ❌ **CONTRADICTION.** INDEX.md says "13 completed, 1 in progress" (line 33). ROADMAP.md shows 14 completed including Sprint 14 (line 28). **Auto-fixed in this round.** |
| ROADMAP.md vs sprint plan — Sprint 14 items | ✅ **Consistent.** ROADMAP.md §Sprint 14 accurately describes the synthetic data infrastructure, tables, and pre-tier retrain. |
| ROADMAP.md vs INDEX.md — pre-tier status | ✅ **Consistent.** Both show pre-tier as done/completed. |
| ROADMAP.md vs database.py — table count | ✅ **Consistent** on schema (3 new tables defined in both SQLite and PG DDL). ❌ **Data issue:** tables don't exist in the live database file. |
| ROADMAP.md vs ml-toolbox/SKILL.md — scripts | ❌ **Gap.** ROADMAP mentions the synthetic data infrastructure; skill files don't reference any of the new scripts. |

---

## Symlink Consistency Check

All 6 root-level `.md` symlinks checked:
- `ROADMAP.md` → `docs/planning/ROADMAP.md` ✅
- `AI_PROBLEMS.md` → `docs/reference/AI_PROBLEMS.md` ✅
- `MVP_SCOPE.md` → `docs/architecture/MVP_SCOPE.md` ✅
- `RESEARCH_FINDINGS.md` → `docs/research/RESEARCH_FINDINGS.md` ✅
- `WINDOWS_SETUP.md` → `docs/guides/WINDOWS_SETUP.md` ✅
- `XGBOOST_INVESTIGATION_REPORT.md` → `docs/reference/xgboost-investigation-report.md` ✅

All symlinks valid. No orphans.

---

## Data Integrity Issue — Research Traceability

The validation report (`backend/reports/audits/synthetic-data-validation-2026-07-08.md`) shows **Check 8 (Research Traceability) FAILED** for 1,539 of 1,827 rows (84.2%). The `research_references` table does not currently exist in `triagemate.db`. Investigation needed:

1. Was `load_research_refs.py` ever run?
2. Was the database reset after the tables were created?
3. If the `research_references` data was loaded but lost, the `load_research_refs.py` script should be re-run before the DB is shared/examined.

---

## Verdict

**NEEDS ATTENTION** — Multiple documentation gaps and one data integrity issue.

### Summary

| Category | Count | Criticality |
|----------|-------|-------------|
| Auto-fixed | 1 (INDEX.md sprint count) | P0 fix |
| P1 items | 9 (INDEX gaps, skill gaps, DB data issue) | High |
| P2 items | 3 (tooling/CLI gaps, stale graphify) | Medium |
| P3 items | 2 (AGENTS.md, old script coexistence) | Low |
| Contradictions resolved | 1 (INDEX.md vs ROADMAP.md) | ✅ |
| Remaining contradictions | 1 (ml-toolbox skill vs reality) | P1 gap |
| Data integrity | 1 (research_references table missing from DB) | P1 |

### Priority Actions

1. **🔴 Run `load_research_refs.py`** to populate the `research_references` table — the synthetic data validation failed on research traceability
2. **🔴 Re-initialize the database** so that `synthetic_assets`, `synthetic_findings`, and `research_references` tables are created
3. **🟡 Update `ml-toolbox/SKILL.md`** — add new scripts, file locations, and `--from-db` option
4. **🟡 Update `justfile` + `triage-toolbox/SKILL.md`** — add just recipes for synthetic data pipeline
5. **🟡 Update `backend-engineering/SKILL.md`** — document the three new tables and their schemas
6. **🟢 Update `docs/INDEX.md`** — add research report, sprint plan references, synthetic table notes
7. **🟢 Run `just graphify`** to refresh auto-generated artifacts
8. **🟢 Consider deprecating `generate_supplemental_hostnames.py`** or documenting both as dual paths
