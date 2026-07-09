# Sprint 17 WIP Audit — Database Accessibility, MCP Compatibility, Missed/Outdated Patterns

**Date:** 2026-07-09
**Scope:** Sprint 17 work-in-progress — DB schema, MCP tooling, implementation completeness, pattern adherence
**Performed by:** auditor
**Pre-flight:** All checks completed. Tests in `test_scoring.py` pass (16/16). Synthetic tables populated. No ML dependencies required.

---

## Results Summary

| # | Check | Result |
|---|-------|--------|
| 1 | Database MCP accessibility | **PASS** |
| 2 | MCP SQL tools can query synthetic tables | **PASS** |
| 3 | Synthetic tables populated | **PASS** |
| 4 | Alembic migration 008 applied to DB | **FAIL** |
| 5 | DDL applied to BOTH SQLite and PG methods | **PASS** |
| 6 | Sprint 17 implementation completeness | **WARN** (~30% done) |
| 7 | Existing JSON column reuse opportunity | **PASS** |
| 8 | Test contract (dimension count) | **FAIL** (not yet updated) |
| 9 | MCP configuration explicit in project | **WARN** |

**Verdict: FAIL WITH ISSUES** — 6 passed, 3 failed, 2 warned. The DDL is correct in code but not applied to the live database. 70% of Sprint 17 scope is still unimplemented. Tests will break once the pipeline code changes.

---

## Check 1: Database MCP Accessibility

**Result: PASS**

- Database file exists at `backend/triagemate.db` (847 KB, last modified Jul 9 17:55)
- Project root has a symlink: `triagemate.db -> backend/triagemate.db`
- The MCP SQLite tools (`db_sqlite_all`, `db_sqlite_get`, `db_sqlite_run`) connect successfully to this database
- Database contains 8 tables: `alembic_version`, `research_references`, `resolved_vulnerabilities`, `reviews`, `sqlite_sequence`, `synthetic_assets`, `synthetic_findings`, `vulnerabilities`

## Check 2: MCP SQL Tools Query Capabilities

**Result: PASS**

All three MCP SQL tools work correctly against the database:
- `db_sqlite_all` — returns all rows as array of objects
- `db_sqlite_get` — returns first row as object
- `db_sqlite_run` — executes mutations

The MCP database path is: `/home/jpc/Documents/Cybersecurity (Temp)/TriageMate/TriageMate MVP/backend/triagemate.db`

## Check 3: Synthetic Tables Populated

**Result: PASS**

| Table | Rows | Status |
|-------|------|--------|
| `synthetic_assets` | 1,827 | ✅ Populated with WA-government-style hostnames |
| `synthetic_findings` | 777 | ✅ CVE data across agencies |
| `research_references` | 97 | ✅ Agency, software, OS references |

Sample data shows realistic WA government conventions (e.g., `health.wa.gov.au`, `education.wa.edu.au`, etc.) with consistent agency domains.

## Check 4: Alembic Migration 008 Applied

**Result: FAIL**

- `alembic_version` table shows **007** — migration 008 has NOT been run
- `telemetry_json` and `network_context_json` columns are **MISSING** from both `vulnerabilities` and `resolved_vulnerabilities` tables in the live database
- The migration file exists at `backend/alembic/versions/008_add_security_context_columns.py` (created Jul 9 17:56) with correct content
- The `database.py` DDL has the columns in both SQLite and PG methods (see Check 5)

**What needs to happen:** User must run `alembic upgrade head` in `backend/` directory.

```bash
cd backend && alembic upgrade head
```

Then verify:
```bash
python3 -c "from database import get_db; db=get_db(); cols=db.execute('PRAGMA table_info(vulnerabilities)').fetchall(); print([c[1] for c in cols if 'telemetry' in c[1] or 'network_context' in c[1]])"
# Expected: ['telemetry_json', 'network_context_json']
```

## Check 5: DDL Applied to Both SQLite and PG Methods

**Result: PASS**

- `telemetry_json`: 4 occurrences in `database.py` ✓ (SQLite `vulnerabilities` + PG `vulnerabilities` + SQLite `resolved_vulnerabilities` + PG `resolved_vulnerabilities`)
- `network_context_json`: 4 occurrences ✓ (same pattern)
- Both columns are at the same structural position (after `tier_1_features`, before closing parens) in both dialect methods
- Column types match: `TEXT` in SQLite, `TEXT` in PostgreSQL (correct mapping)

## Check 6: Sprint 17 Implementation Completeness

**Result: WARN** — approximately 30% complete

| Phase | Status | Files |
|-------|--------|-------|
| Phase 1: Database DDL | ✅ DDL in code | `database.py` — done |
| Phase 1: Alembic migration | ✅ File exists, ⛔ NOT APPLIED | `008_add_security_context_columns.py` — exists |
| Phase 2: synthetic_telemetry.py | ✅ Complete | `integrations/synthetic_telemetry.py` — 11,152 bytes, created Jul 9 18:01 |
| Phase 2: network_context.py | ✅ Complete | `integrations/network_context.py` — 6,271 bytes, created Jul 9 18:00 |
| Phase 3: Pipeline (scoring.py) | ❌ Not started | No `security_context` dimension, no `telemetry_threat_score` param |
| Phase 3: Pipeline (ingest_helpers.py) | ❌ Not started | No `telemetry_threat_score` / `network_blast_radius` in feature vectors |
| Phase 3: Pipeline (routers/ingest.py) | ❌ Not started | No calls to `get_telemetry_context()` or `get_network_context()` |
| Phase 3: Pipeline (models.py) | ❌ Not started | No `telemetry` or `network_context` in `CaseViewData` |
| Phase 3: Pipeline (routers/cases.py) | ❌ Not started | No JSON parsing for the new columns |
| Phase 4: Frontend (panel 5) | ❌ Not started | No `#panel-5`, no `renderPanel5()`, no CSS classes |
| Phase 5: Seed data | ❌ Not started | No telemetry/network_context in seed data |
| Phase 5: Test updates | ❌ Not started | `test_scoring.py` still asserts `len(dimensions) == 6` |
| Phase 5: Test updates | ❌ Not started | `test_queue.py` has no `EXPECTED_PRIORITY_SCORES` found |
| Phase 6: Quality gate | ❌ Not started | |

**The completed integration modules look well-structured:**
- `synthetic_telemetry.py` uses deterministic seeding via `hashlib.sha256(f"{cve_id}:{hostname}:telemetry".encode())` for reproducibility
- Generates realistic Sentinel incidents, EDR alerts, process evidence, and threat scores
- `network_context.py` queries `synthetic_assets` for peers with heuristic fallback
- Both modules have proper `try/except` patterns and always return safe defaults

## Check 7: Existing JSON Column Reuse Opportunity

**Result: PASS**

Existing JSON/context columns in `vulnerabilities`:
- `mitre_techniques_json` — stores MITRE ATT&CK techniques
- `scoring_weights_json` — dimension weights
- `asset_registry_json` — asset registry data
- `summary_paragraphs_json` — prose summaries
- `data_classification` — TEXT (not JSON)

None of these are appropriate for storing telemetry or network context. Using dedicated columns (`telemetry_json`, `network_context_json`) is the correct pattern — it maintains clear separation of concerns and avoids JSON key collision risks. No missed reuse opportunity.

## Check 8: Test Contract — Dimension Count

**Result: FAIL**

`backend/tests/test_scoring.py` line 41:
```python
assert len(result["dimensions"]) == 6
```

This will break when the 7th dimension (`security_context`) is added to `calculate_final_score()`. The test currently passes because no pipeline code has been changed yet.

**What needs to happen:** Update to `== 7` as part of Phase 5 implementation.

Also required (per Sprint 17 plan):
- `backend/tests/test_queue.py`: Update `EXPECTED_PRIORITY_SCORES` (new expected: `[99, 91, 73, 66, 56, 43, 23]`)
- `backend/tests/test_model_versions.py`: Update baseline scores
- `backend/tests/test_integration.py` line 114: Update "6 dimensions" reference to 7

## Check 9: MCP Configuration Explicit in Project

**Result: WARN**

- No `.opencode.jsonc` file exists in the project root directory
- The global config at `/home/jpc/.config/opencode/opencode.jsonc` contains only basic plugin/LSP settings — no MCP SQLite server configuration
- The MCP SQLite tools are available (they work), but there is no explicit configuration documenting WHICH database they connect to

**Issue:** If another developer clones this project, they won't know that MCP SQLite tools are configured or which database they target. The configuration appears to be provided implicitly by the infrastructure layer.

**Recommendation:** Add an explicit `.opencode.jsonc` at project root with the MCP SQLite configuration pointing to `backend/triagemate.db`. This preserves the working setup in version control.

---

## Sprint 17 Score Impact Preview

Current demo scores (no Sprint 17 changes applied):

| ID | CVE | Host | Score | Band |
|----|-----|------|-------|------|
| 1 | CVE-2023-34362 | MOVEit | **94** | Very Critical |
| 2 | CVE-2023-4966 | Citrix ADC | **87** | Very Critical |
| 3 | CVE-2023-27350 | PaperCut | **71** | Critical |
| 4 | CVE-2024-1709 | ScreenConnect | **63** | Critical |
| 5 | CVE-2023-36884 | Office | **55** | Critical |
| 6 | CVE-2023-22515 | Confluence | **41** | Medium |
| 7 | CVE-2022-47966 | ManageEngine | **22** | Low |

Expected new scores (from Sprint 17 plan): `[99, 91, 73, 66, 56, 43, 23]` — these are estimates that will be computed at seed time.

---

## Findings Summary

1. **FAIL — Migration 008 not applied:** `alembic_version` at 007. `telemetry_json` and `network_context_json` columns do not exist in the live database. Run `alembic upgrade head`.

2. **FAIL — Test dimension count:** `test_scoring.py:41` asserts `len(dimensions) == 6`. Must update to `== 7` when the 7th dimension is added.

3. **WARN — Implementation only ~30% complete:** Phases 3-6 not started. Integration modules (Phase 2) are complete and well-structured. Pipeline, frontend, seed data, and tests remain.

4. **WARN — No MCP configuration in source control:** The SQLite MCP tools work but have no explicit config file at project level. Add `.opencode.jsonc` to document the setup.

5. **PASS — DDL parity between SQLite and PostgreSQL:** Both methods have identical column definitions for the new telemetry/network context columns.

6. **PASS — No missed reuse opportunity:** Existing JSON columns are inappropriate for telemetry/network data. New columns are the correct approach.

## Verdict

**FAIL WITH ISSUES** — 6 passed, 2 failed, 2 warned

### What needs fixing (immediate):
1. **Run `alembic upgrade head`** — the DB schema is out of sync with the code. This is the user-actionable item from Sprint 17 Phase 1.
2. **Update `test_scoring.py` line 41** — change `len(dimensions) == 6` to `== 7` once the 7th dimension is implemented.

### What's needed to complete Sprint 17:
- Phases 3-6 require a strike agent to implement: scoring.py, ingest_helpers.py, routers/ingest.py, models.py, routers/cases.py, frontend (panel 5 HTML/CSS/JS), seed_data.py, and test updates.
- Add `.opencode.jsonc` MCP config to document the SQLite tool setup.
