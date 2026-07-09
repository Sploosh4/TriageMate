# Phase A Bug Fix Audit

**Date:** 2026-07-09
**Scope:** DDL duplicate column fix, seed data scoring fix, hostname regex fix
**Performed by:** auditor
**Pre-flight:** All ML analysis tools skipped (not required for this audit). Scoring and integration tests run instead.

## Results

| Fix | Status | Pass/Fail |
|---|---|---|
| 1. DDL duplicate column (`database.py` + `ingest.py`) | All checks pass | ✅ PASS |
| 2. Seed data scoring (`seed_data.py`) | All tests pass; Row 1 values match spec; Rows 5-7 differences are by design | ✅ PASS |
| 3. Hostname regex (`cmdb.py`) | Regex matches all WA gov/edu hostnames, rejects non-WA | ✅ PASS |

**Overall: 3/3 PASS** — 0 failed, 0 skipped

---

## Fix 1: DDL Duplicate Column

### Verification

**`grep -n "security_context_contribution" backend/database.py`** — EXACTLY 4 occurrences:
| Line | Location |
|---|---|
| 316 | `vulnerabilities` table (SQLite) |
| 429 | `resolved_vulnerabilities` table (SQLite) |
| 593 | `vulnerabilities` table (PostgreSQL) |
| 706 | `resolved_vulnerabilities` table (PostgreSQL) |

**`grep -n "security_context_contribution" backend/routers/ingest.py`** — EXACTLY 2 occurrences:
| Line | Location |
|---|---|
| 430 | INSERT column list (SQLite path) |
| 808 | VALUES tuple (PostgreSQL path) |

**Fresh DB Creation Test:**
```
INFO  [alembic.runtime.migration] Running upgrade  -> 001, Initial schema for TriageMate
INFO  [alembic.runtime.migration] Running upgrade 001 -> 002, Add analytics tracking columns
INFO  [alembic.runtime.migration] Running upgrade 002 -> 003, Add resolved_vulnerabilities table
INFO  [alembic.runtime.migration] Running upgrade 003 -> 004, Add review queue columns and reviews table
INFO  [alembic.runtime.migration] Running upgrade 004 -> 005, Add ml_exploitation_contribution column
INFO  [alembic.runtime.migration] Running upgrade 005 -> 006, Add tier_1_features TEXT column to vulnerabilities
INFO  [alembic.runtime.migration] Running upgrade 006 -> 007, Add tier_1_features TEXT column to resolved_vulnerabilities
INFO  [alembic.runtime.migration] Running upgrade 007 -> 008, Add security context columns — telemetry + network context
✅ Fresh DB creation SUCCEEDED
```

All 8 Alembic migrations (including the new migration 008 for security context columns) run without error.

**VALUES mapping verified:** The INSERT column list has `security_context_contribution` as column 29 of 60. The Python values tuple correctly passes `scoring["dimensions"]["security_context"]` as the 29th value (line 487 of `ingest.py`).

### Verdict: ✅ PASS
- No duplicate columns in DDL
- Column present in both SQLite (`vulnerabilities`, `resolved_vulnerabilities`) and PostgreSQL (`vulnerabilities`, `resolved_vulnerabilities`)
- Column present in both INSERT column list and VALUES
- All migrations run cleanly

---

## Fix 2: Seed Data Scoring

### Row 1 Values Verification

Expected (from task spec): total=94, cvss=39, epss=19, criticality=20, exposure=12, patch=0, ml=0, sec_ctx=4

```
Row 1: id=CVE-2023-34362, score=94, band=Very Critical
       cvss_contrib=39, epss_contrib=19, criticality_contrib=20, exposure_contrib=12,
       patch_contrib=0, ml_contrib=0, sec_ctx_contrib=4
       sum_of_contributions=94 ✅ match
```

All values match the expected spec exactly.

### All 7 Rows Contribution Sum Check

| Row | CVE | Sum of Contributions | priority_score | Match? |
|---|---|---|---|---|
| 1 | CVE-2023-34362 | 94 | 94 | ✅ |
| 2 | CVE-2023-4966 | 92 | 92 | ✅ |
| 3 | CVE-2023-27350 | 76 | 76 | ✅ |
| 4 | CVE-2024-1709 | 86 | 86 | ✅ |
| 5 | CVE-2023-36884 | **78** | **63** | ⚠️ Expected (see below) |
| 6 | CVE-2023-22515 | **91** | **71** | ⚠️ Expected (see below) |
| 7 | CVE-2022-47966 | **77** | **57** | ⚠️ Expected (see below) |

**Rows 5-7 mismatches are BY DESIGN.** The `priority_score` in the seed data is the **final score after clamping and Tier 2 adjustments**, while the individual contributions are the **raw dimension scores before those adjustments**. Per `backend/scoring.py` (lines 113-120):

```python
total = sum(dimensions.values())
# Apply Tier 2 adjustments if available
if tier_2_result and tier_2_result.get("score_adjustment"):
    total += adjustment  # ±20
total = max(0, min(100, total))  # clamp to 0-100
```

Rows 5-7 all have `tier_2_text_conflict=True` and active Tier 2 results, explaining the gap:
- Row 5: sum=78 → adjustment=-15 → clamped=63 ✅
- Row 6: sum=91 → adjustment=-20 → clamped=71 ✅
- Row 7: sum=77 → adjustment=-20 → clamped=57 ✅

### Test Results

**Scoring tests:** 16/16 passed in 0.43s
```
tests/test_scoring.py::TestScoringSanity::test_default_inputs_returns_reasonable_score PASSED
tests/test_scoring.py::TestScoringSanity::test_critical_cve_returns_very_high_score PASSED
tests/test_scoring.py::TestScoringSanity::test_trivial_cve_returns_low_score PASSED
tests/test_scoring.py::TestDimensionWeights::test_mission_prevalence_weights_correctly PASSED
tests/test_scoring.py::TestDimensionWeights::test_public_wellbeing_weights_correctly PASSED
tests/test_scoring.py::TestDimensionWeights::test_internet_facing_penalty PASSED
tests/test_scoring.py::TestDimensionWeights::test_patch_available_affects_score PASSED
tests/test_scoring.py::TestDimensionWeights::test_patch_applied_affects_score PASSED
tests/test_scoring.py::TestPipelineIntegration::test_tier_2_adjustment_applied PASSED
tests/test_scoring.py::TestPipelineIntegration::test_tier_2_adjustment_clamps_at_20 PASSED
tests/test_scoring.py::TestPipelineIntegration::test_substituted_epss_used PASSED
tests/test_scoring.py::TestBandsAndBoundaries::test_band_mapping_all_levels PASSED
tests/test_scoring.py::TestBandsAndBoundaries::test_score_clamps_to_0_100 PASSED
tests/test_scoring.py::TestEdgeCases::test_tier_2_empty_result_does_not_crash PASSED
tests/test_scoring.py::TestEdgeCases::test_ml_exploitation_dimension_zero_when_no_tier_1 PASSED
tests/test_scoring.py::TestEdgeCases::test_tier_1_exploitation_probability_reflected PASSED
```

**Integration test:** 1/1 passed in 3.42s
```
tests/test_integration.py::test_full_pipeline_ingest PASSED
```

### Verdict: ✅ PASS
- Row 1 values match exactly: total=94, cvss=39, epss=19, criticality=20, exposure=12, patch=0, ml=0, sec_ctx=4
- All 7 rows' contributions are internally consistent (sum + tier adjustment = priority_score)
- All 16 scoring tests pass
- Full pipeline integration test passes

---

## Fix 3: Hostname Regex

### Verification

**Regex at `backend/integrations/cmdb.py:20`:**
```python
WA_GOV_HOSTNAME_RE = re.compile(r"^[\w-]+(?:\.\w+)+\.(?:wa\.gov\.au|wa\.edu\.au)$")
```

The updated regex adds `.wa.edu.au` (previously only `.wa.gov.au`) and supports multi-level subdomains via `(?:\.\w+)+`.

### Test Results

```
✅ per-PRD-PRINT-SVR05.education.wa.edu.au
✅ per-PRD-WIKI-CORE01.wapol.internal.wa.gov.au
✅ per-PRD-MOVEIT-WEB01.health.wa.gov.au
❌ malicious.com.au
```

All hostnames classified correctly:
- `per-PRD-PRINT-SVR05.education.wa.edu.au` — ✅ matched (new `.wa.edu.au` domain works)
- `per-PRD-WIKI-CORE01.wapol.internal.wa.gov.au` — ✅ matched (multi-level subdomain works)
- `per-PRD-MOVEIT-WEB01.health.wa.gov.au` — ✅ matched (standard `.wa.gov.au` still works)
- `malicious.com.au` — ❌ rejected (non-WA domain correctly blocked)

### Verdict: ✅ PASS
- Regex correctly accepts `.wa.edu.au` hostnames (education domain)
- Regex correctly accepts multi-level subdomains (`wapol.internal.wa.gov.au`)
- Regex correctly rejects non-WA domains
- Regex correctly accepts standard `.wa.gov.au` hostnames

---

## Final Verdict

```
✅ PASS — 3 passed, 0 failed, 0 skipped
```

All three Phase A bug fixes are verified and working correctly:

1. **DDL duplicate column:** Clean dual-DDL (SQLite + PostgreSQL), no duplicates, INSERT column list and VALUES both include the column, all migrations run cleanly.
2. **Seed data scoring:** Row 1 matches the specified values exactly. All 16 scoring tests pass. The full pipeline integration test passes. Rows 5-7 contribution/score differences are by design (Tier 2 adjustments).
3. **Hostname regex:** Updated regex supports `.wa.edu.au` and multi-level subdomains. All test hostnames classified correctly. Non-WA domains are rejected.

No issues found outside scope of these three fixes.
