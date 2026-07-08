# Bookkeeping Report — Sprint 11 Freshness Pass

**Date:** 2026-07-08
**Trigger:** sprint-end (Sprint 11: Parallel Polish)
**Auditor:** bookkeeper

---

## Changes Verified

| Sprint Item | Files Touched | Docs Coverage |
|---|---|---|
| A: CI/CD pipeline expansion | `.github/workflows/ci.yml` | Partial — devops-engineering skill mentions `ci.yml` but no doc explains jobs/coverage threshold |
| B: Scoring engine tests | `backend/tests/test_scoring.py` (16 new tests) | **None** — zero .md references |
| C1: Dark mode | `frontend/css/triagemate.css` (58 new CSS vars, `[data-theme="dark"]`, theme toggle CSS) | **None** — zero .md references |
| C2: JS modernization | `frontend/js/*.js`, `frontend/js/components/*.js` (all 9 files, var→let/const) | **None** — zero .md references |
| D: Seed data ML dimension | `backend/seed_data.py` (6→7 fix), `backend/reports/seed-data-ml-dimension.md` (new verification report) | Partial — ROADMAP.md item 11 still shows 📋 Remaining |

---

## Auto-Fixed

None. The instructions explicitly said not to modify INDEX.md or ROADMAP.md directly — only report what needs updating.

---

## Items Flagged for Human Review

### P1 — ROADMAP.md missing Sprint 11 entirely

**File:** `docs/planning/ROADMAP.md`
**Issue:** The sprint status table (lines 12–24) ends at Sprint 10. Sprint 11 (Parallel Polish) is not present. All four work items completed:
- ✅ CI/CD pipeline expanded (Docker build, coverage, frontend-lint)
- ✅ Scoring engine tests (16 tests in `test_scoring.py`)
- ✅ Dark mode + JS modernization (theme toggle, 58 CSS vars, var→let/const in 9 files)
- ✅ Seed data ML dimension verification (bug found and fixed, report written)

**Recommended action:** Add Sprint 11 row to the sprint status table and a corresponding section describing the completed items.

---

### P1 — ROADMAP.md Sprint NEXT Item 4: CI/CD status stale

**File:** `docs/planning/ROADMAP.md` line 176
**Current text:**
```
| 4 | Rate limiting + CI/CD | 🟡 Partial | Rate limiting implemented and configurable via env vars. CI/CD (GitHub Actions) still pending. |
```
**Reality:** `.github/workflows/ci.yml` now exists with 4 jobs: `test` (matrix 3.11/3.12 with coverage), `frontend-lint` (Node.js syntax check), `lint-only` (ruff), `docker-build` (Dockerfile verification).

**Recommended action:** Change status to ✅ Done and update the note to describe the actual CI pipeline.

---

### P2 — ROADMAP.md Sprint NEXT+ Wave 1 Item 11: complete but marked 📋

**File:** `docs/planning/ROADMAP.md` line 205
**Current text:**
```
| 11 | **Seed data ML dimension** | 30 min | 📋 Remaining — verify ml_exploitation_contribution in demo rows |
```
**Reality:** Completed in Sprint 11 Item D. Bug found (CVE-2023-36884 had 6 instead of 7), fix applied to `seed_data.py`, verification report produced at `backend/reports/seed-data-ml-dimension.md`.

**Recommended action:** Change status to ✅ Done and add a note referencing the verification report.

---

### P2 — INDEX.md stale sprint count

**File:** `docs/INDEX.md` line 33
**Current text:**
```
| `planning/ROADMAP.md` | CURRENT | Master roadmap + sprint history + next actions. All 9 sprints tracked. |
```
**Reality:** The ROADMAP.md sprint status table now shows 11 entries (Sprint 1–3, Course Correction, Sprint 4–10). With Sprint 11 to be added, this number will be 12 entries.

**Recommended action:** Update to something dynamic like "All 10 completed sprints tracked" or remove the count entirely to avoid future staleness.

---

### P2 — Dark mode has zero documentation coverage

**Files affected:**
- `docs/INDEX.md` — No entry or question about dark mode
- `docs/architecture/MVP_SCOPE.md` — Line 162 lists dark mode as "out of scope" (appropriate for an OUTDATED MVP doc, but should note it's now done)
- `.opencode/skills/frontend-engineering/SKILL.md` — No mention of theme toggle, dark mode CSS variables, or `[data-theme="dark"]` block
- `.opencode/skills/ux-designing/SKILL.md` — No mention of dark mode design decisions

**Recommended action:** Either add a brief mention in the frontend-engineering skill or create an INDEX.md query for dark mode. The MVP_SCOPE.md note is fine as-is (it's an OUTDATED document).

---

### P3 — test_scoring.py not referenced in any .md file

**File:** `backend/tests/test_scoring.py` (422 lines, 16 tests)
**Issue:** No .md file mentions this test file. The test count in the sprint plan was "12+ tests" — the actual file has 16 tests across 5 test classes.

**Recommended action:** Minor — consider adding a mention in the ROADMAP.md Sprint 11 section if one is created, or in the frontend-engineering/backend-engineering skill files.

---

### P3 — CI coverage threshold not documented

**File:** `.github/workflows/ci.yml` line 33
**Issue:** `--cov-fail-under=60` enforces a 60% coverage floor, but this threshold is not documented in any .md file. Only the sprint plan (`2026-07-08-sprint-parallel-polish.md`) mentions it.

**Recommended action:** Optional — add a note in devops-engineering skill or ROADMAP.md about the coverage gate.

---

### P3 — INDEX.md missing entry for seed data verification report

**File:** `backend/reports/seed-data-ml-dimension.md` (111 lines, comprehensive ML dimension verification)
**Issue:** This verification report is not referenced in `docs/INDEX.md`. It lives under `backend/reports/` which is not in the INDEX.md directory tree.

**Recommended action:** Either add a `Reports` section to INDEX.md, or note that `backend/reports/` is auto-discoverable. Minor — the report is a one-time verification artifact.

---

## Orphans Found

None. All 6 root-level symlinks are intact and point to correct `docs/` targets:

| Symlink | Target | Status |
|---|---|---|
| `ROADMAP.md` | `docs/planning/ROADMAP.md` | ✅ |
| `AI_PROBLEMS.md` | `docs/reference/AI_PROBLEMS.md` | ✅ |
| `MVP_SCOPE.md` | `docs/architecture/MVP_SCOPE.md` | ✅ |
| `WINDOWS_SETUP.md` | `docs/guides/WINDOWS_SETUP.md` | ✅ |
| `RESEARCH_FINDINGS.md` | `docs/research/RESEARCH_FINDINGS.md` | ✅ |
| `XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/xgboost-investigation-report.md` | ✅ |

No orphaned file references detected. All skill files are internally consistent.

---

## Cross-Reference Check Passed

All verified:
- `Related Skills` sections in skill files point to existing skills
- `docs/INDEX.md` cross-references all resolve to existing files
- `AGENTS.md` Quick Reference table is accurate
- No dead links in CURRENT documentation

---

## Coverage Gaps Summary

| Gap | Severity | Details |
|---|---|---|
| Sprint 11 not in ROADMAP.md | P1 | Major omission — entire sprint undocumented |
| CI/CD status stale in ROADMAP.md | P1 | Still says "pending" when CI exists |
| Seed data item status stale in ROADMAP.md | P2 | Still says "📋 Remaining" when completed |
| Dark mode undocumented | P2 | Zero .md coverage for major frontend feature |
| test_scoring.py unreferenced | P3 | 16 tests but no doc mentions them |
| CI coverage threshold undocumented | P3 | `--cov-fail-under=60` not in any .md |
| INDEX.md stale sprint count | P2 | Says "9" but should be "10+" |
| INDEX.md missing seed data report | P3 | Verification report not listed |

---

## Verdict

**NEEDS ATTENTION** — Two P1 contradictions found:
1. ROADMAP.md has no Sprint 11 section (most critical — the sprint is invisible in project docs)
2. ROADMAP.md says "CI/CD still pending" when CI pipeline is fully operational with 4 jobs

Both are cross-file contradictions (ROADMAP vs. reality), which are the highest-value findings per the audit checklist. Fixing these two items should be prioritized before the next sprint begins.

### Freshness score: 6/10
- Symlink integrity: ✅ Perfect
- Skill file consistency: ✅ Good
- ROADMAP.md completeness: ❌ Missing entire sprint
- INDEX.md accuracy: ⚠️ Minor count error
- Feature documentation: ⚠️ Major gap (dark mode, CI, tests)
