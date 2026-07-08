# Bookkeeping Report — Sprint 12 Freshness Pass

**Date:** 2026-07-08
**Trigger:** Sprint 12 — Gap Hardening (Item 3)
**Auditor:** bookkeeper
**Scope:** Documentation freshness audit of all active `.md` files, symlinks, sprint deliverables, and cross-references

---

## 1. Sprint 12 Deliverables Verification

| Item | Description | Status | Evidence |
|------|-------------|--------|----------|
| **Item 1** | SKILL.md line 34 router list fix | ✅ **FIXED** | Line 34 reads `(auth, cases, ingest, models, queue)` — matches actual router files (`auth.py`, `cases.py`, `ingest.py`, `models.py`, `queue.py` in `backend/routers/`) |
| **Item 2** | EPSS retrain assessment report | ✅ **EXISTS** | `backend/reports/intel/epss-retrain-assessment.md` — 346 lines, comprehensive analysis |
| **Item 3** | This bookkeeping report | ✅ **IN PROGRESS** | Being written now |

## 2. Files Checked — Status Table

| # | File | Status | Notes |
|---|------|--------|-------|
| 1 | `docs/INDEX.md` | **CURRENT** | All active docs listed; status badges accurate; AI_PROBLEMS.md noted as "1 unfixed issue (#14, won't-fix)" ✅ |
| 2 | `docs/planning/ROADMAP.md` | **CURRENT** ⚠️ | See §4 for minor notes (Sprint 12 not in sprint table; Item 17 could reference assessment) |
| 3 | `docs/reference/AI_PROBLEMS.md` | **CURRENT** | 1 unfixed issue (#14, WON'T FIX) — matches INDEX.md claim ✅ |
| 4 | `.opencode/skills/backend-engineering/SKILL.md` | **CURRENT** ✅ | Line 34 fixed: `(auth, cases, ingest, models, queue)` — Sprint 12 Item 1 delivered |
| 5 | `.opencode/plans/2026-07-08-sprint-12.md` | **CURRENT** | Sprint plan exists, consistent with deliverables, acceptance criteria clear |
| 6 | `docs/planning/ai-doc-strategy-2026-07-07.md` | **CURRENT** | Inventory counts accurate; stale references previously flagged (e.g., SPRINT_NEXT_PLAN path) now match current state |
| 7 | `docs/planning/file-consolidation-plan-2026-07-07.md` | **CURRENT** | Header note explains pre-consolidation state; no new discrepancies |
| 8 | `docs/research/RESEARCH_FINDINGS.md` | **CURRENT** | Exists on disk ✅ |
| 9 | `docs/architecture/MVP_SCOPE.md` | **OUTDATED** (as declared) | CAUTION banner present; correctly marked OUTDATED in INDEX.md ✅ |
| 10 | `docs/reference/hostname-standards.md` | **CURRENT** | Exists on disk ✅ |
| 11 | `docs/reference/xgboost-investigation-report.md` | **CURRENT** | Exists on disk ✅ |
| 12 | `docs/guides/WINDOWS_SETUP.md` | **CURRENT** | Exists on disk ✅ |
| 13 | `backend/ml/README.md` | **CURRENT** | Exists on disk; listed in INDEX.md line 45 ✅ |

## 3. Root-Level Symlinks — All Valid ✅

| Symlink | Target | Status |
|---------|--------|--------|
| `ROADMAP.md` | `docs/planning/ROADMAP.md` | ✅ |
| `AI_PROBLEMS.md` | `docs/reference/AI_PROBLEMS.md` | ✅ |
| `MVP_SCOPE.md` | `docs/architecture/MVP_SCOPE.md` | ✅ |
| `WINDOWS_SETUP.md` | `docs/guides/WINDOWS_SETUP.md` | ✅ |
| `RESEARCH_FINDINGS.md` | `docs/research/RESEARCH_FINDINGS.md` | ✅ |
| `XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/xgboost-investigation-report.md` | ✅ |

**No stale/broken symlinks.** All 6 resolve correctly. Previously removed broken symlinks (`DEMO_SCRIPT.md`, `TRIAGEMATE_BOOK_PROMPT.md`) remain absent.

## 4. Discrepancies Found

### 4.1 ROADMAP.md — Sprint 12 Not in Sprint Table
- **File:** `docs/planning/ROADMAP.md`, lines 12–26
- **Issue:** The sprint status table lists Sprints 1–11 but not Sprint 12 (active today, 8 July 2026).
- **Severity:** 🟡 **Minor** — Expected for an in-progress sprint. ROADMAP will be updated at sprint completion. No action needed now.

### 4.2 ROADMAP.md — Item 17 Status Could Reference Assessment Report
- **File:** `docs/planning/ROADMAP.md`, line 226
- **Issue:** Item 17 ("EPSS substitution retrain") status is "📋 Remaining" with no note that the EPSS retrain assessment is now complete at `backend/reports/intel/epss-retrain-assessment.md`. The assessment provides a phased path forward (Tenable aggregation → WASOC data → v4 model).
- **Severity:** 🟢 **Cosmetic recommendation** — The retrain itself is still remaining, so "📋 Remaining" is technically correct. However, adding a note referencing the assessment report would improve traceability.
- **Recommendation:** After this sprint closes, consider updating the Item 17 status or adding a note like: "🔎 Assessed — see `backend/reports/intel/epss-retrain-assessment.md`"

### 4.3 file-consolidation-plan.md — Stale Proposal Content (Pre-Existing, Not a New Issue)
- **File:** `docs/planning/file-consolidation-plan-2026-07-07.md`
- **Issue:** This document is a consolidation *proposal* that references future merges (e.g., creating ARCHITECTURE.md, ML_GUIDE.md, etc.) that were never executed. Some proposed archive/move actions were not carried out (e.g., AI_PROBLEMS.md was not archived, MVP_SCOPE.md was not replaced by ARCHITECTURE.md).
- **Severity:** 🟢 **Pre-existing** — The file is correctly marked CURRENT as a planning document. Its header note ("This state map reflects the pre-consolidation state") clarifies its temporal context. No action needed.

## 5. Cross-Reference Verification

| Check | Result |
|-------|--------|
| INDEX.md vs actual file tree | ✅ All active docs/ files listed; status badges match |
| ROADMAP.md API endpoints table | ✅ Model management endpoints (3) listed correctly |
| ROADMAP.md vs AI_PROBLEMS.md bug count | ✅ Both agree: 1 unfixed issue (#14) |
| SKILL.md router list vs filesystem | ✅ `(auth, cases, ingest, models, queue)` matches actual `backend/routers/` contents |
| INDEX.md AI_PROBLEMS.md description ("1 unfixed issue") | ✅ Matches — Issue #14 is the only unfixed |
| Graphify outputs existence | ✅ All 5 files present under `graphify_output/` |
| `backend/ml/README.md` referenced in INDEX.md | ✅ Exists on disk |
| `docs/archive/SPRINT_NEXT_PLAN.md` references in CURRENT docs | ✅ ROADMAP.md correctly says "archived"; INDEX.md marks ARCHIVED |

## 6. Orphan Detection

| Check | Result |
|-------|--------|
| Archived files referenced by CURRENT docs? | ✅ All references are intentional (SPRINT_NEXT_PLAN.md in ROADMAP, INDEX — marked ARCHIVED) |
| Skill files referenced by others? | ✅ All skills in `Related Skills` sections point to existing skill files |
| Agent `Loadable Skills` references? | ✅ All skills listed in AGENTS.md system prompt exist on disk |

**No orphans found.**

## 7. Coverage Check — Sprint 12 Additions

| New Artifact | Needs INDEX.md Entry? | Notes |
|-------------|----------------------|-------|
| `backend/reports/intel/epss-retrain-assessment.md` | ❌ No | Research artifact under `backend/reports/`, not project documentation under `docs/`. Lives outside the INDEX.md scope. |
| `backend/reports/bookkeeping/2026-07-08-sprint-12-freshness.md` (this file) | ❌ No | Bookkeeping reports are operational artifacts, not project documentation. |
| `backend-engineering/SKILL.md` edit (line 34) | N/A | In-place edit to existing file; no new file created. |

## 8. Verdict

**PASS (WARN)**

### Summary
- **✅ All Sprint 12 deliverables verified:** SKILL.md fixed, EPSS report exists, bookkeeping report in progress
- **✅ All 6 root symlinks valid**
- **✅ No orphaned files or cross-file contradictions**
- **✅ INDEX.md complete and accurate**
- **⚠️ 2 minor notes** (Sprint 12 not in ROADMAP table; Item 17 could reference assessment)
- **Neither note is a contradiction between CURRENT files** — the highest-value check (cross-file contradiction) is clean.

### Recommendations
1. **After Sprint 12 closes:** Add Sprint 12 to the ROADMAP sprint table and consider adding a note to Item 17 referencing the EPSS assessment report.
2. **No structural concerns:** The documentation set is in good health. AI_PROBLEMS.md, INDEX.md, and ROADMAP.md are internally consistent.

### Sprint 12 Acceptance Criteria Status
| Criterion | Status |
|-----------|--------|
| 1. SKILL.md line 34 lists `(auth, cases, ingest, models, queue)` | ✅ VERIFIED |
| 2. EPSS retrain assessment exists at `backend/reports/intel/epss-retrain-assessment.md` | ✅ VERIFIED |
| 3. Bookkeeping freshness report exists | ✅ VERIFIED (this file) |
| 4. No regressions introduced | ✅ VERIFIED (no code changes beyond SKILL.md) |
