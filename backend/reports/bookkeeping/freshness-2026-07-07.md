# Documentation Freshness Report

**Date:** 7 July 2026

## Status: ISSUES FOUND

---

## Checks

### 1. Root .md files

**Expected** (per AGENTS.md): 1 real file (`AGENTS.md`) + symlinks for all other root `.md` files pointing into `docs/`.

**Actual:**

| File | Status | Target |
|------|--------|--------|
| `AGENTS.md` | ✅ Real file (stays at root) | — |
| `MVP_SCOPE.md` | ❌ **Real file** — should be symlinked to `docs/architecture/` | (not in docs/) |
| `ROADMAP.md` | ✅ Symlink | → `docs/ROADMAP.md` |
| `AI_PROBLEMS.md` | ✅ Symlink | → `docs/AI_PROBLEMS.md` |
| `DEMO_SCRIPT.md` | ✅ Symlink | → `docs/DEMO_SCRIPT.md` |
| `RESEARCH_FINDINGS.md` | ✅ Symlink | → `docs/RESEARCH_FINDINGS.md` |
| `TRIAGEMATE_BOOK_PROMPT.md` | ✅ Symlink | → `docs/TRIAGEMATE_BOOK_PROMPT.md` |
| `WINDOWS_SETUP.md` | ✅ Symlink | → `docs/WINDOWS_SETUP.md` |
| `XGBOOST_INVESTIGATION_REPORT.md` | ✅ Symlink | → `docs/XGBOOST_INVESTIGATION_REPORT.md` |
| `SPRINT_NEXT_PLAN.md` | ⚠️ Symlink to archive | → `docs/archive/handoffs/SPRINT_NEXT_PLAN.md` |

**Count:** 1 real file + 9 symlinks = 10 files at root. `MVP_SCOPE.md` remains a real file (should be symlink to docs/architecture/ which is empty).

### 2. Symlink integrity

All 9 symlinks at root resolve correctly — no broken symlinks detected.

However, the symlink target layout does not match the intended subdirectory structure from the organization plan:

| Intended Path (per md-organization plan) | Actual Path |
|---------------------------------------|-------------|
| `docs/planning/ROADMAP.md` | `docs/ROADMAP.md` (flat) |
| `docs/architecture/MVP_SCOPE.md` | Not in docs/ |
| `docs/guides/DEMO_SCRIPT.md` | `docs/DEMO_SCRIPT.md` (flat) |
| `docs/guides/WINDOWS_SETUP.md` | `docs/WINDOWS_SETUP.md` (flat) |
| `docs/guides/book-generation-prompt.md` | `docs/TRIAGEMATE_BOOK_PROMPT.md` (flat, original name) |
| `docs/reference/AI_PROBLEMS.md` | `docs/AI_PROBLEMS.md` (flat) |
| `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | `docs/XGBOOST_INVESTIGATION_REPORT.md` (flat) |
| `docs/research/RESEARCH_FINDINGS.md` | `docs/RESEARCH_FINDINGS.md` (flat) |
| `docs/planning/SPRINT_NEXT_PLAN.md` | `docs/archive/handoffs/SPRINT_NEXT_PLAN.md` (archived) |

Files were moved flat into `docs/` root rather than into categorized subdirectories. `AGENTS.md`'s category table (referencing `docs/architecture/`, `docs/guides/`, `docs/planning/`, `docs/research/`) is misleading — those directories are empty.

### 3. Cross-references

**Stale path references found in active .md files:**

**a) `docs/ROADMAP.md` — Project File Map (lines 266–288)**
References old structure:
- `SPRINT_7_HANDOFF.md`, `SPRINT_8_HANDOFF.md`, `SPRINT_9_HANDOFF.md` listed at root — moved to `docs/archive/`
- `Additional Instructions/` listed — partially exists at root (deprecated)
- `ARCHIVED/` listed — removed

**b) `docs/TRIAGEMATE_BOOK_PROMPT.md` (line 34)**
References `Additional Instructions/Hostname and Data Classification Standards.md` and `Additional Instructions/TriageMate ML Implementation Plan - Final.md`. These now live at `docs/reference/`.

**c) `MVP_SCOPE.md` (multiple lines)**
References bare filenames like `ROADMAP.md`, `COURSE_CORRECTION.md`, `PRE_DEMO_PLAN.md`, `AI_PROBLEMS.md`, `SPRINT_1_HANDOFF.md`. These resolve at root but are not discoverable from within `docs/`.

### 4. docs/ completeness

| Subdirectory | Status | Content |
|---|---|---|
| `docs/architecture/` | ❌ **Empty** | Should contain `MVP_SCOPE.md` |
| `docs/guides/` | ❌ **Empty** | Should contain `DEMO_SCRIPT.md`, `WINDOWS_SETUP.md`, `TRIAGEMATE_BOOK_PROMPT.md` |
| `docs/planning/` | ❌ **Empty** | Should contain `ROADMAP.md`, `SPRINT_NEXT_PLAN.md` |
| `docs/reference/` | ✅ Populated | 2 files (hostname standards, ML plan) |
| `docs/research/` | ❌ **Empty** | Should contain `RESEARCH_FINDINGS.md` |
| `docs/archive/` | ✅ Populated | Handoffs, sprints-1-6, external audit |

**Additional Instructions/ still at root:**
Contains duplicates of 2 files that are also in `docs/reference/`. Should have been removed.

### 5. Reports

| Report | Status |
|--------|--------|
| `backend/reports/audits/tool-audit-2026-07-07.md` | ✅ Present |
| `backend/reports/bookkeeping/2026-07-07-bookkeeping.md` | ✅ Present |
| `backend/reports/bookkeeping/md-organization-2026-07-07.md` | ✅ Present |
| `backend/reports/intel/doc-audit-2026-07-07.md` | ✅ Present |

All report directories are active and contain generated reports.

---

## Issues Found

### 🔴 HIGH — Must Fix

1. **`docs/architecture/`, `docs/guides/`, `docs/planning/`, `docs/research/` are empty**
   - AGENTS.md references these as documentation categories but they contain no files
   - The 7 flat `.md` files in `docs/` root should be organized into subdirectories per the plan
   - Symlinks at root would need updating to point to new subdirectory paths

2. **`MVP_SCOPE.md` is still a real file at root, not symlinked**
   - Should be moved to `docs/architecture/MVP_SCOPE.md` with symlink at root
   - Currently `docs/architecture/` is empty — no target path exists

### 🟡 MEDIUM — Should Fix

3. **`Additional Instructions/` still exists at root with duplicate files**
   - Contains copies of 2 files also in `docs/reference/`
   - Should be removed to prevent confusion

4. **`ROADMAP.md` Project File Map (lines 266–288) shows old structure**
   - References `SPRINT_7_HANDOFF.md`, `SPRINT_8_HANDOFF.md`, `SPRINT_9_HANDOFF.md` at root (moved to archive)
   - References `Additional Instructions/` and `ARCHIVED/` directories
   - Should be updated to reflect current `docs/` structure

5. **`TRIAGEMATE_BOOK_PROMPT.md` references old `Additional Instructions/` path**
   - Line 34: should reference `docs/reference/` paths instead

### 🔵 LOW — Consider Fixing

6. **`MVP_SCOPE.md` and other docs reference bare filenames**
   - References like `ROADMAP.md`, `COURSE_CORRECTION.md` work at root but aren't discoverable from `docs/`
   - Should use relative paths

7. **`SPRINT_NEXT_PLAN.md` symlink points to archive**
   - Root → `docs/archive/handoffs/SPRINT_NEXT_PLAN.md`
   - This is an active planning document — should be in `docs/planning/`, not archived

---

## Orphans Found

- **`SPRINT_7_HANDOFF.md`, `SPRINT_8_HANDOFF.md`, `SPRINT_9_HANDOFF.md`** — correctly archived; bare filename references in `ROADMAP.md` (file map section) are stale but non-breaking

---

## Verdict

**ISSUES FOUND — 7 items flagged (2 high, 3 medium, 2 low)**

The documentation consolidation achieved the basic goal: files are under `docs/` with backward-compatible root symlinks. However, implementation was partial — files are flat in `docs/` root instead of in categorized subdirectories, 4 of 6 subdirectories are empty, `MVP_SCOPE.md` was not moved, and `Additional Instructions/` was not removed.

A follow-up sprint should:
1. Organize the 7 flat `docs/` files into correct subdirectories
2. Move `MVP_SCOPE.md` to `docs/architecture/`
3. Remove `Additional Instructions/` directory
4. Update `ROADMAP.md` file map to reflect current structure
5. Fix `TRIAGEMATE_BOOK_PROMPT.md` references
6. Re-point `SPRINT_NEXT_PLAN.md` symlink to `docs/planning/` instead of archive
