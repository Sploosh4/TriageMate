# Bookkeeping Report — R4: Structural & Symlink Audit

**Date:** 2026-07-07
**Trigger:** manual structural audit
**Scope:** Root `.md` symlink integrity, INDEX.md cross-references, AGENTS.md path validity, stale name references, status badge coverage, orphan detection

---

## 1. Root `.md` Files Listing

**PASS** — Root `.md` files are all real files (symlinks were resolved in prior consolidation).

| File | Type | Status |
|---|---|---|
| `AGENTS.md` | REAL | OK |
| `AI_PROBLEMS.md` | REAL | OK |
| `MVP_SCOPE.md` | REAL | OK |
| `RESEARCH_FINDINGS.md` | REAL | OK |
| `ROADMAP.md` | REAL | OK |
| `WINDOWS_SETUP.md` | REAL | OK |
| `XGBOOST_INVESTIGATION_REPORT.md` | REAL | OK |
| `DEMO_SCRIPT.md` | GONE | (was broken symlink, now removed) |
| `TRIAGEMATE_BOOK_PROMPT.md` | GONE | (was broken symlink, now removed) |
| `SPRINT_NEXT_PLAN.md` | GONE | (was broken symlink, now removed) |

---

## 2. Symlink Resolution

**PASS** — Zero symlinks remain at root. The prior doc consolidation successfully resolved all symlinks to real files.

The `ai-doc-strategy-2026-07-07.md` (line 18) still claims "Root (symlinks to docs/) | 8" and mentions "2 broken: DEMO_SCRIPT.md, TRIAGEMATE_BOOK_PROMPT.md" — this is now **stale metadata** but acceptable in a historical planning document.

---

## 3. Additional Instructions/

**PASS** — Directory contains 2 real files (not symlinks):

| File | Status |
|---|---|
| `Hostname and Data Classification Standards.md` | REAL — 38,650 bytes |
| `TriageMate ML Implementation Plan — Final.md` | REAL — 46,020 bytes |

These are source/provenance files from earlier research phases. They are not referenced by INDEX.md (correct — they are not project docs).

---

## 4. INDEX.md File References Check

**PASS** — Every `.md` path referenced in `docs/INDEX.md` exists:

| INDEX Reference | Resolves To | Status |
|---|---|---|
| `planning/ROADMAP.md` | `docs/planning/ROADMAP.md` | OK |
| `architecture/MVP_SCOPE.md` | `docs/architecture/MVP_SCOPE.md` | OK |
| `reference/AI_PROBLEMS.md` | `docs/reference/AI_PROBLEMS.md` | OK |
| `reference/ml-implementation-plan.md` | `docs/reference/ml-implementation-plan.md` | OK |
| `planning/ai-doc-strategy-2026-07-07.md` | `docs/planning/ai-doc-strategy-2026-07-07.md` | OK |
| `planning/file-consolidation-plan-2026-07-07.md` | `docs/planning/file-consolidation-plan-2026-07-07.md` | OK |
| `reference/xgboost-investigation-report.md` | `docs/reference/xgboost-investigation-report.md` | OK |
| `reference/hostname-standards.md` | `docs/reference/hostname-standards.md` | OK |
| `research/RESEARCH_FINDINGS.md` | `docs/research/RESEARCH_FINDINGS.md` | OK |
| `guides/WINDOWS_SETUP.md` | `docs/guides/WINDOWS_SETUP.md` | OK |
| `archive/SPRINT_NEXT_PLAN.md` | `docs/archive/SPRINT_NEXT_PLAN.md` | OK |
| `archive/handoffs/SPRINT_9_HANDOFF.md` | `docs/archive/handoffs/SPRINT_9_HANDOFF.md` | OK |
| `archive/sprints-1-6/*.md` | (directory exists with 11 files) | OK |

---

## 5. Reverse: `docs/` Files NOT in INDEX.md

**PASS** — Every active (non-archive) `.md` file under `docs/` is listed in INDEX.md.

| File | Noted |
|---|---|
| `docs/INDEX.md` | Self-reference — expected exclusion |
| `docs/architecture/MVP_SCOPE.md` | Listed in INDEX |
| `docs/guides/WINDOWS_SETUP.md` | Listed in INDEX |
| `docs/planning/ROADMAP.md` | Listed in INDEX |
| `docs/planning/ai-doc-strategy-2026-07-07.md` | Listed in INDEX |
| `docs/planning/file-consolidation-plan-2026-07-07.md` | Listed in INDEX |
| `docs/reference/AI_PROBLEMS.md` | Listed in INDEX |
| `docs/reference/hostname-standards.md` | Listed in INDEX |
| `docs/reference/ml-implementation-plan.md` | Listed in INDEX |
| `docs/reference/xgboost-investigation-report.md` | Listed in INDEX |
| `docs/research/RESEARCH_FINDINGS.md` | Listed in INDEX |

Archive files hidden from INDEX are properly excluded (provenance only).

---

## 6. Status Badge Check

**PASS** — All active non-INDEX `.md` files have Status badges in the first 5 lines.

| File | Badge |
|---|---|
| `docs/architecture/MVP_SCOPE.md` | ✅ `Status: OUTDATED` |
| `docs/guides/WINDOWS_SETUP.md` | ✅ `Status: CURRENT` |
| `docs/planning/ROADMAP.md` | ✅ `Status: CURRENT` |
| `docs/planning/ai-doc-strategy-2026-07-07.md` | ✅ `Status: CURRENT` |
| `docs/planning/file-consolidation-plan-2026-07-07.md` | ✅ `Status: CURRENT` |
| `docs/reference/AI_PROBLEMS.md` | ✅ `Status: CURRENT` |
| `docs/reference/hostname-standards.md` | ✅ `Status: CURRENT` |
| `docs/reference/ml-implementation-plan.md` | ✅ `Status: OUTDATED` |
| `docs/reference/xgboost-investigation-report.md` | ✅ `Status: CURRENT` |
| `docs/research/RESEARCH_FINDINGS.md` | ✅ `Status: CURRENT` |
| `docs/archive/SPRINT_NEXT_PLAN.md` | ✅ `ARCHIVED` |
| `docs/archive/handoffs/SPRINT_9_HANDOFF.md` | ✅ `ARCHIVED` |

3 deep-archive files (EXTERNAL_AUDITOR_PROMPT.md, SECOND_WAVE_PROMPT.md, External Auditor Response.md) lack Status badges. These are provenance-only files not listed in INDEX.md — acceptable.

---

## 7. Deleted Files Check

**PASS** — All previously-broken symlinks confirmed GONE:

| File | Expected State | Actual |
|---|---|---|
| `DEMO_SCRIPT.md` | GONE | ✅ Correctly removed |
| `TRIAGEMATE_BOOK_PROMPT.md` | GONE | ✅ Correctly removed |
| `docs/guides/DEMO_SCRIPT.md` | GONE | ✅ Never existed |
| `docs/guides/TRIAGEMATE_BOOK_PROMPT.md` | GONE | ✅ Never existed |

---

## 8. AGENTS.md Path Check

**PASS** — All `.md` paths referenced in `AGENTS.md` resolve:

| AGENTS.md Reference | Resolves To | Status |
|---|---|---|
| `docs/INDEX.md` | `docs/INDEX.md` | OK |
| `docs/planning/ROADMAP.md` | `docs/planning/ROADMAP.md` | OK |
| `docs/reference/AI_PROBLEMS.md` | `docs/reference/AI_PROBLEMS.md` | OK |
| `docs/reference/hostname-standards.md` | `docs/reference/hostname-standards.md` | OK |
| `docs/guides/WINDOWS_SETUP.md` | `docs/guides/WINDOWS_SETUP.md` | OK |

No broken cross-references in AGENTS.md.

---

## 9. Stale Old-Name References

**FAIL** — The ROADMAP.md file tree (§Project File Map, lines 272–309) is significantly stale:

### 9a. `XGBOOST_INVESTIGATION_REPORT` (uppercase, old name)

| Location | Old Reference | Current File | Severity |
|---|---|---|---|
| `ROADMAP.md:282` | `XGBOOST_INVESTIGATION_REPORT.md → docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/xgboost-investigation-report.md` (lowercase, no symlink) | **STALE — still shows symlink arrow, wrong case** |
| `ROADMAP.md:299` | `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | Should be lowercase | **STALE** |
| `ROADMAP.md:278-283` | Shows `DEMO_SCRIPT.md →`, `SPRINT_NEXT_PLAN.md →`, `TRIAGEMATE_BOOK_PROMPT.md →` as existing symlinks | All GONE | **STALE** |

Other references in `file-consolidation-plan-2026-07-07.md` and `ai-doc-strategy-2026-07-07.md` are **acceptable** — those are historical planning docs describing the consolidation that was/is to be done.

### 9b. `Hostname and Data Classification Standards` (old name)

| Location | Old Reference | Current File | Severity |
|---|---|---|---|
| `ROADMAP.md:301` | `docs/reference/Hostname and Data Classification Standards.md` | Actually in `Additional Instructions/`; `docs/reference/hostname-standards.md` is the condensed version | **STALE — wrong path** |
| `file-consolidation-plan-2026-07-07.md` | Multiple references | Planning doc — acceptable | OK |

### 9c. `ML Implementation Plan — Final` (old name with em-dash)

| Location | Old Reference | Current File | Severity |
|---|---|---|---|
| `ROADMAP.md:300` | `docs/reference/TriageMate ML Implementation Plan — Final.md` | `docs/reference/ml-implementation-plan.md` | **STALE — wrong filename** |
| `file-consolidation-plan-2026-07-07.md` | Multiple references | Planning doc — acceptable | OK |

### 9d. ROADMAP.md File Tree — Systemic Staleness

The entire file tree in ROADMAP.md (§Project File Map, lines 272–309) is **badly outdated**:

| Line | Shows | Reality |
|---|---|---|
| 275-283 | 8 symlinks at root | All root `.md` files are now real files (symlinks resolved) |
| 278 | `DEMO_SCRIPT.md → docs/guides/DEMO_SCRIPT.md` | Neither file exists |
| 280 | `SPRINT_NEXT_PLAN.md → docs/planning/SPRINT_NEXT_PLAN.md` | Root symlink GONE; target moved to archive |
| 283 | `TRIAGEMATE_BOOK_PROMPT.md → docs/guides/TRIAGEMATE_BOOK_PROMPT.md` | Neither file exists |
| 291 | `docs/guides/DEMO_SCRIPT.md` | Does not exist |
| 293 | `docs/guides/TRIAGEMATE_BOOK_PROMPT.md` | Does not exist |
| 296 | `docs/planning/SPRINT_NEXT_PLAN.md` | Moved to `docs/archive/SPRINT_NEXT_PLAN.md` |
| 299 | `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | Should be lowercase |
| 300 | `docs/reference/TriageMate ML Implementation Plan — Final.md` | Should be `ml-implementation-plan.md` |
| 301 | `docs/reference/Hostname and Data Classification Standards.md` | Not in docs/reference/ |
| — | Missing: `docs/planning/ai-doc-strategy-2026-07-07.md` | New file not shown |
| — | Missing: `docs/planning/file-consolidation-plan-2026-07-07.md` | New file not shown |

---

## 10. `docs/` File Tree

**PASS** — Complete tree structure is well-organized:

```
docs/
├── INDEX.md
├── architecture/
│   └── MVP_SCOPE.md
├── archive/
│   ├── Additional Information.md
│   ├── EXTERNAL_AUDITOR_PROMPT.md
│   ├── External Auditor Response.md
│   ├── SECOND_WAVE_PROMPT.md
│   ├── SPRINT_NEXT_PLAN.md
│   ├── TriageMate ML Research Prompt.md
│   ├── TriageMate ML Research.md
│   ├── TriageMate MVP Transformation.md
│   ├── handoffs/
│   │   └── SPRINT_9_HANDOFF.md
│   └── sprints-1-6/
│       ├── COURSE_CORRECTION.md
│       ├── DEMO_DATA_GENERATOR_PLAN.md
│       ├── DEMO_DATA_GENERATOR_SCOPE.md
│       ├── PRE_DEMO_PLAN.md
│       ├── SPRINT_1_HANDOFF.md
│       ├── SPRINT_2_HANDOFF.md
│       ├── SPRINT_3_HANDOFF.md
│       ├── SPRINT_7_HANDOFF.md
│       ├── SPRINT_8_HANDOFF.md
│       ├── SPRINT_9_BRIEFING_PLAN.md
│       └── TEAM_BRIEFING.md
├── guides/
│   └── WINDOWS_SETUP.md
├── planning/
│   ├── ROADMAP.md
│   ├── ai-doc-strategy-2026-07-07.md
│   └── file-consolidation-plan-2026-07-07.md
├── reference/
│   ├── AI_PROBLEMS.md
│   ├── hostname-standards.md
│   ├── ml-implementation-plan.md
│   └── xgboost-investigation-report.md
└── research/
    └── RESEARCH_FINDINGS.md
```

---

## Items Auto-Fixed

None — this was a read-only structural audit. No auto-fixes applied.

---

## Items Flagged for Human Review

### 🔴 CRITICAL: ROADMAP.md §Project File Map is badly stale

The file tree at `docs/planning/ROADMAP.md` lines 272–309 shows:
- Non-existent symlinks (DEMO_SCRIPT.md, TRIAGEMATE_BOOK_PROMPT.md, SPRINT_NEXT_PLAN.md)
- Wrong filenames (uppercase XGBOOST, ML Plan with em-dash, old hostname standards name)
- Missing entries (ai-doc-strategy, file-consolidation-plan)
- References to moved files (SPRINT_NEXT_PLAN.md still shown as in `docs/planning/`)

**Recommendation:** Rewrite the entire file tree to reflect current reality. This is the project's navigational map — stale here misdirects all agents.

### 🟡 MEDIUM: Additional Instructions/ files are stale metadata sources

`Additional Instructions/Hostname and Data Classification Standards.md` and `Additional Instructions/TriageMate ML Implementation Plan — Final.md` are large source research files. The former has a condensed version at `docs/reference/hostname-standards.md`. The latter is superseded by `docs/reference/ml-implementation-plan.md`. Consider if these Additional Instructions/ files are still needed.

### 🟢 LOW: Deep-archive files missing Status badges

Three provenance-only archive files (EXTERNAL_AUDITOR_PROMPT.md, SECOND_WAVE_PROMPT.md, External Auditor Response.md) have no Status badge. Acceptable given they are not in INDEX, but adding `> **Status:** ARCHIVED` would be clean.

---

## Orphans Found

None detected. No active file references orphaned files, and no orphaned references found among active docs (the stale ROADMAP.md file tree references some non-existent symlinks at root, but they are dead links to already-removed files, not true orphans).

---

## Coverage Gaps

- **ROADMAP.md** missing 2 new planning documents from its project file tree
- **ROADMAP.md** file tree still documents the old symlink structure that no longer exists
- **AGENTS.md** does not list `decision-framework` explicitly in its quick-reference table (it mentions loading it but doesn't include it in the directory map)

---

## Verdict

**NEEDS ATTENTION**

| Check | Result |
|---|---|
| 1. Root .md listing | ✅ PASS |
| 2. Symlink resolution | ✅ PASS (all resolved) |
| 3. Additional Instructions/ | ✅ PASS |
| 4. INDEX.md references | ✅ PASS |
| 5. docs/ files in INDEX | ✅ PASS |
| 6. Status badges | ✅ PASS |
| 7. Deleted files | ✅ PASS |
| 8. AGENTS.md paths | ✅ PASS |
| 9. Stale old-name refs | ❌ FAIL — ROADMAP.md file tree critically stale |
| 10. docs/ file tree | ✅ PASS |

**Summary:** The symlink cleanup from prior consolidation is complete and verified. All cross-references in INDEX.md and AGENTS.md are valid. However, the **ROADMAP.md §Project File Map** (lines 272–309) has not been updated to reflect the new structure and contains 10+ stale references including non-existent files, wrong filenames, and missing entries. This is the project's primary navigation map for AI agents and needs a rewrite.

**Recommended next action:** Correct ROADMAP.md's file tree to match the current docs/ structure, remove dead symlink references, add missing planning documents, and update filenames to current lowercase versions.
