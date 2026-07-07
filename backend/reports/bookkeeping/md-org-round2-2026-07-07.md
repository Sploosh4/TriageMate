# .md Organization — Round 2 Check

**Date:** 7 July 2026
**Trigger:** Manual — second pass after Round 1 found remaining issues

---

## Current State Verification

### Root directory — 10 `.md` files (all real files, zero symlinks)

```
AGENTS.md                 1,052 bytes   (project rules, commander instructions)
AI_PROBLEMS.md           13,015 bytes   (bug tracker)
DEMO_SCRIPT.md            7,513 bytes   (demo walkthrough)
MVP_SCOPE.md             19,198 bytes   (scope authority — NOT in docs/)
RESEARCH_FINDINGS.md     10,076 bytes   (research findings)
ROADMAP.md               18,053 bytes   (master roadmap)
SPRINT_NEXT_PLAN.md      11,815 bytes   (sprint next plan)
TRIAGEMATE_BOOK_PROMPT.md 18,694 bytes  (book generation guide)
WINDOWS_SETUP.md          2,868 bytes   (Windows hosting)
XGBOOST_INVESTIGATION_REPORT.md 15,840 bytes (ML investigation)
```

**AGENTS.md claims:** "Root-level .md files (except AGENTS.md) are symlinks into docs/ for backward compatibility."
**Reality:** None of the 9 non-AGENTS.md files are symlinks. They are all independent real files.

### docs/ directory — 7 `.md` files at root level + 4 empty subdirs

```
docs/
├── AI_PROBLEMS.md                         (copy — same content as root)
├── DEMO_SCRIPT.md                         (copy — same content as root)
├── RESEARCH_FINDINGS.md                   (copy — same content as root)
├── ROADMAP.md                             (copy — same content as root)
├── TRIAGEMATE_BOOK_PROMPT.md              (copy — same content as root)
├── WINDOWS_SETUP.md                       (copy — same content as root)
├── XGBOOST_INVESTIGATION_REPORT.md        (copy — same content as root)
├── architecture/                          ← EMPTY
├── guides/                                ← EMPTY
├── planning/                              ← EMPTY
├── research/                              ← EMPTY
├── reference/
│   ├── Hostname and Data Classification Standards.md
│   └── TriageMate ML Implementation Plan — Final.md
└── archive/
    ├── Additional Information.md
    ├── External Auditor Response.md
    ├── EXTERNAL_AUDITOR_PROMPT.md
    ├── handoffs/
    │   ├── SPRINT_9_HANDOFF.md
    │   └── SPRINT_NEXT_PLAN.md
    ├── SECOND_WAVE_PROMPT.md
    ├── sprints-1-6/
    │   ├── COURSE_CORRECTION.md
    │   ├── DEMO_DATA_GENERATOR_PLAN.md
    │   ├── DEMO_DATA_GENERATOR_SCOPE.md
    │   ├── PRE_DEMO_PLAN.md
    │   ├── SPRINT_1_HANDOFF.md
    │   ├── SPRINT_2_HANDOFF.md
    │   ├── SPRINT_3_HANDOFF.md
    │   ├── SPRINT_7_HANDOFF.md
    │   ├── SPRINT_8_HANDOFF.md
    │   ├── SPRINT_9_BRIEFING_PLAN.md
    │   └── TEAM_BRIEFING.md
    ├── TriageMate ML Research Prompt.md
    ├── TriageMate ML Research.md
    └── TriageMate MVP Transformation.md
```

**Key observation:** docs/ root files are **identical copies** (same size, same modified timestamp) of the root-level files. They are NOT symlinks — they are duplicate files.

### Additional Instructions/ — still exists, still duplicates

```
Additional Instructions/
├── Hostname and Data Classification Standards.md   ← identical to docs/reference/ copy
└── TriageMate ML Implementation Plan — Final.md    ← identical to docs/reference/ copy
```

### Handoffs status

| File | Root? | docs/ location |
|---|---|---|
| `SPRINT_7_HANDOFF.md` | ❌ Gone | `docs/archive/sprints-1-6/` ✅ |
| `SPRINT_8_HANDOFF.md` | ❌ Gone | `docs/archive/sprints-1-6/` ✅ |
| `SPRINT_9_HANDOFF.md` | ❌ Gone | `docs/archive/handoffs/` ✅ |
| `SPRINT_NEXT_PLAN.md` | ✅ Still at root | `docs/archive/handoffs/` (copy also there) |

---

## Round 1 Issues — Re-checked

| # | Issue | Original Severity | Still Valid? | Updated Notes |
|---|---|---|---|---|
| 1 | 4 docs/ subdirectories empty | 🔴 | **YES** | architecture/, guides/, planning/, research/ are still completely empty |
| 2 | MVP_SCOPE.md at root, not in docs/ | 🔴 | **YES** | MVP_SCOPE.md exists only at root; not copied into docs/ anywhere |
| 3 | Additional Instructions/ duplicates | 🟡 | **YES** | Directory still exists with 2 files that duplicate docs/reference/ |
| 4 | ROADMAP.md file map shows old structure | 🟡 | **YES** | File map references `Additional Instructions/`, `ARCHIVED/`, and `SPRINT_7/8/9_HANDOFF.md` at root — all stale |
| 5 | TRIAGEMATE_BOOK_PROMPT.md references old paths | 🟡 | **YES** | SA-SKILLS subagent table references `Additional Instructions/Hostname...` and `Additional Instructions/TriageMate ML...` |
| 6 | Files use bare filenames instead of docs/ paths | 🔵 | **YES** | `ROADMAP.md` references files by bare name in file map; `TRIAGEMATE_BOOK_PROMPT.md` references `ROADMAP.md`, `MVP_SCOPE.md` etc. by bare name |
| 7 | SPRINT_NEXT_PLAN.md symlink issue | 🔵 | **EVOLVED** | No symlinks exist at all (none were created). SPRINT_NEXT_PLAN.md is still a real file at root AND has a copy in docs/archive/handoffs/. The file should move to `docs/planning/` with a root symlink (not archive, since it's still referenced as active) |

### What Round 1 Implementation Actually Did

From inspecting the delta between the Round 1 plan (`md-organization-2026-07-07.md`) and current disk state:

| Planned Action | Implemented? | Details |
|---|---|---|
| Copy root .md files to docs/ subdirectories | ⚠️ Partial | Files were **copied flat to docs/ root** instead of into categorized subdirectories |
| Create symlinks at root | ❌ No | No symlinks were created; both copies are real files |
| Remove `Additional Instructions/` | ❌ No | Directory still exists with 2 files |
| Remove `ARCHIVED/` | ✅ Yes | Directory at root is gone (contents moved to docs/archive/) |
| Move `SPRINT_7/8/9_HANDOFF.md` to archive | ✅ Yes | Moved to `docs/archive/sprints-1-6/` and `docs/archive/handoffs/` |
| Move `SPRINT_NEXT_PLAN.md` to docs/planning/ | ❌ No | Still at root; also copied to `docs/archive/handoffs/` (wrong subdir) |
| Move MVP_SCOPE.md to docs/architecture/ | ❌ No | Still at root only |

**Verdict:** The implementation was a copy operation (not a move), placed files flat in docs/ instead of in subdirectories, and skipped creating symlinks.

---

## Remaining Action Plan

### Phase 1 — File Moves (Consolidate to Single Canonical Copies)

#### Overview Strategy

Each file currently exists in **2 places** (root + docs/ root) or **3 places** (root + docs/ root + Additional Instructions/). The plan:
1. Delete the docs/ root-level copies (they are duplicates)
2. Move the root-level canonical file to the correct docs/ subdirectory
3. Create a relative symlink from root → docs/ subdirectory
4. Delete or verify the Additional Instructions/ duplicates

#### Moves Needed

| # | File | Current Canonical | Move To | Symlink From Root |
|---|---|---|---|---|
| M1 | `MVP_SCOPE.md` | `./MVP_SCOPE.md` | `docs/architecture/MVP_SCOPE.md` | `MVP_SCOPE.md` → `docs/architecture/MVP_SCOPE.md` |
| M2 | `DEMO_SCRIPT.md` | `./DEMO_SCRIPT.md` | `docs/guides/DEMO_SCRIPT.md` | `DEMO_SCRIPT.md` → `docs/guides/DEMO_SCRIPT.md` |
| M3 | `WINDOWS_SETUP.md` | `./WINDOWS_SETUP.md` | `docs/guides/WINDOWS_SETUP.md` | `WINDOWS_SETUP.md` → `docs/guides/WINDOWS_SETUP.md` |
| M4 | `ROADMAP.md` | `./ROADMAP.md` | `docs/planning/ROADMAP.md` | `ROADMAP.md` → `docs/planning/ROADMAP.md` |
| M5 | `SPRINT_NEXT_PLAN.md` | `./SPRINT_NEXT_PLAN.md` | `docs/planning/SPRINT_NEXT_PLAN.md` | `SPRINT_NEXT_PLAN.md` → `docs/planning/SPRINT_NEXT_PLAN.md` |
| M6 | `AI_PROBLEMS.md` | `./AI_PROBLEMS.md` | `docs/reference/AI_PROBLEMS.md` | `AI_PROBLEMS.md` → `docs/reference/AI_PROBLEMS.md` |
| M7 | `XGBOOST_INVESTIGATION_REPORT.md` | `./XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | `XGBOOST_INVESTIGATION_REPORT.md` → `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` |
| M8 | `RESEARCH_FINDINGS.md` | `./RESEARCH_FINDINGS.md` | `docs/research/RESEARCH_FINDINGS.md` | `RESEARCH_FINDINGS.md` → `docs/research/RESEARCH_FINDINGS.md` |
| M9 | `TRIAGEMATE_BOOK_PROMPT.md` | `./TRIAGEMATE_BOOK_PROMPT.md` | `docs/guides/TRIAGEMATE_BOOK_PROMPT.md` | `TRIAGEMATE_BOOK_PROMPT.md` → `docs/guides/TRIAGEMATE_BOOK_PROMPT.md` |

**Concrete shell commands for Phase 1:**
```bash
# Move each file to its docs/ subdirectory and create relative symlink
# Note: mv overwrites the duplicate if it exists; rm the duplicate first

# Remove duplicate flat docs/ copies
rm docs/AI_PROBLEMS.md docs/DEMO_SCRIPT.md docs/RESEARCH_FINDINGS.md
rm docs/ROADMAP.md docs/TRIAGEMATE_BOOK_PROMPT.md docs/WINDOWS_SETUP.md
rm docs/XGBOOST_INVESTIGATION_REPORT.md

# Remove the incorrectly-placed copy in archive/handoffs/
rm docs/archive/handoffs/SPRINT_NEXT_PLAN.md

# Move canonical files into subdirectories (M1-M9)
mv MVP_SCOPE.md docs/architecture/MVP_SCOPE.md
mv DEMO_SCRIPT.md docs/guides/DEMO_SCRIPT.md
mv WINDOWS_SETUP.md docs/guides/WINDOWS_SETUP.md
mv ROADMAP.md docs/planning/ROADMAP.md
mv SPRINT_NEXT_PLAN.md docs/planning/SPRINT_NEXT_PLAN.md
mv AI_PROBLEMS.md docs/reference/AI_PROBLEMS.md
mv XGBOOST_INVESTIGATION_REPORT.md docs/reference/XGBOOST_INVESTIGATION_REPORT.md
mv RESEARCH_FINDINGS.md docs/research/RESEARCH_FINDINGS.md
mv TRIAGEMATE_BOOK_PROMPT.md docs/guides/TRIAGEMATE_BOOK_PROMPT.md

# Create symlinks at root (relative paths for portability)
ln -sf docs/architecture/MVP_SCOPE.md MVP_SCOPE.md
ln -sf docs/guides/DEMO_SCRIPT.md DEMO_SCRIPT.md
ln -sf docs/guides/WINDOWS_SETUP.md WINDOWS_SETUP.md
ln -sf docs/planning/ROADMAP.md ROADMAP.md
ln -sf docs/planning/SPRINT_NEXT_PLAN.md SPRINT_NEXT_PLAN.md
ln -sf docs/reference/AI_PROBLEMS.md AI_PROBLEMS.md
ln -sf docs/reference/XGBOOST_INVESTIGATION_REPORT.md XGBOOST_INVESTIGATION_REPORT.md
ln -sf docs/research/RESEARCH_FINDINGS.md RESEARCH_FINDINGS.md
ln -sf docs/guides/TRIAGEMATE_BOOK_PROMPT.md TRIAGEMATE_BOOK_PROMPT.md
```

#### Duplicate Cleanup

| # | Action | Details |
|---|---|---|
| D1 | Remove `Additional Instructions/` directory | Contains duplicates of `docs/reference/` files. Files are already at `docs/reference/` |
| D2 | Remove `docs/archive/handoffs/SPRINT_NEXT_PLAN.md` | This is a copy; the canonical goes to `docs/planning/` |
| D3 | Remove all root-level `docs/*.md` flat copies | Already listed in the rm commands above |

**Concrete:**
```bash
git rm -r "Additional Instructions/"
# verify docs/reference/ already has the files — yes, confirmed
rm docs/archive/handoffs/SPRINT_NEXT_PLAN.md
```

---

### Phase 2 — Content Changes Needed

| File | What to Change | Details |
|---|---|---|
| `docs/planning/ROADMAP.md` | File map section (lines ~265-290) | Replace the old structure showing `Additional Instructions/`, `ARCHIVED/`, sprint handoffs at root, etc. with the new `docs/` structure (see Proposed Structure below) |
| `docs/guides/TRIAGEMATE_BOOK_PROMPT.md` | SA-SKILLS table (line ~34) | Change `Additional Instructions/Hostname and Data Classification Standards.md` → `docs/reference/Hostname and Data Classification Standards.md` and `Additional Instructions/TriageMate ML Implementation Plan - Final.md` → `docs/reference/TriageMate ML Implementation Plan — Final.md` |
| `AGENTS.md` | Documentation Structure section | Update to reflect actual structure (see updated section below) |

---

## Proposed docs/ Structure (Final)

```
docs/
├── architecture/
│   └── MVP_SCOPE.md                           # Scope authority (was at root)
├── guides/
│   ├── DEMO_SCRIPT.md                         # Demo walkthrough (was at root)
│   ├── TRIAGEMATE_BOOK_PROMPT.md              # Book generation guide (was at root)
│   └── WINDOWS_SETUP.md                       # Windows setup instructions (was at root)
├── planning/
│   ├── ROADMAP.md                             # Master roadmap (was at root)
│   └── SPRINT_NEXT_PLAN.md                    # Sprint next plan (was at root)
├── reference/
│   ├── AI_PROBLEMS.md                         # Bug tracker (was at root)
│   ├── Hostname and Data Classification Standards.md  # (was Additional Instructions/)
│   ├── TriageMate ML Implementation Plan — Final.md   # (was Additional Instructions/)
│   └── XGBOOST_INVESTIGATION_REPORT.md        # ML investigation (was at root)
├── research/
│   └── RESEARCH_FINDINGS.md                   # Research findings (was at root)
└── archive/
    ├── Additional Information.md
    ├── External Auditor Response.md
    ├── EXTERNAL_AUDITOR_PROMPT.md
    ├── handoffs/
    │   └── SPRINT_9_HANDOFF.md                # (SPRINT_NEXT_PLAN.md removed — moved to planning/)
    ├── SECOND_WAVE_PROMPT.md
    ├── sprints-1-6/
    │   ├── COURSE_CORRECTION.md
    │   ├── DEMO_DATA_GENERATOR_PLAN.md
    │   ├── DEMO_DATA_GENERATOR_SCOPE.md
    │   ├── PRE_DEMO_PLAN.md
    │   ├── SPRINT_1_HANDOFF.md
    │   ├── SPRINT_2_HANDOFF.md
    │   ├── SPRINT_3_HANDOFF.md
    │   ├── SPRINT_7_HANDOFF.md
    │   ├── SPRINT_8_HANDOFF.md
    │   ├── SPRINT_9_BRIEFING_PLAN.md
    │   └── TEAM_BRIEFING.md
    ├── TriageMate ML Research Prompt.md
    ├── TriageMate ML Research.md
    └── TriageMate MVP Transformation.md

Root (only):
    AGENTS.md                                    # (real file — project rules)
    9 symlinks → docs/{architecture,guides,planning,reference,research}/
```

### Root directory after cleanup

```
AGENTS.md                          ← real file (1,052 bytes)
MVP_SCOPE.md                       → docs/architecture/MVP_SCOPE.md
DEMO_SCRIPT.md                     → docs/guides/DEMO_SCRIPT.md
WINDOWS_SETUP.md                   → docs/guides/WINDOWS_SETUP.md
ROADMAP.md                         → docs/planning/ROADMAP.md
SPRINT_NEXT_PLAN.md                → docs/planning/SPRINT_NEXT_PLAN.md
AI_PROBLEMS.md                     → docs/reference/AI_PROBLEMS.md
XGBOOST_INVESTIGATION_REPORT.md    → docs/reference/XGBOOST_INVESTIGATION_REPORT.md
RESEARCH_FINDINGS.md               → docs/research/RESEARCH_FINDINGS.md
TRIAGEMATE_BOOK_PROMPT.md          → docs/guides/TRIAGEMATE_BOOK_PROMPT.md
```

Total: **1 real file + 9 symlinks** = 10 entries. Clean, backward-compatible.

---

## Updated AGENTS.md Section

Replace the current "Documentation Structure" section in `AGENTS.md` with:

```markdown
## Documentation Structure

All project documentation lives under `docs/` in subdirectories by category. Root-level `.md` files (except `AGENTS.md`) are symlinks into `docs/` for backward compatibility.

| Category | Directory | Contents |
|---|---|---|
| Architecture | `docs/architecture/` | `MVP_SCOPE.md` — scope authority |
| Guides | `docs/guides/` | `DEMO_SCRIPT.md`, `TRIAGEMATE_BOOK_PROMPT.md`, `WINDOWS_SETUP.md` |
| Planning | `docs/planning/` | `ROADMAP.md`, `SPRINT_NEXT_PLAN.md` |
| Reference | `docs/reference/` | `AI_PROBLEMS.md`, `XGBOOST_INVESTIGATION_REPORT.md`, hostname standards, ML implementation plan |
| Research | `docs/research/` | `RESEARCH_FINDINGS.md` |
| Archive | `docs/archive/` | Superseded plans, handoffs, sprint archives |

> **Note:** `AGENTS.md` is the only real `.md` file at the project root. All other root `.md` files are symlinks into `docs/`. Opening `ROADMAP.md` at root opens `docs/planning/ROADMAP.md` transparently.
```

---

## Verdict

**NEEDS ATTENTION** — The Round 1 implementation was partial and introduced a split state (files in root AND docs/ root, no symlinks, Additional Instructions/ not cleaned up). A second implementation pass is required to complete the migration.

### Summary of Remaining Work

| Area | Effort | Impact |
|---|---|---|
| Move 9 files to docs/ subdirs + create symlinks | ~5 min | Fixes the core structural issue |
| Remove Additional Instructions/ | ~1 min | Eliminates duplicate source of truth |
| Remove 7 flat copies from docs/ root | ~1 min | Eliminates duplicate files |
| Remove SPRINT_NEXT_PLAN.md from archive/handoffs/ | ~1 min | Corrects wrong placement |
| Update ROADMAP.md file map | ~10 min | Eliminates stale references |
| Update TRIAGEMATE_BOOK_PROMPT.md paths | ~2 min | Fixes broken SA-SKILLS instructions |
| Update AGENTS.md documentation section | ~2 min | Aligns claim with reality |
| **Total** | **~22 min** | |

### Files Not Requiring Symlinks (Correct as-is)

The following files in `docs/archive/` do NOT need root symlinks — they are purely historical:
- `docs/archive/Additional Information.md`
- `docs/archive/External Auditor Response.md`
- `docs/archive/EXTERNAL_AUDITOR_PROMPT.md`
- `docs/archive/SECOND_WAVE_PROMPT.md`
- `docs/archive/TriageMate ML Research Prompt.md`
- `docs/archive/TriageMate ML Research.md`
- `docs/archive/TriageMate MVP Transformation.md`
- `docs/archive/sprints-1-6/*.md`
- `docs/archive/handoffs/SPRINT_9_HANDOFF.md`

### Coverage Gap Noted

No active `.md` file documents:
- The `docs/` categorization scheme (subdirectory purposes)
- A quick-reference index of where everything lives
- Consider adding an `index.md` or `README.md` to `docs/` root once the move is complete
