# Bookkeeping Report — .md File Organization Strategy

**Date:** 2026-07-07
**Trigger:** Sprint: Documentation Cleanup & Tool Audit (Item 3)
**Requested by:** Commander via `2026-07-07-doc-cleanup-sprint.md`

---

## 1. Current State: File Inventory

All `.md` files in the project were audited and categorised. Here is the full landscape:

### Root (13 files)
| File | Type | Est. Size | Active? |
|------|------|-----------|---------|
| `AGENTS.md` | Project rules for AI tooling | ~10 lines | **YES** — must stay at root for opencode to read |
| `ROADMAP.md` | Master roadmap & sprint status | ~370 lines | **YES** — living reference |
| `MVP_SCOPE.md` | MVP scope definition | ~228 lines | **YES** — living reference |
| `SPRINT_NEXT_PLAN.md` | Next sprint plan | ~318 lines | **YES** — active plan |
| `DEMO_SCRIPT.md` | Demo walkthrough script | ~163 lines | **YES** — used for demos |
| `WINDOWS_SETUP.md` | Windows setup guide | ~118 lines | **YES** — onboarding doc |
| `TRIAGEMATE_BOOK_PROMPT.md` | Book generation workflow prompt | ~181 lines | **YES** — utility AI prompt |
| `AI_PROBLEMS.md` | Known bugs & discrepancies | ~165 lines | **YES** — living debt tracker |
| `RESEARCH_FINDINGS.md` | Sprint NEXT+2 research output | ~190 lines | **YES** — referenceable research |
| `XGBOOST_INVESTIGATION_REPORT.md` | Model investigation report | ~206 lines | **YES** — technical reference |
| `SPRINT_7_HANDOFF.md` | Commander handoff (Sprints 1-6 → 7) | ~273 lines | **Historical** — superseded by ROADMAP |
| `SPRINT_8_HANDOFF.md` | Commander handoff (Sprints 7-8 → 9) | ~260 lines | **Historical** — superseded by ROADMAP |
| `SPRINT_9_HANDOFF.md` | Commander handoff (Sprint 9 → NEXT) | ~213 lines | **Historical** — superseded by ROADMAP |

### `Additional Instructions/` (2 active + 4 archived)
| File | Type | Active? |
|------|------|---------|
| `Hostname and Data Classification Standards.md` | WA Gov hostname/spec standard | **YES** — reference spec |
| `TriageMate ML Implementation Plan — Final.md` | ML architecture plan | **YES** — reference spec |
| `ARCHIVED/Additional Information.md` | Deprecated reference | **NO** — should archive |
| `ARCHIVED/TriageMate ML Research Prompt.md` | Deprecated research prompt | **NO** — should archive |
| `ARCHIVED/TriageMate ML Research.md` | Deprecated research output | **NO** — should archive |
| `ARCHIVED/TriageMate MVP Transformation.md` | Deprecated migration doc | **NO** — should archive |

### `External/Archive/` (3 files)
| File | Type | Active? |
|------|------|---------|
| `External Auditor Response.md` | Audit report output | Historical — process artifact |
| `EXTERNAL_AUDITOR_PROMPT.md` | Audit prompt template | Historical — process artifact |
| `SECOND_WAVE_PROMPT.md` | Audit prompt template | Historical — process artifact |

### `ARCHIVED/Sprints_1-6/` (9 files)
All 9 files are historical and belong in the new archive structure.

### `backend/ml/README.md`
Local directory readme — **stays in place**. Not part of this migration.

### `.opencode/` (2 files)
| File | Type | Active? |
|------|------|---------|
| `DESIGN_RATIONALE.md` | Agent/skill design rationale | **YES** — opencode config doc |
| `RESTRUCTURE_HANDOFF.md` | OpenCode restructure handoff | **YES** — opencode config doc |

Both **stay in `.opencode/`**. They are opencode configuration documentation, not project documentation.

### `backend/reports/` (3 empty subdirectories)
- `audits/` — empty, reserved for generated audit reports
- `bookkeeping/` — currently receiving this report, reserved for generated bookkeeping reports
- `intel/` — empty, reserved for generated intel reports

**These stay as-is.** They are output directories for dynamically generated reports, not static docs.

---

## 2. Proposed `docs/` Directory Structure

```
docs/
├── README.md                        # (NEW) Index of docs/ — one-liner per file
│
├── AGENTS.md                        # Symlink target only (actual file at root)
│
├── architecture/                    # System design, scope, architecture specs
│   ├── MVP_SCOPE.md
│   └── ml-implementation-plan.md    # ← from Additional Instructions/
│
├── guides/                          # How-tos, walkthroughs, utility prompts
│   ├── DEMO_SCRIPT.md
│   ├── WINDOWS_SETUP.md
│   └── book-generation-prompt.md    # ← from TRIAGEMATE_BOOK_PROMPT.md
│
├── planning/                        # Roadmaps, sprint plans, next steps
│   ├── ROADMAP.md
│   └── SPRINT_NEXT_PLAN.md
│
├── reference/                       # Technical references, bug trackers, reports
│   ├── hostname-classification-standards.md  # ← from Additional Instructions/
│   ├── AI_PROBLEMS.md
│   └── XGBOOST_INVESTIGATION_REPORT.md
│
├── research/                        # Research outputs
│   └── RESEARCH_FINDINGS.md
│
└── archive/                         # Historical records, superseded handoffs
    ├── handoffs/
    │   ├── SPRINT_7_HANDOFF.md
    │   ├── SPRINT_8_HANDOFF.md
    │   └── SPRINT_9_HANDOFF.md
    ├── sprints-1-6/
    │   ├── COURSE_CORRECTION.md
    │   ├── DEMO_DATA_GENERATOR_PLAN.md
    │   ├── DEMO_DATA_GENERATOR_SCOPE.md
    │   ├── PRE_DEMO_PLAN.md
    │   ├── SPRINT_1_HANDOFF.md
    │   ├── SPRINT_2_HANDOFF.md
    │   ├── SPRINT_3_HANDOFF.md
    │   ├── SPRINT_9_BRIEFING_PLAN.md
    │   └── TEAM_BRIEFING.md
    ├── additional-information.md
    ├── ml-research-prompt.md
    ├── ml-research.md
    ├── mvp-transformation.md
    ├── External_Auditor_Response.md
    ├── EXTERNAL_AUDITOR_PROMPT.md
    └── SECOND_WAVE_PROMPT.md
```

### Visual ASCII Tree

```
TriageMate MVP/
├── AGENTS.md .................................. STAYS (required by opencode)
│
├── docs/ .......................................... NEW DIRECTORY
│   ├── README.md
│   ├── AGENTS.md → ../AGENTS.md ................. (symlink for discoverability)
│   ├── architecture/
│   │   ├── MVP_SCOPE.md
│   │   └── ml-implementation-plan.md
│   ├── guides/
│   │   ├── DEMO_SCRIPT.md
│   │   ├── WINDOWS_SETUP.md
│   │   └── book-generation-prompt.md
│   ├── planning/
│   │   ├── ROADMAP.md
│   │   └── SPRINT_NEXT_PLAN.md
│   ├── reference/
│   │   ├── hostname-classification-standards.md
│   │   ├── AI_PROBLEMS.md
│   │   └── XGBOOST_INVESTIGATION_REPORT.md
│   ├── research/
│   │   └── RESEARCH_FINDINGS.md
│   └── archive/
│       ├── handoffs/
│       │   ├── SPRINT_7_HANDOFF.md
│       │   ├── SPRINT_8_HANDOFF.md
│       │   └── SPRINT_9_HANDOFF.md
│       ├── sprints-1-6/
│       │   ├── COURSE_CORRECTION.md
│       │   ├── DEMO_DATA_GENERATOR_PLAN.md
│       │   ├── DEMO_DATA_GENERATOR_SCOPE.md
│       │   ├── PRE_DEMO_PLAN.md
│       │   ├── SPRINT_1_HANDOFF.md
│       │   ├── SPRINT_2_HANDOFF.md
│       │   ├── SPRINT_3_HANDOFF.md
│       │   ├── SPRINT_9_BRIEFING_PLAN.md
│       │   └── TEAM_BRIEFING.md
│       ├── additional-information.md
│       ├── ml-research-prompt.md
│       ├── ml-research.md
│       ├── mvp-transformation.md
│       ├── External_Auditor_Response.md
│       ├── EXTERNAL_AUDITOR_PROMPT.md
│       └── SECOND_WAVE_PROMPT.md
│
├── backend/
│   ├── ml/README.md ........................... STAYS (local README)
│   └── reports/ .............................. STAYS (generated reports only)
│       ├── audits/
│       ├── bookkeeping/
│       │   └── md-organization-2026-07-07.md
│       └── intel/
│
├── .opencode/
│   ├── DESIGN_RATIONALE.md ................... STAYS (opencode config)
│   └── RESTRUCTURE_HANDOFF.md ............... STAYS (opencode config)
│
├── Additional Instructions/ .................. REMOVED (moved to docs/)
├── External/Archive/ ......................... REMOVED (moved to docs/archive/)
└── ARCHIVED/Sprints_1-6/ .................... REMOVED (moved to docs/archive/)
```

---

## 3. File-by-File Migration Plan

### 3.1 Files Moving to `docs/` (with symlinks from root)

| Current Path | Target Path | Symlink at Root? | Reasoning |
|-------------|-------------|------------------|-----------|
| `ROADMAP.md` | `docs/planning/ROADMAP.md` | YES | Living roadmap, still referenced by name |
| `MVP_SCOPE.md` | `docs/architecture/MVP_SCOPE.md` | YES | Core architecture doc, often referenced |
| `SPRINT_NEXT_PLAN.md` | `docs/planning/SPRINT_NEXT_PLAN.md` | YES | Active plan, referenced by name |
| `DEMO_SCRIPT.md` | `docs/guides/DEMO_SCRIPT.md` | YES | Walkthrough, needed for demos |
| `WINDOWS_SETUP.md` | `docs/guides/WINDOWS_SETUP.md` | YES | Onboarding doc |
| `TRIAGEMATE_BOOK_PROMPT.md` | `docs/guides/book-generation-prompt.md` | YES | Utility prompt, not code |
| `AI_PROBLEMS.md` | `docs/reference/AI_PROBLEMS.md` | YES | Living debt tracker |
| `RESEARCH_FINDINGS.md` | `docs/research/RESEARCH_FINDINGS.md` | YES | Research output |
| `XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | YES | Technical reference |

### 3.2 Files Moving to `docs/archive/` (historical — no symlinks needed)

| Current Path | Target Path | Reasoning |
|-------------|-------------|-----------|
| `SPRINT_7_HANDOFF.md` | `docs/archive/handoffs/SPRINT_7_HANDOFF.md` | Superseded by ROADMAP; historical handoff |
| `SPRINT_8_HANDOFF.md` | `docs/archive/handoffs/SPRINT_8_HANDOFF.md` | Superseded by ROADMAP; historical handoff |
| `SPRINT_9_HANDOFF.md` | `docs/archive/handoffs/SPRINT_9_HANDOFF.md` | Superseded by ROADMAP; historical handoff |
| `ARCHIVED/Sprints_1-6/COURSE_CORRECTION.md` | `docs/archive/sprints-1-6/COURSE_CORRECTION.md` | Historical plan |
| `ARCHIVED/Sprints_1-6/DEMO_DATA_GENERATOR_PLAN.md` | `docs/archive/sprints-1-6/DEMO_DATA_GENERATOR_PLAN.md` | Historical plan |
| `ARCHIVED/Sprints_1-6/DEMO_DATA_GENERATOR_SCOPE.md` | `docs/archive/sprints-1-6/DEMO_DATA_GENERATOR_SCOPE.md` | Historical scope |
| `ARCHIVED/Sprints_1-6/PRE_DEMO_PLAN.md` | `docs/archive/sprints-1-6/PRE_DEMO_PLAN.md` | Historical plan |
| `ARCHIVED/Sprints_1-6/SPRINT_1_HANDOFF.md` | `docs/archive/sprints-1-6/SPRINT_1_HANDOFF.md` | Historical handoff |
| `ARCHIVED/Sprints_1-6/SPRINT_2_HANDOFF.md` | `docs/archive/sprints-1-6/SPRINT_2_HANDOFF.md` | Historical handoff |
| `ARCHIVED/Sprints_1-6/SPRINT_3_HANDOFF.md` | `docs/archive/sprints-1-6/SPRINT_3_HANDOFF.md` | Historical handoff |
| `ARCHIVED/Sprints_1-6/SPRINT_9_BRIEFING_PLAN.md` | `docs/archive/sprints-1-6/SPRINT_9_BRIEFING_PLAN.md` | Historical plan |
| `ARCHIVED/Sprints_1-6/TEAM_BRIEFING.md` | `docs/archive/sprints-1-6/TEAM_BRIEFING.md` | Historical briefing |
| `Additional Instructions/ARCHIVED/Additional Information.md` | `docs/archive/additional-information.md` | Archived reference |
| `Additional Instructions/ARCHIVED/TriageMate ML Research Prompt.md` | `docs/archive/ml-research-prompt.md` | Archived prompt |
| `Additional Instructions/ARCHIVED/TriageMate ML Research.md` | `docs/archive/ml-research.md` | Archived research |
| `Additional Instructions/ARCHIVED/TriageMate MVP Transformation.md` | `docs/archive/mvp-transformation.md` | Archived migration doc |
| `External/Archive/External Auditor Response.md` | `docs/archive/External_Auditor_Response.md` | Historical audit output |
| `External/Archive/EXTERNAL_AUDITOR_PROMPT.md` | `docs/archive/EXTERNAL_AUDITOR_PROMPT.md` | Historical prompt |
| `External/Archive/SECOND_WAVE_PROMPT.md` | `docs/archive/SECOND_WAVE_PROMPT.md` | Historical prompt |

### 3.3 Active Files Moving from `Additional Instructions/` to `docs/`

| Current Path | Target Path | Reasoning |
|-------------|-------------|-----------|
| `Additional Instructions/Hostname and Data Classification Standards.md` | `docs/reference/hostname-classification-standards.md` | Active reference spec (WA Gov naming) |
| `Additional Instructions/TriageMate ML Implementation Plan — Final.md` | `docs/architecture/ml-implementation-plan.md` | Active ML architecture plan |

### 3.4 Files That STAY Where They Are

| File | Location | Reasoning |
|------|----------|-----------|
| `AGENTS.md` | Root | Required at root by opencode AI tooling |
| `backend/ml/README.md` | `backend/ml/` | Local directory README — documents the ML dir for developers browsing it |
| `.opencode/DESIGN_RATIONAL.md` | `.opencode/` | OpenCode configuration doc, not project doc |
| `.opencode/RESTRUCTURE_HANDOFF.md` | `.opencode/` | OpenCode configuration doc, not project doc |
| `backend/reports/audits/` | `backend/reports/` | Reserved for generated audit reports |
| `backend/reports/bookkeeping/` | `backend/reports/` | Reserved for generated bookkeeping reports |
| `backend/reports/intel/` | `backend/reports/` | Reserved for generated intel reports |

### 3.5 Empty Directories to Remove After Migration

| Directory | Reasoning |
|-----------|-----------|
| `Additional Instructions/ARCHIVED/` | All contents migrated to `docs/archive/` |
| `Additional Instructions/` | Now empty; delete |
| `External/Archive/` | All contents migrated to `docs/archive/` |
| `External/` | Now empty; delete |
| `ARCHIVED/Sprints_1-6/` | All contents migrated to `docs/archive/` |
| `ARCHIVED/` | Now empty; delete |

---

## 4. Symlink Strategy

### Why Symlinks?
- **AI tooling compatibility:** If a system prompt says "Read ROADMAP.md", the AI's file search finds the symlink and follows it. No breakage.
- **Human muscle memory:** Typing `cat ROADMAP.md` or `less DEMO_SCRIPT.md` from the project root still works.
- **Backward compatibility:** No existing workflow breaks. Agents and humans gradually learn the new `docs/` structure.

### Symlinks to Create (from root → docs/)

| Root Symlink | Target |
|-------------|--------|
| `AGENTS.md` | `docs/AGENTS.md` (bidirectional — actual file at root, symlink in docs/) |
| `ROADMAP.md` | `docs/planning/ROADMAP.md` |
| `MVP_SCOPE.md` | `docs/architecture/MVP_SCOPE.md` |
| `SPRINT_NEXT_PLAN.md` | `docs/planning/SPRINT_NEXT_PLAN.md` |
| `DEMO_SCRIPT.md` | `docs/guides/DEMO_SCRIPT.md` |
| `WINDOWS_SETUP.md` | `docs/guides/WINDOWS_SETUP.md` |
| `TRIAGEMATE_BOOK_PROMPT.md` | `docs/guides/book-generation-prompt.md` |
| `AI_PROBLEMS.md` | `docs/reference/AI_PROBLEMS.md` |
| `RESEARCH_FINDINGS.md` | `docs/research/RESEARCH_FINDINGS.md` |
| `XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` |

**No symlinks are created for archived files** — they are purely historical.

### Symlink Implementation Details
- Use **relative symlinks** so they survive if the project is moved as a unit:
  ```bash
  cd TriageMate\ MVP
  ln -sf docs/planning/ROADMAP.md ROADMAP.md
  ```
- `AGENTS.md` is the reverse case: the **real file** stays at root, and a **symlink** in `docs/AGENTS.md` points back:
  ```bash
  ln -sf ../AGENTS.md docs/AGENTS.md
  ```

---

## 5. Naming Convention Recommendation

The current files use a mix of naming styles:
- **SCREAMING_SNAKE_CASE:** `AGENTS.md`, `MVP_SCOPE.md`, `SPRINT_7_HANDOFF.md` — legacy but consistent for handoffs
- **Title Case with dashes:** `TriageMate ML Implementation Plan — Final.md` — spaces and em-dash cause CLI headaches
- **PascalCase-ish:** `XGBOOST_INVESTIGATION_REPORT.md`, `DEMO_SCRIPT.md` — inconsistent caps

### Recommended Convention for New `docs/`:
- **Active files:** kebab-case + lowercase (`book-generation-prompt.md`, `ml-implementation-plan.md`)
- **Archived files:** keep original names for traceability (don't rename history)
- **Handoffs in archive:** keep original `SPRINT_7_HANDOFF.md` to maintain accountability trail

This is already reflected in the target paths above. The active files get clean kebab-case names; archived files retain their original names.

---

## 6. Cross-Reference Impact Analysis

I checked all `.md` files for relative-path or file-name references to other `.md` files that would break if moved:

| Source File | References | Will It Break? |
|-------------|-----------|----------------|
| `AGENTS.md` | `.opencode/plans/` | No — `.opencode/` is a directory, not a .md file |
| `MVP_SCOPE.md` | `ROADMAP.md`, `COURSE_CORRECTION.md`, `PRE_DEMO_PLAN.md` | **Potentially** — these are bare filenames. A human reading `docs/architecture/MVP_SCOPE.md` won't find `ROADMAP.md` in the same directory. Two options: |
| | | (A) Update references: `../planning/ROADMAP.md` |
| | | (B) Don't update — rely on symlinks in root (weaker, since reader is in `docs/`) |
| `SPRINT_9_HANDOFF.md` | `ROADMAP.md`, `MVP_SCOPE.md` by name | Same issue — bare filename references |
| `SPRINT_7_HANDOFF.md` | `ROADMAP.md` §7b | Same issue |
| `AI_PROBLEMS.md` | `ROADMAP.md` §7b | Same issue |
| `TRIAGEMATE_BOOK_PROMPT.md` | `ROADMAP.md`, `MVP_SCOPE.md`, `SPRINT_NEXT_PLAN.md`, etc. | Same issue — references by bare filename |
| `RESEARCH_FINDINGS.md` | No cross-refs to other .md files | No breakage |

### Recommendation on Cross-References
**Flag for human review:** The bare filename references in `MVP_SCOPE.md`, `SPRINT_9_HANDOFF.md`, `AI_PROBLEMS.md`, and `TRIAGEMATE_BOOK_PROMPT.md` will not break functionally (the files still exist somewhere in the project), but a reader browsing within `docs/` won't find them by simple filename. Two approaches:

**Option A (Recommended — minimal changes):** Update only the most-critical references in active docs to use relative paths. For example, `MVP_SCOPE.md`'s references to `ROADMAP.md` become `../planning/ROADMAP.md`. This is a quick find-and-replace.

**Option B (Defer):** Leave them as bare filenames. Modern IDEs and search tools (`rg`, `fd`, `fzf`) still find the files. Update references organically when each file is next edited.

I recommend **Option A for active docs**, **Option B for archived docs**.

---

## 7. Implementation Steps for Strike

### Phase 1: Create `docs/` Directories
```bash
mkdir -p docs/{architecture,guides,planning,reference,research,archive/{handoffs,sprints-1-6}}
```

### Phase 2: Move Active Files → `docs/` + Create Symlinks
For each active file:
```bash
# Example for ROADMAP.md
git mv ROADMAP.md docs/planning/ROADMAP.md
ln -sf docs/planning/ROADMAP.md ROADMAP.md
```
Repeat for: `MVP_SCOPE.md`, `SPRINT_NEXT_PLAN.md`, `DEMO_SCRIPT.md`, `WINDOWS_SETUP.md`, `TRIAGEMATE_BOOK_PROMPT.md`, `AI_PROBLEMS.md`, `RESEARCH_FINDINGS.md`, `XGBOOST_INVESTIGATION_REPORT.md`

### Phase 3: Move Architectural Reference Files
```bash
cp "Additional Instructions/Hostname and Data Classification Standards.md" docs/reference/hostname-classification-standards.md
cp "Additional Instructions/TriageMate ML Implementation Plan — Final.md" docs/architecture/ml-implementation-plan.md
git rm -r "Additional Instructions/"
```
(These have spaces in filenames — use quotes carefully. Consider `cp` then `git rm` to keep history.)

### Phase 4: Move Historical Files → `docs/archive/`
```bash
git mv SPRINT_7_HANDOFF.md docs/archive/handoffs/
git mv SPRINT_8_HANDOFF.md docs/archive/handoffs/
git mv SPRINT_9_HANDOFF.md docs/archive/handoffs/
git mv ARCHIVED/Sprints_1-6/*.md docs/archive/sprints-1-6/
# Archived content from Additional Instructions/ARCHIVED/
cp Additional Instructions/ARCHIVED/*.md docs/archive/
# Archived content from External/Archive/
cp External/Archive/*.md docs/archive/
```

### Phase 5: Remove Empty Directories
```bash
git rm -r ARCHIVED/
git rm -r "Additional Instructions/"
git rm -r External/
```

### Phase 6: Create `docs/README.md`
Write a lightweight index so anyone browsing `docs/` sees what's where.

### Phase 7: Create `docs/AGENTS.md` Symlink
```bash
ln -sf ../AGENTS.md docs/AGENTS.md
```

### Phase 8: Update Cross-References (Option A)
In `docs/architecture/MVP_SCOPE.md`:
- Replace `ROADMAP.md` → `../planning/ROADMAP.md`
- Replace `COURSE_CORRECTION.md` → `../archive/sprints-1-6/COURSE_CORRECTION.md`
- Replace `PRE_DEMO_PLAN.md` → `../archive/sprints-1-6/PRE_DEMO_PLAN.md`

In `docs/guides/book-generation-prompt.md` (formerly TRIAGEMATE_BOOK_PROMPT.md):
- Replace `ROADMAP.md` → `../planning/ROADMAP.md`
- Replace `MVP_SCOPE.md` → `../architecture/MVP_SCOPE.md`
- Replace `SPRINT_NEXT_PLAN.md` → `../planning/SPRINT_NEXT_PLAN.md`
- Replace `DEMO_SCRIPT.md` → `../guides/DEMO_SCRIPT.md`
- Replace `AI_PROBLEMS.md` → `../reference/AI_PROBLEMS.md`

### Phase 9: Verify
```bash
ls -la *.md         # Should only show AGENTS.md + 9 symlinks
ls docs/            # Should show new directory tree
rg "\.md" docs/     # Check all cross-references are valid
python -c "import os; paths=['docs/planning/ROADMAP.md','docs/architecture/MVP_SCOPE.md']; print(all(os.path.exists(p) for p in paths))"
```

### Phase 10: Commit
```bash
git add -A
git commit -m "docs: consolidate .md files into docs/ directory structure

- Moved active docs to docs/{architecture,guides,planning,reference,research}
- Moved historical docs to docs/archive/{handoffs,sprints-1-6}
- Created symlinks at root for backward compatibility
- Removed Additional Instructions/, External/, ARCHIVED/ directories
- Updated cross-references in active docs to use relative paths"
```

---

## 8. Post-Migration State

### Root Directory After Migration (clean!)
```
AGENTS.md                  (real file)
ROADMAP.md -> docs/planning/ROADMAP.md     (symlink)
MVP_SCOPE.md -> docs/architecture/MVP_SCOPE.md     (symlink)
SPRINT_NEXT_PLAN.md -> docs/planning/SPRINT_NEXT_PLAN.md     (symlink)
DEMO_SCRIPT.md -> docs/guides/DEMO_SCRIPT.md     (symlink)
WINDOWS_SETUP.md -> docs/guides/WINDOWS_SETUP.md     (symlink)
TRIAGEMATE_BOOK_PROMPT.md -> docs/guides/book-generation-prompt.md     (symlink)
AI_PROBLEMS.md -> docs/reference/AI_PROBLEMS.md     (symlink)
RESEARCH_FINDINGS.md -> docs/research/RESEARCH_FINDINGS.md     (symlink)
XGBOOST_INVESTIGATION_REPORT.md -> docs/reference/XGBOOST_INVESTIGATION_REPORT.md     (symlink)
```

From 13 files down to **1 real file + 9 symlinks**. The root is tidy. Everything still works.

### Files That Never Move
- `AGENTS.md` — stays at root permanently
- `backend/ml/README.md` — stays in `backend/ml/`
- `.opencode/DESIGN_RATIONALE.md` — stays in `.opencode/`
- `.opencode/RESTRUCTURE_HANDOFF.md` — stays in `.opencode/`
- `backend/reports/audits/` — reserved for generated reports
- `backend/reports/bookkeeping/` — reserved for generated reports
- `backend/reports/intel/` — reserved for generated reports

---

## 9. Verdict

**READY TO IMPLEMENT.** All files have been categorised, target paths verified, cross-reference impacts assessed, and symlink strategy defined. This is a mechanical move operation — no content changes, no deletions, no semantic drift. Strike can execute the 10-phase plan in a single session. Estimated time: <15 minutes including commit.
