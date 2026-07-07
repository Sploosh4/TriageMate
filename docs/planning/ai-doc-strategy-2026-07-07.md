# AI Documentation Strategy Proposal

> **Status: CURRENT** (7 July 2026)

**Date:** 7 July 2026
**Requested by:** Commander (project-wide doc consolidation)
**Sources consulted:** All 40+ `.md` files across `docs/`, `AGENTS.md`, file listings, symlink structure, project tree

---

## 1. Current State

### 1.1 Inventory Count

| Location | Count | Types |
|---|---|---|
| Root (real) | 1 | `AGENTS.md` |
| Root (symlinks to `docs/`) | 6 | `MVP_SCOPE.md`, `ROADMAP.md`, `AI_PROBLEMS.md`, `RESEARCH_FINDINGS.md`, `xgboost-investigation-report.md`, `WINDOWS_SETUP.md` — (2 broken removed: `DEMO_SCRIPT.md` (deleted), `TRIAGEMATE_BOOK_PROMPT.md` (deleted)) |
| `docs/architecture/` | 1 | `MVP_SCOPE.md` |
| `docs/guides/` | 1 | `WINDOWS_SETUP.md` (DEMO_SCRIPT and TRIAGEMATE_BOOK_PROMPT targets missing — broken symlinks, both deleted) |
| `docs/planning/` | 2 | `ROADMAP.md`, `SPRINT_NEXT_PLAN.md` |
| `docs/reference/` | 4 | `AI_PROBLEMS.md`, `xgboost-investigation-report.md`, `ml-implementation-plan.md`, `hostname-standards.md` |
| `docs/research/` | 1 | `RESEARCH_FINDINGS.md` |
| `docs/archive/` | 6 | Various research prompts and early docs |
| `docs/archive/handoffs/` | 1 | `SPRINT_9_HANDOFF.md` |
| `docs/archive/sprints-1-6/` | 11 | Handoffs, plans, briefings from Sprints 1–9 |
| **Total** | **~36** (2 broken symlinks) | |

### 1.2 Key Findings

**Finding 1: AGENTS.md is the AI's current entry point but lacks orientation aids.**
It lists the category→directory mapping but provides no guidance on which files are current vs historical, no priority ordering, and no "what to read for which task" quick-reference.

**Finding 2: ROADMAP.md is the closest thing to a single source of truth — but it's incomplete.**
It documents sprint status, config, known bugs, and the project file tree. However:
- It doesn't distinguish what's _implemented_ vs _planned_ at the file level
- `SPRINT_NEXT_PLAN.md` overlaps heavily (duplicate section on Items 1-3, 6, 8)
- It references `AI_PROBLEMS.md` for bugs but doesn't summarise them
- The "Sprint NEXT" section is a hybrid of done/deferred/pending with no clear visual distinction

**Finding 3: Status warnings are inconsistent.**
- `MVP_SCOPE.md` has a large CAUTION banner — excellent
- `ml-implementation-plan.md` has an OUTDATED warning — good
- `AI_PROBLEMS.md` uses ✅ FIXED / 🟢 WON'T FIX badges — good pattern
- `xgboost-investigation-report.md` has a STATUS NOTE about artifacts not existing — good
- `RESEARCH_FINDINGS.md` has a NOTE about roadmap superseding it — excellent
- `SPRINT_9_HANDOFF.md` has a header saying it's historical — good
- But none of these warnings are surfaced in `AGENTS.md` or `ROADMAP.md`

**Finding 4: Files contain large amounts of duplicated information.**
- `ROADMAP.md` §Sprint NEXT and `SPRINT_NEXT_PLAN.md` describe the same items
- `xgboost-investigation-report.md` and `RESEARCH_FINDINGS.md` both analyse model issues
- `MVP_SCOPE.md` §3 (Out of Scope) repeatedly says items are "implemented" or "deferred" — but this is a scope document, not a status tracker
- `SPRINT_9_HANDOFF.md` §§1-3 repeat data found in `ROADMAP.md`

**Finding 5: Broken symlinks exist.**
`DEMO_SCRIPT.md` (deleted) and `TRIAGEMATE_BOOK_PROMPT.md` (deleted) appear in root-level listings and `AGENTS.md`'s file map, but their targets (`docs/guides/DEMO_SCRIPT.md`, `docs/guides/TRIAGEMATE_BOOK_PROMPT.md`) do not exist on disk. An AI attempting to read them will get ENOENT.

**Finding 6: Some files have unclear audience and purpose.**
- `TRIAGEMATE_BOOK_PROMPT.md` (deleted) (broken) was described as a "book generation prompt" — a prompt template, not project documentation
- `hostname-standards.md` is a 43-citation academic-style paper on hostname nomenclature — valuable reference but entirely external research, not TriageMate-specific
- `ml-implementation-plan.md` is explicitly outdated but preserved as historical reference
- Archive files (`Additional Information.md`, `TriageMate ML Research.md`, etc.) are early-iteration source docs that fed into later synthesis

**Finding 7: File naming is inconsistent across 6+ conventions.**

| Convention | Examples | Count |
|---|---|---|
| ALL_CAPS_SNAKE | `MVP_SCOPE.md`, `AI_PROBLEMS.md`, `ROADMAP.md`, `DEMO_SCRIPT.md` (deleted), `WINDOWS_SETUP.md` | 5 |
| Pascal-ish | `SPRINT_NEXT_PLAN.md`, `RESEARCH_FINDINGS.md`, `xgboost-investigation-report.md` | 3 |
| Spaced + em-dash | `ml-implementation-plan.md` | 1 |
| Full Sentence Case | `hostname-standards.md` | 1 |
| Lowercase | `AGENTS.md` | 1 |
| Numbered | `SPRINT_9_HANDOFF.md`, `SPRINT_2_HANDOFF.md`, etc. | 13 |

---

## 2. Proposed AI Landing Page

### 2.1 Location and Name

| Proposal | Verdict |
|---|---|
| **`docs/INDEX.md`** | **Recommended.** Short, conventional, its purpose is obvious. Doesn't collide with any existing name. AI agents can be told "start with `docs/INDEX.md`". |
| `AGENTS.md` section | Not recommended — AGENTS.md is the AI's _operational instructions_ (project rules, decision framework). Mixing in a file catalogue would make it too long. |
| `docs/AI_LANDING.md` | Acceptable, but less conventional. INDEX.md is the standard for project documentation indices across all ecosystems. |
| Root-level `INDEX.md` | Rejected — root should stay minimal (just `AGENTS.md`). |

**Final proposal:** `docs/INDEX.md` — an AI-readable index of all documentation with status, audience, and purpose.

### 2.2 Structure

The index should contain:

1. **Header** — brief description of the project and how to use the index
2. **Quick-Start Section** — "If you're an AI subagent, read these files first" (3-4 files depending on task)
3. **Full File Table** with columns:
   - *Path* (relative to project root, clickable)
   - *Title* (human-readable name)
   - *Status* (CURRENT / OUTDATED / ARCHIVE / BROKEN)
   - *Audience* (AI / Human / Both)
   - *Purpose* (one-line description of what the file contains)
   - *Word Count* (approximate, so AI can estimate reading cost)
   - *Last Updated* (date, or "N/A" for archive)
4. **Category Section** — files organised by category (Architecture, Planning, Reference, etc.) with brief descriptions of each category's role
5. **Table of Broken/Stale Files** — flagged for cleanup

### 2.3 Example Table Row

```markdown
| Path | Title | Status | Audience | Purpose | Words | Updated |
|------|-------|--------|----------|---------|-------|---------|
| `docs/planning/ROADMAP.md` | Master Roadmap & Status | CURRENT | Both | Single source of truth for sprint completion, feature status, config, and known bugs | ~4,500 | 2026-07-02 |
| `docs/reference/AI_PROBLEMS.md` | AI Problems Tracker | CURRENT | AI | Bug tracker for code/model issues discovered during development | ~2,800 | 2026-07-02 |
| `docs/archive/handoffs/SPRINT_9_HANDOFF.md` | Sprint 9 Handoff | ARCHIVE | Both | Historical handoff (data corpus built, 37 features filled) — superseded by ROADMAP.md | ~1,900 | 2026-07-02 |
```

---

## 3. File Consolidation Suggestions

### 3.1 Duplicate/Overlap Analysis

| Files to Merge | Rationale | Tradeoff |
|----------------|-----------|----------|
| **`ROADMAP.md` + `SPRINT_NEXT_PLAN.md`** | `SPRINT_NEXT_PLAN.md` is essentially a detailed subset of `ROADMAP.md`'s "Sprint NEXT" section. ROADMAP already summarises Items 1-8 with status. The plan adds detailed implementation steps and verification commands. | **Fewer files:** Eliminates 1 file. **Downside:** ROADMAP.md grows by ~30%. The detailed commands are useful during active sprint execution but clutter the master status after completion. **Recommendation:** Merge Sprint NEXT implementation steps INTO ROADMAP.md as collapsible `<details>` sections, or keep as a separate `sprint-active-plan.md` that gets promoted into `ROADMAP.md` on completion and archived. |
| **`RESEARCH_FINDINGS.md` + `xgboost-investigation-report.md`** | Both analyse the XGBoost model pipeline. `xgboost-investigation-report.md` covers 8 root-cause fixes from June 2026. `RESEARCH_FINDINGS.md` covers 5 parallel research streams from July 2026, including pipeline drift analysis. They reference overlapping issues (feature mismatch, temporal bias, KEV starvation). | **Fewer files:** Eliminates 1 file. **Downside:** The investigation report is about code fixes already applied; the research findings are about remaining improvement opportunities. Different temporal contexts. **Recommendation:** Keep separate but cross-reference. Add a "Relationship to Research Findings" section at the top of the investigation report. |
| **`TRIAGEMATE_BOOK_PROMPT.md` (deleted) (broken)** | This is a _prompt template_ for generating a book about TriageMate, not project documentation. If it existed, it belongs in a `prompts/` directory, not `docs/`. | **Fewer files:** Remove from the documentation surface. **Downside:** None — it's already broken. Just clean it up. |
| **`WINDOWS_SETUP.md`** | Currently standalone. Could be Section 4 of a unified `SETUP.md` that also covers Linux/macOS, Docker, and bare-metal. | **Fewer files:** Slight consolidation. **Downside:** A single setup guide is longer to parse. **Recommendation:** Keep standalone but rename to `setup-windows.md` to match a convention. A general setup guide could be created at `docs/guides/setup.md` that references the OS-specific files. |
| **`ml-implementation-plan.md`** | This is explicitly outdated but is the largest ML architecture reference. Its content (Section 1 architecture overview, feature list, pipeline data flow) overlaps with `ROADMAP.md`, `MVP_SCOPE.md`, and `SPRINT_NEXT_PLAN.md`. | **Fewer files:** Could archive it fully. **Downside:** It's a useful historical reference for understanding _why_ decisions were made. **Recommendation:** Keep archived. Ensure `ROADMAP.md` cross-references it for historical context. |
| **Archive root files (`Additional Information.md`, `TriageMate ML Research.md`, etc.)** | These 6 files are source materials that fed into the ML Implementation Plan. They are never read by AIs and should not appear in `docs/INDEX.md`. | **Fewer files:** None in the active surface. **Downside:** If someone needs to trace a design decision to its original source, these are valuable. **Recommendation:** Keep archived, exclude from INDEX.md, add a note in INDEX.md saying "archive files preserved for provenance — not needed for normal work". |

### 3.2 Summary of Recommended Merges

| Action | Files | Rationale |
|--------|-------|-----------|
| **MERGE into ROADMAP.md** | `SPRINT_NEXT_PLAN.md` implementation details (as collapsible) | Eliminates 1 file, reduces confusion about which is authoritative |
| **KEEP separate** | `RESEARCH_FINDINGS.md` vs `xgboost-investigation-report.md` | Different temporal/contextual focus. Add cross-refs. |
| **REMOVE (broken symlink)** | `DEMO_SCRIPT.md` (deleted), `TRIAGEMATE_BOOK_PROMPT.md` (deleted) | Already broken. Clean up the reference in AGENTS.md |
| **ARCHIVE** | `ml-implementation-plan.md` if ROADMAP absorbs its current-state info | Already marked outdated. Could be moved to `docs/archive/` |
| **KEEP standalone** | `WINDOWS_SETUP.md` | Specific enough to merit its own file. Rename for convention. |

---

## 4. Naming Convention Proposal

### 4.1 Problems with Current

- Mixed cases make it hard to predict filenames (e.g., is it `ROADMAP.md` or `roadmap.md`?)
- Spaces and em-dashes cause shell/URL issues
- No distinction between _active_, _reference_, and _archive_ in the name
- No indication of what category a file belongs to when viewed in isolation

### 4.2 Proposed Convention

```
<category-prefix>-<topic>[-<modifier>].md
```

**Rules:**
1. **Lowercase kebab-case only** — no ALL_CAPS, no spaces, no em-dashes
2. **Category prefix** — one or two letters indicating the doc category (see table below)
3. **Topic** — short descriptive name (1-4 words)
4. **Modifier** (optional) — `handoff`, `plan`, `prompt`, `standards`, `final`

### 4.3 Category Prefixes

| Category | Prefix | Example |
|----------|--------|---------|
| Architecture | `arch-` | `arch-scope.md` (formerly `MVP_SCOPE.md`) |
| Planning | `plan-` | `plan-roadmap.md` (formerly `ROADMAP.md`) |
| Guide | `guide-` | `guide-setup-windows.md` (formerly `WINDOWS_SETUP.md`) |
| Reference | `ref-` | `ref-ai-problems.md` (formerly `AI_PROBLEMS.md`) |
| Research | `research-` | `research-model-findings.md` (formerly `RESEARCH_FINDINGS.md`) |
| Archive | `archive-` | `archive-sprint-9-handoff.md` (formerly `SPRINT_9_HANDOFF.md`) |

### 4.4 Before/After Table

| Current Name | Proposed Name | Notes |
|---|---|---|
| `AGENTS.md` | `AGENTS.md` (unchanged) | Only real root file, known by system |
| `MVP_SCOPE.md` | `arch-scope.md` | |
| `ROADMAP.md` | `plan-roadmap.md` | |
| `AI_PROBLEMS.md` | `ref-ai-problems.md` | |
| `SPRINT_NEXT_PLAN.md` | `plan-retrain-and-upgrades.md` | More descriptive; absorbed into ROADMAP eventually |
| `RESEARCH_FINDINGS.md` | `research-model-findings.md` | |
| `xgboost-investigation-report.md` | `research-xgboost-investigation.md` | |
| `WINDOWS_SETUP.md` | `guide-setup-windows.md` | |
| `DEMO_SCRIPT.md` (deleted) | (remove — broken symlink) | |
| `TRIAGEMATE_BOOK_PROMPT.md` (deleted) | `prompt-triagemate-book.md` (or remove) | If restored, move to `prompts/` not `docs/` |
| `ml-implementation-plan.md` | `archive-ml-implementation-plan.md` | Move to archive |
| `hostname-standards.md` | `ref-hostname-standards.md` | |
| `SPRINT_9_HANDOFF.md` | `archive-sprint-9-handoff.md` | |

### 4.5 Critical Consideration: Symlinks and AGENTS.md

`AGENTS.md` currently references files by their old names in the "Project File Map" section. If files are renamed, the symlinks at root must be updated to point to new locations. The mapping in AGENTS.md's Documentation Structure table must also be updated.

**Recommendation:** Do NOT break root-level symlinks. If `plan-roadmap.md` replaces `ROADMAP.md`, keep the symlink `ROADMAP.md → docs/planning/plan-roadmap.md` so existing references don't break. Update AGENTS.md to show both old and new names during a transition period.

---

## 5. AI Need Scenarios

What files does an AI subagent actually need, given a specific task? Below is the minimal set (2-4 files) that would give sufficient context to start working.

### Scenario 1: "Fix a bug in the scoring engine"

| Priority | File | Why |
|----------|------|-----|
| 1 | `backend/scoring.py` | The code itself (not docs, but the AI needs to read it) |
| 2 | `docs/planning/ROADMAP.md` | Understand scoring architecture (6 dimensions, weights, bands) |
| 3 | `docs/reference/AI_PROBLEMS.md` | Check if this bug is already tracked; see scoring-related fixes |
| 4 | `docs/architecture/MVP_SCOPE.md` | §2.5 Scoring Engine — scope boundaries, dimension weights |

**Total reading:** ~4 files. Realistically the AI reads the code first, then checks ROADMAP for context, AI_PROBLEMS for known issues.

### Scenario 2: "Add a new integration"

| Priority | File | Why |
|----------|------|-----|
| 1 | `.opencode/skills/new-integration-pattern/SKILL.md` | Boilerplate template and pattern |
| 2 | `backend/integrations/nvd.py` (or any existing integration) | Reference implementation to copy pattern |
| 3 | `docs/planning/ROADMAP.md` | Check if this integration is already planned/done |
| 4 | `docs/architecture/MVP_SCOPE.md` | §3 — check scope boundaries (is this in or out of scope?) |

**Total reading:** ~4 files. Heavy on code reference, light on docs.

### Scenario 3: "Update the frontend"

| Priority | File | Why |
|----------|------|-----|
| 1 | `frontend/js/app.js` + relevant component | The code |
| 2 | `docs/guides/DEMO_SCRIPT.md` (deleted) | Visual reference for expected behaviour (file deleted) |
| 3 | `docs/planning/ROADMAP.md` | Check frontend-related feature status |
| 4 | (Optionally) `demo-reference.html` at root | The approved visual reference |

**Total reading:** ~3 files. Frontend changes rarely need deep docs.

### Scenario 4: "Retrain the model"

| Priority | File | Why |
|----------|------|-----|
| 1 | `docs/planning/ROADMAP.md` | §Sprint NEXT — retrain status, verification commands |
| 2 | `docs/reference/xgboost-investigation-report.md` | 8 fixes applied, what changed, expected metrics |
| 3 | `docs/research/RESEARCH_FINDINGS.md` | Pipeline drift analysis, KEV starvation, EPSS baseline |
| 4 | `backend/ml/train_xgboost.py` | The training script itself |

**Total reading:** ~4 files. This is the most doc-heavy scenario because the model has many known issues and research findings.

### Scenario 5: "Understand the project architecture"

| Priority | File | Why |
|----------|------|-----|
| 1 | `docs/INDEX.md` (proposed) | Landing page — tells you where everything is |
| 2 | `docs/planning/ROADMAP.md` | Architecture overview, feature status, file map |
| 3 | `docs/architecture/MVP_SCOPE.md` | Deep architecture, what's in/out of scope |
| 4 | `AGENTS.md` | Operational instructions for the AI |

**Total reading:** ~4 files. This is the onboarding scenario.

### Scenario 6: "Audit the project" (bookkeeper freshness pass)

| Priority | File | Why |
|----------|------|-----|
| 1 | `docs/planning/ROADMAP.md` | The current truth |
| 2 | `docs/INDEX.md` (proposed) | All files listed with status — quick to verify |
| 3 | `docs/reference/AI_PROBLEMS.md` | Bug tracker — verify fixes and open items |
| 4 | `AGENTS.md` | Verify freshness pass instructions |

**Total reading:** ~4 files.

---

## 6. Recommended AGENTS.md Changes

### 6.1 Add a "First Read" Section

Insert after the "Documentation Structure" table:

```markdown
## Quick Start for AI Subagents

If you're an AI agent spawned for a task, start here:

1. **Read `docs/INDEX.md`** — the master index of all documentation. It tells you what each file contains, its status (CURRENT / OUTDATED / ARCHIVE), and who it's for.
2. **Read `docs/planning/ROADMAP.md`** — the single source of truth for what's implemented, what's planned, and known bugs.
3. **Return to this file (`AGENTS.md`)** for operational instructions (project rules, decision framework, sprint workflow).

### Task-Specific Quick Links

| If your task is... | Start with these files |
|---|---|
| Understanding the project | `docs/INDEX.md` → `docs/planning/ROADMAP.md` → `docs/architecture/MVP_SCOPE.md` |
| Fixing a bug | `docs/reference/AI_PROBLEMS.md` → code in `backend/` → `docs/planning/ROADMAP.md` |
| Adding a feature | `docs/planning/ROADMAP.md` → `docs/architecture/MVP_SCOPE.md` → `.opencode/skills/new-integration-pattern/SKILL.md` |
| Retraining the model | `docs/planning/ROADMAP.md` (Sprint NEXT) → `docs/reference/xgboost-investigation-report.md` → `docs/research/RESEARCH_FINDINGS.md` |
| Running a freshness audit | `docs/INDEX.md` (verify file statuses) → `docs/planning/ROADMAP.md` (verify sprint status) |
```

### 6.2 Add a Status Key Section

Add after the Quick Start:

```markdown
### Documentation Status Key

| Badge | Meaning |
|-------|---------|
| **CURRENT** | Accurately reflects the current state of the project. Read this. |
| **OUTDATED** | Describes a previous state. May still contain useful architecture rationale, but verify against ROADMAP.md before acting. |
| **ARCHIVE** | Historical record. Not needed for normal work. Preserved for provenance/audit. |
| **BROKEN** | Missing file (symlink target does not exist). Do not attempt to read. |
```

### 6.3 Update the Documentation Structure Table

Current table (in AGENTS.md):

```markdown
| Category | Directory | Contents |
|---|---|---|
| Architecture | `docs/architecture/` | `MVP_SCOPE.md` — scope authority |
| Guides | `docs/guides/` | `DEMO_SCRIPT.md` (deleted), `TRIAGEMATE_BOOK_PROMPT.md` (deleted), `WINDOWS_SETUP.md` |
| Planning | `docs/planning/` | `ROADMAP.md`, `SPRINT_NEXT_PLAN.md` |
| Reference | `docs/reference/` | `AI_PROBLEMS.md`, `xgboost-investigation-report.md`, hostname standards, ML implementation plan |
| Research | `docs/research/` | `RESEARCH_FINDINGS.md` |
| Archive | `docs/archive/` | Superseded plans, handoffs, sprint archives |
```

Proposed replacement:

```markdown
| Category | Directory | Contents | Status |
|---|---|---|---|
| **Landing** | `docs/` | `INDEX.md` — master index of all documentation | CURRENT |
| Architecture | `docs/architecture/` | `arch-scope.md` — scope boundaries and architecture | CURRENT |
| Planning | `docs/planning/` | `plan-roadmap.md` — master status and roadmap | CURRENT |
| Reference | `docs/reference/` | `ref-ai-problems.md` — bug tracker | CURRENT |
| Reference | `docs/reference/` | `research-xgboost-investigation.md` — model root cause analysis | CURRENT |
| Reference | `docs/reference/` | `research-model-findings.md` — research findings | CURRENT |
| Reference | `docs/reference/` | `ref-hostname-standards.md` — hostname nomenclature reference | CURRENT |
| Guides | `docs/guides/` | `guide-setup-windows.md` — Windows setup | CURRENT |
| Archive | `docs/archive/` | Sprint handoffs, superseded plans, research sources | ARCHIVE |

> **Broken symlinks (to be removed):** `DEMO_SCRIPT.md` (deleted), `TRIAGEMATE_BOOK_PROMPT.md` (deleted) — their targets don't exist on disk.
```

### 6.4 Add a "File Freshness" Section

```markdown
## Documentation Freshness

The bookkeeper agent runs a freshness pass at the end of every sprint. During this pass:

1. Check every file in `docs/INDEX.md` for status accuracy
2. Update "Last Updated" dates
3. Mark files as OUTDATED or ARCHIVE when they're superseded
4. Cross-reference ROADMAP.md against the codebase for feature completion claims
5. Report any discrepancies as AI_PROBLEMS entries
```

---

## 7. Implementation Plan

Ordered steps for strike to execute:

### Phase 1: Cleanup (30 min)

| Step | Action | Details |
|------|--------|---------|
| 1.1 | Remove broken symlinks | Delete `DEMO_SCRIPT.md` (deleted) and `TRIAGEMATE_BOOK_PROMPT.md` (deleted) from root. Confirm they have no real targets. |
| 1.2 | Verify remaining symlinks | Check that all 8 remaining root-level symlinks resolve to real files in `docs/`. |
| 1.3 | Fix guides directory | The former DEMO_SCRIPT.md (deleted) content referenced in handoff notes is no longer available — document as removed. |

### Phase 2: Create INDEX.md (1 hr)

| Step | Action | Details |
|------|--------|---------|
| 2.1 | Create `docs/INDEX.md` | Per §2 structure: quick-start section, full file table with status/audience/purpose, category sections, broken files table |
| 2.2 | Seed from inventory | Use the inventory in §1.1 of this report as the initial data |
| 2.3 | Add status badges | Mark current files as CURRENT, archive files as ARCHIVE, reference docs as CURRENT, etc. |

### Phase 3: Consolidate Sprint NEXT into ROADMAP (30 min)

| Step | Action | Details |
|------|--------|---------|
| 3.1 | Move detailed commands | From `SPRINT_NEXT_PLAN.md` into `ROADMAP.md` as collapsible `<details>` blocks under the Sprint NEXT section |
| 3.2 | Archive SPRINT_NEXT_PLAN.md | Move to `docs/archive/` once merge is complete. Update INDEX.md. |
| 3.3 | Deduplicate | Check for duplicate text between the two files and remove from the source |

### Phase 4: Rename Files (30 min with symlink updates)

| Step | Action | Details |
|------|--------|---------|
| 4.1 | Rename in `docs/` | Apply the naming convention from §4.2. For example: `mv docs/planning/ROADMAP.md docs/planning/plan-roadmap.md` |
| 4.2 | Update symlinks | Point old names → new names. e.g., `ROADMAP.md → docs/planning/plan-roadmap.md` |
| 4.3 | Update AGENTS.md | Update the Documentation Structure table and Project File Map to reflect new names |
| 4.4 | Create INDEX.md | Include both old and new names in a transition column for 1 sprint |

### Phase 5: Add Cross-References (20 min)

| Step | Action | Details |
|------|--------|---------|
| 5.1 | xgboost-investigation-report.md | Add note: "See also RESEARCH_FINDINGS.md for parallel pipeline drift analysis" |
| 5.2 | RESEARCH_FINDINGS.md | Add note: "See also xgboost-investigation-report.md for 8 code fixes already applied" |
| 5.3 | MVP_SCOPE.md | Keep the CAUTION banner. Add link to ROADMAP.md for current status. |

### Phase 6: Update AGENTS.md (20 min)

| Step | Action | Details |
|------|--------|---------|
| 6.1 | Add Quick Start section | Per §6.1 |
| 6.2 | Add Status Key | Per §6.2 |
| 6.3 | Update Structure table | Per §6.3 |
| 6.4 | Add Freshness section | Per §6.4 |

### Phase 7: Verify (15 min)

| Step | Action | Details |
|------|--------|---------|
| 7.1 | Check all symlinks | `find . -maxdepth 1 -name '*.md' -type l` — verify they all resolve |
| 7.2 | Test AI orientation | Read the new `docs/INDEX.md` — can you find the right file for any given task in ≤2 hops? |
| 7.3 | Run freshness pass | Bookkeeper should verify the new structure after implementation |

---

## Appendix A: Complete File Inventory (as of 7 July 2026)

| # | Path | Status | Audience | Purpose | Words | Last Updated |
|---|------|--------|----------|---------|-------|-------------|
| 1 | `AGENTS.md` | CURRENT | AI | AI operational instructions, project rules, doc structure map | ~400 | 2026-07-02 |
| 2 | `docs/architecture/MVP_SCOPE.md` | OUTDATED | Both | MVP scope, in/out-of-scope decisions, risk register, verification criteria | ~3,500 | 2026-06-30 |
| 3 | `docs/planning/ROADMAP.md` | CURRENT | Both | Master status tracker, sprint completion, config, known bugs, file map | ~4,500 | 2026-07-02 |
| 4 | `docs/archive/SPRINT_NEXT_PLAN.md` | CURRENT (partially superseded) | AI | Sprint NEXT implementation details (Items 1-8) — overlaps with ROADMAP | ~3,000 | 2026-07-02 |
| 5 | `docs/reference/AI_PROBLEMS.md` | CURRENT | AI | Bug tracker for AI-generated code issues, fixes, and workarounds | ~2,800 | 2026-07-02 |
| 6 | `docs/reference/xgboost-investigation-report.md` | CURRENT | AI | Root cause analysis of 8 model issues, fixes applied, pre/post metrics | ~4,000 | 2026-07-02 |
| 7 | `docs/research/RESEARCH_FINDINGS.md` | CURRENT | AI | Research on label strategy, early indicators, missing KEV, EPSS baseline, pipeline drifts | ~5,000 | 2026-07-03 |
| 8 | `docs/reference/ml-implementation-plan.md` | OUTDATED | Both | Original ML architecture plan — superseded by implementation changes | ~6,500 | 2026-06-16 |
| 9 | `docs/reference/hostname-standards.md` | CURRENT | Human | Reference doc on hostname nomenclature and WA government data classification | ~4,000 | 2026-06-16 |
| 10 | `docs/guides/WINDOWS_SETUP.md` | CURRENT | Human | Windows 10/11 setup instructions | ~1,500 | 2026-06-16 |
| 11 | `docs/archive/handoffs/SPRINT_9_HANDOFF.md` | ARCHIVE | Both | Historical sprint handoff — data corpus build, feature fill | ~1,900 | 2026-07-02 |
| 12 | `docs/archive/sprints-1-6/*.md` (11 files) | ARCHIVE | Both | Historical sprint handoffs, plans, briefings — preserved for provenance | varies | 2026-06 to 2026-07 |
| 13 | `docs/archive/*.md` (6 files) | ARCHIVE | Both | Source research documents fed into ML Implementation Plan | varies | 2026-06 |


---

## Appendix B: Files Never Read by AI (by Priority)

Based on analysis of the 40+ files, here's what an AI subagent almost never needs:

| File | Rationale |
|------|-----------|
| `docs/archive/sprints-1-6/SPRINT_1_HANDOFF.md` → `SPRINT_8_HANDOFF.md` | Superseded by ROADMAP.md. Only useful for deep historical trace. |
| `docs/archive/sprints-1-6/TEAM_BRIEFING.md` | Sprint team logistics, not code/docs info. |
| `docs/archive/sprints-1-6/PRE_DEMO_PLAN.md` | Pre-demo hardening plan — all items done. |
| `docs/archive/Additional Information.md` | Early pipeline concept document — absorbed into ML Plan. |
| `docs/archive/TriageMate ML Research.md` | Raw research — absorbed into ML Plan. |
| `docs/archive/TriageMate MVP Transformation.md` | Early scope transformation — all implemented. |
| `docs/reference/hostname-standards.md` | Human reference — only needed when adding WA-government-specific features. |

**Key insight:** Of ~36 non-broken files, an AI subagent realistically needs **4-5** for any given task. The remaining 31 are either archive, human-only reference, or superseded. This validates the INDEX.md approach — the AI reads one file to know which 4 it actually needs.
