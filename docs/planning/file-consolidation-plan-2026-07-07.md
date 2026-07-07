# .md File Consolidation Plan

> **Status: CURRENT** (7 July 2026)

**Date:** 7 July 2026  
**Author:** Bookkeeper  
**Purpose:** Propose a concrete consolidation strategy to reduce file count, eliminate duplication, and improve AI readability.

---

## Current State Map

### Inventory of All Active (Non-Archived) `.md` Files

| # | File | Lines | Est. Words | Category | Freshness | Overlap Score | Notes |
|---|------|-------|-----------|----------|-----------|---------------|-------|
| 1 | `docs/architecture/MVP_SCOPE.md` | 230 | ~3,800 | Architecture | 🔴 STALE — self-declared outdated | Heavy overlap with ROADMAP.md (§Sprint Status) | Banner says "written Sprint 1, not updated" |
| 2 | `docs/planning/ROADMAP.md` | 388 | ~6,500 | Planning | 🟢 CURRENT | Contains content from SPRINT_NEXT_PLAN (items 2,3,6,8), MVP_SCOPE (status), AI_PROBLEMS (bug table) | Best single source of truth |
| 3 | `docs/archive/SPRINT_NEXT_PLAN.md` | 322 | ~5,300 | Planning | 🟡 SUPERSEDED | 90% duplicated in ROADMAP.md (§Sprint NEXT) | Only Item 1 (XGBoost retrain) remains pending; rest is already in ROADMAP |
| 4 | `docs/reference/AI_PROBLEMS.md` | 165 | ~2,700 | Reference | 🟡 MOSTLY STALE | Overlaps with xgboost-investigation-report (both document bugs) | Only 1 unfixed item (#14, won't-fix). Rest is historical record |
| 5 | `docs/reference/xgboost-investigation-report.md` | 214 | ~3,500 | Reference | 🟡 MIXED | Overlaps with AI_PROBLEMS (bugs), RESEARCH_FINDINGS (ML), ML Plan (architecture) | Deep dive report with 8 fixes. Fixes applied, retrain pending |
| 6 | `docs/reference/ml-implementation-plan.md` | 882 | ~15,000 | Reference | 🔴 STALE — self-declared outdated | Major overlap with RESEARCH_FINDINGS, xgboost-investigation-report, MVP_SCOPE | Banner says "OUTDATED — preserved for historical reference" |
| 7 | `docs/reference/hostname-standards.md` | 175 | ~5,000* | Reference | 🟢 EXTERNAL REFERENCE | Low overlap — unique content | Long external citations, research-heavy |
| 8 | `docs/research/RESEARCH_FINDINGS.md` | 192 | ~3,200 | Research | 🟡 MIXED | Overlaps with xgboost-investigation-report (ML fixes), ML Plan (strategy) | Some findings acted on in Sprint NEXT; has note saying "written before Sprint NEXT" |
| 9 | `docs/guides/WINDOWS_SETUP.md` | 118 | ~1,900 | Guides | 🟢 CURRENT | Low overlap | Focused, single-purpose |
| 10 | `AGENTS.md` (root) | 36 | ~400 | Config | 🟡 PARTIALLY WRONG | Describes symlink structure that's partially broken | Lists DEMO_SCRIPT.md and TRIAGEMATE_BOOK_PROMPT.md as existing in docs/guides/ — both deleted |
| 11 | `backend/ml/README.md` | 26 | ~400 | ML Artifacts | 🟢 CURRENT | Low overlap | Small, focused, lives with code |

### Broken Symlinks

| Root File | Claims to Symlink To | Status |
|-----------|---------------------|--------|
| `DEMO_SCRIPT.md` (deleted) | `docs/guides/DEMO_SCRIPT.md` | 🔴 BROKEN — symlink removed |
| `TRIAGEMATE_BOOK_PROMPT.md` (deleted) | `docs/guides/TRIAGEMATE_BOOK_PROMPT.md` | 🔴 BROKEN — symlink removed |

**Total word count estimate for active docs:** ~47,700 words across 11 files.  
**Total unique content (deduplicated estimate):** ~32,000 words. ~33% redundancy.

---

## Consolidation Proposals

### Merge Group 1: Architecture Authority

**Merge MVP_SCOPE.md into ARCHITECTURE.md** (absorbing current status from ROADMAP)

| Source File | Role in New Doc | Preserved | Dropped |
|-------------|----------------|-----------|---------|
| `MVP_SCOPE.md` | Architecture description (sections 2-5) | Pipeline stage descriptions, IN/OUT of scope tables, risk register, verification criteria | Outdated deferral notes (most items now done), Sprint-1-specific language, duplicate status markers |
| `ROADMAP.md` (§Pipeline Stages, §ML Artifacts, §Project File Map) | Current implementation status | Status tables showing what's actually built | — |

**Proposed new file:** `docs/architecture/ARCHITECTURE.md` (replaces MVP_SCOPE.md)  
**Contents:**
- What TriageMate is (1-page elevator)
- Pipeline architecture diagram (ASCII)
- Per-stage description with implementation status (current, not Sprint-1-era)
- IN scope / deferred table (current, not Sprint-1)
- Project file map
- Verification criteria

**What gets cut:**
- "CAUTION: Sprint 1" banner
- References to Sprint-1-specific deferrals that are now done
- Duplicate status reporting (keep that in ROADMAP)

**Tradeoff:**
- **Pro:** One authoritative architecture doc instead of two that contradict each other. New reader reads one file.
- **Con:** Lose the historical record of Sprint 1 scope decisions. Mitigation: archive MVP_SCOPE.md to docs/archive/.
- **Risk:** New ARCHITECTURE.md could fall out of date if not maintained as part of sprint workflow.

---

### Merge Group 2: Roadmap + Plan + Bugs

**Merge ROADMAP.md + SPRINT_NEXT_PLAN.md + AI_PROBLEMS.md into ROADMAP.md** (single master status)

| Source File | Role in New Doc | Preserved | Dropped |
|-------------|----------------|-----------|---------|
| `ROADMAP.md` | Master status | Sprint status table, all done items, config table, quick start, project map | — |
| `SPRINT_NEXT_PLAN.md` | Active work item | Item 1 (XGBoost retrain) — the only pending item | Items 2,3,6,8 (already done, already in ROADMAP), implementation order, verification commands |
| `AI_PROBLEMS.md` | Bug tracker | #14 (only unfixed item) moved to ROADMAP Known Bugs section | All fixed items (historical record preserved in archive) |

**Proposed action:** 
1. Move the 1 pending item from SPRINT_NEXT_PLAN into ROADMAP §Sprint NEXT
2. Move the 1 unfixed bug from AI_PROBLEMS into ROADMAP §Known Bugs
3. Archive SPRINT_NEXT_PLAN.md and AI_PROBLEMS.md to `docs/archive/`
4. Fix broken symlinks at root

**Tradeoff:**
- **Pro:** Single file to read for "what's the status." No more cross-referencing between ROADMAP, SPRINT_NEXT_PLAN, and AI_PROBLEMS. The only pending work and bugs live in one place.
- **Con:** ROADMAP grows by ~50 lines. Still manageable (~440 lines vs current 388).
- **Risk:** If a new bug emerges, the developer must remember to add it to ROADMAP rather than creating a new AI_PROBLEMS.md. Mitigation: update AGENTS.md to say "bugs go in ROADMAP §Known Bugs."

---

### Merge Group 3: ML Ecosystem Guide

**Merge xgboost-investigation-report.md + RESEARCH_FINDINGS.md + ML Implementation Plan → docs/reference/ML_GUIDE.md**

| Source File | Role in New Doc | Preserved | Dropped |
|-------------|----------------|-----------|---------|
| `xgboost-investigation-report.md` | Root cause analysis + fixes | 8 findings, fix descriptions, verification steps, file-change table | Duplicate bug listings that overlap with AI_PROBLEMS |
| `RESEARCH_FINDINGS.md` | Future research findings | Q1-Q5 findings, feature importance analysis, KEV missing analysis, EPSS baseline | Roadmap sections now superseded by Sprint NEXT+ actions |
| `ml-implementation-plan.md` | Architecture decisions + training strategy | Feature list (§2.1), training data blueprint (§4), operational cadence (§6), RAG plan (§5), source divergence log (Appendix A) | Outdated content: PCA references, SecureBERT2.0 CWE encoder details, pre-Sprint-9 feature counts, incorrect model parameters |

**Proposed new file:** `docs/reference/ML_GUIDE.md` (~600 lines)  
**Contents by section:**
1. **ML Architecture Overview** — tier pipeline, feature vector (35+384=419), scoring 6 dimensions
2. **Feature Engineering** — the 35 tabular features + 384 SBERT (no PCA)
3. **Training Pipeline** — data sources, corpus building, label strategy
4. **XGBoost Model** — hyperparameters, calibration, investigation findings with fix status
5. **Research Findings & Future Work** — CWE-stratified thresholds, missing KEV recovery, EPSS baseline
6. **Operational Cadence** — retraining triggers, EPSS refresh, audit sampling
7. **Appendix: Source Divergence Log** — kept from ML Plan (documents why decisions were made)

**What gets cut:**
- PCA references (removed v2.5)
- SecureBERT2.0 CWE classifier (deprecated)
- Incorrect feature counts (37→35 tabular, 69→419 total)
- Pre-Sprint-9 training numbers
- Duplicate cross-references to AI_PROBLEMS.md

**Tradeoff:**
- **Pro:** One ML file covers architecture, current state, research, and future work. Reduces 3 files + ~21,700 words to 1 file + ~8,000 words. New ML contributors read one doc instead of three.
- **Con:** Lose the standalone investigation report narrative format.
- **Risk:** ML_GUIDE.md could become a dumping ground. Must maintain section structure. Add a "Quick Reference" table at top with links to code.

---

### Merge Group 4: Canonical Setup Guide

**Keep WINDOWS_SETUP.md + create SETUP.md covering all platforms**

| Source File | Role in New Doc | Preserved | Dropped |
|-------------|----------------|-----------|---------|
| `WINDOWS_SETUP.md` | Platform-specific | Windows instructions | — |
| `ROADMAP.md` (§Quick Start) | Linux/Mac commands | `uvicorn main:app`, pytest, curl verification | — |
| (New) Docker instructions | Container setup | `docker compose up --build` | — |

**Proposed action:** Create `docs/guides/SETUP.md` that covers:
1. Prerequisites (Python, Git, Docker)
2. Clone & quick start (3 commands)
3. Platform notes (link to WINDOWS_SETUP.md for Windows specifics)
4. Docker setup
5. Configuration (.env, API keys)
6. Seed data & verification
7. Troubleshooting

Keep `WINDOWS_SETUP.md` as the Windows deep-dive, referenced from SETUP.md.

**Tradeoff:**
- **Pro:** Developer reads one 80-line file to get running. Windows users still get their dedicated guide.
- **Con:** Two setup files instead of one. But the content is sufficiently different (cross-platform vs Windows-specific) that this is justified.

---

### Merge Group 5: Reference Standards

**Rename and retain `hostname-standards.md`**

This file is a long, well-researched external reference. It doesn't overlap with other docs. It should be:
1. Renamed to `docs/reference/HOSTNAME_STANDARDS.md` (remove spaces, shorter)
2. Optionally add a one-page summary at the top with "Why This Matters for TriageMate"

**Tradeoff:**
- **Pro:** Unique content preserved. Better discoverability with cleaner filename.
- **Con:** Still very long. Not typically read by AI during development — it's a reference lookup.

---

## Proposed Canonical Set (6 Files)

After consolidation, the active documentation set would be:

| # | File | Purpose | ~Lines | Source Files |
|---|------|---------|--------|-------------|
| 1 | `AGENTS.md` (root) | Agent command center — rules, doc map, workflow | 40 | Current AGENTS.md + new doc index |
| 2 | `docs/architecture/ARCHITECTURE.md` | What the system is, how it's built, pipeline stages | 250 | MVP_SCOPE.md (distilled) + ROADMAP.md (status) |
| 3 | `docs/planning/ROADMAP.md` | Master status — what's done, what's next, known bugs | 440 | Current ROADMAP.md + SPRINT_NEXT_PLAN (item 1) + AI_PROBLEMS (#14) |
| 4 | `docs/guides/SETUP.md` | Quick start — all platforms, Docker, config, verification | 80 | WINDOWS_SETUP.md (extract) + ROADMAP.md (Quick Start) |
| 5 | `docs/reference/ML_GUIDE.md` | ML ecosystem — features, training, research, future work | 600 | xgboost-investigation-report + RESEARCH_FINDINGS + ML Plan (distilled) |
| 6 | `docs/reference/hostname-standards.md` | WA gov hostname + data classification reference | 175 | Retained as-is |

**Plus retained as-is:**
- `docs/guides/WINDOWS_SETUP.md` — Windows deep-dive
- `backend/ml/README.md` — ML artifact index (lives with code)

**Archived:**
- `docs/architecture/MVP_SCOPE.md` → superseded by ARCHITECTURE.md
- `docs/planning/SPRINT_NEXT_PLAN.md` → superseded by ROADMAP.md
- `docs/reference/AI_PROBLEMS.md` → superseded by ROADMAP.md §Known Bugs
- `docs/reference/xgboost-investigation-report.md` → merged into ML_GUIDE.md
- `docs/reference/ml-implementation-plan.md` → merged into ML_GUIDE.md
- `docs/research/RESEARCH_FINDINGS.md` → merged into ML_GUIDE.md

**Deleted / rebuilt symlinks:**
- `AI_PROBLEMS.md` (root) → broken symlink, remove or redirect to ROADMAP.md
- `SPRINT_NEXT_PLAN.md` (root) → broken symlink, remove or redirect to ROADMAP.md
- `DEMO_SCRIPT.md` (root) → broken symlink, removed (file never existed)
- `TRIAGEMATE_BOOK_PROMPT.md` (root) → broken symlink, removed (file never existed)
- `MVP_SCOPE.md` (root) → redirect to ARCHITECTURE.md
- `xgboost-investigation-report.md` (root) → redirect to ML_GUIDE.md
- `RESEARCH_FINDINGS.md` (root) → redirect to ML_GUIDE.md

---

## Migration Plan

### Phase 1 — Create New Files (estimated 2 hours)

| Step | Action | Time |
|------|--------|------|
| 1.1 | Create `docs/architecture/ARCHITECTURE.md` by distilling MVP_SCOPE.md §2-5, incorporating current status from ROADMAP.md | 30 min |
| 1.2 | Update `docs/planning/ROADMAP.md`: add Item 1 from SPRINT_NEXT_PLAN, add #14 from AI_PROBLEMS, remove duplicate Sprint NEXT items already listed | 10 min |
| 1.3 | Create `docs/guides/SETUP.md` with cross-platform quick start | 15 min |
| 1.4 | Create `docs/reference/ML_GUIDE.md` by merging 3 source files, stripping outdated PCA/SecureBERT references | 60 min |
| 1.5 | Rename to `hostname-standards.md` (done) | 2 min |

### Phase 2 — Archive Superceded Files (10 min)

| Step | Action |
|------|--------|
| 2.1 | Move `MVP_SCOPE.md` to `docs/archive/architecture/MVP_SCOPE.md` |
| 2.2 | Move `SPRINT_NEXT_PLAN.md` to `docs/archive/planning/SPRINT_NEXT_PLAN.md` |
| 2.3 | Move `AI_PROBLEMS.md` to `docs/archive/reference/AI_PROBLEMS.md` |
| 2.4 | Move `xgboost-investigation-report.md` to `docs/archive/reference/` |
| 2.5 | Move `ml-implementation-plan.md` to `docs/archive/reference/` |
| 2.6 | Move `RESEARCH_FINDINGS.md` to `docs/archive/research/RESEARCH_FINDINGS.md` |

### Phase 3 — Fix Symlinks (10 min)

| Step | Action |
|------|--------|
| 3.1 | Removed broken `DEMO_SCRIPT.md` symlink at root |
| 3.2 | Removed broken `TRIAGEMATE_BOOK_PROMPT.md` symlink at root |
| 3.3 | Remove or redirect `AI_PROBLEMS.md` → `docs/planning/ROADMAP.md` |
| 3.4 | Remove or redirect `SPRINT_NEXT_PLAN.md` → `docs/planning/ROADMAP.md` |
| 3.5 | Create/update `MVP_SCOPE.md` → `docs/architecture/ARCHITECTURE.md` |
| 3.6 | Create/update `xgboost-investigation-report.md` → `docs/reference/ML_GUIDE.md` |
| 3.7 | Create/update `RESEARCH_FINDINGS.md` → `docs/reference/ML_GUIDE.md` |

### Phase 4 — Update AGENTS.md (5 min)

Rewrite the Documentation Structure table to reflect the canonical set (see below).

---

## AGENTS.md Update

Current `AGENTS.md` §Documentation Structure should be replaced with:

```markdown
## Documentation Structure

This project maintains a canonical set of 6 core documentation files. All root `.md` files
(except AGENTS.md) are symlinks into `docs/` for backward compatibility.

### Canonical Docs (read in order for onboarding)

| Category | File | Contents |
|---|---|---|
| Config | `AGENTS.md` | Agent rules, doc map, workflow (this file) |
| Architecture | `docs/architecture/ARCHITECTURE.md` | What the system is, pipeline stages, scope decisions |
| Planning | `docs/planning/ROADMAP.md` | Master status — done, next, known bugs |
| Setup | `docs/guides/SETUP.md` | Quick start — all platforms, Docker, config |
| ML | `docs/reference/ML_GUIDE.md` | ML ecosystem — features, training, research, future |
| Reference | `docs/reference/HOSTNAME_STANDARDS.md` | WA gov hostname + data classification standards |

### Supplementary Docs

| File | Contents |
|---|---|
| `docs/guides/WINDOWS_SETUP.md` | Windows-specific setup deep-dive |
| `backend/ml/README.md` | ML artifact index (lives with code) |

### Archive

All superseded planning docs, sprint handoffs, and old research live in `docs/archive/`.
Archived files are preserved for historical reference but should not be consulted for current status.
For current status, see `ROADMAP.md`.
For current architecture, see `ARCHITECTURE.md`.
For current ML understanding, see `ML_GUIDE.md`.
```

---

## Verdict

| Criterion | Current | Proposed | Improvement |
|-----------|---------|----------|-------------|
| Active docs count | 11 files | 8 files (6 canonical + 2 retained) | -27% |
| Total word count | ~47,700 | ~32,000 (est.) | -33% |
| Redundancy | ~33% duplication | ~5% duplication | Significant reduction |
| Broken symlinks | 4 (DEMO, TRIAGE_BOOK, AI_PROBLEMS, SPRINT_NEXT) | 0 | Clean root |
| AI onboarding cost | Read 6+ files to understand project | Read 3 files (ARCHITECTURE + ROADMAP + ML_GUIDE) | 50% reduction |

**Recommendation:** Proceed with this consolidation. The main effort is creating `ARCHITECTURE.md` and `ML_GUIDE.md` (approx. 90 min of writing). The rest is file moves and symlink updates (~30 min).
