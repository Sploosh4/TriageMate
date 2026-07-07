# Round 6 Content Audit

**Date:** 2026-07-07
**Requested by:** Commander (automated audit pass)
**Method:** Full re-read of all 12 active `.md` files, cross-referenced against disk state, symlink structure, INDEX.md, AGENTS.md, code in backend/

## Verdict: 10 issues found (2 critical, 5 moderate, 3 minor)

The documentation is in good structural shape. Round 5's cleanup work is holding: broken symlinks are gone, PRIS Act terminology is clean from active docs, docker-compose is clean, dimension counts are correct. The remaining issues cluster in two strategy documents (`ai-doc-strategy-2026-07-07.md` and `file-consolidation-plan-2026-07-07.md`) that were written with stale assumptions about state that had already been cleaned up minutes before. Two numerical contradictions remain in `ROADMAP.md`.

---

## Issues Found

### 🔴 Critical

| # | File | Line(s) | Issue | Suggested Fix |
|---|------|---------|-------|---------------|
| 1 | `docs/planning/ROADMAP.md` | 282 | **Wrong root symlink name.** Project File Map lists `xgboost-investigation-report.md → docs/reference/xgboost-investigation-report.md`, but the actual root symlink is `XGBOOST_INVESTIGATION_REPORT.md` (ALL_CAPS). The lowercase file does not exist at root. | Change `├── xgboost-investigation-report.md → docs/reference/xgboost-investigation-report.md` to `├── XGBOOST_INVESTIGATION_REPORT.md → docs/reference/xgboost-investigation-report.md` |
| 2 | `docs/planning/ROADMAP.md` | 146, 149 | **Numeric contradiction: "67 features (35 tabular + 384 SBERT)"** — 35 + 384 = 419, not 67. The `training_data_v2.npz` stores 67 columns, which are 35 tabular + 32 auxiliary/metadata columns (correctly described at line 189). Lines 146 and 149 conflate the corpus-file column count with the model's total dimension count. | Change to: "67 columns (35 tabular + 32 auxiliary) in corpus file; model uses 419 total dimensions (35 tabular + 384 SBERT embedding)". |

### 🟡 Moderate

| # | File | Line(s) | Issue | Suggested Fix |
|---|------|---------|-------|---------------|
| 3 | `docs/planning/ai-doc-strategy-2026-07-07.md` | 18 | **Wrong root symlink name in inventory.** Lists `xgboost-investigation-report.md` as a root symlink, but the actual symlink is `XGBOOST_INVESTIGATION_REPORT.md`. | Change to `XGBOOST_INVESTIGATION_REPORT.md` (or note the canonical lowercase name in `docs/reference/`). |
| 4 | `docs/planning/ai-doc-strategy-2026-07-07.md` | 21 | **SPRINT_NEXT_PLAN.md location wrong.** Says `docs/planning/` has 2 files: `ROADMAP.md` and `SPRINT_NEXT_PLAN.md`. But `SPRINT_NEXT_PLAN.md` was already moved to `docs/archive/` at the time this doc was written. `docs/planning/` now has 3 files (ROADMAP.md + this doc + file-consolidation-plan). | Update inventory count and contents for `docs/planning/`. |
| 5 | `docs/planning/ai-doc-strategy-2026-07-07.md` | 20 | **Stale docs/guides/ count.** Says `docs/guides/` has "1 (DEMO_SCRIPT and TRIAGEMATE_BOOK_PROMPT targets missing — broken symlinks, both deleted)". But these symlinks were already removed — only WINDOWS_SETUP.md remains. | Simplify to: "`WINDOWS_SETUP.md`" without parenthetical about deleted symlinks. |
| 6 | `docs/planning/ai-doc-strategy-2026-07-07.md` | 57 | **Finding 5 stale.** Claims "`DEMO_SCRIPT.md` and `TRIAGEMATE_BOOK_PROMPT.md` appear in root-level listings and `AGENTS.md`'s file map." But at the time of writing (13:54), these had already been removed from root (symlinks cleaned at 13:01). Current `AGENTS.md` does NOT list individual files in its Directory Map — only category descriptions. | Update Finding 5 to state these were already cleaned up. |
| 7 | `docs/planning/file-consolidation-plan-2026-07-07.md` | 294 | **Claims 4 broken symlinks but actually 0.** Verdict table says "Broken symlinks \| 4 (DEMO, TRIAGE_BOOK, AI_PROBLEMS, SPRINT_NEXT) \| 0". But `AI_PROBLEMS.md` is a valid symlink (resolves correctly). `SPRINT_NEXT_PLAN.md` doesn't exist at root. `DEMO_SCRIPT.md` and `TRIAGEMATE_BOOK_PROMPT.md` have been removed. There are 6 valid symlinks, 0 broken. | Change "4" to "0" in the Current column. |
| 8 | `docs/planning/file-consolidation-plan-2026-07-07.md` | 26 | **Claims AGENTS.md lists DEMO_SCRIPT/TRIAGEMATE_BOOK.** Row 10 says AGENTS.md "Lists DEMO_SCRIPT.md and TRIAGEMATE_BOOK_PROMPT.md as existing in docs/guides/ — both deleted." Current AGENTS.md does not list individual files — its Directory Map only has category descriptions (e.g., "Guides \| Setup, configuration, walkthroughs"). | Remove this claim or rephrase to state the broken symlinks were already cleaned up. |

### 🟢 Minor

| # | File | Line(s) | Issue | Suggested Fix |
|---|------|---------|-------|---------------|
| 9 | `docs/planning/ai-doc-strategy-2026-07-07.md` | 324 (proposed table) | **Proposed AGENTS.md update references deleted files.** The §6.3 proposed replacement table includes `DEMO_SCRIPT.md (deleted)` and `TRIAGEMATE_BOOK_PROMPT.md (deleted)` in the Guides row. These files don't exist. | Remove these from the proposed table. |
| 10 | `docs/planning/ai-doc-strategy-2026-07-07.md` | 346 | **"Broken symlinks (to be removed)" lists already-removed files.** Phase 1 step 1.1 says "Remove broken symlinks: Delete `DEMO_SCRIPT.md` and `TRIAGEMATE_BOOK_PROMPT.md`" — but these were already deleted. | Mark as already done, or remove the step. |

---

## Clean Files (zero issues found)

| File | Status | Notes |
|------|--------|-------|
| `AGENTS.md` | ✅ CLEAN | All refs correct, no stale file listings |
| `docs/INDEX.md` | ✅ CLEAN | All file paths verified, status badges match disk state |
| `docs/architecture/MVP_SCOPE.md` | ✅ CLEAN | OUTDATED by design, banner matches content |
| `docs/guides/WINDOWS_SETUP.md` | ✅ CLEAN | Uses `docker compose`, correct paths |
| `docs/reference/AI_PROBLEMS.md` | ✅ CLEAN | 1 unfixed issue, all claims match code |
| `docs/reference/hostname-standards.md` | ✅ CLEAN | External reference, self-contained |
| `docs/reference/ml-implementation-plan.md` | ✅ CLEAN | OUTDATED by design, banner lists changes |
| `docs/reference/xgboost-investigation-report.md` | ✅ CLEAN | 8 fixes, retrain pending, internal consistency |
| `docs/research/RESEARCH_FINDINGS.md` | ✅ CLEAN | Cross-refs verified, data appendix correct |

---

## Issues from Previous Rounds — Now Verified Clean

Issues flagged in Rounds 1-5 that were fixed and confirmed clean in this pass:

| Round(s) | Issue | Status |
|----------|-------|--------|
| R1-R5 | `PRIS Act` terminology in active docs | ✅ CLEAN — only in archived files + code docstrings (out of scope) |
| R1-R5 | `docker-compose` (hyphenated) command | ✅ CLEAN — all active docs use `docker compose` |
| R1-R5 | "5 dimensions" scoring engine | ✅ CLEAN — ROADMAP.md correctly says "6 dimensions" |
| R1-R5 | Broken symlinks (DEMO_SCRIPT, TRIAGEMATE_BOOK) | ✅ CLEAN — removed from root |
| R1-R5 | `SPRINT_NEXT_PLAN.md` referenced at wrong path | ✅ CLEAN — ROADMAP.md correctly says archived, INDEX.md correct |
| R1-R5 | 37→36→35 feature count confusion | ✅ CLEAN — ROADMAP.md lines 75-76, 189 all consistent |
| R5 | ai-doc-strategy.json vs .md naming | ✅ CLEAN — only `.md` files exist |
| R5 | Plan docs in planning/ | ✅ CLEAN — ai-doc-strategy and file-consolidation-plan in correct dir |

---

## Cross-Reference Verification Summary

### INDEX.md Accuracy Check
| Check | Result |
|-------|--------|
| Every listed file exists at that path | ✅ PASS — all 12 listed files verified on disk |
| Every active doc file listed in INDEX | ⚠️ PASS — `backend/ml/README.md` is not in INDEX (expected — it lives with code, not docs/) |
| Statuses match actual file badges | ✅ PASS — all CURRENT/OUTDATED/ARCHIVED match |
| Quick Reference table entries | ✅ PASS — all 10 entries point to correct locations |

### AGENTS.md Accuracy Check
| Check | Result |
|-------|--------|
| Quick Reference table paths exist | ✅ PASS — ROADMAP.md, INDEX.md, AI_PROBLEMS.md, hostname-standards.md, WINDOWS_SETUP.md all exist |
| Directory Map directories exist | ✅ PASS — all 6 directories verified |
| No stale file references | ✅ PASS — AGENTS.md has no file-level listings |

### ROADMAP.md vs INDEX.md vs Disk
| Check | Result |
|-------|--------|
| Sprint status matches INDEX | ✅ PASS |
| File map entries exist on disk | ⚠️ **ISSUE #1** — `xgboost-investigation-report.md` listed but real file is `XGBOOST_INVESTIGATION_REPORT.md` |
| ML artifact statuses match | ✅ PASS |
| Known bugs match AI_PROBLEMS.md | ✅ PASS — 1 unfixed (#14, won't-fix) |

---

## Summary

| Metric | Value |
|--------|-------|
| Total files audited | 12 |
| Clean files | 9 |
| Files with issues | 2 (ROADMAP.md, ai-doc-strategy.md, file-consolidation-plan.md) |
| Issues found | 10 (2 critical, 5 moderate, 3 minor) |
| Issues from prior rounds, now clean | 8 categories |
| Broken symlinks at root | 0 |
