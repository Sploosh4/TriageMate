# Round 7 Content Audit

**Date:** 2026-07-07
**Requested by:** Commander (automated audit pass)
**Method:** Full re-read of all 12 active `.md` files, cross-referenced against actual disk state (symlinks, file existence, directory tree, code references)
**Previous audit:** R6 (10 issues found)

---

## Executive Summary

**Verdict: 10 issues found (1 critical, 5 moderate, 4 minor).**

The documentation is in very good shape. Round 6's 10 issues have been substantially addressed — 7 of 10 are confirmed fixed. The remaining 3 stale items are in the two strategy/planning documents (`ai-doc-strategy` and `ROADMAP.md`), plus 4 new issues surfaced in this pass.

**R6 fix rate:** 7/10 fixed ✅ | 3/10 still open 🔴 (all in `ai-doc-strategy-2026-07-07.md`)

---

## Issues from Round 6 — Fixed (Verified Clean)

| # | File | Issue | Status |
|---|------|-------|--------|
| R6-1 | ROADMAP.md:282 | Wrong symlink name (`xgboost-investigation-report.md` vs `XGBOOST_INVESTIGATION_REPORT.md`) | ✅ Fixed — now ALL_CAPS |
| R6-2 | ROADMAP.md:146,149 | 67 features conflated with 419 dims | ✅ Fixed — now clearly states "67 columns (35 tabular + 32 auxiliary); model uses 419 dims" |
| R6-3 | ai-doc-strategy.md:18 | Wrong root symlink name | ✅ Fixed — now `XGBOOST_INVESTIGATION_REPORT.md` |
| R6-4 | ai-doc-strategy.md:21 | SPRINT_NEXT_PLAN in wrong dir | ✅ Fixed — planning dir inventory correct |
| R6-5 | ai-doc-strategy.md:20 | Guides dir count stale | ✅ Fixed — simplified to just WINDOWS_SETUP.md |
| R6-7 | file-consolidation-plan.md:294 | Claimed 4 broken symlinks, actually 0 | ✅ Fixed — now "2 (DEMO, TRIAGE_BOOK) → resolved to 0" |
| R6-8 | file-consolidation-plan.md:26 | Claimed AGENTS.md lists broken files | ✅ Fixed — now says "AGENTS.md no longer lists deleted files" |

---

## Issues from Round 6 — Still Open

### 🔴 R6-6: ai-doc-strategy Finding 5 — Stale broken-symlink claim
**File:** `docs/planning/ai-doc-strategy-2026-07-07.md:56-57`
**Issue:** Finding 5 states: "`DEMO_SCRIPT.md` and `TRIAGEMATE_BOOK_PROMPT.md` appear in root-level listings and `AGENTS.md`'s file map". Neither is true anymore — both symlinks were removed from root, and AGENTS.md's Directory Map doesn't list individual files.
**Status:** 🔴 UNFIXED

### 🟡 R6-9: ai-doc-strategy §6.3 — "Current table (in AGENTS.md)" is fabricated
**File:** `docs/planning/ai-doc-strategy-2026-07-07.md:318-329`
**Issue:** The "Current table (in AGENTS.md)" section shows a detailed file-level table that AGENTS.md has never had. AGENTS.md's actual Directory Map only lists category descriptions (e.g., "Setup, configuration, walkthroughs"), not individual filenames. The proposed replacement table also references files that would need renaming (e.g., `arch-scope.md`, `plan-roadmap.md`) which hasn't happened.
**Status:** 🔴 UNFIXED
**Note:** This is a strategy proposal, so some aspirational content is expected. But the "current" table should accurately reflect AGENTS.md's actual content.

### 🟢 R6-10: ai-doc-strategy §6.3 — "Broken symlinks (to be removed)" already removed
**File:** `docs/planning/ai-doc-strategy-2026-07-07.md:346`
**Issue:** States "Broken symlinks (to be removed): DEMO_SCRIPT.md, TRIAGEMATE_BOOK_PROMPT.md" — but these were already removed before this document was written. Phase 1 step 1.1 on line 373-375 marks them ✅ Done.
**Status:** 🔴 UNFIXED

---

## New Issues Found (Round 7)

### 🔴 Critical

#### R7-1: AI_PROBLEMS.md claims a file is preserved that doesn't exist
**File:** `docs/reference/AI_PROBLEMS.md:12-13`
**Text:** "The deprecated file is preserved as `backend/ml/cwe_classifier_deprecated.py` for reference."
**Reality:** `backend/ml/cwe_classifier_deprecated.py` does NOT exist on disk. No `cwe_classifier*` files exist anywhere in `backend/ml/`. The file was removed at some point after the AI_PROBLEMS entry was written.
**Impact:** An AI following this reference will attempt to read the file and get ENOENT. The deprecation claim is still accurate (replaced by `backend/ingest_cwe.py`), but the preservation promise is false.
**Suggested fix:** Remove the sentence "The deprecated file is preserved as..." or update to reflect that it has been deleted.

---

### 🟡 Moderate

#### R7-2: ROADMAP.md — XGBoost retrain status: 🔧 "Retraining" vs "Training not yet run"
**File:** `docs/planning/ROADMAP.md:185,189`
**Issue:** Line 185 says Item 1 is "🔧 Retraining" and line 189 shows the same 🔧 emoji. But line 189 also says "**Training not yet run.**" The 🔧 emoji is defined (line 6) as "In progress." Training hasn't been run at all — this should be 📋 Todo or a different status.
**Impact:** Status indicator misleads readers into thinking the retrain is actively running or partially complete.
**Suggested fix:** Change the emoji to 📋 and the description to "Pending — code fixes applied, training command not yet executed."

#### R7-3: ROADMAP.md line 38 calls auxiliary columns "features"
**File:** `docs/planning/ROADMAP.md:38` (Data Corpus table)
**Text:** "144K filtered training set, 67 features (+ 1 label = 68 columns)"
**Reality:** Lines 146 and 149 correctly clarify these as "67 columns (35 tabular + 32 auxiliary)." The 32 auxiliary columns are metadata (dates, CVE IDs, etc.), not model features. Line 38 calling them "features" contradicts this clarification.
**Suggested fix:** Change "67 features" to "67 columns" for consistency with lines 146, 149, and 189.

#### R7-4: ROADMAP.md Project File Map missing two new planning files
**File:** `docs/planning/ROADMAP.md:293` (file map section)
**Issue:** The Project File Map at lines 274-389 was last updated 2026-07-02, but two new planning files were created on 2026-07-07:
- `docs/planning/ai-doc-strategy-2026-07-07.md`
- `docs/planning/file-consolidation-plan-2026-07-07.md`

These exist on disk and are referenced by INDEX.md, but they don't appear in ROADMAP.md's directory listing.
**Suggested fix:** Add these two files to the `docs/planning/` section of the file map.

#### R7-5: Vendor popularity count discrepancy (17,100 vs 17,102)
**Files:** `docs/planning/ROADMAP.md:37,65` vs `docs/research/RESEARCH_FINDINGS.md:192`
**Texts:**
- ROADMAP.md: "17,100 vendors" (line 37), "17,100-vendor frequency index" (line 65)
- RESEARCH_FINDINGS.md: "Vendor popularity entries | 17,102" (line 192)
**Impact:** Minor, but indicates one of these figures wasn't updated after a corpus rebuild.
**Suggested fix:** Align to the correct number. If 17,102 is the current count from `vendor_popularity.json`, update ROADMAP.md. If it's 17,100, update RESEARCH_FINDINGS.md.

---

### 🟢 Minor

#### R7-6: RESEARCH_FINDINGS.md — Ambiguous "EPSS cache entries" label
**File:** `docs/research/RESEARCH_FINDINGS.md:185`
**Text:** "EPSS cache entries | 140,487 (subset)"
**Issue:** This appears in a Data Appendix where line 184 says "NVD corpus entries | 186,102." The "(subset)" clarifies that 140,487 is a subset of NVD corpus entries that have EPSS scores. But the label says "EPSS cache entries" which can be misinterpreted as a subset of the EPSS cache (full cache is 344,852 per ROADMAP.md).
**Suggested fix:** Change label to "NVD corpus entries with EPSS scores" for clarity.

#### R7-7: xgboost-investigation-report.md — "currently running" vs "not yet run"
**File:** `docs/reference/xgboost-investigation-report.md:15`
**Text:** "Five of eight require model retraining (currently running)."
**Reality:** ROADMAP.md:189 says "Training not yet run." The STATUS NOTE at lines 5-6 of the same report also says "has NOT yet been run." The word "currently running" in line 15 contradicts both.
**Suggested fix:** Change "currently running" to "not yet executed" for internal consistency within the same document.

#### R7-8: ROADMAP.md line 38 still says "67 features" after R6 fix
**File:** `docs/planning/ROADMAP.md:38`
**Note:** This overlaps with R7-3 above. It's listed separately because R6 explicitly flagged that lines 146/149 conflated features vs columns, and those were fixed — but the same issue persists at line 38 in the table header where "67 features" hasn't been updated to "67 columns."
**Suggested fix:** See R7-3.

---

## Files with Zero Issues Found

| File | Status | Notes |
|------|--------|-------|
| `AGENTS.md` | ✅ CLEAN | All paths verified, no stale references |
| `docs/INDEX.md` | ✅ CLEAN | All status badges match disk state, all paths exist |
| `docs/architecture/MVP_SCOPE.md` | ✅ CLEAN | OUTDATED by design, banner accurate |
| `docs/guides/WINDOWS_SETUP.md` | ✅ CLEAN | Uses `docker compose`, paths correct |
| `docs/reference/hostname-standards.md` | ✅ CLEAN | External reference, self-contained |
| `docs/reference/ml-implementation-plan.md` | ✅ CLEAN | OUTDATED by design, banner correct |
| `docs/planning/file-consolidation-plan-2026-07-07.md` | ✅ CLEAN | R6 issues fixed, no new issues |

---

## Cross-Reference Verification Summary

### INDEX.md Accuracy Check
| Check | Result |
|-------|--------|
| Every listed file exists at that path | ✅ PASS — all verified on disk |
| Status badges match file content | ✅ PASS |
| Quick Reference table points correctly | ✅ PASS |
| Missing archive root files mentioned | ⚠️ Note: 6 archive root files intentionally excluded per design, but no disclaimer note present |

### AGENTS.md Accuracy Check
| Check | Result |
|-------|--------|
| Quick Reference table paths exist | ✅ PASS |
| Directory Map directories exist | ✅ PASS |
| Root-level symlink claim verified | ✅ PASS — 6 symlinks, 1 real file (AGENTS.md) |

### ROADMAP.md vs Disk
| Check | Result |
|-------|--------|
| File Map entries resolve | ⚠️ PASS — but missing 2 new planning files (R7-4) |
| ML artifact statuses match | ⚠️ Retrain status inconsistent (R7-2) |
| Known bugs match AI_PROBLEMS.md | ✅ PASS — 1 unfixed (#14, won't-fix) |
| Symlink names in file map | ✅ Fixed from R6 |

---

## Symlink Health Check

| Root Symlink | Target | Status |
|---|---|---|
| `AGENTS.md` | (real file) | ✅ |
| `AI_PROBLEMS.md` | → `docs/reference/AI_PROBLEMS.md` | ✅ |
| `MVP_SCOPE.md` | → `docs/architecture/MVP_SCOPE.md` | ✅ |
| `RESEARCH_FINDINGS.md` | → `docs/research/RESEARCH_FINDINGS.md` | ✅ |
| `ROADMAP.md` | → `docs/planning/ROADMAP.md` | ✅ |
| `WINDOWS_SETUP.md` | → `docs/guides/WINDOWS_SETUP.md` | ✅ |
| `XGBOOST_INVESTIGATION_REPORT.md` | → `docs/reference/xgboost-investigation-report.md` | ✅ |

All 6 symlinks resolve correctly. Zero broken symlinks at root.

---

## Summary

| Metric | Value |
|--------|-------|
| Total files audited | 12 |
| Clean files | 7 |
| Files with issues | 5 (ROADMAP.md, AI_PROBLEMS.md, xgboost-investigation-report.md, RESEARCH_FINDINGS.md, ai-doc-strategy.md) |
| New issues found | 8 (1 critical, 5 moderate, 2 minor) |
| R6 issues still open | 3 (all in ai-doc-strategy.md) |
| Total open issues | 11 (5 moderate, 6 minor in active scope; 1 critical in AI_PROBLEMS.md) |
| Broken symlinks at root | 0 |

### Most impactful fix
**R7-1 (Critical):** AI_PROBLEMS.md claims `cwe_classifier_deprecated.py` is preserved. It isn't. An AI reading the file to understand the deprecated subsystem will get a missing-file error. Fix is a one-line edit.

### Notable improvement since R6
The R6 fix rate is 70% despite the two strategy/planning docs being written minutes before the cleanup happened. ROADMAP.md's two numerical confusion issues are fully resolved. The remaining stale items are cosmetic or in explicitly-provisional planning documents.
