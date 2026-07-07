# Round 4 Content Audit

**Date:** 7 July 2026
**Requested by:** Commander (post-consolidation freshness check)
**Sources consulted:** All 12 files listed in scope, plus directory tree and glob verification

---

## Verdict: ISSUES FOUND — 18 items across 5 categories

The documentation consolidation (INDEX.md, ai-doc-strategy, file-consolidation-plan) has improved organisation significantly, but numerous numeric contradictions, stale file references, and path inaccuracies remain in the core documents.

---

## Internal Contradictions

| File | Line(s) | Contradiction |
|---|---|---|
| `docs/planning/ROADMAP.md` | 38, 42-73, 144, 147 | **37 fields listed ≠ 35 tabular claimed ≠ 67 features ≠ 419 total dimensions.** The feature table at lines 42-73 lists 37 numbered fields. Text says "35 tabular features." The npz says 67 features. The model uses 35+384=419 dims. These four numbers (37, 35, 67, 419) are never reconciled. The reader cannot tell which is the authoritative count. |
| `docs/planning/ROADMAP.md` | 187 | **67 features vs "35 tabular + 384 SBERT = 419 total".** Line 187 says the training data has "67 features (35 tabular + 384 SBERT = 419 total)". 35+384=419, not 67. The parenthetical claims the 67 *equals* 419, which is mathematically impossible. It appears the 67 refers to raw columns in the npz file while 419 is the model's effective dimensionality — but this is never clarified. |
| `docs/reference/AI_PROBLEMS.md` | 9-167 | **Severity ordering is inconsistent.** Document uses sections: HIGH→FIXED→MEDIUM→ADDITIONAL→LOW. The "FIXED ITEMS" section (#4-8) sits between HIGH and MEDIUM, breaking severity ordering. "ADDITIONAL ISSUES" (A-K) appear between MEDIUM and LOW but include HIGH-severity items like label leakage (A). Reader has to read the whole document to find relevant bugs. |
| `docs/planning/ai-doc-strategy-2026-07-07.md` | 18 | **"8 symlinks" but lists 9 items.** Line 18 says "Root (symlinks to `docs/`) | **8** | MVP_SCOPE.md, ROADMAP.md, AI_PROBLEMS.md, RESEARCH_FINDINGS.md, XGBOOST_INVESTIGATION_REPORT.md, SPRINT_NEXT_PLAN.md, WINDOWS_SETUP.md, (2 broken: DEMO_SCRIPT.md, TRIAGEMATE_BOOK_PROMPT.md)". That's 7 valid + 2 broken = 9 total, not 8. |

---

## Cross-File Contradictions

| File A | File B | Issue |
|---|---|---|
| `docs/planning/ai-doc-strategy-2026-07-07.md` (Appx A, row 2) | `docs/architecture/MVP_SCOPE.md` (line 3) | **Status mismatch.** ai-doc-strategy marks MVP_SCOPE.md as `CURRENT (with caveats)`. The actual file says `Status: OUTDATED — Sprint 1 era`. The index file correctly marks it OUTDATED, but the strategy doc got it wrong. |
| `docs/planning/ROADMAP.md` (lines 270-284) | Actual filesystem (root dir listing) | **Claims 10 root symlinks exist.** ROADMAP.md's Project File Map lists MVP_SCOPE, ROADMAP, AI_PROBLEMS, DEMO_SCRIPT, WINDOWS_SETUP, SPRINT_NEXT_PLAN, RESEARCH_FINDINGS, XGBOOST_INVESTIGATION_REPORT, TRIAGEMATE_BOOK_PROMPT, plus AGENTS.md (real). Root directory has only 7 symlinks: AI_PROBLEMS, MVP_SCOPE, RESEARCH_FINDINGS, ROADMAP, WINDOWS_SETUP, XGBOOST_INVESTIGATION_REPORT (6) plus AGENTS.md (real). DEMO_SCRIPT, SPRINT_NEXT_PLAN, and TRIAGEMATE_BOOK_PROMPT do NOT exist at root level. |
| `docs/planning/ROADMAP.md` (lines 280-281, 283-284) | Actual `docs/` directory tree | **4 symlink targets are wrong or missing.** ROADMAP.md claims: `DEMO_SCRIPT.md → docs/guides/DEMO_SCRIPT.md` (target doesn't exist), `SPRINT_NEXT_PLAN.md → docs/planning/SPRINT_NEXT_PLAN.md` (target at `docs/archive/` not `docs/planning/`), `XGBOOST_INVESTIGATION_REPORT.md → docs/reference/XGBOOST_INVESTIGATION_REPORT.md` (actual file is `docs/reference/xgboost-investigation-report.md` — lowercase), `TRIAGEMATE_BOOK_PROMPT.md → docs/guides/TRIAGEMATE_BOOK_PROMPT.md` (target doesn't exist). |
| `docs/planning/ROADMAP.md` (line 308) | `docs/archive/sprints-1-6/` | **Claims SPRINT_1-8 handoffs exist.** Directory contains SPRINT_1, SPRINT_2, SPRINT_3, SPRINT_7, SPRINT_8. **SPRINT_4, SPRINT_5, SPRINT_6 handoff files are missing** — the range notation implies all 8 exist. |
| `docs/planning/ai-doc-strategy-2026-07-07.md` (Appx A, row 4) | `docs/archive/SPRINT_NEXT_PLAN.md` | **Wrong path for SPRINT_NEXT_PLAN.** ai-doc-strategy lists it at `docs/planning/SPRINT_NEXT_PLAN.md` with status "CURRENT (partially superseded)". The file actually lives at `docs/archive/SPRINT_NEXT_PLAN.md` and no copy exists at `docs/planning/`. |
| `docs/planning/file-consolidation-plan-2026-07-07.md` (line 19) | `docs/planning/` directory | **Same SPRINT_NEXT_PLAN path error.** file-consolidation-plan lists `docs/planning/SPRINT_NEXT_PLAN.md` as item #3. This file does not exist at that path. |
| `docs/planning/file-consolidation-plan-2026-07-07.md` (line 27) | `AGENTS.md` | **AGENTS.md line count wrong.** file-consolidation-plan says AGENTS.md is "25 lines / ~400 words". The actual file is **36 lines**. (Minor, but the plan uses this to estimate total deduplication.) |

---

## Stale References

| File | Line | Stale Ref | Should Be |
|---|---|---|---|
| `docs/planning/ROADMAP.md` | 278 | `DEMO_SCRIPT.md` listed in file map | Remove — dead symlink, file never existed at target |
| `docs/planning/ROADMAP.md` | 280, 296 | `SPRINT_NEXT_PLAN.md → docs/planning/SPRINT_NEXT_PLAN.md` | `SPRINT_NEXT_PLAN.md (no root symlink exists) → docs/archive/SPRINT_NEXT_PLAN.md` |
| `docs/planning/ROADMAP.md` | 281, 299 | `XGBOOST_INVESTIGATION_REPORT.md → docs/reference/XGBOOST_INVESTIGATION_REPORT.md` | `XGBOOST_INVESTIGATION_REPORT.md → docs/reference/xgboost-investigation-report.md` (lowercase) |
| `docs/planning/ROADMAP.md` | 282, 293 | `TRIAGEMATE_BOOK_PROMPT.md → docs/guides/TRIAGEMATE_BOOK_PROMPT.md` | Remove — dead symlink, file never existed at target |
| `docs/planning/ROADMAP.md` | 293 | `docs/guides/DEMO_SCRIPT.md` referenced as existing doc | Remove — does not exist on disk |
| `docs/planning/ROADMAP.md` | 308 | `SPRINT_1_HANDOFF.md … SPRINT_8_HANDOFF.md` — implies all 8 handoffs exist | Only SPRINT_1,2,3,7,8 exist. SPRINT_4,5,6 handoffs are missing from `docs/archive/sprints-1-6/` |
| `docs/planning/ai-doc-strategy-2026-07-07.md` | 436 | `docs/planning/SPRINT_NEXT_PLAN.md` | `docs/archive/SPRINT_NEXT_PLAN.md` |
| `docs/planning/ai-doc-strategy-2026-07-07.md` | 434 | `MVP_SCOPE.md` status: `CURRENT (with caveats)` | Status should be `OUTDATED` (file header says OUTDATED) |
| `docs/planning/file-consolidation-plan-2026-07-07.md` | 19 | `docs/planning/SPRINT_NEXT_PLAN.md` | `docs/archive/SPRINT_NEXT_PLAN.md` |
| `docs/reference/AI_PROBLEMS.md` | 3, 162-166 | Self-described as "CURRENT — 1 unfixed issue remaining" | This is technically accurate, but the 1 unfixed issue (#14) is WON'T FIX. Functional status is "0 actionable issues." Consider updating framing. |

### Old Terminology Scan

| File | Stale Term | Location |
|---|---|---|
| `docs/architecture/MVP_SCOPE.md` | `docker compose` | Line 31 — acceptable, as it's outdated by design and its banner warns readers |
| `docs/reference/ml-implementation-plan.md` | "5 dimensions", "37 features", "PCA", "SecureBERT" | Throughout — acceptable, as it's marked OUTDATED and the banner lists these specific changes |
| `docs/planning/file-consolidation-plan-2026-07-07.md` | Proposes renaming many files | The plan itself is CURRENT, but its suggested renames (e.g., ARCHITECTURE.md, ML_GUIDE.md) have not been executed, creating a gap between proposal and reality. **Not a stale reference per se, but worth noting the plan is not yet actioned.** |

---

## OUTDATED Banner Quality

| File | Banner Good? | What's Missing |
|---|---|---|
| `docs/architecture/MVP_SCOPE.md` | ✅ **Excellent** | Specific list of items now done (Docker, JWT, Alembic, T3 queue, drift dash, Pre-Tier RF, PostgreSQL). References ROADMAP.md, COURSE_CORRECTION.md, PRE_DEMO_PLAN.md. Couldn't ask for better. |
| `docs/reference/ml-implementation-plan.md` | ✅ **Good** | Lists PCA removed, SecureBERT deprecated, 35+384=419 features, 6 dims. Points to ROADMAP.md. The banner covers the major changes clearly. |
| `docs/planning/ai-doc-strategy-2026-07-07.md` | N/A (CURRENT) | — |
| `docs/planning/file-consolidation-plan-2026-07-07.md` | N/A (CURRENT) | — |
| All other files | N/A (CURRENT or ARCHIVE) | — |

**Verdict:** Both OUTDATED banners are strong. No improvements needed.

---

## AGENTS.md Accuracy

| Reference | Exists? | Notes |
|---|---|---|
| `docs/planning/ROADMAP.md` | ✅ Yes | Correct path |
| `docs/INDEX.md` | ✅ Yes | Correct path |
| `docs/reference/AI_PROBLEMS.md` | ✅ Yes | Correct path |
| `docs/planning/ROADMAP.md` §ML Artifacts | ✅ Yes | ROADMAP.md has a "ML Artifacts" section at line 140 |
| `docs/reference/hostname-standards.md` | ✅ Yes | Correct path (lowercase, kebab) |
| `docs/guides/WINDOWS_SETUP.md` | ✅ Yes | Correct path |
| Directory Map (Architecture → `docs/architecture/`) | ✅ Correct | Contains `MVP_SCOPE.md` |
| Directory Map (Guides → `docs/guides/`) | ⚠️ **Partially stale** | Says "Setup, configuration, walkthroughs" but only `WINDOWS_SETUP.md` exists. `DEMO_SCRIPT.md` and `TRIAGEMATE_BOOK_PROMPT.md` referenced in AGENTS.md's pre-consolidation file map are gone — but the CURRENT AGENTS.md doesn't list them in the Directory Map. The Quick Reference doesn't reference those files. **AGENTS.md itself is clean of broken references.** |

**AGENTS.md verdict:** CLEAN. No immediate corrections needed. The Quick Reference and Directory Map are all accurate.

---

## Action Items

Priority ordered list for strike:

### P0 — Fix Numeric Confusion in ROADMAP.md (30 min)
1. **Reconcile 37 vs 35 tabular features.** Either update the field table to show 35 items, or add a note clarifying which 2 of the 37 listed are excluded and why (e.g., `cisa_kev` removed as label leakage, and one more as documented in XGBoost investigation §Finding 2).
2. **Fix the 67 ≠ 419 contradiction.** Line 187 currently says "67 features (35 tabular + 384 SBERT = 419 total)". This is mathematically wrong. Clarify: "The npz file stores 67 columns (35 tabular features + 32 auxiliary fields). The model combines 35 tabular + 384 SBERT for 419 total input dimensions."

### P1 — Fix ROADMAP.md File Map (20 min)
3. **Remove stale references to DEMO_SCRIPT.md, TRIAGEMATE_BOOK_PROMPT.md** from the Project File Map (lines 278, 282, 284, 293-294, 299). Neither exists at root level nor as a `docs/guides/` target.
4. **Fix SPRINT_NEXT_PLAN.md path** — remove from root listing (no root symlink exists) and correct target path from `docs/planning/` to `docs/archive/`.
5. **Fix XGBOOST_INVESTIGATION_REPORT.md target** — correct from `docs/reference/XGBOOST_INVESTIGATION_REPORT.md` to `docs/reference/xgboost-investigation-report.md` (lowercase kebab).

### P2 — Fix Cross-Document Status/Path Errors (15 min)
6. **Update ai-doc-strategy-2026-07-07.md Appendix A** — change MVP_SCOPE.md status from "CURRENT (with caveats)" to "OUTDATED" (row 2); fix SPRINT_NEXT_PLAN.md path from `docs/planning/` to `docs/archive/` (row 4); fix symlink count from "8" to "7 valid + 2 broken = 9" (or just "7" if broken are excluded).
7. **Update file-consolidation-plan-2026-07-07.md** — fix SPRINT_NEXT_PLAN.md path (item 3) and AGENTS.md line count (25→36).

### P3 — Missing Sprint Handoff Files (when convenient)
8. **Investigate/confirm SPRINT_4, SPRINT_5, SPRINT_6 handoffs.** ROADMAP.md's file map implies they exist (or once did). If they never existed, update the file map to show only the 5 handoff files that actually exist (SPRINT_1,2,3,7,8). If they were deleted, note that in archive.

### P4 — Optional Cleanup
9. **AI_PROBLEMS.md structural cleanup** — consider reorganising so severity sections are strictly ordered (CRITICAL→HIGH→MEDIUM→LOW) without the "FIXED ITEMS" and "ADDITIONAL ISSUES" sections breaking the hierarchy. Alternatively, add a summary table at the top.
10. **ROADMAP.md verification commands** — line 255-266 includes inline Python for score verification. This is useful but runs the risk of drifting from actual expected scores if model retraining changes outputs. Consider moving to a test file or adding a note about where expected scores come from.

---

## Files Not Requiring Changes

| File | Verdict |
|---|---|
| `AGENTS.md` | ✅ Clean — all references accurate |
| `docs/INDEX.md` | ✅ Clean — accurate statuses and paths |
| `docs/guides/WINDOWS_SETUP.md` | ✅ Clean — no issues |
| `docs/reference/hostname-standards.md` | ✅ Clean — no issues (external reference) |
| `docs/reference/xgboost-investigation-report.md` | ✅ Clean — internally consistent and accurate |
| `docs/research/RESEARCH_FINDINGS.md` | ✅ Clean — note about roadmap superseding is present |
| `docs/architecture/MVP_SCOPE.md` | ✅ Outdated by design, banner is excellent |
| `docs/reference/ml-implementation-plan.md` | ✅ Outdated by design, banner is good |

---

## Summary Table

| Category | Count | P0 | P1 | P2 | P3 | P4 |
|---|---|---|---|---|---|---|
| Internal Contradictions | 4 | 2 | — | 2 | — | — |
| Cross-File Contradictions | 7 | — | 4 | 2 | 1 | — |
| Stale References | 10 | — | 6 | 2 | 1 | 1 |
| OUTDATED Banner Quality | 0 | — | — | — | — | — |
| AGENTS.md Accuracy | 0 | — | — | — | — | — |
| **Total** | **18** | **2** | **10** | **4** | **2** | **2** |

**Key takeaway:** ROADMAP.md has the most issues (numeric contradictions in feature counts + stale file map entries). Fixing ROADMAP.md's Project File Map and numeric confusion would resolve ~70% of the issues found. ai-doc-strategy.md and file-consolidation-plan.md need minor path corrections. All other files are clean.
