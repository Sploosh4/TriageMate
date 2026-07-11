# Bookkeeping Report — General Freshness Pass

**Date:** 2026-07-11
**Trigger:** Comprehensive documentation freshness pass (manual)
**Scope:** All non-archived, non-report `.md` files across the project
**Verdict:** **NEEDS WORK** — 5 issues found (1 P0, 2 P1, 2 P2)

---

## Audit Checklist Applied

| # | Check | Result |
|---|-------|--------|
| 1 | Cross-file consistency | ❌ **1 P0 issue** — Sprint 23 status inconsistent |
| 2 | Stale file references | ⚠️ Minor — old scores in OUTDATED files |
| 3 | Numeric consistency | ⚠️ 2 stale `112` refs in ROADMAP.md |
| 4 | Terminology drift | ⚠️ `docker-compose` still in HANDOFF.md (filename context) |
| 5 | Status badge accuracy | ✅ All badges correct |
| 6 | INDEX.md completeness | ✅ All CURRENT docs listed; Sprint 21/22 tables present |
| 7 | Orphaned files | ✅ No orphaned `.md` files outside expected locations |
| 8 | ROADMAP.md state | ❌ Sprint 23 still shows "Planned" |
| 9 | Plan file state | ❌ Still says "PLANNED" |

---

## Issues Found

### P0 — Cross-File Contradiction

#### 1. Sprint 23 status not reflected as complete

**The user states Sprint 23 is complete "after this commit," but three locations still show it as planned:**

| Location | Current Text | Expected |
|----------|-------------|----------|
| `docs/planning/ROADMAP.md:15` | `Sprints completed \| 17, 18, 19, 20, 21, 22 (Sprint 23 planned)` | Should include Sprint 23 as completed |
| `docs/planning/ROADMAP.md:114` | `## Sprint 23 — 📋 Planned (Score Reconciliation + Bug Hunt)` | Should be `✅ Complete` |
| `docs/planning/ROADMAP.md:118-124` | All Sprint 23 items marked `📋 Planned` | Should be `✅ Done` |
| `.opencode/plans/2026-07-11-sprint-23.md:4` | `**Status:** PLANNED (awaiting user confirmation)` | Should be `COMPLETE` |

**Severity justification:** P0 because the user explicitly states Sprint 23 is complete, and there is a contradiction between the stated canonical facts and what the CURRENT documentation says.

---

### P1 — Stale Numeric References (Current Docs)

#### 2. ROADMAP.md Sprint 17 — "total weight 112"

- **File:** `docs/planning/ROADMAP.md:41`
- **Current text:** `"Security Context" (max 5, total weight 112). Composite: threat_score × 3 + blast_radius × 2.`
- **Problem:** The current scoring system uses 6 dimensions with total weight 107 (after Sprint 21 removed the additive Security Context). While this line describes Sprint 17's historical state accurately, the bare number `112` in a **CURRENT** doc could mislead readers into thinking that's still the current total weight.
- **Recommendation:** Add a note: *"(later replaced by context multiplier in Sprint 21, reducing total to 107)"* or similar clarification.

#### 3. ROADMAP.md Sprint 18 Bonus D — "112-sum"

- **File:** `docs/planning/ROADMAP.md:58`
- **Current text:** `` `docs/architecture/scoring-weights.md` — full weight design rationale, 112-sum, clamping. ``
- **Problem:** Describes scoring-weights.md as it existed in Sprint 18, but that doc now describes 107-sum. The `112-sum` reference is stale.
- **Recommendation:** Change to `107-sum` (current) or clarify that it was the weight at that time.

---

### P2 — Stale Terminology

#### 4. HANDOFF-2026-07-08.md — "docker-compose.yml" filename reference

- **File:** `docs/planning/HANDOFF-2026-07-08.md:150`
- **Current text:** `✅ cpus: 2.0, memory: 1024M in docker-compose.yml`
- **Problem:** References `docker-compose.yml` (hyphenated filename). While the file IS literally named `docker-compose.yml`, prior bookkeeping rounds have repeatedly flagged `docker-compose` references as stale terminology. The project convention is `docker compose` (space-separated). Prior reports (r6-structural-audit, final-2026-07-08, etc.) have called this clean when found only in archive files — this is a **non-archive CURRENT doc**.
- **Recommendation:** Reword to `in docker-compose.yml (the Docker Compose config file)` or similar to distinguish filename from command. Or accept as-is since it references the filename, not the command.
- **Note:** This is a borderline call — previous bookkeeping reports have alternately flagged and accepted `docker-compose.yml` as a filename reference. Flagging for human judgment.

### P2 — Documentation Gaps

#### 5. ROADMAP.md Sprint 17 Item 6 — forward-looking reference to Sprint 23

- **File:** `docs/planning/ROADMAP.md:43`
- **Current text:** `New scores: 99/97/74/91/82/97/80. Later refined in Sprint 23 (Score Reconciliation) to correct for pipeline discrepancies.`
- **Problem:** If Sprint 23 is now complete, "Later refined in Sprint 23" is no longer forward-looking — it's past tense.
- **Recommendation:** Change to: `Refined in Sprint 23 (Score Reconciliation) to correct for pipeline discrepancies.` (remove "Later")

---

## Informational — Not Actionable

### P3 — Stale Scores in OUTDATED/Historical Docs (accepted)

These are stale score references in files that are correctly marked OUTDATED or in historical fix descriptions. Flagged for awareness only.

| File | Line | Text | Notes |
|------|------|------|-------|
| `docs/architecture/MVP_SCOPE.md` | 223 | `(98, 91, 73, 66, 58, 44, 26)` | OUTDATED doc — expected |
| `docs/reference/AI_PROBLEMS.md` | 150 | `[98, 91, 73, 66, 58, 44, 26]` | Historical fix description — contextually correct |

---

## What's Clean ✅

| Quality | Status |
|---------|--------|
| **Canonical scores** `[99, 97, 74, 91, 82, 97, 80]` | ✅ Consistent across ROADMAP.md, scoring-weights.md, INDEX.md |
| **6 dimensions + context multiplier (107-sum)** | ✅ Correct in all CURRENT docs |
| **Test count (449)** | ✅ Consistent across ROADMAP.md and INDEX.md |
| **INDEX.md completeness** | ✅ All CURRENT docs listed; Sprint 21/22 component tables present |
| **Status badges** | ✅ All accurate (CURRENT/OUTDATED/ARCHIVED) |
| **No orphan files** | ✅ All `.md` files accounted for |
| **No stale PRIS Act** | ✅ Only in archive files |
| **comparison-vs-described-system.md** | ✅ Correctly describes 6 dims + context multiplier; date updated to 2026-07-11 |
| **scoring-weights.md** | ✅ Correct total (107), dimensions (6), scores (matching canonical) |
| **Sprint 22 plan file** | ✅ Exists at `.opencode/plans/2026-07-10-sprint-22.md` |

---

## Stale Reference Searches (grep results)

| Pattern | Matches | Verdict |
|---------|---------|---------|
| `98/91/73/66/58/44/26` | 0 in active CURRENT docs | ✅ Clean |
| `7 dimensions` | 0 matches across all docs/ | ✅ Clean |
| `112-sum` | 2 matches (ROADMAP.md:41, 58) | ⚠️ Flagged above |
| `94, 92, 76, 86, 78, 91, 77` | 0 matches in docs/ (these are in `.py` files) | ✅ Clean |
| `PRIS Act` | 1 match (archive/COURSE_CORRECTION.md) | ✅ Archived only |
| `docker-compose` as command | 0 in non-archive active docs | ✅ Clean (HANDOFF.md references filename) |
| `98/91/73` | 0 matches | ✅ Clean |

---

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| **P0** | 1 | Sprint 23 status not reflected as complete across ROADMAP.md and plan file |
| **P1** | 2 | Stale `112` numeric references in Sprint 17/Sprint 18 historical sections |
| **P2** | 2 | `docker-compose.yml` filename ref in HANDOFF.md; forward-looking text in ROADMAP line 43 |
| **P3** | 2 | Old scores in OUTDATED/historical files (accepted, not actionable) |

**Overall Verdict: NEEDS WORK**

The documentation is structurally sound and factually consistent on the key metrics (scores, dimensions, test count). The primary issue is that Sprint 23's completion is not reflected in the docs that describe sprint status. The remaining issues are minor historical numeric references that don't affect accuracy but could confuse readers.
