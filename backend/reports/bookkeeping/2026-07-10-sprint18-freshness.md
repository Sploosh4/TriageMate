# Bookkeeping Report

**Date:** 2026-07-10
**Trigger:** sprint-start (Sprint 18 plan created; ROADMAP/INDEX staleness revealed during planning)

---

## Files Modified

### 1. `docs/planning/ROADMAP.md`
| Change | Before | After |
|--------|--------|-------|
| Status date | `CURRENT (9 July 2026)` | `CURRENT (10 July 2026)` |
| Demo scores | `94/92/86/76/71/63/57` | `98/91/73/66/58/44/26` |
| Sprint 18 header | `Now — Sprint 18: Quick Wins + Monitoring` | `Sprint 18 — In Progress (Quick Wins + Monitoring)` |
| Sprint 18 items | Items 4–7 with old effort (30m/30m/2-4hr/2-4hr) | Items 1–4 matching sprint plan (30m/45m/5-6hr/5-6hr) + bonus row |
| Sprint 18 note re: Item 2 | — | `✅ Part A (fix dead code in _tier_zero_check()) already done` |
| Item 10 (scoring weights) | `107-sum weight design` | `112-sum weight design (CVSS 40 + EPSS 20 + criticality 20 + exposure 12 + patch 5 + ml_exploitation 10 + security_context 5)` |

### 2. `docs/INDEX.md`
| Change | Before | After |
|--------|--------|-------|
| ROADMAP description (Core table, line 18) | `What exists, what's broken, what's next. Start here.` | `...Sprint 17 complete ✅. Sprint 18 in progress. Start here.` |
| ROADMAP description (Planning section, line 33) | `Sprint 18 (Quick Wins + Monitoring) planned.` | `Sprint 18 (Quick Wins + Monitoring) in progress.` |
| Score Contract (line 141) | `backend/seed_data.py` + `94/92/86/76/71/63/57` | `backend/routers/models.py (baseline)` + `98/91/73/66/58/44/26` |

### 3. `.opencode/skills/backend-engineering/SKILL.md`
| Change | Before | After |
|--------|--------|-------|
| Score Contract | `94, 87, 71, 63, 55, 41, 22` | `98, 91, 73, 66, 58, 44, 26` (with source annotation) |

### 4. `backend/reports/intel/2026-07-10-cwe-epss-investigation.md`
| Change | Details |
|--------|---------|
| Added OUTDATED banner | Blockquote at top noting stale findings struck through |
| Lines 64–68 | CRITICAL dead-code finding struck through and marked STALE — VERIFIED FIXED |
| Recommendation 1 (line 172) | Changed from `🟥 CRITICAL — Fix build_feature_vector()` to `🟥 ~~CRITICAL~~ ✅ ALREADY FIXED — ~~Fix...~~` with strike-through body and resolution note |

---

## Items Flagged for Human Review

- **`backend/seed_data.py`** — Contains stale scores (`94/92/86/76/71/63/57` at lines 34, 221, 411, 602, 793, 989, 1180). The DB already has the correct scores (`98/91/73/66/58/44/26`), but the seed data file itself hasn't been updated. This is a code file, not .md, so flagged rather than fixed. Sprint 18 should include a task to update seed_data.py.

- **`docs/planning/ROADMAP.md` line 43** — Sprint 17 summary still says "New scores: 94/92/86/76/71/63/57". This is now stale but the text describes what Sprint 17 *did* at the time. Since the DB has been recalculated since, this could be confusing. Consider either: (a) updating to the current scores, or (b) adding a note that scores were subsequently recalculated during Sprint 17+.

---

## Orphans Found

None. All referenced files exist and are non-archived.

---

## Cross-Reference Issues

- **ROADMAP.md item 10** (`scoring weight documentation`) now correctly says `112-sum`. Verified against `backend/scoring.py:7-8` which says "Weights sum to 112 (CVSS 40 + EPSS 20 + criticality 20 + exposure 12 + patch 5 + ml_exploitation 10 + security_context 5)". ✓
- **Sprint 18 plan** (`.opencode/plans/2026-07-10-sprint-18.md`) references `routers/models.py:89` baseline scores `98/91/73/66/58/44/26` — now consistent with ROADMAP.md, INDEX.md, and backend-engineering skill. ✓

---

## Coverage Gaps

- **`backend/ml/xgboost_predictor.py`** — The `CWE_EPSS_THRESHOLDS` dict (8 CWEs) is not yet documented in any skill file. The `backend-engineering` skill mentions CWE lookups but not the CWE-stratified thresholds. Consider adding a brief note to `backend-engineering/SKILL.md` or `ml-engineering/SKILL.md`.

---

## Verdict

**FRESH** — All stale references identified during Sprint 18 planning have been corrected. One code file (`seed_data.py`) has stale data but is outside bookkeeping's scope. Documented for commander action.
