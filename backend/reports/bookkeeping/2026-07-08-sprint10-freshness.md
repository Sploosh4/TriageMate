# Bookkeeping Report — Sprint 10 Freshness Pass

**Date:** 2026-07-08
**Trigger:** Sprint 10 (Operational Readiness) — quality gate
**Scope:** Full documentation audit of `.md` files under `.opencode/`, `docs/`, and root symlinks

---

## What Was Checked

| Check | Scope |
|---|---|
| Cross-file contradictions | ROADMAP.md ↔ actual files, INDEX.md ↔ actual files, ROADMAP.md vs AI_PROBLEMS.md |
| Stale file references | Paths/names in `.md` files checked against filesystem existence |
| Numeric consistency | Feature counts, training dimensions, model parameters |
| Status badge accuracy | INDEX.md badges matched against file headers |
| INDEX.md completeness | Every document in `docs/` should appear in INDEX.md |
| Sprint 10 items | 3 work items checked against implementation |
| New files this sprint | `cache_health.py`, `test_rate_limit.py`, `test_review.py`, `test_drift.py`, `test_feature_parity.py` |
| Orphaned references | Archived files referenced by active docs |
| Root vs backend `.env.example` | Cross-checked for parity |

---

## Sprint 10 Implementation Status

All 3 Sprint 10 work items are **implemented but NOT committed to git** (all files are unstaged/untracked):

| Item | Status | Evidence |
|---|---|---|
| 1. Rate limit hardening (env var config + test) | ✅ DONE | `middleware/rate_limit.py` reads `os.getenv()`, `test_rate_limit.py` exists (124 lines, 3 tests), `backend/.env.example` has all 6 vars |
| 2. Cache freshness in `/api/health` | ✅ DONE | `integrations/cache_health.py` exists (63 lines), `main.py` imports and calls it, `test_health.py` extended with `TestHealthCacheFreshness` (4 key assertions) |
| 3. Test coverage for review/drift endpoints | ✅ DONE | `test_review.py` (198 lines, 8 tests), `test_drift.py` (72 lines, 6 tests) |

Additional item found implemented (Sprint NEXT+ Wave 1, Item 10):
- **Feature-parity guard test**: `test_feature_parity.py` exists (318 lines, 6 tests)

---

## Items Flagged for Human Review

### P0 — Cross-File Contradictions (Highest Value)

1. **ROADMAP.md §Sprint NEXT+ items 9, 10, 15, 16 show TODO but are implemented**
   - *ROADMAP.md* → `docs/planning/ROADMAP.md` lines 200-219
   - Item 9: "Tests for new endpoints" says all untested → `test_review.py` + `test_drift.py` exist ✅
   - Item 10: "Feature-parity guard test" says needs doing → `test_feature_parity.py` exists ✅
   - Item 15: "Cache freshness in health" says needs adding → `cache_health.py` exists, health endpoint extended ✅
   - Item 16: "Rate limiting" says Token bucket needed → implemented with env var config ✅
   - **Action:** Update these items to ✅ Done or remove (since sprint plan now covers them)

2. **ROADMAP.md §Sprint NEXT Item 4 "Rate limiting + CI/CD" shows 📋 Todo**
   - *ROADMAP.md* → `docs/planning/ROADMAP.md` line 175
   - Rate limiting middleware is ✅ DONE. CI/CD (GitHub Actions) still pending.
   - **Action:** Split into two items or change status to 🟡 Partial (rate limit done)

3. **ROADMAP.md §Sprint NEXT banner says "All Items Complete ✅" but Item 4 contradicts**
   - *ROADMAP.md* → `docs/planning/ROADMAP.md` line 168 banner vs line 175
   - **Action:** Resolve contradiction — either update Item 4 or adjust banner

4. **ROADMAP.md "Last updated: 7 July 2026" is stale**
   - *ROADMAP.md* → `docs/planning/ROADMAP.md` line 5
   - Should be 8 July 2026 given Sprint 10 + clean corpus sprint work
   - **Action:** Bump date

### P1 — Stale/Inconsistent References

5. **Root `.env.example` missing rate limit env vars**
   - *Root `.env.example`* vs `backend/.env.example` (lines 49-55)
   - `backend/.env.example` has: `INGEST_RATE_PER_MIN=30`, `INGEST_BURST_SIZE=50`, `DEMO_RATE_PER_MIN=10`, `DEMO_BURST_SIZE=15`, `CLEAR_RATE_PER_MIN=2`, `CLEAR_BURST_SIZE=3`
   - Root `.env.example` stops at OTX key and has none of these
   - **Action:** Sync root `.env.example` with `backend/.env.example`

### P2 — Minor Gaps

6. **docs/INDEX.md missing explanatory note about excluded archive root files**
   - *`docs/INDEX.md`* — no note about `docs/archive/` root files being intentionally excluded
   - 7 files in `docs/archive/` root are not in INDEX.md (by design per `ai-doc-strategy-2026-07-07.md`)
   - **Action:** Add an archive provenance note to INDEX.md

7. **Sprint 10 not listed in ROADMAP.md Sprint Status table**
   - *ROADMAP.md* → `docs/planning/ROADMAP.md` lines 12-23
   - Table shows Sprint 1-9 + Course Correction but no Sprint 10
   - **Action:** Add Sprint 10 row (🔧 In progress or ✅ Complete based on commit state)

---

## Auto-Fixed

No auto-fixes applied. All issues require human judgment (status changes, banner edits, cross-file sync).

---

## Orphans Found

**None detected.**
- All ARCHIVED files referenced in INDEX.md exist on disk
- All CURRENT/OUTDATED files referenced in INDEX.md exist on disk
- Every available skill is referenced by at least one agent's loadable skills table
- No test file or source file is referenced by any `.md` that no longer exists

---

## Freshness Summary

| Area | Status |
|---|---|
| `docs/INDEX.md` | ✅ Fresh (with unstaged changes — ml-implementation-plan moved to ARCHIVED, graphify refs added) |
| `docs/reference/AI_PROBLEMS.md` | ✅ Fresh — 1 unfixed issue (#14, won't-fix) |
| `docs/architecture/MVP_SCOPE.md` | ✅ Correctly marked OUTDATED |
| `docs/reference/xgboost-investigation-report.md` | ✅ Fresh |
| `docs/reference/hostname-standards.md` | ✅ Fresh |
| `backend/ml/README.md` | ✅ Exists, referenced by INDEX.md |
| `graphify_output/` files | ✅ All 5 exist, referenced by INDEX.md |
| Root symlinks (6 total) | ✅ All resolve correctly |
| `.opencode/skills/` | ✅ Being updated to reference `graphify_output/` (unstaged) |
| Terminology consistency (419 dims, 35+384, WAICP) | ✅ Consistent across all docs |
| NVD corpus size (186K), EPSS size (344K) | ✅ Moved to auto-generated `graphify_output/ml_inventory.md` |
| Score baseline order (94,87,71,63,55,41,22) | ✅ Fixed in unstaged skill changes |

---

## Verdict

**NEEDS ATTENTION**

4 cross-file contradictions (P0) exist between ROADMAP.md and the working tree implementation. The Sprint 10 items are all implemented but uncommitted, and the ROADMAP.md still reflects the pre-sprint state. Once the working tree changes are committed, 3 of the 4 P0 items resolve automatically.

### Recommended Commit Sequence

1. `git add backend/integrations/cache_health.py backend/tests/test_rate_limit.py backend/tests/test_review.py backend/tests/test_drift.py backend/tests/test_feature_parity.py`
2. `git add backend/middleware/rate_limit.py backend/main.py backend/.env.example backend/tests/test_health.py`
3. `git add docs/planning/ROADMAP.md docs/INDEX.md` (if ROADMAP hasn't been staged yet)
4. `git add .opencode/skills/*/SKILL.md` (skill file updates)
5. `git commit -m "sprint: Sprint 10 Operational Readiness — rate limit hardening, cache freshness, review/drift tests"`

### Doc Fixes Needed After Commit (Manual)

- [ ] ROADMAP.md: Mark items 9, 10, 15, 16 as ✅ Done (or remove from Sprint NEXT+)
- [ ] ROADMAP.md: Resolve Item 4 contradiction (rate limit done, CI/CD pending)
- [ ] ROADMAP.md: Bump "Last updated" to 8 July 2026
- [ ] ROADMAP.md: Add Sprint 10 to Sprint Status table
- [ ] Root `.env.example`: Sync rate limit env vars
- [ ] INDEX.md: Add archive provenance note

### STRUCTURALLY VERIFIED

After the above actions, if the next bookkeeping round finds no new issues, trigger the retiring audit process.
