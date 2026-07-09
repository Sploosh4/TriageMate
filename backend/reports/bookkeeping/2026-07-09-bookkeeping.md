# Bookkeeping Report

**Date:** 2026-07-09
**Trigger:** freshness-pass

## Verdict
**NEEDS ATTENTION** — Multiple P0 contradictions found between seed data, docs, and tests. One test currently failing.

---

## 1. `docs/INDEX.md`

**Status: NEEDS UPDATE**

| Line | Issue | Severity |
|------|-------|----------|
| 141 | Seed data scores stale: says `98/91/73/66/58/44/26` but actual seed data has `94/92/76/86/63/71/57` after Phase A recalculation | **P0** |
| 131 | Test count: says "275+ tests" — currently 274 pass + 1 fail (274 pass ≠ 275+) | **P1** |
| 159 | Root-level symlinks note mentions only `ROADMAP.md`, `AI_PROBLEMS.md` but there are also `MVP_SCOPE.md`, `RESEARCH_FINDINGS.md`, `WINDOWS_SETUP.md`, `XGBOOST_INVESTIGATION_REPORT.md` | P3 |

---

## 2. `docs/planning/ROADMAP.md`

**Status: NEEDS UPDATE**

| Line | Issue | Severity |
|------|-------|----------|
| 13 | "275 pass, 0 fail" → currently 274 pass + 1 fail (`test_queue_first_seven_scores_match_seed_data` fails because test expects old scores) | **P0** |
| 14 | "Open bugs: 0 (AI_PROBLEMS.md is clean)" → still accurate ✅ but Phase A bugs not documented there | P2 |
| 18 | "scores 98/91/73/66/58/44/26 (±3 tolerance)" → actual: 94/92/76/86/63/71/57. Only 2 of 7 within ±3 tolerance | **P0** |
| 43 | "New scores: 98/91/73/66/58/44/26 (was 94/87/71/63/55/41/22)" → should read "New scores: 94/92/76/86/63/71/57 (was 98/91/73/66/58/44/26)" | **P0** |

**Detail on tolerance:** The ±3 tolerance claim (±3 from 98/91/73/66/58/44/26) breaks for 5 of 7 rows:
- Row 1: 98→94 (diff 4 ❌)
- Row 2: 91→92 (diff 1 ✅)
- Row 3: 73→76 (diff 3 ✅ boundary)
- Row 4: 66→86 (diff 20 ❌)
- Row 5: 58→63 (diff 5 ❌)
- Row 6: 44→71 (diff 27 ❌)
- Row 7: 26→57 (diff 31 ❌)

---

## 3. `docs/reference/AI_PROBLEMS.md`

**Status: CURRENT with flag**

| Issue | Detail |
|-------|--------|
| Status badge | ✅ "CURRENT — All historical issues resolved" is correct |
| Phase A fixes missing | The 3 Phase A bug fixes (DDL duplicate column, seed data recalculation, hostname regex expansion) are not documented. Per AI_PROBLEMS.md's charter ("incorrect AI-generated code, mismatches"), items 1 and 3 qualify. Item 2 (recalculated scores) may not. **Flag for human review** — should these be added? |

---

## 4. Root Symlinks

**Status: ✅ ALL CORRECT**

| Symlink | Target | Status |
|---------|--------|--------|
| `ROADMAP.md` | `docs/planning/ROADMAP.md` | ✅ Correct |
| `AI_PROBLEMS.md` | `docs/reference/AI_PROBLEMS.md` | ✅ Correct |
| `MVP_SCOPE.md` | `docs/architecture/MVP_SCOPE.md` | ✅ Correct |
| `RESEARCH_FINDINGS.md` | `docs/research/RESEARCH_FINDINGS.md` | ✅ Correct (not in task but verified) |
| `WINDOWS_SETUP.md` | `docs/guides/WINDOWS_SETUP.md` | ✅ Correct (not in task but verified) |
| `XGBOOST_INVESTIGATION_REPORT.md` | `docs/reference/xgboost-investigation-report.md` | ✅ Correct (not in task but verified) |

---

## 5. `docs/planning/HANDOFF-2026-07-08.md`

**Status: OUTDATED (pre-Sprint-17)**

| Line | Issue | Severity |
|------|-------|----------|
| 21 | "275/275 tests pass" → now 274 pass + 1 fail | **P1** |
| 22 | Does not mention sprint 17 (Security Context) additions | P2 |
| 117–133 | Integration modules table lists 12 modules but ROADMAP says 14 (missing Synthetic Telemetry, Network Context) | P2 |
| 209 | ".github/workflows/ci.yml not yet created" — CI/CD pipeline now exists with full matrix test, coverage, lint, Docker | **P1** |
| Overall | No status badge (no CURRENT/OUTDATED marker) | P3 |

**Recommendation:** Mark as OUTDATED or add a note that Sprint 17 work supersedes some sections. No seed data scores to update (it doesn't reference specific scores).

---

## 6. `backend/ml/README.md`

**Status: ✅ CURRENT**

| Check | Result |
|-------|--------|
| Content | 9-line pointer to `graphify_output/ml_inventory.md` — no data to go stale |
| Cross-ref | Refers to `just graphify` which exists ✅ |
| File exists | `graphify_output/ml_inventory.md` exists ✅ |

---

## 7. Cross-Reference Checks

### Related Skills
All 3 skill files with `## Related Skills` references (backend-engineering, ml-engineering, frontend-engineering) point to existing, non-archived skills. ✅

### File Inventory
All files documented in INDEX.md exist on disk. ✅

No orphaned references detected (all referenced files exist).

---

## 8. Coverage Gaps

| Gap | Details |
|-----|---------|
| Phase A bugs | The 3 Phase A fixes (DDL duplicate column `database.py`/`ingest.py`, seed data recalculation `seed_data.py`, hostname regex `cmdb.py`) not documented in any skill file |
| Test failure | `test_queue_first_seven_scores_match_seed_data` expects old scores [98,91,73,66,58,44,26] but `seed_data.py` now has [94,92,76,86,63,71,57]. Test needs updating. |

---

## Summary of Required Actions

### Auto-Fixable (unambiguous)
None recommended — all score changes involve judgment about which values are correct.

### Flagged for Human Review

| Priority | Item |
|----------|------|
| **P0** | Fix `test_queue.py:16` — `EXPECTED_PRIORITY_SCORES` must match current `seed_data.py` values |
| **P0** | Fix `ROADMAP.md:18` — demo row scores |
| **P0** | Fix `ROADMAP.md:43` — "New scores" line |
| **P0** | Fix `ROADMAP.md:13` — test count (274 pass, 1 fail) |
| **P1** | Fix `INDEX.md:141` — seed data scores |
| **P1** | Fix `INDEX.md:131` — test count |
| **P1** | Fix `HANDOFF-2026-07-08.md:21` — test count |
| **P1** | Fix `HANDOFF-2026-07-08.md:209` — CI/CD claim |
| P2 | Consider adding Phase A fixes to `AI_PROBLEMS.md` |
| P2 | Mark `HANDOFF-2026-07-08.md` as OUTDATED or add pre-Sprint-17 caveat |
| P2 | Update HANDOFF integration module count (12→14) |
| P3 | Update INDEX.md symlink note to include all 6 root-level symlinks |

**Clean docs:** MVP_SCOPE.md, ai-doc-strategy, hostname-standards, WINDOWS_SETUP.md, xgboost-investigation-report — all CURRENT ✅
