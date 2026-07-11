# Bookkeeping Report

**Date:** 2026-07-11
**Trigger:** manual (documentation freshness pass)

---

## Summary

**Verdict: NEEDS ATTENTION** — 9 issues found, including 3 P0 contradictions that require human intervention.

---

## Auto-Fixed

None. All issues flagged for human review (per instructions: no auto-fixes).

---

## Items Flagged for Human Review

### P0 — Cross-file contradictions

#### 1. Score Contract: ROADMAP.md vs test_model_versions.py vs seed_data.py vs compute()

**Files involved:** `docs/planning/ROADMAP.md`, `backend/tests/test_model_versions.py`, `backend/seed_data.py`, `backend/routers/models.py`, `docs/architecture/scoring-weights.md`, `backend/scripts/verify_seed_scores.py`

There are **four mutually inconsistent sets of scores** for the 7 demo rows:

| Source | Scores | Notes |
|--------|--------|-------|
| ROADMAP.md line 18 | 98 / 91 / 73 / 66 / 58 / 44 / 26 | Matches scoring-weights.md demo CVE table |
| test_model_versions.py line 133 | [94, 92, 76, 86, 78, 91, 77] | Asserted as `baseline_scores` from `GET /api/model/status` |
| seed_data.py `priority_score` | 94, 92, 76, 86, 63, 71, 57 | Hardcoded in `SEED_ROWS`, stored in DB |
| `calculate_final_score()` (no T2) | 90, 88, 74, 83, 75, 88, 73 | Computed live from seed data inputs |

No two sets agree. Of particular concern:
- `CVE-2023-36884`: stored=63, computed=75 (±12 delta — far outside the ±3 tolerance)
- `CVE-2023-22515`: stored=71, computed=88 (±17 delta)
- `CVE-2022-47966`: stored=57, computed=73 (±16 delta)

**Action needed:** Determine which scores are canonical, update ROADMAP.md/seed_data.py/models.py to be consistent, and re-run `just verify-seeds`.

---

#### 2. INDEX.md omits Sprints 21 & 22

**File:** `docs/INDEX.md`

- **Line 18** (Core Documents): says "Sprints 17, 18, 19 & 20 complete ✅"
- **Line 35** (Planning section): says "Sprints 17, 18, 19 & 20 complete ✅" again
- No Sprint 21 or Sprint 22 sections exist in INDEX.md (Sprint 19 and 20 sections do exist)

**ROADMAP.md line 15** says "Sprints completed | 17, 18, 19, 20, 21, 22"

**Action needed:** Update INDEX.md to mention Sprints 21 and 22, and add Sprint 21/22 component tables.

---

#### 3. ROADMAP.md Post-MVP Item 24 is Already Done

**File:** `docs/planning/ROADMAP.md`

- **Line 139** (Post-MVP section): `| **24** | pytest-benchmark + CI perf gates | Granular performance regression detection |`
- **Sprint 22 Item 2** (line 108): "CI Benchmark Gates ✅ Done — Added pytest-benchmark for scoring calculator (3 benchmarks). CI runs on main branch with 10% regression threshold."

Item 24 was completed in Sprint 22 but still listed as Post-MVP. This is a stale Post-MVP entry that misleads about project status.

**Action needed:** Either remove item 24 from the Post-MVP section or mark it ✅ Done with a reference to Sprint 22.

---

### P1 — Stale references to `security_context` as a live dimension

#### 4. INDEX.md line 28 — "7 dimensions (112-sum)"

**File:** `docs/INDEX.md`, line 28

Current text: `Scoring weight design — 7 dimensions (112-sum, clamped 0–100)`

This describes `scoring-weights.md` as having 7 dimensions and 112-sum, but scoring-weights.md correctly says 6 dimensions and 107-sum. INDEX.md's description is stale (pre-Sprint 21).

**Action needed:** Update to "6 dimensions (107-sum, clamped 0–100)".

---

#### 5. comparison-vs-described-system.md — References 7 dimensions as current

**File:** `docs/architecture/comparison-vs-described-system.md` (Status: CURRENT)

- **Line 44:** "Simple weighted sum of 7 dimensions" — should be 6
- **Line 51:** Lists Security Context (5) as a current dimension — Security Context was removed in Sprint 21
- **Line 53:** "Security Context dimension" as Sprint 17 addition — historically accurate but presented as current architecture

**Action needed:** Either update the document to reflect the 6-dimension + multiplier architecture, or mark it OUTDATED with a note that Sprint 21 changed the dimension count.

---

### P2 — Missing plan file

#### 6. Sprint 22 plan file missing

**File:** `.opencode/plans/` directory

ROADMAP.md says Sprint 22 was "Executed 10 July 2026" and is ✅ Complete, but no plan file exists for it. The directory has files for Sprints 11–21 but nothing for Sprint 22.

**Action needed:** Either create `2026-07-10-sprint-22.md` or add a note explaining why no plan file exists (e.g., "Sprint 22 was small enough to plan directly in ROADMAP.md").

---

### P3 — Stale comments and cosmetic drift

#### 7. verify_seed_scores.py line 29 — Stale comment

**File:** `backend/scripts/verify_seed_scores.py`, line 29

Comment says: `# Find the baseline_scores list — hardcoded as [98, 91, 73, 66, 58, 44, 26]`

The actual `baseline_scores` in `routers/models.py:97` is `[94, 92, 76, 86, 78, 91, 77]`. The comment references the old ROADMAP demo scores, which are a different score set.

**Action needed:** Update the comment to match the actual current values.

---

#### 8. Demo CVEs in scoring-weights.md don't match seed_data.py

**File:** `docs/architecture/scoring-weights.md` vs `backend/seed_data.py`

scoring-weights.md demo CVE list:
```
CVE-2023-27350, CVE-2023-34362, CVE-2024-1709,
CVE-2021-44228, CVE-2024-6387, CVE-2023-3519, CVE-2023-22527
```

seed_data.py SEED_ROWS CVE list:
```
CVE-2023-34362, CVE-2023-4966, CVE-2023-27350, CVE-2024-1709,
CVE-2023-36884, CVE-2023-22515, CVE-2022-47966
```

Only 3 CVEs overlap: CVE-2023-34362, CVE-2023-27350, CVE-2024-1709.

**Action needed:** Either align the scoring-weights.md demo CVE list with the actual seed data, or vice versa.

---

#### 9. ROADMAP.md "Sprint 17 Item 6" — says new scores 98/91/73/66/58/44/26

**File:** `docs/planning/ROADMAP.md`, line 43

"The new scores: 98/91/73/66/58/44/26" — but the actual seed_data.py priority_scores (which should be the Sprint 17 recalculation output) are 94, 92, 76, 86, 63, 71, 57.

**Action needed:** Clarify whether these are the canonical demo output scores or a different metric. If they're the canonical demo output, seed_data.py needs updating.

---

## Orphans Found

None. All `.opencode/` skill files are referenced in the skill table of AGENTS.md. No orphaned doc files detected.

---

## Coverage Gaps

- **INDEX.md** has no Sprint 21 or Sprint 22 component tables — Sprint 21 (Multiplier-Based Security Scoring, Config API, Drift Webhook) and Sprint 22 (Multi-Window KEV Labels, CI Benchmark Gates, Alembic Migration 009, Model Registry Rollback API) are undocumented in INDEX.md.
- **No `.opencode/plans/sprint-22.md`** exists despite Sprint 22 being marked complete.

---

## Verification Checklist

| # | Check | Result |
|---|-------|--------|
| 1 | Cross-file contradictions | **3 P0 found** (score contract, INDEX vs ROADMAP sprints, Post-MVP item 24) |
| 2 | Stale file references | **None** — all referenced files exist |
| 3 | Numeric consistency | **FAIL** — 4 different score sets, 3 different dimension counts (6/7/6) |
| 4 | Terminology drift | **OK** — No PRIS Act/WAICP confusion; docker-compose references appear clean |
| 5 | Status badge accuracy | **FAIL** — INDEX.md badges for scoring-weights.md description is stale (112→107, 7→6 dims) |
| 6 | INDEX.md completeness | **FAIL** — Missing Sprint 21 and 22 sections |

---

## Verdict

**NEEDS ATTENTION**

Priority actions:

1. **(P0)** Resolve which score set is canonical and sync ROADMAP.md, test_model_versions.py, seed_data.py, and scoring-weights.md to match. Currently 4 different score sets exist.
2. **(P0)** Update INDEX.md to cover Sprints 21 and 22.
3. **(P0)** Remove item 24 from Post-MVP section (already completed in Sprint 22).
4. **(P1)** Fix `comparison-vs-described-system.md` — still describes 7-dimension architecture as current.
5. **(P1)** Fix INDEX.md line 28 to say "6 dimensions (107-sum)" instead of "7 dimensions (112-sum)".
6. **(P2)** Either create the Sprint 22 plan file or document why it's missing.
7. **(P3)** Fix stale comment in `verify_seed_scores.py` line 29.
8. **(P3)** Align scoring-weights.md demo CVEs with actual seed_data.py CVEs.
