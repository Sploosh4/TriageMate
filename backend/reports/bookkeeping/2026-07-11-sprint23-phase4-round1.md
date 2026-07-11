# Bookkeeping Report — Sprint 23 Phase 4 Round 1

**Date:** 2026-07-11
**Trigger:** Sprint 23 Phase 4 — Gated Bookkeeping (freshness verification after Phase 3 docs update)

---

## 9 Known Issues — Verification Results

| # | Issue | Expected State | Result |
|---|-------|----------------|--------|
| 1 | Score contract broken (4 sets) | Single canonical set `[99, 97, 74, 91, 82, 97, 80]` across all locs | **FAIL** — see details below |
| 2 | INDEX.md missing Sprints 21/22 | Both sprints documented with component tables | **PASS** ✓ |
| 3 | Post-MVP Item 24 already done | Marked ✅ Done or removed | **PASS** ✓ |
| 4 | INDEX.md line 28 says "7 dims 112-sum" | "6 dims 107-sum" with context multiplier | **PASS** ✓ |
| 5 | comparison-vs-described-system.md stale | Updated architecture (6 dims + multiplier) | **PASS** ✓ |
| 6 | Sprint 22 plan file missing | `.opencode/plans/2026-07-10-sprint-22.md` exists | **PASS** ✓ |
| 7 | verify_seed_scores.py stale comment | Updated to `[99, 97, 74, 91, 82, 97, 80]` | **PASS** ✓ |
| 8 | scoring-weights.md CVE list mismatch | Synced with seed_data.py SEED_ROWS | **PASS** ✓ |
| 9 | ROADMAP.md Sprint 17 scores stale | Updated to canonical values | **PASS** ✓ |

### Issue 1 Detail — Score Contract

**All locations verified correct except one:**

| Location | Value | Status |
|----------|-------|--------|
| `backend/routers/models.py:97` | `[99, 97, 74, 91, 82, 97, 80]` | ✓ |
| `backend/seed_data.py` priority_scores | 99, 97, 74, 91, 82, 97, 80 | ✓ |
| `backend/tests/test_model_versions.py:133` | `[99, 97, 74, 91, 82, 97, 80]` | ✓ |
| `backend/scripts/verify_seed_scores.py:29` | `[99, 97, 74, 91, 82, 97, 80]` | ✓ |
| `docs/architecture/scoring-weights.md:94-100` | 99, 97, 74, 91, 82, 97, 80 | ✓ |
| `docs/planning/ROADMAP.md:18` | `99/97/74/91/82/97/80` | ✓ |
| `docs/planning/ROADMAP.md:43` | `99/97/74/91/82/97/80` | ✓ |
| **`docs/INDEX.md:143`** | **`98/91/73/66/58/44/26`** | **✗ FAIL — still has old scores** |

---

## Additional Checks

### Check 1: Cross-file consistency — Stale Value Search

| Search Pattern | Result |
|----------------|--------|
| `98/91/73/66/58/44/26` in `docs/` | **FOUND in INDEX.md:143** (also in archived bookkeeping reports — expected) |
| `7 dimensions` or `7 dims` in `docs/` | Only in historical context (ROADMAP Sprint 17/18, ai-doc-strategy.md:212) |
| `112-sum` in `docs/` | Only in historical context (ROADMAP Sprint 18 Bonus D) — appropriate |

### Check 2: INDEX.md test count

- INDEX.md line 133: "449+ tests" ✓
- Actual: `449 passed, 1 skipped` — matches ✓

### Check 3: ROADMAP.md accuracy

| Field | Value in ROADMAP | Status |
|-------|-------------------|--------|
| Sprints completed | 17, 18, 19, 20, 21, 22 | ✓ |
| Demo scores | `99/97/74/91/82/97/80` | ✓ |
| Enrichment sources | 14 integrations | ✓ |
| Pipeline stages | Pre-Tier → Tier 0 → Tier 1 → Tier 2 → Tier 3 | ✓ |
| Tests | 449 pass, 0 fail | ✓ |

### Check 4: Sprint 22 plan file

- `.opencode/plans/2026-07-10-sprint-22.md` exists ✓
- 6990 bytes, 194 lines, complete content with 4 items ✓

---

## Minor Issues Found

### Issue A: docs/INDEX.md:143 — Stale Score Contract (Remnant of Issue 1)

**File:** `docs/INDEX.md`, line 143
**Current text:**
```
Updated expected scores: **98/91/73/66/58/44/26** (Sprint 17+ recalculation, verified against `routers/models.py:89`).
```
**Should be:**
```
Updated expected scores: **99/97/74/91/82/97/80** (Sprint 17+ recalculation, verified against `routers/models.py:97`).
```
**Severity:** P1 — one remaining stale reference in a CURRENT document after all other locations were fixed.

### Issue B: docs/planning/ai-doc-strategy-2026-07-07.md:212 — "7 dimensions" reference

**File:** `docs/planning/ai-doc-strategy-2026-07-07.md`, line 212
**Current text:**
```
| 2 | `docs/planning/ROADMAP.md` | Understand scoring architecture (7 dimensions, weights, bands) |
```
**Issue:** This strategy document, which is marked CURRENT, tells an AI agent that ROADMAP.md describes "7 dimensions" for scoring. ROADMAP.md now correctly describes 6 dimensions (Sprint 21 change). The parenthetical is mildly misleading.
**Severity:** P3 — minor terminology drift in a strategy doc. The AI agent would still get correct info from ROADMAP.md itself.

### Issue C: backend/scripts/compute_canonical_scores.py:46-48 — PROMPT_BASELINE old scores

**File:** `backend/scripts/compute_canonical_scores.py`, lines 46-48
**Current text:**
```python
PROMPT_BASELINE = {
    cve: score for cve, score in zip(CVE_ORDER, [94, 87, 71, 55, 63, 41, 22])
}
```
**Issue:** This code file defines a third score set `[94, 87, 71, 55, 63, 41, 22]` labeled "Contract C: Referenced in system prompt guideline 6." If this system prompt still exists and references these scores, it may be stale. If it no longer exists, this code block is dead code.
**Severity:** P3 — code file, not .md. Flagged for human review per bookkeeping rules.

---

## Cross-Reference Verification

### Related Skills in .md files
- All `Related Skills` sections in skill files point to existing skills ✓
- No dead skill links detected ✓

### INDEX.md Cross-References
- All referenced files in INDEX.md's Core Documents table exist ✓
- `planning/ROADMAP.md` → exists ✓
- `architecture/MVP_SCOPE.md` → exists ✓
- `reference/AI_PROBLEMS.md` → exists ✓
- `archive/ml-implementation-plan.md` → exists ✓
- `architecture/scoring-weights.md` → exists ✓
- `architecture/comparison-vs-described-system.md` → exists ✓
- `planning/HANDOFF-2026-07-08.md` → exists ✓
- `planning/ai-doc-strategy-2026-07-07.md` → exists ✓
- `reference/xgboost-investigation-report.md` → exists ✓
- `reference/hostname-standards.md` → exists ✓
- `backend/ml/README.md` → exists ✓
- `research/RESEARCH_FINDINGS.md` → exists ✓
- `guides/WINDOWS_SETUP.md` → exists ✓

### Status Badge Accuracy (INDEX.md)
| File | Badge | Correct? |
|------|-------|----------|
| `planning/ROADMAP.md` | CURRENT | ✓ |
| `architecture/MVP_SCOPE.md` | OUTDATED | ✓ |
| `reference/AI_PROBLEMS.md` | CURRENT | ✓ |
| `archive/ml-implementation-plan.md` | ARCHIVED | ✓ |
| `architecture/scoring-weights.md` | CURRENT | ✓ |
| `architecture/comparison-vs-described-system.md` | CURRENT | ✓ |
| `planning/HANDOFF-2026-07-08.md` | CURRENT | ✓ |
| `planning/ai-doc-strategy-2026-07-07.md` | CURRENT | ✓ |
| `archive/file-consolidation-plan-2026-07-07.md` | ARCHIVED | ✓ |
| `reference/xgboost-investigation-report.md` | CURRENT | ✓ |
| `reference/hostname-standards.md` | CURRENT | ✓ |
| `backend/ml/README.md` | CURRENT | ✓ |
| `research/RESEARCH_FINDINGS.md` | OUTDATED | ✓ |
| `guides/WINDOWS_SETUP.md` | CURRENT | ✓ |
| `archive/SPRINT_NEXT_PLAN.md` | ARCHIVED | ✓ |
| `archive/sprints-1-6/*.md` | ARCHIVED | ✓ |
| `archive/ROADMAP-2026-07-09.md` | ARCHIVED | ✓ |

### INDEX.md Completeness
All documents under `docs/` appear to be listed in INDEX.md ✓

---

## Verdict

**NEEDS ATTENTION** — One remaining P1 issue (stale scores in INDEX.md:143) and two minor P3 issues.

### Action Required for Round 2

| Priority | Fix | File | Details |
|----------|-----|------|---------|
| **P1** | Update score contract values | `docs/INDEX.md:143` | Change `98/91/73/66/58/44/26` → `99/97/74/91/82/97/80` and `models.py:89` → `models.py:97` |
| **P3** | Consider updating "7 dimensions" → "6 dimensions" | `docs/planning/ai-doc-strategy-2026-07-07.md:212` | Minor terminology drift |
| **P3** | Review PROMPT_BASELINE scores | `backend/scripts/compute_canonical_scores.py:46-48` | Check if "Contract C" system prompt is still current |

### Summary

- **8 of 9 known issues: FIXED** ✓
- **1 of 9 known issues: NOT FIXED** (Issue 1 — INDEX.md:143 still has old scores)
- **2 new minor issues detected** (P3 — ai-doc-strategy.md, compute_canonical_scores.py)
- **No orphans, no dead cross-references, no broken links** ✓
- **All status badges correct** ✓
- **INDEX.md is complete** ✓
- **Test count verified: 449 passed** ✓
