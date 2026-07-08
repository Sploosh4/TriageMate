# Bookkeeping Report — Skill Metrics Freshness Pass

**Date:** 2026-07-08
**Trigger:** Targeted freshness pass after skill metric refactoring

---

## 1. `.opencode/skills/ml-engineering/SKILL.md` — Pointer Verification

**Status: ✅ CLEAN**

All graphify pointers verified correct:

| Line | Pointer | Target File | Exists? |
|------|---------|-------------|---------|
| 10 | `graphify_output/ml_inventory.md` | `graphify_output/ml_inventory.md` (12KB) | ✅ |
| 16 | `graphify_output/ml_inventory.md §Tier 1` | Anchor `## Tier 1: XGBoost Exploitation Predictor` line 126 | ✅ |
| 18 | `graphify_output/feature_parity.md` | `graphify_output/feature_parity.md` (4.4KB) | ✅ |
| 27-29 | Both `feature_parity.md` and `ml_inventory.md §Tier 1` | Both exist | ✅ |
| 65-66 | Both graphify files | Both exist | ✅ |

**Stale metrics check:** No hardcoded feature counts, ROC-AUC values, or SBERT dimensions found. All previously hardcoded numbers have been replaced with pointers. The remaining numeric values (7 demo row scores `94, 87, 71, 55, 63, 41, 22` at line 59) are the score contract — intentionally hardcoded as validation targets, not model metrics.

**Regenerate instructions:** `just graphify` referenced at lines 12 and 30 — `justfile` line 146 confirms the command exists.

---

## 2. `.opencode/skills/backend-engineering/SKILL.md` — Pointer Verification

**Status: ✅ CLEAN**

| Line | Pointer | Target File | Exists? |
|------|---------|-------------|---------|
| 19 | `graphify_output/ml_inventory.md §Tier 1` | Anchor exists at line 126 | ✅ |
| 20 | `graphify_output/feature_parity.md` | File exists (4.4KB) | ✅ |

**Stale metrics check:** Tier 1 description (lines 18-20) cleanly points to graphify. No hardcoded metrics remain. Score contract (line 80) correctly preserved as validation target.

---

## 3. `.opencode/skills/ml-toolbox/SKILL.md` — Pointer Line Verification

**Status: ✅ PRESENT**

Line 63: `→ See graphify_output/ml_inventory.md for the canonical file inventory with exact sizes. Paths below are stable by convention.`

Placed correctly immediately before the `## File Locations` section header (line 65). Target file exists. Intent is clear: the table below is stable-by-convention but exact sizes should be looked up in the auto-generated inventory.

---

## 4. Deleted `feature-vector-spec` Directory — Verdict

**Status: ✅ GONE; ⚠️ 1 stale auto-generated reference**

- `.opencode/ARCHIVED/skills/feature-vector-spec/`: ✅ Confirmed deleted (`ls` shows only `dual-database-ddl/` remains in ARCHIVED/skills/)
- `.opencode/ARCHIVED/skills/`: only `dual-database-ddl/` present

**Remaining references (all acceptable except one):**

| File | Line(s) | Verdict |
|------|---------|---------|
| `.opencode/DESIGN_RATIONALE.md` | 157, 168, 205 | ✅ Time-capsule design doc — explicitly marked `[ARCHIVED 2026-07-07]` |
| `.opencode/RESTRUCTURE_HANDOFF.md` | 63, 66 | ✅ Historical handoff doc — snapshot at time of writing |
| `.opencode/plans/2026-07-07-skill-system-consolidation.md` | 16 | ✅ Historical plan — describes what was done |
| `backend/reports/bookkeeping/2026-07-07-bookkeeping.md` | 29, 33, 44, 50, 52, 58, 103, 111 | ✅ Previous audit — historical record |
| `backend/reports/bookkeeping/2026-07-07-bookkeeping-followup.md` | 33 | ✅ Previous audit — historical record |
| `backend/reports/bookkeeping/2026-07-07-bookkeeping-post-refinement.md` | 42, 46 | ✅ Previous audit — historical record |
| **`graphify_output/file_tree.md`** | **30-31** | **⚠️ Stale — shows `feature-vector-spec/` under ARCHIVED/skills/ but directory is gone. Auto-generated; fix with `just graphify`** |

---

## 5. `docs/INDEX.md` — Accuracy After Changes

**Status: ✅ ACCURATE**

- No references to `feature-vector-spec` — clean
- `graphify_output/ml_inventory.md` referenced at lines 21, 43, 75, 83, 94 — all correct
- `graphify_output/feature_parity.md` referenced at lines 84, 96 — correct
- Graphify section (lines 86-96) lists all 6 outputs — complete
- `archive/ml-implementation-plan.md` (lines 21, 43) — still exists, ARCHIVED status is correct
- Score contract not duplicated (it's in the skill files, not INDEX.md) — correct

---

## Cross-Reference Consistency Check

| From | References | Status |
|------|-----------|--------|
| `ml-engineering` Related Skills | `ml-toolbox` | ✅ Active skill, exists |
| `backend-engineering` Related Skills | `ml-engineering`, `new-integration-pattern` | ✅ Both active |
| `ml-toolbox` | No "Related Skills" section | ✅ Acceptable — CLI reference sheet |
| Score contract (ml-engineering line 59) | `94, 87, 71, 55, 63, 41, 22` | ✅ Matches backend-engineering line 80 |
| Training rules consistency | Both skills agree: exclude 7 demo CVEs, report ROC-AUC after retraining | ✅ Consistent |

**No contradictions found between current skill files.**

---

## Summary of Findings

| # | Item | Severity | Action |
|---|------|----------|--------|
| 1 | `graphify_output/file_tree.md` still shows `feature-vector-spec/` under ARCHIVED directory | P3 — auto-generated, stale | Run `just graphify` to regenerate |
| 2 | All graphify pointers in 3 skill files resolve correctly | ✅ Pass | None |
| 3 | No stale hardcoded metrics remain in any skill file | ✅ Pass | None |
| 4 | No orphan references to deleted directory in active docs | ✅ Pass | None |
| 5 | INDEX.md accurate and up-to-date | ✅ Pass | None |

## Verdict

**FRESH — MINOR ISSUES**

One minor stale reference in auto-generated `file_tree.md` (P3). All skill files are internally consistent, point to valid graphify outputs, and contain no hardcoded model metrics. No contradictions found between current documents.

**Recommendation:** Run `just graphify` at the next convenient opportunity to regenerate `file_tree.md` and eliminate the stale `feature-vector-spec/` reference.
