# Bookkeeping Report

**Date:** 2026-07-10
**Trigger:** Manual — documentation freshness audit

---

## Scope Check: `comparison-vs-described-system.md`

| Check | Result |
|---|---|
| File exists at `docs/architecture/comparison-vs-described-system.md` | ✅ |
| Referenced in `docs/INDEX.md` line 29 with CURRENT status | ✅ |
| Content is appropriate — 169 lines, maps 5 described system areas to actual implementation | ✅ |
| Referenced anywhere else? | No — only in INDEX.md. Expected for a freshly added file. |

**Verdict:** ✅ Properly integrated.

---

## INDEX.md Structure Check

| Area | Verdict |
|---|---|
| All 5 architecture files listed exist on disk | ✅ (3 in `docs/architecture/` + `backend/ml/README.md`) |
| All planning files listed exist on disk | ✅ |
| All reference files listed exist on disk | ✅ |
| All guide files listed exist on disk | ✅ |
| All research files listed exist on disk | ✅ |
| Status badges consistent (CURRENT/OUTDATED/ARCHIVED) | ✅ |
| Quick Reference table links resolve correctly | ✅ |
| Sprint detail sections (17, 18) present and accurate | ✅ |

**Verdict:** ✅ Consistent structure. No broken links.

---

## Cross-File Contradictions

### P0 — HANDOFF-2026-07-08.md: Marked CURRENT but factually contradicts ROADMAP.md

| Claim | HANDOFF (line 21) | ROADMAP (line 13) | Truth |
|---|---|---|---|
| Test count | 275/275 | 298 pass, 0 fail | 298 is correct — Sprint 17 & 18 added tests |
| Drift monitoring | ❌ "No model has proper drift monitoring" — Pre-Tier & EPSS drift endpoints all ❌ | ✅ Sprint 18 completed: Pre-Tier drift, EPSS drift, XGBoost drift endpoints all ✅ Done | Drift monitoring exists per Sprint 18 |

**Files:**
- `docs/planning/HANDOFF-2026-07-08.md` (CURRENT — should be OUTDATED or have a note)
- `docs/planning/ROADMAP.md` (CURRENT — authoritative)

**Impact:** An AI agent reading HANDOFF.md will incorrectly believe drift monitoring is missing. The HANDOFF was written before Sprint 17 & 18 completed — it's now superseded.

**Recommendation:** Either:
  - (a) Mark HANDOFF.md as OUTDATED with a banner noting it predates Sprints 17–18, OR
  - (b) Update the test count to 298 and add a §1 addendum noting that Sprint 18 retrofitted drift monitoring for all three model families

### P2 — ROADMAP.md "Later" Section: Items 8, 9, 11 Now in Sprint 19

| "Later" Item | Sprint 19 Item | Status |
|---|---|---|
| **8** — Scheduled retraining | **2** — Scheduled Retraining Triggers | 🟡 Planned (both) |
| **9** — Concept drift monitoring | **4** — Concept Drift | 🟡 Planned (both) |
| **11** — Shared config module | **1** — Shared Config Module | 🟡 Planned (both) |

**File:** `docs/planning/ROADMAP.md` lines 83–85 (Later) vs lines 68–71 (Sprint 19)

**Recommendation:** Once Sprint 19 begins execution, remove Items 8, 9, 11 from the "Later" section. The remaining items (12, 13, 14) are still valid as "Later."

### P3 — GreyNoise Status Mismatch

| Source | GreyNoise Status |
|---|---|
| `ROADMAP.md` line 17 | `[deprecated]` |
| `HANDOFF-2026-07-08.md` line 123 | ⚠️ Free tier restricted |
| `.opencode/skills/intel-toolbox/SKILL.md` line 16 | Listed without any status note |

**Recommendation:** Align terminology. If GreyNoise is deprecated (as ROADMAP states), the intel-toolbox skill should also note it. HANDOFF is already flagged for updates above.

---

## Orphan Detection

### Archived Agent Files Still Referenced
- No active `.md` files reference `.opencode/ARCHIVED/agents/` files — clean ✅

### Archived Skill Files Still Referenced
- `.opencode/ARCHIVED/skills/dual-database-ddl/` is referenced in `.opencode/DESIGN_RATIONALE.md` line 161 (expected — it's a design rationale document) ✅
- `.opencode/DESIGN_RATIONALE.md` line 168 also references `feature-vector-spec` (archived) — expected ✅

### Archive Documents Referenced from Active Docs
| Active Doc | Archive Reference | Status |
|---|---|---|
| `ROADMAP.md` line 5 | `docs/archive/ROADMAP-2026-07-09.md` | Expected ✅ |
| `MVP_SCOPE.md` line 7 | `docs/archive/sprints-1-6/COURSE_CORRECTION.md`, `PRE_DEMO_PLAN.md` | Expected ✅ |
| `INDEX.md` lines 45, 67, 179 | Various archive files | Expected — INDEX.md documents what was archived ✅ |

### Unreferenced Active Files
| File | Referenced By | Verdict |
|---|---|---|
| `.opencode/skills/codebase-review/SKILL.md` | Only in `graphify_output/file_tree.md` (auto-generated) | ⚠️ Not listed in `AGENTS.md` `<available_skills>` — see below |

**Verdict:** No true orphans found. All archive references are by design.

---

## Coverage Gaps

### P3 — `codebase-review` Skill Not in AGENTS.md Available Skills List
- **File:** `.opencode/skills/codebase-review/SKILL.md` exists on disk
- **Issue:** This skill is NOT listed in `AGENTS.md`'s `<available_skills>` section
- **Likely intent:** It's a methodology reference for agents, not a project-specific skill — but its presence in `.opencode/skills/` implies it should be loadable
- **Recommendation:** Either add it to AGENTS.md's available skills list, or move it to a different location if it's meant to be an internal reference only

### P3 — RESTRUCTURE_HANDOFF.md: "4 General Agents" No Longer Accurate
- **File:** `.opencode/RESTRUCTURE_HANDOFF.md` (line 14)
- **Claim:** "New state: 4 general agents (commander, strike, intel, auditor)"
- **Reality:** There are now 5 agents — bookkeeper was added after this handoff
- **Impact:** Low — this is a historical handoff, but the stale count could mislead

---

## Numeric Consistency Verification

| Metric | Claim | Verified | Match? |
|---|---|---|---|
| Demo scores | 98/91/73/66/58/44/26 | ROADMAP line 18, ROADMAP line 43, INDEX.md line 143, scoring-weights.md line 57 all agree | ✅ |
| DB rows: synthetic_assets | 1,827 | INDEX.md line 102, DB query | ✅ |
| DB rows: synthetic_findings | 777 | INDEX.md line 103, DB query | ✅ |
| DB rows: research_references | 97 | INDEX.md line 104, DB query | ✅ |
| Scoring total (max) | 112 | INDEX.md line 28, scoring-weights.md line 17 | ✅ |
| Scoring 7 dimensions | 40+20+20+12+5+10+5 | INDEX.md, scoring-weights.md, ROADMAP.md all agree | ✅ |
| Test files | 24 test_*.py files | `ls backend/tests/test_*.py` | ✅ |

**Note:** The Sprint 17 score contradiction flagged in the previous bookkeeping report (2026-07-10-sprint-19-planning.md) has been **resolved** — ROADMAP.md line 43 now shows 98/91/73/66/58/44/26 instead of the stale 94/92/86/76/71/63/57.

---

## Summary of Findings

| Priority | Issue | File(s) | Status |
|---|---|---|---|
| 🔴 P0 | HANDOFF marked CURRENT but test count (275→298) and drift monitoring status both stale | `docs/planning/HANDOFF-2026-07-08.md` | NEW |
| 🟡 P2 | "Later" section Items 8, 9, 11 overlap with Sprint 19 | `docs/planning/ROADMAP.md` lines 83–85 | PRE-EXISTING (was flagged in prior report, not yet fixed) |
| 🟢 P3 | `codebase-review` skill not in AGENTS.md available_skills | `.opencode/skills/codebase-review/SKILL.md` | NEW |
| 🟢 P3 | GreyNoise deprecated status not reflected in intel-toolbox skill | `.opencode/skills/intel-toolbox/SKILL.md` | NEW |
| 🟢 P3 | RESTRUCTURE_HANDOFF.md says "4 agents" (now 5) | `.opencode/RESTRUCTURE_HANDOFF.md` line 14 | NEW |
| ✅ Fixed | Sprint 17 scores in ROADMAP.md and INDEX.md now consistent | Both files | FIXED (since prior report) |

---

## Verdict

**NEEDS ATTENTION** — One P0 contradiction found. HANDOFF-2026-07-08.md is marked CURRENT but contains stale data (test count, drift monitoring status) that contradicts the authoritative ROADMAP.md. This is the highest-risk finding because AI agents loading this handoff will get incorrect guidance on drift monitoring status.

The P2 overlap between ROADMAP's "Later" section and Sprint 19 was flagged in the previous report and remains unresolved.

## Recommended Actions (for Commander)

| Priority | Action |
|---|---|
| 🔴 P0 | Mark `docs/planning/HANDOFF-2026-07-08.md` as OUTDATED with a banner noting Sprints 17–18 have since been completed, or update its test count and drift monitoring sections to match ROADMAP |
| 🟡 P2 | Remove Items 8, 9, 11 from "Later" section in ROADMAP.md once Sprint 19 begins |
| 🟢 P3 | Add `[deprecated]` note for GreyNoise in `.opencode/skills/intel-toolbox/SKILL.md` |
| 🟢 P3 | Add `codebase-review` to AGENTS.md available_skills or relocate it if not meant to be loadable |
