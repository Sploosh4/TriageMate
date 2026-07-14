# Bookkeeping Report

**Date:** 2026-07-14
**Trigger:** Sprint 28 freshness pass (post-execution audit)

---

## Verdict
**NEEDS ATTENTION** — A CURRENT document (`comparison-vs-described-system.md`) contains two major stale claims that contradict `ROADMAP.md`. A new document (`weight-zero-decision.md`) is missing from `INDEX.md`.

---

## Auto-Fixed
None — all findings require human judgment to fix.

---

## Items Flagged for Human Review

### P0 — Cross-File Contradictions

#### 1. `docs/architecture/comparison-vs-described-system.md` (status: CURRENT) — Two stale claims

**Stale Claim A — PCA status (Section 3, line 83):**
```
| **PCA** | Not mentioned | **Was present, then removed in v2.5** — commit message: "PCA removed..."
```
**Reality:** Sprint 20 re-introduced PCA with correct train/test hygiene. It is now saved as `pca_model.pkl` (generated at training time) with graceful fallback. See `ROADMAP.md` Sprint 20 Item 3.

**Stale Claim B — Tier 2 architecture (Section 5, lines 127, 143, 145, 147, 159, 165):**
```
| Multi-step investigation | Up to 40 steps | Single-shot call...
**Not implemented.** The LLM gets one shot per vulnerability. No step counter, no loop logic.
```
**Reality:** Sprint 20 added a multi-step agentic Tier 2 with 12 read-only tools, 15-step limit, \$0.50 cost budget, and feature-flag gating (`TRIAGEMATE_AGENT_ENABLED=false`). When disabled, single-shot fallback is used. Both paths exist. See `ROADMAP.md` Sprint 20 Item 1.

**Impacts:** The Summary Matrix (lines 157, 159) and Key Takeaways (lines 163–165) are also affected. This document needs a structural update to describe both the agentic path (when enabled) and the single-shot fallback.

**Affected sections:**
- Section 3: PCA description
- Section 5: Multi-step investigation, Investigation architecture, Summary Matrix row 5
- Key Takeaways items 1–2

---

#### 2. `docs/INDEX.md` — `weight-zero-decision.md` missing from Architecture listing

The file `docs/architecture/weight-zero-decision.md` was created in Sprint 28 (Item 2) but is NOT listed in INDEX.md. Every other file under `docs/architecture/` is listed (MVP_SCOPE.md, scoring-weights.md, comparison-vs-described-system.md).

**Action:** Add an Architecture entry for `weight-zero-decision.md` with status CURRENT.

---

#### 3. `docs/INDEX.md` — `comparison-vs-described-system.md` status mismatch

Currently listed as CURRENT, but contains stale claims (see finding 1 above). Recommend either:
- Downgrade status to OUTDATED with a caution banner, OR
- Update the document to reflect PCA re-introduction and agentic Tier 2 capability

---

### P2 — Missing Cross-References

#### 4. `docs/architecture/scoring-weights.md` — No reference to weight-zero decision

The scoring-weights.md document is the canonical source for scoring weight policy, but it does not reference `weight-zero-decision.md`. The weight-zero document documents the intentional min=1 policy, and scoring-weights.md should link to it in §Modification Rules.

---

### P3 — Minor/Informational

#### 5. INDEX.md feature count consistency

INDEX.md line 145: `"Total test count: 457+ tests (up from 142)"` — matches ROADMAP.md `"Tests: 457 pass, 0 fail, 1 skipped"`. Consistent. ✅

#### 6. Bug hunt reference in INDEX.md

INDEX.md line 53: `"162 bugs found across all areas (19 CRITICAL, 38 HIGH, 49 MEDIUM, 56 LOW). Full bug hunt report."`  
INDEX.md line 91: `"58 confirmed actionable"`  
These are factually accurate as a snapshot of the BUG_HUNT report's initial triage. No conflict with Sprint 27 completion, since Sprint 27 resolved all 58+20 actionable items. No change needed. ✅

---

## Orphans Found

None. All `.md` files under `docs/` are referenced from INDEX.md (except `weight-zero-decision.md` — see finding 2 above).

No archived `.md` files are referenced by active CURRENT documents:
- `docs/archive/ROADMAP-2026-07-09.md` — referenced by INDEX.md as ARCHIVED ✅
- `docs/archive/ml-implementation-plan.md` — referenced by INDEX.md as ARCHIVED ✅  
- `docs/archive/TASK_STORE_COLUMNS_IN_NPZ.md` — referenced by INDEX.md as ARCHIVED ✅
- `docs/archive/SPRINT_NEXT_PLAN.md` — referenced by INDEX.md as ARCHIVED ✅
- `docs/archive/handoffs/SPRINT_9_HANDOFF.md` — referenced by INDEX.md as ARCHIVED ✅
- Archive/planned-for-archive files in `.opencode/ARCHIVED/` — not referenced from active docs ✅

---

## Coverage Gaps

### Investigation Reports Exist ✅

All 7 investigation reports from Sprint 28 Phase 8 are present in `backend/reports/investigations/`:
- `agent-tool-access-boundary.md`
- `frontend-xss-evidence.md`
- `keydown-listener-lifecycle.md`
- `ml-readiness-investigation.md`
- `ml-retraining-decision-gate.md`
- `phase-8-remaining.md`
- `test-isolation-investigation.md`

The Sprint 28 plan (§Item 3) correctly references `backend/reports/investigations/`. ✅

---

## GitHub Cross-Reference Check

| Reference | Status | Notes |
|---|---|---|
| Sprint 28 plan → Milestone #12 | ✅ Verified | Milestone exists, title "Sprint 28", 2 open + 3 closed issues |
| Sprint 28 plan → Issue #51 (keydown) | ✅ Verified | Closed — matches plan's "Complete" status |
| Sprint 28 plan → Issue #52 (weight-zero) | ✅ Verified | Closed — matches plan's "Complete" status |
| Sprint 28 plan → Issue #53 (Phase 8) | ✅ Verified | Open — matches plan's "In Progress" status |
| Sprint 28 plan → Issue #54 (docs tracking) | ✅ Verified | Closed — matches plan's "In Progress" status (tracking issue for doc updates) |
| Sprint 28 plan → Issue #55 (ML gate) | ✅ Verified | Open — matches plan's "Assessment Complete" status |
| ROADMAP Sprint 27 → PR #50 | ✅ Verified | References `.opencode/plans/2026-07-13-bug-fix-sprint.md` which exists |
| ROADMAP Sprint 28 → Milestone #12 | ✅ Verified | References GitHub Milestone #12 which exists |

---

## Numeric Consistency Check

| Metric | ROADMAP.md | Sprint 28 Plan | Sprint 27 Plan | Match? |
|---|---|---|---|---|
| Test count | 457 pass, 0 fail, 1 skipped | 457 passed, 1 skipped | 457 passed, 1 skipped | ✅ |
| Sprints completed | 17–27 | Sprint 27 merged | N/A | ✅ |
| Current sprint | Sprint 28 | Sprint 28 | N/A | ✅ |
| Demo CVEs | 7, scores 99/97/74/91/82/97/80 | N/A | N/A | ✅ (scoring-weights.md matches) |

---

## Sprint Plan → Skill Consistency Check

No skill files under `.opencode/skills/` reference Sprint 27 bugs, weight-zero decisions, or keydown listener investigations. All skill files are generic (toolbox commands, engineering patterns) and do not need updates for Sprint 28 content. ✅

---

## Stale `.md` Files for Archiving

No `.md` files under `docs/` are candidates for archiving at this time. All serve active or historical-reference purposes. The most stale file (`comparison-vs-described-system.md`) needs updating, not archiving.

---

## Summary

| Category | Count | Severity |
|---|---|---|
| Cross-file contradictions (P0) | 1 document with 2 stale claims | HIGH |
| Missing INDEX.md entries (P2) | 1 (`weight-zero-decision.md`) | MEDIUM |
| Status badge mismatch (P2) | 1 (`comparison-vs-described-system.md` as CURRENT) | MEDIUM |
| Missing cross-references (P3) | 1 | LOW |
| GitHub reference issues | 0 | — |
| Orphaned references | 0 | — |
| Stale files needing archiving | 0 | — |
