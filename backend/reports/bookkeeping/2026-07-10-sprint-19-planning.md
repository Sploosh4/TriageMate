# Bookkeeping Report

**Date:** 2026-07-10
**Trigger:** Sprint 19 planning — freshness pass

---

## Auto-Fixed

- [`docs/planning/ROADMAP.md`] → Added new **Sprint 19 — 🟡 Planned** section after Sprint 18 (lines 62–77). Table includes Items 1–4 and Bonuses A, F with status "🟡 Planned" and descriptions. Includes note about Bonuses B–G deferred to Sprint 20.

---

## Items Flagged for Human Review

### P0 — Contradiction: Sprint 17 Seed Scores in ROADMAP.md
- **Files:** `docs/planning/ROADMAP.md` (line 43) vs `docs/planning/ROADMAP.md` (line 18)
- **Issue:** ROADMAP.md's Current State section (line 18) lists demo scores as **98/91/73/66/58/44/26**, but the Sprint 17 section (line 43) says **94/92/86/76/71/63/57**. These are the same 7 CVEs with different score sets.
- **Context:** Sprint 19 plan Step 0 explicitly calls this out as a blocker, recommending the CI-gate values (98/91/73/66/58/44/26) as canonical. User decision required before Sprint 19 execution begins.
- **Action:** Update Sprint 17 section to match Current State values after decision.

### P0 — Contradiction: Sprint 17 Seed Scores in INDEX.md
- **File:** `docs/INDEX.md` (line 43 vs line 142)
- **Issue:** The Sprint 17 description section (line 43) says **94/92/86/76/71/63/57**, but the Score Contract section (line 142) says **98/91/73/66/58/44/26** ("Sprint 17+ recalculation"). Same root cause as the ROADMAP.md contradiction.
- **Action:** Align INDEX.md Sprint 17 section scores with the canonical set after user decision. Both INDEX.md sections should reference the same values.

### P2 — Stale "Later" Section Items Overlap with Sprint 19
- **File:** `docs/planning/ROADMAP.md` — "Later — Medium-Term Engineering" section (lines 79–88)
- **Issue:** Three items in "Later" are now being addressed in Sprint 19, making them stale:
  - Item **8** (Scheduled retraining) → Sprint 19 Item **2**
  - Item **9** (Concept drift monitoring) → Sprint 19 Item **4**
  - Item **11** (Shared config module) → Sprint 19 Item **1**
- **Action:** Remove or update these three items from "Later" section once Sprint 19 begins. The remaining items (12: Multiplier scoring, 13: EPSS v4 retrain, 14: Multi-window labels) remain valid as "Later" items.

### P3 — Sprint 17 Section in ROADMAP.md References Pre-Sprint-17 Scores
- **File:** `docs/planning/ROADMAP.md` (line 43 — Sprint 17, Item 6)
- **Issue:** "New scores: 94/92/86/76/71/63/57" — these were the scores *immediately after Sprint 17* but have since been superseded by the Sprint 17+ recalculation (98/91/73/66/58/44/26) after the 7th scoring dimension was finalized. This is the same score set as the P0 issue above — included here to confirm the count.
- **Action:** Covered by P0 resolution above.

### P3 — INDEX.md "Sprint 17" Section Contains Historical Scores
- **File:** `docs/INDEX.md` (line 43)
- **Issue:** Same score set (94/92/86/76/71/63/57) in the Sprint 17 section. Should match the canonical Score Contract section at line 142.
- **Action:** Covered by P0 resolution above.

---

## Orphans Found

- **No orphaned references to Bonuses B–G found outside the sprint plan itself.** The `ROADMAP.md` Sprint 18 section references Bonuses A–D (all ✅ Done — correct historical record). The Sprint 19 plan references Bonuses B–G as deferred to Sprint 20 (expected — the plan file is current, not orphaned). All other `.md` files under `docs/` are clean.
- **No orphaned archive references:** No active `.md` files point to archived files that don't exist.

---

## INDEX.md Concerns

### 1. Score Contradiction (P0 — see above)
Line 43 says `94/92/86/76/71/63/57` but line 142 says `98/91/73/66/58/44/26`.

### 2. No Reference to Shared Config Module or NPZ Feature Names
This is **not yet a problem** — Sprint 19 hasn't been executed. INDEX.md only documents what exists. Once Sprint 19 items are complete, the following INDEX.md sections should be updated:
- **Sprint 19 section** should be added (similar to the Sprint 17/18 sections)
- **Graphify section** (line 162–172) may need updating after NPZ column metadata is added
- **Quick Reference** may need entries for config module or NPZ verification commands

### 3. No Reference to Sprint 19 Plan
The INDEX.md currently only mentions up to Sprint 18. Once Sprint 19 begins, a Sprint 19 section should be added (post-completion).

### 4. No Contradiction with NPZ/Config References
No existing content in INDEX.md contradicts the Sprint 19 plan regarding NPZ columns or shared config module — these features don't exist yet, so there's nothing to contradict.

---

## Coverage Gaps

| Gap | Details |
|-----|---------|
| **ROADMAP.md "Later" section not updated** | Items 8, 9, 11 are now in Sprint 19 but still listed as "Later" (flagged above) |
| **Sprint 17 scores in ROADMAP.md** | Need updating per user decision (flagged above) |
| **Sprint 17 scores in INDEX.md** | Same issue (flagged above) |

---

## Verdict

**NEEDS ATTENTION** — Two P0 contradictions found (same root cause: stale Sprint 17 scores in two files). The "Later" section has overlap with Sprint 19 that should be resolved before or at sprint start. Once the score canonicalization decision is made (Sprint 19 Step 0), three files need updating: `ROADMAP.md` (Sprint 17 scores and "Later" section), and `INDEX.md` (Sprint 17 scores).

### Recommended Action Items (for Commander)

| Priority | Action | Owner |
|----------|--------|-------|
| 🔴 P0 | Resolve canonical score set per Sprint 19 Step 0 (recommend: 98/91/73/66/58/44/26) | User + Commander |
| 🔴 P0 | Update ROADMAP.md Sprint 17 section scores to match canonical set | Bookkeeper (post-decision) |
| 🔴 P0 | Update INDEX.md Sprint 17 section scores to match canonical set | Bookkeeper (post-decision) |
| 🟡 P2 | Remove Items 8, 9, 11 from "Later" section in ROADMAP.md | Bookkeeper (at sprint start) |
