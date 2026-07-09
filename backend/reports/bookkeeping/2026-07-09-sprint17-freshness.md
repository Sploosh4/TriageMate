# Bookkeeping Report

**Date:** 2026-07-09
**Trigger:** quality gate — Sprint 17

---

## Audit: ROADMAP.md Sprint 17 Alignment

### Sprint 17 Items vs Codebase Reality

| ROADMAP Item | Code Evidence | Verdict |
|---|---|---|
| **1. Security Telemetry Module** | `backend/integrations/synthetic_telemetry.py` exists ✅ | BUILT |
| **2. Network Context Panel** | `backend/integrations/network_context.py` exists ✅ | BUILT |
| **3. Doc refresh** | This report ✅ | IN PROGRESS |

**Sprint 17 features are confirmed built.** Both new integration modules exist, the scoring engine accepts `telemetry_threat_score` and `network_blast_radius` parameters (line 29-30 of `backend/scoring.py`), and seed data includes `telemetry_json` and `network_context_json` fields.

---

## Auto-Fixed

### 1. ROADMAP.md — Stale demo score values
**File:** `docs/planning/ROADMAP.md`, line 18
**Issue:** Old score contract `94/87/71/63/55/41/22` — seed data now uses `98/91/73/66/58/44/26`
**Fix applied:** Updated the demo scores to match current seed_data.py values.

### 2. MVP_SCOPE.md — Stale demo score values
**File:** `docs/architecture/MVP_SCOPE.md`, line 223
**Issue:** Verification criteria still reference old scores `(94, 87, 71, 63, 55, 41, 22)`
**Fix applied:** Updated to new scores `(98, 91, 73, 66, 58, 44, 26)`.

---

## Items Flagged for Human Review

### P1 — Old score mention in seed_data.py investigation notes
**File:** `backend/seed_data.py`, line 66
**Issue:** The investigation notes text still says "...assigned a priority score of 94..." but the actual `priority_score` field at line 34 is now 98. The notes also say "All six scoring dimensions triggered at maximum severity" — should be 7 dimensions.
**Action needed:** Update narrative text in seed_data.py to match actual score values and dimension count. This affects demo display text shown to users.

### P1 — intel-toolbox SKILL.md missing Sprint 17 integrations
**File:** `.opencode/skills/intel-toolbox/SKILL.md`
**Issue:** The integration modules table (§Integration Modules) lists 10 modules but omits `synthetic_telemetry.py` and `network_context.py` added in Sprint 17.
**Action needed:** Add the two new integration modules to the table with descriptions.

### P2 — MVP_SCOPE.md dimension count stale (6 → 7)
**File:** `docs/architecture/MVP_SCOPE.md`
**Issues:**
- Line 84: "Six weighted dimensions" — code now has 7 (Security Context dimension added Sprint 17)
- Line 84: "Exposure (max 15)" — actual code (`scoring.py` line 95-101) has max 12
- Line 194: "6-dimension weighted score" — should be 7

### P2 — ai-doc-strategy.md dimension count stale (6 → 7)
**File:** `docs/planning/ai-doc-strategy-2026-07-07.md`, line 212
**Issue:** "Understand scoring architecture (6 dimensions, weights, bands)" — should be 7 dimensions.
**Note:** This document is CURRENT per INDEX.md.

### P3 — INDEX.md missing Sprint 17 section
**File:** `docs/INDEX.md`
**Issue:** INDEX.md has dedicated sections for Sprint 14 (database tables, scripts, automation) and Sprint 16 (ML test files) but no Sprint 17 section documenting:
- `synthetic_telemetry.py` and `network_context.py` integrations
- Scoring engine changes (Security Context dimension, telemetry/blast radius params)
- Seed data changes (telemetry_json, network_context_json fields)

---

## Cross-Reference Check Results

| Check Type | Status | Details |
|---|---|---|
| Cross-file contradictions | **ISSUES FOUND** | ROADMAP vs MVP_SCOPE both stale on scores; both stale on dimension count |
| Stale file references | **CLEAN** | All documented file paths exist |
| Numeric consistency | **ISSUES FOUND** | Score values mismatch between docs and seed_data.py |
| Terminology drift | **ISSUES FOUND** | "6 dimensions" vs code's 7; "Exposure max 15" vs code's 12 |
| Status badge accuracy | **CLEAN** | All INDEX.md status badges match reality |
| INDEX.md completeness | **MINOR ISSUE** | No Sprint 17 section; otherwise complete |

---

## Orphans Found

- **None.** No archived files are referenced by current active files inappropriately. The archived `ROADMAP-2026-07-09.md` contains old scores (as expected of an archive).

---

## Coverage Gaps

- `synthetic_telemetry.py` and `network_context.py` not documented in `.opencode/skills/intel-toolbox/SKILL.md`
- Security Context scoring dimension (7th dimension) not reflected in `MVP_SCOPE.md` or `ai-doc-strategy.md`
- Score contract change (94→98, 87→91, etc.) not reflected in `ROADMAP.md`, `MVP_SCOPE.md` or `seed_data.py` narrative text

---

## Verdict

**NEEDS ATTENTION** — Multiple stale score references and dimension counts across 4 current documents. Seed data code contains narrative text that contradicts actual field values. See flagged items above for action priorities.

**Priority order for human review:**
1. Fix `seed_data.py` investigation notes (P1 — affects user-facing demo display)
2. Update `.opencode/skills/intel-toolbox/SKILL.md` (P1 — agent guidance gap)
3. Update `MVP_SCOPE.md` dimension count (P2 — stale structural reference)
4. Update `ai-doc-strategy.md` dimension count (P2 — stale structural reference)
5. Add Sprint 17 section to `INDEX.md` (P3 — completeness)
