# Bookkeeping Report — Sprint 17 Final

**Date:** 2026-07-09
**Trigger:** Final bookkeeper pass for Sprint 17

---

## Checklist Results

| # | Check | Result |
|---|---|---|
| 1 | `docs/INDEX.md` — Sprint 17 section present? | ✅ Present (lines 133–141) |
| 2 | `docs/planning/ROADMAP.md` — Sprint 17 items listed? | ✅ Present (lines 34–43) |
| 3 | Score contract: docs use 98/91/73 (new) not 94/87/71 (old)? | ✅ All 3 CURRENT docs use new scores |
| 4 | No stale "6 dimensions" in CURRENT docs? | ✅ None found |

---

## Items Already Fixed (since prior report `2026-07-09-sprint17-freshness.md`)

| Item | Status |
|---|---|
| INDEX.md missing Sprint 17 section | ✅ **Added** (was P3, now present) |
| MVP_SCOPE.md dimension count ("Six weighted" → "Seven weighted") | ✅ **Corrected** (was P2) |
| MVP_SCOPE.md exposure max (15 → 12) | ✅ **Corrected** (was P2) |
| ai-doc-strategy.md dimension count (6 → 7) | ✅ **Corrected** (was P2) |
| ROADMAP.md stale scores (94→98, etc.) | ✅ **Fixed** (was auto-fixed) |
| MVP_SCOPE.md stale scores (94→98, etc.) | ✅ **Fixed** (was auto-fixed) |

---

## Remaining Issues (not yet fixed)

### P1 — INDEX.md Sprint 17 section has wrong file paths

The Sprint 17 component table at `docs/INDEX.md` lines 135–141 lists incorrect file paths. The implementation integrated data into `seed_data.py` and existing frontend files, not separate pipeline/panel modules.

| Docs say | Actual location |
|---|---|
| `backend/pipeline/synthetic_telemetry.py` | `backend/integrations/synthetic_telemetry.py` |
| `backend/pipeline/network_context.py` | `backend/integrations/network_context.py` |
| `frontend/panel5.html` | `frontend/index.html` (Panel 5 section inline) |
| `frontend/js/panel5.js` | `frontend/js/components/caseView.js` (Panel 5 rendered inline) |

**Fix:** Update the `Files` column in INDEX.md to match actual file locations.

### P1 — seed_data.py narrative text still says "94" instead of 98

**File:** `backend/seed_data.py`, line 193

The `summary_paragraphs_json` text for Row 1 (CVE-2023-34362) says:
> "...drives the priority score to **94** out of 100."

But `priority_score` is now **98** (line 34). This text appears in the demo case view shown to users.

**Fix:** Change "94" to "98" in the narrative text.

### P1 — intel-toolbox SKILL.md missing Sprint 17 integrations

**File:** `.opencode/skills/intel-toolbox/SKILL.md`

The Integration Modules table lists 10 modules but omits `synthetic_telemetry.py` and `network_context.py`. This means the intel agent won't know about these enrichment sources.

**Fix:** Add two rows to the integration table:
- `synthetic_telemetry.py` — Synthetic Sentinel/EDR telemetry generator
- `network_context.py` — Network blast radius from synthetic_assets

### P3 — INDEX.md description says "post-Sprint 16b"

**File:** `docs/INDEX.md`, line 33

The ROADMAP description says "Forward-looking roadmap post-Sprint 16b." Should be updated to "post-Sprint 17" if the sprint is complete.

### P3 — ROADMAP.md sprint count says "16 + 16b"

**File:** `docs/planning/ROADMAP.md`, line 15

Sprints completed reads "16 + 16b". If this is the final Sprint 17 pass, should read "17".

---

## Orphans Found

**None.** No archived files are referenced by CURRENT docs inappropriately. No CURRENT docs reference stale `docs/archive/*` files.

---

## Cross-Reference Consistency

| Pair | Status |
|---|---|
| ROADMAP.md vs INDEX.md (scores) | ✅ Consistent (both 98/91/73) |
| ROADMAP.md vs MVP_SCOPE.md (scores) | ✅ Consistent (both 98/91/73) |
| INDEX.md vs scoring.py (formula) | ✅ Consistent (threat_score×3 + blast_radius×2, clamped 0–5) |
| INDEX.md vs seed_data.py (scores) | ✅ Consistent (all 7 rows match) |
| INDEX.md vs codebase (file paths) | ❌ **MISMATCH** — see P1 above |

---

## Verdict

**NEEDS ATTENTION** — 3 unresolved P1 issues remain from the prior round. The core numbers (scores, dimensions) are correct across all docs, but two docs have stale file paths and one has stale narrative text. The intel agent's guidance is incomplete.

**Suggested priority:**
1. Fix INDEX.md Sprint 17 file paths (P1 — agents will look for wrong files)
2. Fix seed_data.py narrative "94" → "98" (P1 — user-facing demo text)
3. Update intel-toolbox SKILL.md (P1 — agent guidance gap)
4. Update INDEX.md/ROADMAP.md sprint count descriptions (P3 — cosmetic)
