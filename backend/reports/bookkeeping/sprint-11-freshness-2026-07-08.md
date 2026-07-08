# Bookkeeping Report — Sprint 11 Freshness

**Date:** 2026-07-08
**Trigger:** sprint-end (Sprint 11: Model Governance + Ops Hardening)

---

## Files Checked & Status

### Core Documentation

| File | Status | Notes |
|------|--------|-------|
| `.opencode/plans/2026-07-08-sprint-11.md` | ✅ CURRENT | All 3 items have matching deliverable files on disk |
| `docs/planning/ROADMAP.md` | ⚠️ STALE | Sprint NEXT+ items 13, 14, 18 need status updates |
| `docs/INDEX.md` | ✅ CURRENT | No new `.md` doc files were added; index remains accurate |
| `docs/reference/AI_PROBLEMS.md` | ✅ CURRENT | No new bugs introduced; audit gap wasn't previously tracked here |
| `docs/architecture/MVP_SCOPE.md` | ✅ N/A | Pre-existing OUTDATED state; Sprint 11 doesn't affect it |
| `docs/guides/WINDOWS_SETUP.md` | ✅ CURRENT | Unchanged |
| `docs/reference/hostname-standards.md` | ✅ CURRENT | Unchanged |

### Skills

| File | Status | Notes |
|------|--------|-------|
| `.opencode/skills/backend-engineering/SKILL.md` | ⚠️ STALE | Line 34 router list omits `models` router |
| `.opencode/skills/ml-toolbox/SKILL.md` | ✅ CURRENT | No new CLI commands introduced |
| `.opencode/skills/triage-toolbox/SKILL.md` | ✅ CURRENT | No new just recipes needed |
| `.opencode/skills/intel-toolbox/SKILL.md` | ✅ CURRENT | No new data sources introduced |
| `.opencode/skills/cloud-llm-engineering/SKILL.md` | ✅ CURRENT | No changes to Tier 2 pipeline |
| `.opencode/skills/devops-engineering/SKILL.md` | ✅ CURRENT | No Docker/infra changes in Sprint 11 |
| `.opencode/skills/frontend-engineering/SKILL.md` | ✅ CURRENT | Drift dashboard JS is updated but skill describes general approach |
| `.opencode/skills/ux-designing/SKILL.md` | ✅ CURRENT | CSS changes are incremental; no skill update needed |
| `.opencode/skills/ml-engineering/SKILL.md` | ✅ CURRENT | Model version mgmt is ops, not ML engineering |

### Auto-Generated / Reference

| File | Status | Notes |
|------|--------|-------|
| `backend/ml/README.md` | ✅ CURRENT | Points to auto-generated `graphify_output/ml_inventory.md` |
| `graphify_output/` files | ✅ N/A | Auto-generated; regeneration deferred per scope boundaries |

---

## Sprint 11 Deliverable Files — All Present ✅

| File | Type | Status |
|------|------|--------|
| `backend/routers/ingest.py` | Modified — `effective_routing` fix | ✅ Verified (lines 300-307) |
| `backend/tests/test_audit.py` | New | ✅ Exists on disk |
| `backend/ml/model_registry.json` | New | ✅ Exists (3 version entries: v1, v2, v3) |
| `backend/routers/models.py` | New | ✅ Exists (3 endpoints) |
| `backend/tests/test_model_versions.py` | New | ✅ Exists on disk |
| `backend/ml/xgboost_predictor.py` | Modified — `set_active_version()` | ✅ Verified |
| `backend/main.py` | Modified — includes `models_router` | ✅ Verified (line 12, line 33) |
| `frontend/js/components/driftDashboard.js` | Modified — `loadModelStatusPanel()` | ✅ Verified (lines 1-44) |
| `frontend/index.html` | Modified — `div#model-info-panel` | ✅ Verified (line 165) |
| `frontend/css/triagemate.css` | Modified — `.model-info-*` styles | ✅ Verified (lines 1261-1287) |
| Test count | 85 tests collected | ✅ Up from 43 (Sprint 10 baseline) |

---

## Discrepancies Found

### 1. ROADMAP.md — Sprint NEXT+ Item Statuses Outdated (P1)

Three items completed in Sprint 11 still show pre-Sprint-11 status:

| # | Item | Current Status | Should Be | Sprint 11 Ref |
|---|---|---|---|---|
| 13 | **Model rollback** | 📋 Deferred | ✅ Done (or 🟡 Partial) | Item 2 — version management with activate/switch |
| 14 | **Auto-resolved audit sampling** | 📋 Remaining | ✅ Done | Item 1 — `effective_routing` fix |
| 18 | **Model comparison endpoint** | 📋 Remaining | ✅ Done | Item 3 — `GET /api/model/status` + frontend panel |

**Note on Item 13:** The ROADMAP describes it as "Model rollback" (2 hrs). Sprint 11 delivered broader "Model version management" including list/activate. The `/api/model/activate` endpoint effectively provides rollback capability. However, the implementation allows switching to any version, not just rolling back to the previous one. Status could be "✅ Done" or "🟡 Partial — no dedicated rollback endpoint, but activation covers it."

### 2. ROADMAP.md — New Endpoints Not Documented (P2)

The three new model management endpoints have no mention in ROADMAP.md:

- `GET /api/model/versions` — list registered models
- `POST /api/model/activate` — switch active model
- `GET /api/model/status` — active model info + comparison

They are documented *only* in the sprint plan file (`.opencode/plans/2026-07-08-sprint-11.md`). Operators reading ROADMAP.md for current project state would not know these exist.

### 3. backend-engineering SKILL.md — Router List Incomplete (P3)

Line 34:
```
- `backend/routers/` — API endpoint routers (auth, cases, ingest, queue)
```
Missing `models`. Should be:
```
- `backend/routers/` — API endpoint routers (auth, cases, ingest, models, queue)
```

### 4. New Endpoints Undocumented in Docs/ (P3)

None of the three model endpoints are documented anywhere under `docs/`. Only the sprint plan mentions them. There is no reference documentation for operators about:
- How to list available model versions
- How to switch the active model
- What the model status endpoint returns
- What the drift dashboard model info panel shows

### 5. AI_PROBLEMS.md — Audit Gap Not Tracked (Info)

The Sprint 11 Item 1 fix resolved: "Tier 1 auto-resolved cases were invisible to audit sampling." This was a functional gap (not an AI-generated code bug) and was not previously tracked in AI_PROBLEMS.md. Consider whether it warrants a retrospective entry.

---

## Orphans Found

**None.** All Sprint 11 files are properly wired:
- `routers/models.py` is imported in `main.py`
- `driftDashboard.js` references `/api/model/status` (correct)
- `index.html` has `div#model-info-panel` (correct)
- `triagemate.css` has `.model-info-*` styles (correct)
- No old file references to deleted files

---

## Coverage Gaps

| Gap | Details |
|-----|---------|
| Model management API undocumented | `GET /api/model/versions`, `POST /api/model/activate`, `GET /api/model/status` have no operator-facing docs under `docs/` |
| Skill cross-reference stale | `backend-engineering/SKILL.md` router list missing `models` |

---

## Cross-Reference Verification

| Check | Result |
|-------|--------|
| Sprint plan deliverables → files on disk | ✅ All 10 files present |
| ROADMAP → sprint plan consistency | ⚠️ 3 item statuses out of sync |
| INDEX.md → docs/ completeness | ✅ All docs/ files listed |
| Skill descriptions → actual content | ⚠️ backend-engineering SKILL.md router list |
| AI_PROBLEMS unfixed items → still valid | ✅ #14 still WON'T FIX (fallback path) |
| New endpoints → any doc reference | ⚠️ Only in sprint plan |

---

## Recommendations

1. **Immediate (P1):** Update ROADMAP.md Sprint NEXT+ statuses for Items 13, 14, 18
   - Item 14 → ✅ Done
   - Item 18 → ✅ Done
   - Item 13 → ✅ Done (or 🟡 Partial with explanation)

2. **Immediate (P2):** Add new model management endpoints to ROADMAP.md API Endpoints section

3. **This sprint (P3):** Update `backend-engineering/SKILL.md` line 34 to include `models` in router list

4. **Next sprint (P3):** Consider adding a brief operator reference under `docs/reference/` for model management endpoints, or at minimum update the ROADMAP quick-reference section

5. **Optional:** Add audit sampling fix to AI_PROBLEMS.md as a fixed item if desired for completeness

---

## Verdict

**PASS (WARN)**

All Sprint 11 deliverables exist and are properly wired. Test count grew from 43 to 85. No broken references, no orphan files, no new known bugs. However, ROADMAP.md has **3 stale item statuses** in the Sprint NEXT+ table (Items 13, 14, 18) and the new model management endpoints are invisible to anyone reading the master roadmap. One skill file has an incomplete router listing.

**Warnings issued:**
- ROADMAP.md Sprint NEXT+ item statuses need updating (3 items)
- ROADMAP.md missing new model management endpoints
- backend-engineering SKILL.md router list incomplete
- New endpoints have no operator-facing documentation outside sprint plan
