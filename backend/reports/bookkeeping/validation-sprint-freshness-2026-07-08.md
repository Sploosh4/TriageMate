# Validation Sprint — Freshness Report

> **Date:** 8 July 2026
> **Method:** Full doc-vs-code bookkeeping pass

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 P0 (Must fix) | 2 | ✅ Fixed |
| 🟡 P1 (Stale info) | 2 | ✅ Fixed |
| 🟢 P2 (Minor) | 2 | ✅ Fixed |
| **Total** | **6** | **All resolved** |

## Findings & Fixes

### 🔴 P0 — Cross-Document Contradictions

| # | Issue | File(s) | Fix |
|---|-------|---------|-----|
| 1 | **#14 said "WON'T FIX"** but code was fixed (heuristic routing updated as part of XGBoost investigation). Header claimed "1 unfixed issue". | `docs/reference/AI_PROBLEMS.md` (root symlink too) | Updated #14 to ✅ FIXED with reference to investigation report. Header now says "All issues resolved ✅". ROADMAP.md "Still Unfixed" removed. |
| 2 | **ROC-AUC 0.9409 vs 0.9459** — MVP_SCOPE.md had 3 stale references to 0.9409 while ROADMAP.md + model_registry.json use 0.9459. | `docs/architecture/MVP_SCOPE.md` | All 3 instances updated to 0.9459. Also corrected feature dims (420→419, 36→35 tabular). |

### 🟡 P1 — Stale Information

| # | Issue | File(s) | Fix |
|---|-------|---------|-----|
| 3 | **"10 Pydantic models"** — models.py now has 19 BaseModel subclasses (review queue, drift, TriageConflictResult, auth, etc. added since Sprint 1). | `docs/planning/ROADMAP.md` | Updated to "19 models (BaseModel subclasses)". |
| 4 | **RESEARCH_FINDINGS.md** dated July 3 with "CURRENT" status but several findings (random seed, CIA default, threat_intel_pulses, CWE-stratified thresholds) resolved in Sprint NEXT. | `docs/research/RESEARCH_FINDINGS.md` | Changed to OUTDATED with explanation; points reader to ROADMAP.md for current status. |

### 🟢 P2 — Minor Issues

| # | Issue | File(s) | Fix |
|---|-------|---------|-----|
| 5 | **3 archive files missing ARCHIVED banners** — EXTERNAL_AUDITOR_PROMPT.md, SECOND_WAVE_PROMPT.md, External Auditor Response.md had no status marker. | `docs/archive/` | Added "Status: ARCHIVED" banners. |
| 6 | **Review queue endpoints missing** from API endpoint table in ROADMAP.md. | `docs/planning/ROADMAP.md` | Added 4 endpoints: GET/POST review queue, flag, review, history. |

## Verified Clean (No Issues)

- ✅ INDEX.md — Complete and accurate; status badges updated
- ✅ ROADMAP.md — All sprint completion claims, API endpoints, ML artifacts verified
- ✅ All 6 root symlinks — Resolve correctly to `docs/`
- ✅ backend/ml/README.md — Exists and accurate
- ✅ hostname-standards.md — Clean reference doc
- ✅ WINDOWS_SETUP.md — Setup steps match project structure
- ✅ xgboost-investigation-report.md — All file references and claims verified
- ✅ Graphify outputs — Rebuilt (timestamps: 2026-07-08 15:41)
- ✅ Archive files — All have ARCHIVED banners

## Next Sprint Recommendations

1. Run `just graphify` to regenerate auto-docs from current code state
2. Run `just test` and `just audit-all` to confirm no regressions
3. Consider renaming root-level `.md` files to actual symlinks into `docs/`
