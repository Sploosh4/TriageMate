# Bookkeeping Report — Full Documentation Freshness Verification

**Date:** 2026-07-08
**Trigger:** Manual — full validation sprint
**Methodology:** Read every `.md` in `docs/`, verified claims against actual code in `backend/` and `frontend/`, checked all symlinks, cross-referenced data files.

---

## Summary

| Severity | Count | Description |
|----------|-------|-------------|
| **P0 — Cross-doc contradiction** | 2 | AI_PROBLEMS #14 status contradicts actual code; MVP_SCOPE ROC-AUC contradicts ROADMAP |
| **P1 — Stale information** | 3 | Model count, stale doc content, status badge mismatch |
| **P2 — Minor / cosmetic** | 3 | Stale line reference, 2 archive files missing ARCHIVED banners |
| **P3 — Documentation note** | 1 | RESEARCH_FINDINGS note needs update |
| **No issues** | 11/19 files | INDEX.md, hostname-standards, WINDOWS_SETUP, ROADMAP (all endpoints verified), etc. |

**Verdict: NEEDS ATTENTION** — 2 P0 contradictions between CURRENT docs require immediate resolution.

---

## Per-File Findings

### A. `docs/INDEX.md` — ✅ NO ISSUES

- Every non-archive `.md` in `docs/` is listed ✅
- `backend/ml/README.md` correctly referenced as CURRENT ✅
- `graphify_output/` correctly referenced as auto-generated ✅
- All 6 root-level symlinks resolve correctly ✅
- Status badges match reality for all listed files ✅
- Archive coverage note accurate: "Files under docs/archive/... not listed" ✅

### B. `docs/planning/ROADMAP.md` — ⚠️ P1: Stale model count

**Claims verified against code:**
| Claim | Verification |
|-------|-------------|
| All API endpoints exist | ✅ `GET /api/queue`, `GET /api/case/{id}`, `GET /api/metrics`, `POST /api/ingest`, `POST /api/ingest/batch`, `POST /api/ingest/tenable`, `GET /api/health`, `GET /api/model/versions`, `POST /api/model/activate`, `GET /api/model/status`, `POST /api/auth/login`, `POST /api/auth/refresh`, `GET /api/drift` all confirmed |
| 4 pipeline stages (Pre-Tier → Tier 2) | ✅ Code exists at `backend/pipeline/{pre_tier,tier_0,tier_1,tier_2}.py` |
| ML artifacts | ✅ `xgboost_model.pkl` (1.3MB, Jul 8), `xgboost_calibrator.pkl` (827B), `threshold_info.json` (78B), `pre_tier_model.pkl` (5MB), `model_registry.json` all confirmed |
| Training data v2 | ✅ `training_data_v2.npz` exists, shape (253568, 419) — matches "253K samples, 419 columns" |
| `dates` key in training data | ✅ Confirmed: `data['dates'][:5] = ['2019-01-08', ...]` |
| Score baseline [94,87,71,63,55,41,22] | ✅ Matches model_registry.json v3 exactly |
| JWT auth disabled by default | ✅ `AUTH_DISABLED = not ADMIN_USER` — env vars must be set |
| Sprint completion claims | ✅ All 13 sprint statuses match commit / file evidence |
| FastAPI entry point | ✅ `backend/main.py` exists with CORS, static mounts, startup lifecycle |
| SQLite + PostgreSQL | ✅ `backend/database.py` supports both |
| Background scheduler + audit | ✅ `scheduler.py` + `audit.py` confirmed |
| CWE-stratified EPSS thresholds | ✅ Present in `xgboost_predictor.py` as `CWE_EPSS_THRESHOLDS` dict |
| LanceDB vector store | ✅ `backend/data/lancedb/` exists with FTS indices |

**Issue found:**
- **P1** — "Pydantic models (models.py) — ✅ Done — 10 models" → **models.py now has 19 classes** (or 18 excluding BaseModelConfig). New models added for review queue, drift dashboard, and triage conflict results since the original claim.

### C. `docs/reference/AI_PROBLEMS.md` — 🔴 P0: #14 status contradicts code

**Issue #14 — WON'T FIX but code IS fixed:**
- **Doc claims:** `#14` status is `🟢 WON'T FIX`. References old code `routing = "escalated" if 0.55 <= confidence <= 0.85 else "auto_resolved"` at `tier_1.py:63`
- **Actual code (`backend/pipeline/tier_1.py`):** The heuristic routing now uses:
  ```python
  if exploitation_prob >= 0.50:
      routing = "escalated"
  elif exploitation_prob >= 0.30:
      routing = "escalated" if confidence <= 0.80 else "auto_resolved"
  else:
      routing = "auto_resolved"
  ```
- **Corroboration:** `xgboost-investigation-report.md` §Finding 4 explicitly states: "Also fixed the heuristic fallback in `tier_1.py:84` which had a broken confidence-range check."
- **Impact:** P0 — A CURRENT doc claims an issue is WON'T FIX, but the code fix was applied. An AI agent reading AI_PROBLEMS.md would wrongly believe the heuristic routing is broken.

**Other verified items:**
- Items FIXED (1-13): all correspond to actual code changes ✅
- "1 unfixed issue remaining" header: This is now **incorrect** — #14's status is FIXED, so there should be ZERO unfixed issues, or #14 should be correctly marked.

### D. `docs/architecture/MVP_SCOPE.md` — 🔴 P0: ROC-AUC contradiction

- **OUTDATED banner is correct** — many deferred items are now implemented ✅
- **But:** Claims "ROC-AUC 0.9409 (honest evaluation)" in two places (Tier 1 description, §3.1)
- **ROADMAP.md says:** "ROC-AUC 0.9459"
- **model_registry.json says:** `"roc_auc": 0.9459` (v3)
- **xgboost-investigation-report.md says:** "ROC-AUC 0.9459"
- **Impact:** P0 — Two CURRENT/ACTIVE docs directly contradict on a numeric value. AI agents reading MVP_SCOPE (even with OUTDATED banner) could get the wrong ROC-AUC.

**Also:**
- "3 tables" claim (Scope Summary Table) — Now outdated: there are also `reviews`, `alembic_version` tables. Minor given the OUTDATED banner.

### E. `docs/reference/xgboost-investigation-report.md` — ✅ NO ISSUES

- "All 8 fixes applied and model retrained ✅" verified correct ✅
- All referenced files (`scoring.py`, `database.py`, `routers/ingest.py`, `pipeline/tier_1.py`, `ml/train_xgboost.py`, `ml/xgboost_predictor.py`, `ml/encoder.py`) exist ✅
- Calibration artifacts (`xgboost_calibrator.pkl`, `threshold_info.json`) confirmed on disk ✅
- ROC-AUC 0.9459 matches model_registry.json ✅
- All fix descriptions match current code structure ✅

### F. `docs/reference/hostname-standards.md` — ✅ NO ISSUES

- Correctly marked as CURRENT reference doc ✅
- No code claims to verify (external research document) ✅

### G. `docs/research/RESEARCH_FINDINGS.md` — ⚠️ P2: Stale "CURRENT" status

- **Status:** "CURRENT" (3 July 2026)
- **Issue:** Many findings are now stale because Sprint NEXT was completed:
  - `threat_intel_pulses=0.0` (critical drift #5) — now has `_compute_threat_intel_pulses()` in `train_xgboost.py`
  - No random seed in BTC — now has `random.seed(42)` at `build_training_corpus.py:42`
  - Published dates not stored — now stored in `fetch_nvd_corpus.py:119` and persisted in `training_data_v2.npz`
  - "835 usable KEV positives" — training data now has 1,617 positives (point-in-time fix recovered more)
- **Note:** The doc does have a disclaimer: "NOTE: Some recommendations below... were implemented in Sprint NEXT."
- **Recommendation:** Downgrade to "OUTDATED" or update the content and date.

### H. `docs/guides/WINDOWS_SETUP.md` — ✅ NO ISSUES

- Setup steps (Python venv, pip install, uvicorn, seed_data.py) match project structure ✅
- Docker compose reference is correct ✅
- All troubleshooting items still relevant ✅

### I. `docs/archive/` files — ⚠️ P2: Missing ARCHIVED banners on 3 files

All archive files are correctly located under `docs/archive/` and properly referenced by INDEX.md as archived.

**Missing status banners:**
- `docs/archive/EXTERNAL_AUDITOR_PROMPT.md` — **No ARCHIVED banner** (starts with `# External Auditor Prompt` without status)
- `docs/archive/SECOND_WAVE_PROMPT.md` — **No ARCHIVED banner** (starts with `# Wave 2 Audit Prompt` without status)
- `docs/archive/External Auditor Response.md` — **No ARCHIVED banner** (starts with `I now have enough evidence...`)

All other archive files have proper ARCHIVED banners ✅

Note: These files ARE implicitly archived by being in the `archive/` directory, and INDEX.md has a blanket statement. Adding banners would be best practice.

### J. Root-level `.md` symlinks — ✅ NO ISSUES

```
AGENTS.md          → real file (no symlink needed)
AI_PROBLEMS.md     → docs/reference/AI_PROBLEMS.md          ✅ resolves
MVP_SCOPE.md       → docs/architecture/MVP_SCOPE.md         ✅ resolves
RESEARCH_FINDINGS.md → docs/research/RESEARCH_FINDINGS.md   ✅ resolves
ROADMAP.md         → docs/planning/ROADMAP.md               ✅ resolves
WINDOWS_SETUP.md   → docs/guides/WINDOWS_SETUP.md           ✅ resolves
XGBOOST_INVESTIGATION_REPORT.md → docs/reference/xgboost-investigation-report.md ✅ resolves
```

No broken symlinks. No orphan `.md` files at root. ✅

### K. `backend/ml/README.md` — ✅ NO ISSUES

- Exists at expected path ✅
- Correctly points to `graphify_output/ml_inventory.md` as the canonical source ✅

---

## Cross-Cutting Issues

### 1. [P0] AI_PROBLEMS #14: "WON'T FIX" but code was fixed
**Affected files:**
- `docs/reference/AI_PROBLEMS.md` — claims WON'T FIX, describes old code
- `backend/pipeline/tier_1.py` — code has the fix (probability-based routing)
- `docs/reference/xgboost-investigation-report.md` §Finding 4 — confirms fix applied
- `docs/planning/ROADMAP.md` — correctly lists the issue as addressed

**Recommendation:** Update AI_PROBLEMS.md #14 status to ✅ FIXED, update the description to match current code, or remove the entry since the fix is documented in the investigation report.

### 2. [P0] ROC-AUC value mismatch between MVP_SCOPE and ROADMAP/model_registry
**Affected files:**
- `docs/architecture/MVP_SCOPE.md` — says 0.9409
- `docs/planning/ROADMAP.md` — says 0.9459
- `backend/ml/model_registry.json` — says 0.9459

**Recommendation:** Correct MVP_SCOPE.md to 0.9459 (this is the value from the actual model artifact).

### 3. [P1] Pydantic model count stale
**Affected file:** `docs/planning/ROADMAP.md` — "10 models" should be "19 models" (or 18 excluding base class)

---

## Orphans Found

**None.** All active doc references resolve to existing files. All archive files are properly referenced as archived.

---

## Coverage Gaps

| Feature/File | Missing From | Notes |
|---|---|---|
| Review queue endpoints (4 endpoints) | `ROADMAP.md` API endpoint table | Table lists GET/queue, GET/case, GET/metrics, POST/ingest, etc., but not the review endpoints (`/api/review/queue`, `/api/review/flag/{id}`, `/api/case/{id}/review`, `/api/case/{id}/history`) |

---

## Auto-Fixed

None — this was a read-only pass.

---

## Items Flagged for Human Review

1. **AI_PROBLEMS.md #14** → Status should be FIXED (not WON'T FIX). Code was changed as part of XGBoost investigation fix for Finding 4.

2. **MVP_SCOPE.md ROC-AUC** → Value (0.9409) contradicts ROADMAP.md and model_registry.json (0.9459). One of them is wrong.

3. **AI_PROBLEMS.md "1 unfixed issue" header** → With #14's fix, there should be 0 unfixed issues, or the header needs updating.

4. **ROADMAP.md "10 models"** → Should be updated to reflect 19 model classes.

5. **RESEARCH_FINDINGS.md** → Consider downgrading to OUTDATED or updating. The content is from 3 July and many findings have been addressed by Sprint NEXT.

6. **3 archive files missing ARCHIVED banners** → `EXTERNAL_AUDITOR_PROMPT.md`, `SECOND_WAVE_PROMPT.md`, `External Auditor Response.md` lack status banners.

---

## Verdict

**NEEDS ATTENTION**

Two P0 contradictions between CURRENT docs need immediate resolution. Three P1-P2 stale information items should be updated in the next maintenance pass.

| Priority | Action Item | Owner |
|----------|-------------|-------|
| 🔴 P0 | Fix AI_PROBLEMS.md #14 status (WON'T FIX → FIXED) | Commander |
| 🔴 P0 | Fix ROC-AUC in MVP_SCOPE.md (0.9409 → 0.9459) | Commander |
| 🟡 P1 | Update model count in ROADMAP.md (10 → 19) | Commander |
| 🟡 P1 | Downgrade or update RESEARCH_FINDINGS.md | Commander |
| 🟢 P2 | Add ARCHIVED banners to 3 archive files | Commander |
| 🟢 P2 | Add review endpoints to ROADMAP API table | Commander |
