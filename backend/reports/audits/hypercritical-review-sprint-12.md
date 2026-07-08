# Hypercritical Review — Sprint 12 Plan

**Date:** 8 July 2026
**Tools used:** db_sqlite, grep, glob, filesystem, read

---

## Summary

The sprint plan survived hypercritical review with **one significant refinement** to Item 2. All other assumptions held.

| Check | Result |
|---|---|
| Assumption 1: SKILL.md missing `models` | ✅ **Confirmed** — line 34: `(auth, cases, ingest, queue)` |
| Assumption 2: No other stale router lists | ✅ **Confirmed** — only 1 match across all skill files |
| Assumption 3: EPSS needs assessment | ⚠️ **Refined** — system is mature, real blocker is data |
| Assumption 4: `main.py` wires models router | ✅ **Confirmed** — line 169: `app.include_router(models_router.router)` |
| Assumption 5: DB is uninitialized | ✅ **Confirmed** — `triagemate.db` exists but is 0 bytes |
| Assumption 6: EPSS cache exists | ✅ **Confirmed** — 20MB, ~344K CVE records from FIRST.org |

---

## Detailed Findings

### 1. SKILL.md Router List

```
Found 1 match in backend-engineering/SKILL.md:
  Line 34: - `backend/routers/` — API endpoint routers (auth, cases, ingest, queue)
```

Only occurrence. No other skill files reference this stale list. Fix is a single-line edit.

### 2. EPSS Substitution — Major Refinement

**What exists today (already mature):**

| Component | File | Status |
|---|---|---|
| Hybrid ML + rule engine (674 lines) | `epss_substitutor.py` | ✅ Deployed |
| v1 model (22-feature) | `epss_model.pkl` | ✅ On disk |
| v2 model (37-feature) | `epss_model_v2.pkl` | ✅ On disk |
| v3 model (37-feature, real EPSS data) | `epss_model_v3.pkl` | ✅ On disk, preferred |
| v3 training pipeline | `train_epss_v3.py` | ✅ Uses real FIRST.org EPSS cache |
| EPSS data fetcher | `fetch_epss_data.py` | ✅ Downloads real scores |
| EPSS evaluation | `analysis/epss_eval.py` | ✅ KEV prediction baseline analysis |
| `just train-epss` command | `justfile` line 106 | ✅ |
| `just audit-epss` command | `justfile` line 128 | ✅ |
| Real EPSS cache (20MB, ~344K CVEs) | `backend/data/epss_cache.json` | ✅ |

**The real gap (not code — data):**

The v3 training pipeline (`train_epss_v3.py`) generates **synthetic** training data:
- Picks a random real CVE baseline from the EPSS cache
- Assigns random agency, CWE, exploit maturity
- Applies hardcoded sector multipliers (health = 1.1x, police = 1.1x)
- Adds Gaussian noise for realism

This is the "sector-weighted exploitation data" gap: **no real sector-specific incident data is used.** The model learns to replicate the rule engine's assumptions rather than actual sector exploitation patterns.

**WASOC references exist** in:
- `integrations/tenable.py` — WASOC Tenable.sc/io integration
- `integrations/advisories.py` — WASOC advisory feed (stub)
- `seed_data.py` — WASOC threat intel feed referenced in demo rows
- `epss_substitutor.py` — "sector-specific threat intelligence" in docstring

### 3. Database State

`triagemate.db` exists at root but is 0 bytes. The SQLite MCP tools find no tables. This is not a blocker for this sprint (no DB operations needed).

### 4. Models Router

Confirmed wired in `main.py:169`: `app.include_router(models_router.router)`. The router file `routers/models.py` exists with 3 endpoints.

---

## Plan Modifications Made

| Item | Change | Reason |
|---|---|---|
| Item 2 Description | Added pre-review finding about EPSS maturity | Prevents the intel agent from starting from scratch |
| Item 2 Scope | Narrowed to specific files, added WASOC check | Focuses on the real gap (data, not code) |
| Item 2 Expected output | Added concrete structure with current state inventory | Ensures the report acknowledges existing infrastructure |
| Item 2 NOT in scope | Added "Re-evaluating model performance metrics" | Keeps scope tight — no analysis pipeline execution |

---

## What Was NOT Changed

Items 1 and 3 were validated and require no modification:
- Item 1 (SKILL.md fix): 15 min, single-line edit, trivially correct
- Item 3 (Bookkeeping): Standard AGENTS.md requirement, no assumptions to verify

---

**Verdict: PLAN ACCEPTED with refined Item 2 scope. Ready for execution.**
