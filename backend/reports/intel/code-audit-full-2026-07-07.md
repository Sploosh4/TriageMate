# Full Codebase Comment Audit

**Date:** 2026-07-07
**Requested by:** Commander (full sprint quality gate)
**Sources consulted:** ripgrep across all `.py`, `.js`, `.html` files; previous audit reports from Team A and Team B; manual file readings

---

## Summary

| Category | Status |
|---|---|
| PRIS Act → WAICP (check all files) | ✅ **CLEAN** — zero occurrences in code |
| Wrong dimension counts (4/5 vs 6) | ✅ **CLEAN** — all references correctly say "6" |
| Wrong feature counts (37/68/69) | ⚠️ **1 docstring** — `ingest_helpers.py` internal contradiction (42 vs 35+1) |
| Category 1–4 old terminology in **comments** | ⚠️ **1 docstring mismatch** — `cmdb.py` says "OFFICIAL" but code defaults to "Category 1" |
| Stale version strings (0.2.0/0.3.0) | ⚠️ **10 occurrences** — User-Agent headers stale (current version 2.5.0) |
| TODO/FIXME/HACK in code | ✅ **CLEAN** — zero actionable markers |
| Dead file/function references | ✅ **CLEAN** — zero occurrences |
| `docker-compose` (hyphenated V1) | ✅ **CLEAN** — `justfile` uses `docker compose` (V2) |
| Sprint references | ✅ **CLEAN** — zero occurrences in code |
| Category 1–4 in **code** (not comments) | ⚠️ **8+ lines** — old terminology in mapping keys, variable names, defaults |
| Previous audit findings resolved | ✅ **2 of 2 comment issues from Team A/B re-checked and confirmed** |

---

## Verdict: 2 COMMENT ISSUES + 2 ADJACENT CODE ISSUES

The codebase comments are **mostly clean**. The previous audits caught and fixed the major issues (PRIS Act strings in docs, dimension counts, docker-compose commands). Two real comment problems remain, plus some stale version strings and legacy Category terminology in code paths.

---

## Issues Found

### Issue 1 — Docstring contradiction: `ingest_helpers.py` line 377

**Type:** Comment (docstring)
**Severity:** Low
**Previously flagged:** ✅ Yes — Finding 1 in Team A audit. **Not yet fixed.**

```python
def build_feature_vector(payload, mission_tags: dict, tier_0_result: dict) -> dict:
    """Build the full 42-key feature dict (35 tabular + description) for the Tier 1 XGBoost model.
```

**Problem:** The parenthetical `(35 tabular + description)` implies 36 keys, but the docstring header claims 42 keys. The function actually returns 42 keys total:
- 35 keys are tabular inputs to XGBoost
- 1 key (`description`) is SBERT text input
- 6 keys are enrichment/metadata NOT consumed by the model: `cvss_score`, `osv_fixed_versions`, `osv_package`, `osv_ecosystem`, `internet_scan_detected`, `threat_intel_status`

The parenthetical is misleading because it doesn't explain what the other 6 keys do.

**Suggested fix:**
```
"""Build the full 42-key feature dict for the Tier 1 XGBoost model.
   - 35 keys: tabular features consumed by XGBoost (matches xgboost_predictor.py)
   - 1 key (description): SBERT text encoding input
   - 6 keys: enrichment/metadata (cvss_score, osv_*, internet_scan_detected, threat_intel_status)
"""
```

---

### Issue 2 — Docstring/code mismatch: `cmdb.py` line 169

**Type:** Comment (docstring)
**Severity:** Low
**Previously flagged:** ⚠️ Partially — Team B Finding 2 noted the `Category 1` default but didn't flag the docstring specifically.

```python
def lookup_data_classification(hostname: str) -> str:
    """Look up the WAICP data classification for an asset.

    Delegates to the current CMDB provider.
    Defaults to OFFICIAL for unknown hosts.
    """
    ctx = get_asset_context(hostname)
    return ctx.get("data_classification", "Category 1")
```

**Problem:** The docstring claims the function "Defaults to **OFFICIAL** for unknown hosts" — correct WAICP terminology. But the actual code defaults to `"Category 1"` — old PRIS Act terminology on line 175. If a host is unknown and the CMDB returns no `data_classification` field, the function returns the old term instead of "OFFICIAL".

**Suggested fix:** Change line 175 to `"OFFICIAL"` to match the docstring:
```python
return ctx.get("data_classification", "OFFICIAL")
```

---

### Issue 3 — Stale User-Agent version strings (10 occurrences)

**Type:** Code (operational strings in HTTP headers)
**Severity:** Informational
**Previously flagged:** No

The application reports version `2.5.0` (confirmed in `main.py` line 108 and `test_health.py` line 42). But 10 User-Agent strings across 4 files still use old version numbers:

| File | Lines | Version |
|---|---|---|
| `backend/integrations/nvd.py` | 101 | `TriageMate/0.2.0` |
| `backend/ml/fetch_epss_data.py` | 46 | `TriageMate/0.2.0` |
| `backend/scripts/fetch_nvd_corpus.py` | 286, 376, 498 | `TriageMate/0.3.0` |
| `backend/scripts/refresh_caches.py` | 333, 560 | `TriageMate/0.2.0` |
| `backend/scripts/refresh_caches.py` | 370, 441 | `TriageMate/0.3.0` |
| `backend/scripts/build_cwe_hierarchy.py` | 39 | `TriageMate/0.3.0` |

**Impact:** Minimal — User-Agent strings are advisory only. But a developer looking at these might think the code is outdated. Consider centralising the version string (e.g., `__version__` in `main.py`) or updating to `TriageMate/2.5.0`.

**Suggested fix:** Either:
- Replace all with `TriageMate/2.5.0`, or
- Import a shared version constant (e.g., `from main import APP_VERSION`) for single-source-of-truth.

---

### Issue 4 — "Category 1" old PRIS Act terminology in code (8+ lines)

**Type:** Code (mapping keys, default fallbacks, variable names)
**Severity:** Low
**Previously flagged:** ✅ Yes — Findings 1 & 2 in Team B audit. **Not yet fixed.**

These are **not comments** — they are operational code paths. They are included here for completeness since the audit spans the full codebase:

**Mapping keys using old terminology:**
| File | Line | Current | Suggested |
|---|---|---|---|
| `backend/ml/xgboost_predictor.py` | 218 | `"Category 1": 1` | `"OFFICIAL": 1` |
| `backend/scripts/build_training_corpus.py` | 186 | `"Category 1": 1` | `"OFFICIAL": 1` |
| `backend/analysis/feature_parity_check.py` | 151 | `"Category 1": 1` | `"OFFICIAL": 1` |
| `backend/analysis/feature_parity_check.py` | 166 | `"Category 1": 1` | `"OFFICIAL": 1` |
| `backend/analysis/feature_parity_check.py` | 215 | `"Category 1"` | `"OFFICIAL"` |
| `backend/integrations/cmdb.py` | 175, 219 | `"Category 1"` | `"OFFICIAL"` |
| `backend/routers/queue.py` | 44 | `"Category 1"` | `"OFFICIAL"` |
| `backend/routers/cases.py` | 29 | `"Category 1"` | `"OFFICIAL"` |
| `backend/ml/pretier_features.py` | 127 | `CATEGORY_4_KEYWORDS` | `SENSITIVE_KEYWORDS` |
| `backend/ml/pretier_features.py` | 188 | `CATEGORY_2_KEYWORDS` | `OFFICIAL_KEYWORDS` |
| `backend/ml/pretier_features.py` | 207 | `CATEGORY_1_KEYWORDS` | `UNCLASSIFIED_KEYWORDS` |

**Impact:** Low. These are internal mapping keys, not user-facing. The numbers (1, 2, 4) are the actual ordinal values; the string key is only reached if upstream data still uses old terminology. The WAICP docstring in `pretier_features.py` line 309–310 correctly uses WAICP terminology.

**Note:** Fixing these requires care because the string `"Category 1"` is a valid fallback value that `"OFFICIAL"` in the mappings must still handle (since the training corpus may contain old term strings).

---

## Previously Flagged Issues — Resolution Status

| Finding | Source | Status |
|---|---|---|
| `ingest_helpers.py` docstring contradiction (42 vs 35+1) | Team A Finding 1 | ⚠️ **NOT FIXED** — still present at line 377 |
| `queue.py` / `cases.py` Category 1 default code path | Team A Finding 2 | ⚠️ **NOT FIXED** — still uses `"Category 1"` |
| `cmdb.py` docstring says OFFICIAL but returns Category 1 | This audit | ⚠️ **NOT FIXED** |
| Category 1–4 variable names in `pretier_features.py` | Team B Finding 1 | ⚠️ **NOT FIXED** |
| Mixed terminology in CMDB stub | Team B Finding 2 | ⚠️ **NOT FIXED** — `_stub_lookup` returns `"Category 1"` |
| Stale User-Agent version strings | This audit | ⚠️ **NOT FIXED** |
| PRIS Act strings in active docs | Team A / Team B / Bookkeeping | ✅ **FIXED** — zero in code |
| `docker-compose` (hyphenated) commands | Bookkeeping | ✅ **FIXED** — `justfile` uses V2 |
| Wrong dimension counts | Previous audits | ✅ **FIXED** |
| CWE classifier deprecation comment | Previous audits | ✅ **FIXED** — correct |
| PCA removal documentation | Previous audits | ✅ **FIXED** — correct |

---

## Recommendations

1. **Fix `ingest_helpers.py` line 377** — Clarify the docstring to explain the 42-key breakdown (35 tabular + 1 description + 6 enrichment). Low effort, high clarity.

2. **Fix `cmdb.py` line 175** — Change `"Category 1"` default to `"OFFICIAL"` to match the docstring and WAICP terminology. This is a one-character change that eliminates an inconsistency.

3. **Update User-Agent versions** — Centralise version string (e.g., `backend/version.py` with `__version__ = "2.5.0"`) and import it in all HTTP-calling modules. Or at minimum do a bulk replace to `TriageMate/2.5.0`.

4. **Normalise "Category 1" → "OFFICIAL"** across all mapping keys and defaults (Issue 4 above). This is a wider codebase refactor touching 11+ lines in 6 files. Consider doing it as a dedicated change with attention to downstream consumers (training corpus may have old string values).

5. **Re-run after fixes** — The two docstring fixes (Issues 1, 2) are quick wins. The version string and Category terminology changes are larger but should be tracked in the next sprint.
