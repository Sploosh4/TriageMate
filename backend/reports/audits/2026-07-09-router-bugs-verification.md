# Router Bug Verification Audit

**Date:** 2026-07-09
**Scope:** Verify 6 critical/medium/high bugs reported by Phase B strike swarm
**Performed by:** auditor
**Pre-flight:** No scripts needed — file-only verification audit

## Results Summary

| Bug | Severity | Status |
|-----|----------|--------|
| Bug 1: clear_all_findings column count mismatch | CRITICAL | ✅ CONFIRMED |
| Bug 2: asset_registry_json stores [] | MEDIUM | ✅ CONFIRMED |
| Bug 3: NVD patch_available defaults to True on failure | HIGH | ✅ CONFIRMED |
| Bug 4: cisa_kev/cwe_class missing from build_feature_vector | HIGH | ✅ CONFIRMED |
| Bug 5: Queue sort const reassignment | CRITICAL | ✅ CONFIRMED |
| Bug 6: Auth page-reload loop | CRITICAL | ✅ CONFIRMED |

**Pass:** 0 | **Fail:** 6 | **Skipped:** 0

---

## Bug 1: clear_all_findings column count mismatch ✅ CONFIRMED

**Severity:** CRITICAL

**File:** `backend/routers/ingest.py`, lines 767-825 (`clear_all_findings` endpoint)

**Evidence:**

The `INSERT INTO resolved_vulnerabilities (...)` column list has **65 columns**, but the `SELECT ... FROM vulnerabilities` subquery returns **66 values**.

The mismatch is at the `security_context_contribution` column:

| Position | INSERT column list (65 cols) | SELECT value list (66 vals) |
|----------|------------------------------|-----------------------------|
| 28 | `patch_remediation_contribution` | `patch_remediation_contribution` |
| 29 | `ml_exploitation_contribution` | `ml_exploitation_contribution` |
| 30 | `tier_1_features` | **`security_context_contribution`** |
| 31 | `epss_substituted` | `tier_1_features` |
| ... | ... | shifted by 1 |

**INSERT** (line 778-782):
```sql
cvss_contribution, epss_contribution,
asset_criticality_contribution, exposure_contribution,
patch_remediation_contribution, ml_exploitation_contribution,
tier_1_features,
epss_substituted, epss_substituted_value,
```
**SELECT** (lines 806-810):
```sql
cvss_contribution, epss_contribution,
asset_criticality_contribution, exposure_contribution,
patch_remediation_contribution, ml_exploitation_contribution, security_context_contribution,
tier_1_features,
epss_substituted, epss_substituted_value,
```

The INSERT is missing `security_context_contribution` entirely. The SELECT returns it between `ml_exploitation_contribution` and `tier_1_features`, causing all subsequent columns to shift by one and the query to **fail at runtime** with a column count mismatch (65 columns / 66 values).

**Impact:** The `clear_all_findings` endpoint (DEMO_MODE) is completely broken — every call will throw an SQLite error.

**Fix needed:** Add `security_context_contribution` to the INSERT column list at line 780-781, between `ml_exploitation_contribution` and `tier_1_features`.

---

## Bug 2: asset_registry_json stores [] ✅ CONFIRMED

**Severity:** MEDIUM

**File:** `backend/routers/ingest.py`, line 514

**Evidence:**

In `ingest_vulnerability()`, the INSERT for the `asset_registry_json` column hardcodes an empty array:

```python
# Line 514
json.dumps([]),
```

Meanwhile, the function does have real asset registry data available — `asset_ctx` (containing network_zone, interface_type, operating_system, role, etc.) is fetched at line 97 and its individual fields are stored in separate columns (lines 493-504). The response object `CaseViewData` also builds a real `asset_registry` list (lines 583-595), but this data is **not persisted** to the database.

**Impact:** The `asset_registry_json` database column is always `[]` regardless of actual asset data, making it useless for downstream consumers (review queue, audit trail, data exports).

**Fix needed:** Replace `json.dumps([])` with a dict or list built from `asset_ctx` (and/or the response asset_registry data). For example:
```python
json.dumps({
    "network_zone": asset_ctx.get("network_zone", ""),
    "interface_type": asset_ctx.get("interface_type", ""),
    "operating_system": asset_ctx.get("operating_system", ""),
    "role": asset_ctx.get("role", ""),
    ...
})
```

---

## Bug 3: NVD patch_available defaults to True on failure ✅ CONFIRMED

**Severity:** HIGH

**File:** `backend/integrations/nvd.py`, line 261

**Evidence:**

When `_fetch_cve_data()` returns an empty dict (NVD API unreachable, times out, or returns no data), `get_nvd_data()` returns a fallback result with `patch_available: True`:

```python
# Lines 253-265
if not raw:
    logger.warning("NVD returned no data for %s — enrichment will be empty", cve_id)
    result = {
        "cwe_class": "",
        "nvd_reference_count": 0,
        "vulnerability_age_days": 0,
        "cvss_exploitability_sub": 0.0,
        "cvss_impact_sub": 0.0,
        "patch_available": True,       # <--- LINE 261
        "references_raw": [],
    }
```

This is the opposite of a safe default. When we know nothing about the CVE, assuming a patch is **available** is misleading — it means the scoring engine reduces the priority score for CVEs where we have zero patch information. The correct safe default when data is unavailable should be `False` (or `None` to signal unknown).

Compare with the successful NVD parse path at lines 286-294, where `patch_available` is correctly derived from NVD reference tags via `_has_patch_reference(refs)`.

**Impact:** When NVD API is down, every ingested CVE gets `patch_available: True`, artificially lowering scores and potentially causing false auto-resolutions.

**Fix needed:** Change line 261 from `"patch_available": True` to `"patch_available": False`.

---

## Bug 4: cisa_kev/cwe_class missing from build_feature_vector ✅ CONFIRMED

**Severity:** HIGH

**File:** `backend/ingest_helpers.py` (lines 442-509) and `backend/ml/xgboost_predictor.py` (lines 218-245)

**Evidence:**

The `build_feature_vector()` function returns a dict (lines 442-509) with **44 keys**. Keys `"cisa_kev"` and `"cwe_class"` are **not present** in this dict.

Meanwhile, `_tier_zero_check()` in `xgboost_predictor.py` (lines 218-245) **expects both keys**:

```python
def _tier_zero_check(features: dict) -> dict | None:
    """Pre-model check: if EPSS + CWE signal is strong enough, skip XGBoost."""
    cwe = features.get("cwe_class", "")       # line 220 — always ""
    epss = features.get("epss_score", 0.0)
    kev = features.get("cisa_kev", False)      # line 222 — always False
```

Because these keys are missing from the input dict, both fast-path checks can never trigger:

1. **KEV fast-path** (line 225): `if kev and epss >= 0.30:` — will **never** fire because `kev` defaults to `False`
2. **CWE-stratified EPSS threshold** (line 235): `CWE_EPSS_THRESHOLDS.get(cwe, DEFAULT_EPSS_THRESHOLD)` — will **always** return `DEFAULT_EPSS_THRESHOLD` (0.84) because `cwe` defaults to `""`, not in the map

The `cwe_class` value **is computed** in `build_feature_vector()` (line 424) and stored in local variable `cwe_class`, but it is **never added to the returned dict**.

The `cisa_kev` value **is available** on the `payload` object (`payload.cisa_kev`) and is used in the `_synthetic_internet_scan` call (line 432-433), but it is **never added to the returned dict**.

**Impact:** The XGBoost model is needlessly invoked for every single CVE, even CISA-KEV entries with high EPSS that should short-circuit to `routing: "escalated"` at ~95% exploitation probability. This adds ~50-100ms of inference latency per ingest and bypasses the designed fast-path optimization.

**Fix needed:** Add `"cisa_kev"` and `"cwe_class"` keys to the returned dict in `build_feature_vector()` (around line 442 in `ingest_helpers.py`):
```python
"cisa_kev": payload.cisa_kev if hasattr(payload, "cisa_kev") else False,
"cwe_class": cwe_class,
```

---

## Bug 5: Queue sort const reassignment ✅ CONFIRMED

**Severity:** CRITICAL

**File:** `frontend/js/components/queue.js`, lines 62-72

**Evidence:**

The `sortRows` function declares `va` and `vb` with `const`, then attempts to reassign them:

```javascript
function sortRows(rows, column, direction) {
  return rows.slice().sort(function(a, b) {
    const va = a[column];            // line 64 — const declaration
    const vb = b[column];            // line 65 — const declaration
    if (typeof va === 'string') va = va.toLowerCase();   // line 66 — REASSIGNMENT
    if (typeof vb === 'string') vb = vb.toLowerCase();   // line 67 — REASSIGNMENT
    if (va === vb) return 0;
    const cmp = va < vb ? -1 : 1;
    return direction === 'asc' ? cmp : -cmp;
  });
}
```

In JavaScript, `const` prevents reassignment of the binding. Lines 66-67 will throw a `TypeError: Assignment to constant variable.` whenever the sorted column contains string values (e.g., hostname, vulnerability ID, tier).

**Impact:** The entire queue sort is broken for string columns. Sorting by hostname, vulnerability ID, tier, or detection reason will crash with an uncatchable TypeError in the `Array.sort()` comparator, leaving the queue unsorted.

**Fix needed:** Change `const` to `let` on lines 64-65:
```javascript
let va = a[column];
let vb = b[column];
```

---

## Bug 6: Auth page-reload loop ✅ CONFIRMED

**Severity:** CRITICAL

**File:** `frontend/js/app.js` (lines 43-48), `frontend/js/components/auth.js` (lines 84-87, 217-237), `frontend/js/api.js` (lines 25-42)

**Evidence:**

The page-reload loop is a chain of three interacting issues:

### Step 1: `init()` doesn't stop when auth is required

In `app.js` lines 43-48:
```javascript
async function init() {
  // First, check auth status. If auth is required and user is not logged in,
  // initAuth will show the login modal and we stop here.
  if (typeof initAuth === 'function') {
    await initAuth();
  }
  // ... continues to /api/health, fetchQueue(), fetchMetrics() — NO EARLY RETURN
```

The comment says "we stop here" but there's **no early return**. `initAuth()` just shows the login modal and returns normally.

### Step 2: `initAuth()` returns without blocking

In `auth.js` lines 217-237, when auth is required and the user is not authenticated, `initAuth()` wires the login UI, shows the modal, sets `AUTH_LOADED = true`, and **returns normally** — it does not throw, loop, or signal `init()` to stop.

### Step 3: 401 in data fetch triggers `logout()` → `location.reload()`

In `api.js` lines 25-42, `_authFetch` has a 401 handler:
```javascript
if (res.status === 401 && typeof refreshToken === 'function') {
    try {
      await refreshToken();
      ...
    } catch (refreshErr) {
      if (typeof logout === 'function') {
        logout();    // <-- calls location.reload()
      }
      throw refreshErr;
    }
}
```

### The loop:
1. Page loads → `init()` runs
2. `initAuth()` detects auth required, user not logged in → shows login modal → returns
3. `init()` **continues** → calls `fetchQueue()`, `fetchMetrics()`
4. `fetchQueue()` → `_authFetch('/api/queue')` → no token → backend returns 401
5. `_authFetch` catches 401 → tries `refreshToken()` → fails (no refresh token)
6. `_authFetch` calls `logout()` → `_clearTokens()` + **`location.reload()`** (auth.js line 86)
7. **Page reloads → GOTO step 1 → INFINITE RELOOP**

The user sees the login modal flash briefly before the page reloads endlessly. They can never log in because the reload happens before they can interact with the modal.

**Impact:** Any deployment where `auth_required` is `true` in the health endpoint is completely unusable — the page enters an infinite reload loop on first load.

**Fix needed:** Add an early return in `app.js` `init()` after `await initAuth()` when auth is required but the user is not authenticated. For example:
```javascript
if (typeof initAuth === 'function') {
    await initAuth();
}
if (typeof AUTH_REQUIRED !== 'undefined' && AUTH_REQUIRED && !isAuthenticated()) {
    return; // stop — login modal is displayed, wait for user action
}
```

---

## Verdict

**FAIL** — 0 passed, 6 confirmed, 0 skipped

All six bugs reported by the Strike swarm are **confirmed**. The three CRITICAL bugs (1, 5, 6) will cause runtime crashes. The two HIGH bugs (3, 4) silently degrade pipeline correctness. The MEDIUM bug (2) causes data loss.

### Fix assignments by severity:

| Bug | Severity | Assigned to | Fix description |
|-----|----------|-------------|-----------------|
| Bug 1: clear_all_findings column mismatch | CRITICAL | Strike | Add `security_context_contribution` to INSERT column list in `clear_all_findings()` |
| Bug 5: Queue sort const reassignment | CRITICAL | Strike | Change `const va/vb` to `let va/vb` in `queue.js` |
| Bug 6: Auth page-reload loop | CRITICAL | Strike | Add early return in `init()` after `initAuth()` when not authenticated |
| Bug 3: NVD patch_available defaults to True on failure | HIGH | Strike | Change default to `False` on line 261 of `nvd.py` |
| Bug 4: cisa_kev/cwe_class missing from build_feature_vector | HIGH | Strike | Add `"cisa_kev"` and `"cwe_class"` to returned dict in `build_feature_vector()` |
| Bug 2: asset_registry_json stores [] | MEDIUM | Strike | Replace `json.dumps([])` with actual asset context data |
