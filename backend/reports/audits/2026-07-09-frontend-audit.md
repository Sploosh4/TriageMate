# Frontend Click-to-Open Case Audit

**Date:** 2026-07-09
**Scope:** Click-to-open-case flow: HTML structure, JS syntax/logic, CSS interaction blockers, backend API endpoints
**Performed by:** auditor
**Pre-flight:** 9/9 JS files pass `node --check` syntax verification. Backend database has 7 demo rows with all required columns. `sentence_transformers` not required for this audit.

## Results

| Check | Status |
|---|---|
| HTML structure (ids, script order, elements) | PASS — all correct |
| JS syntax (9 files) | PASS — 9/9 pass `node --check` |
| CSS interaction blockers | PASS — no overlays, `pointer-events: none` only on demo watermark (harmless) |
| Backend `GET /api/queue` | PASS — returns data correctly |
| Backend `GET /api/case/{id}` | **FAIL** — crashes with AttributeError |
| Backend case model serialization | PASS — all 7 rows serialize correctly after fix |
| Frontend network context field names | **FAIL** — snake_case vs camelCase mismatch |

## Findings

### FINDING 1 (CRITICAL — BLOCKER): `sqlite3.Row` has no `.get()` method

**File:** `backend/routers/cases.py`, lines 81–82
**Severity:** CRITICAL — prevents case view from opening entirely

The `_row_to_case_view()` function accesses database row columns using `.get()`:
```python
telemetry = _parse_json_column(r.get("telemetry_json"), default=None)
network_context = _parse_json_column(r.get("network_context_json"), default=None)
```

`r` is a `sqlite3.Row` object — it does NOT support `.get()`. Only bracket notation `r["key"]` works. Calling `.get()` raises:
```
AttributeError: 'sqlite3.Row' object has no attribute 'get'
```

**Impact:** When any queue row is clicked, the frontend calls `GET /api/case/{id}`, the backend crashes with a 500 error, `_authFetch` throws `"Request failed: 500"`, and `showCase()` catches it silently. The user sees nothing happen.

**Fix applied:** Changed both `.get()` calls to bracket notation:
```python
telemetry = _parse_json_column(r["telemetry_json"], default=None)
network_context = _parse_json_column(r["network_context_json"], default=None)
```

Verification: All 7 demo rows now serialize through `CaseResponse` successfully.

---

### FINDING 2 (MEDIUM): Network context fields use wrong property names

**File:** `frontend/js/components/caseView.js`, lines 204–216
**Severity:** MEDIUM — network context section shows all zeros / fallback values

The `renderSecurityContext()` function accesses `NetworkContextData` fields using `snake_case` names, but Pydantic serializes them with `camelCase` aliases.

The backend model:
```python
class NetworkContextData(BaseModelConfig):
    zone: str = ""           # → "zone" (no change)
    zone_display: str = ""   # → "zoneDisplay"
    peer_count: int = 0      # → "peerCount"
    internet_facing_peers: int = 0  # → "internetFacingPeers"
    dc_peers: int = 0        # → "dcPeers"
    blast_radius_score: float = 0.0 # → "blastRadiusScore"
    data_source: str = "heuristic"  # → "dataSource"
```

Serialized example from live data:
```json
{
  "zone": "dmz",
  "zoneDisplay": "DMZ (Health — External)",
  "peerCount": 34,
  "internetFacingPeers": 19,
  "dcPeers": 0,
  "blastRadiusScore": 0.449,
  "dataSource": "synthetic_assets"
}
```

Affected frontend lines:

| Line | Old (snake_case) | Fixed (camelCase) |
|---|---|---|
| 204 | `networkCtx.blast_radius_score` | `networkCtx.blastRadiusScore` |
| 205 | `networkCtx.blast_radius_score` | `networkCtx.blastRadiusScore` |
| 208 | `networkCtx.zone_display` | `networkCtx.zoneDisplay` |
| 209 | `networkCtx.peer_count` | `networkCtx.peerCount` |
| 210 | `networkCtx.internet_facing_peers` | `networkCtx.internetFacingPeers` |
| 211 | `networkCtx.dc_peers` | `networkCtx.dcPeers` |
| 216 | `networkCtx.data_source` | `networkCtx.dataSource` |

**Fix applied:** All 7 accesses updated to camelCase.

---

### FINDING 3 (LOW): Compliance badge text format mismatch

**File:** `frontend/js/components/queue.js`, line 130
**Severity:** LOW — compliance badge shows "OFFICIAL Sensitive" instead of "CAT 4"

The frontend expects compliance strings in `"Category N"` format:
```javascript
r.compliance.replace('Category ', 'CAT ')
```

But the backend now sends WAICP classification strings from the database:
```python
compliance_str = r["data_classification"] or "Category 1"
# Values: "OFFICIAL Sensitive" → cat 4, "OFFICIAL" → cat 2
```

The `.replace('Category ', 'CAT ')` call does nothing on "OFFICIAL" strings, so the badge displays the raw classification instead of a formatted label.

**Suggested fix:** Map compliance category number to display label:
```javascript
const catLabels = { 2: 'CAT 2', 4: 'CAT 4' };
r.compliance.replace('Category ', 'CAT ')  // change to:
catLabels[r.complianceCategory] || r.compliance
```

OR update the backend to send display-friendly compliance strings in the queue response. This is cosmetic — does not affect click-to-open.

---

### FINDING 4 (INFO): `_parse_json_column` returns `[]` when `default=None`

**File:** `backend/routers/cases.py`, lines 49–55
**Severity:** INFO — no runtime impact due to Python falsy handling

```python
def _parse_json_column(val, default=None):
    if val is None:
        return default if default is not None else []
```

When both `val` and `default` are `None`, the function returns `[]` (empty list) instead of `None`. The callers compensate:
```python
telemetry=telemetry if telemetry else None,          # [] → None (falsy)
network_context=NetworkContextData(**network_context) if network_context else None,
```

This works because empty lists are falsy, but the API is confusing. Consider fixing to:
```python
return default if default is not None else None
```
(Not changed — out of scope for click-to-open fix.)

## Verdict

**PASS — Critical and Medium bugs fixed.** 3 bugs found, 2 fixed (1 Critical, 1 Medium), 1 Low deferred.

| Severity | Count | Fixed |
|---|---|---|
| CRITICAL | 1 | ✅ Fixed: `r.get()` → `r[]` in cases.py |
| MEDIUM | 1 | ✅ Fixed: snake_case → camelCase in caseView.js |
| LOW | 1 | ❌ Deferred: compliance badge label mismatch |
| INFO | 1 | ❌ Deferred: `_parse_json_column` minor quirk |

**What was needed to make the tests runnable:** N/A — all tests ran without external dependencies.

**Root cause of click-to-open failure:** The `sqlite3.Row.get()` call has likely been present since Sprint 17 when `telemetry_json` and `network_context_json` columns were added. The ReferenceError fix you applied earlier was necessary but insufficient — the backend crash was the actual blocker.
