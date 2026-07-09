# Frontend CSS/JS Critical Bugs Verification

**Date:** 2026-07-09
**Scope:** Verify Phase B strike swarm frontend bug claims — 5 bugs across CSS, HTML, JS
**Performed by:** auditor
**Pre-flight:** Read-only file audit (no analysis scripts required)

## Results

| Bug | Severity | Status | Pass |
|-----|----------|--------|------|
| 1. Panel 5 CSS undefined variables | CRITICAL | ✅ CONFIRMED | FAIL |
| 2. Duplicate back-bar IDs | HIGH | ✅ CONFIRMED | FAIL |
| 3. Duplicate event listener accumulation | MEDIUM | ✅ CONFIRMED | FAIL |
| 4. Drift dashboard null object access | HIGH | ✅ CONFIRMED | FAIL |
| 5. Demo controls skip auth headers | MEDIUM | ✅ CONFIRMED | FAIL |

**5 passed, 0 failed, 0 skipped**

---

## Bug 1: Security Context Panel CSS Undefined Variables (CRITICAL)

**Verdict:** ✅ CONFIRMED — All 9 claimed variable names are undefined.

### Variables used in Panel 5 but NOT defined in `:root` or `[data-theme="dark"]`

| Variable | Defined in `:root`? | Defined in `[data-theme="dark"]`? | Lines used in Panel 5 |
|----------|---------------------|-----------------------------------|-----------------------|
| `--surface` | ❌ Missing | ❌ Missing | 1842 |
| `--surface-alt` | ❌ Missing | ❌ Missing | 1877, 1934, 1992 |
| `--text-muted` | ❌ Missing | ❌ Missing | 1871, 1903, 1928, 1952, 1959 |
| `--danger` | ❌ Missing | ❌ Missing | 1886, 1942, 1989 |
| `--warning` | ❌ Missing | ❌ Missing | 1878, 1890, 1991 |
| `--success` | ❌ Missing | ❌ Missing | 1947, 1990 |
| `--info` | ❌ Missing | ❌ Missing | 1894 |
| `--mono` | ❌ Missing | ❌ Missing | 1919 |
| `--text` | ❌ Missing | ❌ Missing | 1411 (`model-info-value`), 1992 |

**Evidence:**

- `:root` block: lines 1–89 of `frontend/css/triagemate.css`
- `[data-theme="dark"]` block: lines 92–157
- Panel 5 section: lines 1840–1999

The `:root` block defines similar-named variables (e.g., `--success-bg`, `--warning-text`, `--warning-border`) but **none** have the exact names `--surface`, `--surface-alt`, `--text-muted`, `--danger`, `--warning`, `--success`, `--info`, `--mono`, or `--text`.

These fall back to `var()` default (nothing) → silent `initial` values — likely invisible/transparent backgrounds and black text.

**Note:** `--text` is also used at line 1411 (`.model-info-value { color: var(--text); }`) in the drift dashboard section, outside Panel 5.

**Required action:** Add all 9 variables to both `:root` and `[data-theme="dark"]` blocks.

---

## Bug 2: Duplicate `id="back-bar"` (HIGH)

**Verdict:** ✅ CONFIRMED — Exactly 3 elements with the same ID.

| Occurrence | Line | Screen |
|------------|------|--------|
| 1 | 116 | `#screen-case` (Case View) |
| 2 | 160 | `#screen-review` (Review Queue) |
| 3 | 170 | `#screen-drift` (Drift Dashboard) |

**Evidence:** `frontend/index.html` lines 116, 160, 170.

```html
<!-- Line 116 -->
<div id="back-bar">
<!-- Line 160 -->
<div id="back-bar">
<!-- Line 170 -->
<div id="back-bar">
```

Duplicate `id` attributes violate the HTML spec. `document.getElementById('back-bar')` will return only the first match (line 116), so the JS cannot reliably target the back-bar in review or drift screens.

**Required action:** Use unique IDs per screen, e.g., `id="back-bar-case"`, `id="back-bar-review"`, `id="back-bar-drift"`, or use a class-based approach.

---

## Bug 3: Duplicate Event Listener Accumulation (MEDIUM)

**Verdict:** ✅ CONFIRMED — `container.addEventListener('click', ...)` accumulates on `#review-queue-container`.

### Analysis of `wireReviewEvents()` (line 171 of `reviewQueue.js`)

| Listener | Target | Persists across renders? | Accumulation risk |
|----------|--------|-------------------------|-------------------|
| `.review-row` click (line 172) | `.review-row` elements | ❌ Destroyed by `innerHTML` | No — elements are replaced each render |
| `#review-queue-container` click (line 192) | `#review-queue-container` element | ✅ YES — container persists | **YES — accumulates** |
| `#override-score-slider` input (line 205) | Slider element | ❌ Destroyed by `innerHTML` | No |
| `#review-submit-btn` click (line 213) | Button element | ❌ Destroyed by `innerHTML` | No |

**The problem:** `renderReviewQueue()` (line 42) calls `wireReviewEvents()` at line 94. `wireReviewEvents()` adds a click listener to `#review-queue-container` (line 192). Since the container element persists between renders, each call piles on another click handler. This happens:

1. On initial load: `initReviewQueue()` → `renderReviewQueue()` → `wireReviewEvents()`
2. On row expand/collapse: `wireReviewEvents()` line 178/184 → `renderReviewQueue()` → `wireReviewEvents()`
3. On case detail loaded: `loadReviewCaseDetail()` → `renderReviewQueue()` → `wireReviewEvents()`

The `.review-row` listeners (lines 172–187) are recreated each time, but since the old DOM elements are removed by `container.innerHTML = html`, those don't accumulate. Only the container listener does.

**Evidence:** Lines 189–203 of `frontend/js/components/reviewQueue.js`:
```javascript
const container = document.getElementById('review-queue-container');
if (!container) return;
container.addEventListener('click', function(e) { ... });
```

**Required action:** Use a flag or removeEventListener before adding, or use event delegation only once outside `wireReviewEvents()`.

---

## Bug 4: Drift Dashboard Null Object Access (HIGH)

**Verdict:** ✅ CONFIRMED — 4 unguarded property access paths found.

### Unguarded accesses in `driftDashboard.js`

| Line | Expression | Issue | Guard needed |
|------|-----------|-------|-------------|
| 36 | `v.metrics.training_samples` | Accesses `.metrics` on `v`. If `v.metrics` is null/undefined, crashes | `v.metrics && v.metrics.training_samples` |
| 37 | `v.metrics.roc_auc` | Same — no null check on `v.metrics` | `v.metrics && v.metrics.roc_auc != null` |
| 87 | `data.tierRouting.auto` | Accesses `.tierRouting` on `data`. If `data.tierRouting` is null/undefined, crashes | `data.tierRouting && data.tierRouting.auto` |
| 87 | `data.tierRouting.escalated` | Same | Same |
| 88–89 | `data.tierRouting.auto / esc` | Same path, used in calculation | See above |
| 96–97 | `data.tierRouting.auto / esc` | Same path, used in HTML rendering | See above |
| 126–129 | `data.featureDrift.avgCvss` etc. | Accesses `.featureDrift` on `data` without null check | `data.featureDrift && data.featureDrift.avgCvss` |

### Code evidence

Lines 36–37 (model status panel):
```javascript
var samples = v.metrics.training_samples ? v.metrics.training_samples.toLocaleString() : 'N/A';
var rocAuc = v.metrics.roc_auc != null ? v.metrics.roc_auc : 'N/A';
```
If `v.metrics` is `null` or `undefined`, both lines throw `TypeError: Cannot read properties of null/undefined`.

Lines 87–97 (tier routing panel):
```javascript
const total = data.tierRouting.auto + data.tierRouting.escalated;
const autoPct = total > 0 ? (data.tierRouting.auto / total) * 100 : 0;
const escPct = total > 0 ? (data.tierRouting.escalated / total) * 100 : 0;
```
If `data.tierRouting` is `null` or `undefined`, line 87 throws.

Lines 126–129 (feature drift table):
```javascript
html += '<div class="drift-feature-row"><span class="drift-feature-label">Avg CVSS</span><span class="drift-feature-value">' + data.featureDrift.avgCvss + '</span></div>';
```
If `data.featureDrift` is `null` or `undefined`, throws.

**Note:** Line 57 `if (!data.totalAudited || ...)` does provide some guard on `data` itself, but not on its nested objects.

**Required action:** Add optional chaining or null checks on `v.metrics`, `data.tierRouting`, and `data.featureDrift`.

---

## Bug 5: Demo Controls Skip Auth Headers (MEDIUM)

**Verdict:** ✅ CONFIRMED — All 3 API calls in `demoControls.js` use bare `fetch()` instead of `_authFetch()`.

| Line | Function | Call | Auth header? |
|------|----------|------|-------------|
| 10 | `fetchDemoScenarios()` | `fetch('/api/demo/scenarios')` | ❌ Missing |
| 16 | `generateDemoWave()` | `fetch('/api/demo/generate', { method: 'POST', ...})` | ❌ Missing |
| 26 | `clearAllFindings()` | `fetch('/api/ingest/clear', { method: 'POST' })` | ❌ Missing |

**Evidence:** `frontend/js/components/demoControls.js` lines 10, 16, 26 all use `fetch()` directly. The rest of the codebase (e.g., `reviewQueue.js` line 30, `driftDashboard.js` lines 8–9) consistently uses `_authFetch()`.

```javascript
// Line 10 — bare fetch
const res = await fetch('/api/demo/scenarios');

// Line 16 — bare fetch
const res = await fetch('/api/demo/generate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload)
});

// Line 26 — bare fetch
const res = await fetch('/api/ingest/clear', { method: 'POST' });
```

**Required action:** Replace all 3 `fetch()` calls with `_authFetch()` to include auth headers.

---

## Summary

| Bug | Status | Lines affected | File |
|-----|--------|----------------|------|
| 1. Panel 5 CSS undefined vars | ✅ CONFIRMED | 1842, 1871, 1877, 1878, 1886, 1890, 1894, 1903, 1919, 1928, 1934, 1942, 1947, 1952, 1959, 1989, 1990, 1991, 1992 | `frontend/css/triagemate.css` (also line 1411 for `--text`) |
| 2. Duplicate back-bar IDs | ✅ CONFIRMED | 116, 160, 170 | `frontend/index.html` |
| 3. Event listener accumulation | ✅ CONFIRMED | 189–203 (container listener) | `frontend/js/components/reviewQueue.js` |
| 4. Null object access | ✅ CONFIRMED | 36, 37, 87, 88, 89, 96, 97, 126, 127, 128, 129 | `frontend/js/components/driftDashboard.js` |
| 5. Demo controls skip auth | ✅ CONFIRMED | 10, 16, 26 | `frontend/js/components/demoControls.js` |

**Verdict:** FAIL — 5 bugs confirmed, 0 failed to reproduce, 0 skipped.

All 5 bugs require fixes. Priority order:
1. **CRITICAL** — Bug 1: Add missing CSS variables to `:root` and `[data-theme="dark"]` (strike agent needed)
2. **HIGH** — Bug 2: Unique IDs for back-bar (strike agent needed)
3. **HIGH** — Bug 4: Null guards in driftDashboard.js (strike agent needed)
4. **MEDIUM** — Bug 3: Remove accumulating event listener (strike agent needed)
5. **MEDIUM** — Bug 5: Use `_authFetch()` in demoControls.js (strike agent needed)
