# Frontend XSS Investigation — FE-CRIT-2 & FE-CRIT-3

**Date:** 2026-07-14
**Investigator:** Strike Team (automated code review)
**Scope:** Sprint 27 XSS audit — compliance rendering (FE-CRIT-2) and drift dashboard label XSS (FE-CRIT-3)

---

## Summary

| Bug ID | Description | Status |
|---|---|---|
| FE-CRIT-2 | Compliance rendering XSS | **Not Reproduced** |
| FE-CRIT-3 | Drift dashboard label XSS | **Not Reproduced** (with hygiene note) |

---

## FE-CRIT-2: Compliance rendering XSS

### Status: Not Reproduced

### Evidence

The compliance field is rendered in `frontend/js/components/queue.js` line 130:

```js
'<td data-label="Compliance"><span class="compliance-badge '
  + getComplianceClass(r.complianceCategory) + '">'
  + escHtml(r.compliance.replace('Category ', 'CAT '))
  + '</span></td>'
```

Two code paths were examined:

**1. Compliance text value** — passed through `escHtml()` (line 130). Safe.

```js
// escHtml defined in queue.js lines 17-21:
function escHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}
```

This is a robust HTML-escaping technique used consistently across the frontend.

**2. Compliance category in CSS class** — uses `getComplianceClass(r.complianceCategory)`:

```js
function getComplianceClass(category) {
  return 'compliance-cat' + category;  // line 13-15
}
```

The `complianceCategory` value is typed as `int` in the Pydantic model (`backend/models.py` line 103: `compliance_category: int`). The backend function `compliance_category()` in `backend/ingest_helpers.py` (line 39-45) always returns an integer. No XSS vector from integer-in-class-name.

### All innerHTML usages in compliance-related code

`grep -i 'compliance' frontend/js/` returned only:
- `queue.js`: the two lines above — both safe.

No compliance rendering exists in `caseView.js`, `reviewQueue.js`, `driftDashboard.js`, or `adminSettings.js`.

### Conclusion
The compliance rendering XSS (FE-CRIT-2) is **not present** in the current codebase. It was either never present or was fixed as part of the same Sprint 27 pass that fixed FE-CRIT-1.

---

## FE-CRIT-3: Drift dashboard label XSS

### Status: Not Reproduced (with hygiene note)

### Evidence

**Label rendering paths — all properly escaped:**

1. **Model label** (`frontend/js/components/driftDashboard.js` line 40):
   ```js
   html += '<span class="model-info-label">Deployed Model</span><span class="model-info-value">' + escHtml(v.label) + '</span></div>';
   ```
   — Uses `escHtml()`. Safe.

2. **Feature names** (driftDashboard.js line 161):
   ```js
   html += '<span class="drift-feature-label" title="' + escHtml(fname) + '">' + escHtml(fname) + '</span>';
   ```
   — Uses `escHtml()`. Safe.

3. **Date labels in tooltip** (driftDashboard.js line 78-79):
   ```js
   var label = point.date ? point.date.slice(-5) : '';
   html += '<div class="drift-bar-wrapper" title="' + label + ': ' + point.avgScore + '">';
   ```
   The `date` field comes from `DATE(resolved_at)` (SQLite → date string like `2026-07-14`). No user-controlled data path. Low risk.

**Unescaped numeric values (hygiene finding only):**

Lines 131-134 have 4 values interpolated without `escHtml()`:

```js
html += '<div class="drift-feature-row"><span class="drift-feature-label">Avg CVSS</span><span class="drift-feature-value">' + data.featureDrift.avgCvss + '</span></div>';
html += '<div class="drift-feature-row"><span class="drift-feature-label">Avg EPSS</span><span class="drift-feature-value">' + data.featureDrift.avgEpss + '</span></div>';
html += '<div class="drift-feature-row"><span class="drift-feature-label">Avg Priority</span><span class="drift-feature-value">' + data.featureDrift.avgPriority + '</span></div>';
html += '<div class="drift-feature-row"><span class="drift-feature-label">Total Audited</span><span class="drift-feature-value">' + data.totalAudited + '</span></div>';
```

Data type analysis (traced from API to DB):

| Field | Backend source | Type | XSS Risk |
|---|---|---|---|
| `avgCvss` | `round(COALESCE(AVG(cvss_score), 0), 2)` | float | None |
| `avgEpss` | `round(COALESCE(AVG(epss_score), 0), 2)` | float | None |
| `avgPriority` | `round(COALESCE(AVG(priority_score), 0), 1)` | float | None |
| `totalAudited` | `COUNT(*)` | int | None |

All values are numeric aggregates from SQLite. **No XSS risk in practice**, but the pattern of interpolating API response data into `innerHTML` without the standard `escHtml()` is a code hygiene concern — if data types change in a future refactor, this could become a vector.

### Conclusion
The drift dashboard label XSS (FE-CRIT-3) is **not present** in the current codebase. The Sprint 27 fix pattern (adding `escHtml()` to all string interpolation in innerHTML) was already applied to label/name rendering paths in `driftDashboard.js`.

---

## Sprint 27 Fix Pattern (FE-CRIT-1 reference)

The confirmed FE-CRIT-1 fix in `caseView.js` applies `escHtml()` to all string interpolation within template literals and concatenated HTML strings. Example (line 23):

```js
${cv.summaryParagraphs.map(p => `<p>${escHtml(p)}</p>`).join('')}
```

This same pattern has been applied to:
- `queue.js` — all fields use `escHtml()`
- `reviewQueue.js` — all text fields use `escHtml()` (own copy of function)
- `caseView.js` — all text fields use `escHtml()`
- `driftDashboard.js` — labels and feature names use `escHtml()`

---

## Additional Observation (Out of Scope)

During the investigation, one potentially unescaped string rendering was found in `reviewQueue.js` line 75:

```js
const reviewStatus = r.reviewStatus || 'Pending';
// ...
'<td><span class="review-status-badge">' + reviewStatus + '</span></td>'
```

The `reviewStatus` field is `str | None` in the backend model (`ReviewQueueItem.review_status`). While the backend currently sets it to only `'reviewed'` or `NULL`, there is no escaping. Since this is not part of FE-CRIT-2 or FE-CRIT-3 scope, it is flagged for awareness only.

---

## Proposed Next Actions

| Item | Action | Priority |
|---|---|---|
| FE-CRIT-2 | **Document** — Not reproduced. Close as already resolved. | Low |
| FE-CRIT-3 | **Document** — Not reproduced. Close as already resolved. | Low |
| Hygiene: drift dashboard numeric values (lines 131-134) | **Fix now** — Add `escHtml()` wrapper for consistency and future-proofing. Estimated effort: 5 minutes. | Low |
| Out of scope: reviewQueue.js reviewStatus (line 75) | **Defer** — Flag in AI_PROBLEMS.md or backlog. | Lowest |
