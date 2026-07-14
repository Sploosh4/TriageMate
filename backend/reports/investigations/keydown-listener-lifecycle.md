# FE-MED-5: Keydown Listener Accumulation Investigation

**Status:** Reproduced — accumulation confirmed under auth-enabled flow

**Date:** 2026-07-14

**Investigator:** Strike Team Lead

---

## Executive Summary

Keydown event listeners **do accumulate** when authentication is enabled and the user logs in. The root cause is `auth.js:_handleLogin()` calling `init()` after successful authentication, which re-executes `wireEventListeners()` without removing previously registered listeners. All listeners in `wireEventListeners()` use anonymous functions, making them unreachable for removal.

In the default (auth-disabled) flow, listeners are registered exactly once and do not leak.

---

## Quantitative Evidence

| Metric | Count |
|---|---|
| `addEventListener.*keydown` (across all frontend JS) | **6** |
| `removeEventListener.*keydown` | **0** |
| `removeEventListener` total (all event types) | **3** (all in `reviewQueue.js`, none for keydown) |
| `init()` call sites | **2** (`app.js:310` DOMContentLoaded, `auth.js:173` post-login) |
| `wireEventListeners()` call sites | **1** (`app.js:94`, inside `init()`) |
| Listeners with anonymous functions (cannot be removed) | **28** of 31 addEventListener calls |

---

## Code Paths Analyzed

### 1. `frontend/js/app.js` — `wireEventListeners()` (lines 121–308)

Registers **28 event listeners** total, including:

- **2 document-level keydown listeners:**
  - Line 242–247: Ctrl+S to save notes (`document.addEventListener('keydown', function(e) {...})`)
  - Line 250–254: Escape to go back (`document.addEventListener('keydown', function(e) {...})`)

- **2 element-level keydown listeners:**
  - Line 162–171: `#queue-body` Enter/Space to open case
  - Line 213–220: `#metric-boxes-row` Enter/Space to click metric box

- **24 other listeners** (click, input, change — all on persistent DOM elements)

**All listeners use anonymous functions.** None can be removed with `removeEventListener` after registration. Zero cleanup logic exists in `wireEventListeners()`.

### 2. `frontend/js/app.js` — `navigateToScreen()` (lines 13–52)

Called when switching between screens (queue, case, review, drift, admin).

- **Does NOT call `wireEventListeners()`** — navigation alone does not trigger re-registration.
- Calls `initReviewQueue()`, `initDriftDashboard()`, or `renderAdminSettings()` depending on target screen.

### 3. `frontend/js/components/reviewQueue.js` — `initReviewQueue()` / `wireReviewEvents()`

- `initReviewQueue()` (line 28): Fetches data and calls `renderReviewQueue()`.
- `wireReviewEvents()` (line 181): **Has proper cleanup** — stores handler references on DOM elements and calls `removeEventListener` before re-adding (pattern at lines 186–188, 228–230, 241–243).
- **No keydown listeners are registered here.**
- `wireReviewAccordionEvents()` (line 249): Registers a click listener without cleanup — minor, but not a keydown issue.

### 4. `frontend/js/components/driftDashboard.js` — `initDriftDashboard()` / `renderDriftDashboard()`

- Fetches data and sets `innerHTML`. **No event listeners** of any kind.
- No keydown registration. Clean.

### 5. `frontend/js/components/adminSettings.js` — `renderAdminSettings()` / `wireButtons()`

- `renderAdminSettings()` (line 40): Renders DOM from scratch in an empty container. Only click and input listeners.
- `wireButtons()` (line 251): Adds click listeners on save/reset buttons. No keydown listeners.
- Container is emptied (`container.innerHTML = ''`) before rendering, so stale DOM nodes (and their listeners) are garbage collected.

### 6. `frontend/js/components/auth.js` — `_wireLoginUI()` / `_handleLogin()` / `initAuth()`

- `_wireLoginUI()` (line 184): Registers 2 keydown listeners on `#auth-password` and `#auth-username` (Enter key handling).
  - Called ONLY from `initAuth()` line 237, which only executes when user is NOT authenticated.
  - On re-init after successful login, `initAuth()` sees `isAuthenticated() === true` and skips `_wireLoginUI()`.
  - **These 2 keydown listeners do NOT accumulate** on re-init.

- `_handleLogin()` (line 152): **Root cause of accumulation** — after successful login, calls `init()` on line 173.
  - `init()` calls `wireEventListeners()` on line 94.
  - All listeners in `wireEventListeners()` are re-registered without removal.
  - On every subsequent login (e.g., token expiry → re-login), duplication compounds.

---

## Accumulation Lifecycle

### Flow A: Auth disabled (default) — NO leak
```
DOMContentLoaded → init() → wireEventListeners()      [1 registration]
```
All listeners registered exactly once.

### Flow B: Auth enabled, user pre-authenticated — NO leak
```
DOMContentLoaded → init() → initAuth() → authenticated → wireEventListeners()      [1 registration]
```

### Flow C: Auth enabled, user logs in — LEAK (2x duplication)
```
DOMContentLoaded → init() → initAuth() → NOT authenticated
  → _wireLoginUI() (2 keydown listeners on login form)
  → _showLoginModal()
  → return early from init()                            [wireEventListeners NOT called]

  User logs in →
  _handleLogin() → login successful → init()
  → initAuth() → IS authenticated now → proceeds
  → wireEventListeners()                                ← [1st registration]
    ALL 28 listeners registered (including 4 keydown)

  User navigates to review/drift/admin →
    navigateToScreen() → no wireEventListeners           [no further leak from navigation]

  // If user logs out and re-logs in:
  _handleLogin() → init() → wireEventListeners()         ← [2nd registration]
    SAME 28 listeners registered AGAIN on SAME elements
    → 8 keydown listeners now on document/elements
    → 56 total listeners instead of 28
```

### Demonstrable Impact

On each re-authentication cycle:
- `document` keydown listeners: 2 → 4 → 6 → 8 (compounds)
- `#queue-body` keydown listeners: 1 → 2 → 3 → 4 (compounds)
- `#metric-boxes-row` keydown listeners: 1 → 2 → 3 → 4 (compounds)
- All other listeners compound similarly
- **Potential double-firing**: Ctrl+S in case view would call `notes-save-btn.click()` twice per keypress, potentially submitting duplicate note saves.

---

## Proposed Fix

**Decision:** The accumulation is confirmed. Fix is warranted.

**Approach:** Add a guard in `init()` to prevent `wireEventListeners()` from being called more than once.

```javascript
// app.js — add a flag
let _eventListenersWired = false;

async function init() {
  // ... auth checks ...

  if (!_eventListenersWired) {
    wireEventListeners();
    _eventListenersWired = true;
  }

  // Always re-fetch data regardless of listener state
  try {
    const results = await Promise.all([
      fetchQueue(),
      fetchMetrics()
    ]);
    // ...
  }
}
```

**Alternative approach** (more thorough but riskier for a bugfix): Refactor `wireEventListeners()` to use named functions and call `removeEventListener` before adding — matching the pattern used in `reviewQueue.js`. This is more complex and touches 28 listener registrations.

**Recommended approach:** The guard flag — minimal change, zero risk of breaking existing behavior, and solves the accumulation. The data-fetching in `init()` should still run on re-init (so the queue refreshes after login), which the proposed fix preserves.

---

## Files Not Modified (Out of Scope But Noted)

- `frontend/js/components/reviewQueue.js` has a minor leak in `wireReviewAccordionEvents()` (line 249–258) — click listener on container added without cleanup on each case detail load. This is not a keydown issue, but worth noting for a future audit sweep.

---

## Verification

To verify the fix:
1. Enable auth on the backend (`auth_required: true` in health response)
2. Clear localStorage tokens
3. Load the app → login modal appears
4. Log in → observe `wireEventListeners()` called once
5. Navigate to review, drift, admin screens
6. Log out (via console: `logout()`), log in again
7. Verify keydown listeners on `document` remain at 2 (not 4+)

Without auth enabled, the current code is already clean (single registration).
