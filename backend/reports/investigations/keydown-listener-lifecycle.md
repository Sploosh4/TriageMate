# FE-MED-5: Keydown Listener Accumulation Investigation

**Status:** Corrected — the reported accumulation was not reproducible in the actual auth lifecycle

**Date:** 2026-07-14

**Investigator:** Strike Team Lead

---

## Executive Summary

The original report incorrectly treated the post-login `init()` call as a second
listener registration. In the real auth-required flow, the initial call returns
before `wireEventListeners()` because no user is authenticated. The post-login
call is therefore the first registration. Logout reloads the page, clearing the
DOM and its listeners.

The `_eventListenersWired` guard remains a safe defence-in-depth measure. A
tracked JSDOM regression test now verifies the unauthenticated → post-login →
re-init sequence and all four app keydown handlers.

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

- `_handleLogin()` calls `init()` after successful login. This is not a second
  app-listener registration: the initial unauthenticated `init()` returned
  before reaching `wireEventListeners()`. Logout reloads the document, so a
  later login also starts from a clean listener set.

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

### Flow C: Auth enabled, user logs in — NO accumulation
```
DOMContentLoaded → init() → initAuth() → NOT authenticated
  → _wireLoginUI() (2 keydown listeners on login form)
  → _showLoginModal()
  → return early from init()                            [wireEventListeners NOT called]

  User logs in →
  _handleLogin() → login successful → init()
  → initAuth() → IS authenticated now → proceeds
  → wireEventListeners()                                ← [1st registration]
    ALL 28 listeners registered (including 4 keydown)  [first registration]

  User navigates to review/drift/admin →
    navigateToScreen() → no wireEventListeners           [no further leak from navigation]

  Logout → location.reload() → new document
  // A subsequent login starts with a fresh DOM and no old listeners.
```

### Result

No production listener accumulation was reproduced. The guard nevertheless
makes a future in-place re-initialisation safe, and the regression test asserts
that it cannot duplicate the four keydown handlers.

---

## Proposed Fix

**Decision:** No production defect was confirmed. Retain the guard as a small,
low-risk defence against future in-place re-initialisation.

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

**Recommended approach:** The guard flag is minimal, preserves queue refreshes,
and protects against a future code path that re-runs `init()` after listeners
have already been wired.

---

## Files Not Modified (Out of Scope But Noted)

- `frontend/js/components/reviewQueue.js` has a minor leak in `wireReviewAccordionEvents()` (line 249–258) — click listener on container added without cleanup on each case detail load. This is not a keydown issue, but worth noting for a future audit sweep.

---

## Verification

To verify the fix:
1. Enable auth on the backend (`auth_required: true` in health response)
2. Clear localStorage tokens
3. Load the app → login modal appears and app listeners are not yet wired
4. Log in → observe `wireEventListeners()` called once
5. Verify four app keydown handlers exist (two document-level, two element-level)
6. Re-run `init()` only in a controlled test and verify the count stays at four

Without auth enabled, the current code is already clean (single registration).
