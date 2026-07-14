#!/usr/bin/env node
/**
 * Regression test: FE-MED-5 — _eventListenersWired guard
 *
 * Verifies the auth-required lifecycle: unauthenticated init wires no app
 * handlers, the post-login init wires them once, and a later re-init does not
 * duplicate them.
 *
 * Uses JSDOM to simulate the frontend environment and counts keydown listener
 * registrations by wrapping EventTarget.prototype.addEventListener.
 */

const assert = require('assert');
const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

// === DOM setup — must include all elements referenced by wireEventListeners() ===
const HTML_TEMPLATE = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body>
  <div id="demo-watermark" style="display:none"></div>
  <div id="demo-toggle-btn" style="display:none"></div>
  <div id="screen-queue" class="active">
    <input id="queue-search" />
    <select id="filter-select"></select>
    <table id="queue-table">
      <thead><tr><th class="sortable" data-sort="priorityScore">Score</th></tr></thead>
      <tbody id="queue-body"></tbody>
    </table>
    <div id="metric-boxes-row"></div>
  </div>
  <div id="screen-case">
    <button id="back-btn">Back</button>
    <div id="accordion-container"></div>
    <button id="notes-save-btn">Save</button>
    <textarea id="notes-textarea"></textarea>
    <div id="notes-save-status"></div>
  </div>
  <div id="screen-review"></div>
  <div id="screen-drift"></div>
  <div id="screen-admin"><div id="admin-settings-container"></div></div>
  <button id="review-tab-btn">Review</button>
  <button id="drift-tab-btn">Drift</button>
  <button id="review-back-btn">Back</button>
  <button id="drift-back-btn">Back</button>
  <button id="admin-tab-btn">Admin</button>
  <button id="admin-back-btn">Back</button>
</body>
</html>
`;

function main() {
  // Track the four app keyboard handler targets. JSDOM itself may install a
  // window-level keyboard listener, which is outside app.js and irrelevant to
  // this regression.
  let keydownListenerCount = 0;
  const keydownTargets = [];

  // Create JSDOM instance
  const dom = new JSDOM(HTML_TEMPLATE, {
    runScripts: 'outside-only',
    url: 'http://localhost',
  });

  const win = dom.window;
  const doc = win.document;

  // --- Wire up global mocks that app.js depends on ---

  // Mock fetch for health check
  win.fetch = () => Promise.resolve({
    json: () => Promise.resolve({ demo_mode: false }),
  });

  // Queue and metrics mocks
  win.fetchQueue = async () => ({ rows: [], total: 0 });
  win.fetchMetrics = async () => ({});
  win.renderQueue = () => {};
  win.updateMetricBoxes = () => {};
  win.sortState = { column: null, direction: 'asc' };

  // Auth-required flow: the first init stops at the login modal; a successful
  // login changes the authentication state before app.js re-runs init().
  let authenticated = false;
  win.initAuth = async () => { win.AUTH_REQUIRED = true; };
  win.isAuthenticated = () => authenticated;
  win.AUTH_REQUIRED = true;

  // UI component mocks
  win.wireDemoEventListeners = () => {};
  win.initReviewQueue = () => {};
  win.initDriftDashboard = () => {};
  win.renderAdminSettings = () => {};

  // Patch EventTarget so document-level and element-level keyboard handlers
  // are both covered.
  const origAddEventListener = win.EventTarget.prototype.addEventListener;
  win.EventTarget.prototype.addEventListener = function (type, listener, options) {
    if (type === 'keydown' && (
      this === doc || this.id === 'queue-body' || this.id === 'metric-boxes-row'
    )) {
      keydownListenerCount++;
      keydownTargets.push(this === win ? 'window' : (this.id || this.nodeName || 'unknown'));
    }
    return origAddEventListener.call(this, type, listener, options);
  };

  // Load and evaluate app.js in the JSDOM window context
  const appJsPath = path.resolve(__dirname, '..', '..', 'frontend', 'js', 'app.js');
  if (!fs.existsSync(appJsPath)) {
    console.error('FAIL: app.js not found at', appJsPath);
    process.exit(1);
  }
  const appJsCode = fs.readFileSync(appJsPath, 'utf8');
  win.eval(appJsCode);

  // === Initial unauthenticated init ===
  keydownListenerCount = 0;

  return win
    .init()
    .then(() => {
      assert.strictEqual(keydownListenerCount, 0, 'Unauthenticated init must not wire app listeners');

      // === Successful login triggers the real re-init path ===
      authenticated = true;
      return win.init();
    })
    .then(() => {
      const afterLoginInit = keydownListenerCount;
      console.log(`After post-login init(): ${afterLoginInit} keydown listeners (${keydownTargets.join(', ')})`);

      // A later re-init must remain idempotent.
      return win.init().then(() => {
        const afterRepeatInit = keydownListenerCount;
        console.log(`After repeated authenticated init(): ${afterRepeatInit} keydown listeners`);

        // === Assertions ===
        // 1. Count MUST NOT increase after second init
        assert.strictEqual(
          afterLoginInit,
          afterRepeatInit,
          `GUARD FAILED: keydown listener count increased from ${afterLoginInit} to ${afterRepeatInit}. ` +
            'The _eventListenersWired guard is not preventing re-registration of listeners on init(). ' +
            'Check that frontend/js/app.js wraps wireEventListeners in if (!_eventListenersWired) { ... }.'
        );

        // 2. Four app keyboard handlers are registered: two on document and
        //    two on persistent UI elements.
        assert.strictEqual(
          afterLoginInit,
          4,
          `Expected exactly 4 app keydown listeners after login, got ${afterLoginInit}`
        );

        console.log(
          `PASS: auth-required init then re-init kept ${afterRepeatInit} keydown listeners (expected 4)`
        );
      });
    })
    .catch((err) => {
      console.error('TEST FAILED:', err.message);
      process.exit(1);
    });
}

main();
