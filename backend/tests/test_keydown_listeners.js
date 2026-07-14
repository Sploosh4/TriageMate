#!/usr/bin/env node
/**
 * Regression test: FE-MED-5 — _eventListenersWired guard
 *
 * Verifies that calling init() twice (simulating auth re-init flow) does NOT
 * re-register keydown listeners on document, preventing listener accumulation.
 *
 * Uses JSDOM to simulate the frontend environment and counts keydown listener
 * registrations by wrapping Document.prototype.addEventListener.
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
  // Track document-level keydown listener registrations
  let keydownListenerCount = 0;

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

  // Auth mocks (auth disabled by default)
  win.initAuth = async () => {};
  win.isAuthenticated = () => false;
  win.AUTH_REQUIRED = false;

  // UI component mocks
  win.wireDemoEventListeners = () => {};
  win.initReviewQueue = () => {};
  win.initDriftDashboard = () => {};
  win.renderAdminSettings = () => {};

  // Patch document.addEventListener to count keydown registrations
  const origAddEventListener = doc.addEventListener.bind(doc);
  doc.addEventListener = function (type, listener, options) {
    if (type === 'keydown') {
      keydownListenerCount++;
    }
    return origAddEventListener(type, listener, options);
  };

  // Load and evaluate app.js in the JSDOM window context
  const appJsPath = path.resolve(__dirname, '..', '..', 'frontend', 'js', 'app.js');
  if (!fs.existsSync(appJsPath)) {
    console.error('FAIL: app.js not found at', appJsPath);
    process.exit(1);
  }
  const appJsCode = fs.readFileSync(appJsPath, 'utf8');
  win.eval(appJsCode);

  // === First init() call ===
  keydownListenerCount = 0;

  return win
    .init()
    .then(() => {
      const afterFirstInit = keydownListenerCount;
      console.log(`After 1st init(): ${afterFirstInit} keydown listeners`);

      // === Second init() call (simulating auth re-init flow) ===
      return win.init().then(() => {
        const afterSecondInit = keydownListenerCount;
        console.log(`After 2nd init(): ${afterSecondInit} keydown listeners`);

        // === Assertions ===
        // 1. Count MUST NOT increase after second init
        assert.strictEqual(
          afterFirstInit,
          afterSecondInit,
          `GUARD FAILED: keydown listener count increased from ${afterFirstInit} to ${afterSecondInit}. ` +
            'The _eventListenersWired guard is not preventing re-registration of listeners on init(). ' +
            'Check that frontend/js/app.js wraps wireEventListeners in if (!_eventListenersWired) { ... }.'
        );

        // 2. Exactly two keydown listeners should be registered by wireEventListeners
        //    (lines 249 and 257 of app.js: Ctrl+S save shortcut, Escape to go back)
        assert.strictEqual(
          afterFirstInit,
          2,
          `Expected exactly 2 keydown listeners on document, got ${afterFirstInit}`
        );

        console.log(
          `PASS: init() called twice; keydown listeners stayed at ${afterSecondInit} (expected 2)`
        );
      });
    })
    .catch((err) => {
      console.error('TEST FAILED:', err.message);
      process.exit(1);
    });
}

main();
