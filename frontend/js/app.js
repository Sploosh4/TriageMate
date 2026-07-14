// app.js — Application state and initialization
const appState = {
  screen: 'queue',
  currentRowId: null,
  filter: 'All Tiers',
  queueData: [],
  currentCaseData: null,
  activeMetricFilter: null,
  searchQuery: '',
  accordionOpen: null
};

function navigateToScreen(screen) {
  const screens = ['screen-queue', 'screen-case', 'screen-review', 'screen-drift', 'screen-admin'];
  screens.forEach(function(id) {
    const el = document.getElementById(id);
    if (el) {
      el.classList.remove('active');
      // Cancel any pending hide timeout for this screen
      if (el._hideTimeout) {
        clearTimeout(el._hideTimeout);
        el._hideTimeout = null;
      }
      // Delay hiding to allow opacity transition 1→0 to paint
      if (id !== 'screen-' + screen) {
        el._hideTimeout = setTimeout(function() {
          el.classList.add('hidden');
          el._hideTimeout = null;
        }, 250);
      }
    }
  });

  const target = document.getElementById('screen-' + screen);
  if (target) {
    target.classList.remove('hidden');
    target.classList.add('active');
  }

  appState.screen = screen;

  if (screen === 'review' && typeof initReviewQueue === 'function') {
    initReviewQueue();
  } else if (screen === 'drift' && typeof initDriftDashboard === 'function') {
    initDriftDashboard();
  } else if (screen === 'admin' && typeof renderAdminSettings === 'function') {
    var container = document.getElementById('admin-settings-container');
    if (container) {
      renderAdminSettings(container);
    }
  }
}

function refreshQueue() {
  renderQueue(appState.queueData, appState.filter, appState.activeMetricFilter, appState.searchQuery);
  updateMetricBoxes(appState.queueData);
}

async function init() {
  // First, check auth status. If auth is required and user is not logged in,
  // initAuth will show the login modal and we stop here.
  if (typeof initAuth === 'function') {
    await initAuth();
    // If auth is required but not authenticated, stop here (modal is shown)
    if (window.AUTH_REQUIRED && !window.isAuthenticated()) {
      return;
    }
  }

  // Check demo mode on page load — show watermark if active
  fetch('/api/health')
    .then(function(r) { return r.json(); })
    .then(function(health) {
      if (health.demo_mode) {
        const wm = document.getElementById('demo-watermark');
        if (wm) wm.style.display = 'block';
        document.body.classList.add('demo-active');
      }
    })
    .catch(function() { /* health endpoint not critical for init */ });

  // Auth is disabled or user is authenticated — proceed normally
  try {
    const results = await Promise.all([
      fetchQueue(),
      fetchMetrics()
    ]);
    const queueResponse = results[0];
    appState.queueData = queueResponse.rows;

    renderQueue(appState.queueData, appState.filter, appState.activeMetricFilter, appState.searchQuery);
    updateMetricBoxes(appState.queueData);

    wireEventListeners();
  } catch (err) {
    console.error('TriageMate init failed:', err);
    document.getElementById('queue-body').innerHTML =
      '<tr><td colspan="8" class="queue-empty">Failed to load queue data. Is the backend running?</td></tr>';
  }
}

async function showCase(rowId) {
  try {
    const caseData = await fetchCase(rowId);
    appState.currentCaseData = caseData;
    appState.currentRowId = rowId;
    renderCase(caseData);
    navigateToScreen('case');
    document.getElementById('case-scroll').scrollTop = 0;
    document.getElementById('back-btn').focus();
  } catch (err) {
    console.error('Failed to load case:', err);
  }
}

function showQueue() {
  navigateToScreen('queue');
  document.getElementById('filter-select').focus();
}

function wireEventListeners() {
  // Search input
  const searchInput = document.getElementById('queue-search');
  searchInput.addEventListener('input', function(e) {
    appState.searchQuery = e.target.value;
    renderQueue(appState.queueData, appState.filter, appState.activeMetricFilter, appState.searchQuery);
  });

  // Filter change
  document.getElementById('filter-select').addEventListener('change', function(e) {
    appState.filter = e.target.value;
    if (appState.activeMetricFilter) {
      appState.activeMetricFilter = null;
      document.querySelectorAll('.metric-box').forEach(function(b) { b.classList.remove('active-filter'); });
    }
    renderQueue(appState.queueData, appState.filter, appState.activeMetricFilter, appState.searchQuery);
  });

  // Column sort
  document.querySelector('#queue-table thead').addEventListener('click', function(e) {
    const th = e.target.closest('th.sortable');
    if (!th) return;
    const column = th.dataset.sort;
    if (sortState.column === column) {
      sortState.direction = sortState.direction === 'asc' ? 'desc' : 'asc';
    } else {
      sortState.column = column;
      sortState.direction = column === 'priorityScore' ? 'desc' : 'asc';
    }
    renderQueue(appState.queueData, appState.filter, appState.activeMetricFilter, appState.searchQuery);
  });

  // Queue row clicks (event delegation)
  document.getElementById('queue-body').addEventListener('click', function(e) {
    const tr = e.target.closest('tr[data-row-id]');
    if (tr) {
      const rowId = parseInt(tr.dataset.rowId, 10);
      showCase(rowId);
    }
  });

  document.getElementById('queue-body').addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') {
      const tr = e.target.closest('tr[data-row-id]');
      if (tr) {
        e.preventDefault();
        const rowId = parseInt(tr.dataset.rowId, 10);
        showCase(rowId);
      }
    }
  });

  // Back button
  document.getElementById('back-btn').addEventListener('click', function() {
    showQueue();
  });

  // Accordion delegation
  document.getElementById('accordion-container').addEventListener('click', function(e) {
    const header = e.target.closest('.accordion-header');
    if (!header) return;
    const accordion = header.closest('.accordion');
    if (!accordion) return;
    const id = accordion.dataset.accordionId;

    const allAccordions = document.querySelectorAll('.accordion');
    allAccordions.forEach(function(a) {
      if (a.dataset.accordionId === id) {
        a.classList.toggle('open');
      } else {
        a.classList.remove('open');
      }
    });
  });

  // Metric boxes click
  document.getElementById('metric-boxes-row').addEventListener('click', function(e) {
    const box = e.target.closest('.metric-box');
    if (!box) return;
    const metric = box.dataset.metric;
    if (appState.activeMetricFilter === metric) {
      appState.activeMetricFilter = null;
      box.classList.remove('active-filter');
    } else {
      document.querySelectorAll('.metric-box').forEach(function(b) { b.classList.remove('active-filter'); });
      appState.activeMetricFilter = metric;
      box.classList.add('active-filter');
    }
    renderQueue(appState.queueData, appState.filter, appState.activeMetricFilter, appState.searchQuery);
  });

  // Metric boxes keyboard
  document.getElementById('metric-boxes-row').addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') {
      const box = e.target.closest('.metric-box');
      if (!box) return;
      e.preventDefault();
      box.click();
    }
  });

  // Notes save
  document.getElementById('notes-save-btn').addEventListener('click', async function() {
    const btn = document.getElementById('notes-save-btn');
    const status = document.getElementById('notes-save-status');
    btn.disabled = true;
    status.textContent = 'Saving...';
    try {
      const notes = document.getElementById('notes-textarea').value;
      await saveNotes(appState.currentRowId, notes);
      status.textContent = '\u2713 Saved';
      setTimeout(function() { status.textContent = ''; }, 3000);
    } catch (err) {
      status.textContent = '\u2717 Save failed';
      console.error('Save notes failed:', err);
    } finally {
      btn.disabled = false;
    }
  });

  // Keyboard shortcut: Ctrl+S to save notes
  document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 's' && appState.screen === 'case') {
      e.preventDefault();
      document.getElementById('notes-save-btn').click();
    }
  });

  // Keyboard: Escape to go back
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && appState.screen === 'case') {
      showQueue();
    }
  });

  // Review tab
  const reviewTab = document.getElementById('review-tab-btn');
  if (reviewTab) {
    reviewTab.addEventListener('click', function() {
      navigateToScreen('review');
    });
  }

  // Drift tab
  const driftTab = document.getElementById('drift-tab-btn');
  if (driftTab) {
    driftTab.addEventListener('click', function() {
      navigateToScreen('drift');
    });
  }

  // Review back button
  const reviewBack = document.getElementById('review-back-btn');
  if (reviewBack) {
    reviewBack.addEventListener('click', function() {
      showQueue();
    });
  }

  // Drift back button
  const driftBack = document.getElementById('drift-back-btn');
  if (driftBack) {
    driftBack.addEventListener('click', function() {
      showQueue();
    });
  }

  // Admin tab button
  const adminTab = document.getElementById('admin-tab-btn');
  if (adminTab) {
    adminTab.addEventListener('click', function() {
      navigateToScreen('admin');
    });
  }

  // Admin back button
  const adminBack = document.getElementById('admin-back-btn');
  if (adminBack) {
    adminBack.addEventListener('click', function() {
      showQueue();
    });
  }

  // Demo controls (guarded — only if demo toggle exists in DOM)
  if (document.getElementById('demo-toggle-btn')) {
    wireDemoEventListeners();
  }
}

document.addEventListener('DOMContentLoaded', init);
