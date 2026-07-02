// app.js — Application state and initialization
var appState = {
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
  var queueScreen = document.getElementById('screen-queue');
  var caseScreen = document.getElementById('screen-case');

  if (screen === 'queue') {
    queueScreen.classList.remove('hidden');
    queueScreen.classList.add('active');
    caseScreen.classList.remove('active');
    caseScreen.classList.add('hidden');
    appState.screen = 'queue';
  } else {
    caseScreen.classList.remove('hidden');
    caseScreen.classList.add('active');
    queueScreen.classList.remove('active');
    queueScreen.classList.add('hidden');
    appState.screen = 'case';
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
  }

  // Auth is disabled or user is authenticated — proceed normally
  try {
    var results = await Promise.all([
      fetchQueue(),
      fetchMetrics()
    ]);
    var queueResponse = results[0];
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
    var caseData = await fetchCase(rowId);
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
  var searchInput = document.getElementById('queue-search');
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
    var th = e.target.closest('th.sortable');
    if (!th) return;
    var column = th.dataset.sort;
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
    var tr = e.target.closest('tr[data-row-id]');
    if (tr) {
      var rowId = parseInt(tr.dataset.rowId, 10);
      showCase(rowId);
    }
  });

  document.getElementById('queue-body').addEventListener('keydown', function(e) {
    if (e.key === 'Enter' || e.key === ' ') {
      var tr = e.target.closest('tr[data-row-id]');
      if (tr) {
        e.preventDefault();
        var rowId = parseInt(tr.dataset.rowId, 10);
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
    var header = e.target.closest('.accordion-header');
    if (!header) return;
    var accordion = header.closest('.accordion');
    if (!accordion) return;
    var id = accordion.dataset.accordionId;

    var allAccordions = document.querySelectorAll('.accordion');
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
    var box = e.target.closest('.metric-box');
    if (!box) return;
    var metric = box.dataset.metric;
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
      var box = e.target.closest('.metric-box');
      if (!box) return;
      e.preventDefault();
      box.click();
    }
  });

  // Notes save
  document.getElementById('notes-save-btn').addEventListener('click', async function() {
    var btn = document.getElementById('notes-save-btn');
    var status = document.getElementById('notes-save-status');
    btn.disabled = true;
    status.textContent = 'Saving...';
    try {
      var notes = document.getElementById('notes-textarea').value;
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

  // Demo controls (guarded — only if demo toggle exists in DOM)
  if (document.getElementById('demo-toggle-btn')) {
    wireDemoEventListeners();
  }
}

document.addEventListener('DOMContentLoaded', init);
