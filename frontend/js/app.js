// app.js — Application state and initialization
let appState = {
  screen: 'queue',
  currentRowId: null,
  filter: 'All Tiers',
  queueData: [],
  currentCaseData: null,
  activeMetricFilter: null,
  accordionOpen: null
};

function navigateToScreen(screen) {
  const queueScreen = document.getElementById('screen-queue');
  const caseScreen = document.getElementById('screen-case');

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

async function init() {
  try {
    const [queueResponse, metricsResponse] = await Promise.all([
      fetchQueue(),
      fetchMetrics()
    ]);
    appState.queueData = queueResponse.rows;

    renderQueue(appState.queueData, appState.filter, appState.activeMetricFilter);
    updateMetricBoxes(appState.queueData);

    wireEventListeners();
  } catch (err) {
    console.error('TriageMate init failed:', err);
    document.getElementById('queue-body').innerHTML =
      '<tr><td colspan="6" class="queue-empty">Failed to load queue data. Is the backend running?</td></tr>';
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
  // Filter change
  document.getElementById('filter-select').addEventListener('change', function(e) {
    appState.filter = e.target.value;
    if (appState.activeMetricFilter) {
      appState.activeMetricFilter = null;
      document.querySelectorAll('.metric-box').forEach(function(b) { b.classList.remove('active-filter'); });
    }
    renderQueue(appState.queueData, appState.filter, appState.activeMetricFilter);
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
    allAccordions.forEach(a => {
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
    renderQueue(appState.queueData, appState.filter, appState.activeMetricFilter);
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

  // Keyboard: Escape to go back
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && appState.screen === 'case') {
      showQueue();
    }
  });
}

document.addEventListener('DOMContentLoaded', init);
