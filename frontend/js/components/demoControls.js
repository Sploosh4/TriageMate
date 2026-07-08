// demoControls.js — Demo Data Generator UI controls

const demoState = {
  active: false,
  scenarios: [],
  generating: false
};

async function fetchDemoScenarios() {
  const res = await fetch('/api/demo/scenarios');
  if (!res.ok) throw new Error('Failed to fetch scenarios');
  return res.json();
}

async function generateDemoWave(payload) {
  const res = await fetch('/api/demo/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error('Generate failed: ' + res.status);
  return res.json();
}

async function clearAllFindings() {
  const res = await fetch('/api/ingest/clear', { method: 'POST' });
  if (!res.ok) throw new Error('Clear failed: ' + res.status);
  return res.json();
}

function toggleDemoMode() {
  demoState.active = !demoState.active;
  const panel = document.getElementById('demo-controls-panel');
  const badge = document.getElementById('demo-mode-badge');
  const watermark = document.getElementById('demo-watermark');

  if (demoState.active) {
    panel.classList.remove('hidden');
    badge.classList.remove('hidden');
    if (watermark) watermark.style.display = 'block';
    document.body.classList.add('demo-active');
    renderDemoControls();
    // Fetch scenarios for the picker
    fetchDemoScenarios().then(function(scenarios) {
      demoState.scenarios = scenarios;
      populateScenarioPicker(scenarios);
    }).catch(function(err) {
      console.error('Failed to load scenarios:', err);
    });
  } else {
    panel.classList.add('hidden');
    badge.classList.add('hidden');
    if (watermark) watermark.style.display = 'none';
    document.body.classList.remove('demo-active');
  }
}

function renderDemoControls() {
  const panel = document.getElementById('demo-controls-panel');
  panel.innerHTML =
    '<div class="demo-controls-header">Demo Data Generator</div>' +
    '<div class="demo-controls-body">' +
      '<div class="demo-control-group">' +
        '<label for="scenario-picker">Scenario / Wave Type</label>' +
        '<select id="scenario-picker"></select>' +
      '</div>' +
      '<div class="demo-control-group">' +
        '<label for="wave-size-select">Wave Size</label>' +
        '<select id="wave-size-select">' +
          '<option value="small">Small (5-10 findings)</option>' +
          '<option value="medium" selected>Medium (15-30 findings)</option>' +
          '<option value="large">Large (40-60 findings)</option>' +
        '</select>' +
      '</div>' +
      '<div class="demo-control-buttons">' +
        '<button id="demo-generate-btn" class="demo-generate-btn">Generate Wave</button>' +
        '<button id="demo-clear-btn" class="demo-clear-btn danger">Clear All</button>' +
      '</div>' +
      '<div id="demo-status" class="demo-status"></div>' +
    '</div>';
}

function populateScenarioPicker(scenarios) {
  const picker = document.getElementById('scenario-picker');
  if (!picker) return;
  picker.innerHTML = '';

  // Random Wave option first
  const randomOpt = document.createElement('option');
  randomOpt.value = '_random_';
  randomOpt.textContent = '-- Random Wave (Host-Appropriate) --';
  picker.appendChild(randomOpt);

  // Scenario options
  scenarios.forEach(function(s) {
    const opt = document.createElement('option');
    opt.value = s.id;
    opt.textContent = s.name + ' (' + s.finding_count + ' findings)';
    picker.appendChild(opt);
  });
}

function wireDemoEventListeners() {
  const toggleBtn = document.getElementById('demo-toggle-btn');
  if (!toggleBtn) return;

  toggleBtn.addEventListener('click', toggleDemoMode);

  // Generate button (delegation on panel since it gets replaced)
  const panel = document.getElementById('demo-controls-panel');
  panel.addEventListener('click', function(e) {
    const generateBtn = e.target.closest('#demo-generate-btn');
    if (!generateBtn) return;
    handleGenerate();
  });

  // Clear button
  panel.addEventListener('click', function(e) {
    const clearBtn = e.target.closest('#demo-clear-btn');
    if (!clearBtn) return;
    handleClear();
  });
}

async function handleGenerate() {
  if (demoState.generating) return;
  demoState.generating = true;

  const btn = document.getElementById('demo-generate-btn');
  const status = document.getElementById('demo-status');
  if (btn) btn.disabled = true;
  if (status) status.textContent = 'Generating...';

  try {
    const scenarioId = document.getElementById('scenario-picker').value;
    const size = document.getElementById('wave-size-select').value;

    let payload;
    if (scenarioId === '_random_') {
      payload = { mode: 'random', size: size };
    } else {
      payload = { mode: 'scenario', scenario_id: scenarioId };
    }

    const results = await generateDemoWave(payload);

    // Refresh queue data
    const queueResponse = await fetchQueue();
    appState.queueData = queueResponse.rows;
    refreshQueue();

    if (status) status.textContent = 'Generated ' + results.length + ' findings.';
  } catch (err) {
    console.error('Demo generate error:', err);
    if (status) status.textContent = 'Error: ' + err.message;
  } finally {
    demoState.generating = false;
    if (btn) btn.disabled = false;
  }
}

async function handleClear() {
  const status = document.getElementById('demo-status');
  if (!confirm('Archive all findings and clear the queue?')) return;

  try {
    const result = await clearAllFindings();
    appState.queueData = [];
    refreshQueue();
    if (status) status.textContent = result.message;
  } catch (err) {
    console.error('Clear error:', err);
    if (status) status.textContent = 'Error: ' + err.message;
  }
}
