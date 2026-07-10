/**
 * Admin Settings Panel — Scoring Weight Configuration
 *
 * Renders slider controls for each of the 7 scoring dimensions,
 * with live demo CVE score recalculation as sliders are adjusted.
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

var ADMIN_DEMO_CVES = [
    { id: 'CVE-2023-27350', baseline: 98 },
    { id: 'CVE-2023-34362', baseline: 91 },
    { id: 'CVE-2024-1709', baseline: 73 },
    { id: 'CVE-2021-44228', baseline: 66 },
    { id: 'CVE-2024-6387', baseline: 58 },
    { id: 'CVE-2023-3519', baseline: 44 },
    { id: 'CVE-2023-22527', baseline: 26 },
];

var ADMIN_WEIGHT_CONFIG = [
    { key: 'cvss', label: 'CVSS Base Score', max: 60, default: 40, color: '#2563eb' },
    { key: 'epss', label: 'EPSS Exploitability', max: 40, default: 20, color: '#7c3aed' },
    { key: 'criticality', label: 'Asset Criticality', max: 40, default: 20, color: '#dc2626' },
    { key: 'exposure', label: 'Exposure & Network', max: 30, default: 12, color: '#ea580c' },
    { key: 'patch', label: 'Patch/Remediation', max: 15, default: 5, color: '#16a34a' },
    { key: 'ml_exploitation', label: 'ML Exploitation Prob.', max: 25, default: 10, color: '#0891b2' },
];

var ADMIN_DEFAULT_TOTAL = 107;

var adminCurrentWeights = {};
var adminIsDirty = false;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

function renderAdminSettings(container) {
    container.innerHTML = '';
    container.style.padding = '24px';

    var heading = document.createElement('h2');
    heading.textContent = 'Scoring Weight Configuration';
    heading.style.marginBottom = '8px';
    container.appendChild(heading);

    var subtitle = document.createElement('p');
    subtitle.textContent = 'Adjust the relative importance of each scoring dimension. Changes are saved locally and applied in real-time to the demo preview below.';
    subtitle.style.color = 'var(--text-secondary)';
    subtitle.style.marginBottom = '24px';
    container.appendChild(subtitle);

    var slidersDiv = document.createElement('div');
    slidersDiv.id = 'admin-sliders';
    container.appendChild(slidersDiv);

    var totalDiv = document.createElement('div');
    totalDiv.id = 'admin-total';
    totalDiv.style.cssText = 'margin: 16px 0; font-weight: 600;';
    container.appendChild(totalDiv);

    var btnRow = document.createElement('div');
    btnRow.style.cssText = 'display: flex; gap: 12px; margin-bottom: 24px;';

    var saveBtn = document.createElement('button');
    saveBtn.id = 'admin-save-btn';
    saveBtn.className = 'btn btn-primary';
    saveBtn.textContent = 'Save to Server';
    saveBtn.disabled = true;
    btnRow.appendChild(saveBtn);

    var resetBtn = document.createElement('button');
    resetBtn.id = 'admin-reset-btn';
    resetBtn.className = 'btn btn-secondary';
    resetBtn.textContent = 'Reset to Defaults';
    btnRow.appendChild(resetBtn);

    container.appendChild(btnRow);

    var demoDiv = document.createElement('div');
    demoDiv.id = 'admin-demo-preview';
    demoDiv.style.cssText = 'margin-top: 24px; padding: 16px; background: var(--page-bg, #f8fafc); border-radius: 8px; border: 1px solid var(--border, #e2e8f0);';
    demoDiv.innerHTML = '' +
        '<h3 style="margin-bottom: 12px;">Demo CVE Score Preview</h3>' +
        '<p style="color: var(--text-secondary, #64748b); margin-bottom: 16px;">' +
        'Recalculated scores using current weight settings.</p>' +
        '<div id="admin-demo-table"></div>';
    container.appendChild(demoDiv);

    // Load current config
    apiGet('/api/admin/config/scoring')
        .then(function(config) {
            adminCurrentWeights = {};
            for (var k in config.weights) {
                if (config.weights.hasOwnProperty(k)) {
                    adminCurrentWeights[k] = config.weights[k];
                }
            }
            renderSliders(container, config);
            renderDemoPreview(container);
            updateTotal(container);
            wireButtons(container);
        })
        .catch(function(err) {
            container.innerHTML = '<p style="color: #dc2626;">Failed to load config: ' + err.message + '</p>';
        });
}

// ---------------------------------------------------------------------------
// Slider rendering
// ---------------------------------------------------------------------------

function renderSliders(container, config) {
    var slidersDiv = document.getElementById('admin-sliders');
    slidersDiv.innerHTML = '';

    // Save status indicator
    var statusDiv = document.createElement('div');
    statusDiv.id = 'admin-save-status';
    statusDiv.style.cssText = 'font-size: 0.8125rem; margin-bottom: 12px; min-height: 20px; color: var(--text-secondary, #64748b);';
    slidersDiv.appendChild(statusDiv);

    ADMIN_WEIGHT_CONFIG.forEach(function(cfg) {
        var value = adminCurrentWeights[cfg.key] != null ? adminCurrentWeights[cfg.key] : cfg.default;

        var row = document.createElement('div');
        row.className = 'admin-slider-row';
        row.style.cssText = 'display: flex; align-items: center; margin-bottom: 16px; gap: 12px;';

        var label = document.createElement('label');
        label.className = 'admin-slider-label';
        label.htmlFor = 'slider-' + cfg.key;
        label.textContent = cfg.label;
        label.style.cssText = 'width: 200px; font-size: 14px; color: var(--text-primary, #1e293b); font-weight: 500;';
        row.appendChild(label);

        var input = document.createElement('input');
        input.type = 'range';
        input.id = 'slider-' + cfg.key;
        input.className = 'admin-slider-input';
        input.min = '1';
        input.max = String(cfg.max);
        input.value = String(value);
        input.style.cssText = 'flex: 1; max-width: 300px; accent-color: ' + cfg.color + ';';
        row.appendChild(input);

        var valueSpan = document.createElement('span');
        valueSpan.className = 'admin-slider-value';
        valueSpan.id = 'val-' + cfg.key;
        valueSpan.textContent = String(value);
        valueSpan.style.cssText = 'width: 60px; text-align: right; font-weight: 600; font-size: 14px; color: ' + cfg.color + ';';
        row.appendChild(valueSpan);

        var maxSpan = document.createElement('span');
        maxSpan.className = 'admin-slider-max';
        maxSpan.textContent = '/ ' + cfg.max;
        maxSpan.style.cssText = 'width: 50px; font-size: 12px; color: var(--text-secondary, #64748b);';
        row.appendChild(maxSpan);

        slidersDiv.appendChild(row);

        // Wire slider change
        input.addEventListener('input', function() {
            var newVal = parseInt(this.value, 10);
            adminCurrentWeights[cfg.key] = newVal;
            valueSpan.textContent = String(newVal);
            adminIsDirty = true;
            document.getElementById('admin-save-btn').disabled = false;
            var statusEl = document.getElementById('admin-save-status');
            if (statusEl) statusEl.textContent = '';
            updateTotal(container);
            renderDemoPreview(container);
        });
    });
}

// ---------------------------------------------------------------------------
// Total display
// ---------------------------------------------------------------------------

function updateTotal(container) {
    var totalEl = document.getElementById('admin-total');
    if (!totalEl) return;
    var total = 0;
    ADMIN_WEIGHT_CONFIG.forEach(function(cfg) {
        total += adminCurrentWeights[cfg.key] || 0;
    });
    var valid = total >= 100;
    totalEl.textContent = 'Total Weight: ' + total + ' / ' + ADMIN_DEFAULT_TOTAL;
    totalEl.style.color = valid ? 'var(--text-primary, #1e293b)' : '#dc2626';
    document.getElementById('admin-save-btn').disabled = !adminIsDirty || !valid;
}

// ---------------------------------------------------------------------------
// Demo score preview
// ---------------------------------------------------------------------------

function calculateDemoScore(baseline) {
    var total = 0;
    ADMIN_WEIGHT_CONFIG.forEach(function(cfg) {
        total += adminCurrentWeights[cfg.key] || 0;
    });
    var raw = (baseline / ADMIN_DEFAULT_TOTAL) * total;
    return Math.max(0, Math.min(100, Math.round(raw)));
}

function renderDemoPreview(container) {
    var tableDiv = document.getElementById('admin-demo-table');
    if (!tableDiv) return;

    var table = document.createElement('table');
    table.className = 'admin-demo-table';

    // Header
    var thead = document.createElement('thead');
    thead.innerHTML = '<tr>' +
        '<th>CVE</th>' +
        '<th>Baseline Score</th>' +
        '<th>Recalculated</th>' +
        '<th>Change</th>' +
        '</tr>';
    table.appendChild(thead);

    var tbody = document.createElement('tbody');
    ADMIN_DEMO_CVES.forEach(function(cve) {
        var recalc = calculateDemoScore(cve.baseline);
        var diff = recalc - cve.baseline;
        var diffStr = diff > 0 ? '+' + diff : String(diff);
        var diffColor = diff > 0 ? '#16a34a' : (diff < 0 ? '#dc2626' : '#64748b');

        var tr = document.createElement('tr');
        tr.innerHTML = '' +
            '<td style="font-family: monospace;">' + cve.id + '</td>' +
            '<td>' + cve.baseline + '</td>' +
            '<td style="font-weight: 600;">' + recalc + '</td>' +
            '<td style="color: ' + diffColor + ';">' + diffStr + '</td>';
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);

    tableDiv.innerHTML = '';
    tableDiv.appendChild(table);
}

// ---------------------------------------------------------------------------
// Button wiring
// ---------------------------------------------------------------------------

function wireButtons(container) {
    var saveBtn = document.getElementById('admin-save-btn');
    var resetBtn = document.getElementById('admin-reset-btn');
    var statusEl = document.getElementById('admin-save-status');

    saveBtn.addEventListener('click', function() {
        saveBtn.disabled = true;
        if (statusEl) statusEl.textContent = 'Saving...';
        var weights = {};
        ADMIN_WEIGHT_CONFIG.forEach(function(cfg) {
            weights[cfg.key] = adminCurrentWeights[cfg.key];
        });
        apiPut('/api/admin/config/scoring', { weights: weights })
            .then(function() {
                adminIsDirty = false;
                saveBtn.disabled = true;
                if (statusEl) {
                    statusEl.textContent = '\u2713 Saved successfully';
                    statusEl.style.color = '#16a34a';
                }
                setTimeout(function() {
                    if (statusEl) {
                        statusEl.textContent = '';
                        statusEl.style.color = 'var(--text-secondary, #64748b)';
                    }
                }, 3000);
            })
            .catch(function(err) {
                saveBtn.disabled = false;
                if (statusEl) {
                    statusEl.textContent = '\u2717 Save failed: ' + err.message;
                    statusEl.style.color = '#dc2626';
                }
            });
    });

    resetBtn.addEventListener('click', function() {
        resetBtn.disabled = true;
        if (statusEl) statusEl.textContent = 'Resetting...';
        apiPost('/api/admin/config/scoring/reset')
            .then(function(config) {
                adminCurrentWeights = {};
                for (var k in config.weights) {
                    if (config.weights.hasOwnProperty(k)) {
                        adminCurrentWeights[k] = config.weights[k];
                    }
                }
                adminIsDirty = false;
                renderSliders(container, config);
                updateTotal(container);
                renderDemoPreview(container);
                document.getElementById('admin-save-btn').disabled = true;
                if (statusEl) {
                    statusEl.textContent = '\u2713 Reset to defaults';
                    statusEl.style.color = '#16a34a';
                }
                setTimeout(function() {
                    if (statusEl) {
                        statusEl.textContent = '';
                        statusEl.style.color = 'var(--text-secondary, #64748b)';
                    }
                }, 3000);
            })
            .catch(function(err) {
                if (statusEl) {
                    statusEl.textContent = '\u2717 Reset failed: ' + err.message;
                    statusEl.style.color = '#dc2626';
                }
            })
            .finally(function() {
                resetBtn.disabled = false;
            });
    });
}
