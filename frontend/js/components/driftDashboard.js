// driftDashboard.js — Model Drift Dashboard (CSS-only charts)
async function initDriftDashboard() {
  // Load model status info panel
  loadModelStatusPanel();

  try {
    var res = await _authFetch('/api/drift');
    var data = await res.json();
    renderDriftDashboard(data);
  } catch (err) {
    console.error('Failed to load drift data:', err);
    var container = document.getElementById('drift-dashboard-container');
    if (container) container.innerHTML = '<div class="review-empty">Failed to load drift metrics.</div>';
  }
}

function loadModelStatusPanel() {
  var panel = document.getElementById('model-info-panel');
  if (!panel) return;

  fetch('/api/model/status')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var v = data.active_version;
      if (!v) {
        panel.innerHTML = '<div class="drift-panel"><div class="drift-panel-title">Deployed Model</div><div class="drift-no-data">No active model</div></div>';
        return;
      }
      var samples = v.metrics.training_samples ? v.metrics.training_samples.toLocaleString() : 'N/A';
      var rocAuc = v.metrics.roc_auc != null ? v.metrics.roc_auc : 'N/A';
      var trainedDate = v.created_at ? new Date(v.created_at).toLocaleDateString() : 'N/A';
      var html = '<div class="model-info-bar">';
      html += '<div class="model-info-item"><span class="model-info-label">Deployed Model</span><span class="model-info-value">' + v.label + '</span></div>';
      html += '<div class="model-info-item"><span class="model-info-label">ROC-AUC</span><span class="model-info-value">' + rocAuc + '</span></div>';
      html += '<div class="model-info-item"><span class="model-info-label">Samples</span><span class="model-info-value">' + samples + '</span></div>';
      html += '<div class="model-info-item"><span class="model-info-label">Trained</span><span class="model-info-value">' + trainedDate + '</span></div>';
      html += '</div>';
      panel.innerHTML = html;
    })
    .catch(function(err) {
      console.error('Failed to load model status:', err);
      panel.innerHTML = '';
    });
}

function renderDriftDashboard(data) {
  var container = document.getElementById('drift-dashboard-container');
  if (!container) return;

  if (!data.totalAudited || data.totalAudited === 0) {
    container.innerHTML = '<div class="review-empty">No audited cases yet. Drift metrics will appear after cases are resolved.</div>';
    return;
  }

  var html = '<div class="drift-grid">';

  // Panel 1: Score Trend Sparkline
  html += '<div class="drift-panel">';
  html += '<div class="drift-panel-title">Score Trend (30-day avg)</div>';
  html += '<div class="drift-sparkline">';
  if (data.scoreTrend && data.scoreTrend.length > 0) {
    var maxScore = 100;
    data.scoreTrend.forEach(function(point) {
      var pct = (point.avgScore / maxScore) * 100;
      var colour = pct > 75 ? '#EF4444' : pct > 50 ? '#F97316' : pct > 25 ? '#F59E0B' : '#22C55E';
      var label = point.date ? point.date.slice(-5) : '';
      html += '<div class="drift-bar-wrapper" title="' + label + ': ' + point.avgScore + '">';
      html += '<div class="drift-bar" style="height:' + pct + '%;background:' + colour + '"></div>';
      html += '</div>';
    });
  } else {
    html += '<div class="drift-no-data">No data</div>';
  }
  html += '</div></div>';

  // Panel 2: Tier Routing (two-color semicircle)
  html += '<div class="drift-panel">';
  html += '<div class="drift-panel-title">Tier Routing</div>';
  html += '<div class="drift-semicircle">';
  var total = data.tierRouting.auto + data.tierRouting.escalated;
  var autoPct = total > 0 ? (data.tierRouting.auto / total) * 100 : 0;
  var escPct = total > 0 ? (data.tierRouting.escalated / total) * 100 : 0;
  var escStart = 180 - (escPct * 1.8);
  html += '<div class="semicircle-bar">';
  html += '<div class="semicircle-fill semicircle-auto" style="width:' + autoPct + '%"></div>';
  html += '<div class="semicircle-fill semicircle-esc" style="width:' + escPct + '%"></div>';
  html += '</div>';
  html += '<div class="semicircle-legend">';
  html += '<span><span class="legend-dot auto"></span> Auto: ' + data.tierRouting.auto + '</span>';
  html += '<span><span class="legend-dot esc"></span> Escalated: ' + data.tierRouting.escalated + '</span>';
  html += '</div></div></div>';

  // Panel 3: Risk Band Distribution (5 colored bars)
  html += '<div class="drift-panel">';
  html += '<div class="drift-panel-title">Risk Band Distribution</div>';
  html += '<div class="drift-risk-bands">';
  var bands = ['Very Critical', 'Critical', 'Medium', 'Low'];
  var bandColours = { 'Very Critical': '#EF4444', 'Critical': '#F97316', 'Medium': '#F59E0B', 'Low': '#22C55E' };
  var maxCount = 1;
  bands.forEach(function(b) {
    var c = data.riskBandDistribution[b] || 0;
    if (c > maxCount) maxCount = c;
  });
  bands.forEach(function(b) {
    var count = data.riskBandDistribution[b] || 0;
    var pct = maxCount > 0 ? (count / maxCount) * 100 : 0;
    html += '<div class="risk-band-row">';
    html += '<span class="risk-band-label" style="color:' + (bandColours[b] || '#64748B') + '">' + b + '</span>';
    html += '<div class="risk-band-bar-bg"><div class="risk-band-bar-fill" style="width:' + pct + '%;background:' + (bandColours[b] || '#64748B') + '"></div></div>';
    html += '<span class="risk-band-count">' + count + '</span>';
    html += '</div>';
  });
  html += '</div></div>';

  // Panel 4: Feature Drift Table
  html += '<div class="drift-panel">';
  html += '<div class="drift-panel-title">Feature Drift (30-day avg)</div>';
  html += '<div class="drift-feature-table">';
  html += '<div class="drift-feature-row"><span class="drift-feature-label">Avg CVSS</span><span class="drift-feature-value">' + data.featureDrift.avgCvss + '</span></div>';
  html += '<div class="drift-feature-row"><span class="drift-feature-label">Avg EPSS</span><span class="drift-feature-value">' + data.featureDrift.avgEpss + '</span></div>';
  html += '<div class="drift-feature-row"><span class="drift-feature-label">Avg Priority</span><span class="drift-feature-value">' + data.featureDrift.avgPriority + '</span></div>';
  html += '<div class="drift-feature-row"><span class="drift-feature-label">Total Audited</span><span class="drift-feature-value">' + data.totalAudited + '</span></div>';
  html += '</div></div>';

  html += '</div>'; // drift-grid

  container.innerHTML = html;
}
