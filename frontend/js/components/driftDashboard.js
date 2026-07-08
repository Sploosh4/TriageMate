// driftDashboard.js — Model Drift Dashboard (CSS-only charts)
async function initDriftDashboard() {
  // Load model status info panel
  loadModelStatusPanel();

  try {
    const [driftRes, mlDriftRes] = await Promise.all([
      _authFetch('/api/drift'),
      _authFetch('/api/drift/ml')
    ]);
    const driftData = await driftRes.json();
    let mlDriftData = null;
    if (mlDriftRes.ok) {
      mlDriftData = await mlDriftRes.json();
    }
    renderDriftDashboard(driftData, mlDriftData);
  } catch (err) {
    console.error('Failed to load drift data:', err);
    const container = document.getElementById('drift-dashboard-container');
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

function renderDriftDashboard(data, mlDriftData) {
  const container = document.getElementById('drift-dashboard-container');
  if (!container) return;

  if (!data.totalAudited || data.totalAudited === 0) {
    container.innerHTML = '<div class="review-empty">No audited cases yet. Drift metrics will appear after cases are resolved.</div>';
    return;
  }

  let html = '<div class="drift-grid">';

  // Panel 1: Score Trend Sparkline
  html += '<div class="drift-panel">';
  html += '<div class="drift-panel-title">Score Trend (30-day avg)</div>';
  html += '<div class="drift-sparkline">';
  if (data.scoreTrend && data.scoreTrend.length > 0) {
    const maxScore = 100;
    data.scoreTrend.forEach(function(point) {
      const pct = (point.avgScore / maxScore) * 100;
      const colour = pct > 75 ? '#EF4444' : pct > 50 ? '#F97316' : pct > 25 ? '#F59E0B' : '#22C55E';
      const label = point.date ? point.date.slice(-5) : '';
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
  const total = data.tierRouting.auto + data.tierRouting.escalated;
  const autoPct = total > 0 ? (data.tierRouting.auto / total) * 100 : 0;
  const escPct = total > 0 ? (data.tierRouting.escalated / total) * 100 : 0;
  const escStart = 180 - (escPct * 1.8);
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
  const bands = ['Very Critical', 'Critical', 'Medium', 'Low'];
  const bandColours = { 'Very Critical': '#EF4444', 'Critical': '#F97316', 'Medium': '#F59E0B', 'Low': '#22C55E' };
  let maxCount = 1;
  bands.forEach(function(b) {
    const c = data.riskBandDistribution[b] || 0;
    if (c > maxCount) maxCount = c;
  });
  bands.forEach(function(b) {
    const count = data.riskBandDistribution[b] || 0;
    const pct = maxCount > 0 ? (count / maxCount) * 100 : 0;
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

  // Panel 5: ML Drift (XGBoost PSI)
  html += '<div class="drift-panel">';
  html += '<div class="drift-panel-title">ML Drift (XGBoost PSI)</div>';
  if (mlDriftData && mlDriftData.totalSamples > 0) {
    var psi = mlDriftData.compositePsi;
    var psiStatus = mlDriftData.status;
    var psiColour = psiStatus === 'critical' ? '#EF4444' : psiStatus === 'warning' ? '#F97316' : '#22C55E';
    var psiLabel = psiStatus === 'critical' ? 'Critical Drift' : psiStatus === 'warning' ? 'Warning' : 'Stable';

    html += '<div class="drift-psi-gauge" style="text-align:center;padding:12px 0;">';
    html += '<div style="font-size:36px;font-weight:700;color:' + psiColour + ';">' + psi.toFixed(4) + '</div>';
    html += '<div style="font-size:14px;color:' + psiColour + ';margin-top:4px;">' + psiLabel + '</div>';
    html += '<div style="font-size:12px;color:#94A3B8;margin-top:8px;">Samples: ' + mlDriftData.totalSamples + '</div>';
    html += '</div>';

    // Feature table (hide features with psi <= 0.01)
    var hasFeatures = false;
    html += '<div class="drift-feature-table" style="margin-top:8px;">';
    for (var fname in mlDriftData.features) {
      var feat = mlDriftData.features[fname];
      if (feat.psi <= 0.01) continue;
      hasFeatures = true;
      var fColour = feat.status === 'critical' ? '#EF4444' : feat.status === 'warning' ? '#F97316' : '#22C55E';
      html += '<div class="drift-feature-row">';
      html += '<span class="drift-feature-label" title="' + fname + '">' + fname + '</span>';
      html += '<span class="drift-feature-value" style="color:' + fColour + ';">' + feat.psi.toFixed(4) + ' <span style="font-size:11px;opacity:0.7;">(' + feat.status + ')</span></span>';
      html += '</div>';
    }
    if (!hasFeatures) {
      html += '<div class="drift-no-data" style="padding:8px 0;">All features stable (PSI ≤ 0.01)</div>';
    }
    html += '</div>';
  } else {
    html += '<div class="drift-no-data" style="padding:16px 0;">No ML feature data yet. PSI will appear after findings are ingested through Tier 1.</div>';
  }
  html += '</div>';

  html += '</div>'; // drift-grid

  container.innerHTML = html;
}
