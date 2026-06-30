// queue.js — Queue table rendering
// Helpers
function getRiskColour(score) {
  if (score <= 25) return '#22C55E';
  if (score <= 50) return '#F59E0B';
  if (score <= 75) return '#F97316';
  return '#EF4444';
}

function getComplianceClass(category) {
  return 'compliance-cat' + category;
}

function escHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function metricFilterMatch(row, filter) {
  if (filter === 'critical') return row.riskBand === 'Very Critical';
  if (filter === 'human-val') return row.tier === 'SLM Tier';
  if (filter === 'low-conf') {
    if (row.tier === 'SLM Tier') return true;
    if (row.tier === 'ML Tier') {
      var m = row.detectionReason.match(/ML confidence ([0-9.]+)/);
      if (m && parseFloat(m[1]) < 0.85) return true;
    }
    return false;
  }
  if (filter === 'exposed') {
    return (row.interfaceType || '').toLowerCase().indexOf('internet-facing') !== -1;
  }
  return false;
}

function filterRows(rows, filter, activeMetricFilter) {
  let filtered = rows;
  if (filter !== 'All Tiers') {
    filtered = filtered.filter(r => r.tier === filter);
  }
  if (activeMetricFilter) {
    filtered = filtered.filter(r => metricFilterMatch(r, activeMetricFilter));
  }
  return filtered;
}

// Render queue
function renderQueue(rows, filter, activeMetricFilter) {
  const tbody = document.getElementById('queue-body');
  const filtered = filterRows(rows, filter, activeMetricFilter);

  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="queue-empty">No rows match the selected filter.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(r => {
    const colour = getRiskColour(r.priorityScore);
    return `<tr tabindex="0" data-row-id="${r.id}">
      <td><span class="queue-id">${escHtml(r.vulnerabilityId)}</span></td>
      <td><span class="queue-hostname">${escHtml(r.hostname)}</span></td>
      <td>
        <span class="queue-score-cell">
          <span class="queue-score-circle" style="background:${colour}"></span>
          <span class="queue-score-text" style="color:${colour}">${r.priorityScore}</span>
        </span>
      </td>
      <td><span class="queue-risk-text" style="color:${colour}">${escHtml(r.riskBand)}</span></td>
      <td><span class="queue-reason" title="${escHtml(r.detectionReason)}">${escHtml(r.detectionReason)}</span></td>
      <td><span class="compliance-badge ${getComplianceClass(r.complianceCategory)}">${r.compliance.replace('Category ', 'CAT ')}</span></td>
    </tr>`;
  }).join('');
}
