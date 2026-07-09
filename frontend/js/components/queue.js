// queue.js — Queue table rendering with search, sort, and tier badges

// Sort state
const sortState = { column: 'priorityScore', direction: 'desc' };

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

function getTierBadgeClass(tier) {
  if (tier === 'Deterministic') return 'tier-badge-det';
  if (tier === 'ML Tier') return 'tier-badge-ml';
  return 'tier-badge-slm';
}

function stripTierFromReason(reason, tier) {
  const prefix = tier + ': ';
  if (reason.indexOf(prefix) === 0) {
    return reason.substring(prefix.length);
  }
  return reason;
}

function metricFilterMatch(row, filter) {
  if (filter === 'critical') return row.riskBand === 'Very Critical';
  if (filter === 'human-val') return row.tier === 'SLM Tier';
  if (filter === 'low-conf') {
    if (row.tier === 'SLM Tier') return true;
    if (row.tier === 'ML Tier') {
      const m = row.detectionReason.match(/ML confidence ([0-9.]+)/);
      if (m && parseFloat(m[1]) < 0.85) return true;
    }
    return false;
  }
  if (filter === 'exposed') {
    return (row.interfaceType || '').toLowerCase().indexOf('internet-facing') !== -1;
  }
  return false;
}

function searchMatch(row, query) {
  if (!query) return true;
  const q = query.toLowerCase();
  return (row.vulnerabilityId || '').toLowerCase().indexOf(q) !== -1 ||
         (row.hostname || '').toLowerCase().indexOf(q) !== -1 ||
         (row.detectionReason || '').toLowerCase().indexOf(q) !== -1;
}

function sortRows(rows, column, direction) {
  return rows.slice().sort(function(a, b) {
    let va = a[column];
    let vb = b[column];
    if (typeof va === 'string') va = va.toLowerCase();
    if (typeof vb === 'string') vb = vb.toLowerCase();
    if (va === vb) return 0;
    const cmp = va < vb ? -1 : 1;
    return direction === 'asc' ? cmp : -cmp;
  });
}

function filterRows(rows, filter, activeMetricFilter, searchQuery) {
  let filtered = rows;
  if (filter !== 'All Tiers') {
    filtered = filtered.filter(function(r) { return r.tier === filter; });
  }
  if (activeMetricFilter) {
    filtered = filtered.filter(function(r) { return metricFilterMatch(r, activeMetricFilter); });
  }
  if (searchQuery) {
    filtered = filtered.filter(function(r) { return searchMatch(r, searchQuery); });
  }
  return filtered;
}

function updateSortArrows() {
  const headers = document.querySelectorAll('#queue-table th.sortable');
  headers.forEach(function(th) {
    const arrow = th.querySelector('.sort-arrow');
    if (arrow) {
      if (th.dataset.sort === sortState.column) {
        arrow.textContent = sortState.direction === 'asc' ? '\u25B2' : '\u25BC';
        arrow.classList.add('active');
      } else {
        arrow.textContent = '';
        arrow.classList.remove('active');
      }
    }
  });
}

// Render queue
function renderQueue(rows, filter, activeMetricFilter, searchQuery) {
  const tbody = document.getElementById('queue-body');
  const filtered = filterRows(rows, filter, activeMetricFilter, searchQuery);
  const sorted = sortRows(filtered, sortState.column, sortState.direction);

  if (sorted.length === 0) {
    tbody.innerHTML = '<tr><td colspan="99" class="queue-empty">No rows match the current filters.</td></tr>';
    return;
  }

  tbody.innerHTML = sorted.map(function(r) {
    const colour = getRiskColour(r.priorityScore);
    const reasonStripped = stripTierFromReason(r.detectionReason, r.tier);
    return '<tr tabindex="0" data-row-id="' + r.id + '">' +
      '<td data-label="Vulnerability ID"><span class="queue-id">' + escHtml(r.vulnerabilityId) + '</span></td>' +
      '<td data-label="Hostname"><span class="queue-hostname">' + escHtml(r.hostname) + '</span></td>' +
      '<td data-label="Score">' +
        '<span class="queue-score-cell">' +
          '<span class="queue-score-circle" style="background:' + colour + '"></span>' +
          '<span class="queue-score-text" style="color:' + colour + '">' + r.priorityScore + '</span>' +
        '</span>' +
      '</td>' +
      '<td data-label="Risk"><span class="queue-risk-text" style="color:' + colour + '">' + escHtml(r.riskBand) + '</span></td>' +
      '<td data-label="Tier"><span class="' + getTierBadgeClass(r.tier) + '">' + escHtml(r.tier) + '</span></td>' +
      '<td data-label="Reason"><span class="queue-reason" title="' + escHtml(r.detectionReason) + '">' + escHtml(reasonStripped) + '</span></td>' +
      '<td data-label="Compliance"><span class="compliance-badge ' + getComplianceClass(r.complianceCategory) + '">' + r.compliance.replace('Category ', 'CAT ') + '</span></td>' +
      '<td data-label="Since"><span class="queue-time">' + escHtml(r.createdAt || '') + '</span></td>' +
    '</tr>';
  }).join('');

  updateSortArrows();
}
