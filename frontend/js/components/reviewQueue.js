// reviewQueue.js — Tier 3 Human Review Queue
const reviewState = {
  rows: [],
  expandedId: null,
  caseData: null,
  loadingCase: false,
};

function getRiskColour(score) {
  if (score <= 25) return '#22C55E';
  if (score <= 50) return '#F59E0B';
  if (score <= 75) return '#F97316';
  return '#EF4444';
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

async function initReviewQueue() {
  try {
    const res = await _authFetch('/api/review/queue');
    const data = await res.json();
    reviewState.rows = data.rows || [];
  } catch (err) {
    console.error('Failed to load review queue:', err);
    reviewState.rows = [];
  }
  reviewState.expandedId = null;
  reviewState.caseData = null;
  renderReviewQueue();
}

function renderReviewQueue() {
  const container = document.getElementById('review-queue-container');
  if (!container) return;

  if (reviewState.rows.length === 0) {
    container.innerHTML = '<div class="review-empty">No cases pending review.</div>';
    return;
  }

  let html = '<table id="review-table"><thead><tr>' +
    '<th>Vulnerability ID</th>' +
    '<th>Hostname</th>' +
    '<th>Score</th>' +
    '<th>Risk Band</th>' +
    '<th>Tier</th>' +
    '<th>Review Status</th>' +
    '<th>Conflict</th>' +
    '</tr></thead><tbody>';

  reviewState.rows.forEach(function(r) {
    const colour = getRiskColour(r.priorityScore);
    const isExpanded = reviewState.expandedId === r.id;
    const reviewStatus = r.reviewStatus || 'Pending';
    const conflictBadge = r.tier2TextConflict
      ? '<span class="review-conflict-badge">Conflict</span>'
      : '<span class="review-no-conflict">None</span>';

    html += '<tr class="review-row' + (isExpanded ? ' expanded' : '') + '" data-review-id="' + r.id + '">' +
      '<td><span class="queue-id">' + escHtml(r.vulnerabilityId) + '</span></td>' +
      '<td><span class="queue-hostname">' + escHtml(r.hostname) + '</span></td>' +
      '<td><span class="review-score" style="color:' + colour + '">' + r.priorityScore + '</span></td>' +
      '<td><span class="review-risk" style="color:' + colour + '">' + escHtml(r.riskBand) + '</span></td>' +
      '<td><span class="' + getTierBadgeClass(r.detectionTier) + '">' + escHtml(r.detectionTier) + '</span></td>' +
      '<td><span class="review-status-badge">' + reviewStatus + '</span></td>' +
      '<td>' + conflictBadge + '</td>' +
      '</tr>';

    if (isExpanded) {
      html += '<tr class="review-detail-row"><td colspan="7"><div class="review-detail">';
      if (reviewState.loadingCase) {
        html += '<div class="review-loading">Loading case detail...</div>';
      } else if (reviewState.caseData) {
        html += renderReviewDetail(reviewState.caseData, r);
      }
      html += '</div></td></tr>';
    }
  });

  html += '</tbody></table>';
  html += '<div class="review-count">' + reviewState.rows.length + ' case(s) pending review</div>';

  container.innerHTML = html;
  wireReviewEvents();
}

function renderReviewDetail(caseResponse, reviewRow) {
  const cv = caseResponse.caseView;
  const qr = caseResponse.queueRow;
  let html = '';

  html += '<div class="review-panels">';

  html += '<div class="review-panel review-panel-summary' + (cv.textConflict ? ' text-conflict' : '') + '">';
  html += '<div class="prose">';
  html += cv.summaryParagraphs.map(function(p) { return '<p>' + escHtml(p) + '</p>'; }).join('');
  html += '<div class="mission-tags">';
  html += cv.missionPrevalence.map(function(t) { return '<span class="mission-tag">' + escHtml(t) + '</span>'; }).join('');
  html += '</div>';
  html += '<div class="mitre-row">';
  html += cv.mitreTechniques.map(function(m) { return '<span class="mitre-badge"><span class="mitre-id">' + escHtml(m.id) + '</span> <span class="mitre-name">&mdash; ' + escHtml(m.name) + '</span></span>'; }).join('');
  html += '</div>';
  if (cv.textConflictNote) html += '<div class="tier-0-note">' + escHtml(cv.textConflictNote) + '</div>';
  html += '</div></div>';

  html += '<div class="review-panel review-panel-accordions">';
  const accordions = [
    { label: 'Scanner Output', content: '<pre class="code-block">' + escHtml(cv.scannerOutput) + '</pre>' },
    { label: 'Weakness Logic Template', content: '<pre class="code-block">' + escHtml(cv.weaknessTemplate) + '</pre>' },
    { label: 'Advisory Reference', content: '<div class="advisory-quote"><strong>' + escHtml(cv.advisoryRefId) + '</strong><br><br>' + escHtml(cv.advisoryQuote) + '</div>' }
  ];
  accordions.forEach(function(a, i) {
    html += '<div class="review-accordion' + (i === 0 ? ' open' : '') + '">' +
      '<button class="review-accordion-header">' + escHtml(a.label) + '</button>' +
      '<div class="review-accordion-body">' + a.content + '</div></div>';
  });
  html += '</div>';

  html += '<div class="review-panel review-panel-weights">';
  html += '<div class="p4-section-title">Scoring Weights</div>';
  cv.scoringWeights.forEach(function(w) {
    html += '<div class="weight-item"><span class="weight-name">' + escHtml(w.name) + ':</span> ' +
      w.awarded + ' out of ' + w.max + ' points &mdash; ' + escHtml(w.justification) + '.</div>';
  });
  html += '</div>';

  html += '</div>';

  html += '<div class="review-form">';
  html += '<div class="review-form-title">Analyst Review Decision</div>';
  html += '<div class="review-form-row">';
  html += '<button class="review-btn confirm" data-decision="confirm">Confirm Score</button>';
  html += '<button class="review-btn override" data-decision="override">Override Score</button>';
  html += '</div>';

  html += '<div class="review-override-fields hidden">';
  html += '<label class="review-label">Override Score: <span id="override-score-value">' + reviewRow.priorityScore + '</span></label>';
  html += '<input type="range" id="override-score-slider" min="0" max="100" value="' + reviewRow.priorityScore + '" class="review-slider">';
  html += '<label class="review-label">Override Band:</label>';
  html += '<select id="override-band-select" class="review-select">';
  html += '<option value="Low"' + (reviewRow.riskBand === 'Low' ? ' selected' : '') + '>Low</option>';
  html += '<option value="Medium"' + (reviewRow.riskBand === 'Medium' ? ' selected' : '') + '>Medium</option>';
  html += '<option value="Critical"' + (reviewRow.riskBand === 'Critical' ? ' selected' : '') + '>Critical</option>';
  html += '<option value="Very Critical"' + (reviewRow.riskBand === 'Very Critical' ? ' selected' : '') + '>Very Critical</option>';
  html += '</select>';
  html += '</div>';

  html += '<label class="review-label">Notes:</label>';
  html += '<textarea id="review-notes" class="review-textarea" placeholder="Analyst notes..."></textarea>';
  html += '<label class="review-label">Analyst Name:</label>';
  html += '<input type="text" id="review-analyst-name" class="review-input" placeholder="Your name">';
  html += '<div class="review-form-actions">';
  html += '<button id="review-submit-btn" class="notes-save-btn">Submit Review</button>';
  html += '<span id="review-submit-status" class="review-submit-status"></span>';
  html += '</div>';
  html += '</div>';

  return html;
}

function wireReviewEvents() {
  document.querySelectorAll('.review-row').forEach(function(row) {
    row.addEventListener('click', function(e) {
      const id = parseInt(row.dataset.reviewId, 10);
      if (reviewState.expandedId === id) {
        reviewState.expandedId = null;
        reviewState.caseData = null;
        renderReviewQueue();
        return;
      }
      reviewState.expandedId = id;
      reviewState.loadingCase = true;
      reviewState.caseData = null;
      renderReviewQueue();
      loadReviewCaseDetail(id);
    });
  });

  const container = document.getElementById('review-queue-container');
  if (!container) return;

  container.addEventListener('click', function(e) {
    const btn = e.target.closest('.review-btn');
    if (btn) {
      const decision = btn.dataset.decision;
      const fields = container.querySelector('.review-override-fields');
      document.querySelectorAll('.review-btn').forEach(function(b) { b.classList.remove('selected'); });
      btn.classList.add('selected');
      if (fields) {
        fields.classList.toggle('hidden', decision !== 'override');
      }
    }
  });

  const slider = document.getElementById('override-score-slider');
  if (slider) {
    slider.addEventListener('input', function() {
      const val = document.getElementById('override-score-value');
      if (val) val.textContent = slider.value;
    });
  }

  const submitBtn = document.getElementById('review-submit-btn');
  if (submitBtn) {
    submitBtn.addEventListener('click', submitReview);
  }
}

function wireReviewAccordionEvents() {
  const container = document.getElementById('review-queue-container');
  if (!container) return;
  container.addEventListener('click', function(e) {
    const header = e.target.closest('.review-accordion-header');
    if (!header) return;
    const accordion = header.closest('.review-accordion');
    if (!accordion) return;
    accordion.classList.toggle('open');
  });
}

async function loadReviewCaseDetail(caseId) {
  try {
    const res = await _authFetch('/api/case/' + caseId);
    const data = await res.json();
    reviewState.caseData = data;
  } catch (err) {
    console.error('Failed to load case detail:', err);
    reviewState.caseData = null;
  }
  reviewState.loadingCase = false;
  renderReviewQueue();
  wireReviewAccordionEvents();
}

async function submitReview() {
  if (!reviewState.expandedId) return;

  const selectedBtn = document.querySelector('.review-btn.selected');
  if (!selectedBtn) {
    setReviewStatus('Please select confirm or override.', 'error');
    return;
  }
  const analystName = document.getElementById('review-analyst-name');
  if (!analystName || !analystName.value.trim()) {
    setReviewStatus('Please enter your name.', 'error');
    return;
  }

  const decision = selectedBtn.dataset.decision;
  const body = {
    analyst_decision: decision,
    notes: document.getElementById('review-notes') ? document.getElementById('review-notes').value : '',
    analyst_name: analystName.value.trim(),
  };

  if (decision === 'override') {
    const slider = document.getElementById('override-score-slider');
    const band = document.getElementById('override-band-select');
    body.override_score = slider ? parseInt(slider.value, 10) : null;
    body.override_band = band ? band.value : null;
  }

  setReviewStatus('Submitting...', '');

  try {
    const res = await _authFetch('/api/case/' + reviewState.expandedId + '/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error('Submit failed: ' + res.status);
    setReviewStatus('Review submitted successfully!', 'success');
    reviewState.expandedId = null;
    reviewState.caseData = null;
    setTimeout(function() {
      initReviewQueue();
      refreshQueue();
    }, 800);
  } catch (err) {
    setReviewStatus('Submit failed: ' + err.message, 'error');
  }
}

function setReviewStatus(msg, type) {
  const el = document.getElementById('review-submit-status');
  if (!el) return;
  el.textContent = msg;
  el.className = 'review-submit-status';
  if (type) el.classList.add('review-submit-' + type);
}
