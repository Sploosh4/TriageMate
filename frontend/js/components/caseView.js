// caseView.js — Case view rendering
function highlightYaml(yaml) {
  let html = escHtml(yaml);
  html = html.replace(/^(\s*)([a-zA-Z_][-\w.]*?)(\s*:)/gm, '$1<span class="yaml-key">$2</span>$3');
  html = html.replace(/^(\s*-\s+)([a-zA-Z_][-\w.]+?)(\s*:)/gm, '$1<span class="yaml-key">$2</span>$3');
  html = html.replace(/(:\s*)&quot;([^&]*)&quot;/g, '$1<span class="yaml-string">&quot;$2&quot;</span>');
  html = html.replace(/(:\s*)&#39;([^&]*)&#39;/g, '$1<span class="yaml-string">&#39;$2&#39;</span>');
  html = html.replace(/(:\s*)(TRUE|FALSE|true|false)(\s|$|,)/g, '$1<span class="yaml-bool">$2</span>$3');
  html = html.replace(/(:\s*)(-?[0-9]+(?:\.[0-9]+)?)(\s|$)/g, '$1<span class="yaml-number">$2</span>$3');
  return html;
}

function renderCase(caseResponse) {
  const cv = caseResponse.caseView;

  // Panel 1
  const p1 = document.getElementById('panel-1');
  p1.className = '';
  if (cv.textConflict) p1.classList.add('text-conflict');

  p1.innerHTML = `
    <div class="prose">
      ${cv.summaryParagraphs.map(p => `<p>${escHtml(p)}</p>`).join('')}
      <div class="mission-tags">
        ${cv.missionPrevalence.map(t => `<span class="mission-tag">${escHtml(t)}</span>`).join('')}
      </div>
      <div class="mitre-row">
        ${cv.mitreTechniques.map(m => `<span class="mitre-badge"><span class="mitre-id">${escHtml(m.id)}</span> <span class="mitre-name">&mdash; ${escHtml(m.name)}</span></span>`).join('')}
      </div>
      ${cv.textConflictNote ? `<div class="tier-0-note">${cv.textConflictNote}</div>` : ''}
    </div>
  `;

  // Panel 2 accordions
  const accordionContainer = document.getElementById('accordion-container');
  accordionContainer.innerHTML = '';

  const accordions = [
    { id: 'scanner', label: 'Scanner Output', content: `<pre class="code-block">${escHtml(cv.scannerOutput)}</pre>` },
    { id: 'weakness', label: 'Weakness Logic Template', content: `<pre class="code-block">${highlightYaml(cv.weaknessTemplate)}</pre>` },
    { id: 'advisory', label: 'WASOC Advisory Reference', content: `<div class="advisory-quote"><strong>${escHtml(cv.advisoryRefId)}</strong><br><br>${escHtml(cv.advisoryQuote)}</div>` }
  ];

  accordions.forEach(a => {
    const div = document.createElement('div');
    div.className = 'accordion' + (a.id === 'scanner' ? ' open' : '');
    div.dataset.accordionId = a.id;
    div.innerHTML = `
      <button class="accordion-header">${escHtml(a.label)}</button>
      <div class="accordion-body">${a.content}</div>
    `;
    accordionContainer.appendChild(div);
  });

  // Panel 3
  document.getElementById('notes-textarea').value = cv.investigationNotes;

  // Score gauge
  const gaugeFill = document.getElementById('gauge-fill');
  gaugeFill.style.width = cv.scoreGaugeValue + '%';
  document.getElementById('gauge-score').textContent = cv.scoreGaugeValue + ' / 100';
  const gaugeBand = document.getElementById('gauge-band');
  gaugeBand.textContent = cv.scoreGaugeBand;
  gaugeBand.style.color = cv.gaugeBandColour;

  // Substitution block
  const subBlock = document.getElementById('substitution-block');
  if (cv.hasSubstitution && cv.substitutionBlock) {
    const sb = cv.substitutionBlock;
    subBlock.style.display = 'block';
    subBlock.className = 'substitution-block substituted';
    subBlock.innerHTML = `
      <span class="substitution-label">TriageMate Internal Alternate Metric Substituted</span>
      <div class="substitution-content">
        <strong>EPSS Score Substituted:</strong> ${sb.originalEpss} &rarr; ${sb.substitutedEpss} (Model confidence: ${sb.modelConfidence})<br>
        ${sb.reason}
      </div>
    `;
  } else {
    subBlock.className = 'substitution-block';
    subBlock.innerHTML = '';
    subBlock.style.display = 'none';
  }

  // Enrichment staleness badge
  let staleBadge = '';
  if (cv.nvdFreshness !== undefined && cv.nvdFreshness > 86400) {
    staleBadge = '<span class="enrichment-stale-badge">Enrichment Stale</span>';
  } else if (cv.nvdFreshness === -1) {
    staleBadge = '<span class="enrichment-stale-badge">Enrichment Stale</span>';
  }

  // Panel 4
  const p4 = document.getElementById('panel-4');
  p4.innerHTML = `
    <div class="panel-4-half">
      <div class="p4-section-title">Scoring Weight Itemisation ${staleBadge}</div>
      ${cv.scoringWeights.map(w => {
        let extra = '';
        if (w.isSubstituted) {
          extra = ' <span class="weight-sub-note">[Internal Metric Substituted]</span>';
        }
        return '<div class="weight-item">' +
          '<span class="weight-name">' + escHtml(w.name) + ':</span> ' +
          w.awarded + ' out of ' + w.max + ' points &mdash; ' +
          escHtml(w.justification) + '.' + extra +
        '</div>';
      }).join('')}
    </div>
    <div class="panel-4-half">
      <div class="p4-section-title">Asset Registry Entry</div>
      <div class="registry-list">
        ${cv.assetRegistry.map(entry => `
          <div class="registry-row">
            <span class="registry-label">${escHtml(entry.label)}</span>
            <span class="registry-value">${escHtml(entry.value)}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;

    // ── Panel 5: Security Context ────────────────────────────────
    renderSecurityContext(cv);
}

/**
 * Render Panel 5 — Security Telemetry + Network Context.
 */
function renderSecurityContext(cv) {
    const panel5 = document.getElementById('panel-5');
    if (!panel5) return;

    const telemetry = cv.telemetry || {};
    const networkCtx = cv.networkContext || {};

    // ── Telemetry content ─────────────────────────────────────────
    const contentDiv = document.getElementById('panel-5-content');
    let html = '<div class="telemetry-grid">';

    // Left column: Sentinel Incidents
    html += '<div class="telemetry-col">';
    html += '<div class="telemetry-col-title">Sentinel Incidents</div>';
    const incidents = telemetry.sentinel_incidents || [];
    if (incidents.length === 0) {
        html += '<div class="telemetry-no-data">No related Sentinel incidents detected.</div>';
    } else {
        incidents.forEach(function(inc) {
            var sev = (inc.severity || 'Informational').toLowerCase();
            html += '<div class="telemetry-incident severity-' + sev + '">';
            html += '<div class="telemetry-incident-title"><span class="severity-badge severity-' + sev + '">' + (inc.severity || '') + '</span> ' + (inc.title || '') + '</div>';
            html += '<div class="telemetry-incident-meta">' + (inc.incident_id || '') + ' &middot; ' + (inc.status || '') + ' &middot; ' + (inc.detected_at || '').split('T')[0] + '</div>';
            if (inc.mitre_techniques && inc.mitre_techniques.length) {
                html += '<div class="telemetry-incident-mitre">MITRE: ' + inc.mitre_techniques.join(', ') + '</div>';
            }
            html += '</div>';
        });
    }
    html += '</div>'; // end left col

    // Right column: EDR Process Evidence
    html += '<div class="telemetry-col">';
    html += '<div class="telemetry-col-title">EDR Process Evidence</div>';
    var processEv = telemetry.process_evidence || {};
    if (!processEv || processEv.evidence_quality === 'none') {
        html += '<div class="telemetry-no-data">No EDR process evidence available.</div>';
    } else {
        html += '<div class="process-evidence-box">';
        if (processEv.is_running) {
            html += '<div class="process-running">⚠ Vulnerable process IS running</div>';
        } else {
            html += '<div class="process-not-running">✓ Vulnerable process is NOT running</div>';
        }
        if (processEv.is_loaded) {
            html += '<div class="process-running" style="margin-top:4px;">⚠ Vulnerable module IS loaded</div>';
        } else if (processEv.evidence_quality !== 'none') {
            html += '<div class="process-not-running" style="margin-top:4px;">✓ Vulnerable module is NOT loaded</div>';
        }
        html += '<div class="evidence-quality">Evidence quality: <strong>' + (processEv.evidence_quality || 'none') + '</strong></div>';
        html += '</div>';

        // EDR alerts
        const alerts = telemetry.edr_alerts || [];
        if (alerts.length > 0) {
            html += '<div class="telemetry-col-title" style="margin-top:10px;">EDR Alerts</div>';
            alerts.forEach(function(a) {
                var sev = (a.severity || 'info').toUpperCase();
                html += '<div class="telemetry-alert">';
                html += '<div class="telemetry-alert-type">[' + sev + '] ' + (a.alert_type || '').replace(/_/g, ' ') + '</div>';
                html += '<div class="telemetry-alert-detail">' + (a.details || '') + '</div>';
                html += '</div>';
            });
        }
    }
    html += '</div>'; // end right col
    html += '</div>'; // end telemetry-grid

    // ── Network Context ───────────────────────────────────────────
    var ncHtml = '';
    if (!networkCtx || !networkCtx.zone) {
        ncHtml = '<div class="telemetry-no-data">Network context data not available.</div>';
    } else {
        var zoneClass = networkCtx.zone === 'dmz' ? 'zone-dmz' : networkCtx.zone === 'protected' ? 'zone-protected' : networkCtx.zone === 'restricted' ? 'zone-restricted' : 'zone-internal';
        var blastClass = networkCtx.blastRadiusScore > 0.5 ? 'high' : networkCtx.blastRadiusScore > 0.2 ? 'medium' : 'low';
        var blastPct = Math.min(100, Math.round((networkCtx.blastRadiusScore || 0) * 100));

        ncHtml += '<div class="network-context-grid">';
        ncHtml += '<div><span class="network-zone-badge ' + zoneClass + '">' + (networkCtx.zoneDisplay || networkCtx.zone) + '</span></div>';
        ncHtml += '<div class="network-stat"><span class="network-stat-value">' + (networkCtx.peerCount || 0) + '</span><span class="network-stat-label">Reachable Peers</span></div>';
        ncHtml += '<div class="network-stat"><span class="network-stat-value">' + (networkCtx.internetFacingPeers || 0) + '</span><span class="network-stat-label">Internet-Facing</span></div>';
        ncHtml += '<div class="network-stat"><span class="network-stat-value">' + (networkCtx.dcPeers || 0) + '</span><span class="network-stat-label">Domain Controllers</span></div>';
        ncHtml += '<div class="blast-radius-bar">';
        ncHtml += '<div class="blast-radius-label"><span>Blast Radius</span><span class="blast-radius-percent">' + blastPct + '%</span></div>';
        ncHtml += '<div class="blast-radius-track"><div class="blast-radius-fill ' + blastClass + '" style="width:' + blastPct + '%;"></div></div>';
        ncHtml += '</div>';
        ncHtml += '<div style="font-size:11px;color:var(--text-muted);font-variant:small-caps;">Source: ' + (networkCtx.dataSource || 'heuristic') + '</div>';
        ncHtml += '</div>';
    }

    contentDiv.innerHTML = html;
    document.getElementById('network-context-section').innerHTML = ncHtml;
}
