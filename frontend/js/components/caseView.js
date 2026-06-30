// caseView.js — Case view rendering
function highlightYaml(yaml) {
  var html = escHtml(yaml);
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

  // Panel 4
  const p4 = document.getElementById('panel-4');
  p4.innerHTML = `
    <div class="panel-4-half">
      <div class="p4-section-title">Scoring Weight Itemisation</div>
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
}
