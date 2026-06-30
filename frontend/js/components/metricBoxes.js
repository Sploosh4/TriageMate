// metricBoxes.js — Summary metric boxes
function updateMetricBoxes(rows) {
  var criticalCount = rows.filter(function(r) { return r.riskBand === 'Very Critical'; }).length;
  document.getElementById('count-critical').textContent = criticalCount;
  var criticalBox = document.querySelector('.metric-box.critical');
  criticalBox.classList.toggle('empty', criticalCount === 0);
  criticalBox.querySelector('.metric-box-subtitle').textContent = criticalCount === 0 ? 'No critical items in queue' : 'Require immediate attention';
  criticalBox.setAttribute('aria-label', 'Critical actions: ' + criticalCount + ' items requiring immediate attention');

  var lowConfCount = rows.filter(function(r) {
    if (r.tier === 'SLM Tier') return true;
    if (r.tier === 'ML Tier') {
      var m = r.detectionReason.match(/ML confidence ([0-9.]+)/);
      if (m && parseFloat(m[1]) < 0.85) return true;
    }
    return false;
  }).length;
  document.getElementById('count-low-confidence').textContent = lowConfCount;
  var lowConfBox = document.querySelector('.metric-box.low-conf');
  lowConfBox.classList.toggle('empty', lowConfCount === 0);
  lowConfBox.querySelector('.metric-box-subtitle').textContent = lowConfCount === 0 ? 'All predictions confident' : 'AI certainty below threshold';
  lowConfBox.setAttribute('aria-label', 'Low confidence: ' + lowConfCount + ' predictions below AI certainty threshold');

  var exposedCount = rows.filter(function(r) {
    return (r.interfaceType || '').toLowerCase().indexOf('internet-facing') !== -1;
  }).length;
  document.getElementById('count-exposed').textContent = exposedCount;
  var exposedBox = document.querySelector('.metric-box.exposed');
  exposedBox.classList.toggle('empty', exposedCount === 0);
  exposedBox.querySelector('.metric-box-subtitle').textContent = exposedCount === 0 ? 'No external exposure detected' : 'Internet-facing vulnerable assets';
  exposedBox.setAttribute('aria-label', 'Exposed: ' + exposedCount + ' internet-facing vulnerable assets');

  var humanValCount = rows.filter(function(r) { return r.tier === 'SLM Tier'; }).length;
  document.getElementById('count-human-validation').textContent = humanValCount;
  var humanValBox = document.querySelector('.metric-box.human-val');
  humanValBox.classList.toggle('empty', humanValCount === 0);
  humanValBox.querySelector('.metric-box-subtitle').textContent = humanValCount === 0 ? 'Queue fully processed' : 'Escalated for analyst review';
  humanValBox.setAttribute('aria-label', 'Needs human validation: ' + humanValCount + ' cases escalated for analyst review');
}
