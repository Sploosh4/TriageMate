// api.js — Single responsibility: talk to the backend
const API_BASE = '/api';

async function fetchQueue() {
  const res = await fetch(`${API_BASE}/queue`);
  if (!res.ok) throw new Error(`Queue fetch failed: ${res.status}`);
  return res.json();
}

async function fetchCase(rowId) {
  const res = await fetch(`${API_BASE}/case/${rowId}`);
  if (!res.ok) throw new Error(`Case fetch failed: ${res.status}`);
  return res.json();
}

async function fetchMetrics() {
  const res = await fetch(`${API_BASE}/metrics`);
  if (!res.ok) throw new Error(`Metrics fetch failed: ${res.status}`);
  return res.json();
}
