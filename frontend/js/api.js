// api.js — Single responsibility: talk to the backend
// Supports Bearer token auth via auth.js global functions.

var API_BASE = '/api';

// ---------------------------------------------------------------------------
// Helper: fetch with automatic Bearer token + 401 refresh + retry
// ---------------------------------------------------------------------------

async function _authFetch(url, options) {
  options = options || {};
  options.headers = options.headers || {};

  // Attach token if available
  if (typeof getAccessToken === 'function') {
    var token = getAccessToken();
    if (token) {
      options.headers['Authorization'] = 'Bearer ' + token;
    }
  }

  var res = await fetch(url, options);

  // On 401, attempt token refresh and retry once
  if (res.status === 401 && typeof refreshToken === 'function') {
    try {
      await refreshToken();
      var newToken = getAccessToken();
      if (newToken) {
        options.headers['Authorization'] = 'Bearer ' + newToken;
      }
      var retryRes = await fetch(url, options);
      if (!retryRes.ok) {
        throw new Error('Request failed: ' + retryRes.status);
      }
      return retryRes;
    } catch (refreshErr) {
      if (typeof logout === 'function') {
        logout();
      }
      throw refreshErr;
    }
  }

  if (!res.ok) {
    throw new Error('Request failed: ' + res.status);
  }
  return res;
}

// ---------------------------------------------------------------------------
// Public API functions
// ---------------------------------------------------------------------------

async function fetchQueue() {
  var res = await _authFetch(API_BASE + '/queue');
  return res.json();
}

async function fetchCase(rowId) {
  var res = await _authFetch(API_BASE + '/case/' + rowId);
  return res.json();
}

async function fetchMetrics() {
  var res = await _authFetch(API_BASE + '/metrics');
  return res.json();
}

async function saveNotes(caseId, notes) {
  var res = await _authFetch(API_BASE + '/case/' + caseId + '/notes', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notes: notes })
  });
  return res.json();
}
