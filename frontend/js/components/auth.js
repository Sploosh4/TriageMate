// auth.js — Authentication for TriageMate
// Provides login, token management, and auth-UI orchestration.
// Declares global functions consumed by api.js and app.js.

var AUTH_STORAGE_KEY = 'triagemate_auth';
var AUTH_REQUIRED = false;       // set after health check
var AUTH_LOADED = false;         // true once initial check completes

// ---------------------------------------------------------------------------
// Token storage helpers
// ---------------------------------------------------------------------------

function _getStored() {
  try {
    return JSON.parse(localStorage.getItem(AUTH_STORAGE_KEY));
  } catch (_) {
    return null;
  }
}

function _storeTokens(accessToken, refreshToken) {
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify({
    accessToken: accessToken,
    refreshToken: refreshToken,
    expiresAt: Date.now() + 25 * 60 * 1000  // slightly less than 30 min
  }));
}

function _clearTokens() {
  localStorage.removeItem(AUTH_STORAGE_KEY);
}

function getAccessToken() {
  var stored = _getStored();
  return stored ? stored.accessToken : null;
}

function isAuthenticated() {
  var stored = _getStored();
  if (!stored) return false;
  // Optimistic check — the server will reject expired tokens anyway
  return Date.now() < stored.expiresAt;
}

// ---------------------------------------------------------------------------
// Auth API calls
// ---------------------------------------------------------------------------

async function login(username, password) {
  var res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username, password: password })
  });
  if (!res.ok) {
    var errBody;
    try { errBody = await res.json(); } catch (_) { errBody = {}; }
    throw new Error(errBody.detail || 'Login failed');
  }
  var data = await res.json();
  _storeTokens(data.accessToken, data.refreshToken);
  return data;
}

async function refreshToken() {
  var stored = _getStored();
  if (!stored || !stored.refreshToken) {
    throw new Error('No refresh token available');
  }
  var res = await fetch('/api/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken: stored.refreshToken })
  });
  if (!res.ok) {
    _clearTokens();
    throw new Error('Token refresh failed');
  }
  var data = await res.json();
  _storeTokens(data.accessToken, data.refreshToken);
  return data;
}

function logout() {
  _clearTokens();
  location.reload();
}

// ---------------------------------------------------------------------------
// Auth status check
// ---------------------------------------------------------------------------

async function _checkAuthStatus() {
  // Ping health endpoint — it is always unauthenticated
  try {
    var hres = await fetch('/api/health', { cache: 'no-cache' });
    if (hres.ok) {
      var health = await hres.json();
      if (health.auth_required === true) {
        AUTH_REQUIRED = true;
        return { authRequired: true };
      }
      // auth_required is false → auth is disabled
      AUTH_REQUIRED = false;
      return { authRequired: false };
    }
  } catch (_) {
    // Backend not available — assume auth is required to be safe
  }

  // Fallback: try a protected endpoint to see if we get 401
  try {
    var token = getAccessToken();
    var headers = {};
    if (token) headers['Authorization'] = 'Bearer ' + token;
    var qres = await fetch('/api/queue', { headers: headers, cache: 'no-cache' });
    if (qres.ok) {
      AUTH_REQUIRED = false;
      return { authRequired: false };
    }
    if (qres.status === 401) {
      AUTH_REQUIRED = true;
      return { authRequired: true };
    }
  } catch (_) {
    // If queue also fails, assume auth is not blocking
  }

  AUTH_REQUIRED = false;
  return { authRequired: false };
}

// ---------------------------------------------------------------------------
// Login modal UI
// ---------------------------------------------------------------------------

function _showLoginModal() {
  var overlay = document.getElementById('auth-overlay');
  if (overlay) {
    overlay.classList.remove('hidden');
    document.getElementById('auth-username').focus();
  }
}

function _hideLoginModal() {
  var overlay = document.getElementById('auth-overlay');
  if (overlay) {
    overlay.classList.add('hidden');
  }
}

async function _handleLogin() {
  var username = document.getElementById('auth-username').value.trim();
  var password = document.getElementById('auth-password').value;
  var errorEl = document.getElementById('auth-error');
  var btn = document.getElementById('auth-login-btn');

  if (!username || !password) {
    errorEl.textContent = 'Please enter username and password';
    errorEl.classList.remove('hidden');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Signing in...';
  errorEl.classList.add('hidden');

  try {
    await login(username, password);
    _hideLoginModal();
    // Re-run initialisation now that we have a token
    if (typeof init === 'function') {
      init();
    }
  } catch (err) {
    errorEl.textContent = err.message || 'Login failed';
    errorEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign In';
  }
}

function _wireLoginUI() {
  var loginBtn = document.getElementById('auth-login-btn');
  if (loginBtn) {
    loginBtn.addEventListener('click', _handleLogin);
  }

  // Enter key in password field triggers login
  var passwordField = document.getElementById('auth-password');
  if (passwordField) {
    passwordField.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        _handleLogin();
      }
    });
  }

  // Enter key in username field moves to password
  var usernameField = document.getElementById('auth-username');
  if (usernameField) {
    usernameField.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('auth-password').focus();
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Public entry point — called from app.js after DOMContentLoaded
// ---------------------------------------------------------------------------

async function initAuth() {
  var status = await _checkAuthStatus();

  if (!status.authRequired) {
    AUTH_REQUIRED = false;
    AUTH_LOADED = true;
    return;  // no auth UI needed, proceed normally
  }

  AUTH_REQUIRED = true;

  if (isAuthenticated()) {
    AUTH_LOADED = true;
    return;  // already logged in, proceed
  }

  // Not authenticated — show login modal
  _wireLoginUI();
  _showLoginModal();
  AUTH_LOADED = true;
}

// Expose initAuth globally so app.js can call it
window.initAuth = initAuth;
