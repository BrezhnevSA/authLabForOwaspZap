import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 8711);
const USERNAME = process.env.COMPLEX_AUTH_USERNAME || 'zapuser';
const PASSWORD = process.env.COMPLEX_AUTH_PASSWORD || 'ZapTest123!';
const CONTROL_TOKEN = process.env.TESTBED_CONTROL_TOKEN || 'zap-testbed-reset-v1';
const TOKEN_TTL_MS = Number(process.env.COMPLEX_AUTH_TOKEN_TTL_MS || 60 * 60 * 1000);

const expected = [
  { path: '/api/dashboard', discovery: 'plain-div-onclick-depth-1' },
  { path: '/api/orders', discovery: 'dropdown-div-onclick-depth-2' },
  { path: '/api/contracts', discovery: 'nested-dropdown-div-depth-3' },
  { path: '/api/archive', discovery: 'nested-dropdown-div-depth-3' },
  { path: '/api/customers', discovery: 'div-role-menuitem' },
  { path: '/api/reports', discovery: 'plain-div-onclick-depth-1' },
];
const expectedSet = new Set(expected.map((item) => item.path));

const state = {
  hits: new Map(),
  tokens: new Map(),
  resetAt: new Date().toISOString(),
  auth: {
    loginAttempts: 0,
    successfulLogins: 0,
    wrongContentType: 0,
    badCredentials: 0,
    validAuthenticatedRequests: 0,
    unauthorizedRequests: 0,
    expiredTokenRequests: 0,
  },
};

function now() { return new Date().toISOString(); }

function recordHit(pathname, method) {
  if (!expectedSet.has(pathname)) return;
  const old = state.hits.get(pathname) || { count: 0 };
  state.hits.set(pathname, { count: old.count + 1, method, lastAt: now() });
}

function bearerToken(req) {
  const header = String(req.get('authorization') || '');
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match ? match[1] : null;
}

function requireAuth(req, res, next) {
  const token = bearerToken(req);
  if (!token) {
    state.auth.unauthorizedRequests += 1;
    return res.status(401).json({ authenticated: false, error: 'BEARER_TOKEN_REQUIRED' });
  }

  const session = state.tokens.get(token);
  if (!session) {
    state.auth.unauthorizedRequests += 1;
    return res.status(401).json({ authenticated: false, error: 'INVALID_BEARER_TOKEN' });
  }

  if (Date.now() >= session.expiresAt) {
    state.tokens.delete(token);
    state.auth.expiredTokenRequests += 1;
    state.auth.unauthorizedRequests += 1;
    return res.status(401).json({ authenticated: false, error: 'BEARER_TOKEN_EXPIRED' });
  }

  state.auth.validAuthenticatedRequests += 1;
  req.authSession = session;
  next();
}

app.disable('x-powered-by');

app.get('/health', (_req, res) => res.json({ ok: true, app: 'complex-react-auth', port: PORT }));

app.post('/api/auth/login', (req, res, next) => {
  state.auth.loginAttempts += 1;
  if (!req.is('application/json')) {
    state.auth.wrongContentType += 1;
    return res.status(415).json({ authenticated: false, error: 'JSON_CONTENT_TYPE_REQUIRED' });
  }
  next();
}, express.json({ limit: '32kb' }), (req, res) => {
  const { username, password } = req.body || {};
  if (username !== USERNAME || password !== PASSWORD) {
    state.auth.badCredentials += 1;
    return res.status(401).json({ authenticated: false, error: 'BAD_CREDENTIALS' });
  }

  const token = crypto.randomBytes(24).toString('base64url');
  const expiresAt = Date.now() + TOKEN_TTL_MS;
  state.tokens.set(token, { username, issuedAt: Date.now(), expiresAt });
  state.auth.successfulLogins += 1;

  res.json({
    authenticated: true,
    access_token: token,
    token_type: 'Bearer',
    expires_in: Math.floor(TOKEN_TTL_MS / 1000),
    user: { username },
  });
});

app.get('/api/auth/currentUser', requireAuth, (req, res) => {
  res.json({ authenticated: true, username: req.authSession.username });
});

// Alias kept for the existing testbed Browser Based Auth poll configuration.
app.get('/api/whoami', requireAuth, (req, res) => {
  res.json({ authenticated: true, username: req.authSession.username });
});

function protectedMarker(pathname) {
  app.get(pathname, requireAuth, (req, res) => {
    recordHit(pathname, req.method);
    res.json({
      authenticated: true,
      endpoint: pathname,
      query: req.query,
      marker: 'COMPLEX_REACT_AUTH_PROTECTED',
    });
  });
}

for (const item of expected) protectedMarker(item.path);

app.get('/__testbed/expected', (_req, res) => {
  res.json({
    app: 'complex-react-auth',
    expected: expected.length,
    endpoints: expected,
    authModel: {
      loginPage: '/app/#/login',
      loginRequest: 'POST /api/auth/login as JSON',
      sessionTransport: 'Authorization: Bearer <access_token>',
      browserStorage: 'localStorage.access_token',
      formBasedExpected: 'FAIL',
      browserBasedWithSessionHeadersExpected: 'PASS',
    },
  });
});

app.get('/__testbed/coverage', (_req, res) => {
  const visited = expected.filter((item) => state.hits.has(item.path));
  const missing = expected.filter((item) => !state.hits.has(item.path));
  res.json({
    app: 'complex-react-auth',
    expected: expected.length,
    visited: visited.length,
    coveragePercent: expected.length ? Number(((visited.length / expected.length) * 100).toFixed(2)) : 100,
    visitedEndpoints: visited.map((item) => ({ ...item, ...state.hits.get(item.path) })),
    missingEndpoints: missing,
    authentication: { ...state.auth, activeTokens: state.tokens.size },
    resetAt: state.resetAt,
  });
});

// Intentionally not linked, not documented in the UI, and returns 404 without the private control header.
app.post('/__testbed/control/reset', (req, res) => {
  if (req.get('X-Testbed-Control') !== CONTROL_TOKEN) return res.sendStatus(404);
  state.hits.clear();
  state.tokens.clear();
  state.resetAt = now();
  for (const key of Object.keys(state.auth)) state.auth[key] = 0;
  res.json({ ok: true, app: 'complex-react-auth', resetAt: state.resetAt });
});

app.use('/app', express.static(path.join(__dirname, 'dist'), { index: false }));

app.get('/', (_req, res) => res.redirect('/app/#/login'));
app.get(['/app', '/app/'], (_req, res) => res.sendFile(path.join(__dirname, 'dist', 'index.html')));
app.get(/^\/app\/.*$/, (_req, res) => res.sendFile(path.join(__dirname, 'dist', 'index.html')));

app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[complex-react-auth] listening on ${PORT}`);
});
