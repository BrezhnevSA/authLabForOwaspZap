const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const SCENARIO = process.env.SCENARIO || 'jwt-exp';
const USERNAME = 'zapuser';
const PASSWORD = 'ZapTest123!';
const tokens = new Map();
let loginCount = 0;
let checkCount = 0;
let protectedCount = 0;

const scenarioConfig = {
  'jwt-exp': { ttlSeconds: 12, format: 'jwt' },
  'timeout': { ttlSeconds: 120, format: 'opaque' },
  'check': { ttlSeconds: 8, format: 'opaque' }
};
const cfg = scenarioConfig[SCENARIO];
if (!cfg) throw new Error(`Unknown SCENARIO=${SCENARIO}`);

function json(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(body));
}
function html(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html><html><body style="font-family:sans-serif;max-width:760px;margin:48px auto">${body}</body></html>`);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch { resolve({}); }
    });
    req.on('error', reject);
  });
}
function b64url(value) {
  return Buffer.from(value).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function issueToken() {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + cfg.ttlSeconds;
  const id = crypto.randomUUID();
  let token;
  if (cfg.format === 'jwt') {
    token = `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify({ sub: USERNAME, iat: now, exp, jti: id }))}.`;
  } else {
    token = `zap-${SCENARIO}-${id}`;
  }
  tokens.set(token, { username: USERNAME, expiresAt: exp * 1000 });
  return { token, exp };
}
function bearer(req) {
  const auth = req.headers.authorization || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}
function validateToken(token) {
  const entry = token && tokens.get(token);
  if (!entry) return null;
  if (Date.now() >= entry.expiresAt) {
    tokens.delete(token);
    return null;
  }
  return entry;
}
function requireAuth(req, res, kind) {
  const entry = validateToken(bearer(req));
  if (!entry) {
    json(res, 401, { authenticated: false, scenario: SCENARIO, kind }, { 'WWW-Authenticate': 'Bearer realm="ZAP-SCRIPT-LAB"' });
    return null;
  }
  return entry;
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;

  if (path === '/health') return json(res, 200, { ok: true, scenario: SCENARIO, ttlSeconds: cfg.ttlSeconds, format: cfg.format });

  if (req.method === 'POST' && path === '/api/login') {
    const body = await readJson(req);
    if (body.username !== USERNAME || body.password !== PASSWORD) {
      return json(res, 401, { status: 'fail', message: 'bad credentials' });
    }
    loginCount += 1;
    const issued = issueToken();
    return json(res, 200, {
      status: 'success',
      auth_token: issued.token,
      token_type: 'Bearer',
      expires_in: cfg.ttlSeconds,
      expires_at: issued.exp,
      scenario: SCENARIO,
      login_count: loginCount
    });
  }

  if (req.method === 'GET' && path === '/me') {
    checkCount += 1;
    const entry = requireAuth(req, res, 'token-check');
    if (!entry) return;
    return json(res, 200, { authenticated: true, username: entry.username, scenario: SCENARIO, check_count: checkCount });
  }

  if (req.method === 'GET' && path === '/api/whoami') {
    protectedCount += 1;
    const entry = requireAuth(req, res, 'whoami');
    if (!entry) return;
    return json(res, 200, { authenticated: true, username: entry.username, scenario: SCENARIO, protected_count: protectedCount });
  }

  if (req.method === 'GET' && path === '/private') {
    protectedCount += 1;
    const entry = requireAuth(req, res, 'private');
    if (!entry) return;
    return html(res, 200, `<h1>AUTHENTICATED</h1><p>user=${entry.username}</p><p>scenario=${SCENARIO}</p><a href="/api/whoami">whoami</a>`);
  }

  if (req.method === 'GET' && path === '/api/stats') {
    let validTokens = 0;
    for (const [token] of tokens) if (validateToken(token)) validTokens += 1;
    return json(res, 200, { scenario: SCENARIO, loginCount, checkCount, protectedCount, validTokens, ttlSeconds: cfg.ttlSeconds });
  }

  if (req.method === 'POST' && path === '/logout') {
    const token = bearer(req);
    if (token) tokens.delete(token);
    return json(res, 200, { ok: true });
  }

  if (path === '/' || path === '/login') {
    return html(res, 200, `<h1>ZAP HttpSender token lab</h1><p>scenario=${SCENARIO}</p><p>POST JSON credentials to <code>/api/login</code>, then use <code>Authorization: Bearer ...</code> on <code>/api/whoami</code> or <code>/private</code>.</p>`);
  }

  return json(res, 404, { error: 'not found', scenario: SCENARIO });
}

http.createServer((req, res) => {
  handle(req, res).catch(err => {
    console.error(err);
    json(res, 500, { error: String(err), scenario: SCENARIO });
  });
}).listen(PORT, '0.0.0.0', () => console.log(`script-auth-token-lab scenario=${SCENARIO} port=${PORT}`));
