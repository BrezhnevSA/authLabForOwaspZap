'use strict';

const http = require('node:http');
const { randomBytes, createHash, timingSafeEqual } = require('node:crypto');
const { DEFAULT_SECRET, decodeBase32, verifyTotp } = require('./totp');

const USERNAME = process.env.TOTP_USERNAME || 'zapuser';
const PASSWORD = process.env.TOTP_PASSWORD || 'ZapTest123!';
const SECRET = process.env.TOTP_SECRET || DEFAULT_SECRET;
const CONTROL_TOKEN = process.env.TESTBED_CONTROL_TOKEN || 'zap-testbed-reset-v1';
const COOKIE_SECURE = (process.env.COOKIE_SECURE || 'auto').toLowerCase();
const PORT = Number(process.env.PORT || 3000);
const PENDING_TTL = 3 * 60 * 1000;
const SESSION_TTL = 60 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;
const EXPECTED = ['/login', '/2fa', '/private', '/api/whoami', '/api/profile', '/api/orders'];
// Fail during startup if the configured secret is invalid.
decodeBase32(SECRET);

function equalSecret(a, b) {
  const x = createHash('sha256').update(String(a)).digest();
  const y = createHash('sha256').update(String(b)).digest();
  return timingSafeEqual(x, y);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function page(title, content) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)} | ZAP TOTP lab</title><style>body{background:#f5f7fa;color:#1c2737;font:16px system-ui,sans-serif;line-height:1.5;margin:4rem auto;max-width:32rem;padding:0 1rem}main{background:#fff;border:1px solid #d8e0eb;border-radius:14px;padding:2rem;box-shadow:0 5px 18px #1422370c}h1{font-size:1.6rem;margin-top:0}label{display:block;margin:1rem 0 .4rem}input{box-sizing:border-box;display:block;width:100%;padding:.7rem;border-radius:7px;border:1px solid #9cabbc;font:inherit}button{background:#265ac2;color:#fff;padding:.7rem 1.4rem;border:0;border-radius:8px;font:inherit;cursor:pointer;margin-top:1rem}a{color:#265ac2}.muted{color:#637084}.error{color:#a32828}code{overflow-wrap:anywhere}li{margin:.4rem 0}</style></head><body><main>${content}</main></body></html>`;
}
function loginPage(error = '') {
  return page('Sign in', `<h1>Sign in</h1><p>Two-factor authentication lab · step 1 of 2</p>${error ? `<p class="error">${esc(error)}</p>` : ''}<form action="/login" method="post"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Continue</button></form>`);
}
function otpPage(error = '') {
  return page('Verify code', `<h1>Authenticator code</h1><p>Step 2 of 2 · Enter the six-digit code from your authenticator app.</p>${error ? `<p class="error">${esc(error)}</p>` : ''}<form action="/2fa" method="post"><label for="otp">One-time code</label><input id="otp" name="otp" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required autofocus><button type="submit">Verify and sign in</button></form><p class="muted"><a href="/2fa/setup">Set up authenticator</a></p>`);
}
function setupPage() {
  const uri = `otpauth://totp/${encodeURIComponent('ZAP TOTP Lab:' + USERNAME)}?secret=${encodeURIComponent(SECRET)}&issuer=${encodeURIComponent('ZAP TOTP Lab')}&algorithm=SHA1&digits=6&period=30`;
  return page('Set up authenticator', `<h1>Set up authenticator</h1><p>This is a <strong>test-only</strong> shared secret. Add an account manually in Google Authenticator, Microsoft Authenticator, Aegis, or another TOTP app.</p><p><strong>Account:</strong> ${esc(USERNAME)}<br><strong>Secret (base32):</strong><br><code>${esc(SECRET)}</code></p><details><summary>otpauth URI (for provisioning)</summary><code>${esc(uri)}</code></details><p>Type: time-based, SHA-1, 6 digits, 30 seconds.</p><a href="/2fa">Back to verification</a>`);
}
function cookies(req) {
  const result = {};
  for (const entry of (req.headers.cookie || '').split(';')) {
    const idx = entry.indexOf('=');
    if (idx > 0) result[entry.slice(0, idx).trim()] = entry.slice(idx + 1).trim();
  }
  return result;
}
function cookie(req, name, value, age) {
  const secure = COOKIE_SECURE === 'true' || (COOKIE_SECURE === 'auto' && req.headers['x-forwarded-proto'] === 'https');
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}${age != null ? `; Max-Age=${age}` : ''}`;
}
function respond(res, status, body, type = 'text/html; charset=utf-8', extra = {}) {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'no-referrer', 'X-Frame-Options':'DENY', ...extra });
  res.end(body);
}
function json(res, status, obj) { respond(res, status, JSON.stringify(obj), 'application/json; charset=utf-8'); }
function redirect(res, where, headers = {}) { respond(res, 303, '', 'text/plain; charset=utf-8', {'Location':where, ...headers}); }
function readForm(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 8192) { reject(Object.assign(new Error('Payload too large'), {status:413})); req.destroy(); }
    });
    req.on('end', () => {
      try {
        if ((req.headers['content-type'] || '').includes('application/json')) resolve(JSON.parse(body || '{}'));
        else resolve(Object.fromEntries(new URLSearchParams(body)));
      } catch { reject(Object.assign(new Error('Invalid payload'), {status:400})); }
    });
    req.on('error', reject);
  });
}
function app() {
  const sessions = new Map();
  const pending = new Map();
  const hits = new Map();
  const auth = {loginAttempts:0, failedLogins:0, otpChallenges:0, otpAttempts:0, invalidOtp:0, successfulLogins:0, authenticatedRequests:0, unauthorizedRequests:0, logoutCount:0};
  let lastAccepted = -1;
  function hit(path) { if (EXPECTED.includes(path)) hits.set(path, (hits.get(path) || 0) + 1); }
  function activeSession(req) {
    const id = cookies(req).zap2fa_session;
    const item = id && sessions.get(id);
    if (!item) return null;
    if (item.expiresAt <= Date.now()) { sessions.delete(id); return null; }
    return item;
  }
  function activePending(req) {
    const id = cookies(req).zap2fa_pending;
    const item = id && pending.get(id);
    if (!item) return null;
    if (item.expiresAt <= Date.now()) { pending.delete(id); return null; }
    return { id, ...item };
  }
  function reset() {
    sessions.clear(); pending.clear(); hits.clear(); lastAccepted = -1;
    Object.keys(auth).forEach(k => { auth[k] = 0; });
  }
  function privateGuard(req, res) {
    const session = activeSession(req);
    if (!session) { auth.unauthorizedRequests++; return null; }
    auth.authenticatedRequests++;
    return session;
  }
  async function route(req, res) {
    const path = new URL(req.url, 'http://localhost').pathname;
    if (req.method === 'GET' && path === '/health') return json(res, 200, {ok:true, application:'totp-2fa'});
    if (req.method === 'GET' && path === '/__testbed/expected') return json(res, 200, {application:'totp-2fa', expectedEndpoints:EXPECTED});
    if (req.method === 'GET' && path === '/__testbed/coverage') {
      const visited = EXPECTED.filter(p => hits.has(p));
      return json(res, 200, {application:'totp-2fa', discovery:{expected:EXPECTED.length,visited:visited.length,coveragePercent:Number((100 * visited.length / EXPECTED.length).toFixed(2)),visitedEndpoints:visited,missingEndpoints:EXPECTED.filter(p => !hits.has(p))}, authentication:{...auth,activeSessions:sessions.size,pendingChallenges:pending.size}});
    }
    if (req.method === 'POST' && path === '/__testbed/control/reset') {
      if (!equalSecret(req.headers['x-testbed-control'] || '', CONTROL_TOKEN)) return json(res, 404, {error:'not found'});
      reset(); return json(res, 200, {reset:true, application:'totp-2fa'});
    }
    if (path === '/' && req.method === 'GET') return redirect(res, activeSession(req) ? '/private' : '/login');
    if (path === '/login' && req.method === 'GET') { hit(path); return respond(res, 200, loginPage()); }
    if (path === '/login' && req.method === 'POST') {
      hit(path); auth.loginAttempts++;
      const form = await readForm(req);
      if (form.username !== USERNAME || !equalSecret(form.password || '', PASSWORD)) {
        auth.failedLogins++;
        return respond(res, 401, loginPage('Invalid username or password'));
      }
      const id = randomBytes(32).toString('hex');
      pending.set(id, {username:USERNAME, expiresAt:Date.now() + PENDING_TTL, attempts:0});
      auth.otpChallenges++;
      return redirect(res, '/2fa', {'Set-Cookie':cookie(req, 'zap2fa_pending', id, 180)});
    }
    if (path === '/2fa' && req.method === 'GET') {
      hit(path);
      if (!activePending(req)) return redirect(res, '/login');
      return respond(res, 200, otpPage());
    }
    if (path === '/2fa/setup' && req.method === 'GET') {
      if (!activePending(req)) return redirect(res, '/login');
      return respond(res, 200, setupPage());
    }
    if (path === '/2fa' && req.method === 'POST') {
      hit(path);
      const state = activePending(req);
      if (!state) return json(res, 401, {authenticated:false, error:'No valid first-factor challenge'});
      const form = await readForm(req);
      auth.otpAttempts++;
      const accepted = verifyTotp(form.otp, SECRET, Date.now(), lastAccepted);
      if (accepted === null) {
        auth.invalidOtp++;
        const original = pending.get(state.id);
        original.attempts++;
        if (original.attempts >= MAX_OTP_ATTEMPTS) {
          pending.delete(state.id);
          return respond(res, 401, loginPage('Too many invalid codes. Sign in again'), 'text/html; charset=utf-8', {'Set-Cookie':cookie(req, 'zap2fa_pending', '', 0)});
        }
        return respond(res, 401, otpPage('Invalid, expired, or already used code'));
      }
      lastAccepted = accepted;
      pending.delete(state.id);
      const sid = randomBytes(32).toString('hex');
      sessions.set(sid, {username:state.username, expiresAt:Date.now() + SESSION_TTL});
      auth.successfulLogins++;
      return redirect(res, '/private', {'Set-Cookie':[cookie(req, 'zap2fa_pending', '', 0), cookie(req, 'zap2fa_session', sid, 3600)]});
    }
    if (path === '/logout' && req.method === 'POST') {
      const vals = cookies(req);
      if (vals.zap2fa_session) sessions.delete(vals.zap2fa_session);
      if (vals.zap2fa_pending) pending.delete(vals.zap2fa_pending);
      auth.logoutCount++;
      return redirect(res, '/login', {'Set-Cookie':[cookie(req, 'zap2fa_session', '', 0), cookie(req, 'zap2fa_pending', '', 0)]});
    }
    if (path === '/private' && req.method === 'GET') {
      hit(path);
      const user = privateGuard(req, res);
      if (!user) return respond(res, 401, page('Access denied', '<h1>401 · Authentication required</h1><a href="/login">Sign in</a>'));
      return respond(res, 200, page('Private area', `<h1>AUTHENTICATED</h1><p>Welcome, ${esc(user.username)}. Both factors have been verified.</p><ul><li><a href="/api/profile">API profile</a></li><li><a href="/api/orders">API orders</a></li></ul><form action="/logout" method="post"><button type="submit">Logout</button></form>`));
    }
    if (req.method === 'GET' && ['/api/whoami','/api/profile','/api/orders'].includes(path)) {
      hit(path);
      const user = privateGuard(req, res);
      if (!user) return json(res, 401, {authenticated:false, error:'Both factors required'});
      return json(res, 200, {authenticated:true, username:user.username, mfa:true, factor:'totp', endpoint:path, data:path === '/api/orders' ? [{id:'ZAP-001',item:'synthetic test data'}] : path === '/api/profile' ? {role:'tester',lab:'zap'} : undefined});
    }
    return json(res, 404, {error:'not found'});
  }
  return http.createServer((req, res) => {
    Promise.resolve().then(() => route(req,res)).catch(e => {
      if (!res.headersSent && !res.destroyed) json(res, e.status || 500, {error:e.status ? e.message : 'internal server error'});
      if (!e.status) console.error(e);
    });
  });
}
module.exports = { app };
if (require.main === module) app().listen(PORT, '0.0.0.0', () => console.log(`ZAP TOTP lab listening on ${PORT}`));
