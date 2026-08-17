const http = require('http');
const { randomUUID } = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const SCENARIO = process.env.SCENARIO || 'delayed-render';
const USERNAME = 'zapuser';
const PASSWORD = 'ZapTest123!';
const OTP = '123456';

const sessions = new Map();
const pending = new Map();

function html(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
  res.end(`<!doctype html><html><head><meta charset="utf-8"><title>ZAP auth: ${SCENARIO}</title>
<style>body{font-family:sans-serif;max-width:720px;margin:48px auto;padding:0 16px}label{display:block;margin:12px 0}input,button{font:inherit;padding:8px}iframe{width:100%;height:320px;border:1px solid #aaa}</style></head><body>${body}</body></html>`);
}

function json(res, status, obj, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(obj));
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, { Location: location, ...headers });
  res.end();
}

function cookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function currentUser(req) {
  const sid = cookies(req).zap_edge_sid;
  return sid && sessions.get(sid) || null;
}

function loginHeaders(username) {
  const sid = randomUUID();
  sessions.set(sid, username);
  return { 'Set-Cookie': `zap_edge_sid=${encodeURIComponent(sid)}; Path=/; HttpOnly; SameSite=Lax` };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1024 * 1024) req.destroy();
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

async function fields(req) {
  const body = await readBody(req);
  if ((req.headers['content-type'] || '').includes('application/json')) {
    try { return JSON.parse(body || '{}'); } catch { return {}; }
  }
  return Object.fromEntries(new URLSearchParams(body));
}

function standardLoginForm(action = '/login', extra = '') {
  return `<h1>${SCENARIO}</h1><form method="post" action="${action}">
<label>Username <input name="username" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label>
${extra}<button type="submit">Sign in</button></form>`;
}

function invalid(res, back = '/login') {
  html(res, 401, `<h1>Login failed</h1><p>Invalid credentials.</p><a href="${back}">Try again</a>`);
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;

  if (req.method === 'GET' && path === '/api/whoami') {
    const user = currentUser(req);
    return json(res, 200, user
      ? { authenticated: true, username: user, technology: 'node-http', scenario: SCENARIO }
      : { authenticated: false, technology: 'node-http', scenario: SCENARIO });
  }

  if (req.method === 'GET' && path === '/private') {
    const user = currentUser(req);
    if (!user) return json(res, 401, { authenticated: false, error: 'login required', scenario: SCENARIO });
    return html(res, 200, `<h1>AUTHENTICATED</h1><p>user=${user}</p><p>scenario=${SCENARIO}</p><a href="/logout">Logout</a>`);
  }

  if (req.method === 'GET' && path === '/logout') {
    const sid = cookies(req).zap_edge_sid;
    if (sid) sessions.delete(sid);
    return redirect(res, SCENARIO === 'hash-spa' ? '/#/signin' : '/login', {
      'Set-Cookie': 'zap_edge_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
    });
  }

  if (SCENARIO === 'delayed-render') {
    if (req.method === 'GET' && (path === '/' || path === '/login')) {
      return html(res, 200, `<h1>Delayed render login</h1><p>The form appears after 2.5 seconds.</p><div id="root">Loading sign-in UI…</div>
<script>setTimeout(()=>{document.getElementById('root').innerHTML=${JSON.stringify(standardLoginForm('/login'))}},2500)</script>`);
    }
    if (req.method === 'POST' && path === '/login') {
      const f = await fields(req);
      if (f.username === USERNAME && f.password === PASSWORD) return redirect(res, '/private', loginHeaders(USERNAME));
      return invalid(res);
    }
  }

  if (SCENARIO === 'nonstandard-fields') {
    if (req.method === 'GET' && (path === '/' || path === '/login')) {
      return html(res, 200, `<h1>Non-standard field names</h1><form method="post" action="/session/start">
<label>Account reference <input id="account-ref" name="employeeIdentifier" autocomplete="off"></label>
<label>Secret phrase <input id="secret-phrase" type="password" name="accessPhrase" autocomplete="off"></label>
<button type="submit">Continue</button></form>`);
    }
    if (req.method === 'POST' && path === '/session/start') {
      const f = await fields(req);
      if (f.employeeIdentifier === USERNAME && f.accessPhrase === PASSWORD) return redirect(res, '/private', loginHeaders(USERNAME));
      return invalid(res);
    }
  }

  if (SCENARIO === 'hash-spa') {
    if (req.method === 'GET' && (path === '/' || path === '/login')) {
      return html(res, 200, `<div id="app"></div>
<script>
const app=document.getElementById('app');
function render(){
  if(location.hash==='#/signin'){
    app.innerHTML='<h1>Hash-router SPA login</h1><form id="loginForm"><label>Username <input id="username" autocomplete="username"></label><label>Password <input id="password" type="password" autocomplete="current-password"></label><button>Sign in</button></form><p id="error"></p>';
    document.getElementById('loginForm').addEventListener('submit', async e=>{e.preventDefault();const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});if(r.ok){location.hash='#/dashboard';}else{document.getElementById('error').textContent='Login failed';}});
  } else if(location.hash==='#/dashboard') {
    app.innerHTML='<h1>Dashboard</h1><p>SPA navigation completed.</p><a href="/private">Protected server resource</a>';
  } else {
    app.innerHTML='<h1>Public SPA page</h1><a id="signin" href="#/signin">Sign in</a>';
  }
}
addEventListener('hashchange',render);render();
</script>`);
    }
    if (req.method === 'POST' && path === '/api/login') {
      const f = await fields(req);
      if (f.username === USERNAME && f.password === PASSWORD) return json(res, 200, { ok: true }, loginHeaders(USERNAME));
      return json(res, 401, { ok: false });
    }
  }

  if (SCENARIO === 'enter-submit') {
    if (req.method === 'GET' && (path === '/' || path === '/login')) {
      return html(res, 200, `<h1>Enter-only JavaScript login</h1><p>There is intentionally no submit button and no HTML form.</p>
<label>User <input id="userBox" autocomplete="username"></label>
<label>Pass <input id="passBox" type="password" autocomplete="current-password"></label><p id="msg">Press Enter in the password field to submit.</p>
<script>
document.getElementById('passBox').addEventListener('keydown',async e=>{if(e.key!=='Enter')return;const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('userBox').value,password:document.getElementById('passBox').value})});if(r.ok)location.href='/private';else document.getElementById('msg').textContent='Login failed';});
</script>`);
    }
    if (req.method === 'POST' && path === '/api/login') {
      const f = await fields(req);
      if (f.username === USERNAME && f.password === PASSWORD) return json(res, 200, { ok: true }, loginHeaders(USERNAME));
      return json(res, 401, { ok: false });
    }
  }

  if (SCENARIO === 'iframe-login') {
    if (req.method === 'GET' && (path === '/' || path === '/login')) {
      return html(res, 200, `<h1>Login hosted in an iframe</h1><p>The top document contains no credential inputs.</p><iframe title="Authentication" src="/embedded-login"></iframe>`);
    }
    if (req.method === 'GET' && path === '/embedded-login') {
      return html(res, 200, standardLoginForm('/login'));
    }
    if (req.method === 'POST' && path === '/login') {
      const f = await fields(req);
      if (f.username === USERNAME && f.password === PASSWORD) return redirect(res, '/private', loginHeaders(USERNAME));
      return invalid(res);
    }
  }

  if (SCENARIO === 'otp-challenge') {
    if (req.method === 'GET' && (path === '/' || path === '/login')) {
      return html(res, 200, standardLoginForm('/login'));
    }
    if (req.method === 'POST' && path === '/login') {
      const f = await fields(req);
      if (f.username !== USERNAME || f.password !== PASSWORD) return invalid(res);
      const tx = randomUUID();
      pending.set(tx, USERNAME);
      return redirect(res, `/otp?tx=${encodeURIComponent(tx)}`);
    }
    if (req.method === 'GET' && path === '/otp') {
      const tx = url.searchParams.get('tx') || '';
      if (!pending.has(tx)) return html(res, 400, '<h1>Expired challenge</h1>');
      return html(res, 200, `<h1>One-time code</h1><p>Test fixture OTP is documented in the test matrix, but is not present in this page.</p>
<form method="post" action="/otp"><input type="hidden" name="tx" value="${tx.replaceAll('&','&amp;').replaceAll('"','&quot;')}"><label>Verification code <input name="otp" inputmode="numeric" autocomplete="one-time-code"></label><button type="submit">Verify</button></form>`);
    }
    if (req.method === 'POST' && path === '/otp') {
      const f = await fields(req);
      const user = pending.get(f.tx);
      if (!user || f.otp !== OTP) return html(res, 401, '<h1>OTP failed</h1>');
      pending.delete(f.tx);
      return redirect(res, '/private', loginHeaders(user));
    }
  }

  return json(res, 404, { error: 'not found', scenario: SCENARIO });
}

http.createServer((req, res) => {
  handle(req, res).catch(err => {
    console.error(err);
    json(res, 500, { error: 'internal error', scenario: SCENARIO });
  });
}).listen(PORT, '0.0.0.0', () => {
  console.log(`ZAP auth edge case '${SCENARIO}' listening on ${PORT}`);
});
