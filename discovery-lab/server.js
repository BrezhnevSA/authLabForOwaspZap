'use strict';

const http = require('http');
const { URL } = require('url');

const SCENARIO = process.env.SCENARIO || 'large-bundle-spa';
const PORT = Number(process.env.PORT || 8705);
const CONTROL_TOKEN = process.env.TESTBED_CONTROL_TOKEN || 'zap-testbed-reset-v1';

const state = {
  hits: new Map(),
  noise: new Map(),
  startedAt: new Date().toISOString(),
  resetAt: new Date().toISOString(),
};

const configs = {
  'large-bundle-spa': {
    name: '8705-large-bundle-spa',
    expected: ['/api/bootstrap', '/api/orders', '/api/lazy-reports'],
    note: 'Boundary test around ZAP response-body storage limits. Default bundles are 900 KiB, 1150 KiB and a lazy 1250 KiB bundle; 4 MiB is opt-in only.',
  },
  'many-states-spa': {
    name: '8706-many-states-spa',
    expected: Array.from({ length: 15 }, (_, i) => `/api/state/${String(i + 1).padStart(2, '0')}`),
    note: 'Fifteen sequential DOM states. Useful for maxCrawlStates/maxCrawlDepth regression testing.',
  },
  'runtime-discovery-spa': {
    name: '8707-runtime-discovery-spa',
    expected: [
      '/api/runtime/onload',
      '/api/runtime/custom-element',
      '/api/runtime/div-role',
      '/api/runtime/modal',
      '/api/runtime/hash-route',
      '/api/runtime/iframe',
    ],
    note: 'Endpoints are assembled at runtime and triggered by non-uniform UI interactions.',
  },
  'large-api-response': {
    name: '8708-large-api-response',
    expected: ['/api/size/100k', '/api/size/900k', '/api/size/1150k'],
    note: 'API responses straddle the 1 MiB boundary. A 4 MiB endpoint exists only as an opt-in stress URL.',
  },
  'bft-regression-spa': {
    name: '8709-bft-regression-spa',
    expected: [
      '/api/session/bootstrap',
      '/api/dashboard/summary',
      '/rest/orders',
      '/service/contracts',
      '/api/documents',
      '/rest/reports',
      '/service/tasks',
      '/api/search',
      '/rest/settings',
      '/service/audit',
    ],
    note: 'Composite SPA regression: hash routing, custom elements, runtime URLs, cross-path APIs and nested actions.',
  },
  'scope-noise': {
    name: '8710-scope-noise',
    expected: ['/api/local/a', '/api/local/b', '/api/local/c'],
    note: 'Target page deliberately loads resources from three same-container DNS aliases to reveal out-of-scope crawler pollution.',
  },
};

const config = configs[SCENARIO];
if (!config) {
  throw new Error(`Unknown SCENARIO=${SCENARIO}`);
}
const expectedSet = new Set(config.expected);

function now() {
  return new Date().toISOString();
}

function record(map, key, method) {
  const previous = map.get(key) || { count: 0 };
  map.set(key, { count: previous.count + 1, method, lastAt: now() });
}

function mainHost(req) {
  return String(req.headers.host || '').split(':')[0].toLowerCase();
}

function track(req, pathname) {
  if (expectedSet.has(pathname)) {
    record(state.hits, pathname, req.method);
  }
  if (SCENARIO === 'scope-noise') {
    const host = mainHost(req);
    if (host && !['scope-noise', '127.0.0.1', 'localhost'].includes(host) && pathname.startsWith('/noise/')) {
      record(state.noise, `${host}${pathname}`, req.method);
    }
  }
}

function send(res, status, body, type = 'text/plain; charset=utf-8', extra = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(status, {
    'Content-Type': type,
    'Content-Length': buf.length,
    'Cache-Control': 'no-store',
    ...extra,
  });
  res.end(buf);
}

function json(res, status, value, extra = {}) {
  send(res, status, JSON.stringify(value, null, 2), 'application/json; charset=utf-8', extra);
}

function padJs(source, targetBytes) {
  const current = Buffer.byteLength(source);
  if (current >= targetBytes) return source;
  const filler = Math.max(0, targetBytes - current - 8);
  return `${source}\n/*${'x'.repeat(filler)}*/\n`;
}

function htmlPage(title, body, scripts = []) {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>${title}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 20px}button,[role=button],bft-menu-item,runtime-action{display:inline-block;margin:6px;padding:10px 14px;border:1px solid #777;border-radius:6px;cursor:pointer}pre{background:#eee;padding:12px;white-space:pre-wrap}.panel{padding:16px;border:1px solid #bbb;margin:12px 0}.menu{display:flex;flex-wrap:wrap;gap:4px}
</style></head><body><h1>${title}</h1>${body}${scripts.map(src => `<script src="${src}" defer></script>`).join('')}</body></html>`;
}

function coverage() {
  const visited = config.expected.filter(p => state.hits.has(p));
  const missing = config.expected.filter(p => !state.hits.has(p));
  const hits = Object.fromEntries([...state.hits.entries()]);
  return {
    application: config.name,
    scenario: SCENARIO,
    port: PORT,
    expected: config.expected.length,
    visited: visited.length,
    coveragePercent: config.expected.length ? Number((visited.length * 100 / config.expected.length).toFixed(2)) : 100,
    visitedEndpoints: visited,
    missingEndpoints: missing,
    hits,
    noiseRequests: Object.fromEntries([...state.noise.entries()]),
    startedAt: state.startedAt,
    resetAt: state.resetAt,
  };
}

function openApi() {
  const paths = {};
  for (const p of config.expected) {
    paths[p] = { get: { responses: { '200': { description: 'testbed endpoint' } } } };
  }
  return {
    openapi: '3.0.3',
    info: { title: config.name, version: '1.0.0' },
    servers: [{ url: `http://${config.name.split('-').slice(1).join('-')}:${PORT}` }],
    paths,
  };
}

function apiMarker(req, res, pathname, extra = {}) {
  track(req, pathname);
  json(res, 200, { ok: true, application: config.name, endpoint: pathname, query: Object.fromEntries(new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams), ...extra });
}

function largeBundleRoutes(req, res, u) {
  if (u.pathname === '/' || u.pathname === '/app' || u.pathname === '/app/') {
    const body = `<p>This page deliberately crosses the 1 MiB response-body boundary without loading extreme files by default.</p>
<div class="panel"><button id="orders">Open orders</button><button id="lazy">Load lazy reports</button></div>
<pre id="out">waiting</pre>
<p>Opt-in stress page (not linked for crawlers): <code>/stress.html</code></p>`;
    return send(res, 200, htmlPage(config.name, body, ['/assets/bundle-900k.js', '/assets/bundle-1150k.js']), 'text/html; charset=utf-8');
  }
  if (u.pathname === '/assets/bundle-900k.js') {
    const js = `fetch('/api/bootstrap?source=bundle900').then(r=>r.json()).then(v=>{document.getElementById('out').textContent=JSON.stringify(v)});`;
    return send(res, 200, padJs(js, 900 * 1024), 'application/javascript; charset=utf-8');
  }
  if (u.pathname === '/assets/bundle-1150k.js') {
    const js = `document.addEventListener('DOMContentLoaded',()=>{document.getElementById('orders').addEventListener('click',()=>fetch('/api/'+'orders?filter=open').then(r=>r.json()).then(v=>document.getElementById('out').textContent=JSON.stringify(v)));document.getElementById('lazy').addEventListener('click',()=>{const s=document.createElement('script');s.src='/assets/lazy-1250k.js';document.body.appendChild(s);});});`;
    return send(res, 200, padJs(js, 1150 * 1024), 'application/javascript; charset=utf-8');
  }
  if (u.pathname === '/assets/lazy-1250k.js') {
    const js = `fetch('/api/lazy-'+'reports?range=30d').then(r=>r.json()).then(v=>document.getElementById('out').textContent=JSON.stringify(v));`;
    return send(res, 200, padJs(js, 1250 * 1024), 'application/javascript; charset=utf-8');
  }
  if (u.pathname === '/stress.html') {
    return send(res, 200, htmlPage(`${config.name} stress`, '<p>Opt-in 4 MiB bundle. Do not use in default regression runs.</p>', ['/assets/stress-4mb.js']), 'text/html; charset=utf-8');
  }
  if (u.pathname === '/assets/stress-4mb.js') {
    return send(res, 200, padJs(`console.log('4 MiB stress bundle loaded');`, 4 * 1024 * 1024), 'application/javascript; charset=utf-8');
  }
  if (expectedSet.has(u.pathname)) return apiMarker(req, res, u.pathname);
  return false;
}

function manyStatesRoutes(req, res, u) {
  if (u.pathname === '/') {
    const script = `<script>
let current=1;
function render(n){current=n;location.hash='#/state/'+String(n).padStart(2,'0');const p='/api/state/'+String(n).padStart(2,'0');fetch(p+'?from=ui').then(r=>r.json()).then(v=>document.getElementById('result').textContent=JSON.stringify(v));const root=document.getElementById('state');root.innerHTML='<h2>State '+n+'</h2>';if(n<15){const b=document.createElement('button');b.id='next-state';b.textContent='Next state';b.onclick=()=>render(n+1);root.appendChild(b);}else{root.insertAdjacentHTML('beforeend','<p>Final state</p>');}}
addEventListener('DOMContentLoaded',()=>render(1));
</script>`;
    return send(res, 200, htmlPage(config.name, `<p>Exactly one next-state control is exposed at a time.</p><div id="state" class="panel"></div><pre id="result"></pre>${script}`), 'text/html; charset=utf-8');
  }
  if (expectedSet.has(u.pathname)) return apiMarker(req, res, u.pathname, { state: u.pathname.slice(-2) });
  return false;
}

function runtimeDiscoveryRoutes(req, res, u) {
  if (u.pathname === '/') {
    return send(res, 200, htmlPage(config.name, '<p>The HTML contains no business API URLs. They are assembled by runtime.js.</p><div id="runtime-root" class="panel"></div><pre id="runtime-out"></pre>', ['/runtime.js']), 'text/html; charset=utf-8');
  }
  if (u.pathname === '/runtime.js') {
    const js = `
const seg=(a)=>String.fromCharCode(...a);const base='/' + seg([97,112,105]) + '/' + seg([114,117,110,116,105,109,101]) + '/';
const call=(name)=>fetch(base+name+'?ts='+Date.now()).then(r=>r.json()).then(v=>document.getElementById('runtime-out').textContent=JSON.stringify(v));
class RuntimeAction extends HTMLElement{connectedCallback(){this.setAttribute('tabindex','0');this.textContent=this.getAttribute('label');this.addEventListener('click',()=>call(this.getAttribute('action')));}}customElements.define('runtime-action',RuntimeAction);
addEventListener('DOMContentLoaded',()=>{call('on'+'load');const root=document.getElementById('runtime-root');root.innerHTML='<runtime-action label="Custom element" action="custom-element"></runtime-action><div role="button" id="role-action">DIV role=button</div><button id="modal-action">Open modal</button><runtime-action label="Hash route" action="hash-route"></runtime-action><button id="iframe-action">Load iframe</button>';document.getElementById('role-action').onclick=()=>call('div-'+'role');document.getElementById('modal-action').onclick=()=>{const m=document.createElement('div');m.className='panel';m.innerHTML='<button id="modal-confirm">Confirm modal</button>';root.appendChild(m);document.getElementById('modal-confirm').onclick=()=>call('mo'+'dal');};document.querySelector('runtime-action[action="hash-route"]').addEventListener('click',()=>{location.hash='#/runtime';});document.getElementById('iframe-action').onclick=()=>{const f=document.createElement('iframe');f.src='/runtime-frame.html';root.appendChild(f);};});`;
    return send(res, 200, js, 'application/javascript; charset=utf-8');
  }
  if (u.pathname === '/runtime-frame.html') {
    return send(res, 200, '<!doctype html><script>fetch("/api/runtime/"+"iframe?from=frame")</script><p>runtime iframe</p>', 'text/html; charset=utf-8');
  }
  if (expectedSet.has(u.pathname)) return apiMarker(req, res, u.pathname);
  return false;
}

function largeApiRoutes(req, res, u) {
  if (u.pathname === '/') {
    const body = `<p>Three linked API responses: below, near, and above 1 MiB.</p><ul>
<li><a href="/api/size/100k?q=spider">100 KiB</a></li>
<li><a href="/api/size/900k?q=spider">900 KiB</a></li>
<li><a href="/api/size/1150k?q=spider">1150 KiB</a></li>
</ul><p>Opt-in stress URL (not linked): <code>/stress/4mb?q=manual</code></p>`;
    return send(res, 200, htmlPage(config.name, body), 'text/html; charset=utf-8');
  }
  const sizes = { '/api/size/100k': 100 * 1024, '/api/size/900k': 900 * 1024, '/api/size/1150k': 1150 * 1024, '/stress/4mb': 4 * 1024 * 1024 };
  if (sizes[u.pathname]) {
    track(req, u.pathname);
    const prefix = JSON.stringify({ ok: true, endpoint: u.pathname, q: u.searchParams.get('q') || '', marker: 'LARGE_API_RESPONSE' }).slice(0, -1) + ',"payload":"';
    const suffix = '"}';
    const fill = Math.max(0, sizes[u.pathname] - Buffer.byteLength(prefix) - Buffer.byteLength(suffix));
    return send(res, 200, prefix + 'A'.repeat(fill) + suffix, 'application/json; charset=utf-8');
  }
  return false;
}

function bftRegressionRoutes(req, res, u) {
  if (u.pathname === '/') {
    res.writeHead(302, { Location: '/app/' }); return res.end();
  }
  if (u.pathname === '/app' || u.pathname === '/app/') {
    const body = '<p>Composite BFT-like discovery regression. Business URLs are generated in the app bundle and many are outside /app.</p><div id="menu" class="menu"></div><div id="view" class="panel">dashboard</div><pre id="bft-out"></pre>';
    return send(res, 200, htmlPage(config.name, body, ['/app/app-shell.js']), 'text/html; charset=utf-8');
  }
  if (u.pathname === '/app/app-shell.js') {
    const js = `
const out=v=>document.getElementById('bft-out').textContent=JSON.stringify(v);const req=(p)=>fetch(p+'?ui=1').then(r=>r.json()).then(out);
class BftMenuItem extends HTMLElement{connectedCallback(){this.setAttribute('tabindex','0');this.textContent=this.getAttribute('label');this.addEventListener('click',()=>{const key=this.getAttribute('k');openView(key);});}}customElements.define('bft-menu-item',BftMenuItem);
const routes={dashboard:['api','dashboard','summary'],orders:['rest','orders'],contracts:['service','contracts'],documents:['api','documents'],reports:['rest','reports'],tasks:['service','tasks'],search:['api','search'],settings:['rest','settings']};
function pathFor(k){return '/'+routes[k].join('/');}
function openView(k){location.hash='#/'+k;document.getElementById('view').innerHTML='<h2>'+k+'</h2>';req(pathFor(k));if(k==='settings'){const b=document.createElement('button');b.id='audit';b.textContent='Open audit';b.onclick=()=>req('/'+'service'+'/'+'audit');document.getElementById('view').appendChild(b);}}
addEventListener('DOMContentLoaded',()=>{req('/api/session/'+'bootstrap');const menu=document.getElementById('menu');Object.keys(routes).forEach(k=>{const e=document.createElement('bft-menu-item');e.setAttribute('k',k);e.setAttribute('label',k);menu.appendChild(e);});});`;
    return send(res, 200, padJs(js, 700 * 1024), 'application/javascript; charset=utf-8');
  }
  if (expectedSet.has(u.pathname)) return apiMarker(req, res, u.pathname);
  return false;
}

function scopeNoiseRoutes(req, res, u) {
  const host = mainHost(req);
  if (u.pathname === '/') {
    const body = `<p>Main target intentionally contacts three different DNS aliases.</p>
<script src="http://scope-noise-cdn:8710/noise/cdn.js"></script>
<img alt="noise pixel" src="http://scope-noise-analytics:8710/noise/pixel.gif">
<script>fetch('http://scope-noise-updates:8710/noise/config.json').catch(()=>{});fetch('/api/local/a?from=load');</script>
<button onclick="fetch('/api/local/b?from=button')">Local B</button><button onclick="fetch('/api/local/c?from=button')">Local C</button>`;
    return send(res, 200, htmlPage(config.name, body), 'text/html; charset=utf-8');
  }
  if (u.pathname === '/noise/cdn.js') {
    track(req, u.pathname); return send(res, 200, `console.log('scope-noise CDN host: ${host}')`, 'application/javascript; charset=utf-8', { 'Access-Control-Allow-Origin': '*' });
  }
  if (u.pathname === '/noise/config.json') {
    track(req, u.pathname); return json(res, 200, { update: false, sourceHost: host }, { 'Access-Control-Allow-Origin': '*' });
  }
  if (u.pathname === '/noise/pixel.gif') {
    track(req, u.pathname); return send(res, 200, Buffer.from('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==', 'base64'), 'image/gif', { 'Access-Control-Allow-Origin': '*' });
  }
  if (expectedSet.has(u.pathname)) return apiMarker(req, res, u.pathname);
  return false;
}

const scenarioHandlers = {
  'large-bundle-spa': largeBundleRoutes,
  'many-states-spa': manyStatesRoutes,
  'runtime-discovery-spa': runtimeDiscoveryRoutes,
  'large-api-response': largeApiRoutes,
  'bft-regression-spa': bftRegressionRoutes,
  'scope-noise': scopeNoiseRoutes,
};

const server = http.createServer((req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (u.pathname === '/health') return json(res, 200, { ok: true, application: config.name });
  if (u.pathname === '/__testbed/expected' && req.method === 'GET') {
    return json(res, 200, { application: config.name, scenario: SCENARIO, expectedEndpoints: config.expected, note: config.note });
  }
  if (u.pathname === '/__testbed/coverage' && req.method === 'GET') return json(res, 200, coverage());
  if (u.pathname === '/__testbed/openapi.json' && req.method === 'GET') return json(res, 200, openApi());
  if (u.pathname === '/__testbed/control/reset' && req.method === 'POST') {
    if (req.headers['x-testbed-control'] !== CONTROL_TOKEN) return json(res, 404, { error: 'not found' });
    state.hits.clear(); state.noise.clear(); state.resetAt = now();
    return json(res, 200, { reset: true, application: config.name, resetAt: state.resetAt });
  }

  const handled = scenarioHandlers[SCENARIO](req, res, u);
  if (handled !== false) return;
  json(res, 404, { error: 'not found', path: u.pathname });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`${config.name} listening on 0.0.0.0:${PORT}`);
});
