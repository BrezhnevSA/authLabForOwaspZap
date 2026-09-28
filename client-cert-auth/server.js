'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');
const { URL } = require('url');

const path = require('path');
const PORT = Number(process.env.PORT || 8712);
const CONTROL_PORT = Number(process.env.CONTROL_PORT || 9712);
const CERT_DIR = process.env.CERT_DIR || '/app/certs';
const CONTROL_TOKEN = process.env.TESTBED_CONTROL_TOKEN || 'zap-testbed-reset-v1';
const EXPECTED = ['/api/profile', '/api/orders', '/api/documents'];
const EXPECTED_SET = new Set(EXPECTED);

const state = {
  hits: new Map(),
  mtls: {
    successfulTlsRequests: 0,
    tlsClientErrors: 0,
    authenticatedRequests: 0,
    lastClientSubject: null,
    lastClientIssuer: null,
    lastClientSerialNumber: null,
  },
  resetAt: new Date().toISOString(),
};

function send(res, status, value, type = 'application/json; charset=utf-8', extra = {}) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(type.startsWith('application/json') ? JSON.stringify(value, null, 2) : String(value));
  res.writeHead(status, {
    'Content-Type': type,
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    ...extra,
  });
  res.end(body);
}

function json(res, status, value, extra = {}) {
  send(res, status, value, 'application/json; charset=utf-8', extra);
}

function html(res, status, body) {
  send(res, status, `<!doctype html>
<html><head><meta charset="utf-8"><title>client-cert-auth</title>
<style>body{font-family:system-ui,sans-serif;max-width:820px;margin:42px auto;padding:0 18px}li{margin:10px 0}code{background:#eee;padding:2px 5px}</style></head>
<body>${body}</body></html>`, 'text/html; charset=utf-8');
}

function record(pathname) {
  if (EXPECTED_SET.has(pathname)) {
    state.hits.set(pathname, (state.hits.get(pathname) || 0) + 1);
  }
}

function clientInfo(req) {
  const cert = req.socket.getPeerCertificate();
  return {
    subject: cert && cert.subject ? cert.subject : null,
    issuer: cert && cert.issuer ? cert.issuer : null,
    serialNumber: cert && cert.serialNumber ? cert.serialNumber : null,
  };
}

function coverage() {
  const visited = EXPECTED.filter(path => state.hits.has(path));
  const missing = EXPECTED.filter(path => !state.hits.has(path));
  return {
    application: 'client-cert-auth',
    discovery: {
      expected: EXPECTED.length,
      visited: visited.length,
      coveragePercent: Number((visited.length * 100 / EXPECTED.length).toFixed(2)),
      visitedEndpoints: visited,
      missingEndpoints: missing,
    },
    authentication: {
      type: 'mutual-tls-client-certificate',
      ...state.mtls,
    },
    hits: Object.fromEntries(state.hits.entries()),
    resetAt: state.resetAt,
  };
}

function reset() {
  state.hits.clear();
  state.mtls.successfulTlsRequests = 0;
  state.mtls.tlsClientErrors = 0;
  state.mtls.authenticatedRequests = 0;
  state.mtls.lastClientSubject = null;
  state.mtls.lastClientIssuer = null;
  state.mtls.lastClientSerialNumber = null;
  state.resetAt = new Date().toISOString();
}

function protectedHandler(req, res) {
  state.mtls.successfulTlsRequests++;

  // rejectUnauthorized=true performs the real mTLS gate before this handler.
  // Keep the explicit check as a defensive assertion and to make failures obvious.
  if (!req.socket.authorized) {
    return json(res, 401, { authenticated: false, error: 'CLIENT_CERTIFICATE_REQUIRED' });
  }

  state.mtls.authenticatedRequests++;
  const info = clientInfo(req);
  state.mtls.lastClientSubject = info.subject;
  state.mtls.lastClientIssuer = info.issuer;
  state.mtls.lastClientSerialNumber = info.serialNumber;

  const u = new URL(req.url, `https://${req.headers.host || 'localhost'}`);
  const p = u.pathname;

  if (p === '/health') {
    return json(res, 200, { ok: true, authenticated: true, authType: 'mTLS' });
  }
  if (p === '/api/whoami') {
    return json(res, 200, {
      authenticated: true,
      authType: 'mTLS',
      clientCertificate: info,
    });
  }
  if (p === '/' || p === '/app' || p === '/app/') {
    return html(res, 200, `<h1>Mutual TLS client-certificate test</h1>
<p>This HTTPS application is reachable only when the TLS client presents a certificate signed by the test CA.</p>
<ul>
  <li><a href="/api/profile?view=full">Profile</a></li>
  <li><a href="/api/orders?status=open">Orders</a></li>
  <li><a href="/api/documents?type=invoice">Documents</a></li>
  <li><a href="/api/whoami">Who am I?</a></li>
</ul>
<p>Expected DAST configuration: upload the supplied <code>.pfx</code>, its password, and certificate index <code>0</code>.</p>`);
  }
  if (EXPECTED_SET.has(p)) {
    record(p);
    return json(res, 200, {
      authenticated: true,
      authType: 'mTLS',
      endpoint: p,
      query: Object.fromEntries(u.searchParams),
      clientCertificate: info,
    });
  }
  return json(res, 404, { error: 'not found' });
}

function controlHandler(req, res) {
  const u = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (req.method === 'GET' && u.pathname === '/health') {
    return json(res, 200, { ok: true, application: 'client-cert-auth-control' });
  }
  if (req.method === 'GET' && u.pathname === '/__testbed/expected') {
    return json(res, 200, {
      application: 'client-cert-auth',
      target: `https://client-cert-auth:${PORT}/`,
      expectedEndpoints: EXPECTED,
      note: 'Control API is on a separate port and is not exposed to the crawler target.',
    });
  }
  if (req.method === 'GET' && u.pathname === '/__testbed/coverage') {
    return json(res, 200, coverage());
  }
  if (req.method === 'POST' && u.pathname === '/__testbed/control/reset') {
    if (req.headers['x-testbed-control'] !== CONTROL_TOKEN) {
      return json(res, 404, { error: 'not found' });
    }
    reset();
    return json(res, 200, { reset: true, application: 'client-cert-auth' });
  }
  return json(res, 404, { error: 'not found' });
}

const tlsServer = https.createServer({
  key: fs.readFileSync(path.join(CERT_DIR, 'server.key')),
  cert: fs.readFileSync(path.join(CERT_DIR, 'server.crt')),
  ca: fs.readFileSync(path.join(CERT_DIR, 'testbed-ca.crt')),
  requestCert: true,
  rejectUnauthorized: true,
  minVersion: 'TLSv1.2',
}, protectedHandler);

tlsServer.on('tlsClientError', error => {
  state.mtls.tlsClientErrors++;
  console.warn('[client-cert-auth] TLS client rejected:', error.message);
});

tlsServer.listen(PORT, '0.0.0.0', () => {
  console.log(`[client-cert-auth] mTLS target listening on https://0.0.0.0:${PORT}`);
});

http.createServer(controlHandler).listen(CONTROL_PORT, '0.0.0.0', () => {
  console.log(`[client-cert-auth] hidden control API listening on http://0.0.0.0:${CONTROL_PORT}`);
});
