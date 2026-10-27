'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { decodeBase32, hotp, totp, verifyTotp, DEFAULT_SECRET } = require('../totp');
const { app } = require('../server');

test('RFC 6238 SHA1 test vectors (8 digits)', () => {
  const key = decodeBase32('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  for (const [seconds, expected] of [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037']]) {
    assert.equal(hotp(key, Math.floor(seconds / 30), 8), expected);
  }
});

test('TOTP verification: clock window, wrong codes, and replay', () => {
  const at = 500000 * 30000;
  const code = totp(DEFAULT_SECRET, at);
  assert.equal(verifyTotp(code, DEFAULT_SECRET, at), 500000);
  assert.equal(verifyTotp(code, DEFAULT_SECRET, at + 30000), 500000);
  assert.equal(verifyTotp(code, DEFAULT_SECRET, at + 60000), null);
  assert.equal(verifyTotp(code, DEFAULT_SECRET, at, 500000), null);
  assert.equal(verifyTotp('123', DEFAULT_SECRET, at), null);
  assert.throws(() => decodeBase32('!!invalid!!'));
});

test('end-to-end two factor flow: first-factor cookie never grants access', async () => {
  const server = app();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  const jar = new Map();
  const request = async (path, {method='GET', form=null, header={}, useCookies=true}={}) => {
    const headers = {...header};
    if (useCookies && jar.size) headers.Cookie = Array.from(jar, ([k,v])=>`${k}=${v}`).join('; ');
    if (form) headers['Content-Type'] = 'application/x-www-form-urlencoded';
    const res = await fetch(base + path, {method, headers, body:form && new URLSearchParams(form), redirect:'manual'});
    for (const cookie of res.headers.getSetCookie()) {
      const [key, val] = cookie.split(';',1)[0].split('=');
      if (val) jar.set(key, val); else jar.delete(key);
    }
    return res;
  };
  try {
    assert.equal((await request('/health')).status, 200);
    assert.equal((await request('/api/whoami')).status, 401);
    assert.equal((await request('/private')).status, 401);
    assert.equal((await request('/2fa')).status, 303);
    let r = await request('/login', {method:'POST', form:{username:'zapuser', password:'bad'}});
    assert.equal(r.status, 401);
    r = await request('/login', {method:'POST', form:{username:'zapuser', password:'ZapTest123!'}});
    assert.equal(r.status, 303);
    assert.equal(r.headers.get('location'), '/2fa');
    assert.ok(jar.has('zap2fa_pending'));
    assert.equal((await request('/private')).status, 401);
    assert.equal((await request('/api/whoami')).status, 401);
    assert.equal((await request('/2fa')).status, 200);
    assert.equal((await request('/2fa/setup')).status, 200);
    r = await request('/2fa', {method:'POST', form:{otp:'notacode'}});
    assert.equal(r.status, 401);
    r = await request('/2fa', {method:'POST', form:{otp:totp(DEFAULT_SECRET)}});
    assert.equal(r.status, 303);
    assert.equal(r.headers.get('location'), '/private');
    assert.ok(jar.has('zap2fa_session'));
    assert.ok(!jar.has('zap2fa_pending'));
    assert.equal((await request('/private')).status, 200);
    assert.equal((await request('/api/profile')).status, 200);
    assert.equal((await request('/api/orders')).status, 200);
    r = await request('/api/whoami');
    assert.equal(r.status, 200);
    assert.equal((await r.json()).mfa, true);
    // A fresh password challenge cannot reuse the same 30-second TOTP.
    r = await request('/login', {method:'POST', form:{username:'zapuser', password:'ZapTest123!'}});
    assert.equal(r.status, 303);
    jar.delete('zap2fa_session');
    r = await request('/2fa', {method:'POST', form:{otp:totp(DEFAULT_SECRET)}});
    assert.equal(r.status, 401);
    assert.equal((await request('/private')).status, 401);
    r = await request('/__testbed/control/reset', {method:'POST'});
    assert.equal(r.status, 404);
    r = await request('/__testbed/coverage');
    assert.equal(r.status, 200);
    const coverage = await r.json();
    assert.equal(coverage.authentication.successfulLogins, 1);
    assert.equal(coverage.discovery.expected, 6);
    assert.ok(coverage.authentication.invalidOtp >= 2);
    r = await request('/__testbed/control/reset', {method:'POST', header:{'X-Testbed-Control':'zap-testbed-reset-v1'}});
    assert.equal(r.status, 200);
    assert.equal((await request('/__testbed/coverage').then(r=>r.json())).authentication.successfulLogins, 0);
    assert.equal((await request('/api/whoami')).status, 401);
    // After resetting replay state, fresh auth works again.
    jar.clear();
    await request('/login', {method:'POST', form:{username:'zapuser', password:'ZapTest123!'}});
    assert.equal((await request('/2fa', {method:'POST', form:{otp:totp(DEFAULT_SECRET)}})).status, 303);
    assert.equal((await request('/logout', {method:'POST'})).status, 303);
    assert.equal((await request('/api/whoami')).status, 401);
  } finally {
    server.close();
    await once(server, 'close');
  }
});
