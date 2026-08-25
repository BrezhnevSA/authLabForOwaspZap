# OWASP ZAP Authentication + Discovery Lab v7

A local authentication testbed for comparing OWASP ZAP authentication/session mechanisms against deliberately different real-world login flows.

This version keeps all previous authentication scenarios, the Kerberos/SPNEGO lab, HTTP Sender script-auth fixtures and mock 1C flow, and adds six deterministic discovery regression applications on ports 8705-8710 plus the complex React authentication/discovery fixture on port 8711.

## Credentials and fixed test secrets

```text
username: zapuser
password: ZapTest123!
OTP:      123456

Bearer token:    zap-bearer-token-2026
X-API-Key:       zap-api-key-2026
X-Client-Id:     zap-client
X-Client-Secret: zap-client-secret-2026
NTLM domain:     ZAPLAB
Kerberos realm:  ZAP.TEST
```

All host-published ports bind to `127.0.0.1`. For the hostname-sensitive SSO cases, see `HOSTS_SETUP.md` if your host does not resolve the supplied `.localhost` names.

## Start the normal lab

```bash
docker compose up --build -d
./smoke.sh
./smoke-discovery.sh
```

Kerberos is intentionally behind a profile because it starts a KDC and builds extra system packages:

```bash
docker compose --profile kerberos up --build -d
docker compose --profile kerberos run --rm kerberos-client-check
```

The KDC now provisions **everything automatically**. After startup, look in `./kerberos-generated/`:

```text
kerberos-generated/
├── zapuser.keytab       # client keytab: provide this to ZAP
├── http.keytab          # server keytab: test web service only
├── krb5-docker.conf     # ZAP/backend running in Docker network
├── krb5-host.conf       # ZAP/backend running directly on host
├── krb5.conf            # same as Docker config
├── TESTBED.txt          # principals, credentials, targets
├── kerberos-client.env  # machine-readable client values
├── zapuser.keytab.txt   # klist inventory
└── http.keytab.txt      # klist inventory
```

No manual `kadmin.local`, `docker cp`, or keytab generation is required. The second command authenticates **using `zapuser.keytab`**, then calls the SPNEGO-protected endpoint, proving the exact client keytab intended for ZAP works.

To print the exact generated paths and target for your deployment mode:

```bash
./kerberos-files.sh
```

## Scenario groups

### Original framework/browser matrix

| Port | Target | Characteristic |
|---:|---|---|
| 8101 | spring-form | Spring form + CSRF + JSESSIONID |
| 8102 | django-form | Django form + CSRF + session |
| 8103 | express-form | plain form + session |
| 8104 | dotnet-form | ASP.NET antiforgery + cookie |
| 8201 | react-json-cookie | React -> JSON login -> HttpOnly cookie |
| 8202 | fastapi-dynamic | login UI dynamically created by JavaScript |
| 8203 | go-multistep | username and password on separate steps |
| 8301 | delayed-render | login form appears after 2.5 s |
| 8302 | nonstandard-fields | unusual field names |
| 8303 | hash-spa | hash router + JSON fetch |
| 8304 | enter-submit | no form/button; Enter key triggers login |
| 8305 | iframe-login | credential fields only inside iframe |
| 8306 | otp-challenge | password followed by OTP |

### HTTP/header authentication

| Port | Target | Required authentication |
|---:|---|---|
| 8401 | http-basic | real HTTP Basic challenge |
| 8402 | http-digest | real HTTP Digest MD5/qop=auth challenge |
| 8403 | bearer-token | `Authorization: Bearer ...` |
| 8404 | api-key-header | `X-API-Key` |
| 8405 | multi-header | two required custom headers |
| 8406 | basic-then-form | HTTP Basic gate followed by a normal form login |

### Additional customer-style browser flows

| Port | Target | Characteristic |
|---:|---|---|
| 8501 | modal-login | login fields do not exist until `Sign in` is clicked |
| 8502 | consent-checkbox | username/password are valid only when consent checkbox is selected |
| 8503 | localstorage-jwt | JSON login returns JWT; browser stores it in localStorage and uses Authorization header |
| 8504/8505 | sso-app + sso-idp | app redirects to a separate IdP origin and back with `state` + code |
| 8506/8507 | cross-domain-app + IdP | same SSO pattern using distinct hostnames `customer-app.localhost` / `identity.localhost` |

### Integrated authentication

| Port | Target | Characteristic |
|---:|---|---|
| 8601 | ntlm-auth | real NTLM challenge/response implemented with pyspnego |
| 8602 | kerberos-web | real Kerberos/SPNEGO protected HTTP service (profile `kerberos`) |

### HTTP Sender script authentication

| Port | Target | Characteristic |
|---:|---|---|
| 8701 | script-jwt-exp | Token endpoint returns a JWT with a real `exp`; the HTTP Sender script parses the expiration time and refreshes the token before it expires |
| 8702 | script-token-timeout | Token endpoint returns an opaque token; the HTTP Sender script cannot read an `exp`, so it refreshes proactively using its own timeout |
| 8703 | script-token-check | Token endpoint returns a short-lived opaque token; the HTTP Sender script periodically checks the current token against `/me` and requests a new token after the old one expires |
| 8704 | mock-1c | 1C-style `vrs-session2` -> login activation -> plain `vrs-session`; validates UUID `clnId` and cross-path session propagation |

Scripts used by these targets:

- `8701`: `http-sender-scripts/token-lab/01-jwt-exp-parsing.js`
- `8702`: `http-sender-scripts/token-lab/02-token-refresh-timeout.js`
- `8703`: `http-sender-scripts/token-lab/03-token-refresh-timeout-and-check.js`
- `8704`: `http-sender-scripts/existing-apps/09-1c-vrs-session.js`

For the 1C mock use Docker target `http://mock-1c:8704`. The protected cross-path target is `http://mock-1c:8704/RPS/hs/WMSService/messagequeue/3421247882389737259`.


### Discovery regression applications

| Port | Target | Characteristic |
|---:|---|---|
| 8705 | large-bundle-spa | 900 KiB / 1150 KiB / lazy 1250 KiB JS bundles to test the 1 MiB response-body boundary without default extreme stress |
| 8706 | many-states-spa | 15 sequential DOM states, each calling a unique API endpoint; measures `maxCrawlStates` / crawl-depth effects |
| 8707 | runtime-discovery-spa | runtime-built API URLs triggered by custom elements, `div role=button`, modal, hash route and iframe |
| 8708 | large-api-response | linked API responses around the 1 MiB boundary: 100 KiB, 900 KiB and 1150 KiB |
| 8709 | bft-regression-spa | composite BFT-like SPA: hash routing, custom menu elements, runtime URLs, cross-path APIs and nested action |
| 8710 | scope-noise | target intentionally loads resources from separate Docker DNS aliases so out-of-scope crawler pollution can be measured |
| 8711 | complex-react-auth | ordinary-looking React login that actually submits JSON, stores `access_token` in localStorage, requires Bearer headers, and uses only DIV-based application navigation |

Every discovery fixture, including `complex-react-auth`, has an independent `GET /__testbed/coverage` counter and `GET /__testbed/expected`. The reset endpoint is intentionally unlinked and omitted from OpenAPI; use `./discovery-coverage.sh reset`. See [`DISCOVERY_TESTS.md`](DISCOVERY_TESTS.md).

## v2 baseline observed in ZAP

These are the previously observed results and are intentionally kept as a baseline for regression comparison:

| app | Form | Browser |
|---|---:|---:|
| otp-challenge | no | no |
| iframe-login | yes | no |
| enter-submit | yes | yes |
| hash-spa | yes | yes |
| nonstandard-fields | yes | yes |
| delayed-render | yes | yes |
| go-multistep | no | yes |
| fastapi-dynamic | no | no |
| react-json-cookie | no | yes |
| dotnet-form | yes | yes |
| express-form | yes | yes |
| django-form | yes | yes |
| spring-form | yes | yes |

## Recommended ZAP mechanism to try

The lab does not force an expected answer; the point is to record what your ZAP build and configuration actually support. Good first choices are:

| Scenario | First ZAP mechanism to test |
|---|---|
| 8101-8306 | Form and Browser Based Authentication |
| 8401 Basic | HTTP/NTLM Authentication -> Basic |
| 8402 Digest | HTTP/NTLM Authentication -> Digest |
| 8403 Bearer | auth header env vars, Replacer, or Header Based Session Management |
| 8404 API key | custom auth header / Replacer |
| 8405 multiple headers | Header Based Session Management / Replacer |
| 8406 Basic -> form | useful stacked-auth boundary; likely needs scripting/custom composition |
| 8501-8507 | Browser Based Authentication first; compare Form/JSON where meaningful |
| 8601 NTLM | HTTP/NTLM Authentication -> NTLM |
| 8602 Kerberos | use your Kerberos integration with generated `krb5-*.conf` + `zapuser.keytab`; endpoint uses real SPNEGO |
| 8701 script-jwt-exp | HTTP Sender script `token-lab/01-jwt-exp-parsing.js`; refresh based on JWT `exp` |
| 8702 script-token-timeout | HTTP Sender script `token-lab/02-token-refresh-timeout.js`; proactive refresh by local timeout |
| 8703 script-token-check | HTTP Sender script `token-lab/03-token-refresh-timeout-and-check.js`; periodic server-side token check + refresh |
| 8704 mock-1c | HTTP Sender script `existing-apps/09-1c-vrs-session.js` |
| 8705-8710 discovery | Spider + AJAX Spider now; add Client Spider to the same coverage matrix when the runner supports it |

## Common verification

Most targets provide `/api/whoami` and `/private`. Successful authentication contains:

```json
{"authenticated":true,"username":"zapuser"}
```

Suggested logged-in regex:

```regex
"authenticated"\s*:\s*true
```

Protocol-auth examples:

```bash
curl -u 'zapuser:ZapTest123!' http://127.0.0.1:8401/api/whoami
curl --digest -u 'zapuser:ZapTest123!' http://127.0.0.1:8402/api/whoami
curl -H 'Authorization: Bearer zap-bearer-token-2026' http://127.0.0.1:8403/api/whoami
curl -H 'X-API-Key: zap-api-key-2026' http://127.0.0.1:8404/api/whoami
curl -H 'X-Client-Id: zap-client' -H 'X-Client-Secret: zap-client-secret-2026' http://127.0.0.1:8405/api/whoami
```

## New flow details

### 8406 Basic -> form

The first request receives `401 WWW-Authenticate: Basic`. Only after the Basic credentials are accepted is the HTML login form returned. The second stage creates a cookie session. This intentionally tests a stacked authentication flow rather than a single ZAP auth method.

### 8501 login modal

The initial DOM contains no username/password elements. Clicking `Sign in` inserts a modal containing the login form.

### 8502 consent checkbox

The browser must both provide valid credentials and explicitly select a consent checkbox. The backend rejects JSON login attempts without `consent=true`.

### 8503 JWT in localStorage

The login API returns a token. JavaScript stores it as `localStorage.access_token`; protected fetches explicitly set `Authorization: Bearer <token>`. There is no cookie session to inherit.

### 8504/8505 SSO redirect

Entry at `http://sso-app.localhost:8504/login` redirects to `http://sso-idp.localhost:8505/authorize`, authenticates there, and returns to `/callback` with state and a short-lived fixture code before the application creates its session.

### 8506/8507 cross-host redirect

Entry at `http://customer-app.localhost:8506/login` redirects to `http://identity.localhost:8507/authorize` and back. `*.localhost` is used so the lab stays local while still forcing the browser across hostnames/origins.

### 8601 NTLM

This endpoint performs an actual NTLM token exchange. It is not a Basic-auth imitation. Test account:

```text
domain:   ZAPLAB
username: zapuser
password: ZapTest123!
```

### 8602 Kerberos/SPNEGO

The Kerberos profile provisions:

```text
realm:              ZAP.TEST
client principal:   zapuser@ZAP.TEST
client password:    ZapTest123!
HTTP service SPN:   HTTP/kerberos-web.zap.test@ZAP.TEST
```

Two **different** keytabs are generated automatically:

- `kerberos-generated/zapuser.keytab` — client keytab to pass to your ZAP Kerberos implementation;
- `kerberos-generated/http.keytab` — server keytab mounted read-only into `kerberos-web`; do not use it as the ZAP client keytab.

The same startup also generates two configs:

- `krb5-docker.conf` points the realm at `kerberos-kdc.zap.test:88`; use it when the ZAP/backend container is attached to the `zap-auth-testbed` network. Target: `http://kerberos-web.zap.test:8080`.
- `krb5-host.conf` points the realm at `127.0.0.1:10088`; use it when ZAP/backend runs directly on the Docker host. Add `127.0.0.1 kerberos-web.zap.test` to `/etc/hosts`, then target `http://kerberos-web.zap.test:8602`.

The web endpoint returns `401 WWW-Authenticate: Negotiate` before authentication and validates the real GSSAPI/SPNEGO token against `http.keytab`.

To verify the generated **client** artifacts:

```bash
docker compose --profile kerberos run --rm kerberos-client-check
```

That check executes `kinit -kt /shared/zapuser.keytab zapuser@ZAP.TEST` before calling `/api/whoami`.

## ZAP in Docker

Attach the ZAP container to the lab network:

```bash
docker network connect zap-auth-testbed <zap-container>
```

For the ordinary services, use Docker service names. For hostname-sensitive SSO/Kerberos cases, use the aliases shown in `ZAP_TEST_MATRIX.md`.

## What to record

For every target record more than just whether the login dialog says success:

1. authentication operation result;
2. `/api/whoami` as the authenticated user;
3. `/private` as the authenticated user;
4. session state after spidering;
5. session state during active scan;
6. re-authentication after logout/session loss;
7. whether auth state is propagated from Selenium/browser traffic to scanner HTTP traffic.

## Safety

All credentials/tokens are fixed and intentionally weak. This is a disposable localhost test fixture, not production authentication code. Do not expose these services to an untrusted network.

## HTTP Sender script authentication

The v5 fixture adds reusable HTTP Sender script tests and three lightweight token-refresh services so VAmPI is not required for script-auth regression testing.

See [`SCRIPT_AUTH_TESTS.md`](SCRIPT_AUTH_TESTS.md).

### Complex React authentication / DIV navigation (8711)

`complex-react-auth` deliberately looks like a normal username/password form, but React prevents the native form submit and sends JSON to `/api/auth/login`. The server rejects classic `application/x-www-form-urlencoded` form authentication. A successful login returns `access_token`; the browser stores it in `localStorage`, and protected APIs accept only `Authorization: Bearer <access_token>`.

After login, application navigation is made only from clickable `div` elements, including nested dropdowns. There are no business `<a href>` links or navigation buttons. This makes the same fixture useful for both Browser Based Authentication/session-header regression and AJAX Spider click-element discovery.

Expected auth behavior:

- Form Based Authentication: expected to fail.
- Browser Based Authentication without session headers: browser login can succeed, but backend-driven protected requests are unauthorized.
- Browser Based Authentication with `{"Authorization":"Bearer {%json:access_token%}"}`: expected to pass.

Coverage and authentication counters are available at `GET /__testbed/coverage`; the hidden reset uses the same control-header mechanism as 8705-8710.


HTTP Sender host ports: `8701` (JWT `exp` parsing), `8702` (proactive timeout refresh), `8703` (timeout + server token check), `8704` (1C-style `vrs-session`). Discovery regression ports are `8705`-`8710`; see `DISCOVERY_TESTS.md`.
