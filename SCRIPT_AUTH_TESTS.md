# ZAP HTTP Sender script authentication tests

This extension of the auth testbed is intended to compare custom HTTP Sender authentication with the existing Form and Browser Based Authentication scenarios.

## What these tests prove

An HTTP Sender script runs on every request/response processed by ZAP, so these fixtures are useful for verifying that:

- the script is uploaded, loaded and enabled correctly;
- scanner, spider and other ZAP-generated requests pass through the script;
- a login request can be sent from the script through `helper.getHttpSender()`;
- tokens/cookies survive between script invocations through `ScriptVars`;
- credentials are propagated to the actual scan requests;
- refresh/check logic works during a long scan;
- concurrent scanner traffic does not cause a login storm (the supplied scripts use `ReentrantLock`).

They are **not** an automatic-auth-discovery benchmark. A custom script already knows the exact login flow, so a successful result means the scripted integration is reliable, not that ZAP inferred the flow by itself.

## New token refresh fixtures

Three small services replace the VAmPI dependency while preserving the contract expected by the supplied VAmPI-derived scripts:

```json
POST /api/login
{"username":"zapuser","password":"ZapTest123!"}

200
{
  "status":"success",
  "auth_token":"...",
  "token_type":"Bearer"
}
```

Protected resources accept `Authorization: Bearer <token>`.

| Service | Docker URL | Host URL | Purpose |
|---|---|---|---|
| `script-jwt-exp` | `http://script-jwt-exp:3000` | `http://127.0.0.1:8701` | JWT contains a real `exp`; token TTL 12 s |
| `script-token-timeout` | `http://script-token-timeout:3000` | `http://127.0.0.1:8702` | opaque token valid 120 s; supplied script refreshes proactively every 5 s |
| `script-token-check` | `http://script-token-check:3000` | `http://127.0.0.1:8703` | opaque token TTL 8 s; supplied script re-checks `/me` every 2 s and refreshes after expiry |

All three expose:

- `POST /api/login`
- `GET /api/whoami`
- `GET /private`
- `GET /me`
- `GET /api/stats`
- `POST /logout`

`/api/stats` is useful during a scan because it exposes `loginCount`, `checkCount` and `protectedCount`.

### Scripts

Use these as **HTTP Sender** scripts:

```text
http-sender-scripts/token-lab/01-jwt-exp-parsing.js
http-sender-scripts/token-lab/02-token-refresh-timeout.js
http-sender-scripts/token-lab/03-token-refresh-timeout-and-check.js
```

They are adaptations of the supplied VAmPI scripts. The response contract remains `status=success` + `auth_token`, so the important refresh logic is unchanged.

The third supplied VAmPI script checked/refreshed the token but did not copy the cached token to the actual outgoing managed request. The adapted testbed version adds:

```javascript
var token = cachedToken();
msg.getRequestHeader().setHeader(AUTH_HEADER, authorizationValue(token));
```

Without that propagation, a target that requires the Bearer header on every protected request will still receive unauthenticated scanner traffic.

## Existing applications reused for script auth

The following scripts intentionally reuse existing fixtures instead of adding duplicate applications.

| Existing target | Script | What it tests | Comparison value |
|---|---|---|---|
| `express-form` | `01-express-form-cookie.js` | direct form POST + session cookie | baseline: classic form |
| `react-json-cookie` | `02-react-json-cookie.js` | JSON login + session cookie | useful where classic Form auth is a poor fit |
| `spring-form` | `03-spring-form-csrf-cookie.js` | GET login page, parse CSRF, POST login, preserve cookie | state + anti-CSRF |
| `go-multistep` | `04-go-multistep-cookie.js` | username step, parse transaction id, password step, session cookie | multi-request auth choreography |
| `consent-checkbox` | `05-consent-checkbox-cookie.js` | JSON login with required extra field `consent=true` | exact custom payload |
| `iframe-login` | `06-iframe-login-cookie.js` | direct POST to login endpoint, independent of DOM/iframe | shows script auth is not UI-dependent |
| `otp-challenge` | `07-otp-challenge-cookie.js` | username/password -> transaction -> known fixture OTP -> cookie | deterministic multi-factor fixture only |
| `localstorage-jwt` | `08-localstorage-jwt-bearer.js` | JSON login -> `access_token` -> Authorization header | browser-token propagation without browser session state |
| `mock-1c` | `09-1c-vrs-session.js` | 1C-style start/landing/login, random UUID `clnId`, plain `vrs-session` | custom multi-request protocol + host-wide header propagation |

Directory:

```text
http-sender-scripts/existing-apps/
```

### Why not create a script for every UI variation?

`delayed-render`, `modal-login`, `hash-spa`, `enter-submit` and several other scenarios differ mainly in how a browser discovers/operates the login UI. Once an HTTP Sender script is given the exact backend login endpoint, those DOM differences disappear. Testing all of them with near-identical direct-login scripts would add little signal.

The selected set instead covers distinct HTTP/session mechanisms: form, JSON, CSRF, multi-step state, extra fields, iframe/UI independence, OTP, and Bearer propagation.

## Recommended comparison matrix

Run the same target with Form, Browser Based and HTTP Sender script auth where applicable.

| Scenario | Form/Browser question | HTTP Sender expectation |
|---|---|---|
| `express-form` | baseline | pass |
| `spring-form` | can built-in auth handle CSRF/session? | pass after explicit CSRF parsing |
| `react-json-cookie` | can the built-in mode handle JSON + cookie? | pass |
| `go-multistep` | can built-in auth handle a two-request login? | pass because the script encodes both steps |
| `iframe-login` | does browser automation discover fields inside the iframe? | pass because the script bypasses the DOM |
| `consent-checkbox` | can automation satisfy the required extra value? | pass because the script sends `consent=true` |
| `otp-challenge` | can generic auth solve a second factor? | pass only because the fixture OTP is deliberately hard-coded |
| `localstorage-jwt` | is browser localStorage state propagated to scanner HTTP? | pass because the script injects the Bearer header directly |

The `otp-challenge` result must not be interpreted as generic MFA support. A real OTP/TOTP/push/WebAuthn flow needs a source for the second factor or a test bypass.

## Starting the fixtures

```bash
docker compose up --build -d
```

Kerberos still uses its separate profile:

```bash
docker compose --profile kerberos up --build -d
```

If ZAP runs in a different Compose project, attach it to the testbed network:

```bash
docker network connect zap-auth-testbed zap
```

## Quick manual validation of the new token lab

JWT-exp example from the host:

```bash
response=$(curl -sS \
  -H 'Content-Type: application/json' \
  -d '{"username":"zapuser","password":"ZapTest123!"}' \
  http://127.0.0.1:8701/api/login)

token=$(jq -r .auth_token <<< "$response")

curl -sS \
  -H "Authorization: Bearer $token" \
  http://127.0.0.1:8701/api/whoami
```

During a ZAP run, inspect counters:

```bash
curl -sS http://127.0.0.1:8701/api/stats | jq
curl -sS http://127.0.0.1:8702/api/stats | jq
curl -sS http://127.0.0.1:8703/api/stats | jq
```

Expected qualitative behavior:

- `script-jwt-exp`: `loginCount` increments again when the JWT nears its `exp`.
- `script-token-timeout`: `loginCount` increments roughly every 5 seconds while managed requests continue, even though old tokens remain server-valid.
- `script-token-check`: `checkCount` increases; after a token actually expires, a check returns 401 and `loginCount` increases.

## Suggested scan target

For script-auth regression use `/api/whoami` or `/private` as the initial target and verify that spider/active-scan requests remain authenticated. Do not judge only the explicit login request: the important assertion is that ZAP-generated traffic receives authenticated responses after the HttpSender script runs.


## Mock 1C VRS-session fixture

The `mock-1c` service listens on host port `8704` and Docker URL `http://mock-1c:8704`. It emulates:

```text
POST /app/e1cib/start
  -> 301 + vrs-session2 + Location
GET landing
POST /app/ru_RU/e1cib/login?...&sid=<UUID>&nooida&vl=ru&clnId=<UUID>
  -> {"response":{"seance":"<UUID>"}}
protected request
  -> requires vrs-session: <plain UUID>
```

The fixture rejects a non-UUID `clnId`. Its primary scan target intentionally lives outside `/app` on the same hostname:

```text
/RPS/hs/WMSService/messagequeue/3421247882389737259
```

This verifies that the HTTP Sender script can authenticate through `/app` and then propagate the same session header to another path on the same host. The protected response contains `"authenticated":true`, so it can also be used with the regression runner's `ACTION=check`.
