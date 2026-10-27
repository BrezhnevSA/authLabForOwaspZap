# TOTP 2FA fixture (OWASP ZAP)

A separate **real time-based second factor**, not the fixed `123456` `otp-challenge` fixture. Uses Node.js built-in modules only (no `npm install`, network dependencies or database).

## Login steps

1. `GET /login` -> `POST /login` with `username=zapuser`, `password=ZapTest123!`.
2. If correct, server creates a short-lived `zap2fa_pending` **HttpOnly** cookie and redirects to `GET /2fa`. **No protected URL is accessible at this stage.**
3. Enter current 6-digit RFC 6238 TOTP: `POST /2fa` with `otp=NNNNNN` and the same cookie.
4. If valid, server invalidates pending challenge and creates `zap2fa_session` **HttpOnly** cookie, then redirects to `/private`.
5. For authenticated-session checks, use `GET /api/whoami`: `401` before both factors, `200 {"authenticated":true,"mfa":true,...}` after both factors. `GET /api/profile`, `/api/orders` and `/private` are also protected. `POST /logout` invalidates the session.

TOTP uses SHA-1, **30-second rotation**, six digits, a ±1 time-step clock-skew window. Successfully used codes cannot be reused (including a fresh login) until the TOTP counter advances. Pending sessions expire in 3 minutes and lock after 5 bad TOTP attempts; authenticated sessions expire in 60 minutes. Session state and accepted-code counter are in memory, and reset at process restart.

## Provision the test authenticator

The **test-only**, fixed default seed (intentionally reproducible in both labs):

```text
JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
```

After submitting the correct password, open `/2fa/setup` to see the seed and an `otpauth://` URI to add to Google Authenticator, Aegis, Microsoft Authenticator, etc. The provisioning page requires the first-factor cookie and is not accessible anonymously.

Generate the **current** code from the command line:

```bash
node totp-2fa/totp.js
# Or in the running local container:
docker compose exec -T totp-2fa node totp.js
```

When using a custom seed set `TOTP_SECRET` for **both** the app and the CLI. There is deliberately no unauthenticated `GET /otp-code` bypass.

Environment variables: `PORT` (default `3000`), `TOTP_USERNAME`, `TOTP_PASSWORD`, `TOTP_SECRET`, `TESTBED_CONTROL_TOKEN`, `COOKIE_SECURE` (`auto`, `true` or `false`). With HTTPS behind Traefik, `COOKIE_SECURE=auto` emits Secure cookies from `X-Forwarded-Proto: https`. The test-only shared secret and default credentials **must not be used for real users**; expose the testbed only inside a trusted network.

## Test endpoints / ZAP setup

| Endpoint | Access | Purpose |
|---|---|---|
| `GET /login` / `POST /login` | public | Password factor |
| `GET /2fa` / `POST /2fa` | pending cookie | TOTP challenge |
| `GET /2fa/setup` | pending cookie | Test authenticator enrollment |
| `GET /private` | full session | HTML logged-in indicator: `AUTHENTICATED` |
| `GET /api/whoami` | full session | Reliable logged-in HTTP 200 vs logged-out HTTP 401 |
| `GET /api/profile`, `GET /api/orders` | full session | Protected scan endpoints |
| `GET /__testbed/expected`, `GET /__testbed/coverage` | public | Standard testbed diagnostics (without secrets) |
| `POST /__testbed/control/reset` | `X-Testbed-Control` only | Clear sessions, replay counter and metrics (unauthorized: 404) |
| `GET /health` | public | Health probe |

For ZAP, an ordinary Form-Based Authentication request handling only `/login` is **not** enough: the client must follow the redirect, retain the pending cookie, compute the *current* TOTP, and submit `/2fa`, then use the resulting session cookie. You can log in through Browser Based Authentication with a configured authenticator, or create an Authentication Script that performs both POSTs. Use `/api/whoami` for context-level logged-in / logged-out detection.

Tests: `node --test totp-2fa/test/*.test.js`. The app deliberately does **not** contain password-bypass, OTP-bypass or hard-coded fixed OTP switches.
