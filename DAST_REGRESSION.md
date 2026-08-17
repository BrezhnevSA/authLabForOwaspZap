# AppScreener DAST authentication regression

This client checks the actual authentication path used by a scan:

```text
AppScreener Backend -> DAST daemon -> ZAP -> test target
```

The quick mode calls `POST /dastProjects/checkAuth`. It configures a temporary ZAP context, makes
the authenticated request, returns the captured request/response data, and invokes the daemon's
normal cleanup. It does not create a scan and does not require manual context deletion between
checks. For ordinary form/header/protocol checks, the daemon removes the context and forced user,
clears transient ZAP state, and cleans the session directory.

The current daemon restarts the ZAP process automatically before Browser Based Authentication to
discard authhelper state. Kerberos also restarts ZAP: it installs `krb5.conf` and the keytab and
obtains a ticket with `kinit` before enabling native GSS/SPNEGO. Neither case needs a manual restart.

## 1. Start the fixtures

When using the repository's main standalone stack (the layout with containers named `zap` and
`zapdaemon`), start only the newly added fixtures in that same Compose project/network:

```bash
cd /path/to/as-backend
docker compose -f docker-compose.standalone.war-outside.yml --profile kerberos up --build -d \
  http-basic http-digest bearer-token api-key-header multi-header basic-then-form \
  modal-login consent-checkbox localstorage-jwt sso-app sso-idp \
  cross-domain-app cross-domain-idp ntlm-auth kerberos-kdc kerberos-web
docker compose -f docker-compose.standalone.war-outside.yml --profile kerberos \
  run --rm kerberos-client-check
```

The command does not need to recreate `zap` or `zapdaemon`; the new targets share their existing
default Compose network.

For a standalone testbed, start all ordinary scenarios plus the optional KDC:

```bash
cd /path/to/zap-auth-testbed
docker compose --profile kerberos up --build -d
docker compose --profile kerberos run --rm kerberos-client-check
```

The second command verifies the Kerberos fixture independently of ZAP. The KDC creates these local
files:

```text
kerberos-lab/generated/krb5.conf
kerberos-lab/generated/http.keytab
kerberos-lab/generated/zapuser.keytab
```

Only for that standalone testbed layout, attach the ZAP container to the testbed network once:

```bash
docker network connect zap-auth-testbed <zap-container-name>
```

If it is already connected, Docker reports that fact and no reconnect is needed.

Use `TARGET_PROFILE=docker` (the default) when ZAP runs in a container. The `host` profile is only
for a daemon/ZAP process that can really reach the host's `127.0.0.1` ports. Kerberos remains a
hostname-sensitive Docker-network case because its service principal is
`HTTP/kerberos-web.zap.test@ZAP.TEST`.

## 2. Fast terminal regression

Set the AppScreener project and either API credentials or an existing access token. With credentials,
the runner uses backend Basic Auth by default and does not create a new JWT session:

```bash
export PROJECT_ID=42
export APP_LOGIN='admin'
export APP_PASSWORD='password'
```

To use an existing JWT instead:

```bash
export PROJECT_ID=42
export APP_TOKEN='existing-appscreener-jwt'
```

`API_AUTH=auto` is the default: it prefers `APP_TOKEN`, then falls back to Basic Auth with
`APP_LOGIN` and `APP_PASSWORD`. If Basic Auth is disabled in a deployment, use `API_AUTH=jwt` to
obtain a JWT from those credentials. That mode creates a server-side session and can therefore hit
the deployment's session limit; an existing `APP_TOKEN` is preferable for repeated runs.

`AGENT_ID` is optional when the project already has a DAST agent assigned. Otherwise set it:

```bash
export AGENT_ID=7
```

Run the strict protocol suite:

```bash
ACTION=check AUTH_MODE=protocol ./run-dast-scans.sh
```

It checks these seven configurations and returns non-zero if one no longer reaches an authenticated
endpoint:

| Target | Backend auth fields | Expected |
|---|---|---:|
| `http-basic` | `authBasicLogin` / `authBasicPassword` | pass |
| `http-digest` | HTTP/NTLM auth configured for the Digest host/port/realm | pass |
| `bearer-token` | `authToken` | pass |
| `api-key-header` | one `authCustomHeaders` entry | pass |
| `multi-header` | two entries in the same `authCustomHeaders` object | pass |
| `ntlm-auth` | HTTP/NTLM auth with username `ZAPLAB\zapuser` and auth scope realm `ZAPLAB` | pass |
| `kerberos-web` | `krb5.conf`, `zapuser.keytab`, host, port, and client principal | pass |

All seven checks passed against the current local backend/daemon/ZAP stack.

The backend field named `authNtlmKerberosRealm` intentionally receives
`zapuser@ZAP.TEST` for Kerberos: the current daemon passes that value to `kinit` as the principal.
The fixture keytab also contains service-principal aliases for the canonical Docker names used by
the repository stack (`kerberos-web.as-backend_default`) and standalone testbed
(`kerberos-web.zap-auth-testbed`). ZAP 2.17's Apache HTTP client canonicalizes the target hostname
before creating its SPNEGO service name.

To skip Kerberos explicitly when the profile is not running:

```bash
ACTION=check AUTH_MODE=protocol SKIP_KERBEROS=true ./run-dast-scans.sh
```

Missing Kerberos files are an error unless that opt-out is present, so a supposedly complete quick
run cannot silently omit Kerberos.

## 3. New form/browser observations

Run only the new browser cases:

```bash
ACTION=check AUTH_MODE=browser \
ONLY=basic-then-form,modal-login,consent-checkbox,localstorage-jwt,sso-redirect,cross-host-sso \
./run-dast-scans.sh
```

Run the new direct-form comparisons:

```bash
ACTION=check AUTH_MODE=form \
ONLY=modal-login,consent-checkbox,localstorage-jwt \
./run-dast-scans.sh
```

These cases are marked as observations because they exercise support boundaries:

- `basic-then-form` needs two auth stages. The backend accepts only one auth type per request, but
  ZAP Browser Based Authentication can answer HTTP Basic in Firefox and then try the HTML form;
- `modal-login` needs a preliminary click before credential fields exist;
- `consent-checkbox` needs an extra checkbox/custom step that the current backend multipart model
  does not expose;
- `localstorage-jwt` uses Header Based Session Management with
  `{"Authorization":"Bearer {%json:access_token%}"}` so scanner requests can reuse the login JSON
  token;
- the SSO cases test redirects through a second origin or hostname.

Observed against the current local backend/daemon/ZAP stack:

| Scenario | Form | Browser |
|---|---:|---:|
| `basic-then-form` | n/a | fail (`INVALID_BROWSER_AUTH`) |
| `modal-login` | pass | backend timeout; daemon finishes after the 30 s wait limit |
| `consent-checkbox` | fail | fail (`INVALID_BROWSER_AUTH`) |
| `localstorage-jwt` | fail | pass with header-based session management |
| `sso-redirect` | n/a | fail (`INVALID_BROWSER_AUTH`) |
| `cross-host-sso` | n/a | fail (`INVALID_BROWSER_AUTH`) |

The modal result is deliberately recorded as a timeout rather than an authentication failure: ZAP
does create a cookie-based session, but the daemon sends the result after the backend has already
returned `Cannot check auth for project`. Raising the runner's `HTTP_TIMEOUT` cannot change that
server-side 30-second wait.

The script prints one of:

- `PASS` — the returned traffic contains an authenticated protected response;
- `FAIL (regression)` — a protocol or known-good v2 scenario stopped working;
- `EXPECTED FAIL` — a preserved v2 negative baseline such as OTP/iframe browser auth;
- `PASS/FAIL (observation)` — a new boundary case, reported without failing the suite.

For an observation or known negative baseline, the runner also recognizes the backend's generic
`Cannot check auth for project` response as a completed failed auth-check instead of a curl error.
The same response remains a regression for a scenario whose baseline is `pass`.

Run every old and new quick check in one command:

```bash
ACTION=check AUTH_MODE=all ./run-dast-scans.sh
```

Use `ONLY=name1,name2`, `DRY_RUN=true`, or `STRICT_CHECKS=false` to narrow or inspect a run. The
default for quick checks is to continue through the matrix and return a summary at the end.

## 4. Queue full scans

The original behavior remains available:

```bash
ACTION=scan AUTH_MODE=protocol ./run-dast-scans.sh
ACTION=scan AUTH_MODE=browser ONLY=modal-login,sso-redirect ./run-dast-scans.sh
ACTION=scan AUTH_MODE=all ./run-dast-scans.sh
```

`scan` reports only whether the backend accepted and queued each scan. Authentication success is
then determined from scan status/logs; use `check` first for a much faster regression signal.

## 5. Postman

Import:

```text
postman/zap-auth-testbed.postman_collection.json
postman/zap-auth-testbed.postman_environment.json
```

Use `zap-auth-testbed-host.postman_environment.json` only when the daemon/ZAP can reach the host
ports. Set these collection/environment variables before running quick checks:

```text
apiBaseUrl
projectId
agentId
appToken, or appLogin + appPassword
```

`apiAuth=auto` prefers `appToken`; when it is empty, Postman uses backend Basic Auth with `appLogin`
and `appPassword` and does not create a JWT session. If Basic Auth is disabled, run
`00 - Login to AppScreener` to populate `appToken` and use `apiAuth=token`.

The folders are:

1. `01 - QUICK protocol auth checks` — strict seven-scenario regression;
2. `02 - QUICK v3 form/browser observations` — new direct-form and browser cases;
3. `03 - PROTOCOL scans` — queues full scans;
4. `FORM scans` and `BROWSER scans` — the original matrix extended with v3 cases.

For the Kerberos request, set `kerberosConfigPath` and `kerberosKeytabPath` to the generated
`krb5.conf` and `zapuser.keytab`. Postman Desktop may require selecting those two files in the
request once because local-file access is controlled by Postman's working-directory settings.

The collection stores the most recent synchronous result in `lastAuthCheckPassed` and logs `PASS`
or `FAIL` in the Postman console. The protocol folder has a strict assertion on the protected
response. Observation requests accept either a normal checkAuth response or the backend's known
failed-check response, so unsupported browser cases do not turn the observation folder into a
strict regression gate.

With Newman, the same non-Kerberos quick folder can be run from a terminal (select the folder name
with `--folder` and provide the required variables with `--env-var`). For the complete suite,
including Kerberos file upload, `run-dast-scans.sh` is the more reliable terminal client.

## Why JWT needs session headers

Browser Based Authentication performs the interactive login, but an authenticated browser does not
automatically give ZAP's ordinary HTTP scanner a localStorage token. Header Based Session Management
bridges that boundary by extracting a JSON value from the authentication response and adding it to
later scanner requests. ZAP documents JSON tokens such as `{%json:path.to.data%}` for this purpose:

- <https://www.zaproxy.org/docs/desktop/addons/authentication-helper/browser-auth/>
- <https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-header/>
