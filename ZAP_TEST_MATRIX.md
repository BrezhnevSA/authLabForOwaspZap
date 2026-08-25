# ZAP authentication test matrix — v4

## Shared credentials

```text
username = zapuser
password = ZapTest123!
OTP = 123456
Bearer = zap-bearer-token-2026
X-API-Key = zap-api-key-2026
X-Client-Id = zap-client
X-Client-Secret = zap-client-secret-2026
NTLM domain = ZAPLAB
Kerberos realm = ZAP.TEST
```

## Host entry URLs

| Port | Scenario | Entry/login | Verify |
|---:|---|---|---|
| 8101 | spring-form | `http://127.0.0.1:8101/login` | `/api/whoami` |
| 8102 | django-form | `http://127.0.0.1:8102/login` | `/api/whoami` |
| 8103 | express-form | `http://127.0.0.1:8103/login` | `/api/whoami` |
| 8104 | dotnet-form | `http://127.0.0.1:8104/login` | `/api/whoami` |
| 8201 | react-json-cookie | `http://127.0.0.1:8201/login` | `/api/whoami` |
| 8202 | fastapi-dynamic | `http://127.0.0.1:8202/` | `/api/whoami` |
| 8203 | go-multistep | `http://127.0.0.1:8203/login` | `/api/whoami` |
| 8301 | delayed-render | `http://127.0.0.1:8301/login` | `/api/whoami` |
| 8302 | nonstandard-fields | `http://127.0.0.1:8302/login` | `/api/whoami` |
| 8303 | hash-spa | `http://127.0.0.1:8303/#/signin` | `/api/whoami` |
| 8304 | enter-submit | `http://127.0.0.1:8304/login` | `/api/whoami` |
| 8305 | iframe-login | `http://127.0.0.1:8305/login` | `/api/whoami` |
| 8306 | otp-challenge | `http://127.0.0.1:8306/login` | `/api/whoami` |
| 8401 | HTTP Basic | `http://127.0.0.1:8401/` | `/api/whoami` |
| 8402 | HTTP Digest | `http://127.0.0.1:8402/` | `/api/whoami` |
| 8403 | Bearer token | `http://127.0.0.1:8403/` | `/api/whoami` |
| 8404 | API key header | `http://127.0.0.1:8404/` | `/api/whoami` |
| 8405 | two custom headers | `http://127.0.0.1:8405/` | `/api/whoami` |
| 8406 | Basic then form | `http://127.0.0.1:8406/login` | `/api/whoami` |
| 8501 | modal-after-click | `http://127.0.0.1:8501/login` | `/api/whoami` |
| 8502 | consent-checkbox | `http://127.0.0.1:8502/login` | `/api/whoami` |
| 8503 | JWT localStorage | `http://127.0.0.1:8503/login` | `/api/whoami` with Bearer propagated from browser |
| 8504 | SSO app | `http://sso-app.localhost:8504/login` | `http://sso-app.localhost:8504/api/whoami` |
| 8506 | cross-host SSO app | `http://customer-app.localhost:8506/login` | `http://customer-app.localhost:8506/api/whoami` |
| 8601 | NTLM | `http://127.0.0.1:8601/` | `/api/whoami` |
| 8602 | Kerberos/SPNEGO | Docker: `http://kerberos-web.zap.test:8080/`; host: `http://kerberos-web.zap.test:8602/` | `/api/whoami` |

## Mechanism matrix to fill in

Use `yes/no/partial` and add notes when ZAP logs in but scanner requests are not authenticated.

| Scenario | Form | JSON | Browser auto | HTTP/NTLM | Header/Replacer | Client/Auth script | Notes |
|---|---|---|---|---|---|---|---|
| spring-form | | | | | | | |
| django-form | | | | | | | |
| express-form | | | | | | | |
| dotnet-form | | | | | | | |
| react-json-cookie | | | | | | | |
| fastapi-dynamic | | | | | | | |
| go-multistep | | | | | | | |
| delayed-render | | | | | | | |
| nonstandard-fields | | | | | | | |
| hash-spa | | | | | | | |
| enter-submit | | | | | | | |
| iframe-login | | | | | | | |
| otp-challenge | | | | | | | |
| http-basic | | | | | | | |
| http-digest | | | | | | | |
| bearer-token | | | | | | | |
| api-key-header | | | | | | | |
| multi-header | | | | | | | |
| basic-then-form | | | | | | | |
| modal-login | | | | | | | |
| consent-checkbox | | | | | | | |
| localstorage-jwt | | | | | | | |
| sso-redirect | | | | | | | |
| cross-host-sso | | | | | | | |
| ntlm | | | | | | | |
| kerberos-spnego | | | | | | | |

## Scanner-state worksheet

| Scenario | login phase | whoami | private | spider | active scan | reauth | Notes |
|---|---|---|---|---|---|---|---|
| spring-form | | | | | | | |
| django-form | | | | | | | |
| express-form | | | | | | | |
| dotnet-form | | | | | | | |
| react-json-cookie | | | | | | | |
| fastapi-dynamic | | | | | | | |
| go-multistep | | | | | | | |
| delayed-render | | | | | | | |
| nonstandard-fields | | | | | | | |
| hash-spa | | | | | | | |
| enter-submit | | | | | | | |
| iframe-login | | | | | | | |
| otp-challenge | | | | | | | |
| http-basic | | | | | | | |
| http-digest | | | | | | | |
| bearer-token | | | | | | | |
| api-key-header | | | | | | | |
| multi-header | | | | | | | |
| basic-then-form | | | | | | | |
| modal-login | | | | | | | |
| consent-checkbox | | | | | | | |
| localstorage-jwt | | | | | | | |
| sso-redirect | | | | | | | |
| cross-host-sso | | | | | | | |
| ntlm | | | | | | | |
| kerberos-spnego | | | | | | | |

## Docker network names

```text
spring-form:8080
django-form:8000
express-form:3000
dotnet-form:8080
react-json-cookie:3000
fastapi-dynamic:8000
go-multistep:8080
delayed-render:3000
nonstandard-fields:3000
hash-spa:3000
enter-submit:3000
iframe-login:3000
otp-challenge:3000
http-basic:3000
http-digest:3000
bearer-token:3000
api-key-header:3000
multi-header:3000
basic-then-form:3000
modal-login:3000
consent-checkbox:3000
localstorage-jwt:3000
sso-app.localhost:8504
sso-idp.localhost:8505
customer-app.localhost:8506
identity.localhost:8507
ntlm-auth.zap.test:8080
kerberos-kdc.zap.test:88
kerberos-web.zap.test:8080
```

## Kerberos generated inputs for ZAP

After `docker compose --profile kerberos up --build -d`:

```text
Docker/container ZAP:
  config    = kerberos-generated/krb5-docker.conf
  keytab    = kerberos-generated/zapuser.keytab
  principal = zapuser@ZAP.TEST
  target    = http://kerberos-web.zap.test:8080

Host ZAP/backend:
  config    = kerberos-generated/krb5-host.conf
  keytab    = kerberos-generated/zapuser.keytab
  principal = zapuser@ZAP.TEST
  target    = http://kerberos-web.zap.test:8602
```

For host mode add:

```text
127.0.0.1 kerberos-web.zap.test
```

`http.keytab` is deliberately the server keytab and must not be supplied as the client keytab.

## v5 HTTP Sender script-auth additions

| Port | Scenario | Entry/login | Verify | Dedicated HTTP Sender script |
|---:|---|---|---|---|
| 8701 | script-jwt-exp | `POST /api/login` | `/api/whoami`, `/private` | `token-lab/01-jwt-exp-parsing.js` |
| 8702 | script-token-timeout | `POST /api/login` | `/api/whoami`, `/private` | `token-lab/02-token-refresh-timeout.js` |
| 8703 | script-token-check | `POST /api/login`, check `/me` | `/api/whoami`, `/private` | `token-lab/03-token-refresh-timeout-and-check.js` |
| 8704 | mock-1c | `POST /app/e1cib/start` + `/app/ru_RU/e1cib/login` | `/RPS/hs/WMSService/messagequeue/...` | `existing-apps/09-1c-vrs-session.js` |

Representative existing targets with dedicated comparison scripts are documented in `SCRIPT_AUTH_TESTS.md`.
