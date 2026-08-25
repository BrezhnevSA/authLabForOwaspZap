# Mock 1C VRS-session authentication

This fixture emulates the 1C HTTP flow used by `http-sender-scripts/existing-apps/09-1c-vrs-session.js`.

Flow:

1. `POST /app/e1cib/start` with `usr`, `pwd`, `authfailhandling=error`.
2. Response: `301`, `vrs-session2: <UUID>`, and a landing `Location`.
3. Landing redirects to `/app/ru_RU/`.
4. `POST /app/ru_RU/e1cib/login?...&sid=<UUID>&nooida&vl=ru&clnId=<UUID>`.
5. Successful response contains `"seance":"<sid>"`.
6. Protected requests require `vrs-session: <plain sid UUID>`.

The fixture deliberately rejects a non-UUID `clnId`, so it catches the regression where an OIDC client id is accidentally reused as the 1C web-client id.

Docker URL visible to ZAP on the testbed network:

```text
http://mock-1c:8704
```

Host port:

```text
http://127.0.0.1:8704
```

Test credentials are the common testbed credentials: `zapuser` / `ZapTest123!`.

Protected endpoints:

```text
GET /app/api/orders
GET /RPS/hs/WMSService/messagequeue/3421247882389737259
```

The second endpoint intentionally lives outside `/app` on the same host, verifying the host-only `isManagedRequest()` behavior. Both return `401` without `vrs-session` and return JSON containing `"authenticated":true` after the HTTP Sender script injects a valid session.

OpenAPI:

```text
http://mock-1c:8704/openapi.json
```
