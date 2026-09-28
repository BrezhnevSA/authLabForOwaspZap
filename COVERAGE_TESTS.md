# Unified testbed coverage API

Every application in the testbed now exposes the same **unlinked** diagnostic contract. Normally it is on the application port; the 8712 mTLS fixture serves it on loopback-only port 9712 so the scan target can keep strict TLS client-certificate enforcement:

```text
GET  /__testbed/expected
GET  /__testbed/coverage
POST /__testbed/control/reset
```

The reset endpoint requires:

```text
X-Testbed-Control: zap-testbed-reset-v1
```

Without that header it returns `404`. None of the `__testbed` endpoints are linked from the application UI or included in fixture OpenAPI documents, so normal Spider/AJAX Spider discovery should not reach them. The diagnostic requests themselves are excluded from coverage and authentication counters.

## Why coverage is split in two

The response separates **discovery** from **authentication**. `checkAuthUrl`/polling endpoints such as `/api/whoami`, `/me`, and `/api/auth/currentUser` are intentionally not counted as discovered business endpoints because the DAST runner calls those directly.

Representative response:

```json
{
  "application": "react-json-cookie",
  "scenario": "json-login-cookie-session",
  "discovery": {
    "expected": 4,
    "visited": 3,
    "coveragePercent": 75.0,
    "visitedEndpoints": ["/private", "/api/profile", "/api/orders"],
    "missingEndpoints": ["/api/documents"]
  },
  "authentication": {
    "loginAttempts": 1,
    "successfulLogins": 1,
    "authenticatedRequests": 34,
    "unauthorizedRequests": 2
  }
}
```

Applications add scenario-specific counters where useful. Token fixtures expose token issuance/check/expiry counters, SSO fixtures expose authorize/callback/state counters, and the 1C fixture exposes `vrs-session` lifecycle counters.

## Coverage levels

- **Minimal**: 8101-8104, 8401-8405, 8601-8602. The primary protected endpoint is enough; the main value is auth request/challenge counters.
- **Full auth/discovery**: 8201-8203, 8301-8306, 8406, 8501-8507, 8701-8704. These expose multiple protected business endpoints or flow-specific state counters.
- **Discovery regression**: 8705-8711. Existing deterministic coverage remains, now with the same `discovery` object shape (backward-compatible top-level fields are retained where older helpers used them).

## CLI helper

```bash
./testbed-coverage.sh reset all
# run check/scan
./testbed-coverage.sh summary all
```

Useful focused commands:

```bash
./testbed-coverage.sh reset complex-react-auth
./testbed-coverage.sh show complex-react-auth
./testbed-coverage.sh expected 8704
```

The Kerberos service on 8602 is optional and will appear as unavailable unless the `kerberos` compose profile is running.

## DAST runner integration

`tools/run-dast-scans-postman-sync-with-cert-mode.sh` resets the selected target counters before each check/scan by default:

```text
RESET_TESTBED_COVERAGE=true
```

For synchronous `ACTION=check` it also prints compact coverage immediately afterwards:

```text
SHOW_CHECK_COVERAGE=true
```

A DAST scan is asynchronous, so the runner only prints the corresponding coverage URL. Query it after the scan finishes or use `testbed-coverage.sh summary`.

For SSO targets, resetting `sso-redirect` resets both 8504 and 8505; resetting `cross-host-sso` resets both 8506 and 8507. For `client-cert-auth` (8712), the scan target is HTTPS/mTLS on 8712 while the hidden coverage/reset API is `http://127.0.0.1:9712` so the crawler cannot discover or mutate its counters.
