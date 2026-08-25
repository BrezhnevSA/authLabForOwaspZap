# Complex React Auth regression fixture (8711)

Target: `http://complex-react-auth:8711/app/#/login` from the ZAP Docker network, or `http://127.0.0.1:8711/app/#/login` from the host.

## Authentication behavior

The page visibly contains a conventional username/password form. React intercepts submit with `preventDefault()` and sends:

```http
POST /api/auth/login
Content-Type: application/json
```

Classic form encoding is rejected with HTTP 415 and `JSON_CONTENT_TYPE_REQUIRED`. No session cookie is issued. On success the response contains `access_token`, which React stores in `localStorage`. Protected endpoints require a Bearer header.

The existing browser-auth session-header template can be used:

```json
{"Authorization":"Bearer {%json:access_token%}"}
```

`GET /api/whoami` and `GET /api/auth/currentUser` both work as authenticated polling/check endpoints.

## DIV-only navigation

Business navigation intentionally avoids anchors and navigation buttons:

- Dashboard: plain clickable DIV.
- Operations -> Orders: dropdown DIV, depth 2.
- Operations -> Documents -> Contracts: nested dropdown DIV, depth 3.
- Operations -> Documents -> Archive: nested dropdown DIV, depth 3.
- Customers: DIV with `role=menuitem`.
- Reports: plain clickable DIV.

The complete business API URL is not present in the initial HTML; the React code assembles paths at runtime.

## Coverage

```text
GET /__testbed/expected
GET /__testbed/coverage
```

Coverage also reports authentication counters such as login attempts, successful logins, wrong content types, unauthorized requests, and valid authenticated requests.

Reset is intentionally unlinked:

```http
POST /__testbed/control/reset
X-Testbed-Control: <testbed control token>
```

Without the header it returns 404.
