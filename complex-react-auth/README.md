# complex-react-auth (8711)

Regression fixture for a visually conventional username/password React login that is intentionally incompatible with classic form-based authentication.

## Why Form Based Authentication should fail

The page contains `username`, `password`, and a normal submit button, but React calls `preventDefault()` and sends JSON to `POST /api/auth/login`. The server rejects `application/x-www-form-urlencoded` with HTTP 415. No authentication cookie is created.

After successful browser login, the JSON response contains `access_token`. React stores it in `localStorage` and protected APIs accept only:

```text
Authorization: Bearer <access_token>
```

This is intended to validate Browser Based Authentication with session-header extraction.

## Discovery behavior

All navigation after login uses clickable `div` elements. There are no business `<a href>` links and no navigation buttons. Some menu items exist only after opening another `div` dropdown, and API paths are assembled at runtime.

Expected protected business endpoints:

- `/api/dashboard` - plain DIV, depth 1
- `/api/orders` - DIV inside a dropdown, depth 2
- `/api/contracts` - DIV inside a nested dropdown, depth 3
- `/api/archive` - DIV inside a nested dropdown, depth 3
- `/api/customers` - DIV with `role=menuitem`
- `/api/reports` - plain DIV, depth 1

## Testbed endpoints

```text
GET /__testbed/expected
GET /__testbed/coverage
```

Reset is deliberately undiscoverable from the UI and requires the testbed control header:

```text
POST /__testbed/control/reset
X-Testbed-Control: <testbed control token>
```

The reset endpoint returns 404 without the control header and is not linked from the application.
