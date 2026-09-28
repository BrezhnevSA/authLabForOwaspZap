#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PFX="${CLIENT_CERTIFICATE_FILE:-${SCRIPT_DIR}/client-cert-auth/certs/client-auth.pfx}"
PFX_PASSWORD="${CLIENT_CERTIFICATE_PASSWORD:-ZapCert123!}"
TARGET="${CLIENT_CERT_TARGET_URL:-https://127.0.0.1:8712}"
CONTROL="${CLIENT_CERT_CONTROL_URL:-http://127.0.0.1:9712}"
TOKEN="${TESTBED_CONTROL_TOKEN:-zap-testbed-reset-v1}"

[[ -s "$PFX" ]] || { echo "Missing PFX: $PFX" >&2; exit 2; }

printf 'anonymous TLS handshake ... '
if curl -kfsS --connect-timeout 3 "$TARGET/" >/dev/null 2>&1; then
  echo 'FAIL (target accepted connection without a client certificate)' >&2
  exit 1
else
  echo 'PASS (rejected)'
fi

printf 'PFX authenticated request ... '
curl -kfsS --connect-timeout 3 --cert-type P12 --cert "${PFX}:${PFX_PASSWORD}" "$TARGET/api/whoami" \
  | grep -q '"authenticated": true'
echo 'PASS'

printf 'coverage control ... '
curl -fsS --connect-timeout 3 -X POST -H "X-Testbed-Control: ${TOKEN}" "$CONTROL/__testbed/control/reset" >/dev/null
curl -kfsS --connect-timeout 3 --cert-type P12 --cert "${PFX}:${PFX_PASSWORD}" "$TARGET/api/orders?status=smoke" >/dev/null
curl -fsS --connect-timeout 3 "$CONTROL/__testbed/coverage" | grep -q '"visited": 1'
echo 'PASS'
