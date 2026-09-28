#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOKEN="${TESTBED_CONTROL_TOKEN:-zap-testbed-reset-v1}"

# Only verifies diagnostic API availability. It does not require the protected auth flow to succeed.
failed=0
while IFS='|' read -r port name control_base; do
  [[ -n "$port" ]] || continue
  base="${control_base:-http://127.0.0.1:${port}}"
  if [[ "$port" == 8602 ]] && ! curl -fsS --connect-timeout 1 "$base/health" >/dev/null 2>&1; then
    printf '%-5s %-24s SKIP (kerberos profile not running)\n' "$port" "$name"
    continue
  fi
  no_header=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 -X POST "$base/__testbed/control/reset" || true)
  reset=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 -X POST -H "X-Testbed-Control: $TOKEN" "$base/__testbed/control/reset" || true)
  cov=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 "$base/__testbed/coverage" || true)
  if [[ "$no_header" == 404 && "$reset" == 200 && "$cov" == 200 ]]; then
    printf '%-5s %-24s PASS\n' "$port" "$name"
  else
    printf '%-5s %-24s FAIL (reset-without-header=%s reset=%s coverage=%s)\n' "$port" "$name" "$no_header" "$reset" "$cov" >&2
    failed=1
  fi
done <<'EOF'
8101|spring-form
8102|django-form
8103|express-form
8104|dotnet-form
8201|react-json-cookie
8202|fastapi-dynamic
8203|go-multistep
8301|delayed-render
8302|nonstandard-fields
8303|hash-spa
8304|enter-submit
8305|iframe-login
8306|otp-challenge
8401|http-basic
8402|http-digest
8403|bearer-token
8404|api-key-header
8405|multi-header
8406|basic-then-form
8501|modal-login
8502|consent-checkbox
8503|localstorage-jwt
8504|sso-app
8505|sso-idp
8506|cross-domain-app
8507|cross-domain-idp
8601|ntlm-auth
8602|kerberos-web
8701|script-jwt-exp
8702|script-token-timeout
8703|script-token-check
8704|mock-1c
8705|large-bundle-spa
8706|many-states-spa
8707|runtime-discovery-spa
8708|large-api-response
8709|bft-regression-spa
8710|scope-noise
8711|complex-react-auth
8712|client-cert-auth|http://127.0.0.1:9712
EOF
exit "$failed"
