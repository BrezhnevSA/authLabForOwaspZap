#!/usr/bin/env bash
set -Eeuo pipefail

TOKEN="${TESTBED_CONTROL_TOKEN:-zap-testbed-reset-v1}"
ACTION="${1:-summary}"
FILTER="${2:-all}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-2}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-10}"

apps=$(cat <<'EOF'
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
)

usage(){ cat <<'EOF'
Usage: ./testbed-coverage.sh [summary|show|expected|reset] [all|name|port]

Examples:
  ./testbed-coverage.sh reset all
  ./testbed-coverage.sh summary all
  ./testbed-coverage.sh show mock-1c
  ./testbed-coverage.sh expected 8711

The reset endpoint is intentionally hidden from crawlers and requires X-Testbed-Control.
Kerberos (8602) can be unavailable unless the kerberos compose profile is running.
EOF
}

[[ "$ACTION" != '-h' && "$ACTION" != '--help' ]] || { usage; exit 0; }
case "$ACTION" in summary|show|coverage|expected|reset) ;; *) usage >&2; exit 2;; esac
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 2; }

selected(){ local port=$1 name=$2; [[ "$FILTER" == all || "$FILTER" == "$port" || "$FILTER" == "$name" ]]; }

found=0
while IFS='|' read -r port name control_base; do
  selected "$port" "$name" || continue
  found=1
  base="${control_base:-http://127.0.0.1:${port}}"
  case "$ACTION" in
    reset)
      code=$(curl -sS -o /tmp/zap-testbed-coverage.$$ -w '%{http_code}' --connect-timeout "$CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -X POST -H "X-Testbed-Control: ${TOKEN}" "${base}/__testbed/control/reset" || true)
      if [[ "$code" == 200 ]]; then printf '%-5s %-24s reset OK\n' "$port" "$name"; else printf '%-5s %-24s unavailable/reset failed (HTTP %s)\n' "$port" "$name" "${code:-curl-error}"; fi
      rm -f /tmp/zap-testbed-coverage.$$
      ;;
    expected)
      printf '\n== %s (%s) ==\n' "$name" "$port"
      curl -fsS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" "${base}/__testbed/expected" || printf '{"unavailable":true}\n'
      printf '\n'
      ;;
    show|coverage)
      printf '\n== %s (%s) ==\n' "$name" "$port"
      curl -fsS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" "${base}/__testbed/coverage" || printf '{"unavailable":true}\n'
      printf '\n'
      ;;
    summary)
      payload=$(curl -fsS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" "${base}/__testbed/coverage" 2>/dev/null || true)
      if [[ -z "$payload" ]]; then printf '%-5s %-24s unavailable\n' "$port" "$name"; continue; fi
      if command -v jq >/dev/null; then
        printf '%s' "$payload" | jq -r --arg p "$port" --arg n "$name" '
          (.discovery // {expected:.expected,visited:.visited,coveragePercent:.coveragePercent}) as $d |
          (.authentication // {}) as $a |
          [$p,$n,(($d.visited//0)|tostring)+"/"+(($d.expected//0)|tostring), (($d.coveragePercent//0)|tostring)+"%", (($a.successfulLogins//$a.tokensIssued//$a.authenticatedRequests//0)|tostring), (($a.unauthorizedRequests//0)|tostring)] | @tsv' \
          | awk -F '\t' '{printf "%-5s %-24s discovery=%-8s %-8s auth-success=%-6s unauthorized=%s\n",$1,$2,$3,$4,$5,$6}'
      else
        printf '%-5s %-24s %s\n' "$port" "$name" "$payload"
      fi
      ;;
  esac
done <<< "$apps"

[[ "$found" -eq 1 ]] || { echo "Unknown app/port: $FILTER" >&2; exit 2; }
