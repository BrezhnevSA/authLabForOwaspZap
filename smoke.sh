#!/usr/bin/env sh
set -eu

check_code() {
  name="$1"; url="$2"; expected="$3"
  code=$(curl -sS -o /dev/null -w '%{http_code}' "$url" || true)
  printf '%-26s %-3s expected=%s\n' "$name" "$code" "$expected"
}

# Public/login entry checks.
check_code spring-form http://127.0.0.1:8101/login 200
check_code django-form http://127.0.0.1:8102/login 200
check_code express-form http://127.0.0.1:8103/login 200
check_code dotnet-form http://127.0.0.1:8104/login 200
check_code react-json-cookie http://127.0.0.1:8201/login 200
check_code fastapi-dynamic http://127.0.0.1:8202/ 200
check_code go-multistep http://127.0.0.1:8203/login 200
check_code delayed-render http://127.0.0.1:8301/login 200
check_code nonstandard-fields http://127.0.0.1:8302/login 200
check_code hash-spa http://127.0.0.1:8303/ 200
check_code enter-submit http://127.0.0.1:8304/login 200
check_code iframe-login http://127.0.0.1:8305/login 200
check_code otp-challenge http://127.0.0.1:8306/login 200

# HTTP/header auth should reject anonymous requests.
for p in 8401 8402 8403 8404 8405 8406 8601; do check_code "anonymous-$p" "http://127.0.0.1:$p/api/whoami" 401; done

# Positive protocol checks.
printf '%-26s ' http-basic-authenticated
curl -fsS -u 'zapuser:ZapTest123!' http://127.0.0.1:8401/api/whoami; echo
printf '%-26s ' http-digest-authenticated
curl -fsS --digest -u 'zapuser:ZapTest123!' http://127.0.0.1:8402/api/whoami; echo
printf '%-26s ' bearer-authenticated
curl -fsS -H 'Authorization: Bearer zap-bearer-token-2026' http://127.0.0.1:8403/api/whoami; echo
printf '%-26s ' apikey-authenticated
curl -fsS -H 'X-API-Key: zap-api-key-2026' http://127.0.0.1:8404/api/whoami; echo
printf '%-26s ' multiheader-authenticated
curl -fsS -H 'X-Client-Id: zap-client' -H 'X-Client-Secret: zap-client-secret-2026' http://127.0.0.1:8405/api/whoami; echo

# New browser-flow entry checks.
check_code modal-login http://127.0.0.1:8501/login 200
check_code consent-checkbox http://127.0.0.1:8502/login 200
check_code localstorage-jwt http://127.0.0.1:8503/login 200
check_code sso-app http://sso-app.localhost:8504/login 302
check_code cross-domain-app http://customer-app.localhost:8506/login 302

cat <<'TXT'

NTLM positive authentication is intentionally not attempted by this generic smoke script;
use ZAP HTTP/NTLM Authentication or an NTLM-capable client.
For Kerberos run:
  docker compose --profile kerberos run --rm kerberos-client-check
TXT
