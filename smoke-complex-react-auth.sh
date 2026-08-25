#!/usr/bin/env sh
set -eu

BASE="${COMPLEX_AUTH_BASE_URL:-http://127.0.0.1:8711}"
CONTROL_TOKEN="${TESTBED_CONTROL_TOKEN:-zap-testbed-reset-v1}"
USERNAME="${COMPLEX_AUTH_USERNAME:-zapuser}"
PASSWORD="${COMPLEX_AUTH_PASSWORD:-ZapTest123!}"

code() {
  curl -sS -o /tmp/complex-auth-smoke-body -w '%{http_code}' "$@"
}

printf '%-36s ' 'React login page'
status=$(code "$BASE/app/#/login")
echo "$status"; [ "$status" = 200 ]

printf '%-36s ' 'Classic form encoding rejected'
status=$(code -X POST "$BASE/api/auth/login" -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "username=$USERNAME" --data-urlencode "password=$PASSWORD")
echo "$status"; [ "$status" = 415 ]

printf '%-36s ' 'Anonymous protected API rejected'
status=$(code "$BASE/api/auth/currentUser")
echo "$status"; [ "$status" = 401 ]

login=$(curl -fsS -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' --data "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
token=$(printf '%s' "$login" | node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const j=JSON.parse(s);if(!j.access_token)process.exit(2);process.stdout.write(j.access_token)})')

printf '%-36s ' 'Bearer protected API accepted'
status=$(code "$BASE/api/auth/currentUser" -H "Authorization: Bearer $token")
echo "$status"; [ "$status" = 200 ]

printf '%-36s ' 'Business endpoint accepted'
status=$(code "$BASE/api/orders?status=open" -H "Authorization: Bearer $token")
echo "$status"; [ "$status" = 200 ]

printf '%-36s ' 'Hidden reset without header'
status=$(code -X POST "$BASE/__testbed/control/reset")
echo "$status"; [ "$status" = 404 ]

printf '%-36s ' 'Hidden reset with control header'
status=$(code -X POST "$BASE/__testbed/control/reset" -H "X-Testbed-Control: $CONTROL_TOKEN")
echo "$status"; [ "$status" = 200 ]

curl -fsS "$BASE/__testbed/coverage"; echo
