#!/usr/bin/env bash
set -Eeuo pipefail

USER='zapuser'
PASS='ZapTest123!'

require() { command -v "$1" >/dev/null || { echo "missing command: $1" >&2; exit 1; }; }
require curl
require jq

login() {
  local base=$1
  curl -fsS -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" \
    "$base/api/login"
}

for port in 8701 8702 8703; do
  base="http://127.0.0.1:$port"
  echo "== $base =="
  response=$(login "$base")
  token=$(jq -er .auth_token <<<"$response")
  curl -fsS -H "Authorization: Bearer $token" "$base/api/whoami" | jq .
  curl -fsS "$base/api/stats" | jq .
  echo
done
