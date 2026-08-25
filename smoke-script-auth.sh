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


echo "== mock-1c =="
base="http://127.0.0.1:8704"
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT
curl -fsS -D "$headers" -o /dev/null \
  -X POST "$base/app/e1cib/start" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "usr=$USER" \
  --data-urlencode "pwd=$PASS" \
  --data-urlencode 'authfailhandling=error'
sid=$(sed -n 's/^[Vv][Rr][Ss]-[Ss][Ee][Ss][Ss][Ii][Oo][Nn]2:[[:space:]]*\([^[:space:]\r]*\).*/\1/p' "$headers")
[[ -n "$sid" ]]
client_id='33361285-03a1-4368-b9c9-91385cdb2b60'
curl -fsS -X POST \
  "$base/app/ru_RU/e1cib/login?version=8.3.25.1445&sid=$sid&nooida&vl=ru&clnId=$client_id" \
  -H 'Content-Type: application/json; charset=UTF-8' \
  --data '' | jq -e --arg sid "$sid" '.response.seance == $sid' >/dev/null
curl -fsS \
  -H "vrs-session: $sid" \
  "$base/RPS/hs/WMSService/messagequeue/3421247882389737259" \
  | jq -e '.authenticated == true and .authenticatedBy == "vrs-session"' >/dev/null
echo "mock-1c direct flow: PASS"
