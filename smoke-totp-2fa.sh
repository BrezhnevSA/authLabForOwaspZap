#!/usr/bin/env bash
set -Eeuo pipefail

# Standalone end-to-end TOTP check. For a non-default app seed export TOTP_SECRET.
BASE_URL="${TOTP_BASE_URL:-http://127.0.0.1:8714}"
USERNAME="${TOTP_USERNAME:-zapuser}"
PASSWORD="${TOTP_PASSWORD:-ZapTest123!}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v node >/dev/null || { echo 'node is required for TOTP generation' >&2; exit 2; }
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 2; }
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

expect() {
  local expected="$1" name="$2"; shift 2
  local actual
  actual=$(curl -sS -o /dev/null -w '%{http_code}' "$@")
  printf '%-28s HTTP %s (expected %s)\n' "$name" "$actual" "$expected"
  [[ "$actual" == "$expected" ]] || { echo "FAIL: $name" >&2; exit 1; }
}

expect 200 login-page "$BASE_URL/login"
expect 401 unauthorized-before "$BASE_URL/api/whoami"
expect 303 password-accepted -c "$COOKIE_JAR" -b "$COOKIE_JAR" --data-urlencode "username=$USERNAME" --data-urlencode "password=$PASSWORD" "$BASE_URL/login"
expect 401 pending-not-authenticated -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE_URL/api/whoami"
expect 200 totp-page -b "$COOKIE_JAR" "$BASE_URL/2fa"
CODE=$(node "$SCRIPT_DIR/totp-2fa/totp.js")
expect 303 totp-accepted -c "$COOKIE_JAR" -b "$COOKIE_JAR" --data-urlencode "otp=$CODE" "$BASE_URL/2fa"
expect 200 authenticated -b "$COOKIE_JAR" "$BASE_URL/api/whoami"
expect 200 private-page -b "$COOKIE_JAR" "$BASE_URL/private"
expect 303 logout -c "$COOKIE_JAR" -b "$COOKIE_JAR" -X POST "$BASE_URL/logout"
expect 401 unauthorized-after-logout -b "$COOKIE_JAR" "$BASE_URL/api/whoami"
echo 'TOTP 2FA end-to-end check passed.'
