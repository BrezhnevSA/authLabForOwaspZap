#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly USERNAME='zapuser'
readonly PASSWORD='ZapTest123!'
readonly BEARER_TOKEN='zap-bearer-token-2026'
readonly API_KEY='zap-api-key-2026'
readonly CLIENT_ID='zap-client'
readonly CLIENT_SECRET='zap-client-secret-2026'
readonly LOGGED_IN_REGEX='"authenticated"\s*:\s*true'
readonly LOGGED_OUT_REGEX='"authenticated"\s*:\s*false'
readonly FORM_LOGGED_IN_INDICATOR='AUTHENTICATED'
readonly LOCALSTORAGE_SESSION_HEADERS='{"Authorization":"Bearer {%json:access_token%}"}'

NTLM_USERNAME="${NTLM_USERNAME:-ZAPLAB\\zapuser}"

declare -a FORM_TARGETS=()
declare -a BROWSER_TARGETS=()
declare -a PROTOCOL_TARGETS=()
declare -a SCRIPT_TARGETS=()
declare -a DISCOVERY_TARGETS=()
declare -a CERTIFICATE_TARGETS=()
declare -a ACTIVE_TARGETS=()
declare -a API_AUTH_ARGS=()

API_BASE_URL="${API_BASE_URL:-http://127.0.0.1:8080/app/api/v1}"
PROJECT_ID="${PROJECT_ID:-}"
APP_TOKEN="${APP_TOKEN:-}"
APP_LOGIN="${APP_LOGIN:-}"
APP_PASSWORD="${APP_PASSWORD:-}"
API_AUTH="${API_AUTH:-auto}"
TARGET_PROFILE="${TARGET_PROFILE:-docker}"
AUTH_MODE="${AUTH_MODE:-both}"
CERT_MODE="${CERT_MODE:-none}"
ACTION="${ACTION:-scan}"
ATTACK_MODE="${ATTACK_MODE:-STANDARD}"
AJAX_SPIDER_ENABLED="${AJAX_SPIDER_ENABLED:-true}"
AJAX_SPIDER_TIMEOUT="${AJAX_SPIDER_TIMEOUT:-5}"
REQUESTS_PER_SECOND="${REQUESTS_PER_SECOND:-0}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-300}"
BROWSER_LOGIN_PAGE_WAIT="${BROWSER_LOGIN_PAGE_WAIT:-5}"
BROWSER_STEP_DELAY="${BROWSER_STEP_DELAY:-0}"
BROWSER_POLL_FREQUENCY="${BROWSER_POLL_FREQUENCY:-60}"
BROWSER_POLL_FREQUENCY_UNITS="${BROWSER_POLL_FREQUENCY_UNITS:-REQUESTS}"
DELAY_BETWEEN_REQUESTS="${DELAY_BETWEEN_REQUESTS:-${DELAY_BETWEEN_SCANS:-0}}"
CONTINUE_ON_ERROR="${CONTINUE_ON_ERROR:-}"
STRICT_CHECKS="${STRICT_CHECKS:-true}"
VERBOSE_FAILURES="${VERBOSE_FAILURES:-true}"
RESULTS_DIR="${RESULTS_DIR:-}"
SKIP_KERBEROS="${SKIP_KERBEROS:-false}"
SKIP_SCRIPT_AUTH="${SKIP_SCRIPT_AUTH:-false}"
RESET_TESTBED_COVERAGE="${RESET_TESTBED_COVERAGE:-${RESET_DISCOVERY_COVERAGE:-true}}"
SHOW_CHECK_COVERAGE="${SHOW_CHECK_COVERAGE:-true}"
TESTBED_CONTROL_TOKEN="${TESTBED_CONTROL_TOKEN:-zap-testbed-reset-v1}"
ONLY="${ONLY:-}"
AGENT_ID="${AGENT_ID:-}"
DRY_RUN="${DRY_RUN:-false}"
KERBEROS_CONFIG_FILE="${KERBEROS_CONFIG_FILE:-${SCRIPT_DIR}/pr2/as-backend/zap-auth-testbed/kerberos-lab/generated/krb5.conf}"
KERBEROS_KEYTAB_FILE="${KERBEROS_KEYTAB_FILE:-${SCRIPT_DIR}/pr2/as-backend/zap-auth-testbed/kerberos-lab/generated/zapuser.keytab}"
SCRIPT_AUTH_DIR="${SCRIPT_AUTH_DIR:-${SCRIPT_DIR}/pr2/as-backend/zap-auth-testbed/http-sender-scripts}"
CLIENT_CERTIFICATE_FILE="${CLIENT_CERTIFICATE_FILE:-${SCRIPT_DIR}/../client-cert-auth/certs/client-auth.pfx}"
CLIENT_CERTIFICATE_PASSWORD="${CLIENT_CERTIFICATE_PASSWORD:-ZapCert123!}"
CLIENT_CERTIFICATE_INDEX="${CLIENT_CERTIFICATE_INDEX:-0}"

REQUEST_COUNT=0
REQUEST_FAILURES=0
CHECK_PASSES=0
CHECK_EXPECTED_FAILURES=0
CHECK_OBSERVED_FAILURES=0
CHECK_REGRESSIONS=0
CHECK_SKIPPED=0

usage() {
    cat <<'EOF'
Check authentication or launch DAST scans for zap-auth-testbed targets.

Required environment:
  PROJECT_ID       DAST project ID
  APP_TOKEN        Existing AppScreener JWT, or APP_LOGIN + APP_PASSWORD

Main switches:
  API_AUTH          auto, basic, jwt, or token. With auto, APP_TOKEN is preferred;
                    otherwise APP_LOGIN + APP_PASSWORD use Basic without creating a session
  ACTION            check (quick synchronous auth check) or scan. Default: scan
  AUTH_MODE         none, both, form, browser, protocol, script, discovery, or all. Default: both
  CERT_MODE         none or certificate. Independent from AUTH_MODE. Default: none
  TARGET_PROFILE    docker (names visible to ZAP) or host (127.0.0.1 ports)
  ONLY              Comma-separated target names
  AGENT_ID          DAST agent ID. For check it is resolved from the project if omitted
  STRICT_CHECKS     Return non-zero when a known passing check regresses. Default: true
  VERBOSE_FAILURES  Print compact response details for failed auth checks. Default: true
  RESULTS_DIR       Optional directory for complete checkAuth JSON responses
  SKIP_KERBEROS     Skip Kerberos when its generated files are absent. Default: false
  SKIP_SCRIPT_AUTH  Skip script-auth targets when their JS files are absent. Default: false
  RESET_TESTBED_COVERAGE    Reset per-app coverage/auth counters before each selected check/scan. Default: true
  SHOW_CHECK_COVERAGE       Print compact coverage after synchronous checkAuth. Default: true
  SCRIPT_AUTH_DIR   Directory with HTTP Sender JS scripts
  CLIENT_CERTIFICATE_FILE      PFX/P12 file for CERT_MODE=certificate
  CLIENT_CERTIFICATE_PASSWORD  Password for the test client certificate
  CLIENT_CERTIFICATE_INDEX     Certificate index inside PKCS#12. Default: 0
  CONTINUE_ON_ERROR Continue after rejected requests. Default: true for check, false for scan
  CONNECT_TIMEOUT   Backend connection timeout in seconds. Default: 5
  HTTP_TIMEOUT      Maximum time for one backend request. Default: 300
  DRY_RUN           Print redacted curl commands without sending them

Protocol targets:
  http-basic, http-digest, bearer-token, api-key-header, multi-header,
  ntlm-auth, kerberos-web

New browser targets:
  basic-then-form, modal-login, consent-checkbox, localstorage-jwt,
  sso-redirect, cross-host-sso, complex-react-auth

Script auth targets:
  express-form, react-json-cookie, spring-form, go-multistep,
  consent-checkbox, iframe-login, otp-challenge, localstorage-jwt,
  script-jwt-exp, script-token-timeout, script-token-check, mock-1c

Client certificate target (CERT_MODE=certificate, scan only):
  client-cert-auth (real mutual TLS, PFX/P12 client certificate)

Discovery targets (scan only):
  large-bundle-spa, many-states-spa, runtime-discovery-spa,
  large-api-response, bft-regression-spa, scope-noise

Examples:
  ACTION=check AUTH_MODE=protocol PROJECT_ID=42 \
    APP_LOGIN=admin APP_PASSWORD='...' ./run-dast-scans.sh
  ACTION=check AUTH_MODE=protocol PROJECT_ID=42 APP_TOKEN='...' ./run-dast-scans.sh
  ACTION=check AUTH_MODE=browser ONLY=modal-login,localstorage-jwt \
    PROJECT_ID=42 APP_TOKEN='...' ./run-dast-scans.sh
  ACTION=scan AUTH_MODE=all PROJECT_ID=42 APP_TOKEN='...' ./run-dast-scans.sh
  ACTION=scan AUTH_MODE=script PROJECT_ID=42 APP_TOKEN='...' ./run-dast-scans.sh
  ACTION=scan AUTH_MODE=none CERT_MODE=certificate ONLY=client-cert-auth PROJECT_ID=42 APP_TOKEN='...' ./run-dast-scans.sh
  ACTION=scan AUTH_MODE=discovery ONLY=large-bundle-spa,many-states-spa \
    PROJECT_ID=42 APP_TOKEN='...' ./run-dast-scans.sh
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

is_true() {
    case "${1,,}" in
        true|1|yes) return 0 ;;
        *) return 1 ;;
    esac
}

is_selected() {
    local name=$1
    local -a selected_targets
    local selected

    [[ -z "$ONLY" ]] && return 0
    IFS=',' read -r -a selected_targets <<< "$ONLY"
    for selected in "${selected_targets[@]}"; do
        selected=${selected#"${selected%%[![:space:]]*}"}
        selected=${selected%"${selected##*[![:space:]]}"}
        [[ "$name" == "$selected" ]] && return 0
    done
    return 1
}

validate_only() {
    local -a requested_targets
    local requested
    local target
    local name
    local found

    [[ -z "$ONLY" ]] && return
    IFS=',' read -r -a requested_targets <<< "$ONLY"
    for requested in "${requested_targets[@]}"; do
        requested=${requested#"${requested%%[![:space:]]*}"}
        requested=${requested%"${requested##*[![:space:]]}"}
        found=false
        for target in "${ACTIVE_TARGETS[@]}"; do
            name=${target%%|*}
            if [[ "$requested" == "$name" ]]; then
                found=true
                break
            fi
        done
        is_true "$found" || die "Target '$requested' is not available for AUTH_MODE=$AUTH_MODE, CERT_MODE=$CERT_MODE"
    done
}

acquire_token() {
    local response
    local status
    local body

    [[ -n "$APP_LOGIN" && -n "$APP_PASSWORD" ]] || {
        die 'API_AUTH=jwt requires APP_TOKEN or both APP_LOGIN and APP_PASSWORD'
    }

    response=$(curl --silent --show-error \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$HTTP_TIMEOUT" \
        --write-out $'\n%{http_code}' \
        --request POST "${API_BASE_URL%/}/auth/jwt" \
        --header 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "username=${APP_LOGIN}" \
        --data-urlencode "password=${APP_PASSWORD}" \
        --data-urlencode 'token_name=zap-auth-testbed-postman')
    status=${response##*$'\n'}
    body=${response%$'\n'*}
    [[ "$status" =~ ^2[0-9][0-9]$ ]] || {
        printf '%s\n' "$body" >&2
        die "Authentication failed with HTTP $status"
    }
    APP_TOKEN=$(jq -er '.accessToken' <<< "$body") || {
        die 'Authentication response has no accessToken'
    }
}

configure_api_auth() {
    local selected=$API_AUTH

    if [[ "$selected" == auto ]]; then
        if [[ -n "$APP_TOKEN" ]]; then
            selected=token
        elif [[ -n "$APP_LOGIN" && -n "$APP_PASSWORD" ]]; then
            selected=basic
        elif is_true "$DRY_RUN"; then
            selected=token
            APP_TOKEN='<APP_TOKEN>'
        else
            die 'Set APP_TOKEN or both APP_LOGIN and APP_PASSWORD'
        fi
    fi

    case "$selected" in
        basic)
            [[ -n "$APP_LOGIN" && -n "$APP_PASSWORD" ]] || {
                die 'API_AUTH=basic requires APP_LOGIN and APP_PASSWORD'
            }
            API_AUTH_ARGS=(--user "${APP_LOGIN}:${APP_PASSWORD}")
            ;;
        jwt)
            if [[ -z "$APP_TOKEN" ]]; then
                if is_true "$DRY_RUN"; then
                    APP_TOKEN='<APP_TOKEN_FROM_LOGIN>'
                else
                    acquire_token
                fi
            fi
            API_AUTH_ARGS=(--header "Authorization: Bearer ${APP_TOKEN}")
            ;;
        token)
            if [[ -z "$APP_TOKEN" ]]; then
                if is_true "$DRY_RUN"; then
                    APP_TOKEN='<APP_TOKEN>'
                else
                    die 'API_AUTH=token requires APP_TOKEN'
                fi
            fi
            API_AUTH_ARGS=(--header "Authorization: Bearer ${APP_TOKEN}")
            ;;
        *) die 'API_AUTH must be auto, basic, jwt, or token' ;;
    esac
    API_AUTH=$selected
}

resolve_agent_id() {
    local response
    local status
    local body

    [[ "$ACTION" == check ]] || return 0
    if [[ -n "$AGENT_ID" ]]; then
        [[ "$AGENT_ID" =~ ^[1-9][0-9]*$ ]] || die 'AGENT_ID must be a positive integer'
        return
    fi
    if is_true "$DRY_RUN"; then
        AGENT_ID='<AGENT_ID>'
        return
    fi

    response=$(curl --silent --show-error \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$HTTP_TIMEOUT" \
        --write-out $'\n%{http_code}' \
        --request GET "${API_BASE_URL%/}/dastProjects/${PROJECT_ID}" \
        "${API_AUTH_ARGS[@]}")
    status=${response##*$'\n'}
    body=${response%$'\n'*}
    [[ "$status" =~ ^2[0-9][0-9]$ ]] || {
        printf '%s\n' "$body" >&2
        die "Cannot resolve project agent: HTTP $status"
    }
    AGENT_ID=$(jq -er '.agent | select(type == "number" and . > 0)' <<< "$body") || {
        die 'The project has no DAST agent; set AGENT_ID explicitly'
    }
}

set_target_profile() {
    case "$TARGET_PROFILE" in
        docker)
            FORM_TARGETS=(
                'spring-form|http://spring-form:8080|/login|/login|username|password|form|_csrf={csrfToken}|pass|'
                'django-form|http://django-form:8000|/login|/login|username|password|form|csrfmiddlewaretoken={csrfToken}|pass|'
                'express-form|http://express-form:3000|/login|/login|username|password|form||pass|'
                'dotnet-form|http://dotnet-form:8080|/login|/login|username|password|form|__RequestVerificationToken={csrfToken}|pass|'
                'react-json-cookie|http://react-json-cookie:3000|/login|/api/login|username|password|json||fail|'
                'fastapi-dynamic|http://fastapi-dynamic:8000|/|/api/login|username|password|json||fail|'
                'go-multistep|http://go-multistep:8080|/login|/login/username|username|password|multistep||fail|'
                'delayed-render|http://delayed-render:3000|/login|/login|username|password|form||pass|'
                'nonstandard-fields|http://nonstandard-fields:3000|/login|/session/start|employeeIdentifier|accessPhrase|form||pass|'
                'hash-spa|http://hash-spa:3000|/#/signin|/api/login|username|password|json||pass|'
                'enter-submit|http://enter-submit:3000|/login|/api/login|username|password|json||pass|'
                'iframe-login|http://iframe-login:3000|/login|/login|username|password|form||pass|'
                'otp-challenge|http://otp-challenge:3000|/login|/login|username|password|otp||fail|'
                'modal-login|http://modal-login:3000|/login|/login|username|password|form||observe|'
                'consent-checkbox|http://consent-checkbox:3000|/login|/api/login|username|password|json|consent=true|observe|'
                'localstorage-jwt|http://localstorage-jwt:3000|/login|/api/login|username|password|json||observe|'
                'complex-react-auth|http://complex-react-auth:8711|/app/#/login|/api/auth/login|username|password|json||fail|'
            )
            BROWSER_TARGETS=(
                'spring-form|http://spring-form:8080|/login|/login|username|password|form||pass||/private'
                'django-form|http://django-form:8000|/login|/login|username|password|form||pass||/private'
                'express-form|http://express-form:3000|/login|/login|username|password|form||pass||/private'
                'dotnet-form|http://dotnet-form:8080|/login|/login|username|password|form||pass||/private'
                'react-json-cookie|http://react-json-cookie:3000|/login|/api/login|username|password|json||pass||/api/whoami'
                'fastapi-dynamic|http://fastapi-dynamic:8000|/|/api/login|username|password|json||fail||/api/whoami'
                'go-multistep|http://go-multistep:8080|/login|/login/username|username|password|multistep||pass||/api/whoami'
                'delayed-render|http://delayed-render:3000|/login|/login|username|password|form||pass||/private'
                'nonstandard-fields|http://nonstandard-fields:3000|/login|/session/start|employeeIdentifier|accessPhrase|form||pass||/private'
                'hash-spa|http://hash-spa:3000|/#/signin|/api/login|username|password|json||pass||/api/whoami'
                'enter-submit|http://enter-submit:3000|/login|/api/login|username|password|json||pass||/api/whoami'
                'iframe-login|http://iframe-login:3000|/login|/login|username|password|form||fail||/private'
                'otp-challenge|http://otp-challenge:3000|/login|/login|username|password|otp||fail||/api/whoami'
                'basic-then-form|http://basic-then-form:3000|/login|/login|username|password|form||observe||/api/whoami'
                'modal-login|http://modal-login:3000|/login|/login|username|password|form||observe||/api/whoami'
                'consent-checkbox|http://consent-checkbox:3000|/login|/api/login|username|password|json||observe||/api/whoami'
                "localstorage-jwt|http://localstorage-jwt:3000|/login|/api/login|username|password|json||observe|${LOCALSTORAGE_SESSION_HEADERS}|/api/whoami"
                "complex-react-auth|http://complex-react-auth:8711|/app/#/login|/api/auth/login|username|password|json||pass|${LOCALSTORAGE_SESSION_HEADERS}|/api/auth/currentUser"
                'sso-redirect|http://sso-app.localhost:8504|/login|/authorize|username|password|form||observe||/api/whoami'
                'cross-host-sso|http://customer-app.localhost:8506|/login|/authorize|username|password|form||observe||/api/whoami'
            )
            PROTOCOL_TARGETS=(
                'http-basic|http://http-basic:3000|basic||||-|pass'
                'http-digest|http://http-digest:3000|http|http-digest|3000|ZAP-AUTH-LAB|-|pass'
                "bearer-token|http://bearer-token:3000|token||||${BEARER_TOKEN}|pass"
                "api-key-header|http://api-key-header:3000|headers||||{\"X-API-Key\":\"${API_KEY}\"}|pass"
                "multi-header|http://multi-header:3000|headers||||{\"X-Client-Id\":\"${CLIENT_ID}\",\"X-Client-Secret\":\"${CLIENT_SECRET}\"}|pass"
                "ntlm-auth|http://ntlm-auth.zap.test:8080|http|ntlm-auth.zap.test|8080|ZAPLAB|${NTLM_USERNAME}|pass"
                'kerberos-web|http://kerberos-web.zap.test:8080|kerberos|kerberos-web.zap.test|8080|zapuser@ZAP.TEST|-|pass'
            )
            SCRIPT_TARGETS=(
                'express-form|http://express-form:3000|existing-apps/01-express-form-cookie.js|/private|pass'
                'react-json-cookie|http://react-json-cookie:3000|existing-apps/02-react-json-cookie.js|/api/whoami|pass'
                'spring-form|http://spring-form:8080|existing-apps/03-spring-form-csrf-cookie.js|/private|pass'
                'go-multistep|http://go-multistep:8080|existing-apps/04-go-multistep-cookie.js|/api/whoami|pass'
                'consent-checkbox|http://consent-checkbox:3000|existing-apps/05-consent-checkbox-cookie.js|/api/whoami|pass'
                'iframe-login|http://iframe-login:3000|existing-apps/06-iframe-login-cookie.js|/private|pass'
                'otp-challenge|http://otp-challenge:3000|existing-apps/07-otp-challenge-cookie.js|/api/whoami|pass'
                'localstorage-jwt|http://localstorage-jwt:3000|existing-apps/08-localstorage-jwt-bearer.js|/api/whoami|pass'
                'script-jwt-exp|http://script-jwt-exp:3000|token-lab/01-jwt-exp-parsing.js|/private|pass'
                'script-token-timeout|http://script-token-timeout:3000|token-lab/02-token-refresh-timeout.js|/private|pass'
                'script-token-check|http://script-token-check:3000|token-lab/03-token-refresh-timeout-and-check.js|/private|pass'
                'mock-1c|http://mock-1c:8704|existing-apps/09-1c-vrs-session.js|/app/|pass'
            )
            DISCOVERY_TARGETS=(
                'large-bundle-spa|http://large-bundle-spa:8705|http://127.0.0.1:8705|/'
                'many-states-spa|http://many-states-spa:8706|http://127.0.0.1:8706|/'
                'runtime-discovery-spa|http://runtime-discovery-spa:8707|http://127.0.0.1:8707|/'
                'large-api-response|http://large-api-response:8708|http://127.0.0.1:8708|/'
                'bft-regression-spa|http://bft-regression-spa:8709|http://127.0.0.1:8709|/app/'
                'scope-noise|http://scope-noise:8710|http://127.0.0.1:8710|/'
            )
            CERTIFICATE_TARGETS=(
                'client-cert-auth|https://client-cert-auth:8712|/|pass'
            )
            ;;
        host)
            FORM_TARGETS=(
                'spring-form|http://127.0.0.1:8101|/login|/login|username|password|form|_csrf={csrfToken}|pass|'
                'django-form|http://127.0.0.1:8102|/login|/login|username|password|form|csrfmiddlewaretoken={csrfToken}|pass|'
                'express-form|http://127.0.0.1:8103|/login|/login|username|password|form||pass|'
                'dotnet-form|http://127.0.0.1:8104|/login|/login|username|password|form|__RequestVerificationToken={csrfToken}|pass|'
                'react-json-cookie|http://127.0.0.1:8201|/login|/api/login|username|password|json||fail|'
                'fastapi-dynamic|http://127.0.0.1:8202|/|/api/login|username|password|json||fail|'
                'go-multistep|http://127.0.0.1:8203|/login|/login/username|username|password|multistep||fail|'
                'delayed-render|http://127.0.0.1:8301|/login|/login|username|password|form||pass|'
                'nonstandard-fields|http://127.0.0.1:8302|/login|/session/start|employeeIdentifier|accessPhrase|form||pass|'
                'hash-spa|http://127.0.0.1:8303|/#/signin|/api/login|username|password|json||pass|'
                'enter-submit|http://127.0.0.1:8304|/login|/api/login|username|password|json||pass|'
                'iframe-login|http://127.0.0.1:8305|/login|/login|username|password|form||pass|'
                'otp-challenge|http://127.0.0.1:8306|/login|/login|username|password|otp||fail|'
                'modal-login|http://127.0.0.1:8501|/login|/login|username|password|form||observe|'
                'consent-checkbox|http://127.0.0.1:8502|/login|/api/login|username|password|json|consent=true|observe|'
                'localstorage-jwt|http://127.0.0.1:8503|/login|/api/login|username|password|json||observe|'
                'complex-react-auth|http://127.0.0.1:8711|/app/#/login|/api/auth/login|username|password|json||fail|'
            )
            BROWSER_TARGETS=(
                'spring-form|http://127.0.0.1:8101|/login|/login|username|password|form||pass||/private'
                'django-form|http://127.0.0.1:8102|/login|/login|username|password|form||pass||/private'
                'express-form|http://127.0.0.1:8103|/login|/login|username|password|form||pass||/private'
                'dotnet-form|http://127.0.0.1:8104|/login|/login|username|password|form||pass||/private'
                'react-json-cookie|http://127.0.0.1:8201|/login|/api/login|username|password|json||pass||/api/whoami'
                'fastapi-dynamic|http://127.0.0.1:8202|/|/api/login|username|password|json||fail||/api/whoami'
                'go-multistep|http://127.0.0.1:8203|/login|/login/username|username|password|multistep||pass||/api/whoami'
                'delayed-render|http://127.0.0.1:8301|/login|/login|username|password|form||pass||/private'
                'nonstandard-fields|http://127.0.0.1:8302|/login|/session/start|employeeIdentifier|accessPhrase|form||pass||/private'
                'hash-spa|http://127.0.0.1:8303|/#/signin|/api/login|username|password|json||pass||/api/whoami'
                'enter-submit|http://127.0.0.1:8304|/login|/api/login|username|password|json||pass||/api/whoami'
                'iframe-login|http://127.0.0.1:8305|/login|/login|username|password|form||fail||/private'
                'otp-challenge|http://127.0.0.1:8306|/login|/login|username|password|otp||fail||/api/whoami'
                'basic-then-form|http://127.0.0.1:8406|/login|/login|username|password|form||observe||/api/whoami'
                'modal-login|http://127.0.0.1:8501|/login|/login|username|password|form||observe||/api/whoami'
                'consent-checkbox|http://127.0.0.1:8502|/login|/api/login|username|password|json||observe||/api/whoami'
                "localstorage-jwt|http://127.0.0.1:8503|/login|/api/login|username|password|json||observe|${LOCALSTORAGE_SESSION_HEADERS}|/api/whoami"
                "complex-react-auth|http://127.0.0.1:8711|/app/#/login|/api/auth/login|username|password|json||pass|${LOCALSTORAGE_SESSION_HEADERS}|/api/auth/currentUser"
                'sso-redirect|http://sso-app.localhost:8504|/login|/authorize|username|password|form||observe||/api/whoami'
                'cross-host-sso|http://customer-app.localhost:8506|/login|/authorize|username|password|form||observe||/api/whoami'
            )
            PROTOCOL_TARGETS=(
                'http-basic|http://127.0.0.1:8401|basic||||-|pass'
                'http-digest|http://127.0.0.1:8402|http|127.0.0.1|8402|ZAP-AUTH-LAB|-|pass'
                "bearer-token|http://127.0.0.1:8403|token||||${BEARER_TOKEN}|pass"
                "api-key-header|http://127.0.0.1:8404|headers||||{\"X-API-Key\":\"${API_KEY}\"}|pass"
                "multi-header|http://127.0.0.1:8405|headers||||{\"X-Client-Id\":\"${CLIENT_ID}\",\"X-Client-Secret\":\"${CLIENT_SECRET}\"}|pass"
                "ntlm-auth|http://127.0.0.1:8601|http|127.0.0.1|8601|ZAPLAB|${NTLM_USERNAME}|pass"
                'kerberos-web|http://kerberos-web.zap.test:8080|kerberos|kerberos-web.zap.test|8080|zapuser@ZAP.TEST|-|pass'
            )
            SCRIPT_TARGETS=()
            DISCOVERY_TARGETS=(
                'large-bundle-spa|http://127.0.0.1:8705|http://127.0.0.1:8705|/'
                'many-states-spa|http://127.0.0.1:8706|http://127.0.0.1:8706|/'
                'runtime-discovery-spa|http://127.0.0.1:8707|http://127.0.0.1:8707|/'
                'large-api-response|http://127.0.0.1:8708|http://127.0.0.1:8708|/'
                'bft-regression-spa|http://127.0.0.1:8709|http://127.0.0.1:8709|/app/'
                'scope-noise|http://127.0.0.1:8710|http://127.0.0.1:8710|/'
            )
            CERTIFICATE_TARGETS=(
                'client-cert-auth|https://127.0.0.1:8712|/|pass'
            )
            if [[ "$AUTH_MODE" == script ]]; then
                die 'AUTH_MODE=script requires TARGET_PROFILE=docker because the supplied JS scripts use Docker service URLs'
            fi
            ;;
        *) die "TARGET_PROFILE must be docker or host, got: $TARGET_PROFILE" ;;
    esac
}

collect_active_targets() {
    ACTIVE_TARGETS=()
    case "$AUTH_MODE" in
        form) ACTIVE_TARGETS+=("${FORM_TARGETS[@]}") ;;
        browser) ACTIVE_TARGETS+=("${BROWSER_TARGETS[@]}") ;;
        both)
            ACTIVE_TARGETS+=("${FORM_TARGETS[@]}")
            ACTIVE_TARGETS+=("${BROWSER_TARGETS[@]}")
            ;;
        protocol) ACTIVE_TARGETS+=("${PROTOCOL_TARGETS[@]}") ;;
        script) ACTIVE_TARGETS+=("${SCRIPT_TARGETS[@]}") ;;
        discovery) ACTIVE_TARGETS+=("${DISCOVERY_TARGETS[@]}") ;;
        none) ;;
        all)
            ACTIVE_TARGETS+=("${FORM_TARGETS[@]}")
            ACTIVE_TARGETS+=("${BROWSER_TARGETS[@]}")
            ACTIVE_TARGETS+=("${PROTOCOL_TARGETS[@]}")
            ACTIVE_TARGETS+=("${SCRIPT_TARGETS[@]}")
            ;;
        *) die 'AUTH_MODE must be none, both, form, browser, protocol, script, discovery, or all' ;;
    esac
    if [[ "$CERT_MODE" == certificate ]]; then
        ACTIVE_TARGETS+=("${CERTIFICATE_TARGETS[@]}")
    fi
}

append_common_fields() {
    local -n command_ref=$1
    local target_url=$2

    command_ref+=(
        --form-string "url=${target_url}"
        --form-string "spiderUrl=${target_url}"
        --form-string "attackMode=${ATTACK_MODE}"
        --form-string "ajaxSpiderEnabled=${AJAX_SPIDER_ENABLED}"
        --form-string "ajaxSpiderTimeout=${AJAX_SPIDER_TIMEOUT}"
        --form-string "requestsPerSecond=${REQUESTS_PER_SECOND}"
    )
    if [[ "$ACTION" == check ]]; then
        command_ref+=(
            --form-string "agentId=${AGENT_ID}"
            --form-string "checkAuthUrl=${target_url}"
        )
    fi
}

append_form_auth() {
    local -n command_ref=$1
    local origin=$2
    local form_action=$3
    local username_field=$4
    local password_field=$5
    local kind=$6
    local extra=$7
    local logged_in_indicator=$8
    local request_data

    case "$kind" in
        form|json|multistep|otp)
            request_data="${username_field}={${USERNAME}}&${password_field}={${PASSWORD}}"
            [[ -n "$extra" ]] && request_data="${extra}&${request_data}"
            ;;
        *) die "Unknown form kind: $kind" ;;
    esac

    command_ref+=(
        --form-string "authFormBasedRequestPostData=${request_data}"
        --form-string "authFormBasedUsernameFormName=${username_field}"
        --form-string "authFormBasedPasswordFormName=${password_field}"
        --form-string "authFormBasedLoginUrl=${origin}${form_action}"
        --form-string "authFormBasedLogoutUrl=${origin}/logout"
        --form-string "authFormBasedLoginUrlPattern=${logged_in_indicator}"
        --form-string "authFormBasedLogoutUrlPattern=${LOGGED_OUT_REGEX}"
    )
}

append_browser_auth() {
    local -n command_ref=$1
    local origin=$2
    local login_path=$3
    local session_headers=$4

    command_ref+=(
        --form-string "authBrowserBasedUsername=${USERNAME}"
        --form-string "authBrowserBasedPassword=${PASSWORD}"
        --form-string "authBrowserBasedLoginPageUrl=${origin}${login_path}"
        --form-string "authBrowserBasedLoginPageWait=${BROWSER_LOGIN_PAGE_WAIT}"
        --form-string "authBrowserBasedStepDelay=${BROWSER_STEP_DELAY}"
        --form-string "authBrowserBasedLoggedInRegex=${LOGGED_IN_REGEX}"
        --form-string "authBrowserBasedLoggedOutRegex=${LOGGED_OUT_REGEX}"
        --form-string "authBrowserBasedLogoutUrl=${origin}/logout"
        --form-string "authBrowserBasedPollUrl=${origin}/api/whoami"
        --form-string "authBrowserBasedPollFrequency=${BROWSER_POLL_FREQUENCY}"
        --form-string "authBrowserBasedPollFrequencyUnits=${BROWSER_POLL_FREQUENCY_UNITS}"
    )
    if [[ -n "$session_headers" ]]; then
        command_ref+=(--form-string "authBrowserBasedSessionHeaders=${session_headers}")
    fi
}

append_protocol_auth() {
    local -n command_ref=$1
    local auth_type=$2
    local hostname=$3
    local port=$4
    local realm=$5
    local value=$6
    local http_username=$USERNAME

    case "$auth_type" in
        basic)
            command_ref+=(
                --form-string "authBasicLogin=${USERNAME}"
                --form-string "authBasicPassword=${PASSWORD}"
            )
            ;;
        token)
            command_ref+=(--form-string "authToken=${value}")
            ;;
        headers)
            command_ref+=(--form-string "authCustomHeaders=${value}")
            ;;
        http)
            if [[ "$value" != '-' ]]; then
                http_username=$value
            fi
            command_ref+=(
                --form-string 'authNtlmUsernameFieldName=username'
                --form-string 'authNtlmPasswordFieldName=password'
                --form-string "authNtlmUsername=${http_username}"
                --form-string "authNtlmPassword=${PASSWORD}"
                --form-string "authNtlmKerberosHostname=${hostname}"
                --form-string "authNtlmKerberosPort=${port}"
                --form-string "authNtlmKerberosRealm=${realm}"
            )
            ;;
        kerberos)
            command_ref+=(
                --form-string "authNtlmKerberosHostname=${hostname}"
                --form-string "authNtlmKerberosPort=${port}"
                --form-string "authNtlmKerberosRealm=${realm}"
                --form "authKerberosConfiguration=@${KERBEROS_CONFIG_FILE};type=text/plain"
                --form "authKerberosKeytab=@${KERBEROS_KEYTAB_FILE};type=application/octet-stream"
            )
            ;;
        *) die "Unknown protocol authentication type: $auth_type" ;;
    esac
}

append_client_certificate() {
    local -n command_ref=$1
    [[ -s "$CLIENT_CERTIFICATE_FILE" ]] || die "Client certificate file not found: $CLIENT_CERTIFICATE_FILE"
    [[ "$CLIENT_CERTIFICATE_INDEX" =~ ^[0-9]+$ ]] || die 'CLIENT_CERTIFICATE_INDEX must be a non-negative integer'
    command_ref+=(
        --form "certificate=@${CLIENT_CERTIFICATE_FILE};type=application/x-pkcs12"
        --form-string "clientCertificatePassword=${CLIENT_CERTIFICATE_PASSWORD}"
        --form-string "clientCertificateIndex=${CLIENT_CERTIFICATE_INDEX}"
    )
}

append_custom_script_auth() {
    local -n command_ref=$1
    local script_file=$2

    command_ref+=(
        --form "authCustomScript=@${script_file};type=application/javascript"
    )
}

request_endpoint() {
    if [[ "$ACTION" == check ]]; then
        printf '%s/dastProjects/checkAuth?id=%s' "${API_BASE_URL%/}" "$PROJECT_ID"
    elif [[ -n "$AGENT_ID" ]]; then
        printf '%s/dastProjects/%s/scans/from_form_data?agent=%s' \
            "${API_BASE_URL%/}" "$PROJECT_ID" "$AGENT_ID"
    else
        printf '%s/dastProjects/%s/scans/from_form_data' "${API_BASE_URL%/}" "$PROJECT_ID"
    fi
}

print_redacted_command() {
    local argument

    printf 'DRY RUN:'
    for argument in "$@"; do
        if [[ "$argument" == 'Authorization: Bearer '* ]]; then
            argument='Authorization: Bearer <APP_TOKEN>'
        fi
        if [[ -n "$APP_PASSWORD" ]]; then
            argument=${argument//${APP_PASSWORD}/<APP_PASSWORD>}
        fi
        argument=${argument//${PASSWORD}/<TARGET_PASSWORD>}
        argument=${argument//${BEARER_TOKEN}/<TARGET_TOKEN>}
        argument=${argument//${API_KEY}/<API_KEY>}
        argument=${argument//${CLIENT_SECRET}/<CLIENT_SECRET>}
        argument=${argument//${CLIENT_CERTIFICATE_PASSWORD}/<CLIENT_CERTIFICATE_PASSWORD>}
        printf ' %q' "$argument"
    done
    printf '\n'
}

auth_succeeded() {
    jq -e '
        type == "array" and any(.[]?;
            (.responseBody // "") as $body
            | (try ($body | fromjson | .authenticated == true) catch false)
                or ($body | test("AUTHENTICATED"))
        )
    ' >/dev/null 2>&1
}

print_failed_response_details() {
    if ! jq -e 'type == "array"' >/dev/null 2>&1 <<< "$1"; then
        jq -r '
            "  API response: "
            + ((.errorMessage // .message // tostring) | gsub("[\\r\\n\\t]+"; " ") | .[0:400])
        ' <<< "$1" >&2 || printf '  API response: %.400s\n' "$1" >&2
        return
    fi
    jq -r '
        [
            .[]?
            | {
                headers: (
                    (.responseHeader // "")
                    | split("\r\n")
                    | map(select(test("^(HTTP/|WWW-Authenticate:)"; "i")))
                    | join(" | ")
                ),
                body: (
                    (.responseBody // "")
                    | gsub("[\\r\\n\\t]+"; " ")
                    | .[0:400]
                )
            }
        ]
        | .[-5:][]
        | "  response: \(.headers) body=\(.body)"
    ' <<< "$1" >&2
}

record_check_result() {
    local name=$1
    local mode=$2
    local expected=$3
    local body=$4

    if auth_succeeded <<< "$body"; then
        CHECK_PASSES=$((CHECK_PASSES + 1))
        if [[ "$expected" == fail ]]; then
            printf 'PASS (previous baseline was FAIL)\n'
        elif [[ "$expected" == observe ]]; then
            printf 'PASS (observation)\n'
        else
            printf 'PASS\n'
        fi
        return
    fi

    case "$expected" in
        pass)
            CHECK_REGRESSIONS=$((CHECK_REGRESSIONS + 1))
            printf 'FAIL (regression)\n' >&2
            ;;
        fail)
            CHECK_EXPECTED_FAILURES=$((CHECK_EXPECTED_FAILURES + 1))
            printf 'EXPECTED FAIL\n'
            ;;
        observe)
            CHECK_OBSERVED_FAILURES=$((CHECK_OBSERVED_FAILURES + 1))
            printf 'FAIL (observation)\n'
            ;;
        *) die "Unknown expected result '$expected' for $mode/$name" ;;
    esac
    if is_true "$VERBOSE_FAILURES"; then
        print_failed_response_details "$body"
    fi
}

execute_request() {
    local name=$1
    local mode=$2
    local expected=$3
    local -n command_ref=$4
    local response
    local status
    local body

    REQUEST_COUNT=$((REQUEST_COUNT + 1))
    if is_true "$DRY_RUN"; then
        printf '\n[%s] %s\n' "$mode" "$name"
        print_redacted_command "${command_ref[@]}"
        return
    fi

    printf '%-9s %-22s ... ' "$mode" "$name"
    if ! response=$("${command_ref[@]}"); then
        REQUEST_FAILURES=$((REQUEST_FAILURES + 1))
        printf 'curl failed\n' >&2
        is_true "$CONTINUE_ON_ERROR" || return 1
        return
    fi
    status=${response##*$'\n'}
    body=${response%$'\n'*}
    if [[ "$ACTION" == check && -n "$RESULTS_DIR" ]]; then
        mkdir -p "$RESULTS_DIR"
        chmod 700 "$RESULTS_DIR"
        printf '%s\n' "$body" > "${RESULTS_DIR}/${mode,,}-${name}.json"
        chmod 600 "${RESULTS_DIR}/${mode,,}-${name}.json"
    fi
    if [[ ! "$status" =~ ^2[0-9][0-9]$ ]]; then
        if [[ "$ACTION" == check && "$status" == 500 ]] \
            && jq -e --arg message "Cannot check auth for project: ${PROJECT_ID}" '
                type == "object"
                and .statusCode == 500
                and .errorMessage == $message
            ' >/dev/null 2>&1 <<< "$body"; then
            record_check_result "$name" "$mode" "$expected" "$body"
            return
        fi
        REQUEST_FAILURES=$((REQUEST_FAILURES + 1))
        printf 'HTTP %s\n%s\n' "$status" "$body" >&2
        is_true "$CONTINUE_ON_ERROR" || return 1
        return
    fi

    if [[ "$ACTION" == scan ]]; then
        printf 'HTTP %s, scan id=%s, status=%s\n' \
            "$status" \
            "$(jq -r '.id // "?"' <<< "$body")" \
            "$(jq -r '.status // "?"' <<< "$body")"
    else
        record_check_result "$name" "$mode" "$expected" "$body"
    fi
    if [[ "$ACTION" == check ]]; then
        show_target_coverage "$name"
    else
        print_coverage_hint "$name"
    fi

}

run_form_target() {
    local target=$1
    local name
    local origin
    local login_path
    local form_action
    local username_field
    local password_field
    local kind
    local extra
    local expected
    local unused_session_headers
    local target_url
    local logged_in_indicator
    local -a command

    IFS='|' read -r name origin login_path form_action username_field password_field kind extra \
        expected unused_session_headers <<< "$target"
    if ! is_selected "$name"; then
        return 0
    fi
    if [[ "$kind" == form ]]; then
        target_url="${origin}/private"
        logged_in_indicator=$FORM_LOGGED_IN_INDICATOR
    else
        target_url="${origin}/api/whoami"
        logged_in_indicator=$LOGGED_IN_REGEX
    fi
    command=(
        curl --silent --show-error
        --connect-timeout "$CONNECT_TIMEOUT"
        --max-time "$HTTP_TIMEOUT"
        --write-out $'\n%{http_code}'
        --request POST
        "${API_AUTH_ARGS[@]}"
        "$(request_endpoint)"
    )
    append_common_fields command "$target_url"
    append_form_auth command "$origin" "$form_action" "$username_field" \
        "$password_field" "$kind" "$extra" "$logged_in_indicator"
    reset_target_coverage "$name"
    execute_request "$name" FORM "$expected" command
}

run_browser_target() {
    local target=$1
    local name
    local origin
    local login_path
    local unused_form_action
    local unused_username_field
    local unused_password_field
    local unused_kind
    local unused_extra
    local expected
    local session_headers
    local target_path
    local target_url
    local -a command

    IFS='|' read -r name origin login_path unused_form_action unused_username_field \
        unused_password_field unused_kind unused_extra expected session_headers target_path <<< "$target"
    if ! is_selected "$name"; then
        return 0
    fi
    if [[ "$ACTION" == scan ]]; then
        # Crawl from the real browser entry point; checkAuth still probes the protected target below.
        target_url="${origin}${login_path}"
    else
        target_url="${origin}${target_path}"
    fi
    command=(
        curl --silent --show-error
        --connect-timeout "$CONNECT_TIMEOUT"
        --max-time "$HTTP_TIMEOUT"
        --write-out $'\n%{http_code}'
        --request POST
        "${API_AUTH_ARGS[@]}"
        "$(request_endpoint)"
    )
    append_common_fields command "$target_url"
    append_browser_auth command "$origin" "$login_path" "$session_headers"
    reset_target_coverage "$name"
    execute_request "$name" BROWSER "$expected" command
}

run_protocol_target() {
    local target=$1
    local name
    local origin
    local auth_type
    local hostname
    local port
    local realm
    local value
    local expected
    local target_url
    local -a command

    IFS='|' read -r name origin auth_type hostname port realm value expected <<< "$target"
    if ! is_selected "$name"; then
        return 0
    fi
    if [[ "$auth_type" == kerberos ]] \
        && [[ ! -s "$KERBEROS_CONFIG_FILE" || ! -s "$KERBEROS_KEYTAB_FILE" ]]; then
        if is_true "$SKIP_KERBEROS"; then
            CHECK_SKIPPED=$((CHECK_SKIPPED + 1))
            printf '%-9s %-22s ... SKIP (run the kerberos compose profile first)\n' \
                PROTOCOL "$name"
            return
        fi
        REQUEST_FAILURES=$((REQUEST_FAILURES + 1))
        printf '%-9s %-22s ... FAIL (missing %s or %s)\n' \
            PROTOCOL "$name" "$KERBEROS_CONFIG_FILE" "$KERBEROS_KEYTAB_FILE" >&2
        is_true "$CONTINUE_ON_ERROR" || return 1
        return
    fi

    target_url="${origin}/api/whoami"
    command=(
        curl --silent --show-error
        --connect-timeout "$CONNECT_TIMEOUT"
        --max-time "$HTTP_TIMEOUT"
        --write-out $'\n%{http_code}'
        --request POST
        "${API_AUTH_ARGS[@]}"
        "$(request_endpoint)"
    )
    append_common_fields command "$target_url"
    append_protocol_auth command "$auth_type" "$hostname" "$port" "$realm" "$value"
    reset_target_coverage "$name"
    execute_request "$name" PROTOCOL "$expected" command
}

run_script_target() {
    local target=$1
    local name
    local origin
    local script_relative_path
    local target_path
    local expected
    local script_file
    local target_url
    local -a command

    IFS='|' read -r name origin script_relative_path target_path expected <<< "$target"
    if ! is_selected "$name"; then
        return 0
    fi

    script_file="${SCRIPT_AUTH_DIR%/}/${script_relative_path}"
    if [[ ! -s "$script_file" ]]; then
        if is_true "$SKIP_SCRIPT_AUTH"; then
            CHECK_SKIPPED=$((CHECK_SKIPPED + 1))
            printf '%-9s %-22s ... SKIP (missing %s)\n' SCRIPT "$name" "$script_file"
            return 0
        fi
        REQUEST_FAILURES=$((REQUEST_FAILURES + 1))
        printf '%-9s %-22s ... FAIL (missing script %s)\n' \
            SCRIPT "$name" "$script_file" >&2
        is_true "$CONTINUE_ON_ERROR" || return 1
        return 0
    fi

    target_url="${origin}${target_path}"
    command=(
        curl --silent --show-error
        --connect-timeout "$CONNECT_TIMEOUT"
        --max-time "$HTTP_TIMEOUT"
        --write-out $'\n%{http_code}'
        --request POST
        "${API_AUTH_ARGS[@]}"
        "$(request_endpoint)"
    )
    append_common_fields command "$target_url"
    append_custom_script_auth command "$script_file"
    reset_target_coverage "$name"
    execute_request "$name" SCRIPT "$expected" command
}

coverage_control_urls() {
    case "$1" in
        spring-form) echo 'http://127.0.0.1:8101' ;;
        django-form) echo 'http://127.0.0.1:8102' ;;
        express-form) echo 'http://127.0.0.1:8103' ;;
        dotnet-form) echo 'http://127.0.0.1:8104' ;;
        react-json-cookie) echo 'http://127.0.0.1:8201' ;;
        fastapi-dynamic) echo 'http://127.0.0.1:8202' ;;
        go-multistep) echo 'http://127.0.0.1:8203' ;;
        delayed-render) echo 'http://127.0.0.1:8301' ;;
        nonstandard-fields) echo 'http://127.0.0.1:8302' ;;
        hash-spa) echo 'http://127.0.0.1:8303' ;;
        enter-submit) echo 'http://127.0.0.1:8304' ;;
        iframe-login) echo 'http://127.0.0.1:8305' ;;
        otp-challenge) echo 'http://127.0.0.1:8306' ;;
        http-basic) echo 'http://127.0.0.1:8401' ;;
        http-digest) echo 'http://127.0.0.1:8402' ;;
        bearer-token) echo 'http://127.0.0.1:8403' ;;
        api-key-header) echo 'http://127.0.0.1:8404' ;;
        multi-header) echo 'http://127.0.0.1:8405' ;;
        basic-then-form) echo 'http://127.0.0.1:8406' ;;
        modal-login) echo 'http://127.0.0.1:8501' ;;
        consent-checkbox) echo 'http://127.0.0.1:8502' ;;
        localstorage-jwt) echo 'http://127.0.0.1:8503' ;;
        sso-redirect) printf '%s\n' 'http://127.0.0.1:8504' 'http://127.0.0.1:8505' ;;
        cross-host-sso) printf '%s\n' 'http://127.0.0.1:8506' 'http://127.0.0.1:8507' ;;
        ntlm-auth) echo 'http://127.0.0.1:8601' ;;
        kerberos-web) echo 'http://127.0.0.1:8602' ;;
        script-jwt-exp) echo 'http://127.0.0.1:8701' ;;
        script-token-timeout) echo 'http://127.0.0.1:8702' ;;
        script-token-check) echo 'http://127.0.0.1:8703' ;;
        mock-1c) echo 'http://127.0.0.1:8704' ;;
        large-bundle-spa) echo 'http://127.0.0.1:8705' ;;
        many-states-spa) echo 'http://127.0.0.1:8706' ;;
        runtime-discovery-spa) echo 'http://127.0.0.1:8707' ;;
        large-api-response) echo 'http://127.0.0.1:8708' ;;
        bft-regression-spa) echo 'http://127.0.0.1:8709' ;;
        scope-noise) echo 'http://127.0.0.1:8710' ;;
        complex-react-auth) echo 'http://127.0.0.1:8711' ;;
        client-cert-auth) echo 'http://127.0.0.1:9712' ;;
    esac
}

reset_target_coverage() {
    local name=$1
    local base status
    is_true "$RESET_TESTBED_COVERAGE" || return 0
    is_true "$DRY_RUN" && return 0
    while IFS= read -r base; do
        [[ -n "$base" ]] || continue
        status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
            --connect-timeout "$CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" \
            --request POST --header "X-Testbed-Control: ${TESTBED_CONTROL_TOKEN}" \
            "${base}/__testbed/control/reset" || true)
        if [[ "$status" != 200 ]]; then
            printf 'WARN: could not reset coverage for %s via %s (HTTP %s)\n' \
                "$name" "$base" "${status:-curl-error}" >&2
        fi
    done < <(coverage_control_urls "$name")
}

show_target_coverage() {
    local name=$1
    local base payload
    is_true "$SHOW_CHECK_COVERAGE" || return 0
    is_true "$DRY_RUN" && return 0
    while IFS= read -r base; do
        [[ -n "$base" ]] || continue
        payload=$(curl --silent --show-error --fail \
            --connect-timeout "$CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" \
            "${base}/__testbed/coverage" 2>/dev/null || true)
        [[ -n "$payload" ]] || continue
        printf '  coverage %-22s %s\n' "$name" "$(jq -c '{application:(.application // .app), discovery:(.discovery // {expected:.expected,visited:.visited,coveragePercent:.coveragePercent}), authentication:(.authentication // null)}' <<< "$payload" 2>/dev/null || printf '%s' "$payload")"
    done < <(coverage_control_urls "$name")
}

print_coverage_hint() {
    local name=$1 base
    is_true "$DRY_RUN" && return 0
    while IFS= read -r base; do
        [[ -n "$base" ]] || continue
        printf '  coverage after scan: %s/__testbed/coverage\n' "$base"
    done < <(coverage_control_urls "$name")
}

run_certificate_target() {
    local target=$1
    local name
    local origin
    local target_path
    local expected
    local target_url
    local -a command

    IFS='|' read -r name origin target_path expected <<< "$target"
    if ! is_selected "$name"; then
        return 0
    fi
    if [[ "$ACTION" != scan ]]; then
        CHECK_SKIPPED=$((CHECK_SKIPPED + 1))
        printf '%-11s %-22s ... SKIP (client certificates are wired to scan creation only)\n' CERTIFICATE "$name"
        return 0
    fi

    target_url="${origin}${target_path}"
    command=(
        curl --silent --show-error
        --connect-timeout "$CONNECT_TIMEOUT"
        --max-time "$HTTP_TIMEOUT"
        --write-out $'\n%{http_code}'
        --request POST
        "${API_AUTH_ARGS[@]}"
        "$(request_endpoint)"
    )
    append_common_fields command "$target_url"
    append_client_certificate command
    reset_target_coverage "$name"
    execute_request "$name" CERTIFICATE "$expected" command
}

run_discovery_target() {
    local target=$1
    local name
    local origin
    local control_origin
    local target_path
    local target_url
    local -a command

    IFS='|' read -r name origin control_origin target_path <<< "$target"
    if ! is_selected "$name"; then
        return 0
    fi
    reset_target_coverage "$name"
    target_url="${origin}${target_path}"
    command=(
        curl --silent --show-error
        --connect-timeout "$CONNECT_TIMEOUT"
        --max-time "$HTTP_TIMEOUT"
        --write-out $'\n%{http_code}'
        --request POST
        "${API_AUTH_ARGS[@]}"
        "$(request_endpoint)"
    )
    append_common_fields command "$target_url"
    execute_request "$name" DISCOVERY pass command
}

pause_between_requests() {
    [[ "$DELAY_BETWEEN_REQUESTS" == 0 ]] || sleep "$DELAY_BETWEEN_REQUESTS"
}

print_summary() {
    if is_true "$DRY_RUN"; then
        printf '\nDry run: %d request(s) generated.\n' "$REQUEST_COUNT"
    elif [[ "$ACTION" == check ]]; then
        printf '\nSummary: %d pass, %d expected fail, %d observed fail, %d regression, %d skipped, %d request error(s).\n' \
            "$CHECK_PASSES" "$CHECK_EXPECTED_FAILURES" "$CHECK_OBSERVED_FAILURES" \
            "$CHECK_REGRESSIONS" "$CHECK_SKIPPED" "$REQUEST_FAILURES"
    else
        printf '\nSummary: %d scan request(s), %d request error(s).\n' \
            "$REQUEST_COUNT" "$REQUEST_FAILURES"
    fi
}

main() {
    local target

    [[ ${1:-} == '-h' || ${1:-} == '--help' ]] && { usage; return; }
    [[ $# -eq 0 ]] || die 'This script takes no positional arguments; use environment variables'
    require_command curl
    require_command jq
    [[ -n "$PROJECT_ID" ]] || die 'PROJECT_ID is required'
    [[ "$PROJECT_ID" =~ ^[1-9][0-9]*$ ]] || die 'PROJECT_ID must be a positive integer'
    case "$ACTION" in check|scan) ;; *) die 'ACTION must be check or scan' ;; esac
    if [[ "$AUTH_MODE" == discovery && "$ACTION" != scan ]]; then
        die 'AUTH_MODE=discovery supports ACTION=scan only'
    fi
    case "$CERT_MODE" in
        none|certificate) ;;
        *) die 'CERT_MODE must be none or certificate' ;;
    esac
    if [[ "$CERT_MODE" == certificate && "$ACTION" != scan ]]; then
        die 'CERT_MODE=certificate supports ACTION=scan only'
    fi
    case "$ATTACK_MODE" in STANDARD|ATTACK|ATTACK_ON_START) ;; *) die 'Invalid ATTACK_MODE' ;; esac
    case "$BROWSER_POLL_FREQUENCY_UNITS" in
        REQUESTS|SECONDS) ;;
        *) die 'Invalid BROWSER_POLL_FREQUENCY_UNITS' ;;
    esac
    if [[ -z "$CONTINUE_ON_ERROR" ]]; then
        [[ "$ACTION" == check ]] && CONTINUE_ON_ERROR=true || CONTINUE_ON_ERROR=false
    fi

    set_target_profile
    collect_active_targets
    validate_only
    configure_api_auth
    resolve_agent_id

    printf 'API: %s\nBackend auth: %s\nProject: %s\nAgent: %s\nTarget profile: %s\nAction: %s\nAuth mode: %s\nCert mode: %s\n' \
        "$API_BASE_URL" "$API_AUTH" "$PROJECT_ID" "${AGENT_ID:-project default}" \
        "$TARGET_PROFILE" "$ACTION" "$AUTH_MODE" "$CERT_MODE"

    case "$AUTH_MODE" in
        form|both|all)
            for target in "${FORM_TARGETS[@]}"; do
                run_form_target "$target"
                pause_between_requests
            done
            ;;
    esac
    case "$AUTH_MODE" in
        browser|both|all)
            for target in "${BROWSER_TARGETS[@]}"; do
                run_browser_target "$target"
                pause_between_requests
            done
            ;;
    esac
    case "$AUTH_MODE" in
        protocol|all)
            for target in "${PROTOCOL_TARGETS[@]}"; do
                run_protocol_target "$target"
                pause_between_requests
            done
            ;;
    esac
    case "$AUTH_MODE" in
        script|all)
            for target in "${SCRIPT_TARGETS[@]}"; do
                run_script_target "$target"
                pause_between_requests
            done
            ;;
    esac

    if [[ "$CERT_MODE" == certificate ]]; then
        for target in "${CERTIFICATE_TARGETS[@]}"; do
            run_certificate_target "$target"
            pause_between_requests
        done
    fi

    case "$AUTH_MODE" in
        discovery)
            for target in "${DISCOVERY_TARGETS[@]}"; do
                run_discovery_target "$target"
                pause_between_requests
            done
            ;;
    esac

    [[ "$REQUEST_COUNT" -gt 0 || "$CHECK_SKIPPED" -gt 0 ]] || die 'No targets selected'
    print_summary
    [[ "$REQUEST_FAILURES" -eq 0 ]] || return 1
    if [[ "$ACTION" == check ]] && is_true "$STRICT_CHECKS"; then
        [[ "$CHECK_REGRESSIONS" -eq 0 ]] || return 1
    fi
}

main "$@"
