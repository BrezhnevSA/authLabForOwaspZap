#!/usr/bin/env sh
set -eu

TOKEN="${TESTBED_CONTROL_TOKEN:-zap-testbed-reset-v1}"
ACTION="${1:-show}"

apps='8705 large-bundle-spa
8706 many-states-spa
8707 runtime-discovery-spa
8708 large-api-response
8709 bft-regression-spa
8710 scope-noise
8711 complex-react-auth'

printf '%s\n' "$apps" | while read -r port name; do
  base="http://127.0.0.1:${port}"
  case "$ACTION" in
    reset)
      printf '%-24s ' "$name"
      curl -fsS -X POST -H "X-Testbed-Control: ${TOKEN}" "${base}/__testbed/control/reset"
      printf '\n'
      ;;
    expected)
      printf '\n== %s ==\n' "$name"
      curl -fsS "${base}/__testbed/expected"
      printf '\n'
      ;;
    show|coverage)
      printf '\n== %s ==\n' "$name"
      curl -fsS "${base}/__testbed/coverage"
      printf '\n'
      ;;
    *)
      echo "Usage: $0 [show|coverage|expected|reset]" >&2
      exit 2
      ;;
  esac
done
